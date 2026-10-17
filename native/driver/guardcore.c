/* GuardCore research minifilter. Documented callbacks only; no hooks or patches. */
#pragma warning(push)
#pragma warning(disable:4324) /* WDK structures deliberately contain aligned padding. */
#include <fltKernel.h>
#pragma warning(pop)
#include "guard_protocol.h"
#include "guard_policy.h"

#define DG_TAG 'cGdD'
#define DG_MAX_PROCESSES 128
/* Public Windows access-right values; the kernel headers omit several aliases. */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE 0x0001
#define PROCESS_CREATE_THREAD 0x0002
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_READ 0x0010
#define PROCESS_VM_WRITE 0x0020
#define PROCESS_CREATE_PROCESS 0x0080
#define PROCESS_SET_QUOTA 0x0100
#define PROCESS_SET_INFORMATION 0x0200
#define PROCESS_SUSPEND_RESUME 0x0800
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif
#ifndef THREAD_SET_THREAD_TOKEN
#define THREAD_SET_THREAD_TOKEN 0x0080
#define THREAD_IMPERSONATE 0x0100
#define THREAD_DIRECT_IMPERSONATION 0x0200
#endif
/* Restrict the modifiable rights documented for OB_PRE_CREATE_HANDLE_INFORMATION.
   Do not advertise unsupported read-only memory/context interception as proven. */
#define DG_PROCESS_DENY (PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | \
    PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME | \
    PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_CREATE_PROCESS)
#define DG_THREAD_DENY (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | \
    THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN | \
    THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION)

typedef struct DG_PROCESS {
    LIST_ENTRY Link;
    PEPROCESS Process;
} DG_PROCESS;

typedef struct DG_FILE_CONTEXT { BOOLEAN Guarded; } DG_FILE_CONTEXT;

static PFLT_FILTER gFilter;
static PFLT_PORT gServerPort;
static PFLT_PORT gClientPort;
static PEPROCESS gController;
static EX_PUSH_LOCK gLock;
static LIST_ENTRY gProcesses;
static ULONG gProcessCount;
static PVOID gObjectRegistration;
static BOOLEAN gNotifyRegistered;
static volatile LONG gConfigured;
static volatile LONG gConfiguring;
static volatile LONG gConnected;
static volatile LONG gDenied;
static volatile LONG gStripped;
static volatile LONG gUnclassified;
static WCHAR gProfileBuffer[DG_PATH_CHARS];
static WCHAR gInstallBuffer[DG_PATH_CHARS];
static WCHAR gImageBuffer[DG_PATH_CHARS];
static UNICODE_STRING gProfile;
static UNICODE_STRING gInstall;
static UNICODE_STRING gImage;

static VOID DgLock(VOID) { KeEnterCriticalRegion(); ExAcquirePushLockExclusive(&gLock); }
static VOID DgUnlock(VOID) { ExReleasePushLockExclusive(&gLock); KeLeaveCriticalRegion(); }

static BOOLEAN DgTrustedLocked(PEPROCESS Process) {
    PLIST_ENTRY entry;
    if (Process == gController) return TRUE;
    for (entry = gProcesses.Flink; entry != &gProcesses; entry = entry->Flink) {
        if (CONTAINING_RECORD(entry, DG_PROCESS, Link)->Process == Process) return TRUE;
    }
    return FALSE;
}

static BOOLEAN DgTrusted(PEPROCESS Process) {
    BOOLEAN trusted;
    DgLock(); trusted = DgTrustedLocked(Process); DgUnlock();
    return trusted;
}

static NTSTATUS DgTrack(PEPROCESS Process) {
    DG_PROCESS* node = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*node), DG_TAG);
    if (!node) return STATUS_INSUFFICIENT_RESOURCES;
    DgLock();
    if (DgTrustedLocked(Process)) { DgUnlock(); ExFreePoolWithTag(node, DG_TAG); return STATUS_SUCCESS; }
    if (gProcessCount >= DG_MAX_PROCESSES) {
        DgUnlock(); ExFreePoolWithTag(node, DG_TAG); return STATUS_QUOTA_EXCEEDED;
    }
    ObReferenceObject(Process);
    node->Process = Process;
    InsertTailList(&gProcesses, &node->Link);
    ++gProcessCount;
    DgUnlock();
    return STATUS_SUCCESS;
}

static BOOLEAN DgWithin(PCUNICODE_STRING Name, PCUNICODE_STRING Root) {
    return Root->Length && RtlPrefixUnicodeString(Root, Name, TRUE) &&
        (Name->Length == Root->Length || Name->Buffer[Root->Length / sizeof(WCHAR)] == L'\\');
}

static BOOLEAN DgGuardedName(PCUNICODE_STRING Name) {
    return DgWithin(Name, &gProfile) || DgWithin(Name, &gInstall);
}

static VOID DgProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo) {
    PLIST_ENTRY entry;
    UNREFERENCED_PARAMETER(ProcessId);
    if (!CreateInfo) {
        DgLock();
        for (entry = gProcesses.Flink; entry != &gProcesses; entry = entry->Flink) {
            DG_PROCESS* node = CONTAINING_RECORD(entry, DG_PROCESS, Link);
            if (node->Process == Process) {
                RemoveEntryList(entry); --gProcessCount; DgUnlock();
                ObDereferenceObject(node->Process); ExFreePoolWithTag(node, DG_TAG); return;
            }
        }
        DgUnlock();
        return;
    }
    /* Use the actual creator, not spoofable ParentProcessId. Only the same
       configured image is inherited; scripts, helpers and updates are not trusted. */
    if (InterlockedCompareExchange(&gConfigured, 0, 0) &&
        InterlockedCompareExchange(&gConnected, 0, 0) &&
        CreateInfo->FileOpenNameAvailable && CreateInfo->ImageFileName &&
        RtlEqualUnicodeString(CreateInfo->ImageFileName, &gImage, TRUE) &&
        DgTrusted(PsGetCurrentProcess())) {
        CreateInfo->CreationStatus = DgTrack(Process);
    }
}

static OB_PREOP_CALLBACK_STATUS DgObjectPre(PVOID Context, POB_PRE_OPERATION_INFORMATION Info) {
    PEPROCESS target = Info->ObjectType == *PsProcessType ?
        (PEPROCESS)Info->Object : IoThreadToProcess((PETHREAD)Info->Object);
    ACCESS_MASK* desired;
    ACCESS_MASK previous, restricted, dangerous;
    BOOLEAN duplicate = Info->Operation == OB_OPERATION_HANDLE_DUPLICATE;
    BOOLEAN sourceTrusted, destinationTrusted = FALSE;
    UNREFERENCED_PARAMETER(Context);
    if (!DgTrusted(target) || Info->KernelHandle) return OB_PREOP_SUCCESS;
    sourceTrusted = DgTrusted(PsGetCurrentProcess());
    if (duplicate) {
        destinationTrusted = DgTrusted(Info->Parameters->DuplicateHandleInformation.TargetProcess);
        desired = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
    dangerous = Info->ObjectType == *PsProcessType ? DG_PROCESS_DENY : DG_THREAD_DENY;
    previous = *desired;
    restricted = DgRestrictedAccess(previous, dangerous, sourceTrusted, destinationTrusted, duplicate, FALSE);
    *desired = restricted;
    if (restricted != previous) InterlockedIncrement(&gStripped);
    return OB_PREOP_SUCCESS;
}

static BOOLEAN DgRequestTrusted(PFLT_CALLBACK_DATA Data) {
    return (BOOLEAN)DgFileAllowed(InterlockedCompareExchange(&gConnected, 0, 0) != 0,
        DgTrusted(FltGetRequestorProcess(Data)), Data->RequestorMode == KernelMode);
}

static BOOLEAN DgClassify(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS Objects) {
    PFLT_FILE_NAME_INFORMATION name = NULL;
    DG_FILE_CONTEXT* context = NULL;
    BOOLEAN guarded = FALSE;
    if (Objects->FileObject && NT_SUCCESS(FltGetStreamHandleContext(Objects->Instance,
            Objects->FileObject, (PFLT_CONTEXT*)&context))) {
        guarded = context->Guarded;
        FltReleaseContext(context);
        if (guarded) return TRUE;
    }
    if (NT_SUCCESS(FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name))) {
        guarded = DgGuardedName(&name->Name);
        FltReleaseFileNameInformation(name);
    } else InterlockedIncrement(&gUnclassified);
    return guarded;
}

static FLT_PREOP_CALLBACK_STATUS DgDeny(PFLT_CALLBACK_DATA Data) {
    if (FLT_IS_FASTIO_OPERATION(Data)) return FLT_PREOP_DISALLOW_FASTIO;
    InterlockedIncrement(&gDenied);
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS DgPreCreate(PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS Objects, PVOID* CompletionContext) {
    UNREFERENCED_PARAMETER(CompletionContext);
    if (!InterlockedCompareExchange(&gConfigured, 0, 0) || Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!DgClassify(Data, Objects)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!DgRequestTrusted(Data)) return DgDeny(Data);
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS DgPostCreate(PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS Objects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
    DG_FILE_CONTEXT* context = NULL;
    UNREFERENCED_PARAMETER(CompletionContext);
    if (!(Flags & FLTFL_POST_OPERATION_DRAINING) && NT_SUCCESS(Data->IoStatus.Status) &&
            Data->IoStatus.Status != STATUS_REPARSE &&
            NT_SUCCESS(FltAllocateContext(gFilter, FLT_STREAMHANDLE_CONTEXT,
                sizeof(*context), NonPagedPoolNx, (PFLT_CONTEXT*)&context))) {
        context->Guarded = TRUE;
        (VOID)FltSetStreamHandleContext(Objects->Instance, Objects->FileObject,
            FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, NULL);
        FltReleaseContext(context);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_PREOP_CALLBACK_STATUS DgPreIo(PFLT_CALLBACK_DATA Data,
        PCFLT_RELATED_OBJECTS Objects, PVOID* CompletionContext) {
    BOOLEAN guarded;
    PFLT_FILE_NAME_INFORMATION destination = NULL;
    FILE_INFORMATION_CLASS kind;
    UNREFERENCED_PARAMETER(CompletionContext);
    if (!InterlockedCompareExchange(&gConfigured, 0, 0) || Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        InterlockedIncrement(&gUnclassified);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (DgRequestTrusted(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    guarded = DgClassify(Data, Objects);
    if (!guarded && Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION) {
        kind = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
        if (kind == FileRenameInformation || kind == FileRenameInformationEx ||
            kind == FileLinkInformation || kind == FileLinkInformationEx) {
            PFILE_RENAME_INFORMATION rename = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
            ULONG bufferLength = Data->Iopb->Parameters.SetFileInformation.Length;
            ULONG headerLength = (ULONG)FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
            if (!rename || bufferLength < headerLength ||
                    rename->FileNameLength > bufferLength - headerLength ||
                    (rename->FileNameLength % sizeof(WCHAR)) != 0) return DgDeny(Data);
            if (NT_SUCCESS(FltGetDestinationFileNameInformation(Objects->Instance,
                    Objects->FileObject, rename->RootDirectory, rename->FileName, rename->FileNameLength,
                    FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &destination))) {
                guarded = DgGuardedName(&destination->Name);
                FltReleaseFileNameInformation(destination);
            } else InterlockedIncrement(&gUnclassified);
        }
    }
    return guarded ? DgDeny(Data) : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS DgCopyPath(WCHAR* Destination, const WCHAR* Source, PUNICODE_STRING Result) {
    ULONG i;
    for (i = 0; i < DG_PATH_CHARS; ++i) if (!Source[i]) break;
    if (i < 20 || i == DG_PATH_CHARS || Source[0] != L'\\' || Source[i - 1] == L'\\')
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(Destination, Source, (i + 1) * sizeof(WCHAR));
    RtlInitUnicodeString(Result, Destination);
    return STATUS_SUCCESS;
}

static NTSTATUS DgVolumeAttached(PCUNICODE_STRING Root) {
    UNICODE_STRING name = *Root;
    PFLT_VOLUME volume = NULL;
    PFLT_INSTANCE instance = NULL;
    USHORT index;
    NTSTATUS status;
    for (index = 8; index < Root->Length / sizeof(WCHAR); ++index)
        if (Root->Buffer[index] == L'\\') break;
    if (index >= Root->Length / sizeof(WCHAR)) return STATUS_INVALID_PARAMETER;
    name.Length = name.MaximumLength = (USHORT)(index * sizeof(WCHAR));
    status = FltGetVolumeFromName(gFilter, &name, &volume);
    if (!NT_SUCCESS(status)) return status;
    status = FltGetVolumeInstanceFromName(gFilter, volume, NULL, &instance);
    if (instance) FltObjectDereference(instance);
    FltObjectDereference(volume);
    return status;
}

static VOID DgStatus(DG_STATUS* Status) {
    RtlZeroMemory(Status, sizeof(*Status));
    Status->Version = DG_PROTOCOL_VERSION;
    Status->Configured = (ULONG)InterlockedCompareExchange(&gConfigured, 0, 0);
    Status->ControllerConnected = (ULONG)InterlockedCompareExchange(&gConnected, 0, 0);
    Status->ProcessCallbacks = gObjectRegistration != NULL;
    DgLock(); Status->TrackedProcesses = gProcessCount; DgUnlock();
    Status->DeniedFileOperations = (ULONG)InterlockedCompareExchange(&gDenied, 0, 0);
    Status->StrippedHandles = (ULONG)InterlockedCompareExchange(&gStripped, 0, 0);
    Status->UnclassifiedFileOperations = (ULONG)InterlockedCompareExchange(&gUnclassified, 0, 0);
}

static NTSTATUS DgMessage(PVOID Cookie, PVOID Input, ULONG InputSize,
        PVOID Output, ULONG OutputSize, PULONG Returned) {
    DG_REQUEST* request;
    DG_STATUS status;
    NTSTATUS result = STATUS_INVALID_PARAMETER;
    PEPROCESS process = NULL;
    PUNICODE_STRING image = NULL;
    BOOLEAN ownsConfiguration = FALSE;
    UNREFERENCED_PARAMETER(Cookie);
    *Returned = 0;
    if (PsGetCurrentProcess() != gController || InputSize != sizeof(DG_REQUEST) ||
        OutputSize < sizeof(status) || !Input || !Output) return STATUS_INVALID_PARAMETER;
    request = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*request), DG_TAG);
    if (!request) return STATUS_INSUFFICIENT_RESOURCES;
    __try { RtlCopyMemory(request, Input, sizeof(*request)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { result = GetExceptionCode(); goto done; }
    if (request->Version != DG_PROTOCOL_VERSION) goto done;
    switch (request->Operation) {
    case DgQuery: result = STATUS_SUCCESS; break;
    case DgConfigure:
        if (InterlockedCompareExchange(&gConfiguring, 1, 0)) { result = STATUS_DEVICE_BUSY; break; }
        ownsConfiguration = TRUE;
        if (InterlockedCompareExchange(&gConfigured, 0, 0)) { result = STATUS_ALREADY_REGISTERED; break; }
        result = DgCopyPath(gProfileBuffer, request->ProfileRoot, &gProfile);
        if (!NT_SUCCESS(result)) break;
        result = DgCopyPath(gInstallBuffer, request->InstallRoot, &gInstall);
        if (!NT_SUCCESS(result)) break;
        result = DgCopyPath(gImageBuffer, request->ImagePath, &gImage);
        if (!NT_SUCCESS(result) || !DgWithin(&gImage, &gInstall)) { result = STATUS_INVALID_PARAMETER; break; }
        result = DgVolumeAttached(&gProfile);
        if (!NT_SUCCESS(result)) break;
        result = DgVolumeAttached(&gInstall);
        if (!NT_SUCCESS(result)) break;
        InterlockedExchange(&gConfigured, 1);
        result = STATUS_SUCCESS;
        break;
    case DgEnroll:
        if (!InterlockedCompareExchange(&gConfigured, 0, 0)) { result = STATUS_DEVICE_NOT_READY; break; }
        result = ObReferenceObjectByHandle((HANDLE)(ULONG_PTR)request->ProcessHandle,
            PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, UserMode, (PVOID*)&process, NULL);
        if (!NT_SUCCESS(result)) break;
        result = SeLocateProcessImageName(process, &image);
        if (NT_SUCCESS(result)) result = RtlEqualUnicodeString(image, &gImage, TRUE) ? DgTrack(process) : STATUS_ACCESS_DENIED;
        break;
    default: result = STATUS_INVALID_DEVICE_REQUEST; break;
    }
    if (NT_SUCCESS(result)) {
        DgStatus(&status);
        __try { RtlCopyMemory(Output, &status, sizeof(status)); *Returned = sizeof(status); }
        __except (EXCEPTION_EXECUTE_HANDLER) { result = GetExceptionCode(); }
    }
done:
    if (ownsConfiguration) InterlockedExchange(&gConfiguring, 0);
    if (image) ExFreePool(image);
    if (process) ObDereferenceObject(process);
    ExFreePoolWithTag(request, DG_TAG);
    return result;
}

static NTSTATUS DgConnect(PFLT_PORT Client, PVOID ServerCookie, PVOID Context,
        ULONG ContextSize, PVOID* Cookie) {
    UNREFERENCED_PARAMETER(ServerCookie); UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextSize); UNREFERENCED_PARAMETER(Cookie);
    DgLock();
    if (gController || InterlockedCompareExchange(&gConfigured, 0, 0)) {
        DgUnlock(); return STATUS_DEVICE_BUSY; /* Reconfiguration requires explicit unload/reload. */
    }
    gController = PsGetCurrentProcess(); ObReferenceObject(gController);
    gClientPort = Client;
    InterlockedExchange(&gConnected, 1);
    DgUnlock();
    return STATUS_SUCCESS;
}

static VOID DgDisconnect(PVOID Cookie) {
    PEPROCESS previous;
    UNREFERENCED_PARAMETER(Cookie);
    InterlockedExchange(&gConnected, 0);
    FltCloseClientPort(gFilter, &gClientPort);
    DgLock(); previous = gController; gController = NULL; DgUnlock();
    if (previous) ObDereferenceObject(previous);
    /* Roots remain configured: new user-mode access is denied after broker loss. */
}

static NTSTATUS DgInstanceSetup(PCFLT_RELATED_OBJECTS Objects, FLT_INSTANCE_SETUP_FLAGS Flags,
        DEVICE_TYPE DeviceType, FLT_FILESYSTEM_TYPE FileSystemType) {
    UNREFERENCED_PARAMETER(Objects); UNREFERENCED_PARAMETER(Flags); UNREFERENCED_PARAMETER(DeviceType);
    return FileSystemType == FLT_FSTYPE_NTFS ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}

static VOID DgCleanup(VOID) {
    if (gServerPort) { FltCloseCommunicationPort(gServerPort); gServerPort = NULL; }
    if (gObjectRegistration) { ObUnRegisterCallbacks(gObjectRegistration); gObjectRegistration = NULL; }
    if (gNotifyRegistered) { (VOID)PsSetCreateProcessNotifyRoutineEx(DgProcessNotify, TRUE); gNotifyRegistered = FALSE; }
    if (gFilter) { FltUnregisterFilter(gFilter); gFilter = NULL; }
    while (!IsListEmpty(&gProcesses)) {
        DG_PROCESS* node = CONTAINING_RECORD(RemoveHeadList(&gProcesses), DG_PROCESS, Link);
        ObDereferenceObject(node->Process); ExFreePoolWithTag(node, DG_TAG);
    }
}

static NTSTATUS DgUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    DgCleanup();
    return STATUS_SUCCESS; /* Explicit administrator recovery is never obstructed. */
}

static const FLT_CONTEXT_REGISTRATION gContexts[] = {
    { FLT_STREAMHANDLE_CONTEXT, 0, NULL, sizeof(DG_FILE_CONTEXT), DG_TAG, NULL, NULL, NULL },
    { FLT_CONTEXT_END, 0, NULL, 0, 0, NULL, NULL, NULL }
};
static const FLT_OPERATION_REGISTRATION gOperations[] = {
    { IRP_MJ_CREATE, 0, DgPreCreate, DgPostCreate, NULL },
    { IRP_MJ_READ, 0, DgPreIo, NULL, NULL },
    { IRP_MJ_WRITE, 0, DgPreIo, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, DgPreIo, NULL, NULL },
    { IRP_MJ_QUERY_INFORMATION, 0, DgPreIo, NULL, NULL },
    { IRP_MJ_DIRECTORY_CONTROL, 0, DgPreIo, NULL, NULL },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, DgPreIo, NULL, NULL },
    { IRP_MJ_OPERATION_END, 0, NULL, NULL, NULL }
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    FLT_REGISTRATION registration = {0};
    OB_OPERATION_REGISTRATION operations[2] = {0};
    OB_CALLBACK_REGISTRATION callbacks = {0};
    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"385201.4242"); /* Laboratory only; not a production allocation. */
    UNICODE_STRING portName = RTL_CONSTANT_STRING(DG_PORT_NAME);
    SECURITY_DESCRIPTOR descriptor;
    UCHAR aclBuffer[128];
    PACL acl = (PACL)aclBuffer;
    OBJECT_ATTRIBUTES attributes;
    UNREFERENCED_PARAMETER(RegistryPath);
    ExInitializePushLock(&gLock); InitializeListHead(&gProcesses);
    registration.Size = sizeof(registration);
    registration.Version = FLT_REGISTRATION_VERSION;
    registration.ContextRegistration = gContexts;
    registration.OperationRegistration = gOperations;
    registration.FilterUnloadCallback = DgUnload;
    registration.InstanceSetupCallback = DgInstanceSetup;
    status = FltRegisterFilter(DriverObject, &registration, &gFilter);
    if (!NT_SUCCESS(status)) return status;
    operations[0].ObjectType = PsProcessType;
    operations[1].ObjectType = PsThreadType;
    operations[0].Operations = operations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations[0].PreOperation = operations[1].PreOperation = DgObjectPre;
    callbacks.Version = OB_FLT_REGISTRATION_VERSION;
    callbacks.OperationRegistrationCount = 2;
    callbacks.Altitude = altitude;
    callbacks.OperationRegistration = operations;
    status = ObRegisterCallbacks(&callbacks, &gObjectRegistration);
    if (!NT_SUCCESS(status)) goto failure;
    status = PsSetCreateProcessNotifyRoutineEx(DgProcessNotify, FALSE);
    if (!NT_SUCCESS(status)) goto failure;
    gNotifyRegistered = TRUE;
    status = RtlCreateSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) goto failure;
    status = RtlCreateAcl(acl, sizeof(aclBuffer), ACL_REVISION);
    if (!NT_SUCCESS(status)) goto failure;
    status = RtlAddAccessAllowedAce(acl, ACL_REVISION, FLT_PORT_ALL_ACCESS, SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status)) goto failure;
    status = RtlSetDaclSecurityDescriptor(&descriptor, TRUE, acl, FALSE);
    if (!NT_SUCCESS(status)) goto failure;
    InitializeObjectAttributes(&attributes, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, &descriptor);
    status = FltCreateCommunicationPort(gFilter, &gServerPort, &attributes, NULL,
        DgConnect, DgDisconnect, DgMessage, 1);
    if (!NT_SUCCESS(status)) goto failure;
    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) goto failure;
    return STATUS_SUCCESS;
failure:
    DgCleanup();
    return status;
}
