// LocalSystem broker and a status/launch client. No secret extraction or remote endpoint.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fltuser.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <algorithm>
#include <cwctype>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include "guard_protocol.h"

class Handle {
    HANDLE value_ = nullptr;
public:
    Handle() = default;
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    HANDLE* out() { return &value_; }
};

static SERVICE_STATUS_HANDLE gServiceHandle;
static SERVICE_STATUS gServiceStatus{};
static HANDLE gStop;
static HANDLE gPort;
static std::wstring gSid, gImage, gProfile, gInstall;

static void Require(bool ok, const char* detail) {
    if (!ok) throw std::runtime_error(detail);
}

static bool Equal(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
}

static std::wstring TokenSid(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    Require(size > 0, "Token user unavailable");
    std::vector<BYTE> buffer(size);
    Require(GetTokenInformation(token, TokenUser, buffer.data(), size, &size) != FALSE, "Token user unavailable");
    LPWSTR text = nullptr;
    Require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &text) != FALSE,
            "Token SID unavailable");
    std::wstring result(text);
    LocalFree(text);
    return result;
}

static bool IsSystemProcess(HANDLE process) {
    Handle token;
    return OpenProcessToken(process, TOKEN_QUERY, token.out()) && TokenSid(token.get()) == L"S-1-5-18";
}

static void RejectReparse(std::wstring path) {
    Require(path.size() >= 3 && path[1] == L':' && path[2] == L'\\', "Only local absolute paths are supported");
    for (;;) {
        DWORD attributes = GetFileAttributesW(path.c_str());
        Require(attributes != INVALID_FILE_ATTRIBUTES, "Required file or directory missing");
        Require(!(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "Reparse paths are not permitted");
        const auto slash = path.find_last_of(L'\\');
        if (slash == std::wstring::npos || slash <= 2) break;
        path.resize(slash);
    }
}

static std::wstring NativePath(const std::wstring& path) {
    RejectReparse(path);
    wchar_t device[32768]{};
    Require(QueryDosDeviceW(path.substr(0, 2).c_str(), device, ARRAYSIZE(device)) != 0,
            "Drive mapping unavailable");
    std::wstring result = std::wstring(device) + path.substr(2);
    Require(result.size() < DG_PATH_CHARS && result.rfind(L"\\Device\\HarddiskVolume", 0) == 0,
            "An NTFS local volume path is required");
    return result;
}

static bool VerifyDiscord(const std::wstring& image) {
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = image.c_str();
    WINTRUST_DATA trust{};
    trust.cbStruct = sizeof(trust);
    trust.dwUIChoice = WTD_UI_NONE;
    trust.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE;
    trust.pFile = &file;
    trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = WinVerifyTrust(nullptr, &action, &trust);
    bool allowed = false;
    if (result == ERROR_SUCCESS) {
        auto provider = WTHelperProvDataFromStateData(trust.hWVTStateData);
        auto signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
        if (signer && signer->csCertChain && signer->pasCertChain[0].pCert) {
            wchar_t organisation[128]{};
            CertGetNameStringW(signer->pasCertChain[0].pCert, CERT_NAME_ATTR_TYPE, 0,
                const_cast<char*>(szOID_ORGANIZATION_NAME), organisation, ARRAYSIZE(organisation));
            allowed = Equal(organisation, L"Discord Inc.");
        }
    }
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trust);
    return allowed;
}

static bool StandardEntry(const std::wstring& image) {
    const std::wstring directory = image.substr(0, image.find_last_of(L'\\'));
    if (GetFileAttributesW((directory + L"\\resources\\app").c_str()) != INVALID_FILE_ATTRIBUTES) return false;
    RejectReparse(directory + L"\\resources\\app.asar");
    WIN32_FIND_DATAW found{};
    HANDLE search = FindFirstFileW((directory + L"\\modules\\discord_desktop_core-*").c_str(), &found);
    if (search == INVALID_HANDLE_VALUE) return false;
    std::wstring core;
    unsigned int count = 0;
    do {
        if (found.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { core = found.cFileName; ++count; }
    } while (FindNextFileW(search, &found));
    FindClose(search);
    if (count != 1) return false;
    core = directory + L"\\modules\\" + core + L"\\discord_desktop_core";
    RejectReparse(core + L"\\core.asar");
    const std::wstring entry = core + L"\\index.js";
    RejectReparse(entry);
    Handle file(CreateFileW(entry.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE || GetFileSize(file.get(), nullptr) >= 512) return false;
    char bytes[512]{};
    DWORD size = 0;
    if (!ReadFile(file.get(), bytes, sizeof(bytes) - 1, &size, nullptr)) return false;
    std::string compact;
    for (DWORD index = 0; index < size; ++index) {
        const char ch = bytes[index];
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;
        compact += ch == '"' ? '\'' : ch;
    }
    if (!compact.empty() && compact.back() == ';') compact.pop_back();
    return compact == "module.exports=require('./core.asar')";
}

static bool IsStandardToken(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenGroups, nullptr, 0, &size);
    if (!size) return false;
    std::vector<BYTE> buffer(size);
    if (!GetTokenInformation(token, TokenGroups, buffer.data(), size, &size)) return false;
    BYTE admin[SECURITY_MAX_SID_SIZE]{};
    DWORD adminSize = sizeof(admin);
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admin, &adminSize)) return false;
    const auto groups = reinterpret_cast<TOKEN_GROUPS*>(buffer.data());
    for (DWORD index = 0; index < groups->GroupCount; ++index)
        if (EqualSid(groups->Groups[index].Sid, admin)) return false; // Also reject deny-only admin memberships.
    return true;
}

static void ReadConfiguration() {
    PSID sid = nullptr;
    Require(ConvertStringSidToSidW(gSid.c_str(), &sid) != FALSE, "Invalid protected SID");
    LocalFree(sid);
    Require(gSid.rfind(L"S-1-5-21-", 0) == 0, "Only a local user SID is supported");
    const std::wstring key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + gSid;
    wchar_t registered[32768]{};
    DWORD bytes = sizeof(registered);
    Require(RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), L"ProfileImagePath", RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                        nullptr, registered, &bytes) == ERROR_SUCCESS, "Protected Windows profile is missing");
    std::wstring profile(registered);
    gProfile = profile + L"\\AppData\\Roaming\\discord";
    gInstall = profile + L"\\AppData\\Local\\Discord";
    Require(gImage.size() > gInstall.size() && Equal(gImage.substr(0, gInstall.size()), gInstall) &&
            gImage[gInstall.size()] == L'\\', "Discord image must be inside the protected installation");
    const std::wstring suffix = gImage.substr(gInstall.size() + 1);
    const auto slash = suffix.find(L'\\');
    Require(suffix.rfind(L"app-", 0) == 0 && slash != std::wstring::npos &&
            Equal(suffix.substr(slash + 1), L"Discord.exe") && suffix.find(L'\\', slash + 1) == std::wstring::npos,
            "Only the standard Discord desktop image is supported");
    const std::wstring version = suffix.substr(4, slash - 4);
    Require(!version.empty() && version.front() != L'.' && version.back() != L'.' &&
        version.find(L"..") == std::wstring::npos && std::count(version.begin(), version.end(), L'.') == 2 &&
        std::all_of(version.begin(), version.end(), [](wchar_t ch) { return (ch >= L'0' && ch <= L'9') || ch == L'.'; }),
        "Unexpected desktop version directory");
    RejectReparse(gProfile); RejectReparse(gInstall); RejectReparse(gImage);
    Require(VerifyDiscord(gImage), "Discord Inc. Authenticode signature was not verified");
    Require(StandardEntry(gImage), "Standard Discord core loader was not verified");
}

static DWORD DriverMessage(DG_REQUEST& request, DG_STATUS& reply) {
    DWORD returned = 0;
    request.Version = DG_PROTOCOL_VERSION;
    HRESULT result = FilterSendMessage(gPort, &request, sizeof(request), &reply, sizeof(reply), &returned);
    if (FAILED(result)) return HRESULT_CODE(result);
    return returned == sizeof(reply) && reply.Version == DG_PROTOCOL_VERSION ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

static std::vector<wchar_t> SafeEnvironment(HANDLE token) {
    LPVOID raw = nullptr;
    Require(CreateEnvironmentBlock(&raw, token, FALSE) != FALSE, "User environment unavailable");
    std::vector<wchar_t> result;
    for (auto item = static_cast<const wchar_t*>(raw); *item; item += wcslen(item) + 1) {
        std::wstring name(item);
        std::transform(name.begin(), name.end(), name.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towupper(ch)); });
        if (name.rfind(L"NODE_", 0) == 0 || name.rfind(L"ELECTRON_", 0) == 0 ||
            name.rfind(L"CHROME_", 0) == 0 || name.rfind(L"CHROMIUM_", 0) == 0) continue;
        result.insert(result.end(), item, item + wcslen(item) + 1);
    }
    DestroyEnvironmentBlock(raw);
    result.push_back(L'\0');
    return result;
}

static DWORD Launch(DWORD session) {
    Handle token;
    if (!WTSQueryUserToken(session, token.out())) return GetLastError();
    if (TokenSid(token.get()) != gSid || !IsStandardToken(token.get())) return ERROR_ACCESS_DENIED;
    RejectReparse(gImage);
    if (!VerifyDiscord(gImage) || !StandardEntry(gImage)) return ERROR_INVALID_IMAGE_HASH;
    DG_REQUEST query{};
    query.Operation = DgQuery;
    DG_STATUS current{};
    DWORD error = DriverMessage(query, current);
    if (error) return error;
    if (!current.Configured || !current.ControllerConnected || !current.ProcessCallbacks) return ERROR_NOT_READY;
    if (current.TrackedProcesses) return ERROR_ALREADY_EXISTS;
    auto environment = SafeEnvironment(token.get());
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    wchar_t desktop[] = L"winsta0\\default";
    startup.lpDesktop = desktop;
    PROCESS_INFORMATION process{};
    std::wstring command = L"\"" + gImage + L"\"";
    const std::wstring directory = gImage.substr(0, gImage.find_last_of(L'\\'));
    if (!CreateProcessAsUserW(token.get(), gImage.c_str(), command.data(), nullptr, nullptr, FALSE,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, environment.data(), directory.c_str(), &startup, &process))
        return GetLastError();
    Handle processHandle(process.hProcess), threadHandle(process.hThread);
    DG_REQUEST enroll{};
    enroll.Operation = DgEnroll;
    enroll.ProcessHandle = reinterpret_cast<ULONG_PTR>(process.hProcess);
    error = DriverMessage(enroll, current);
    if (!error && ResumeThread(process.hThread) == static_cast<DWORD>(-1)) error = GetLastError();
    if (error) TerminateProcess(process.hProcess, error); // It has never executed user code.
    return error;
}

static bool Transfer(HANDLE pipe, void* data, DWORD bytes, bool write) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    DWORD done = 0;
    BOOL result = write ? WriteFile(pipe, data, bytes, &done, &overlapped) : ReadFile(pipe, data, bytes, &done, &overlapped);
    if (!result && GetLastError() == ERROR_IO_PENDING) {
        HANDLE waits[] = { gStop, event.get() };
        if (WaitForMultipleObjects(2, waits, FALSE, 5000) != WAIT_OBJECT_0 + 1) {
            CancelIoEx(pipe, &overlapped);
            GetOverlappedResult(pipe, &overlapped, &done, TRUE);
            return false;
        }
        result = GetOverlappedResult(pipe, &overlapped, &done, FALSE);
    }
    return result && done == bytes;
}

static void Serve() {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GRGW;;;AU)",
        SDDL_REVISION_1, &descriptor, nullptr) != FALSE, "Pipe security unavailable");
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    Handle pipe(CreateNamedPipeW(DG_PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, sizeof(DG_PIPE_REPLY), sizeof(DG_PIPE_REQUEST), 0, &security));
    LocalFree(descriptor);
    Require(pipe.get() != INVALID_HANDLE_VALUE, "Broker pipe unavailable or already owned");
    while (WaitForSingleObject(gStop, 0) != WAIT_OBJECT_0) {
        Handle connected(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        OVERLAPPED overlapped{};
        overlapped.hEvent = connected.get();
        BOOL success = ConnectNamedPipe(pipe.get(), &overlapped);
        DWORD error = success ? ERROR_SUCCESS : GetLastError();
        if (error == ERROR_IO_PENDING) {
            HANDLE waits[] = {gStop, connected.get()};
            if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) == WAIT_OBJECT_0) {
                CancelIoEx(pipe.get(), &overlapped);
                DWORD ignored = 0;
                GetOverlappedResult(pipe.get(), &overlapped, &ignored, TRUE);
                break;
            }
        } else if (error != ERROR_PIPE_CONNECTED && error != ERROR_SUCCESS) break;
        DG_PIPE_REQUEST request{};
        DG_PIPE_REPLY reply{};
        reply.Version = DG_PROTOCOL_VERSION;
        reply.Error = ERROR_INVALID_PARAMETER;
        if (Transfer(pipe.get(), &request, sizeof(request), false) && request.Version == DG_PROTOCOL_VERSION) {
            try {
                if (request.Operation == DgPipeQuery) reply.Error = ERROR_SUCCESS;
                else if (request.Operation == DgPipeLaunch) {
                    Require(ImpersonateNamedPipeClient(pipe.get()) != FALSE, "Client impersonation failed");
                    Handle token;
                    DWORD session = 0, size = sizeof(session);
                    bool valid = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, token.out()) != FALSE;
                    if (valid) valid = TokenSid(token.get()) == gSid &&
                        GetTokenInformation(token.get(), TokenSessionId, &session, sizeof(session), &size);
                    RevertToSelf();
                    reply.Error = valid && session ? Launch(session) : ERROR_ACCESS_DENIED;
                }
                if (reply.Error == ERROR_SUCCESS || reply.Error == ERROR_ALREADY_EXISTS) {
                    DG_REQUEST query{};
                    query.Operation = DgQuery;
                    DWORD statusError = DriverMessage(query, reply.Status);
                    if (statusError) reply.Error = statusError;
                }
            } catch (...) { RevertToSelf(); reply.Error = ERROR_ACCESS_DENIED; }
            Transfer(pipe.get(), &reply, sizeof(reply), true);
        }
        DisconnectNamedPipe(pipe.get());
    }
}

static void Report(DWORD state, DWORD error = 0) {
    gServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gServiceStatus.dwCurrentState = state;
    gServiceStatus.dwWin32ExitCode = error;
    gServiceStatus.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
    gServiceStatus.dwWaitHint = state == SERVICE_START_PENDING ? 10000 : 0;
    SetServiceStatus(gServiceHandle, &gServiceStatus);
}

static DWORD WINAPI Control(DWORD code, DWORD, void*, void*) {
    if (code == SERVICE_CONTROL_STOP) SetEvent(gStop);
    return ERROR_SUCCESS;
}

static void WINAPI ServiceMain(DWORD, wchar_t**) {
    gServiceHandle = RegisterServiceCtrlHandlerExW(DG_SERVICE_NAME, Control, nullptr);
    if (!gServiceHandle) return;
    Report(SERVICE_START_PENDING);
    DWORD error = ERROR_SUCCESS;
    try {
        Require(IsSystemProcess(GetCurrentProcess()), "Broker requires LocalSystem");
        ReadConfiguration();
        Handle port;
        Require(SUCCEEDED(FilterConnectCommunicationPort(DG_PORT_NAME, 0, nullptr, 0, nullptr, port.out())),
                "Signed GuardCore driver is not connected");
        gPort = port.get();
        DG_REQUEST configure{};
        configure.Operation = DgConfigure;
        const std::wstring profile = NativePath(gProfile), install = NativePath(gInstall), image = NativePath(gImage);
        wcscpy_s(configure.ProfileRoot, profile.c_str());
        wcscpy_s(configure.InstallRoot, install.c_str());
        wcscpy_s(configure.ImagePath, image.c_str());
        DG_STATUS status{};
        Require(DriverMessage(configure, status) == ERROR_SUCCESS && status.Configured && status.ProcessCallbacks,
                "Driver configuration rejected");
        Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        gStop = stop.get();
        Report(SERVICE_RUNNING);
        Serve();
        gStop = nullptr; gPort = nullptr;
    } catch (...) { error = ERROR_SERVICE_SPECIFIC_ERROR; }
    Report(SERVICE_STOPPED, error);
}

static DWORD Client(unsigned long operation) {
    if (!WaitNamedPipeW(DG_PIPE_NAME, 2000)) {
        DWORD error = GetLastError();
        std::cout << "{\"available\":false,\"error\":" << error << "}\n";
        return error;
    }
    Handle pipe(CreateFileW(DG_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr));
    if (pipe.get() == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cout << "{\"available\":false,\"error\":" << error << "}\n";
        return error;
    }
    ULONG pid = 0;
    Require(GetNamedPipeServerProcessId(pipe.get(), &pid) != FALSE, "Broker PID unavailable");
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    Require(manager != nullptr, "Service manager unavailable");
    SC_HANDLE service = OpenServiceW(manager, DG_SERVICE_NAME, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    bool verified = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&status), sizeof(status), &needed) && status.dwProcessId == pid &&
        status.dwCurrentState == SERVICE_RUNNING;
    if (verified) {
        QueryServiceConfigW(service, nullptr, 0, &needed);
        std::vector<BYTE> configBytes(needed);
        auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBytes.data());
        wchar_t self[32768]{};
        verified = needed && QueryServiceConfigW(service, config, needed, &needed) &&
            GetModuleFileNameW(nullptr, self, ARRAYSIZE(self)) &&
            config->dwServiceType == SERVICE_WIN32_OWN_PROCESS && Equal(config->lpServiceStartName, L"LocalSystem");
        if (verified) {
            const std::wstring prefix = std::wstring(L"\"") + self + L"\" --service --sid ";
            const std::wstring configured(config->lpBinaryPathName);
            verified = configured.size() > prefix.size() && Equal(configured.substr(0, prefix.size()), prefix);
        }
    }
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    Require(verified, "Pipe is not owned by the registered broker service");
    DWORD mode = PIPE_READMODE_MESSAGE;
    Require(SetNamedPipeHandleState(pipe.get(), &mode, nullptr, nullptr) != FALSE, "Pipe mode unavailable");
    DG_PIPE_REQUEST request{DG_PROTOCOL_VERSION, operation};
    DG_PIPE_REPLY reply{};
    DWORD transferred = 0;
    Require(TransactNamedPipe(pipe.get(), &request, sizeof(request), &reply, sizeof(reply), &transferred, nullptr) &&
        transferred == sizeof(reply) && reply.Version == DG_PROTOCOL_VERSION, "Broker reply invalid");
    std::cout << "{\"available\":true,\"error\":" << reply.Error
        << ",\"configured\":" << reply.Status.Configured
        << ",\"connected\":" << reply.Status.ControllerConnected
        << ",\"process_callbacks\":" << reply.Status.ProcessCallbacks
        << ",\"tracked_processes\":" << reply.Status.TrackedProcesses
        << ",\"denied_file_operations\":" << reply.Status.DeniedFileOperations
        << ",\"stripped_handles\":" << reply.Status.StrippedHandles
        << ",\"unclassified_file_operations\":" << reply.Status.UnclassifiedFileOperations << "}\n";
    return reply.Error == ERROR_ALREADY_EXISTS ? ERROR_SUCCESS : reply.Error;
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 6 && Equal(argv[1], L"--service") && Equal(argv[2], L"--sid") && Equal(argv[4], L"--image")) {
            gSid = argv[3]; gImage = argv[5];
            SERVICE_TABLE_ENTRYW table[] = {{const_cast<wchar_t*>(DG_SERVICE_NAME), ServiceMain}, {nullptr, nullptr}};
            return StartServiceCtrlDispatcherW(table) ? 0 : static_cast<int>(GetLastError());
        }
        if (argc == 2 && (Equal(argv[1], L"--query") || Equal(argv[1], L"--launch"))) {
            /* Client prints one validated JSON reply; early connection failures are exceptions. */
            return Client(Equal(argv[1], L"--query") ? DgPipeQuery : DgPipeLaunch) ? 1 : 0;
        }
        std::cerr << "Usage: GuardCoreCtl --query | --launch (driver VM service is configured by install-vm.ps1)\n";
        return 2;
    } catch (...) {
        std::cout << "{\"available\":false,\"error\":5}\n";
        return 1;
    }
}
