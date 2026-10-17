#pragma once

/* Fixed-size messages: no caller-supplied kernel pointers or arbitrary IOCTLs. */
#define DG_PROTOCOL_VERSION 1u
#define DG_PATH_CHARS 512u
#define DG_PORT_NAME L"\\DiscordGuardCorePort"
#define DG_PIPE_NAME L"\\\\.\\pipe\\DiscordGuardCore"
#define DG_SERVICE_NAME L"DiscordGuardBroker"

enum DG_OPERATION { DgQuery = 1, DgConfigure = 2, DgEnroll = 3 };
enum DG_PIPE_OPERATION { DgPipeQuery = 1, DgPipeLaunch = 2 };

typedef struct DG_REQUEST {
    unsigned long Version;
    unsigned long Operation;
    unsigned long long ProcessHandle;
    wchar_t ProfileRoot[DG_PATH_CHARS];
    wchar_t InstallRoot[DG_PATH_CHARS];
    wchar_t ImagePath[DG_PATH_CHARS];
} DG_REQUEST;

typedef struct DG_STATUS {
    unsigned long Version;
    unsigned long Configured;
    unsigned long ControllerConnected;
    unsigned long ProcessCallbacks;
    unsigned long TrackedProcesses;
    unsigned long DeniedFileOperations;
    unsigned long StrippedHandles;
    unsigned long UnclassifiedFileOperations;
} DG_STATUS;

typedef struct DG_PIPE_REQUEST {
    unsigned long Version;
    unsigned long Operation;
} DG_PIPE_REQUEST;

typedef struct DG_PIPE_REPLY {
    unsigned long Version;
    unsigned long Error;
    DG_STATUS Status;
} DG_PIPE_REPLY;
