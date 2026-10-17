// Passwordless virtual-account broker. The desktop app never runs as SYSTEM.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <winhttp.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;
constexpr wchar_t Broker[] = L"DiscordGuardDesktop";
constexpr wchar_t Identity[] = L"DiscordGuardIdentity";
constexpr wchar_t IdentityAccount[] = L"NT SERVICE\\DiscordGuardIdentity";
constexpr wchar_t Pipe[] = L"\\\\.\\pipe\\DiscordGuard.Desktop.v1";
constexpr wchar_t Registry[] = L"SOFTWARE\\DiscordGuard\\Desktop";
constexpr DWORD Protocol = 1;
struct Request { DWORD version, operation; }; // 0 status, 1 install/launch, 2 harmless boundary probe
struct Reply {
    DWORD version, error, ready, installed, running, identityPid;
    DWORD probePid = 0, fileDenied = 0, memoryDenied = 0;
    wchar_t fixture[MAX_PATH]{};
};

class Handle {
    HANDLE value_ = nullptr;
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() { if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const { return value_; }
    HANDLE* out() { return &value_; }
};
class ServiceHandle {
    SC_HANDLE value_;
public:
    explicit ServiceHandle(SC_HANDLE value) : value_(value) {}
    ~ServiceHandle() { if (value_) CloseServiceHandle(value_); }
    SC_HANDLE get() const { return value_; }
};
class InternetHandle {
    HINTERNET value_;
public:
    explicit InternetHandle(HINTERNET value) : value_(value) {}
    ~InternetHandle() { if (value_) WinHttpCloseHandle(value_); }
    HINTERNET get() const { return value_; }
};
class Security {
    PSECURITY_DESCRIPTOR value_ = nullptr;
public:
    explicit Security(const std::wstring& sddl) {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &value_, nullptr))
            throw std::runtime_error("security descriptor");
    }
    ~Security() { LocalFree(value_); }
    PSECURITY_DESCRIPTOR get() const { return value_; }
};
static HANDLE stopEvent;
static SERVICE_STATUS_HANDLE statusHandle;
static SERVICE_STATUS serviceStatus{};
static bool identityMode;

static void Check(bool ok) {
    if (!ok) {
        const auto error = GetLastError();
        throw std::system_error(static_cast<int>(error ? error : ERROR_INVALID_DATA), std::system_category());
    }
}
static bool Equal(const std::wstring& a, const std::wstring& b) {
    return CompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, TRUE) == CSTR_EQUAL;
}
static std::wstring SidText(PSID sid) {
    LPWSTR text = nullptr;
    Check(ConvertSidToStringSidW(sid, &text) != FALSE);
    std::wstring result(text); LocalFree(text); return result;
}
static std::wstring TokenSid(HANDLE token) {
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    Check(size > 0);
    std::vector<BYTE> data(size);
    Check(GetTokenInformation(token, TokenUser, data.data(), size, &size) != FALSE);
    return SidText(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid);
}
static std::wstring IdentitySid() {
    BYTE sid[SECURITY_MAX_SID_SIZE]{};
    wchar_t domain[256]{};
    DWORD size = sizeof(sid), domainSize = ARRAYSIZE(domain);
    SID_NAME_USE use{};
    Check(LookupAccountNameW(nullptr, IdentityAccount, sid, &size, domain, &domainSize, &use) != FALSE);
    return SidText(sid);
}
static std::wstring Self() {
    wchar_t path[32768]{};
    DWORD size = GetModuleFileNameW(nullptr, path, ARRAYSIZE(path));
    Check(size && size < ARRAYSIZE(path)); return path;
}
static std::wstring Origin() {
    wchar_t value[256]{};
    DWORD size = sizeof(value);
    Check(RegGetValueW(HKEY_LOCAL_MACHINE, Registry, L"OriginSid", RRF_RT_REG_SZ, nullptr, value, &size) == ERROR_SUCCESS);
    Check(std::regex_match(value, std::wregex(L"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+")));
    return value;
}
static void NoReparse(fs::path path) {
    Check(path.is_absolute() && !path.root_name().empty() && path.native().rfind(L"\\\\", 0) != 0);
    for (;;) {
        DWORD attributes = GetFileAttributesW(path.c_str());
        Check(attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT));
        if (path == path.root_path()) break;
        path = path.parent_path();
    }
}
static bool PrivateAcl(const fs::path& path, const std::wstring& sid) {
    NoReparse(path);
    PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR raw = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                             &owner, nullptr, &acl, nullptr, &raw) != ERROR_SUCCESS) return false;
    const auto trusted = [&](PSID candidate) {
        const auto text = SidText(candidate);
        return text == sid || text == L"S-1-5-18" || text == L"S-1-5-32-544";
    };
    bool allowed = owner && acl && trusted(owner) && acl->AceCount > 0;
    for (DWORD index = 0; allowed && index < acl->AceCount; ++index) {
        void* rawAce = nullptr;
        if (!GetAce(acl, index, &rawAce)) { allowed = false; break; }
        const auto header = static_cast<ACE_HEADER*>(rawAce);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(rawAce);
            // Conservative: any effective allow for another principal is refused.
            if (ace->Mask && !trusted(&ace->SidStart)) allowed = false;
        } else if (header->AceType != ACCESS_DENIED_ACE_TYPE) allowed = false;
    }
    LocalFree(raw); return allowed;
}
static void PrivateTree(const fs::path& root, const std::wstring& sid) {
    Check(PrivateAcl(root, sid));
    size_t count = 0;
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        Check(++count < 50000);
        Check(PrivateAcl(entry.path(), sid));
    }
}
static fs::path Profile(HANDLE token) {
    DWORD size = 32768;
    std::vector<wchar_t> value(size);
    Check(GetUserProfileDirectoryW(token, value.data(), &size) != FALSE);
    fs::path result(value.data());
    NoReparse(result);
    Check(PrivateAcl(result, IdentitySid()));
    return result;
}
static void PrivateDirectory(const fs::path& path, const std::wstring& sid) {
    if (fs::exists(path)) { Check(PrivateAcl(path, sid)); return; }
    NoReparse(path.parent_path());
    Security descriptor(L"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + sid + L")");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.get(), FALSE};
    Check(CreateDirectoryW(path.c_str(), &attributes) != FALSE);
}
static DWORD ServicePid(const wchar_t* name, const std::wstring& account, const std::wstring& argument) {
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    Check(manager.get() != nullptr);
    ServiceHandle service(OpenServiceW(manager.get(), name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG));
    Check(service.get() != nullptr);
    DWORD size = 0;
    QueryServiceConfigW(service.get(), nullptr, 0, &size);
    Check(size > 0);
    std::vector<BYTE> buffer(size);
    auto config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    Check(QueryServiceConfigW(service.get(), config, size, &size) != FALSE);
    Check(Equal(config->lpServiceStartName, account));
    Check(Equal(config->lpBinaryPathName, L"\"" + Self() + L"\" " + argument));
    SERVICE_STATUS_PROCESS status{};
    Check(QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&status), sizeof(status), &size) != FALSE);
    Check(status.dwCurrentState == SERVICE_RUNNING && status.dwProcessId != 0);
    return status.dwProcessId;
}
static DWORD IdentityToken(Handle& token) {
    DWORD pid = ServicePid(Identity, IdentityAccount, L"--identity-service");
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    Check(process.get() && OpenProcessToken(process.get(), TOKEN_QUERY | TOKEN_DUPLICATE, token.out()));
    Check(TokenSid(token.get()) == IdentitySid());
    return pid;
}
static bool SignedDiscord(const fs::path& image) {
    WINTRUST_FILE_INFO file{}; file.cbStruct = sizeof(file); file.pcwszFilePath = image.c_str();
    WINTRUST_DATA trust{}; trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
    trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &file; trust.dwStateAction = WTD_STATEACTION_VERIFY;
    trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    bool valid = false;
    if (WinVerifyTrust(nullptr, &action, &trust) == ERROR_SUCCESS) {
        const auto provider = WTHelperProvDataFromStateData(trust.hWVTStateData);
        const auto signer = provider ? WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0) : nullptr;
        if (signer && signer->csCertChain && signer->pasCertChain[0].pCert) {
            wchar_t organisation[128]{};
            CertGetNameStringW(signer->pasCertChain[0].pCert, CERT_NAME_ATTR_TYPE, 0,
                const_cast<char*>(szOID_ORGANIZATION_NAME), organisation, ARRAYSIZE(organisation));
            valid = Equal(organisation, L"Discord Inc.");
        }
    }
    trust.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust(nullptr, &action, &trust);
    return valid;
}
static fs::path DiscordImage(const fs::path& profile) {
    const auto root = profile / L"AppData\\Local\\Discord";
    if (!fs::exists(root)) return {};
    PrivateTree(root, IdentitySid());
    std::vector<unsigned long> selectedVersion;
    fs::path selected;
    const std::wregex pattern(L"app-([0-9]+)\\.([0-9]+)\\.([0-9]+)");
    for (const auto& entry : fs::directory_iterator(root)) {
        std::wsmatch match;
        const auto name = entry.path().filename().wstring();
        if (!entry.is_directory() || !std::regex_match(name, match, pattern)) continue;
        const std::vector<unsigned long> version{std::stoul(match[1]), std::stoul(match[2]), std::stoul(match[3])};
        if (selected.empty() || version > selectedVersion) { selected = entry.path(); selectedVersion = version; }
    }
    if (selected.empty()) return {};
    const auto image = selected / L"Discord.exe";
    Check(fs::is_regular_file(image) && SignedDiscord(image));
    Check(!fs::exists(selected / L"resources\\app") && fs::is_regular_file(selected / L"resources\\app.asar"));
    size_t cores = 0;
    for (const auto& entry : fs::directory_iterator(selected / L"modules")) {
        if (!entry.is_directory() || !std::regex_match(entry.path().filename().wstring(), std::wregex(L"discord_desktop_core-[0-9]+"))) continue;
        ++cores;
        const auto core = entry.path() / L"discord_desktop_core";
        Check(fs::is_regular_file(core / L"core.asar"));
        const auto loader = core / L"index.js";
        Check(fs::file_size(loader) < 512);
        Handle file(CreateFileW(loader.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
        char data[512]{}; DWORD bytes = 0;
        Check(file.get() != INVALID_HANDLE_VALUE && ReadFile(file.get(), data, sizeof(data) - 1, &bytes, nullptr));
        std::string compact;
        for (DWORD index = 0; index < bytes; ++index) {
            const auto ch = data[index];
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;
            compact += ch == '"' ? '\'' : ch;
        }
        if (!compact.empty() && compact.back() == ';') compact.pop_back();
        Check(compact == "module.exports=require('./core.asar')");
    }
    Check(cores == 1); return image;
}
static void EnablePrivilege(const wchar_t* name) {
    Handle token; Check(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, token.out()) != FALSE);
    TOKEN_PRIVILEGES privileges{}; privileges.PrivilegeCount = 1;
    Check(LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid) != FALSE);
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    Check(AdjustTokenPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr) && GetLastError() == ERROR_SUCCESS);
}
static DWORD Spawn(HANDLE identityToken, DWORD session, const fs::path& image, const std::wstring& arguments, bool wait) {
    Handle restricted, primary;
    Check(CreateRestrictedToken(identityToken, DISABLE_MAX_PRIVILEGE, 0, nullptr, 0, nullptr, 0, nullptr, restricted.out()) != FALSE);
    Check(DuplicateTokenEx(restricted.get(), TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, primary.out()) != FALSE);
    Check(SetTokenInformation(primary.get(), TokenSessionId, &session, sizeof(session)) != FALSE);
    BYTE medium[SECURITY_MAX_SID_SIZE]{}; DWORD sidSize = sizeof(medium);
    Check(CreateWellKnownSid(WinMediumLabelSid, nullptr, medium, &sidSize) != FALSE);
    TOKEN_MANDATORY_LABEL label{{medium, SE_GROUP_INTEGRITY}};
    Check(SetTokenInformation(primary.get(), TokenIntegrityLevel, &label, sizeof(label) + sidSize) != FALSE);
    Check(TokenSid(primary.get()) == IdentitySid());
    LPVOID rawEnvironment = nullptr;
    Check(CreateEnvironmentBlock(&rawEnvironment, primary.get(), FALSE) != FALSE);
    std::vector<wchar_t> environment;
    for (auto item = static_cast<const wchar_t*>(rawEnvironment); *item; item += wcslen(item) + 1) {
        std::wstring upper(item);
        std::transform(upper.begin(), upper.end(), upper.begin(), [](wchar_t ch) { return static_cast<wchar_t>(towupper(ch)); });
        if (upper.rfind(L"NODE_", 0) == 0 || upper.rfind(L"ELECTRON_", 0) == 0 ||
            upper.rfind(L"CHROME_", 0) == 0 || upper.rfind(L"CHROMIUM_", 0) == 0) continue;
        environment.insert(environment.end(), item, item + wcslen(item) + 1);
    }
    DestroyEnvironmentBlock(rawEnvironment); environment.push_back(0);
    std::wstring command = L"\"" + image.wstring() + L"\"" + arguments;
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    wchar_t desktop[] = L"winsta0\\default"; startup.lpDesktop = desktop;
    PROCESS_INFORMATION process{};
    Check(CreateProcessAsUserW(primary.get(), image.c_str(), command.data(), nullptr, nullptr, FALSE,
        CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW, environment.data(), image.parent_path().c_str(), &startup, &process) != FALSE);
    Handle child(process.hProcess), thread(process.hThread);
    if (wait) {
        Check(WaitForSingleObject(child.get(), 300000) == WAIT_OBJECT_0);
        DWORD code = 1; Check(GetExitCodeProcess(child.get(), &code) && code == 0);
    }
    return process.dwProcessId;
}
static bool OfficialHost(const std::wstring& host) {
    for (const std::wstring suffix : {L"discord.com", L"discordapp.com", L"discordapp.net"}) {
        if (Equal(host, suffix) || (host.size() > suffix.size() &&
            host[host.size() - suffix.size() - 1] == L'.' && Equal(host.substr(host.size() - suffix.size()), suffix))) return true;
    }
    return false;
}
static void Download(const fs::path& destination) {
    InternetHandle internet(WinHttpOpen(L"DiscordGuard/0.8", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    Check(internet.get() != nullptr);
    Check(WinHttpSetTimeouts(internet.get(), 15000, 15000, 30000, 30000) != FALSE);
    std::wstring url = L"https://discord.com/api/download?platform=win";
    for (unsigned redirect = 0; redirect < 8; ++redirect) {
        URL_COMPONENTS components{}; components.dwStructSize = sizeof(components);
        components.dwHostNameLength = components.dwUrlPathLength = components.dwExtraInfoLength = static_cast<DWORD>(-1);
        components.dwUserNameLength = components.dwPasswordLength = static_cast<DWORD>(-1);
        Check(WinHttpCrackUrl(url.c_str(), 0, 0, &components) != FALSE);
        std::wstring host(components.lpszHostName, components.dwHostNameLength);
        Check(components.nScheme == INTERNET_SCHEME_HTTPS && components.nPort == 443 && OfficialHost(host)
              && !components.dwUserNameLength && !components.dwPasswordLength);
        std::wstring target(components.lpszUrlPath, components.dwUrlPathLength);
        if (components.dwExtraInfoLength) target.append(components.lpszExtraInfo, components.dwExtraInfoLength);
        InternetHandle connection(WinHttpConnect(internet.get(), host.c_str(), 443, 0));
        Check(connection.get() != nullptr);
        InternetHandle request(WinHttpOpenRequest(connection.get(), L"GET", target.c_str(), nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));
        Check(request.get() != nullptr);
        DWORD disable = WINHTTP_DISABLE_REDIRECTS;
        Check(WinHttpSetOption(request.get(), WINHTTP_OPTION_DISABLE_FEATURE, &disable, sizeof(disable)) != FALSE);
        Check(WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)
              && WinHttpReceiveResponse(request.get(), nullptr));
        DWORD status = 0, size = sizeof(status);
        Check(WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) != FALSE);
        if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
            wchar_t location[8192]{}; size = sizeof(location);
            Check(WinHttpQueryHeaders(request.get(), WINHTTP_QUERY_LOCATION, WINHTTP_HEADER_NAME_BY_INDEX,
                location, &size, WINHTTP_NO_HEADER_INDEX) != FALSE);
            url = location; continue;
        }
        Check(status == 200);
        Handle file(CreateFileW(destination.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        Check(file.get() != INVALID_HANDLE_VALUE);
        BYTE bytes[65536]{}; DWORD read = 0; unsigned long long total = 0;
        for (;;) {
            Check(WinHttpReadData(request.get(), bytes, sizeof(bytes), &read) != FALSE);
            if (!read) break;
            total += read; Check(total <= 200000000);
            DWORD written = 0; Check(WriteFile(file.get(), bytes, read, &written, nullptr) && written == read);
        }
        Check(total > 0 && FlushFileBuffers(file.get())); return;
    }
    throw std::runtime_error("download redirects");
}
static bool Running(DWORD session) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    Check(snapshot.get() != INVALID_HANDLE_VALUE);
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    Check(Process32FirstW(snapshot.get(), &entry) != FALSE);
    do {
        if (!Equal(entry.szExeFile, L"Discord.exe")) continue;
        DWORD processSession = 0;
        Check(ProcessIdToSessionId(entry.th32ProcessID, &processSession) != FALSE);
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID));
        Handle token;
        if (!process.get() || !OpenProcessToken(process.get(), TOKEN_QUERY, token.out())) continue;
        if (TokenSid(token.get()) == IdentitySid()) {
            Check(processSession == session); // Never share this profile across desktops.
            return true;
        }
    } while (Process32NextW(snapshot.get(), &entry));
    return false;
}
static Reply Perform(DWORD operation, DWORD session) {
    Reply reply{Protocol, 0, 0, 0, 0, 0};
    Handle token;
    reply.identityPid = IdentityToken(token);
    const auto profile = Profile(token.get());
    const auto sid = IdentitySid();
    PrivateDirectory(profile / L"AppData", sid);
    PrivateDirectory(profile / L"AppData\\Local", sid);
    PrivateDirectory(profile / L"AppData\\Roaming", sid);
    PrivateDirectory(profile / L"AppData\\Roaming\\discord", sid);
    PrivateTree(profile / L"AppData\\Roaming\\discord", sid);
    reply.ready = 1;
    if (operation == 2) {
        const auto staging = profile / L"AppData\\Local\\DiscordGuard";
        PrivateDirectory(staging, sid);
        GUID id{}; Check(CoCreateGuid(&id) == S_OK);
        wchar_t name[40]{}; Check(StringFromGUID2(id, name, ARRAYSIZE(name)) > 0);
        const auto fixture = staging / (std::wstring(name) + L".fixture");
        Check(fixture.wstring().size() < MAX_PATH);
        wcscpy_s(reply.fixture, fixture.c_str());
        reply.probePid = Spawn(token.get(), session, Self(), L" --boundary-child " + std::wstring(name), false);
        bool ready = false;
        for (unsigned attempt = 0; attempt < 100; ++attempt) {
            if (fs::exists(fixture) && fs::file_size(fixture) == 32) { ready = true; break; }
            Sleep(100);
        }
        Check(ready && PrivateAcl(fixture, sid));
        return reply;
    }
    auto image = DiscordImage(profile);
    reply.installed = image.empty() ? 0u : 1u;
    reply.running = Running(session) ? 1u : 0u;
    if (operation == 0 || reply.running) return reply;
    if (image.empty()) {
        const auto staging = profile / L"AppData\\Local\\DiscordGuard";
        PrivateDirectory(staging, sid);
        GUID id{}; Check(CoCreateGuid(&id) == S_OK);
        wchar_t name[40]{}; Check(StringFromGUID2(id, name, ARRAYSIZE(name)) > 0);
        const auto installer = staging / (std::wstring(name) + L".exe");
        try {
            Download(installer);
            Handle lock(CreateFileW(installer.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr));
            Check(lock.get() != INVALID_HANDLE_VALUE && SignedDiscord(installer));
            Spawn(token.get(), session, installer, L" --silent", true);
        } catch (...) { DeleteFileW(installer.c_str()); throw; }
        DeleteFileW(installer.c_str());
        image = DiscordImage(profile); Check(!image.empty());
    }
    if (!Running(session)) Spawn(token.get(), session, image, L"", false);
    reply.installed = 1; reply.running = 1; return reply;
}
static bool Transfer(HANDLE pipe, void* buffer, DWORD bytes, bool write, DWORD timeout) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    OVERLAPPED overlapped{}; overlapped.hEvent = event.get();
    DWORD transferred = 0;
    BOOL ok = write ? WriteFile(pipe, buffer, bytes, &transferred, &overlapped) : ReadFile(pipe, buffer, bytes, &transferred, &overlapped);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(event.get(), timeout) != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &overlapped); GetOverlappedResult(pipe, &overlapped, &transferred, TRUE); return false;
        }
        ok = GetOverlappedResult(pipe, &overlapped, &transferred, FALSE);
    }
    return ok && transferred == bytes;
}
static DWORD CallerSession(HANDLE pipe) {
    const auto origin = Origin();
    Check(ImpersonateNamedPipeClient(pipe) != FALSE);
    Handle caller; DWORD session = 0;
    bool valid = false;
    try {
        Check(OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, caller.out()) != FALSE);
        DWORD size = 0;
        valid = TokenSid(caller.get()) == origin &&
            GetTokenInformation(caller.get(), TokenSessionId, &session, sizeof(session), &size) && session != 0;
    } catch (...) { RevertToSelf(); throw; }
    Check(RevertToSelf() != FALSE); Check(valid);
    Handle interactive;
    Check(WTSQueryUserToken(session, interactive.out()) && TokenSid(interactive.get()) == origin);
    return session;
}
static void Serve() {
    Security descriptor(L"D:P(A;;GA;;;SY)(A;;GRGW;;;" + Origin() + L")");
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor.get(), FALSE};
    Handle pipe(CreateNamedPipeW(Pipe, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, sizeof(Reply), sizeof(Request), 0, &attributes));
    Check(pipe.get() != INVALID_HANDLE_VALUE);
    while (WaitForSingleObject(stopEvent, 0) != WAIT_OBJECT_0) {
        Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        OVERLAPPED overlapped{}; overlapped.hEvent = event.get();
        BOOL connected = ConnectNamedPipe(pipe.get(), &overlapped);
        if (!connected) {
            const DWORD error = GetLastError();
            if (error == ERROR_PIPE_CONNECTED) connected = TRUE;
            else if (error == ERROR_IO_PENDING) {
                HANDLE waits[]{stopEvent, event.get()};
                if (WaitForMultipleObjects(2, waits, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) {
                    CancelIoEx(pipe.get(), &overlapped); DWORD ignored = 0;
                    GetOverlappedResult(pipe.get(), &overlapped, &ignored, TRUE); break;
                }
                DWORD ignored = 0; connected = GetOverlappedResult(pipe.get(), &overlapped, &ignored, FALSE);
            }
        }
        if (connected) {
            Reply reply{Protocol, ERROR_ACCESS_DENIED, 0, 0, 0, 0}; Request request{};
            if (Transfer(pipe.get(), &request, sizeof(request), false, 5000) && request.version == Protocol && request.operation <= 2) {
                try { reply = Perform(request.operation, CallerSession(pipe.get())); }
                catch (const std::system_error& error) { reply.error = static_cast<DWORD>(error.code().value()); }
                catch (...) { reply.error = ERROR_NOT_READY; }
            }
            if (Transfer(pipe.get(), &reply, sizeof(reply), true, 5000)) {
                DWORD acknowledgement = 0;
                Transfer(pipe.get(), &acknowledgement, sizeof(acknowledgement), false, 5000);
            }
            if (reply.fixture[0]) DeleteFileW(reply.fixture);
        }
        DisconnectNamedPipe(pipe.get());
    }
}
static void Report(DWORD state, DWORD error = 0) {
    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = state; serviceStatus.dwWin32ExitCode = error;
    serviceStatus.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    SetServiceStatus(statusHandle, &serviceStatus);
}
static DWORD WINAPI Control(DWORD command, DWORD, void*, void*) {
    if (command == SERVICE_CONTROL_STOP || command == SERVICE_CONTROL_SHUTDOWN) {
        Report(SERVICE_STOP_PENDING); SetEvent(stopEvent);
    }
    return NO_ERROR;
}
static void WINAPI ServiceMain(DWORD, LPWSTR*) {
    statusHandle = RegisterServiceCtrlHandlerExW(identityMode ? Identity : Broker, Control, nullptr);
    if (!statusHandle) return;
    Report(SERVICE_START_PENDING);
    Handle stop(CreateEventW(nullptr, TRUE, FALSE, nullptr)); stopEvent = stop.get();
    try {
        Handle token; Check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.out()) != FALSE);
        Check(TokenSid(token.get()) == (identityMode ? IdentitySid() : L"S-1-5-18"));
        if (identityMode) {
            // Windows SCM owns the password and loads the virtual account profile.
            Profile(token.get());
            Report(SERVICE_RUNNING); WaitForSingleObject(stopEvent, INFINITE);
        } else {
            EnablePrivilege(SE_TCB_NAME); EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME); EnablePrivilege(SE_INCREASE_QUOTA_NAME);
            Origin(); Report(SERVICE_RUNNING); Serve();
        }
        Report(SERVICE_STOPPED);
    } catch (const std::system_error& error) { Report(SERVICE_STOPPED, static_cast<DWORD>(error.code().value())); }
      catch (...) { Report(SERVICE_STOPPED, ERROR_NOT_READY); }
}
static void GrantDesktopObject(HANDLE object, const std::wstring& sid, DWORD access) {
    DWORD needed = 0; SECURITY_INFORMATION info = DACL_SECURITY_INFORMATION;
    GetUserObjectSecurity(object, &info, nullptr, 0, &needed); Check(needed > 0);
    std::vector<BYTE> security(needed);
    Check(GetUserObjectSecurity(object, &info, security.data(), needed, &needed) != FALSE);
    PACL oldAcl = nullptr; BOOL present = FALSE, defaults = FALSE;
    Check(GetSecurityDescriptorDacl(security.data(), &present, &oldAcl, &defaults) && present && oldAcl);
    PSID target = nullptr; Check(ConvertStringSidToSidW(sid.c_str(), &target) != FALSE);
    EXPLICIT_ACCESSW entry{}; entry.grfAccessPermissions = access; entry.grfAccessMode = GRANT_ACCESS;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID; entry.Trustee.ptstrName = static_cast<LPWSTR>(target);
    PACL newAcl = nullptr;
    DWORD error = SetEntriesInAclW(1, &entry, oldAcl, &newAcl); LocalFree(target); Check(error == ERROR_SUCCESS);
    SECURITY_DESCRIPTOR descriptor{};
    bool ok = InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION) &&
        SetSecurityDescriptorDacl(&descriptor, TRUE, newAcl, FALSE) && SetUserObjectSecurity(object, &info, &descriptor);
    LocalFree(newAcl); Check(ok);
}
static Reply Client(DWORD operation) {
    const auto pid = ServicePid(Broker, L"LocalSystem", L"--broker-service");
    if (!WaitNamedPipeW(Pipe, 10000) && GetLastError() != ERROR_SEM_TIMEOUT) Check(false);
    Handle pipe(CreateFileW(Pipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    Check(pipe.get() != INVALID_HANDLE_VALUE);
    ULONG server = 0; Check(GetNamedPipeServerProcessId(pipe.get(), &server) && server == pid);
    // SCM configuration plus its live PID authenticates the SYSTEM endpoint.
    // Ordinary callers need no read access to the SYSTEM process token.
    if (operation != 0) {
        // Grant only this virtual identity access to this desktop. No SYSTEM GUI.
        GrantDesktopObject(GetProcessWindowStation(), IdentitySid(), 0x337);
        GrantDesktopObject(GetThreadDesktop(GetCurrentThreadId()), IdentitySid(), 0xC7);
    }
    Request request{Protocol, operation}; Reply reply{};
    Check(Transfer(pipe.get(), &request, sizeof(request), true, 5000));
    Check(Transfer(pipe.get(), &reply, sizeof(reply), false, operation ? 420000 : 30000));
    Check(reply.version == Protocol);
    if (operation == 2 && !reply.error && reply.probePid && reply.fixture[0]) {
        Check(reply.fixture[MAX_PATH - 1] == 0);
        Handle fixture(CreateFileW(reply.fixture, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr));
        reply.fileDenied = fixture.get() == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED ? 1u : 0u;
        Handle process(OpenProcess(PROCESS_VM_READ, FALSE, reply.probePid));
        reply.memoryDenied = !process.get() && GetLastError() == ERROR_ACCESS_DENIED ? 1u : 0u;
        if (!reply.fileDenied || !reply.memoryDenied) reply.error = ERROR_ACCESS_DENIED;
    }
    DWORD acknowledgement = Protocol;
    Check(Transfer(pipe.get(), &acknowledgement, sizeof(acknowledgement), true, 5000));
    return reply;
}
int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && (Equal(argv[1], L"--identity-service") || Equal(argv[1], L"--broker-service"))) {
        identityMode = Equal(argv[1], L"--identity-service");
        SERVICE_TABLE_ENTRYW table[]{{const_cast<LPWSTR>(identityMode ? Identity : Broker), ServiceMain}, {nullptr, nullptr}};
        return StartServiceCtrlDispatcherW(table) ? 0 : 1;
    }
    try {
        if (argc == 3 && Equal(argv[1], L"--boundary-child")) {
            Check(std::regex_match(argv[2], std::wregex(L"\\{[A-Fa-f0-9-]{36}\\}")));
            Handle token; Check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, token.out()) != FALSE);
            Check(TokenSid(token.get()) == IdentitySid());
            BYTE plain[32]{};
            for (BYTE index = 0; index < sizeof(plain); ++index) plain[index] = index;
            DATA_BLOB input{sizeof(plain), plain}, encrypted{}, decrypted{};
            Check(CryptProtectData(&input, L"DiscordGuard harmless fixture", nullptr, nullptr, nullptr,
                CRYPTPROTECT_UI_FORBIDDEN, &encrypted) != FALSE);
            const bool decoded = CryptUnprotectData(&encrypted, nullptr, nullptr, nullptr, nullptr,
                CRYPTPROTECT_UI_FORBIDDEN, &decrypted) != FALSE;
            const bool matches = decoded && decrypted.cbData == sizeof(plain) && !memcmp(decrypted.pbData, plain, sizeof(plain));
            LocalFree(encrypted.pbData); LocalFree(decrypted.pbData); Check(matches);
            const auto path = Profile(token.get()) / L"AppData\\Local\\DiscordGuard" / (std::wstring(argv[2]) + L".fixture");
            {
                Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr));
                DWORD written = 0;
                Check(file.get() != INVALID_HANDLE_VALUE && WriteFile(file.get(), plain, sizeof(plain), &written, nullptr)
                      && written == sizeof(plain) && FlushFileBuffers(file.get()));
            }
            Sleep(30000); return 0;
        }
        Check(argc == 2 && (Equal(argv[1], L"--query") || Equal(argv[1], L"--launch") || Equal(argv[1], L"--verify-boundary")));
        const auto reply = Client(Equal(argv[1], L"--launch") ? 1 : Equal(argv[1], L"--verify-boundary") ? 2 : 0);
        std::cout << "{\"available\":true,\"error\":" << reply.error << ",\"ready\":" << reply.ready
                  << ",\"installed\":" << reply.installed << ",\"running\":" << reply.running
                  << ",\"file_denied\":" << reply.fileDenied << ",\"memory_denied\":" << reply.memoryDenied << "}\n";
        return reply.error ? 1 : 0;
    } catch (const std::system_error& error) {
        std::cout << "{\"available\":false,\"error\":" << error.code().value() << "}\n"; return 1;
    } catch (...) {
        std::cout << "{\"available\":false,\"error\":21}\n"; return 1;
    }
}
