/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwBootstrap.h"
#include "windowsEtwBrokerPrivate.h"
#include "windowsEtwControllerSecurity.h"
#include "windowsEtwWatcher.h"
#include <tlhelp32.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace WindowsProfiler::Etw::Broker {
namespace {
using Object = ControllerObject;
struct Descriptor {
    PSECURITY_DESCRIPTOR value = nullptr;
    ~Descriptor() { if (value) LocalFree(value); }
};
struct Attributes {
    std::vector<unsigned char> bytes;
    LPPROC_THREAD_ATTRIBUTE_LIST value = nullptr;
    ~Attributes() { if (value) DeleteProcThreadAttributeList(value); }
};
struct Child {
    PROCESS_INFORMATION info{};
    bool finished = false;
    ~Child() {
        if (info.hProcess) {
            if (!finished && WaitForSingleObject(info.hProcess, 0) == WAIT_TIMEOUT) {
                TerminateProcess(info.hProcess, ERROR_PROCESS_ABORTED);
                WaitForSingleObject(info.hProcess, 5000);
            }
            CloseHandle(info.hProcess);
        }
        if (info.hThread) CloseHandle(info.hThread);
    }
};
struct Startup {
    ULONG protocol = 2, size = sizeof(Startup), targetPid = 0, bootstrapPid = 0, once = 0;
    FILETIME bootstrapCreated{};
    LUID workerToken{};
    WCHAR pipe[240]{};
};
static_assert(sizeof(Startup) == 516);
bool sameLuid(const LUID& left, const LUID& right) { return left.LowPart == right.LowPart && left.HighPart == right.HighPart; }
ULONG statistics(HANDLE token, TOKEN_STATISTICS& result) {
    DWORD length;
    return GetTokenInformation(token, TokenStatistics, &result, sizeof(result), &length) ? ERROR_SUCCESS : GetLastError();
}
ULONG actualParent(DWORD& parent) {
    Object snapshot; snapshot.value = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot.value == INVALID_HANDLE_VALUE) return GetLastError();
    PROCESSENTRY32W entry{sizeof(entry)};
    for (BOOL next = Process32FirstW(snapshot.value, &entry); next; next = Process32NextW(snapshot.value, &entry)) {
        if (entry.th32ProcessID == GetCurrentProcessId()) { parent = entry.th32ParentProcessID; return ERROR_SUCCESS; }
    }
    return ERROR_PROCESS_ABORTED;
}
}

int server(DWORD targetPid, const WCHAR* pipeName, bool once) try {
    if (!targetPid || !pipePath(pipeName)) return ERROR_INVALID_PARAMETER;
    auto error = protectBootstrap();
    if (error) return error;
    ControllerLaunchTokens tokens;
    error = tokens.initialize();
    if (error) return error;
    Descriptor descriptor;
    error = controllerSecurity(descriptor.value);
    if (error) return error;
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor.value, FALSE};
    Object mapping, childMapping, ready, childReady, parent;
    mapping.value = CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0, sizeof(Startup), nullptr);
    ready.value = CreateEventW(&security, TRUE, FALSE, nullptr);
    if (!mapping.value || !ready.value) return GetLastError();
    if (!DuplicateHandle(GetCurrentProcess(), mapping.value, GetCurrentProcess(), &childMapping.value, FILE_MAP_READ, TRUE, 0)
            || !DuplicateHandle(GetCurrentProcess(), ready.value, GetCurrentProcess(), &childReady.value, EVENT_MODIFY_STATE, TRUE, 0)
            || !DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &parent.value,
                SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0)) return GetLastError();
    auto state = static_cast<Startup*>(MapViewOfFile(mapping.value, FILE_MAP_WRITE, 0, 0, sizeof(Startup)));
    if (!state) return GetLastError();
    Startup config; config.targetPid = targetPid; config.bootstrapPid = GetCurrentProcessId(); config.once = once;
    error = processCreated(GetCurrentProcess(), config.bootstrapCreated);
    std::wmemcpy(config.pipe, pipeName, std::wcslen(pipeName) + 1);
    Attributes attributes;
    SIZE_T length = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &length);
    attributes.bytes.resize(length);
    attributes.value = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.bytes.data());
    if (!InitializeProcThreadAttributeList(attributes.value, 1, 0, &length)) { attributes.value = nullptr; error = GetLastError(); }
    std::array<HANDLE, 3> handles{childMapping.value, childReady.value, parent.value};
    if (!error && !UpdateProcThreadAttribute(attributes.value, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handles.data(), sizeof(handles), nullptr, nullptr)) error = GetLastError();
    std::vector<WCHAR> path(32768);
    auto count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!count || count >= path.size()) error = count ? ERROR_FILENAME_EXCED_RANGE : GetLastError();
    std::wstring executable(path.data(), count);
    std::wstring command = L"\"" + executable + L"\" --etw-broker-worker";
    for (auto handle : handles) command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
    Child child;
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.lpAttributeList = attributes.value;
    if (!error) error = tokens.createSuspended(executable.c_str(), command.data(), startup, child.info, config.workerToken);
    if (!error) *state = config;
    UnmapViewOfFile(state);
    if (error) return error;
    error = controlScheduling(child.info.hProcess);
    if (error) return error;
    if (ResumeThread(child.info.hThread) == DWORD(-1)) return GetLastError();
    HANDLE events[] = {ready.value, child.info.hProcess};
    auto signalled = WaitForMultipleObjects(2, events, FALSE, 10000);
    if (signalled != WAIT_OBJECT_0 || WaitForSingleObject(child.info.hProcess, 0) != WAIT_TIMEOUT) {
        DWORD code = ERROR_BROKEN_PIPE;
        if (signalled == WAIT_OBJECT_0 + 1) GetExitCodeProcess(child.info.hProcess, &code);
        return signalled == WAIT_TIMEOUT ? ERROR_TIMEOUT : code ? code : ERROR_BROKEN_PIPE;
    }
    std::wprintf(L"ETW_BROKER_READY pid=%lu target=%lu pipe=%ls\n", child.info.dwProcessId, targetPid, pipeName); std::fflush(stdout);
    if (WaitForSingleObject(child.info.hProcess, INFINITE) != WAIT_OBJECT_0) return GetLastError();
    DWORD code;
    if (!GetExitCodeProcess(child.info.hProcess, &code)) return GetLastError();
    child.finished = true;
    return code;
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }

int worker(HANDLE mapping, HANDLE ready, HANDLE bootstrap) try {
    auto state = static_cast<const Startup*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(Startup)));
    if (!state) return GetLastError();
    Startup config = *state;
    UnmapViewOfFile(state); CloseHandle(mapping);
    if (config.protocol != 2 || config.size != sizeof(config) || config.once > 1 || !config.targetPid || config.pipe[239]
            || !pipePath(config.pipe) || GetProcessId(bootstrap) != config.bootstrapPid
            || WaitForSingleObject(bootstrap, 0) != WAIT_TIMEOUT) return ERROR_INVALID_DATA;
    DWORD parent;
    auto error = actualParent(parent);
    FILETIME created;
    if (!error && parent != config.bootstrapPid) error = ERROR_ACCESS_DENIED;
    if (!error) error = processCreated(bootstrap, created);
    if (!error && CompareFileTime(&created, &config.bootstrapCreated)) error = ERROR_ACCESS_DENIED;
    std::vector<unsigned char> ownUser, parentUser;
    if (!error) error = tokenUser(GetCurrentProcess(), ownUser);
    if (!error) error = tokenUser(bootstrap, parentUser);
    if (!error && !sameUser(ownUser, parentUser)) error = ERROR_ACCESS_DENIED;
    Object token;
    if (!error && !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) error = GetLastError();
    TOKEN_STATISTICS value;
    if (!error) error = statistics(token.value, value);
    if (!error && !sameLuid(value.TokenId, config.workerToken)) error = ERROR_ACCESS_DENIED;
    WCHAR ownPath[32768], parentPath[32768]; DWORD parentLength = 32768;
    if (!error && (!GetModuleFileNameW(nullptr, ownPath, 32768) || !QueryFullProcessImageNameW(bootstrap, 0, parentPath, &parentLength))) error = GetLastError();
    if (!error && _wcsicmp(ownPath, parentPath)) error = ERROR_ACCESS_DENIED;
    if (!error) error = verifyController(GetCurrentProcess(), false);
    if (!error) error = collector(config.targetPid, config.pipe, bootstrap, ready, config.once);
    CloseHandle(ready); CloseHandle(bootstrap);
    return error;
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
}
