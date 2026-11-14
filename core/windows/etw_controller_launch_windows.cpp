/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwControllerSecurity.h"

namespace WindowsProfiler::Etw::Broker {
namespace {
bool sameLuid(const LUID& left, const LUID& right) {
    return left.LowPart == right.LowPart && left.HighPart == right.HighPart;
}
ULONG statistics(HANDLE token, TOKEN_STATISTICS& result) {
    DWORD length;
    return GetTokenInformation(token, TokenStatistics, &result, sizeof(result), &length)
        ? ERROR_SUCCESS : GetLastError();
}
ULONG privateDefaults(HANDLE token, PSECURITY_DESCRIPTOR descriptor) {
    PACL acl; BOOL present, defaulted;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted)) return GetLastError();
    TOKEN_DEFAULT_DACL defaults{acl};
    return SetTokenInformation(token, TokenDefaultDacl, &defaults, sizeof(defaults))
        ? ERROR_SUCCESS : GetLastError();
}
ULONG enable(HANDLE token, const WCHAR* name, bool required) {
    TOKEN_PRIVILEGES privilege{}; privilege.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, name, &privilege.Privileges[0].Luid)) return GetLastError();
    privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &privilege, sizeof(privilege), nullptr, nullptr)) return GetLastError();
    auto error = GetLastError();
    return error == ERROR_NOT_ALL_ASSIGNED && !required ? ERROR_SUCCESS : error;
}
struct Child {
    PROCESS_INFORMATION info{};
    ~Child() {
        if (info.hProcess) {
            TerminateProcess(info.hProcess, ERROR_PROCESS_ABORTED);
            WaitForSingleObject(info.hProcess, 5000);
            CloseHandle(info.hProcess);
        }
        if (info.hThread) CloseHandle(info.hThread);
    }
};
struct Impersonation {
    bool active = false;
    ~Impersonation() {
        if (active && !RevertToSelf()) {
            auto error = GetLastError();
            ExitProcess(error ? error : ERROR_CANNOT_IMPERSONATE);
        }
    }
    ULONG restore() {
        if (!RevertToSelf()) return GetLastError();
        active = false;
        return ERROR_SUCCESS;
    }
};
}

ControllerLaunchTokens::~ControllerLaunchTokens() { if (descriptor) LocalFree(descriptor); }

ULONG ControllerLaunchTokens::initialize() {
    if (source.value) return ERROR_ALREADY_INITIALIZED;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &source.value)) return GetLastError();
    auto error = statistics(source.value, before);
    if (!error) error = controllerSecurity(descriptor);
    if (error) return error;
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    if (!DuplicateTokenEx(source.value, TOKEN_ALL_ACCESS, &security, SecurityImpersonation, TokenPrimary, &primary.value)
            || !DuplicateTokenEx(source.value, TOKEN_ALL_ACCESS, &security, SecurityImpersonation, TokenImpersonation, &creator.value)) return GetLastError();
    error = privateDefaults(primary.value, descriptor);
    if (!error) error = privateDefaults(creator.value, descriptor);
    if (!error) error = enable(creator.value, L"SeIncreaseQuotaPrivilege", true);
    if (!error) error = enable(creator.value, L"SeAssignPrimaryTokenPrivilege", false);
    initialized = !error;
    return error;
}

ULONG ControllerLaunchTokens::createSuspended(const WCHAR* executable, WCHAR* command,
        STARTUPINFOEXW& startup, PROCESS_INFORMATION& process, LUID& tokenId) {
    process = {};
    tokenId = {};
    if (!initialized || startup.StartupInfo.cb != sizeof(startup) || !startup.lpAttributeList) return ERROR_INVALID_PARAMETER;
    initialized = false;
    // Restoring a pre-existing caller impersonation would require a different
    // contract. Reject it before changing the current thread's identity.
    ControllerObject previous;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &previous.value)) return ERROR_BAD_IMPERSONATION_LEVEL;
    auto error = GetLastError();
    if (error != ERROR_NO_TOKEN) return error;
    Child child;
    Impersonation impersonation;
    if (!SetThreadToken(nullptr, creator.value)) return GetLastError();
    impersonation.active = true;
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    BOOL created = CreateProcessAsUserW(primary.value, executable, command, &security, &security, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | NORMAL_PRIORITY_CLASS, nullptr, nullptr,
        &startup.StartupInfo, &child.info);
    error = created ? ERROR_SUCCESS : GetLastError();
    auto restoreError = impersonation.restore();
    if (restoreError) {
        if (created) TerminateProcess(child.info.hProcess, restoreError);
        ExitProcess(restoreError);
    }
    if (error) return error;
    TOKEN_STATISTICS after;
    error = statistics(source.value, after);
    if (!error && (!sameLuid(before.TokenId, after.TokenId) || !sameLuid(before.ModifiedId, after.ModifiedId))) error = ERROR_INVALID_DATA;
    ControllerObject childToken;
    if (!error && !OpenProcessToken(child.info.hProcess, TOKEN_QUERY, &childToken.value)) error = GetLastError();
    TOKEN_STATISTICS childStatistics{};
    if (!error) error = statistics(childToken.value, childStatistics);
    if (!error && sameLuid(before.TokenId, childStatistics.TokenId)) error = ERROR_INVALID_DATA;
    if (error) return error;
    tokenId = childStatistics.TokenId;
    process = child.info;
    child.info = {};
    return ERROR_SUCCESS;
}
}
