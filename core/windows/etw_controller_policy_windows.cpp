/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwControllerSecurity.h"
#include <aclapi.h>
#include <tlhelp32.h>
#include <vector>

namespace WindowsProfiler::Etw::Broker {
namespace {
ULONG policy(PACL acl, DWORD query) {
    if (!acl || !IsValidAcl(acl)) return ERROR_ACCESS_DENIED;
    bool owner = false;
    for (DWORD index = 0; index < acl->AceCount; ++index) {
        void* raw;
        if (!GetAce(acl, index, &raw)) return GetLastError();
        auto header = static_cast<ACE_HEADER*>(raw);
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) return ERROR_ACCESS_DENIED;
        auto allowed = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        auto sid = &allowed->SidStart;
        if (IsWellKnownSid(sid, WinCreatorOwnerRightsSid)) owner = true;
        if (!IsWellKnownSid(sid, WinBuiltinAdministratorsSid) && !IsWellKnownSid(sid, WinLocalSystemSid)
                && (allowed->Mask & ~query)) return ERROR_ACCESS_DENIED;
    }
    return owner ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}
ULONG objectPolicy(HANDLE object, DWORD query) {
    PACL acl;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    auto error = GetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &acl, nullptr, &descriptor);
    if (!error) error = policy(acl, query);
    if (descriptor) LocalFree(descriptor);
    return error;
}
ULONG tokenData(HANDLE token, TOKEN_INFORMATION_CLASS kind, std::vector<unsigned char>& data) {
    DWORD length = 0;
    GetTokenInformation(token, kind, nullptr, 0, &length);
    if (!length || length > 65536) return ERROR_INVALID_DATA;
    data.resize(length);
    return GetTokenInformation(token, kind, data.data(), length, &length) ? ERROR_SUCCESS : GetLastError();
}
ULONG threadPolicies(DWORD process) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH) snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return GetLastError();
    THREADENTRY32 entry{sizeof(entry)};
    DWORD count = 0;
    ULONG error = ERROR_SUCCESS;
    BOOL next = Thread32First(snapshot, &entry);
    while (next) {
        if (entry.th32OwnerProcessID == process) {
            HANDLE thread = OpenThread(READ_CONTROL | THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
            if (!thread) {
                error = GetLastError();
                if (error != ERROR_INVALID_PARAMETER) break;
            } else {
                auto owner = GetProcessIdOfThread(thread);
                if (!owner) error = GetLastError();
                else if (owner == process) { error = objectPolicy(thread, 0); if (!error) ++count; }
                else error = ERROR_SUCCESS;
                if (error) {
                    DWORD code;
                    if (GetExitCodeThread(thread, &code) && code != STILL_ACTIVE) error = ERROR_SUCCESS;
                }
                CloseHandle(thread);
                if (error) break;
            }
        }
        next = Thread32Next(snapshot, &entry);
    }
    if (!next) error = GetLastError() == ERROR_NO_MORE_FILES ? ERROR_SUCCESS : GetLastError();
    CloseHandle(snapshot);
    return error ? error : count ? ERROR_SUCCESS : ERROR_PROCESS_ABORTED;
}
}
ULONG verifyController(HANDLE process, bool exposed) try {
    auto error = objectPolicy(process, exposed ? PROCESS_QUERY_LIMITED_INFORMATION : 0);
    if (error) return error;
    ControllerObject token;
    if (!OpenProcessToken(process, TOKEN_QUERY | READ_CONTROL, &token.value)) return GetLastError();
    error = objectPolicy(token.value, exposed ? TOKEN_QUERY : 0);
    std::vector<unsigned char> data;
    if (!error) error = tokenData(token.value, TokenDefaultDacl, data);
    if (!error) error = policy(reinterpret_cast<TOKEN_DEFAULT_DACL*>(data.data())->DefaultDacl, 0);
    TOKEN_ELEVATION elevated{}; DWORD length;
    if (!error && (!GetTokenInformation(token.value, TokenElevation, &elevated, sizeof(elevated), &length) || !elevated.TokenIsElevated)) error = ERROR_ELEVATION_REQUIRED;
    if (!error) error = tokenData(token.value, TokenIntegrityLevel, data);
    if (!error) {
        auto sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(data.data())->Label.Sid;
        auto count = *GetSidSubAuthorityCount(sid);
        if (!count || *GetSidSubAuthority(sid, count - 1) < SECURITY_MANDATORY_HIGH_RID) error = ERROR_ELEVATION_REQUIRED;
    }
    if (!error) error = threadPolicies(GetProcessId(process));
    return error;
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
}
