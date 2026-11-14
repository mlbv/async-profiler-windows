/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwControllerSecurity.h"
#include "windowsEtwBrokerPrivate.h"
#include <aclapi.h>
#include <tlhelp32.h>
#include <vector>

namespace WindowsProfiler::Etw::Broker {
namespace {
enum class QueryObject { Process, Token };
ULONG grantQuery(HANDLE object, PSID user, QueryObject kind) {
    DWORD access = kind == QueryObject::Process ? PROCESS_QUERY_LIMITED_INFORMATION : TOKEN_QUERY;
    PACL previous = nullptr, replacement = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    auto error = GetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, &previous, nullptr, &descriptor);
    if (error) return error;
    // Preserve privileged callers' rights. Logon-session and owner grants can
    // otherwise expose token duplication even when the user ACE is query-only.
    if (previous) {
        for (DWORD index = 0; index < previous->AceCount; ++index) {
            void* raw;
            if (!GetAce(previous, index, &raw)) { error = GetLastError(); break; }
            auto header = static_cast<ACE_HEADER*>(raw);
            if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                auto allowed = static_cast<ACCESS_ALLOWED_ACE*>(raw);
                if (!IsWellKnownSid(&allowed->SidStart, WinBuiltinAdministratorsSid)
                        && !IsWellKnownSid(&allowed->SidStart, WinLocalSystemSid)) allowed->Mask &= access;
            } else if (header->AceType == ACCESS_DENIED_ACE_TYPE) {
                auto denied = static_cast<ACCESS_DENIED_ACE*>(raw);
                // Relax only identity queries in the launcher's process deny.
                if (kind == QueryObject::Process && IsWellKnownSid(&denied->SidStart, WinWorldSid)) denied->Mask &= ~PROCESS_QUERY_LIMITED_INFORMATION;
            } else {
                error = ERROR_NOT_SUPPORTED;
                break;
            }
        }
    }
    alignas(SID) unsigned char sids[3][SECURITY_MAX_SID_SIZE];
    WELL_KNOWN_SID_TYPE types[] = {WinCreatorOwnerRightsSid, WinBuiltinAdministratorsSid, WinLocalSystemSid};
    for (size_t index = 0; !error && index < std::size(types); ++index) {
        DWORD length = SECURITY_MAX_SID_SIZE;
        if (!CreateWellKnownSid(types[index], nullptr, sids[index], &length)) error = GetLastError();
    }
    EXPLICIT_ACCESSW entries[4]{};
    auto allow = [&](size_t index, PSID sid, DWORD rights) {
        entries[index].grfAccessPermissions = rights; entries[index].grfAccessMode = GRANT_ACCESS;
        entries[index].grfInheritance = NO_INHERITANCE; BuildTrusteeWithSidW(&entries[index].Trustee, sid);
    };
    allow(0, user, access);
    // OWNER_RIGHTS suppresses implicit owner WRITE_DAC/READ_CONTROL. An
    // administrator still obtains its original explicit administrator grants.
    allow(1, sids[0], access);
    ULONG count = 2;
    if (!previous) {
        auto full = kind == QueryObject::Process ? PROCESS_ALL_ACCESS : TOKEN_ALL_ACCESS;
        allow(2, sids[1], full); allow(3, sids[2], full); count = 4;
    }
    if (!error) error = SetEntriesInAclW(count, entries, previous, &replacement);
    if (!error) error = SetSecurityInfo(object, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, replacement, nullptr);
    if (replacement) LocalFree(replacement);
    if (descriptor) LocalFree(descriptor);
    return error;
}
ULONG hardenControllerThreads(PACL acl) {
    auto error = SetSecurityInfo(GetCurrentThread(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, acl, nullptr);
    if (error) return error;
    auto process = GetCurrentProcessId(), current = GetCurrentThreadId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH) snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return GetLastError();
    THREADENTRY32 entry{sizeof(entry)};
    BOOL next = Thread32First(snapshot, &entry);
    while (next) {
        if (entry.th32OwnerProcessID == process && entry.th32ThreadID != current) {
            HANDLE thread = OpenThread(WRITE_DAC | THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
            if (!thread) {
                error = GetLastError();
                if (error != ERROR_INVALID_PARAMETER) break;
            } else {
                auto owner = GetProcessIdOfThread(thread);
                if (!owner) error = GetLastError();
                else if (owner == process) error = SetSecurityInfo(thread, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, acl, nullptr);
                else error = ERROR_SUCCESS; // The snapshot's thread exited and its ID was reused.
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
    CloseHandle(snapshot); return error;
}
ULONG allowServerVerification(PSID targetUser) {
    // Split-token launchers can give elevated processes an administrator-only
    // DACL. Restrict the token before making process identity queries available.
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | READ_CONTROL | WRITE_DAC, &token)) return GetLastError();
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    auto error = controllerSecurity(descriptor);
    if (!error) {
        PACL acl; BOOL present, defaulted;
        if (!GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted)) error = GetLastError();
        if (!error) {
            TOKEN_DEFAULT_DACL defaults{acl};
            if (!SetTokenInformation(token, TokenDefaultDacl, &defaults, sizeof(defaults))) error = GetLastError();
        }
        if (!error) error = hardenControllerThreads(acl);
        LocalFree(descriptor);
    }
    if (!error) error = grantQuery(token, targetUser, QueryObject::Token);
    CloseHandle(token);
    return error ? error : grantQuery(GetCurrentProcess(), targetUser, QueryObject::Process);
}
}
ULONG hardenControllerIdentity() try {
    std::vector<unsigned char> user;
    auto error = tokenUser(GetCurrentProcess(), user);
    if (!error) error = allowServerVerification(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid);
    return error ? error : verifyController(GetCurrentProcess(), true);
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
ULONG protectBootstrap() {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    auto error = controllerSecurity(descriptor);
    if (error) return error;
    PACL acl; BOOL present, defaulted;
    if (!GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted)) error = GetLastError();
    if (!error) error = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
        nullptr, nullptr, acl, nullptr);
    if (!error) error = hardenControllerThreads(acl);
    LocalFree(descriptor); return error;
}
}
