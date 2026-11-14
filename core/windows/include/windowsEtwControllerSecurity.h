/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <sddl.h>

namespace WindowsProfiler::Etw {
struct ControllerObject {
    HANDLE value = nullptr;
    ControllerObject() = default;
    ControllerObject(const ControllerObject&) = delete;
    ControllerObject& operator=(const ControllerObject&) = delete;
    ~ControllerObject() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
// Used for private controller objects and watcher process/thread creation.
// OWNER_RIGHTS suppresses implicit owner ACL-control permissions.
inline ULONG controllerSecurity(PSECURITY_DESCRIPTOR& descriptor) {
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x0;;;OW)", SDDL_REVISION_1, &descriptor, nullptr)
        ? ERROR_SUCCESS : GetLastError();
}
}

namespace WindowsProfiler::Etw::Broker {
// The caller must already run with an isolated primary token. This function
// changes that token's object/default DACLs; never use it on shared credentials.
ULONG hardenControllerIdentity();
ULONG protectBootstrap();
ULONG verifyController(HANDLE process, bool exposed);

// Preserves the caller's token while creating a child with private primary and
// creator tokens, trusted defaults, and protected process/thread objects.
class ControllerLaunchTokens {
    ControllerObject source, primary, creator;
    TOKEN_STATISTICS before{};
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    bool initialized = false;
public:
    ControllerLaunchTokens() = default;
    ~ControllerLaunchTokens();
    ControllerLaunchTokens(const ControllerLaunchTokens&) = delete;
    ControllerLaunchTokens& operator=(const ControllerLaunchTokens&) = delete;
    ULONG initialize();
    // One launch per instance. startup must provide an explicit inherited-handle list. On success the
    // caller owns process and must publish tokenId before resuming the child.
    // On failure no child survives and process is empty.
    ULONG createSuspended(const WCHAR* executable, WCHAR* command,
                          STARTUPINFOEXW& startup, PROCESS_INFORMATION& process,
                          LUID& tokenId);
};
}
