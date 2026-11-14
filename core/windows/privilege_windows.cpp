/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsPrivilege.h"

namespace WindowsProfiler {
DWORD Privilege::enable() {
    if (_token) return ERROR_ALREADY_INITIALIZED;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &_token)) return GetLastError();
    TOKEN_PRIVILEGES requested{};
    requested.PrivilegeCount = 1;
    DWORD error = ERROR_SUCCESS;
    if (!LookupPrivilegeValueW(nullptr, _name, &requested.Privileges[0].Luid)) error = GetLastError();
    else {
        requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        DWORD length = sizeof(_previous);
        SetLastError(ERROR_SUCCESS);
        if (!AdjustTokenPrivileges(_token, FALSE, &requested, sizeof(_previous), &_previous, &length)) error = GetLastError();
        else error = GetLastError();
        _changed = error == ERROR_SUCCESS;
    }
    if (error) restore();
    return error;
}
void Privilege::restore() {
    if (!_token) return;
    if (_changed) AdjustTokenPrivileges(_token, FALSE, &_previous, 0, nullptr, nullptr);
    CloseHandle(_token);
    _token = nullptr;
    _changed = false;
}
}
