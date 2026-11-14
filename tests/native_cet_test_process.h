/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>

// Creates only the caller's owned test process; no existing policy is changed.
inline DWORD runCetTestProcess(const WCHAR* executable, std::wstring command, bool strict) {
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    std::vector<unsigned char> storage(size);
    auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &size)) return GetLastError();
    DWORD64 policies[] = {0, (strict ? PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_STRICT_MODE
            : PROCESS_CREATION_MITIGATION_POLICY2_CET_USER_SHADOW_STACKS_ALWAYS_ON)
        | PROCESS_CREATION_MITIGATION_POLICY2_USER_CET_SET_CONTEXT_IP_VALIDATION_ALWAYS_ON};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            policies, sizeof(policies), nullptr, nullptr)) {
        auto error = GetLastError();
        DeleteProcThreadAttributeList(attributes);
        return error;
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = attributes;
    PROCESS_INFORMATION process{};
    auto created = CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE,
        EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &process);
    auto error = created ? ERROR_SUCCESS : GetLastError();
    DeleteProcThreadAttributeList(attributes);
    if (!created) return error;
    CloseHandle(process.hThread);
    auto wait = WaitForSingleObject(process.hProcess, 30000);
    if (wait != WAIT_OBJECT_0) {
        error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
        TerminateProcess(process.hProcess, error);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        return error;
    }
    DWORD result;
    if (!GetExitCodeProcess(process.hProcess, &result)) result = GetLastError();
    CloseHandle(process.hProcess);
    return result;
}
