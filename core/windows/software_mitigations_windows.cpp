/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsSoftwareMitigations.h"
#include <algorithm>
#include <array>
#include <string>
#include <vector>

namespace WindowsProfiler::SoftwareMitigations {
namespace {
constexpr DWORD timeout = 10000;
struct Launch {
    HANDLE mapping = nullptr, target = nullptr, process = nullptr;
    Wire::State* state = nullptr;
    std::vector<unsigned char> attributeStorage;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;
    ~Launch() {
        if (attributes) DeleteProcThreadAttributeList(attributes);
        if (state) UnmapViewOfFile(state);
        if (process) CloseHandle(process);
        if (target) CloseHandle(target);
        if (mapping) CloseHandle(mapping);
    }
};
}

Result prepare(const unsigned char* code, size_t codeSize, std::span<const std::uint8_t> continuations) noexcept {
    Result result;
    try {
        // The DWORD layout is PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY.
        if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy,
                &result.policyFlags, sizeof(result.policyFlags))) {
            result.error = GetLastError();
            return result;
        }
        Wire::Request request{Wire::VERSION, sizeof(Wire::State), GetCurrentProcessId(), result.policyFlags,
            0, reinterpret_cast<std::uintptr_t>(code), codeSize, static_cast<DWORD>(continuations.size()), {}};
        if (continuations.size() > MAX_CONTINUATIONS) {
            result.error = ERROR_INVALID_PARAMETER;
            return result;
        }
        std::copy(continuations.begin(), continuations.end(), request.continuations);
        if (!Wire::validCode(request)) {
            result.error = ERROR_INVALID_PARAMETER;
            return result;
        }
        if (!(result.policyFlags & REQUIRED_POLICY_BITS)) return result;
        Launch launch;
        SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
        launch.mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0, sizeof(Wire::State), nullptr);
        if (!launch.mapping) { result.error = GetLastError(); return result; }
        launch.state = static_cast<Wire::State*>(MapViewOfFile(launch.mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(Wire::State)));
        if (!launch.state) { result.error = GetLastError(); return result; }
        if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &launch.target,
                PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | SYNCHRONIZE, TRUE, 0)) {
            result.error = GetLastError(); return result;
        }
        FILETIME creation, exit, kernel, user;
        if (!GetProcessTimes(launch.target, &creation, &exit, &kernel, &user)) {
            result.error = GetLastError(); return result;
        }
        request.creation = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
        *launch.state = {};
        launch.state->request = request;
        std::array<HANDLE, 2> handles{launch.mapping, launch.target};
        SIZE_T attributeSize = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
        launch.attributeStorage.resize(attributeSize);
        auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(launch.attributeStorage.data());
        if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributeSize)) {
            result.error = GetLastError(); return result;
        }
        launch.attributes = attributes;
        if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.data(), sizeof(handles), nullptr, nullptr)) {
            result.error = GetLastError(); return result;
        }
        std::vector<WCHAR> path(32768);
        auto length = GetModuleFileNameW(selfModule(), path.data(), static_cast<DWORD>(path.size()));
        if (!length || length >= path.size()) {
            result.error = length ? ERROR_FILENAME_EXCED_RANGE : GetLastError(); return result;
        }
        std::wstring executable(path.data(), length);
        executable.resize(executable.find_last_of(L"\\/") + 1);
        executable += L"asprof-helper.exe";
        std::wstring command = L"\"" + executable + L"\" --software-mitigations";
        for (auto handle : handles) command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = attributes;
        PROCESS_INFORMATION child{};
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
                CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &child)) {
            result.error = GetLastError(); return result;
        }
        launch.process = child.hProcess;
        CloseHandle(child.hThread);
        CloseHandle(launch.target); launch.target = nullptr;
        CloseHandle(launch.mapping); launch.mapping = nullptr;
        result.registrationPossible = 1;
        auto wait = WaitForSingleObject(launch.process, timeout);
        if (wait != WAIT_OBJECT_0) {
            result.error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
            // A terminated or unresponsive helper may already have registered
            // addresses. Its request never permits the caller to free code.
            TerminateProcess(launch.process, result.error);
            WaitForSingleObject(launch.process, 5000);
            return result;
        }
        DWORD exitCode;
        if (!GetExitCodeProcess(launch.process, &exitCode)) { result.error = GetLastError(); return result; }
        if (InterlockedCompareExchange(&launch.state->complete, 0, 0) != 1) {
            result.error = exitCode ? exitCode : ERROR_INVALID_DATA; return result;
        }
        auto completed = launch.state->result;
        if (completed.error != exitCode
                || ((completed.policyFlags ^ result.policyFlags) & REQUIRED_POLICY_BITS)
                || (completed.continuationMask & ~Wire::allContinuations(request)) || completed.rangeProcessed > 1
                || completed.registrationPossible > 1
                || (!completed.registrationPossible && (completed.continuationMask || completed.rangeProcessed))) {
            result.error = ERROR_INVALID_DATA; return result;
        }
        if (!completed.error && (((completed.policyFlags & CONTEXT_IP_VALIDATION)
                    && completed.continuationMask != Wire::allContinuations(request))
                || ((completed.policyFlags & SHADOW_STACK_ENABLED) && completed.rangeProcessed != 1)
                || !completed.registrationPossible)) {
            result.error = ERROR_INVALID_DATA; return result;
        }
        return completed;
    } catch (...) {
        result.error = ERROR_NOT_ENOUGH_MEMORY;
        return result;
    }
}
}
