/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsSoftwareMitigations.h"

namespace WindowsProfiler::SoftwareMitigations {
namespace {
// Local ABI declarations also support SDKs that predate these APIs.
struct ContinuationTarget { ULONG_PTR address, flags; };
struct EnforcedRange { ULONG_PTR base; SIZE_T size; DWORD flags; };
using SetTargets = BOOL (WINAPI*)(HANDLE, USHORT, ContinuationTarget*);
using SetRanges = BOOL (WINAPI*)(HANDLE, USHORT, EnforcedRange*);
constexpr ULONG_PTR add = 1, processed = 2;
static_assert(sizeof(ContinuationTarget) == 16 && sizeof(EnforcedRange) == 24);

DWORD apply(HANDLE target, const Wire::Request& request, Result& result) noexcept {
    if (request.version != Wire::VERSION || request.size != sizeof(Wire::State)) return ERROR_REVISION_MISMATCH;
    if (!Wire::validCode(request) || GetProcessId(target) != request.pid || request.pid == GetCurrentProcessId())
        return ERROR_INVALID_DATA;
    FILETIME creation, exit, kernel, user;
    if (!GetProcessTimes(target, &creation, &exit, &kernel, &user)) return GetLastError();
    auto birth = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    if (birth != request.creation) return ERROR_INVALID_DATA;
    auto wait = WaitForSingleObject(target, 0);
    if (wait != WAIT_TIMEOUT) return wait == WAIT_OBJECT_0 ? ERROR_PROCESS_ABORTED : GetLastError();
    if (!GetProcessMitigationPolicy(target, ProcessUserShadowStackPolicy, &result.policyFlags, sizeof(result.policyFlags)))
        return GetLastError();
    if ((result.policyFlags ^ request.policyFlags) & REQUIRED_POLICY_BITS) return ERROR_INVALID_DATA;
    MEMORY_BASIC_INFORMATION memory;
    if (!VirtualQueryEx(target, reinterpret_cast<void*>(request.code), &memory, sizeof(memory))) return GetLastError();
    auto base = reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
    if (memory.State != MEM_COMMIT || memory.Type != MEM_PRIVATE || memory.Protect != PAGE_EXECUTE_READ
            || base > request.code || request.code - base > memory.RegionSize
            || request.codeSize > memory.RegionSize - (request.code - base)) return ERROR_INVALID_ADDRESS;
    auto module = GetModuleHandleW(L"kernel32.dll");
    auto setTargets = reinterpret_cast<SetTargets>(GetProcAddress(module, "SetProcessDynamicEHContinuationTargets"));
    auto setRanges = reinterpret_cast<SetRanges>(GetProcAddress(module, "SetProcessDynamicEnforcedCetCompatibleRanges"));
    auto targetsRequired = (result.policyFlags & CONTEXT_IP_VALIDATION) != 0;
    auto rangeRequired = (result.policyFlags & SHADOW_STACK_ENABLED) != 0;
    if ((targetsRequired && !setTargets) || (rangeRequired && !setRanges)) return ERROR_PROC_NOT_FOUND;
    if (targetsRequired) {
        ContinuationTarget targets[MAX_CONTINUATIONS];
        for (DWORD i = 0; i < request.continuationCount; ++i) targets[i] = {request.code + request.continuations[i], add};
        result.registrationPossible = 1;
        auto success = setTargets(target, static_cast<USHORT>(request.continuationCount), targets);
        auto error = success ? ERROR_SUCCESS : GetLastError();
        for (DWORD i = 0; i < request.continuationCount; ++i)
            if (targets[i].flags & processed) result.continuationMask |= 1u << i;
        if (!success || result.continuationMask != Wire::allContinuations(request)) return error ? error : ERROR_INVALID_DATA;
    }
    if (rangeRequired) {
        EnforcedRange range{request.code, request.codeSize, static_cast<DWORD>(add)};
        result.registrationPossible = 1;
        auto success = setRanges(target, 1, &range);
        auto error = success ? ERROR_SUCCESS : GetLastError();
        result.rangeProcessed = (range.flags & processed) ? 1 : 0;
        if (!success || !result.rangeProcessed) return error ? error : ERROR_INVALID_DATA;
    }
    return ERROR_SUCCESS;
}
}

DWORD helper(HANDLE mapping, HANDLE target) noexcept {
    auto state = static_cast<Wire::State*>(MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(Wire::State)));
    if (!state) return GetLastError();
    auto request = state->request;
    Result result;
    result.error = apply(target, request, result);
    state->result = result;
    InterlockedExchange(&state->complete, 1);
    UnmapViewOfFile(state);
    CloseHandle(target);
    CloseHandle(mapping);
    return result.error;
}
}
