/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <span>

namespace WindowsProfiler::SoftwareMitigations {
constexpr DWORD SHADOW_STACK_ENABLED = 1u << 0;
constexpr DWORD CONTEXT_IP_VALIDATION = 1u << 2;
constexpr DWORD REQUIRED_POLICY_BITS = SHADOW_STACK_ENABLED | CONTEXT_IP_VALIDATION;
constexpr size_t MAX_CODE_BYTES = 64;
constexpr size_t MAX_CONTINUATIONS = 24;

struct Result {
    DWORD error = ERROR_SUCCESS;
    DWORD policyFlags = 0;
    // Bit i: continuation i was processed.
    DWORD continuationMask = 0;
    DWORD rangeProcessed = 0;
    // Retain the immutable code if registration succeeded, partially succeeded,
    // or the helper's completion could not be established.
    DWORD registrationPossible = 0;
};

// code is one immutable displaced-execution block; continuations are the
// strictly increasing offsets where exception dispatch may resume it. The
// caller keeps this RX allocation alive whenever registrationPossible is
// nonzero. Success establishes the requirements of the reported policy,
// without changing it.
Result prepare(const unsigned char* code, size_t codeSize, std::span<const std::uint8_t> continuations) noexcept;

// One-shot role: both handles come from the target's explicit inheritance list.
DWORD helper(HANDLE mapping, HANDLE target) noexcept;

namespace Wire {
constexpr DWORD VERSION = 2;
struct Request {
    DWORD version;
    DWORD size;
    DWORD pid;
    DWORD policyFlags;
    std::uint64_t creation;
    std::uintptr_t code;
    size_t codeSize;
    DWORD continuationCount;
    std::uint8_t continuations[MAX_CONTINUATIONS];
};
struct State {
    Request request;
    Result result;
    volatile LONG complete;
};
static_assert(sizeof(Request) == 72 && sizeof(Result) == 20 && sizeof(State) == 96);
inline DWORD allContinuations(const Request& request) noexcept { return (1u << request.continuationCount) - 1; }
inline bool validCode(const Request& request) noexcept {
    if (!request.code || !request.codeSize || request.codeSize > MAX_CODE_BYTES
            || request.code > UINTPTR_MAX - request.codeSize
            || !request.continuationCount || request.continuationCount > MAX_CONTINUATIONS) return false;
    for (DWORD index = 0; index < request.continuationCount; ++index)
        if (request.continuations[index] >= request.codeSize
                || (index && request.continuations[index] <= request.continuations[index - 1])) return false;
    return true;
}
}
}
