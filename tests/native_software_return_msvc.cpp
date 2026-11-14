/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// MSVC-compiled return-probe targets: SEH scopes, C++ EH frames and /O2 layouts.
#include <windows.h>
#include <cstdint>

using Filter = int (*)(EXCEPTION_POINTERS*);
using Work = std::uint64_t (*)(std::uint64_t);
extern "C" {
__declspec(dllexport) volatile std::uint64_t MsvcDestroyed = 0;
__declspec(dllexport) volatile std::uint64_t MsvcSink = 0;
}

namespace {
struct Guard {
    ~Guard() { MsvcDestroyed = MsvcDestroyed + 1; }
};
}

__declspec(noinline) void MsvcMaybeThrow(std::uint64_t value) {
    MsvcSink = value;
    if (value & 1) throw static_cast<int>(value);
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t MsvcWork(std::uint64_t value) {
    MsvcSink = value;
    return value * 2 + 1;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t MsvcSeh(std::uint64_t address) {
    __try {
        return *reinterpret_cast<volatile std::uint64_t*>(address) + 1;
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return 99;
    }
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t MsvcCxx(std::uint64_t value) {
    Guard guard;
    MsvcMaybeThrow(value);
    return value + 6;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t MsvcCatch(std::uint64_t value) {
    try {
        MsvcMaybeThrow(value);
        return value + 8;
    } catch (int thrown) {
        return static_cast<std::uint64_t>(thrown);
    }
}
// An early exit before the expensive path invites MSVC shrink-wrapping.
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t MsvcShrink(std::uint64_t value) {
    if (value < 4) return value * 3;
    auto first = MsvcWork(value), second = MsvcWork(first ^ value), third = MsvcWork(second + value);
    return first + second + third + value;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t MsvcCxxDriver(unsigned count) {
    std::uint64_t returned = 0;
    for (unsigned index = 0; index < count; ++index) {
        try { returned += MsvcCxx(index) == index + 6; } catch (int) {}
    }
    return returned;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t MsvcSehDriver(unsigned count) {
    volatile std::uint64_t value = 5;
    std::uint64_t sum = 0;
    for (unsigned index = 0; index < count; ++index)
        sum += MsvcSeh(index & 1 ? 0 : reinterpret_cast<std::uint64_t>(&value));
    return sum;
}
// The filter is reached only if exception dispatch unwinds every inner frame.
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t MsvcFiltered(Filter filter, Work work, std::uint64_t value) {
    __try {
        return work(value);
    } __except (filter(GetExceptionInformation())) {
        return 0;
    }
}
