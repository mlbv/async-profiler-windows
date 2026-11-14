/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <atomic>

#if RELOAD_VERSION == 2
#pragma code_seg(push, ".text$a")
extern "C" __declspec(dllexport) __declspec(noinline) DWORD ReloadFiller(DWORD value) {
    for (DWORD i = 0; i < 128; ++i) value = (value << 5) ^ (value >> 7) ^ i;
    return value;
}
#pragma code_seg(pop)
#endif

#pragma code_seg(push, ".text$m")
namespace ReloadFixture {
#if RELOAD_VERSION == 1
struct VersionOne { static __declspec(noinline) DWORD work(DWORD value) { return value + 101; } };
using Version = VersionOne;
#else
struct VersionTwo { static __declspec(noinline) DWORD work(DWORD value) { return value + 202; } };
using Version = VersionTwo;
#endif
}
#pragma code_seg(pop)

extern "C" __declspec(dllexport) std::uint64_t RunReloadWork(DWORD count) {
    std::uint64_t sum = 0;
    for (DWORD i = 0; i < count; ++i) sum += ReloadFixture::Version::work(i);
    return sum;
}
extern "C" __declspec(dllexport) std::uintptr_t ReloadTargetAddress() {
    return reinterpret_cast<std::uintptr_t>(&ReloadFixture::Version::work);
}

extern "C" __declspec(dllexport) std::uint64_t RunReloadTimedWork(DWORD milliseconds) {
    LARGE_INTEGER start, now, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    std::uint64_t sum = 0;
    do {
        for (DWORD i = 0; i < 10000; ++i) sum += ReloadFixture::Version::work(i);
        QueryPerformanceCounter(&now);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart * milliseconds / 1000);
    return sum;
}

std::atomic<DWORD> threadAttachDelay{0};
extern "C" __declspec(dllexport) void ConfigureThreadAttach(DWORD milliseconds) { threadAttachDelay.store(milliseconds); }
extern "C" __declspec(dllexport) __declspec(noinline) void ReloadThreadAttachBusy(DWORD milliseconds) {
    LARGE_INTEGER start, now, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    volatile std::uint64_t value = 1;
    do {
        for (int i = 0; i < 10000; ++i) value = value * 31 + (value >> 7);
        QueryPerformanceCounter(&now);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart * milliseconds / 1000);
}
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, void*) {
    if (reason == DLL_THREAD_ATTACH) {
        DWORD delay = threadAttachDelay.load();
        if (delay) ReloadThreadAttachBusy(delay);
    }
    return TRUE;
}
