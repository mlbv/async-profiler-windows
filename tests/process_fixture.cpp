/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) return 2;
    constexpr SIZE_T memorySize = 64 * 1024 * 1024;
    auto memory = static_cast<volatile unsigned char*>(VirtualAlloc(nullptr, memorySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!memory) return 3;
    for (SIZE_T offset = 0; offset < memorySize; offset += 4096) memory[offset] = 1;
    auto file = CreateFileW(argv[1], GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 4;
    DWORD written;
    if (!WriteFile(file, const_cast<const unsigned char*>(memory), 8 * 1024 * 1024, &written, nullptr) || written != 8 * 1024 * 1024) return 5;
    PROCESS_MEMORY_COUNTERS_EX2 counters{};
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters))) return 6;
    std::printf("READY %lu %zu\n", GetCurrentProcessId(), counters.PrivateWorkingSetSize);
    std::fflush(stdout);
    LARGE_INTEGER frequency, start, now;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    volatile std::uint64_t hash = 1;
    do {
        for (int i = 0; i < 100000; ++i) hash = (hash ^ (hash >> 13)) * 0x100000001b3ULL;
        QueryPerformanceCounter(&now);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart * 60);
    CloseHandle(file);
    VirtualFree(const_cast<unsigned char*>(memory), 0, MEM_RELEASE);
    return hash == 0;
}
