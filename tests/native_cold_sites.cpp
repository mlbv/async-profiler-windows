/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "native_cet_test_process.h"
#include <cstdio>
#include <cwchar>
#include <bit>
#include <string>
#include <vector>

namespace {
int launch(const WCHAR* library, const WCHAR* fixture, bool strict) {
    WCHAR path[32768];
    auto length = GetModuleFileNameW(nullptr, path, 32768);
    if (!length || length >= 32768) return 10;
    std::wstring command = L"\"" + std::wstring(path) + L"\" --cet-child \"" + library
        + L"\" \"" + fixture + L"\" " + (strict ? L"strict" : L"compatible");
    DWORD result = runCetTestProcess(path, std::move(command), strict);
    std::printf("COLD_SITE_CET_CHILD_EXIT=%lu strict=%u\n", result, strict ? 1u : 0u);
    return static_cast<int>(result);
}
}

int wmain(int argc, WCHAR** argv) {
    if (argc == 4 && (std::wcscmp(argv[1], L"--cet") == 0 || std::wcscmp(argv[1], L"--strict-cet") == 0))
        return launch(argv[2], argv[3], std::wcscmp(argv[1], L"--strict-cet") == 0);
    bool cet = argc == 5 && std::wcscmp(argv[1], L"--cet-child") == 0;
    if (argc != 3 && !cet) return 2;
    if (cet) {
        DWORD flags = 0;
        bool strict = std::wcscmp(argv[4], L"strict") == 0;
        DWORD required = strict ? 0x15u : 0x5u;
        if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &flags, sizeof(flags))
                || (flags & required) != required || (flags & 0x20au)
                || ((flags & 0x10u) != 0) != strict) {
            std::printf("COLD_SITE_CET_POLICY_FAIL actual=%lx required=%lx Windows=%lu\n", flags, required, GetLastError());
            return 16;
        }
        std::printf("COLD_SITE_CET_FLAGS=%lx strict=%u\n", flags, strict ? 1u : 0u);
        std::fflush(stdout);
    }
    auto library = LoadLibraryW(argv[cet ? 2 : 1]);
    if (!library) { std::printf("Cannot load private cold preparation artifact Windows=%lu\n", GetLastError()); return 3; }
    using Test = DWORD (*)(const WCHAR*, char*, DWORD);
    auto test = std::bit_cast<Test>(GetProcAddress(library, "asprof_test_native_cold_sites"));
    if (!test) { std::puts("Required private test export is absent"); return 4; }
    WCHAR temporary[MAX_PATH], directory[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, temporary) || !GetTempFileNameW(temporary, L"cps", 0, directory)
            || !DeleteFileW(directory) || !CreateDirectoryW(directory, nullptr)) return 5;
    std::wstring fixture = std::wstring(directory) + L"\\active.dll";
    if (!CopyFileW(argv[cet ? 3 : 2], fixture.c_str(), TRUE)) return 6;
    char report[1024]{};
    auto result = test(fixture.c_str(), report, sizeof(report));
    std::printf("%s", report);
    std::wprintf(L"COLD_SITE_OWNED_FIXTURE=%ls\n", directory);
    return static_cast<int>(result);
}
