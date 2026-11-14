/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "native_cet_test_process.h"
#include <cwchar>
int wmain(int argc, WCHAR** argv) {
    if (argc != 6 || (std::wcscmp(argv[1], L"strict") && std::wcscmp(argv[1], L"compatible"))) return 2;
    bool strict = std::wcscmp(argv[1], L"strict") == 0;
    std::wstring command;
    for (int i = 2; i < argc; ++i) {
        if (i != 2) command += L" ";
        command += L"\"" + std::wstring(argv[i]) + L"\"";
    }
    command += strict ? L" strict" : L" compatible";
    DWORD result = runCetTestProcess(argv[2], std::move(command), strict);
    std::printf("SOFTWARE_ENTRY_CET_CHILD_EXIT=%lu strict=%u\n", result, strict ? 1u : 0u);
    return static_cast<int>(result);
}
