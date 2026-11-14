/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsNativeErrorState.h"
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace {
void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s Windows=%lu\n", message, GetLastError()); std::exit(1); }
}
}
int main() {
    using namespace WindowsProfiler;
    auto error = prepareNativeErrorState();
    require(error == nullptr, error ? error : "Native error-state setup");
    require(prepareNativeErrorState() == nullptr, "Repeated cold setup");
    using GetStatus = LONG (WINAPI*)();
    auto getStatus = std::bit_cast<GetStatus>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetLastNtStatus"));
    require(getStatus != nullptr, "Loaded status getter");
    WCHAR root[MAX_PATH], file[MAX_PATH];
    require(GetTempPathW(MAX_PATH, root) && GetTempFileNameW(root, L"nes", 0, file), "Owned test file");
    std::wstring absent = std::wstring(file) + L".missing";
    require(GetFileAttributesW(absent.c_str()) == INVALID_FILE_ATTRIBUTES, "Missing fixture path");
    auto originalStatus = getStatus();
    SetLastError(0x1e4eaa);
    {
        SavedNativeErrorState saved;
        require(!CreateDirectoryW(file, nullptr), "Existing file cannot become a directory");
        require(GetLastError() != 0x1e4eaa && getStatus() != originalStatus, "Fixture mutates both error domains");
        auto nestedStatus = getStatus();
        auto nestedError = GetLastError();
        {
            SavedNativeErrorState nested;
            require(GetFileAttributesW(absent.c_str()) == INVALID_FILE_ATTRIBUTES, "Nested missing path");
            SetLastError(0x217ace);
        }
        require(GetLastError() == nestedError && getStatus() == nestedStatus, "Nested error state restored");
    }
    require(GetLastError() == 0x1e4eaa && getStatus() == originalStatus, "Both error domains restored");
    require(DeleteFileW(file), "Remove owned test file");
    std::puts("NATIVE_ERROR_STATE_OK loadedGetter=1 nativeStatus=1 lastError=1 nested=1 coldIdempotent=1");
}
