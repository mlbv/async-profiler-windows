/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "importHooks.h"
#include "asprof.h"
#include <cstdio>
#include <cwchar>
#include <string>

namespace {
decltype(&CreateToolhelp32Snapshot) original;
unsigned calls, injected;
DWORD fault;
bool persistent;
std::string output;
void collect(const char* bytes, size_t length) { output.append(bytes, length); }
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
HANDLE WINAPI snapshot(DWORD flags, DWORD pid) {
    ++calls;
    if (persistent || injected == 0) {
        ++injected;
        SetLastError(fault);
        return INVALID_HANDLE_VALUE;
    }
    return original(flags, pid);
}
unsigned long long metric(const char* name) {
    std::string key = std::string(name) + " ";
    auto offset = output.find(key);
    require(offset != std::string::npos, name);
    return std::stoull(output.substr(offset + key.size()));
}
}

int wmain(int argc, WCHAR** argv) try {
    require(argc == 3, "Usage: snapshot-fault DLL retry|access|persistent");
    fault = std::wcscmp(argv[2], L"access") == 0 ? ERROR_ACCESS_DENIED : ERROR_BAD_LENGTH;
    persistent = std::wcscmp(argv[2], L"persistent") == 0;
    require(persistent || std::wcscmp(argv[2], L"retry") == 0 || fault == ERROR_ACCESS_DENIED, "Unknown fault case");
    auto library = LoadLibraryW(argv[1]);
    require(library != nullptr, "Cannot load profiler");
    auto init = reinterpret_cast<asprof_init_t>(GetProcAddress(library, "asprof_init"));
    auto execute = reinterpret_cast<asprof_execute_t>(GetProcAddress(library, "asprof_execute"));
    require(init && execute, "C API is unavailable");
    init();
    auto changed = WindowsProfiler::Imports::patch_module(library,
        [](std::string_view, std::string_view name, void* address) -> void* {
            if (name != "CreateToolhelp32Snapshot") return nullptr;
            original = reinterpret_cast<decltype(original)>(address);
            return reinterpret_cast<void*>(snapshot);
        });
    require(changed == 1 && original, "Snapshot import was not intercepted");
    auto error = execute("start,event=cpu,interval=100ms", collect);
    if (!persistent && fault == ERROR_BAD_LENGTH) {
        require(error == nullptr, "Recovered snapshot error prevented profiling");
        require(execute("stop", collect) == nullptr, "Cannot stop recovered recording");
    } else {
        require(error != nullptr, "Import initialization failure did not reject profiling");
        output.clear();
        require(execute("status", collect) == nullptr && output.find("not active") != std::string::npos,
            "Initialization failure left profiling active");
    }
    output.clear();
    require(execute("metrics", collect) == nullptr, "Cannot read profiler metrics");
    auto retries = metric("windows_snapshot_retries");
    auto failures = metric("windows_snapshot_failures");
    require(injected > 0 && metric("windows_snapshot_last_error") == fault, "Injected Windows error was not retained");
    if (persistent) {
        require(retries == failures && failures > 0 && calls == 2 * failures, "Persistent failure was not bounded to two calls per snapshot");
    } else if (fault == ERROR_BAD_LENGTH) {
        require(injected == 1 && retries == 1 && failures == 0 && metric("windows_import_failed") == 0, "Transient snapshot failure poisoned import interception");
    } else {
        require(injected == 1 && retries == 0 && failures == 1, "Unrelated Windows errors must not be retried");
    }
    WindowsProfiler::Imports::patch_module(library,
        [](std::string_view, std::string_view name, void*) -> void* {
            return name == "CreateToolhelp32Snapshot" ? reinterpret_cast<void*>(original) : nullptr;
        });
    std::printf("SNAPSHOT_FAULT_OK case=%ls calls=%u retries=%llu failures=%llu\n", argv[2], calls, retries, failures);
    return 0;
} catch (const std::exception& error) {
    std::fprintf(stderr, "%s\n%s\n", error.what(), output.c_str());
    return 1;
}
