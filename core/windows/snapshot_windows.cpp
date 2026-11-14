/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "writer.h"
#include <tlhelp32.h>
#include <atomic>

namespace WindowsProfiler {
namespace {
std::atomic<std::uint64_t> retries{0}, failures{0};
std::atomic<DWORD> lastError{0};
}
HANDLE toolhelpSnapshot(DWORD flags, DWORD pid) {
    auto snapshot = CreateToolhelp32Snapshot(flags, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        auto error = GetLastError();
        lastError.store(error, std::memory_order_relaxed);
        // Toolhelp can observe the loader between module-list updates.
        // https://learn.microsoft.com/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
        if (error == ERROR_BAD_LENGTH) {
            retries.fetch_add(1, std::memory_order_relaxed);
            SwitchToThread();
            snapshot = CreateToolhelp32Snapshot(flags, pid);
        }
        if (snapshot == INVALID_HANDLE_VALUE) {
            lastError.store(GetLastError(), std::memory_order_relaxed);
            failures.fetch_add(1, std::memory_order_relaxed);
        }
    }
    return snapshot;
}
void writeSnapshotMetrics(Writer& out) {
    out << "windows_snapshot_retries " << static_cast<u64>(retries.load()) << '\n';
    out << "windows_snapshot_failures " << static_cast<u64>(failures.load()) << '\n';
    out << "windows_snapshot_last_error " << static_cast<u64>(lastError.load()) << '\n';
}
}
