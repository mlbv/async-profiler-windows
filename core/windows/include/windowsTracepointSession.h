/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <evntrace.h>

namespace WindowsProfiler::Tracepoint {
inline constexpr GUID KERNEL_PROCESS_PROVIDER = {0x22fb2cd6,0x0e7b,0x422b,{0xa0,0xc7,0x2f,0xad,0x1f,0xd0,0xe7,0x16}};
struct ProviderSpec {
    GUID provider{};
    USHORT eventId = 0;
    bool named = false, stacks = true;
};
struct ProviderLease {
    TRACEHANDLE session = 0;
    GUID source{};
    ULONG pid = 0;
    ProviderSpec selected{};
    bool lifecycleEnabled = false, primaryEnabled = false;
};
// Kernel-Process selection arms its final merged filter here exactly once;
// enableSelected is then a no-op. Other providers arm after the target has
// taken its initial thread snapshot. Caller gates preactivation samples.
ULONG enableLifecycle(ProviderLease& lease);
ULONG enableSelected(ProviderLease& lease);
// Disables each physical provider once. The caller must still stop its
// private session even when a provider API fails; errors are not swallowed.
ULONG disableProviders(ProviderLease& lease);
}
