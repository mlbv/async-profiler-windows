/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <cstdint>

namespace WindowsProfiler::Etw {
// Pointer-free so the same request can be validated by the privileged helper.
struct RawPmuConfig {
    std::uint64_t config = 0;
    ULONG family = 0, model = 0, stepping = 0;
    ULONG vendor = 0; // 1 = Intel, 2 = AMD
};
struct RawPmuLease {
    RawPmuConfig config;
    ULONG interval = 0;
    WCHAR name[96]{};
    ULONG source = 0, minimum = 0, maximum = 0;
    volatile LONG pending = 0;
};
bool isRawPmu(const char* name);
// Parsing and preparation never change kernel state.
const char* parseRawPmu(const char* name, RawPmuConfig& config);
ULONG prepareRawPmu(const RawPmuConfig& config, ULONG interval, RawPmuLease& lease);
// Hold the profiling configuration mutex, refuse other PMC sessions, and place
// the prepared lease in watchdog-visible storage before either operation.
ULONG addRawPmu(RawPmuLease& lease);
// Bounds become known only after registration. Explicit requests remain strict;
// an implicit default adapts to the host without changing the event encoding.
ULONG selectRawPmuInterval(RawPmuLease& lease, bool explicitInterval);
ULONG removeRawPmu(RawPmuLease& lease);
}
