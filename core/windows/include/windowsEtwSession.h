/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <evntrace.h>
#include <vector>
#include "windowsRawPmu.h"

namespace WindowsProfiler::Etw {
// PERF_PMC_PROFILE occupies PERFINFO_GROUPMASK.Masks[1], bit 0x400:
// https://learn.microsoft.com/windows/win32/api/evntrace/nf-evntrace-traceconfigurelastbranchrecord
constexpr ULONG PMC_PROFILE_MASK = 0x400;
constexpr ULONG WATCH_PROTOCOL = 3;
struct Properties {
    EVENT_TRACE_PROPERTIES p;
    WCHAR name[128];
};
struct WatchState {
    ULONG protocol;
    ULONG size;
    ULONG ownerPid;
    GUID guid;
    WCHAR name[128];
    volatile LONG sessionOwned;
    // Set under the registry lock before the owner's first registry mutation.
    volatile LONG shareOwned;
    ULONG shareSlot;
    volatile LONG ready;
    ULONG startupError;
    ULONG stopError;
    ULONG restoreError;
    ULONG eventsLost;
    ULONG buffersLost;
    ULONG realtimeBuffersLost;
};
struct SessionProperties { EVENT_TRACE_PROPERTIES p; WCHAR names[2048]; };
ULONG querySessions(std::vector<SessionProperties>& properties);
// Sessions with the timer or PMC profile flag, except those with the given GUIDs.
ULONG otherProfilers(bool pmc, bool& busy, const std::vector<GUID>& excluded = {});
// Stops the named session only if it still has this GUID. A missing session
// succeeds; a reused name fails with ERROR_INVALID_DATA.
ULONG stopSession(const WCHAR* name, const GUID& guid, Properties& stopped);
class ProfileShare;
// Called serially by the target, or by its watcher after the target exits.
// The target marks ownership before each OS mutation, so termination between
// the API call and its return cannot hide a resource from the watcher.
void cleanupSession(WatchState& state, ProfileShare* share);
}
