/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwSession.h"
#include "windowsEtwProfileShare.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <vector>

namespace WindowsProfiler::Etw {
ULONG querySessions(std::vector<SessionProperties>& properties) try {
    properties.assign(256, {});
    std::array<EVENT_TRACE_PROPERTIES*, 256> pointers;
    for (size_t i = 0; i < pointers.size(); ++i) {
        properties[i].p.Wnode.BufferSize = sizeof(SessionProperties);
        pointers[i] = &properties[i].p;
    }
    ULONG count = 0;
    auto result = QueryAllTracesW(pointers.data(), static_cast<ULONG>(pointers.size()), &count);
    if (result == ERROR_WMI_INSTANCE_NOT_FOUND || result == ERROR_INVALID_HANDLE) {
        result = QueryAllTracesW(pointers.data(), static_cast<ULONG>(pointers.size()), &count);
    }
    if (result) return result;
    if (count > pointers.size()) return ERROR_INVALID_DATA;
    properties.resize(count);
    return ERROR_SUCCESS;
} catch (...) {
    return ERROR_NOT_ENOUGH_MEMORY;
}

ULONG otherProfilers(bool pmc, bool& busy, const std::vector<GUID>& excluded) {
    std::vector<SessionProperties> sessions;
    auto result = querySessions(sessions);
    if (result) return result;
    busy = false;
    for (const auto& session : sessions) {
        auto properties = &session.p;
        if (!(properties->LogFileMode & EVENT_TRACE_SYSTEM_LOGGER_MODE)
                || std::any_of(excluded.begin(), excluded.end(), [&](const GUID& guid) { return IsEqualGUID(guid, properties->Wnode.Guid); })) continue;
        ULONG masks[8]{};
        ULONG length = 0;
        result = TraceQueryInformation(properties->Wnode.HistoricalContext, TraceSystemTraceEnableFlagsInfo,
            masks, sizeof(masks), &length);
        if (result == ERROR_WMI_INSTANCE_NOT_FOUND || result == ERROR_INVALID_HANDLE) continue;
        if (result) return result;
        if (pmc ? (masks[1] & PMC_PROFILE_MASK) != 0 : (masks[0] & EVENT_TRACE_FLAG_PROFILE) != 0) busy = true;
    }
    return ERROR_SUCCESS;
}

ULONG stopSession(const WCHAR* name, const GUID& guid, Properties& stopped) {
    stopped = {};
    stopped.p.Wnode.BufferSize = sizeof(stopped);
    stopped.p.LoggerNameOffset = offsetof(Properties, name);
    auto result = ControlTraceW(0, name, &stopped.p, EVENT_TRACE_CONTROL_QUERY);
    if (result == ERROR_WMI_INSTANCE_NOT_FOUND) return ERROR_SUCCESS;
    if (result) return result;
    // A reused name must never authorize stopping another session.
    if (!IsEqualGUID(stopped.p.Wnode.Guid, guid)) return ERROR_INVALID_DATA;
    result = ControlTraceW(stopped.p.Wnode.HistoricalContext, nullptr, &stopped.p, EVENT_TRACE_CONTROL_STOP);
    return result == ERROR_WMI_INSTANCE_NOT_FOUND ? ERROR_SUCCESS : result;
}

void cleanupSession(WatchState& state, ProfileShare* share) {
    state.stopError = state.restoreError = ERROR_SUCCESS;
    if (InterlockedCompareExchange(&state.sessionOwned, 0, 0)) {
        Properties stopped;
        state.stopError = stopSession(state.name, state.guid, stopped);
        if (state.stopError) return;
        state.eventsLost = stopped.p.EventsLost;
        state.buffersLost = stopped.p.LogBuffersLost;
        state.realtimeBuffersLost = stopped.p.RealTimeBuffersLost;
        InterlockedExchange(&state.sessionOwned, 0);
    }
    if (share) state.restoreError = share->release(state);
}
}
