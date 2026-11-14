/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwSession.h"
#include <bcrypt.h>
#include <cstdio>
#include <cwchar>
#include <cstddef>
#include <stdexcept>
#include <cstring>

using namespace WindowsProfiler::Etw;
namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct Session {
    TRACEHANDLE handle = 0;
    Properties properties{};
    ~Session() { if (handle) ControlTraceW(handle, nullptr, &properties.p, EVENT_TRACE_CONTROL_STOP); }
};
}
int main(int argc, char** argv) try {
    if (argc == 2 && std::strcmp(argv[1], "--sessions") == 0) {
        std::vector<SessionProperties> sessions;
        auto error = querySessions(sessions);
        if (error) { std::fprintf(stderr, "QueryAllTraces: %lu\n", error); return 1; }
        for (const auto& session : sessions) {
            auto name = reinterpret_cast<const WCHAR*>(reinterpret_cast<const unsigned char*>(&session) + session.p.LoggerNameOffset);
            if (std::wcsncmp(name, L"async-profiler-", 15) == 0) std::printf("%ls\n", name);
        }
        return 0;
    }
    require(argc == 1, "Unknown ETW controller test command");
    Session session;
    auto& properties = session.properties;
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    std::swprintf(properties.name, 128, L"async-profiler-%lu-%llu", GetCurrentProcessId(), static_cast<unsigned long long>(counter.QuadPart));
    properties.p.Wnode.BufferSize = sizeof(properties);
    properties.p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.p.Wnode.ClientContext = 1;
    properties.p.LoggerNameOffset = offsetof(Properties, name);
    properties.p.LogFileMode = EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE;
    require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&properties.p.Wnode.Guid), sizeof(GUID), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "GUID generation");
    auto error = StartTraceW(&session.handle, properties.name, &properties.p);
    if (error) { std::fprintf(stderr, "StartTrace: %lu\n", error); return 1; }
    WatchState state{};
    state.sessionOwned = 1;
    state.guid = properties.p.Wnode.Guid;
    state.guid.Data1 ^= 1;
    std::wmemcpy(state.name, properties.name, 128);
    cleanupSession(state, nullptr);
    require(state.stopError == ERROR_INVALID_DATA && state.restoreError == 0 && state.sessionOwned == 1,
        "A different session identity must prevent stop");
    Properties query{};
    query.p.Wnode.BufferSize = sizeof(query);
    query.p.LoggerNameOffset = offsetof(Properties, name);
    require(ControlTraceW(0, state.name, &query.p, EVENT_TRACE_CONTROL_QUERY) == ERROR_SUCCESS
        && IsEqualGUID(query.p.Wnode.Guid, properties.p.Wnode.Guid), "Foreign identity was stopped");
    state.guid = properties.p.Wnode.Guid;
    cleanupSession(state, nullptr);
    require(state.stopError == 0 && state.restoreError == 0 && state.sessionOwned == 0, "Own session cleanup");
    session.handle = 0;
    query = {};
    query.p.Wnode.BufferSize = sizeof(query);
    require(ControlTraceW(0, state.name, &query.p, EVENT_TRACE_CONTROL_QUERY) == ERROR_WMI_INSTANCE_NOT_FOUND, "Own session still exists");
    cleanupSession(state, nullptr);
    require(state.stopError == 0 && state.restoreError == 0, "Repeated cleanup must be harmless");
    std::puts("ETW_CONTROL_OK identityGuard=1 cleanup=1 repeatedCleanup=1");
    return 0;
} catch (const std::exception& error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
}
