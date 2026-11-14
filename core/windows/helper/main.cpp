/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwProfileShare.h"
#include "windowsPrivilege.h"
#include "windowsEtwBroker.h"
#include "windowsEtwBootstrap.h"
#include "windowsEtwControllerSecurity.h"
#include "windowsSoftwareMitigations.h"
#include "windowsPreload.h"
#include <cwchar>
#include <cstdlib>
#include <cstdint>
#include <initializer_list>
#include <string>

using namespace WindowsProfiler::Etw;
namespace {
HANDLE handle(const WCHAR* text) {
    WCHAR* end;
    auto value = std::wcstoull(text, &end, 10);
    return end != text && *end == 0 ? reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(value)) : nullptr;
}
}

int wmain(int argc, WCHAR** argv) {
    if (argc > 1 && std::wcscmp(argv[1], L"--preload") == 0) return WindowsProfiler::Preload::launch(argc, argv);
    if (argc == 4 && std::wcscmp(argv[1], L"--software-mitigations") == 0) {
        auto mapping = handle(argv[2]), target = handle(argv[3]);
        return mapping && target ? WindowsProfiler::SoftwareMitigations::helper(mapping, target) : ERROR_INVALID_HANDLE;
    }
    if (argc == 5 && std::wcscmp(argv[1], L"--etw-broker-worker") == 0) {
        auto mapping = handle(argv[2]), ready = handle(argv[3]), parent = handle(argv[4]);
        return mapping && ready && parent ? WindowsProfiler::Etw::Broker::worker(mapping, ready, parent) : ERROR_INVALID_HANDLE;
    }
    bool once = argc == 5 && std::wcscmp(argv[4], L"--once") == 0;
    if ((argc == 3 || argc == 4 || once) && std::wcscmp(argv[1], L"--etw-broker") == 0) {
        WCHAR* end;
        auto pid = std::wcstoul(argv[2], &end, 10);
        auto pipe = std::wstring(L"\\\\.\\pipe\\async-profiler-") + std::to_wstring(pid);
        return end != argv[2] && !*end && pid
            ? WindowsProfiler::Etw::Broker::server(pid, argc >= 4 ? argv[3] : pipe.c_str(), once) : ERROR_INVALID_PARAMETER;
    }
    bool brokerWatch = argc == 9 && std::wcscmp(argv[1], L"--etw-watch-broker") == 0;
    if (argc != 9 || (!brokerWatch && std::wcscmp(argv[1], L"--etw-watch") != 0)) return ERROR_INVALID_PARAMETER;
    auto mapping = handle(argv[2]), ready = handle(argv[3]), done = handle(argv[4]);
    auto parent = handle(argv[5]), space = handle(argv[6]), lock = handle(argv[7]), section = handle(argv[8]);
    if (!mapping || !ready || !done || !parent || !space != !lock || !lock != !section) return ERROR_INVALID_HANDLE;
    ProfileShare share;
    auto state = static_cast<WatchState*>(MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(WatchState)));
    if (!state) return GetLastError();
    ULONG error = ERROR_SUCCESS;
    WindowsProfiler::Privilege privilege(L"SeSystemProfilePrivilege");
    WCHAR prefix[48];
    std::swprintf(prefix, 48, L"async-profiler-%lu-", state->ownerPid);
    if (state->protocol != WATCH_PROTOCOL || state->size != sizeof(WatchState)) error = ERROR_REVISION_MISMATCH;
    else if (GetProcessId(parent) != state->ownerPid || state->name[127] != 0
            || std::wcsncmp(state->name, prefix, std::wcslen(prefix)) != 0) error = ERROR_INVALID_DATA;
    else {
        if (brokerWatch) error = WindowsProfiler::Etw::Broker::hardenControllerIdentity();
        if (!error) error = privilege.enable();
        if (!error && lock) error = share.attach(space, lock, section);
    }
    state->startupError = error;
    InterlockedExchange(&state->ready, error == ERROR_SUCCESS ? 1 : -1);
    SetEvent(ready);
    if (!error) {
        HANDLE events[] = {parent, done};
        auto result = WaitForMultipleObjects(2, events, FALSE, INFINITE);
        if (result == WAIT_OBJECT_0 || result == WAIT_OBJECT_0 + 1) {
            try {
                cleanupSession(*state, lock ? &share : nullptr);
                error = state->stopError ? state->stopError : state->restoreError;
            } catch (...) { error = ERROR_NOT_ENOUGH_MEMORY; }
        } else error = GetLastError();
    }
    UnmapViewOfFile(state);
    for (auto object : {mapping, ready, done, parent}) CloseHandle(object);
    return error;
}
