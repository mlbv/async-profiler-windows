/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsEtwSession.h"
#include <atomic>

namespace WindowsProfiler::Etw {
// A control process created suspended runs on every processor at normal priority rather
// than inheriting a pinned or deprioritized target's scheduling.
ULONG controlScheduling(HANDLE process);
struct WatchResult {
    ULONG error = 0, eventsLost = 0, buffersLost = 0, realtimeBuffersLost = 0;
};
class SessionWatcher {
    HANDLE _mapping = nullptr, _ready = nullptr, _done = nullptr;
    HANDLE _parent = nullptr, _space = nullptr, _lock = nullptr, _section = nullptr, _process = nullptr;
    WatchState* _state = nullptr;
    ProfileShare* _share = nullptr;
    DWORD _pid = 0;
    PTP_WAIT _wait = nullptr;
    SRWLOCK _control = SRWLOCK_INIT;
    enum Phase { CAPTURE_ACTIVE = 1, HELPER_FAILED = 2, EXIT_EXPECTED = 4 };
    // One atomic word prevents activation and helper exit from both missing
    // each other, which is possible with two release/acquire flags.
    std::atomic<unsigned> _phase{0};
    static void CALLBACK helperExited(PTP_CALLBACK_INSTANCE, void* context, PTP_WAIT, TP_WAIT_RESULT);
    void stopWaiting();
    void close();
public:
    // share, if any, must outlive finish(); the watcher releases this capture's share.
    ULONG start(const Properties& properties, ProfileShare* share, bool secure = false);
    WatchState* state() { return _state; }
    DWORD pid() const { return _pid; }
    HANDLE process() const { return _process; }
    bool failed() const { return (_phase.load(std::memory_order_acquire) & HELPER_FAILED) != 0; }
    ULONG activate();
    ULONG cleanup();
    WatchResult finish();
};
}
