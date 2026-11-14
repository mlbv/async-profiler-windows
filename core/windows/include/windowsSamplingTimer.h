/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "arch.h"
#include "arguments.h"

class ThreadList;

namespace WindowsProfiler {
Error prepareSamplingThreads();
Error prepareThreadCpuClock();
ThreadList* listSamplingThreads();
u32 samplingThreadError();

class SamplingTimer {
    void* _timer = nullptr;
    void* _cancel = nullptr;
    u32 _error = 0;

  public:
    Error open();
    bool wait(u64 nanos);
    // Waits until an OS::nanotime() deadline; a passed deadline waits for the next tick.
    bool waitUntil(u64 deadline);
    // The timer expires on system timer ticks, so a wait can end up to one tick
    // after its deadline. Measures that period with back-to-back minimal waits.
    u64 measurePeriod();
    void cancel();
    void close();
    u32 error() const { return loadAcquire(_error); }
};
}
