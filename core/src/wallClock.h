/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _WALLCLOCK_H
#define _WALLCLOCK_H

#include <signal.h>
#include <pthread.h>
#include "engine.h"
#include "os.h"
#ifdef _WIN32
#include "windowsSamplingTimer.h"
#endif

struct ThreadSleepState;

class WallClock : public Engine {
  private:
    enum Mode {
        CPU_ONLY,
        WALL_BATCH,
        WALL_LEGACY
    };

    static int64_t _interval;
    static int _signal;
    static Mode _mode;

    volatile bool _running;
    pthread_t _thread;
#ifdef _WIN32
    WindowsProfiler::SamplingTimer _timer;
#endif

    void timerLoop();
    bool waitForTimer(u64 nanos);

    static void* threadEntry(void* wall_clock) {
        ((WallClock*)wall_clock)->timerLoop();
        return NULL;
    }

    static u64 getThreadFingerprint(void* ucontext);

    static void signalHandler(int signo, siginfo_t* siginfo, void* ucontext);

    static void recordWallClock(const ThreadSleepState& tss, ThreadState state, int tid);

  public:
    const char* type() {
        return "wall";
    }

    const char* title() {
        return _mode == CPU_ONLY ? "CPU profile" : "Wall clock profile";
    }

    const char* units() {
        return "ns";
    }

    int64_t interval() {
        return _interval;
    }

    Error start(Arguments& args);
    void stop();
    void flush();
#ifdef _WIN32
    Error timerError() {
        if (_timer.error() != 0) return Error("Windows wall-clock sampling timer failed");
        return WindowsProfiler::samplingThreadError() != 0 ? Error("Windows wall-clock thread snapshot failed") : Error::OK;
    }
#endif
};

#endif // _WALLCLOCK_H
