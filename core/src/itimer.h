/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _ITIMER_H
#define _ITIMER_H

#include "cpuEngine.h"


class ITimer : public CpuEngine {
#ifdef _WIN32
  protected:
    // The requested upstream event served by the Windows CPU-time engine.
    const char* _type = "cpu";
    Error startCounter(Arguments& args, bool cycles);
#endif
  public:
    const char* type() {
#ifdef _WIN32
        return _type;
#else
        return "itimer";
#endif
    }

    Error start(Arguments& args);
    void stop();
};

#ifdef _WIN32
class WindowsCycleEngine : public ITimer {
public:
    const char* type() override { return "cycles"; }
    const char* title() override { return "CPU cycle profile"; }
    const char* units() override { return "cycles"; }
    Error start(Arguments& args) override { return startCounter(args, true); }
};
#endif

#endif // _ITIMER_H
