/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _FLIGHTRECORDER_H
#define _FLIGHTRECORDER_H

#include "arch.h"
#include "arguments.h"
#include "event.h"
#include "log.h"
#include "lookup.h"

class Recording;

class FlightRecorder {
  private:
    Recording* _rec;
    MethodMap _retained_methods;

    Error startMasterRecording(Arguments& args, const char* filename);
    Error stopMasterRecording();

  public:
    static const LogLevel MIN_LOG_LEVEL = LogLevel::LOG_DEBUG;
    static const size_t MAX_STRING_BYTES = 8191;

    FlightRecorder() : _rec(NULL) {
    }

    Error start(Arguments& args, bool reset);
    void reset();
    Error stop(const char* copy_file = nullptr);
    void flush();
    Error snapshot(const char* filename);
    size_t usedMemory();
    bool timerTick(u64 wall_time, u32 gc_id);
    void processMonitorCycle(u64 wall_time);

    bool active() const {
        return _rec != NULL;
    }

    void recordEvent(int lock_index, int tid, u32 call_trace_id,
                     EventType event_type, Event* event);

    void recordLog(LogLevel level, const char* message, size_t len);

    static bool isJfrStarting();
};

#endif // _FLIGHTRECORDER_H
