/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _PROCESSSAMPLER_H
#define _PROCESSSAMPLER_H

#include <unordered_map>
#include "os.h"

const u64 MAX_TIME_NS = 900000000UL; // Timeout after 900ms to guarantee runtime <1sec
const int MAX_PROCESSES = 5000;      // Hard limit to prevent excessive work
const int MAX_PROCESS_SAMPLE_JFR_EVENT_LENGTH = 2500;

struct ProcessHistory {
    double prev_cpu_total = 0.0;
    u64 prev_timestamp = 0;
    u64 start_time = 0;
};

class ProcessSampler {
  private:
    static u64 _next_sample_time;
    static std::unordered_map<int, ProcessHistory> _process_history;

    int64_t _sampling_interval = -1;
    int _pids[MAX_PROCESSES];

    static double getRssUsageRatio(const ProcessInfo& info);
    static bool shouldIncludeProcess(const ProcessInfo& info);
    static bool populateCpuPercent(ProcessInfo& info, u64 sampling_time);

    void cleanupProcessHistory(int pid_count);

  public:
    void enable(int64_t sampling_interval, u64 start_time);
    bool shouldSample(u64 wall_time) const;
    int sample(u64 wall_time);
    bool getProcessInfo(int pid_index, u64 sampling_time, ProcessInfo& info);
};

#endif // _PROCESSSAMPLER_H
