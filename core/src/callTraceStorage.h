/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _CALLTRACESTORAGE_H
#define _CALLTRACESTORAGE_H

#include <map>
#include <vector>
#include "arch.h"
#include "linearAllocator.h"
#include "vmEntry.h"


class LongHashTable;

struct CallTrace {
    int num_frames;
    ASGCT_CallFrame frames[1];
};

struct CallTraceSample {
    CallTrace* trace;
    u64 samples;
    u64 counter;
    u64 jfr_samples;
    u64 jfr_samples_written;

    CallTrace* acquireTrace() {
        return loadAcquire(trace);
    }

    void setTrace(CallTrace* value) {
        storeRelease(trace, value);
    }

    void add(u64 sample_count, u64 counter_value) {
        atomicInc(samples, sample_count);
        atomicInc(counter, counter_value);
        atomicInc(jfr_samples, sample_count);
    }

    CallTraceSample& operator+=(const CallTraceSample& s) {
        trace = s.trace;
        samples += s.samples;
        counter += s.counter;
        return *this;
    }
};

class CallTraceStorage {
  private:
    static CallTrace _overflow_trace;

    LinearAllocator _allocator;
    LongHashTable* _current_table;
    size_t _used_memory;
    size_t _mem_limit;
    u64 _overflow;
    CallTraceSample _overflow_sample;

    u64 calcHash(int num_frames, ASGCT_CallFrame* frames);
    CallTrace* storeCallTrace(int num_frames, ASGCT_CallFrame* frames);
    CallTrace* findCallTrace(LongHashTable* table, u64 hash);
    u32 overflowTrace(u64 counter);

  public:
    CallTraceStorage();
    ~CallTraceStorage();

    void clear(size_t mem_limit);
    u32 capacity();
    size_t usedMemory();
    u64 overflow() { return _overflow; }

    void collectTraces(std::map<u32, CallTrace*>& map);
    void collectSamples(std::vector<CallTraceSample*>& samples);
    void collectSamples(std::map<u64, CallTraceSample>& map);

    u32 put(int num_frames, ASGCT_CallFrame* frames, u64 counter);
    void add(u32 call_trace_id, u64 samples, u64 counter);
    void resetCounters();
};

#endif // _CALLTRACESTORAGE
