/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _TSC_H
#define _TSC_H

#include "arguments.h"
#include "os.h"


const u64 NANOTIME_FREQ = 1000000000;


#if defined(__x86_64__) || defined(__i386__)

#include <cpuid.h>

#define TSC_SUPPORTED true

// JFR prefers TSC only if its frequency is higher than 1GHz
#define JFR_ALLOWED_FREQUENCY(freq) ((freq) > NANOTIME_FREQ)

static inline u64 rdtsc() {
#if defined(__x86_64__)
    u32 lo, hi;
    asm volatile("rdtsc" : "=a" (lo), "=d" (hi));
    return ((u64)hi << 32) | lo;
#else
    u64 result;
    asm volatile("rdtsc" : "=A" (result));
    return result;
#endif
}

// Returns true if this CPU has a good ("invariant") timestamp counter
static bool cpuHasGoodTimestampCounter() {
    unsigned int eax, ebx, ecx, edx;

    // Check if CPUID supports misc feature flags
    __cpuid(0x80000000, eax, ebx, ecx, edx);
    if (eax < 0x80000007) {
        return 0;
    }

    // Get misc feature flags
    __cpuid(0x80000007, eax, ebx, ecx, edx);

    // Bit 8 of EDX indicates invariant TSC
    return (edx & (1 << 8)) != 0;
}

#elif defined(__aarch64__)

#define TSC_SUPPORTED true
#define JFR_ALLOWED_FREQUENCY(freq) true

static inline u64 rdtsc() {
    u64 value;
    asm volatile("mrs %0, cntvct_el0" : "=r"(value));
    return value;
}

static bool cpuHasGoodTimestampCounter() {
    // AARCH64 always has a good timestamp counter.
    return true;
}

#else

#define TSC_SUPPORTED false
#define JFR_ALLOWED_FREQUENCY(freq) false
#define rdtsc() 0

static bool cpuHasGoodTimestampCounter() {
    return false;
}

#endif


class TSC {
  private:
    static bool _initialized;
    static bool _initialized_with_jvm;
    static bool _available;
    static bool _enabled;
    static u64 _offset;
    static u64 _frequency;
#ifdef _WIN32
    static bool _qpc_available;
    static bool _qpc_enabled;
    static u64 _qpc_base;
    static u64 _qpc_frequency;
    static u64 _jvm_base;
    static u64 _jvm_frequency;
    static bool _recording_clock;
    static u64 _recording_source_base;
    static u64 _recording_target_base;
    static u64 _recording_source_frequency;
    static u64 _recording_frequency;
    static u64 qpcTicks();
    static u64 recordingTicks(u64 value);
#endif

    static bool syncWithJvm();
    static bool calibrate();

  public:
    static void enable(Clock clock);
#ifdef _WIN32
    static bool useRecordingClock(u64 start_time, u64 start_ticks, u64 frequency);
#endif

    static bool hasMappedClock() {
#ifdef _WIN32
        return _recording_clock;
#else
        return false;
#endif
    }

    static bool enabled() {
        return TSC_SUPPORTED && _enabled;
    }

    static bool usesJvmClock() {
#ifdef _WIN32
        return enabled() || _qpc_enabled;
#else
        return enabled();
#endif
    }

    static u64 ticks() {
#ifdef _WIN32
        u64 value = _qpc_enabled ? qpcTicks() : enabled() ? rdtsc() - _offset : OS::nanotime();
        return _recording_clock ? recordingTicks(value) : value;
#else
        return enabled() ? rdtsc() - _offset : OS::nanotime();
#endif
    }

    // Ticks per second, synchronized with the JVM or calibrated against the OS clock.
    static u64 frequency() {
#ifdef _WIN32
        if (_recording_clock) return _recording_frequency;
        if (_qpc_enabled) return _jvm_frequency;
#endif
        return enabled() ? _frequency : NANOTIME_FREQ;
    }
};

#endif // _TSC_H
