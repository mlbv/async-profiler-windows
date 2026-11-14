/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include <jvmti.h>
#include "tsc.h"
#include "vmEntry.h"
#include "vmStructs.h"
#ifdef _WIN32
#include <windows.h>
#endif


bool TSC::_initialized = false;
bool TSC::_initialized_with_jvm = false;
bool TSC::_available = false;
bool TSC::_enabled = false;
u64 TSC::_offset = 0;
u64 TSC::_frequency = NANOTIME_FREQ;
#ifdef _WIN32
bool TSC::_qpc_available = false;
bool TSC::_qpc_enabled = false;
u64 TSC::_qpc_base = 0;
u64 TSC::_qpc_frequency = 0;
u64 TSC::_jvm_base = 0;
u64 TSC::_jvm_frequency = 0;
bool TSC::_recording_clock = false;
u64 TSC::_recording_source_base = 0;
u64 TSC::_recording_target_base = 0;
u64 TSC::_recording_source_frequency = 0;
u64 TSC::_recording_frequency = 0;

static u64 convertClockTicks(u64 value, u64 source_base, u64 target_base, u64 source_frequency, u64 target_frequency) {
    u64 elapsed = value - source_base;
    if (source_frequency == target_frequency) return target_base + elapsed;
    return target_base + static_cast<u64>(static_cast<unsigned __int128>(elapsed) * target_frequency / source_frequency);
}

u64 TSC::qpcTicks() {
    LARGE_INTEGER value;
    QueryPerformanceCounter(&value);
    return convertClockTicks(value.QuadPart, _qpc_base, _jvm_base, _qpc_frequency, _jvm_frequency);
}

u64 TSC::recordingTicks(u64 value) {
    return convertClockTicks(value, _recording_source_base, _recording_target_base,
                             _recording_source_frequency, _recording_frequency);
}

bool TSC::useRecordingClock(u64 start_time, u64 start_ticks, u64 frequency) {
    if (!frequency || frequency > MAX_JLONG || start_time > MAX_JLONG || start_ticks > MAX_JLONG) return false;
    _recording_clock = false;
    u64 source_frequency = TSC::frequency();
    u64 before = ticks();
    u64 wall_time = OS::micros() * 1000;
    u64 after = ticks();
    __int128 target = static_cast<__int128>(start_ticks)
        + (static_cast<__int128>(wall_time) - start_time) * frequency / NANOTIME_FREQ;
    if (target < 0 || target > MAX_JLONG) return false;
    // Resume preserves the first chunk's tick representation while the selected
    // source supplies elapsed time. Re-anchor each segment to its wall-clock time.
    _recording_source_base = before + (after - before) / 2;
    _recording_target_base = static_cast<u64>(target);
    _recording_source_frequency = source_frequency;
    _recording_frequency = frequency;
    _recording_clock = true;
    return true;
}
#endif

void TSC::enable(Clock clock) {
#ifdef _WIN32
    _recording_clock = false;
#endif
    if (!TSC_SUPPORTED || clock == CLK_MONOTONIC) {
        _enabled = false;
#ifdef _WIN32
        if (!VM::loaded()) { _qpc_enabled = false; return; }
#else
        return;
#endif
    }

    if (!_initialized || _initialized_with_jvm != VM::loaded()) {
        if (VM::loaded()) {
            _available = syncWithJvm();
        } else {
            _available = calibrate();
        }
        _initialized_with_jvm = VM::loaded();
        _initialized = !VM::loaded() || VM::jni() != nullptr;
    }

    _enabled = _available && clock != CLK_MONOTONIC;
#ifdef _WIN32
    _qpc_enabled = !_enabled && _qpc_available && VM::loaded();
#endif
}

bool TSC::calibrate() {
    if (!cpuHasGoodTimestampCounter()) return false;
    u64 start = OS::nanotime();
    u64 ticks = rdtsc();
    OS::sleep(20000000);
    u64 elapsed = OS::nanotime() - start;
    u64 cycles = rdtsc() - ticks;
    if (elapsed == 0 || cycles == 0) return false;
    _frequency = static_cast<u64>(static_cast<long double>(cycles) * NANOTIME_FREQ / elapsed);
    _offset = 0;
    return true;
}

// Try to use the same clock source with the same offset/frequency as the JVM does
bool TSC::syncWithJvm() {
    JVMFlag* f = JVMFlag::find("UseFastUnorderedTimeStamps");
#ifndef _WIN32
    if (f == nullptr || !f->get()) {
        return false;
    }
#else
    _qpc_available = false;
#endif

    JNIEnv* env = VM::jni();
    if (env == nullptr) return false;

    jfieldID jvm;
    jmethodID counterTime, getTicksFrequency;
    jclass cls = env->FindClass("jdk/jfr/internal/JVM");
    if (cls == nullptr || (counterTime = env->GetStaticMethodID(cls, "counterTime", "()J")) == nullptr) {
        env->ExceptionClear();
        return false;
    }

    u64 frequency = 0;
    // Method is static since JDK 22
    if ((getTicksFrequency = env->GetStaticMethodID(cls, "getTicksFrequency", "()J")) != nullptr) {
        frequency = env->CallStaticLongMethod(cls, getTicksFrequency);
    } else {
        env->ExceptionClear();
        if ((getTicksFrequency = env->GetMethodID(cls, "getTicksFrequency", "()J")) != nullptr &&
                (jvm = env->GetStaticFieldID(cls, "jvm", "Ljdk/jfr/internal/JVM;")) != nullptr) {
            frequency = env->CallLongMethod(env->GetStaticObjectField(cls, jvm), getTicksFrequency);
        }
    }
    env->ExceptionClear();

    if (frequency == 0) {
        return false;
    }

#ifdef _WIN32
    LARGE_INTEGER qpc_frequency;
    QueryPerformanceFrequency(&qpc_frequency);
    u64 best_delta = ~u64(0), tsc_offset = 0;
    for (int attempt = 0; attempt < 2; ++attempt) {
        LARGE_INTEGER before, after;
        QueryPerformanceCounter(&before);
        u64 jvm_ticks = env->CallStaticLongMethod(cls, counterTime);
        QueryPerformanceCounter(&after);
        u64 native_ticks = rdtsc();
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            return false;
        }
        u64 elapsed = after.QuadPart - before.QuadPart;
        if (elapsed < best_delta) {
            best_delta = elapsed;
            _qpc_base = before.QuadPart + elapsed / 2;
            _jvm_base = jvm_ticks;
            tsc_offset = native_ticks - jvm_ticks;
        }
    }
    // Match the JVM tick origin and rate, including when QPC supplies the
    // monotonic source. A reader can use the first chunk's clock for all chunks.
    _qpc_frequency = qpc_frequency.QuadPart;
    _jvm_frequency = frequency;
    _qpc_available = true;
#else
    u64 jvm_ticks = env->CallStaticLongMethod(cls, counterTime);
#endif
    if (f == nullptr || !f->get() || !JFR_ALLOWED_FREQUENCY(frequency)) {
        return false;
    }
#ifdef _WIN32
    _offset = tsc_offset;
#else
    _offset = rdtsc() - jvm_ticks;
#endif
    _frequency = frequency;

    env->ExceptionClear();
    return true;
}
