/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _ENGINE_H
#define _ENGINE_H

#include "arguments.h"
#include <atomic>


class Engine {
  protected:
    static std::atomic<bool> _enabled;
    static std::atomic<uint64_t> _event_generation;

    static uint64_t sampleGeneration() { return _event_generation.load(std::memory_order_acquire); }
    static bool canSample(uint64_t generation) {
        return _enabled.load(std::memory_order_acquire)
                && _event_generation.load(std::memory_order_acquire) == generation;
    }

    static bool updateCounter(volatile unsigned long long& counter, unsigned long long value, unsigned long long interval) {
        if (interval <= 1) {
            return true;
        }

        while (true) {
            unsigned long long prev = counter;
            unsigned long long next = prev + value;
            if (next < interval) {
                if (__sync_bool_compare_and_swap(&counter, prev, next)) {
                    return false;
                }
            } else {
                if (__sync_bool_compare_and_swap(&counter, prev, next % interval)) {
                    return true;
                }
            }
        }
    }

  public:
    virtual const char* type() {
        return "noop";
    }

    virtual const char* title() {
        return "Flame Graph";
    }

    virtual const char* units() {
        return "total";
    }

    virtual int64_t interval() {
        return 1;
    }

    virtual Error prepare(Arguments& args) { return Error::OK; }
    virtual Error start(Arguments& args);
    virtual void stop();

    virtual void enableEvents(bool enabled) {
        _event_generation.fetch_add(1, std::memory_order_acq_rel);
        _enabled.store(enabled, std::memory_order_release);
    }
};

#endif // _ENGINE_H
