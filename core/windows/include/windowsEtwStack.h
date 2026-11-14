/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsEtw.h"
#include "vmEntry.h"
#include "spinLock.h"
#include <atomic>
#include <span>

class CodeCache;
namespace WindowsProfiler::Etw {
class EventWindows {
    struct Boundary { std::uint64_t time; bool enabled; };
    mutable SpinLock lock;
    std::vector<Boundary> boundaries;
    size_t count = 0;
    std::uint64_t overflowTime = 0;
    std::atomic<std::uint64_t> outside{0};
public:
    Error prepare(bool needed);
    void reset();
    bool configured() const { return !boundaries.empty(); }
    bool accepts(std::uint64_t time);
    bool enable(Engine& owner, bool enabled);
    ULONG failure() const;
    void writeMetrics(Writer& out, const char* prefix) const;
};

struct StackSample {
    std::uint64_t time = 0, ip = 0, counter = 0;
    ULONG tid = 0, source = 0;
    USHORT cpu = 0;
    std::span<const std::uint64_t> kernel, user;
    bool stacksRequested = true, complete = true, overflow = false;
    size_t rawLimit = MAX_STACK_FRAMES;
};

class StackPublisher {
    struct Lifetime {
        std::uint64_t epoch, since, confirmedThrough;
        bool closed = false;
    };
    struct Library {
        CodeCache* cache;
        std::uintptr_t begin, end;
        std::uint64_t observedEpoch = 0;
        std::vector<Lifetime> lifetimes;
    };
    std::vector<Library> libraries;
    std::vector<ASGCT_CallFrame> callFrames;
    int maxDepth = 0, truncatedDepth = 0;
    StackWalkFeatures features{};
    bool allUser = false, nativeFrames = true, recordCpu = false;
    std::uint64_t clockQpc = 0, clockTicks = 0, qpcFrequency = 0;
    std::atomic<std::uint64_t> ambiguousNativePcs{0};
    std::atomic<std::uint64_t> samples{0}, missingStacks{0}, missingUserStacks{0}, missingKernelStacks{0};
    std::atomic<std::uint64_t> partialJava{0}, partialVm{0}, partialNative{0}, depthLimited{0}, truncatedStacks{0};
    std::atomic<std::uint64_t> unprovenCfiStacks{0};
    std::uint64_t ticks(std::uint64_t time) const;
    void observeLibrary(Library& library);
    const char* nativeName(std::uint64_t address, std::uint64_t time);
public:
    Error prepare(const Arguments& args);
    void reset();
    void rememberLibraries(std::uint64_t since);
    void calibrateClock();
    // Whether publish would record a sample of this thread.
    bool accepts(ULONG tid) const;
    bool publish(const StackSample& sample);
    void writeMetrics(Writer& out, const char* prefix) const;
};
}
