/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <array>
#include <cstdint>
#include <map>
#include <span>
#include <vector>

namespace WindowsProfiler::Etw {
enum class SoftwareKind : ULONG { None = 0, PageFaults = 1, ContextSwitches = 2 };
SoftwareKind softwareEvent(const char* name);
const char* softwareEventName(SoftwareKind kind);
std::uint64_t softwareDefaultPeriod(SoftwareKind kind);
ULONG softwareEnableFlags(SoftwareKind kind);
std::span<const CLASSIC_EVENT_ID> softwareStackEvents(SoftwareKind kind);

// Router output for an outgoing switch whose owner was proven by the thread's next
// switch-in StackWalk. Header time, PID and CPU describe the switch-out; that
// stack, keyed by stackTime, is the thread's stack at the switch-out.
constexpr GUID provenSwitchProvider = {0xca6f115c, 0xb96d, 0x46f3, {0xb4, 0xb0, 0x92, 0x82, 0x5c, 0x5f, 0x88, 0x8a}};
struct ProvenSwitch { std::uint64_t stackTime; ULONG tid, reserved; };
static_assert(sizeof(ProvenSwitch) == 16);

enum class SoftwareRecordKind { Ignore, Sample, Switch, ThreadStart, ThreadEnd, ThreadRundown, Malformed, Unsupported };
struct SoftwareRecord {
    SoftwareRecordKind kind = SoftwareRecordKind::Ignore;
    std::uint64_t time = 0, ip = 0, stackTime = 0;
    ULONG pid = 0, tid = 0, incomingTid = 0;
    USHORT cpu = 0;
    UCHAR category = 0;
    bool terminated = false;
};
// PageFault_TypeGroup1 uses the faulting header PID/TID and an exact fault PC.
// A raw CSwitch is a Switch: OldThreadId switches out, NewThreadId switches in;
// its header does not identify either thread's process. A ProvenSwitch is a Sample.
SoftwareRecord decodeSoftware(SoftwareKind selected, const EVENT_RECORD& event);

// Consumer-thread state only. Counter phases belong to thread lifetimes and
// advance before output-window/thread-filter decisions, like per-TID perf FDs.
class SoftwareThreadPeriods {
    friend struct SoftwareThreadPeriodsTest;
    struct Thread { std::uint64_t phase = 0; };
    std::map<ULONG, Thread> threads;
public:
    void reset() { threads.clear(); }
    void seed(ULONG tid) { threads.try_emplace(tid); }
    ULONG begin(ULONG tid, bool rundown, bool beforeCapture);
    void end(ULONG tid) { threads.erase(tid); }
    bool contains(ULONG tid) const { return threads.contains(tid); }
    ULONG count(ULONG tid, std::uint64_t period, bool& selected);
};

// Assembles StackWalk parts of selected software samples; consumer-thread state.
// ETW logs a kernel part at each stack key and defers the thread's user part until
// it returns to user mode, then logs it once under one key of that kernel-mode
// interval. Keys after that key share the unchanged user context when their
// kernel part or kernel-mode PC places the thread in kernel mode; ETW logs no
// stack for faults nested in another fault's handling. Earlier keys still
// waiting belong to an interval whose user part was not logged.
class SoftwareStacks {
public:
    struct Sample {
        std::uint64_t time = 0, stackTime = 0, ip = 0;
        ULONG tid = 0;
        USHORT cpu = 0;
        bool kernelRequired = false;
        std::vector<std::uint64_t> kernel, user;
        bool kernelSeen = false, userSeen = false, shared = false, overflow = false;
        bool complete() const { return userSeen && (kernelSeen || !kernelRequired); }
    };
    // Samples to publish: complete, or final without a provable user part.
    using Ready = std::vector<Sample>;
    SoftwareStacks(size_t frameLimit, size_t limit) : _frameLimit(frameLimit), _limit(limit) {}
    void reset() { _threads.clear(); _count = 0; }
    size_t size() const { return _count; }
    ULONG open(Sample sample);
    void part(ULONG tid, std::uint64_t stackTime, std::span<const std::uint64_t> frames, Ready& ready);
    // A thread that logged its end never returns to user mode.
    void end(ULONG tid, Ready& ready);
    void finish(Ready& ready);
private:
    std::map<ULONG, std::vector<Sample>> _threads;
    size_t _count = 0, _frameLimit, _limit;
    void release(std::vector<Sample>& samples, Ready& ready);
};
}
