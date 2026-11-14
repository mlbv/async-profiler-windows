/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsSoftwareEvents.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <limits>
namespace WindowsProfiler::Etw {
struct SoftwareThreadPeriodsTest {
    static void phase(SoftwareThreadPeriods& periods, ULONG tid, std::uint64_t value) {
        periods.threads.at(tid).phase = value;
    }
};
}
using namespace WindowsProfiler::Etw;
static void require(bool okay, const char* message) { if (!okay) { std::fprintf(stderr, "%s\n", message); std::exit(1); } }
template<class T> static void put(std::vector<unsigned char>& bytes, size_t offset, T value) { std::memcpy(bytes.data() + offset, &value, sizeof(value)); }
static unsigned widePeriodChecks = 0;
static void widePeriods() {
    for (auto period : {std::uint64_t{1} << 32, (std::uint64_t{1} << 32) + 1,
            static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()),
            std::numeric_limits<std::uint64_t>::max()}) {
        SoftwareThreadPeriods periods;
        periods.seed(43); periods.seed(44);
        bool selected = true;
        for (unsigned count = 0; count < 5; ++count) {
            require(!periods.count(43, period, selected) && !selected, "Wide period truncated or selected before boundary");
            require(!periods.count(44, period, selected) && !selected, "Wide period lost independent phase");
            widePeriodChecks += 2;
        }
        SoftwareThreadPeriodsTest::phase(periods, 43, period - 2);
        SoftwareThreadPeriodsTest::phase(periods, 44, period - 1);
        require(!periods.begin(43, true, false), "Wide period rundown rejected");
        require(!periods.count(43, period, selected) && !selected, "Wide period rundown reset or selected before boundary");
        require(!periods.count(44, period, selected) && selected, "Wide period lost second thread boundary");
        require(!periods.count(43, period, selected) && selected, "Wide period overflowed or missed exact boundary");
        require(!periods.count(43, period, selected) && !selected
            && !periods.count(44, period, selected) && !selected, "Wide period failed to wrap phase to zero");
        SoftwareThreadPeriodsTest::phase(periods, 43, period - 1);
        require(periods.begin(43, false, false) == ERROR_INVALID_DATA, "Wide period overlapping lifetime accepted");
        require(!periods.count(43, period, selected) && selected, "Rejected lifetime replacement reset phase");
        SoftwareThreadPeriodsTest::phase(periods, 43, period - 1);
        periods.end(43);
        require(periods.count(43, period, selected) == ERROR_NOT_FOUND && !selected, "Wide period accepted ended thread");
        require(!periods.begin(43, false, false), "Wide period reuse rejected");
        require(!periods.count(43, period, selected) && !selected, "Wide period reuse inherited selection");
        SoftwareThreadPeriodsTest::phase(periods, 43, period - 1);
        require(!periods.begin(43, false, true) && !periods.count(43, period, selected) && !selected,
            "Pre-capture replacement retained old wide phase");
        SoftwareThreadPeriodsTest::phase(periods, 44, period - 1);
        periods.reset();
        require(!periods.contains(43) && !periods.contains(44)
            && periods.count(44, period, selected) == ERROR_NOT_FOUND && !selected, "Wide period session reset retained lifetime");
        periods.seed(44);
        require(!periods.count(44, period, selected) && !selected, "Wide period restart inherited phase");
        widePeriodChecks += 13;
    }
    SoftwareThreadPeriods periods;
    periods.seed(43);
    bool selected = true;
    require(periods.count(43, 0, selected) == ERROR_INVALID_PARAMETER && !selected, "Zero period changed selection");
    for (unsigned index = 0; index < 256; ++index) {
        require(!periods.begin(43, false, true), "Pre-capture lifetime replacement rejected");
        require(!periods.count(43, 1, selected) && selected, "Unit physical event was not selected");
        periods.end(43);
        require(!periods.begin(43, false, false), "Churned lifetime start rejected");
        require(!periods.count(43, 3, selected) && !selected, "Churned lifetime inherited phase");
        periods.end(43);
        widePeriodChecks += 4;
    }
}
static unsigned stackChecks = 0;
static void check(bool okay, const char* message) { require(okay, message); ++stackChecks; }
static void provenSwitches() {
    EVENT_RECORD event{};
    ProvenSwitch value{777, 88, 0};
    event.EventHeader.ProviderId = provenSwitchProvider;
    event.EventHeader.TimeStamp.QuadPart = 500; event.EventHeader.ProcessId = 42;
    event.BufferContext.ProcessorIndex = 9;
    event.UserData = &value; event.UserDataLength = sizeof(value);
    auto parsed = decodeSoftware(SoftwareKind::ContextSwitches, event);
    require(parsed.kind == SoftwareRecordKind::Sample && parsed.time == 500 && parsed.stackTime == 777
        && parsed.tid == 88 && parsed.pid == 42 && parsed.cpu == 9 && !parsed.ip, "Proven switch identity/clock/CPU/stack key");
    require(decodeSoftware(SoftwareKind::PageFaults, event).kind == SoftwareRecordKind::Ignore, "Proven switch accepted for faults");
    for (auto change : {0, 1, 2, 3, 4}) {
        auto copy = event; auto bad = value;
        copy.UserData = &bad;
        if (change == 0) copy.UserDataLength = sizeof(bad) - 1;
        if (change == 1) bad.tid = 0;
        if (change == 2) bad.tid = ULONG(-1);
        if (change == 3) bad.reserved = 1;
        if (change == 4) copy.EventHeader.EventDescriptor.Version = 1;
        require(decodeSoftware(SoftwareKind::ContextSwitches, copy).kind == SoftwareRecordKind::Malformed, "Malformed proven switch accepted");
    }
}
static void softwareStacks() {
    constexpr std::uint64_t k1 = 0xfffff80000001000ULL, k2 = 0xfffff80000002000ULL, u1 = 0x7ff600001000ULL, u2 = 0x7ff600002000ULL;
    auto sample = [](ULONG tid, std::uint64_t time, std::uint64_t key, bool kernel = true, std::uint64_t ip = 0) {
        SoftwareStacks::Sample value; value.tid = tid; value.time = time; value.stackTime = key;
        value.kernelRequired = kernel; value.ip = ip; return value;
    };
    std::vector<std::uint64_t> kernel{k1, k2}, user{u1, u2};
    SoftwareStacks::Ready ready;
    SoftwareStacks stacks(4, 3);
    check(!stacks.open(sample(1, 10, 100)) && stacks.size() == 1, "Open selected sample");
    stacks.part(1, 99, kernel, ready); stacks.part(2, 100, kernel, ready);
    check(ready.empty(), "Foreign key or thread completed sample");
    stacks.part(1, 100, kernel, ready);
    check(ready.empty(), "Kernel part alone completed switch sample");
    stacks.part(1, 100, user, ready);
    check(ready.size() == 1 && ready[0].complete() && !ready[0].shared && ready[0].time == 10 && ready[0].ip == k1
        && ready[0].kernel == kernel && ready[0].user == user && !stacks.size(), "Exact kernel/user assembly");
    ready.clear();
    // One kernel-mode interval: the user part names its first key and covers later keys.
    for (auto key : {200, 210, 220}) check(!stacks.open(sample(1, key - 100, key)), "Open interval sample");
    check(stacks.open(sample(1, 1, 300)) == ERROR_BUFFER_OVERFLOW, "Open sample beyond limit");
    for (auto key : {200, 210, 220}) stacks.part(1, key, kernel, ready);
    stacks.part(1, 200, user, ready);
    check(ready.size() == 3 && ready[0].complete() && ready[1].shared && ready[2].shared
        && ready[1].user == user && ready[2].user == user, "User part shared with later keys of its interval");
    ready.clear();
    // A user part naming a later key cannot prove earlier keys still waiting.
    for (auto key : {400, 410, 420}) check(!stacks.open(sample(1, key, key)), "Open later-key sample");
    for (auto key : {400, 410, 420}) stacks.part(1, key, kernel, ready);
    stacks.part(1, 420, user, ready);
    check(ready.size() == 3 && !ready[0].complete() && !ready[1].complete() && ready[0].user.empty()
        && ready[2].complete() && !ready[2].shared, "Earlier waiting keys released without a user part");
    ready.clear();
    check(!stacks.open(sample(1, 500, 500)) && stacks.open(sample(1, 501, 500)) == ERROR_DUP_NAME, "Duplicate stack key rejected");
    check(!stacks.open(sample(1, 510, 510, false, u1)), "Open user-mode sample without kernel part");
    check(!stacks.open(sample(1, 520, 520, true, k1)), "Open kernel-mode sample without kernel part");
    stacks.part(1, 500, kernel, ready);
    stacks.part(1, 490, user, ready);
    check(ready.size() == 2 && ready[0].stackTime == 500 && ready[0].shared && ready[0].complete()
        && ready[1].stackTime == 520 && ready[1].shared && !ready[1].complete() && ready[1].user == user,
        "Kernel-mode samples share an earlier user part and are final without their kernel part");
    check(stacks.size() == 1, "User-mode sample without its kernel part cannot share an earlier user part");
    ready.clear();
    stacks.end(1, ready);
    check(ready.size() == 1 && ready[0].stackTime == 510 && !ready[0].userSeen, "Ended thread releases waiting samples");
    ready.clear();
    // Callback stacks keep nested kernel frames below the first user frame.
    std::vector<std::uint64_t> combined{k1, u1, k2, u2};
    check(!stacks.open(sample(3, 600, 600)), "Open combined sample");
    stacks.part(3, 600, combined, ready);
    check(ready.size() == 1 && ready[0].kernel == std::vector<std::uint64_t>{k1}
        && ready[0].user == std::vector<std::uint64_t>{u1, k2, u2}, "Combined part split at first user frame");
    ready.clear();
    // A user-mode fault needs no kernel part.
    check(!stacks.open(sample(4, 700, 700, false, u1)), "Open user-mode fault");
    stacks.part(4, 700, user, ready);
    check(ready.size() == 1 && ready[0].complete() && ready[0].ip == u1, "User-mode fault completed by user part");
    ready.clear();
    std::vector<std::uint64_t> deep{u1, u2, u1, u2, u1};
    check(!stacks.open(sample(5, 800, 800, false)), "Open deep sample");
    stacks.part(5, 800, deep, ready);
    check(ready.size() == 1 && ready[0].user.size() == 4 && ready[0].overflow, "Frame limit marks overflow");
    ready.clear();
    check(!stacks.open(sample(6, 900, 900)) && !stacks.open(sample(7, 900, 900)), "Open samples for finish");
    stacks.finish(ready);
    check(ready.size() == 2 && !stacks.size(), "Finish releases every waiting sample");
    stacks.reset();
    check(!stacks.size(), "Reset");
}
int main() {
    constexpr GUID fault = {0x3d6fa8d3,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
    constexpr GUID thread = {0x3d6fa8d1,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
    EVENT_RECORD event{};
    event.EventHeader.TimeStamp.QuadPart = 123456;
    event.EventHeader.ProcessId = 42; event.EventHeader.ThreadId = 43;
    event.EventHeader.EventDescriptor.Version = 2;
    event.BufferContext.ProcessorIndex = 300;
    for (bool x64 : {false, true}) {
        auto width = x64 ? 8 : 4;
        event.EventHeader.Flags = x64 ? EVENT_HEADER_FLAG_64_BIT_HEADER : EVENT_HEADER_FLAG_32_BIT_HEADER;
        std::vector<unsigned char> bytes(2 * width);
        if (x64) { put<std::uint64_t>(bytes, 0, 0xffff888812345000ULL); put<std::uint64_t>(bytes, 8, 0x123456789abULL); }
        else { put<ULONG>(bytes, 0, 0x12345000); put<ULONG>(bytes, 4, 0x23456789); }
        event.UserData = bytes.data(); event.UserDataLength = bytes.size(); event.EventHeader.ProviderId = fault;
        for (UCHAR opcode = 10; opcode <= 15; ++opcode) {
            event.EventHeader.EventDescriptor.Opcode = opcode;
            auto parsed = decodeSoftware(SoftwareKind::PageFaults, event);
            require(parsed.kind == SoftwareRecordKind::Sample && parsed.pid == 42 && parsed.tid == 43
                && parsed.time == 123456 && parsed.cpu == 300 && parsed.category == opcode, "Fault identity/category/clock/CPU");
            require(parsed.ip == (x64 ? 0x123456789abULL : 0x23456789), "Fault PC confused with virtual address");
        }
        event.EventHeader.EventDescriptor.Opcode = 32;
        require(decodeSoftware(SoftwareKind::PageFaults, event).kind == SoftwareRecordKind::Ignore, "Hard-fault completion double counted");
        event.EventHeader.EventDescriptor.Opcode = 11;
        for (size_t length = 0; length < bytes.size(); ++length) {
            event.UserDataLength = length;
            require(decodeSoftware(SoftwareKind::PageFaults, event).kind == SoftwareRecordKind::Malformed, "Truncated fault accepted");
        }
        event.UserDataLength = bytes.size(); event.EventHeader.EventDescriptor.Version = 3;
        require(decodeSoftware(SoftwareKind::PageFaults, event).kind == SoftwareRecordKind::Unsupported, "Unknown fault schema guessed");
        event.EventHeader.EventDescriptor.Version = 2;
        event.EventHeader.ProcessId = ULONG(-1);
        require(decodeSoftware(SoftwareKind::PageFaults, event).kind == SoftwareRecordKind::Malformed, "Fault without process accepted");
        event.EventHeader.ProcessId = 42;
        require(decodeSoftware(SoftwareKind::PageFaults, event).stackTime == 123456, "Fault stack key differs from fault time");
    }
    event.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
    std::vector<unsigned char> bytes(24);
    put<ULONG>(bytes, 0, 500); put<ULONG>(bytes, 4, 43);
    event.UserData = bytes.data(); event.UserDataLength = bytes.size();
    event.EventHeader.ProviderId = thread; event.EventHeader.EventDescriptor.Opcode = 36;
    auto switched = decodeSoftware(SoftwareKind::ContextSwitches, event);
    require(switched.kind == SoftwareRecordKind::Switch && switched.tid == 43 && switched.incomingTid == 500
        && !switched.terminated && switched.pid == 0, "Switch identities confused with header thread");
    require(switched.ip == 0 && switched.cpu == 300 && switched.time == 123456, "Switch invented fault PC/clock/CPU");
    bytes[14] = 4;
    require(decodeSoftware(SoftwareKind::ContextSwitches, event).terminated, "Terminated switch-out not recognized");
    bytes[14] = 5;
    require(!decodeSoftware(SoftwareKind::ContextSwitches, event).terminated, "Waiting switch-out treated as terminated");
    bytes[14] = 0;
    for (size_t length = 0; length < 24; ++length) {
        event.UserDataLength = length;
        require(decodeSoftware(SoftwareKind::ContextSwitches, event).kind == SoftwareRecordKind::Malformed, "Truncated switch accepted");
    }
    event.UserDataLength = bytes.size();
    for (UCHAR version : {2, 3, 4, 5}) {
        event.EventHeader.EventDescriptor.Version = version;
        for (unsigned length : {24, 32, 40}) {
            bytes.resize(length, 0xab); event.UserData = bytes.data(); event.UserDataLength = bytes.size();
            auto parsed = decodeSoftware(SoftwareKind::ContextSwitches, event);
            require(parsed.kind == (version == 2 && length != 24 ? SoftwareRecordKind::Malformed : SoftwareRecordKind::Switch),
                "Context-switch versioned prefix validation");
            if (parsed.kind == SoftwareRecordKind::Switch)
                require(parsed.tid == 43 && parsed.incomingTid == 500 && parsed.time == 123456 && parsed.cpu == 300,
                    "Context-switch version changed identities");
        }
        event.UserDataLength = 23;
        require(decodeSoftware(SoftwareKind::ContextSwitches, event).kind == SoftwareRecordKind::Malformed,
            "Truncated versioned switch accepted");
    }
    bytes.resize(24); event.UserData = bytes.data(); event.UserDataLength = bytes.size();
    event.EventHeader.EventDescriptor.Version = 6;
    require(decodeSoftware(SoftwareKind::ContextSwitches, event).kind == SoftwareRecordKind::Unsupported,
        "Unproven switch version accepted");
    event.EventHeader.EventDescriptor.Version = 2;
    put<ULONG>(bytes, 4, 0);
    switched = decodeSoftware(SoftwareKind::ContextSwitches, event);
    require(switched.kind == SoftwareRecordKind::Switch && !switched.tid && switched.incomingTid == 500, "Switch-in from idle lost");
    put<ULONG>(bytes, 0, 0);
    require(decodeSoftware(SoftwareKind::ContextSwitches, event).kind == SoftwareRecordKind::Ignore, "Idle-only switch retained");
    put<ULONG>(bytes, 4, ULONG(-1));
    require(decodeSoftware(SoftwareKind::ContextSwitches, event).kind == SoftwareRecordKind::Malformed, "Invalid outgoing thread accepted");
    put<ULONG>(bytes, 4, 43); put<ULONG>(bytes, 0, ULONG(-1));
    require(decodeSoftware(SoftwareKind::ContextSwitches, event).kind == SoftwareRecordKind::Malformed, "Invalid incoming thread accepted");
    require(decodeSoftware(SoftwareKind::PageFaults, event).kind == SoftwareRecordKind::Ignore, "Switch decoded in fault mode");
    provenSwitches();
    event.EventHeader.EventDescriptor.Opcode = 1;
    put<ULONG>(bytes, 0, 42); put<ULONG>(bytes, 4, 43);
    auto started = decodeSoftware(SoftwareKind::PageFaults, event);
    require(started.kind == SoftwareRecordKind::ThreadStart && started.pid == 42 && started.tid == 43, "Thread v2 identity");
    event.EventHeader.EventDescriptor.Version = 0; put<ULONG>(bytes, 0, 43); put<ULONG>(bytes, 4, 42);
    started = decodeSoftware(SoftwareKind::ContextSwitches, event);
    require(started.kind == SoftwareRecordKind::ThreadStart && started.pid == 42 && started.tid == 43, "Thread v0 identity reversed");
    require(softwareDefaultPeriod(SoftwareKind::PageFaults) == 1 && softwareDefaultPeriod(SoftwareKind::ContextSwitches) == 2, "Upstream default periods");
    require(softwareStackEvents(SoftwareKind::PageFaults).size() == 6 && softwareStackEvents(SoftwareKind::ContextSwitches)[0].Type == 36, "Event stack enable list");
    SoftwareThreadPeriods periods; periods.seed(43); periods.seed(44);
    bool selected = true;
    for (unsigned i = 0; i < 3; ++i) { require(!periods.count(43, 5, selected) && !selected, "Premature per-thread period"); }
    unsigned samples = 0;
    for (unsigned i = 0; i < 7; ++i) { require(!periods.count(44, 5, selected), "Second thread period failed"); samples += selected; }
    require(samples == 1, "Global period substituted for per-thread period");
    require(!periods.begin(44, true, false), "Rundown rejected");
    require(!periods.count(44, 5, selected) && !selected, "Rundown reset live phase");
    require(periods.begin(44, false, false) == ERROR_INVALID_DATA, "Overlapping thread lifetime accepted");
    periods.end(44); require(!periods.begin(44, false, false), "Reused TID not enrolled");
    for (unsigned i = 0; i < 4; ++i) require(!periods.count(44, 5, selected) && !selected, "Reused TID inherited phase");
    require(!periods.count(44, 5, selected) && selected, "Reused TID lost fresh phase");
    periods.end(44); require(periods.count(44, 5, selected) == ERROR_NOT_FOUND, "Exited TID accepted");
    widePeriods();
    softwareStacks();
    std::printf("SOFTWARE_EVENTS_OK fault_categories=6 widths=2 switch_identities=1 proven_switch=1 thread_versions=2 per_tid_period=1 reuse=1 wide_period_checks=%u stack_checks=%u\n",
        widePeriodChecks, stackChecks);
}
