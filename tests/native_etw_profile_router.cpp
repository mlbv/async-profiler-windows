/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwProfileRouter.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>

using namespace WindowsProfiler::Etw::Broker;
namespace {
constexpr GUID perfInfo = {0xce1dbfb4,0x137e,0x4da6,{0x87,0xb0,0x3f,0x59,0xaa,0x10,0x2c,0xbc}};
constexpr GUID stackWalk = {0xdef2fe46,0x7bd6,0x4b80,{0xbd,0x94,0xf5,0x7f,0xe2,0x0d,0x0c,0xe3}};
constexpr GUID threads = {0x3d6fa8d1,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
constexpr GUID pageFault = {0x3d6fa8d3,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
constexpr GUID image = {0x2cb15d1d,0x5fc1,0x11d2,{0xab,0xe1,0x00,0xa0,0xc9,0x11,0xf5,0x18}};
void require(bool condition, const char* text) { if (!condition) throw std::runtime_error(text); }
bool empty(const ProfileRouter::Output& output) { return output.first.empty() && output.second.empty(); }
struct Profile { std::uint64_t pc; ULONG tid; USHORT count, flags; } profile{0x123456, 88, 1, 0};
struct Stack { std::uint64_t time; ULONG pid, tid; std::uint64_t pc; } stack{100, 123, 88, 0x123456};
EVENT_RECORD event(const GUID& guid, UCHAR opcode, ULONG pid, std::uint64_t time, void* data, USHORT size) {
    EVENT_RECORD result{}; result.EventHeader.ProviderId = guid; result.EventHeader.EventDescriptor.Opcode = opcode;
    result.EventHeader.EventDescriptor.Version = 2; result.EventHeader.ProcessId = pid; result.EventHeader.ThreadId = 999;
    result.EventHeader.ActivityId.Data1 = 0xdead; result.EventHeader.TimeStamp.QuadPart = time;
    result.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER; result.UserData = data; result.UserDataLength = size;
    return result;
}
void softwareTests() {
    using WindowsProfiler::Etw::SoftwareKind;
    Request request; request.interval = 2; request.software = static_cast<ULONG>(SoftwareKind::ContextSwitches);
    require(validateRequest(request) == 0, "context-switch request valid");
    request.software = static_cast<ULONG>(SoftwareKind::PageFaults);
    require(validateRequest(request) == 0, "page-fault request valid");
    for (ULONG kind : {3ul, ULONG(-1)}) {
        auto invalid = request; invalid.software = kind;
        require(validateRequest(invalid) == ERROR_INVALID_PARAMETER, "unknown software request rejected");
    }
    auto invalid = request; invalid.source = 1;
    require(validateRequest(invalid) == ERROR_INVALID_PARAMETER, "software source rejected");
    invalid = request; invalid.raw = 1;
    require(validateRequest(invalid) == ERROR_INVALID_PARAMETER, "software raw PMU rejected");
    invalid = request; invalid.rawConfig.config = 1;
    require(validateRequest(invalid) == ERROR_INVALID_PARAMETER, "software raw config rejected");
    invalid = request; invalid.rawConfig.vendor = 2;
    require(validateRequest(invalid) == ERROR_INVALID_PARAMETER, "software raw identity rejected");
    invalid = request; invalid.interval = 0;
    require(validateRequest(invalid) == ERROR_INVALID_PARAMETER, "zero software period rejected");
    invalid = request; invalid.stacks = 2;
    require(validateRequest(invalid) == ERROR_INVALID_PARAMETER, "invalid software stack flag rejected");

    ProfileView view; ProfileRouter::Output output; DecodedEvent decoded;
    std::uint64_t fault[] = {0xfeedface, 0x123456};
    auto source = event(pageFault, 10, 123, 100, fault, sizeof(fault));
    source.EventHeader.ThreadId = 88; source.BufferContext.ProcessorIndex = 7;
    source.EventHeader.EventDescriptor.Id = 0xbeef; source.EventHeader.EventDescriptor.Keyword = ~0ull;
    EVENT_HEADER_EXTENDED_DATA_ITEM extension{}; extension.ExtType = 0xffff; extension.DataPtr = 1;
    source.ExtendedData = &extension; source.ExtendedDataCount = 1;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == 0 && view.kind == ProfileKind::Sample,
        "software page fault recognized");
    require(view.event.EventHeader.ThreadId == 88 && view.event.EventHeader.ProcessId == 123
        && view.event.BufferContext.ProcessorIndex == 7 && !view.event.ExtendedDataCount
        && !view.event.EventHeader.EventDescriptor.Id && !view.event.EventHeader.EventDescriptor.Keyword,
        "fault ownership/cpu preserved and emitter metadata removed");
    std::uint64_t payload[2]; std::memcpy(payload, view.event.UserData, sizeof(payload));
    require(payload[0] == 0 && payload[1] == fault[1], "fault VA removed while PC retained");
    ProfileRouter faults; faults.configureSoftware(123, true, SoftwareKind::PageFaults, 8);
    require(faults.route(view, false, output) == 0 && !output.first.empty() && output.second.empty(), "target fault forwarded immediately");
    source.EventHeader.ProcessId = 999;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == 0 && view.kind == ProfileKind::ForeignSample
        && faults.route(view, false, output) == 0 && empty(output), "foreign fault withheld despite equal TID");
    source.EventHeader.ProcessId = ULONG(-1);
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == ERROR_INVALID_DATA, "fault without process rejected");
    source.EventHeader.ProcessId = 123;
    Stack faultStack{100, 123, 88, 0x123456};
    auto faultWalk = event(stackWalk, 32, 999, 101, &faultStack, sizeof(faultStack));
    require(profileEvent(123, false, faultWalk, view, SoftwareKind::PageFaults) == 0
        && faults.route(view, false, output) == 0 && output.first.empty() && !output.second.empty(), "target fault stack forwarded");
    faultStack.pid = 999;
    require(profileEvent(123, false, faultWalk, view, SoftwareKind::PageFaults) == 0
        && faults.route(view, false, output) == 0 && empty(output), "foreign fault stack withheld");
    ULONG identity[] = {123, 88};
    auto ended = event(threads, 2, 999, 102, identity, sizeof(identity));
    require(profileEvent(123, false, ended, view, SoftwareKind::PageFaults) == 0
        && faults.route(view, false, output) == 0 && !output.first.empty(), "target end forwarded");
    source.EventHeader.TimeStamp.QuadPart = 103;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == 0
        && faults.route(view, false, output) == 0 && empty(output), "fault after its thread's end not counted");
    ULONG foreignIdentity[] = {999, 88};
    auto started = event(threads, 1, 999, 104, foreignIdentity, sizeof(foreignIdentity));
    require(profileEvent(123, false, started, view, SoftwareKind::PageFaults) == 0
        && faults.route(view, false, output) == 0 && empty(output), "foreign start private");
    source.EventHeader.TimeStamp.QuadPart = 105;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == 0
        && faults.route(view, false, output) == 0 && !output.first.empty(), "reused TID clears end state");
    source.EventHeader.ProviderId = perfInfo; source.EventHeader.EventDescriptor.Opcode = 46;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == 0 && view.kind == ProfileKind::Ignore,
        "software cannot admit timer samples");
    source.EventHeader.ProviderId = pageFault; source.EventHeader.EventDescriptor.Opcode = 32;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == 0 && view.kind == ProfileKind::Ignore,
        "fault completion excluded");
    source.EventHeader.EventDescriptor.Opcode = 10; source.EventHeader.EventDescriptor.Version = 3;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == ERROR_NOT_SUPPORTED,
        "software unknown schema rejected");
    source.EventHeader.EventDescriptor.Version = 2; source.UserDataLength = 8;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == ERROR_INVALID_DATA,
        "software malformed payload rejected");
    ULONG fault32[] = {0xfeed, 0x1234};
    source.UserData = fault32; source.EventHeader.Flags = EVENT_HEADER_FLAG_32_BIT_HEADER;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == 0
        && view.event.UserDataLength == 8 && static_cast<ULONG*>(view.event.UserData)[0] == 0
        && static_cast<ULONG*>(view.event.UserData)[1] == fault32[1], "32-bit fault sanitized");
    source.EventHeader.Flags = 0;
    require(profileEvent(123, false, source, view, SoftwareKind::PageFaults) == ERROR_INVALID_DATA,
        "software pointer width must be exact");
    Result faultResult; faults.finish(faultResult);
    auto faultStats = faults.softwareDiagnostics();
    require(!faultResult.error && faultResult.foreignProfiles == 1 && faultStats.samples == 2 && faultStats.exitingEvents == 1
        && faultStats.stacks == 2 && faultStats.targetStacks == 1 && !faultStats.switchOuts, "fault routing diagnostics");

    ULONG switchData[] = {77, 88, 0, 0, 0, 0};
    auto switched = event(threads, 36, 999, 200, switchData, sizeof(switchData));
    auto switchState = [&](ULONG incoming, ULONG outgoing, std::uint64_t time, USHORT cpu, UCHAR state = 5) {
        switchData[0] = incoming; switchData[1] = outgoing; reinterpret_cast<unsigned char*>(switchData)[14] = state;
        switched.EventHeader.TimeStamp.QuadPart = time; switched.BufferContext.ProcessorIndex = cpu;
        require(profileEvent(123, false, switched, view, SoftwareKind::ContextSwitches) == 0 && view.kind == ProfileKind::Switch
            && view.tid == outgoing && view.incomingTid == incoming && view.cpu == cpu && view.terminated == (state == 4)
            && !view.event.UserDataLength, "switch view carries both identities and no payload");
    };
    switchData[0] = 0; switchData[1] = 0;
    require(profileEvent(123, false, switched, view, SoftwareKind::ContextSwitches) == 0 && view.kind == ProfileKind::Ignore,
        "idle-only switch ignored");
    switchData[1] = ULONG(-1);
    require(profileEvent(123, false, switched, view, SoftwareKind::ContextSwitches) == ERROR_INVALID_DATA, "invalid outgoing TID rejected");
    switched.EventHeader.EventDescriptor.Version = 6; switchData[1] = 88;
    require(profileEvent(123, false, switched, view, SoftwareKind::ContextSwitches) == ERROR_NOT_SUPPORTED,
        "unknown future switch schema rejected");
    switched.EventHeader.EventDescriptor.Version = 2;
    Stack proof{0, 123, 88, 0xfffff80000001234ULL};
    auto walked = event(stackWalk, 32, 999, 0, &proof, sizeof(proof));
    auto walk = [&](std::uint64_t time, ULONG pid, ULONG tid, ProfileRouter& router) {
        proof = {time, pid, tid, 0xfffff80000001234ULL}; walked.EventHeader.TimeStamp.QuadPart = static_cast<LONGLONG>(time + 20);
        require(profileEvent(123, false, walked, view, SoftwareKind::ContextSwitches) == 0, "switch-in stack view");
        return router.route(view, false, output);
    };
    auto provenAt = [&](std::uint64_t out, std::uint64_t in, ULONG tid, USHORT cpu) {
        require(decodeEvent(output.first, nullptr, decoded) == 0, "proven switch decodes");
        auto record = WindowsProfiler::Etw::decodeSoftware(SoftwareKind::ContextSwitches, decoded.event);
        return record.kind == WindowsProfiler::Etw::SoftwareRecordKind::Sample && record.time == out && record.stackTime == in
            && record.tid == tid && record.pid == 123 && record.cpu == cpu && !decoded.event.EventHeader.ThreadId;
    };

    ProfileRouter switches; switches.configureSoftware(123, true, SoftwareKind::ContextSwitches, 8);
    switchState(0, 88, 300, 3);
    require(switches.route(view, true, output) == 0 && empty(output), "switch-out held until its owner is proven");
    require(walk(300, 123, 88, switches) == 0 && output.first.empty() && !output.second.empty(),
        "stack at the switch-out time belongs to the incoming thread");
    switchState(88, 0, 400, 5);
    require(switches.route(view, true, output) == 0 && empty(output), "switch-in held for its stack");
    require(walk(400, 123, 88, switches) == 0 && provenAt(300, 400, 88, 3) && !output.second.empty(),
        "next switch-in stack proves owner and supplies the switch-out stack");
    require(walk(400, 123, 88, switches) == 0 && output.first.empty() && !output.second.empty(), "later part forwarded only as stack");
    // A foreign owner is proven by the same rule and withheld.
    switchState(0, 89, 500, 1); require(switches.route(view, false, output) == 0, "foreign switch-out");
    switchState(89, 0, 600, 2); require(switches.route(view, false, output) == 0, "foreign switch-in");
    require(walk(600, 999, 89, switches) == 0 && empty(output), "foreign proof withholds switch and stack");
    // Same-tick switch-out and switch-in on different processors: either delivery order pairs them.
    switchState(0, 90, 700, 1); require(switches.route(view, false, output) == 0, "same-tick setup out");
    switchState(90, 0, 800, 2); require(switches.route(view, false, output) == 0, "same-tick setup in");
    require(walk(800, 123, 90, switches) == 0 && provenAt(700, 800, 90, 1), "same-tick setup proof");
    switchState(90, 0, 900, 4); require(switches.route(view, false, output) == 0, "switch-in delivered first");
    switchState(0, 90, 900, 6); require(switches.route(view, false, output) == 0, "switch-out at the same tick");
    require(walk(900, 123, 90, switches) == 0 && provenAt(900, 900, 90, 6), "same-tick switch-out precedes switch-in");
    // Exit: switch-outs after the thread's end are not counted until its terminated switch-out.
    ULONG target90[] = {123, 90};
    auto end90 = event(threads, 2, 999, 950, target90, sizeof(target90));
    require(profileEvent(123, false, end90, view, SoftwareKind::ContextSwitches) == 0
        && switches.route(view, false, output) == 0 && !output.first.empty(), "target end forwarded immediately");
    switchState(0, 90, 960, 4); require(switches.route(view, false, output) == 0, "exiting switch-out");
    switchState(90, 0, 970, 4); require(switches.route(view, false, output) == 0, "exiting switch-in");
    require(walk(970, 123, 90, switches) == 0 && output.first.empty(), "exiting switch-out never proven");
    switchState(0, 90, 980, 4, 4); require(switches.route(view, false, output) == 0, "terminated switch-out");
    auto start90 = event(threads, 1, 999, 990, target90, sizeof(target90));
    require(profileEvent(123, false, start90, view, SoftwareKind::ContextSwitches) == 0
        && switches.route(view, false, output) == 0 && !output.first.empty(), "reused target TID forwarded");
    switchState(90, 0, 995, 4); require(switches.route(view, false, output) == 0, "first switch-in of new lifetime");
    switchState(0, 90, 1000, 4); require(switches.route(view, false, output) == 0, "new lifetime switch-out");
    switchState(90, 0, 1010, 4); require(switches.route(view, false, output) == 0, "new lifetime switch-in");
    require(walk(1010, 123, 90, switches) == 0 && provenAt(1000, 1010, 90, 4), "new lifetime counted");
    // Lost events break a sequence without guessing its owner.
    switchState(0, 91, 1100, 1); require(switches.route(view, false, output) == 0, "break setup");
    switchState(0, 91, 1110, 1); require(switches.route(view, false, output) == 0, "double switch-out");
    switchState(91, 0, 1120, 1); require(switches.route(view, false, output) == 0, "switch-in without stack");
    switchState(0, 91, 1130, 1); require(switches.route(view, false, output) == 0, "switch-out after missing stack");
    switchState(91, 0, 1140, 1); require(switches.route(view, false, output) == 0, "switch-in after break");
    require(walk(1140, 123, 91, switches) == 0 && provenAt(1130, 1140, 91, 1), "sequence resumes at next exact pair");
    switchState(0, 92, 1200, 1); require(switches.route(view, false, output) == 0, "switch-out before end");
    ULONG target92[] = {123, 92};
    auto end92 = event(threads, 2, 999, 1210, target92, sizeof(target92));
    require(profileEvent(123, false, end92, view, SoftwareKind::ContextSwitches) == 0
        && switches.route(view, false, output) == 0, "end without intervening switch-in");
    switchState(0, 93, 1300, 1); require(switches.route(view, false, output) == 0, "unresolved at finish");
    switchState(94, 0, 1250, 1);
    require(switches.route(view, false, output) == ERROR_INVALID_DATA, "switch time reversal rejected");
    Result switchResult; switches.finish(switchResult);
    auto switchStats = switches.softwareDiagnostics();
    require(!switchResult.error && switchResult.foreignProfiles == 1 && !switchResult.potentialTargetLoss
        && switchStats.reason == RouterFailure::SwitchTimeReversal && switchStats.provenTarget == 5
        && switchStats.provenForeign == 1 && switchStats.exitingEvents == 1 && switchStats.terminatedSwitches == 1
        && switchStats.sequenceBreaks == 3 && switchStats.unresolved == 1 && switchStats.switchOuts == 10
        && switchStats.switchIns == 7, "switch routing diagnostics");
    require(switchResult.router.provenTarget == 5 && switchResult.router.unresolved == 1, "finish publishes diagnostics");

    ProfileRouter stackless; stackless.configureSoftware(123, false, SoftwareKind::ContextSwitches, 8);
    switchState(0, 88, 100, 1); require(stackless.route(view, false, output) == 0, "stackless switch-out");
    switchState(88, 0, 200, 1); require(stackless.route(view, false, output) == 0, "stackless switch-in");
    require(walk(200, 123, 88, stackless) == 0 && provenAt(100, 200, 88, 1) && output.second.empty(),
        "stackless proof stays private");
    ProfileRouter bounded; bounded.configureSoftware(123, true, SoftwareKind::ContextSwitches, 1);
    switchState(0, 88, 100, 1); require(bounded.route(view, false, output) == 0, "capacity setup");
    switchState(0, 89, 101, 1);
    require(bounded.route(view, false, output) == ERROR_BUFFER_OVERFLOW
        && bounded.softwareDiagnostics().reason == RouterFailure::SwitchCapacity, "switch capacity fails without eviction");
    ProfileRouter exits; exits.configureSoftware(123, true, SoftwareKind::ContextSwitches, 1);
    for (ULONG tid : {95ul, 96ul}) {
        ULONG ending[] = {123, tid};
        auto record = event(threads, 2, 999, 100 + tid, ending, sizeof(ending));
        require(profileEvent(123, false, record, view, SoftwareKind::ContextSwitches) == 0, "exit capacity view");
        auto error = exits.route(view, false, output);
        require(error == (tid == 95 ? 0 : ERROR_BUFFER_OVERFLOW), "exit capacity bounded");
    }
    require(exits.softwareDiagnostics().reason == RouterFailure::ExitCapacity, "exit capacity diagnosed");
    static_assert(PROTOCOL == 8 && sizeof(Result) == 160 && sizeof(RouterDiagnostics) == 112);

    walked.EventHeader.EventDescriptor.Version = 1;
    require(profileEvent(123, false, walked, view, SoftwareKind::ContextSwitches) == ERROR_NOT_SUPPORTED,
        "unsupported software proof version rejected");
}
}
int main() try {
    ProfileRouter router; router.configure(123, true, 4);
    ProfileRouter::Output output;
    ProfileView view;
    auto sample = event(perfInfo, 46, 999, 100, &profile, sizeof(profile));
    require(profileEvent(123, true, sample, view) == 0 && router.route(view, true, output) == 0 && empty(output), "foreign header rejected despite TID hint");
    sample.EventHeader.ProcessId = ULONG(-1);
    require(profileEvent(123, true, sample, view) == 0 && router.route(view, true, output) == 0 && empty(output), "unknown PID cannot use TID hint");
    auto walked = event(stackWalk, 32, 4, 101, &stack, sizeof(stack));
    stack.pid = 999;
    require(profileEvent(123, true, walked, view) == 0 && router.route(view, false, output) == 0 && empty(output), "explicit foreign stack rejects waiting sample");
    sample.EventHeader.TimeStamp.QuadPart = 200; stack.time = 200; stack.pid = 123;
    require(profileEvent(123, true, sample, view) == 0 && router.route(view, true, output) == 0 && empty(output), "second unknown held");
    require(profileEvent(123, true, walked, view) == 0 && router.route(view, false, output) == 0
        && !output.first.empty() && !output.second.empty(), "own StackWalk releases exact sample");
    DecodedEvent decoded;
    require(decodeEvent(output.second, nullptr, decoded) == 0 && decoded.event.EventHeader.ProcessId == 123
        && decoded.event.EventHeader.TimeStamp.QuadPart == 200 && decoded.event.UserDataLength == 16
        && decoded.event.EventHeader.ThreadId == 0 && decoded.event.EventHeader.ActivityId.Data1 == 0, "normalized PID/minimal profile metadata");
    stack.time = 300;
    require(profileEvent(123, true, walked, view) == 0 && router.route(view, false, output) == 0, "stack-first proof");
    sample.EventHeader.TimeStamp.QuadPart = 300;
    require(profileEvent(123, true, sample, view) == 0 && router.route(view, false, output) == 0 && !output.first.empty(), "stack-first ownership");
    sample.EventHeader.TimeStamp.QuadPart = 400;
    require(profileEvent(123, true, sample, view) == 0 && router.route(view, true, output) == 0 && empty(output), "unproven potential target held");
    sample.EventHeader.TimeStamp.QuadPart = 500;
    require(profileEvent(123, true, sample, view) == 0 && router.route(view, false, output) == 0 && empty(output), "global unattributed held");
    Result stats; router.finish(stats);
    require(stats.foreignProfiles == 2 && stats.unattributedProfiles == 1 && stats.potentialTargetLoss == 1, "distinct discard diagnostics");
    ProfileRouter stackless; stackless.configure(123, false, 1);
    sample.EventHeader.TimeStamp.QuadPart = 600; stack.time = 600;
    require(profileEvent(123, true, sample, view) == 0 && stackless.route(view, true, output) == 0 && empty(output), "stackless unknown still waits");
    require(profileEvent(123, true, walked, view) == 0 && stackless.route(view, false, output) == 0
        && output.first.empty() && !output.second.empty(), "proof stacks suppressed in stackless output");
    sample.EventHeader.TimeStamp.QuadPart = 700;
    require(profileEvent(123, true, sample, view) == 0 && stackless.route(view, true, output) == 0, "bounded candidate one");
    sample.EventHeader.TimeStamp.QuadPart = 800;
    require(profileEvent(123, true, sample, view) == 0 && stackless.route(view, false, output) == 0, "bounded candidate eviction");
    Result limited; stackless.finish(limited);
    require(limited.potentialTargetLoss == 1 && limited.unattributedProfiles == 1, "bounded eviction reported");
    ProfileRouter quarantined; quarantined.configure(123, true, 4);
    stack.time = 1000; stack.pid = 123;
    require(profileEvent(123, true, walked, view) == 0 && quarantined.route(view, false, output) == 0, "owned conflict setup");
    stack.pid = 999;
    require(profileEvent(123, true, walked, view) == 0 && quarantined.route(view, false, output) == 0 && empty(output), "foreign conflicting proof private");
    sample.EventHeader.TimeStamp.QuadPart = 1000;
    require(profileEvent(123, true, sample, view) == 0 && quarantined.route(view, true, output) == 0 && empty(output), "conflicting proofs quarantine unknown");
    sample.EventHeader.TimeStamp.QuadPart = 1100;
    require(profileEvent(123, true, sample, view) == 0 && quarantined.route(view, true, output) == 0 && empty(output), "duplicate setup");
    require(profileEvent(123, true, sample, view) == 0 && quarantined.route(view, true, output) == 0 && empty(output), "duplicate unknown quarantined");
    stack.time = 1100; stack.pid = 123;
    require(profileEvent(123, true, walked, view) == 0 && quarantined.route(view, false, output) == 0 && output.second.empty(), "later own stack cannot release duplicate");
    require(profileEvent(123, true, sample, view) == 0 && quarantined.route(view, true, output) == 0 && empty(output), "quarantine remains after own proof");
    stack.time = 1200; stack.pid = 999;
    require(profileEvent(123, true, walked, view) == 0 && quarantined.route(view, false, output) == 0 && empty(output), "foreign proof first");
    sample.EventHeader.TimeStamp.QuadPart = 1200;
    require(profileEvent(123, true, sample, view) == 0 && quarantined.route(view, true, output) == 0 && empty(output), "foreign-first rejects unknown");
    ULONG identity[] = {123, 88, 0xfeed};
    auto thread = event(threads, 1, 999, 900, identity, sizeof(identity));
    require(profileEvent(123, true, thread, view) == 0 && view.kind == ProfileKind::Thread
        && view.event.EventHeader.ProcessId == 0 && view.event.EventHeader.ThreadId == 0
        && view.event.UserDataLength == 8 && !view.event.ExtendedDataCount, "thread tails/emitter data removed");
    thread.EventHeader.ProviderId.Data4[6] = 0x0d;
    require(profileEvent(123, true, thread, view) == 0 && view.kind == ProfileKind::Ignore, "misspelled thread GUID is not lifecycle metadata");
    thread.EventHeader.ProviderId = threads;
    ULONG legacy[] = {88, 123}; thread.EventHeader.EventDescriptor.Version = 0; thread.UserData = legacy; thread.UserDataLength = sizeof(legacy);
    require(profileEvent(123, true, thread, view) == 0 && view.pid == 123 && view.tid == 88
        && view.event.EventHeader.EventDescriptor.Version == 2 && std::memcmp(view.event.UserData, identity, 8) == 0, "classic v0 IDs normalized");
    struct Image { std::uint64_t base, size; ULONG pid, checksum, stamp, secret; } loaded{0xfffff80000001000, 4096, 999, 42, 43, 0xfeed};
    auto notification = event(image, 10, 999, 901, &loaded, sizeof(loaded));
    require(profileEvent(123, true, notification, view) == 0 && view.kind == ProfileKind::KernelImage
        && view.event.UserDataLength == 28 && view.event.EventHeader.ProcessId == 0
        && std::memcmp(static_cast<unsigned char*>(view.event.UserData) + 16, "\0\0\0\0", 4) == 0, "kernel identity excludes PID/tail");
    notification.EventHeader.EventDescriptor.Version = 3; notification.EventHeader.EventDescriptor.Opcode = 3;
    require(profileEvent(123, true, notification, view) == 0 && view.kind == ProfileKind::KernelImage
        && view.event.EventHeader.EventDescriptor.Version == 3 && view.event.EventHeader.EventDescriptor.Opcode == 3
        && view.event.EventHeader.TimeStamp.QuadPart == 901 && view.event.UserDataLength == 28
        && !view.event.ExtendedDataCount && view.event.EventHeader.ProcessId == 0, "v3 rundown preserves typed prefix/time/version only");
    notification.EventHeader.EventDescriptor.Version = 4;
    require(profileEvent(123, true, notification, view) == ERROR_NOT_SUPPORTED, "unknown image v4 rejected");
    notification.EventHeader.EventDescriptor.Version = 3;
    loaded.base = 0x100000;
    require(profileEvent(123, true, notification, view) == 0 && view.kind == ProfileKind::Ignore, "foreign user image rejected");
    softwareTests();
    std::puts("BROKER_PROFILE_ROUTER_OK tidHintNeverAuthorizes=1 exactStackProof=1 bounded=1 stacklessPrivateProof=1 metadataMinimized=1 softwareDispatch=1 switchInProof=1 sameTickSwitches=1 exitingThreads=1 sequenceBreaks=1 softwarePrivacy=1 capacityDiagnostics=1 wire8=1");
    return 0;
} catch (const std::exception& error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
