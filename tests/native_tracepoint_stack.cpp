/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsTracepointStack.h"
#include "windowsEtwBroker.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

using namespace WindowsProfiler::Tracepoint;
namespace Broker = WindowsProfiler::Etw::Broker;
namespace {
unsigned checks = 0;
constexpr ULONG PID = 123, TID = 456;
constexpr std::uint64_t KERNEL = 0xfffff80012345678ULL, USER = 0x7ffa12345678ULL;
constexpr GUID PROVIDER = {42, 1, 2, {3,4,5,6,7,8,9,10}};
void require(bool condition, const char* text) {
    ++checks;
    if (!condition) { std::fprintf(stderr, "%s\n", text); std::exit(1); }
}
Record primary(std::uint64_t match = 77, ULONG tid = TID) {
    Record r;
    r.kind = Kind::Event; r.provider = PROVIDER;
    r.descriptor.Id = 123; r.descriptor.Version = 4; r.descriptor.Task = 5;
    r.descriptor.Keyword = 0x8000000000000001ULL;
    r.time = 1000; r.pid = PID; r.tid = tid; r.cpu = 300;
    r.stackCount = 1;
    r.stacks[0].matchId = match; r.stacks[0].pointerSize = 8;
    r.stacks[0].depth = 1; r.stacks[0].addresses[0] = KERNEL;
    return r;
}
Record companion(std::uint64_t match = 77, ULONG tid = TID, bool wow64 = false) {
    auto r = primary(match, tid);
    r.kind = Kind::Continuation; r.provider = STACK_CONTINUATION_PROVIDER;
    r.descriptor = {}; r.descriptor.Id = 18; r.descriptor.Opcode = 24; r.descriptor.Task = 6;
    r.time = 2000; r.cpu = 17;
    r.stacks[0].pointerSize = wow64 ? 4 : 8; r.stacks[0].addresses[0] = wow64 ? 0xf1234567 : USER;
    return r;
}
Record both(std::uint64_t match = 77, ULONG tid = TID) {
    auto r = primary(match, tid);
    r.stackCount = 2; r.stacks[1] = companion(match, tid).stacks[0];
    return r;
}
void checkJoined(const JoinedStack& out, const Record& original, std::uint64_t weight, std::uint64_t lifetime, bool wow64) {
    require(out.counter == weight && out.lifetime == lifetime, "primary weight/lifetime changed");
    const auto& r = out.record;
    require(r.kind == Kind::Event && IsEqualGUID(r.provider, original.provider)
        && std::memcmp(&r.descriptor, &original.descriptor, sizeof(r.descriptor)) == 0
        && r.schema == original.schema, "primary event identity changed");
    require(r.time == original.time && r.pid == PID && r.tid == original.tid && r.cpu == original.cpu,
        "primary timestamp/PID/TID/CPU changed");
    require(r.stackCount == 2 && r.stacks[0].addresses[0] == KERNEL && r.stacks[0].depth == 1
        && r.stacks[1].addresses[0] == (wow64 ? 0xf1234567 : USER) && r.stacks[1].depth == 1
        && r.stacks[1].pointerSize == (wow64 ? 4u : 8u)
        && r.stacks[0].matchId == 77 && r.stacks[1].matchId == 77, "stack halves changed");
}
void arrivalOrders() {
    JoinedStack out; bool ready;
    for (bool first : {false, true}) for (bool wow64 : {false, true}) {
        StackJoiner joiner; joiner.reset(PID);
        auto original = primary();
        original.schema = {9,0,0,'E','v','e','n','t',0};
        auto p = original, c = companion(77, TID, wow64);
        // No time-based eviction: the continuation may be delayed arbitrarily.
        c.time = UINT64_MAX;
        auto code = first ? joiner.primary(std::move(p), 9001, UINT64_MAX, out, ready)
            : joiner.continuation(std::move(c), out, ready);
        require(code == 0 && !ready && joiner.stats().pending == 1 && joiner.stats().retainedBytes > 0,
            "first half did not become pending");
        code = first ? joiner.continuation(std::move(c), out, ready)
            : joiner.primary(std::move(p), 9001, UINT64_MAX, out, ready);
        require(code == 0 && ready, "opposite half failed to join");
        checkJoined(out, original, UINT64_MAX, 9001, wow64);
        auto stats = joiner.stats();
        require(stats.joined == 1 && !stats.pending && !stats.retainedBytes && joiner.finish() == 0,
            "successful join did not release pending state");
    }
    StackJoiner joiner; joiner.reset(PID);
    auto immediate = primary(0); immediate.stacks[0].depth = 2; immediate.stacks[0].addresses[1] = USER;
    require(joiner.primary(std::move(immediate), 12, 34, out, ready) == 0 && ready && out.counter == 34
        && out.lifetime == 12 && out.record.stackCount == 1, "complete mixed stack deferred");
    auto noStack = primary(); noStack.stackCount = 0;
    require(joiner.primary(std::move(noStack), 13, 35, out, ready) == 0 && ready, "stackless primary deferred");
    auto inlinePair = both(); auto original = inlinePair;
    require(joiner.primary(std::move(inlinePair), 14, 36, out, ready) == 0 && ready, "inline pair deferred");
    checkJoined(out, original, 36, 14, false);
    require(joiner.stats().joined == 1 && joiner.finish() == 0, "immediate primary accounting");
}
void isolationAndAmbiguity() {
    JoinedStack out; bool ready;
    StackJoiner joiner; joiner.reset(PID);
    require(joiner.primary(primary(77, 10), 1, 2, out, ready) == 0 && !ready, "first isolated primary");
    require(joiner.primary(primary(77, 11), 2, 3, out, ready) == 0 && !ready, "second TID isolated primary");
    require(joiner.primary(primary(78, 10), 1, 4, out, ready) == 0 && !ready, "second match isolated primary");
    require(joiner.continuation(companion(77, 11), out, ready) == 0 && ready
        && out.record.tid == 11 && out.counter == 3 && out.lifetime == 2, "TID isolation failed");
    require(joiner.continuation(companion(78, 10), out, ready) == 0 && ready && out.counter == 4, "MatchId isolation failed");
    require(joiner.continuation(companion(77, 10), out, ready) == 0 && ready && out.counter == 2
        && joiner.finish() == 0, "remaining isolated primary");
    joiner.reset(PID);
    require(joiner.primary(primary(77), 1, 2, out, ready) == 0
        && joiner.primary(primary(78), 99, 3, out, ready) == 0, "old/new lifetime seed");
    require(joiner.continuation(companion(77), out, ready) == 0 && ready && out.lifetime == 1
        && joiner.continuation(companion(78), out, ready) == 0 && ready && out.lifetime == 99,
        "later lifetime displaced selected-primary generation");
    for (bool duplicatePrimary : {false, true}) for (bool completed : {false, true}) {
        joiner.reset(PID);
        require(joiner.primary(primary(), 1, 2, out, ready) == 0 && !ready, "ambiguity seed");
        if (completed) require(joiner.continuation(companion(), out, ready) == 0 && ready, "ambiguity completion seed");
        if (duplicatePrimary) {
            // A different lifetime must not turn reuse into a guessed association.
            require(joiner.primary(primary(), 99, 3, out, ready) == ERROR_INVALID_DATA && !ready, "reused primary accepted");
        } else {
            require(joiner.continuation(companion(), out, ready) == (completed ? ERROR_INVALID_DATA : 0), "first continuation");
            require(joiner.continuation(companion(), out, ready) == ERROR_INVALID_DATA && !ready, "duplicate continuation accepted");
        }
        require(joiner.stats().ambiguous == 1 && joiner.finish() == ERROR_INVALID_DATA, "ambiguity not sticky at stop");
        require(joiner.primary(primary(99), 1, 2, out, ready) == ERROR_INVALID_DATA && !ready, "fatal state not sticky");
    }
    joiner.reset(PID);
    require(joiner.continuation(companion(), out, ready) == 0, "companion-first reuse seed");
    require(joiner.continuation(companion(), out, ready) == ERROR_INVALID_DATA && !ready, "duplicate pending companion accepted");
    joiner.reset(PID);
    auto early = companion(); early.time = 999;
    require(joiner.primary(primary(), 1, 2, out, ready) == 0
        && joiner.continuation(std::move(early), out, ready) == ERROR_INVALID_DATA && !ready, "reversed event time accepted");
    joiner.reset(PID);
    auto coincident = companion(); coincident.time = 1000;
    require(joiner.primary(primary(), 1, 2, out, ready) == 0
        && joiner.continuation(std::move(coincident), out, ready) == 0 && ready, "equal QPC incorrectly ambiguous");
    joiner.reset(PID);
    auto foreign = companion(); ++foreign.pid;
    require(joiner.continuation(std::move(foreign), out, ready) == ERROR_INVALID_DATA && !ready, "foreign PID joined");
}
void rejectedShapes() {
    JoinedStack out; bool ready;
    for (unsigned variant = 0; variant < 15; ++variant) {
        StackJoiner joiner; joiner.reset(PID);
        auto r = primary();
        switch (variant) {
            case 0: r.stacks[0].addresses[0] = USER; break;
            case 1: r.stacks[0].depth = 0; break;
            case 2: r.stacks[0].depth = 2; r.stacks[0].addresses[1] = USER; break;
            case 3: r.stacks[0].pointerSize = 4; r.stacks[0].addresses[0] = UINT64_MAX; break;
            case 4: r.stacks[0].pointerSize = 3; break;
            case 5: r.stacks[0].addresses[0] = 0; break;
            case 6: r.stacks[0].addresses[0] = 0x800000000000ULL; break;
            case 7: r.stacks[0].depth = MAX_STACK_FRAMES + 1; break;
            case 8: r.stackCount = 3; break;
            case 9: r = both(); r.stacks[1].matchId++; break;
            case 10: r = both(); r.stacks[1] = r.stacks[0]; break;
            case 11: r = both(); r.stacks[0].matchId = 0; break;
            case 12: r.tid = 0; break;
            case 13: r.time = 0; break;
            case 14: r.kind = Kind::Continuation; break;
        }
        require(joiner.primary(std::move(r), 1, 2, out, ready) == ERROR_INVALID_DATA && !ready, "invalid primary shape accepted");
    }
    for (bool zeroLifetime : {false, true}) {
        StackJoiner joiner; joiner.reset(PID);
        require(joiner.primary(primary(), zeroLifetime ? 0 : 1, zeroLifetime ? 1 : 0, out, ready)
            == ERROR_INVALID_DATA && !ready, "unselected primary state accepted");
    }
    for (unsigned variant = 0; variant < 11; ++variant) {
        StackJoiner joiner; joiner.reset(PID);
        auto r = companion();
        switch (variant) {
            case 0: r.provider.Data1++; break;
            case 1: r.descriptor.Id++; break;
            case 2: r.descriptor.Version++; break;
            case 3: r.descriptor.Opcode++; break;
            case 4: r.descriptor.Task++; break;
            case 5: r.stackCount = 2; r.stacks[1] = r.stacks[0]; break;
            case 6: r.stacks[0].addresses[0] = KERNEL; break;
            case 7: r.stacks[0].depth = 0; break;
            case 8: r.stacks[0].matchId = 0; break;
            case 9: r.stacks[0].depth = 2; r.stacks[0].addresses[1] = KERNEL; break;
            case 10: r.stackCount = 0; break;
        }
        require(joiner.continuation(std::move(r), out, ready) == (variant >= 5 ? ERROR_INVALID_DATA : ERROR_NOT_SUPPORTED)
            && !ready, "unsupported continuation provenance accepted");
    }
}
void limitsAndStop() {
    JoinedStack out; bool ready;
    StackJoiner probe; probe.reset(PID);
    require(probe.primary(primary(), 1, 2, out, ready) == 0, "byte cost seed");
    const auto entryBytes = static_cast<size_t>(probe.stats().retainedBytes);
    require(probe.finish() == ERROR_INVALID_DATA && probe.stats().incomplete == 1
        && !probe.stats().retainedBytes && !probe.stats().pending, "unresolved primary did not fail stop");
    require(probe.finish() == ERROR_INVALID_DATA && probe.stats().incomplete == 1, "repeat stop lost failure or recounted");
    for (unsigned variant = 0; variant < 4; ++variant) {
        JoinLimits limits;
        if (variant == 0) limits.pending = 1;
        if (variant == 1) limits.bytes = entryBytes * 2 - 1;
        if (variant == 2) limits.completed = 0;
        if (variant == 3) limits.bytes = entryBytes - 1;
        StackJoiner joiner(limits); joiner.reset(PID);
        if (variant < 2) {
            require(joiner.primary(primary(), 1, 2, out, ready) == 0 && !ready, "bounded first pending rejected");
            require(joiner.primary(primary(78), 1, 2, out, ready) == ERROR_BUFFER_OVERFLOW && !ready, "pending/byte cap not enforced");
        } else if (variant == 2) {
            require(joiner.primary(primary(), 1, 2, out, ready) == 0
                && joiner.continuation(companion(), out, ready) == ERROR_BUFFER_OVERFLOW && !ready, "completed cap not enforced");
        } else require(joiner.primary(primary(), 1, 2, out, ready) == ERROR_BUFFER_OVERFLOW && !ready, "first entry byte cap not enforced");
        require(joiner.stats().overflows == 1 && joiner.finish() == ERROR_BUFFER_OVERFLOW, "overflow not sticky at stop");
    }
    StackJoiner schemas({10, entryBytes + 8, 10}); schemas.reset(PID);
    auto large = primary(); large.schema.resize(9);
    require(schemas.primary(std::move(large), 1, 2, out, ready) == ERROR_BUFFER_OVERFLOW, "schema storage escaped cap");
    StackJoiner exact({1, entryBytes, 1}); exact.reset(PID);
    require(exact.primary(primary(), 1, 2, out, ready) == 0
        && exact.continuation(companion(), out, ready) == 0 && ready && !exact.stats().retainedBytes,
        "exact byte/pending/completed boundary rejected");
    require(exact.primary(both(78), 1, 2, out, ready) == ERROR_BUFFER_OVERFLOW && !ready, "second completed entry escaped cap");
    StackJoiner joiner; joiner.reset(PID);
    require(joiner.continuation(companion(), out, ready) == 0 && !ready, "orphan seed");
    require(joiner.finish() == 0 && joiner.stats().orphanContinuations == 1 && !joiner.stats().incomplete
        && !joiner.stats().joined && !joiner.stats().pending, "unselected orphan charged or failed stop");
    joiner.reset(PID);
    require(joiner.primary(primary(0), 7, 8, out, ready) == 0 && ready && out.counter == 8, "valid output before stop seed");
    require(joiner.primary(primary(), 1, 2, out, ready) == 0 && !ready
        && joiner.continuation(companion(78), out, ready) == 0 && !ready, "mixed stop seed");
    require(joiner.finish() == ERROR_INVALID_DATA && joiner.stats().incomplete == 1
        && joiner.stats().orphanContinuations == 1 && out.counter == 8, "stop failure lost valid output or orphan policy");
    joiner.reset(PID);
    require(!joiner.stats().incomplete && !joiner.stats().ambiguous && !joiner.stats().overflows
        && joiner.primary(both(), 1, 2, out, ready) == 0 && ready && joiner.finish() == 0, "capture reset retained failure/key state");
}

void unselectedPrimaries() {
    JoinedStack out; bool ready;
    for (bool companionFirst : {false, true}) {
        StackJoiner joiner; joiner.reset(PID);
        if (companionFirst) require(joiner.continuation(companion(), out, ready) == 0 && !ready, "unselected companion-first seed");
        auto skipped = primary();
        require(joiner.unselected(skipped) == 0 && !joiner.stats().pending && !joiner.stats().retainedBytes,
            "unselected primary retained stack state");
        if (!companionFirst) require(joiner.continuation(companion(), out, ready) == 0 && !ready, "unselected late companion");
        require(joiner.finish() == 0 && joiner.stats().orphanContinuations == 1
            && !joiner.stats().joined && !joiner.stats().incomplete, "unselected pair charged an event or failed stop");
        require(joiner.primary(primary(), 99, 2, out, ready) == ERROR_INVALID_DATA && !ready,
            "unselected identity forgotten after companion discard/stop");
    }
    // S = selected primary, U = unselected primary, C = continuation.
    for (const char* order : {"SUC", "SCU", "USC", "UCS", "CSU", "CUS"}) {
        StackJoiner joiner; joiner.reset(PID);
        bool failed = false, primarySeen = false;
        for (const char* step = order; *step && !failed; ++step) {
            ULONG code;
            if (*step == 'C') code = joiner.continuation(companion(), out, ready);
            else {
                code = *step == 'S' ? joiner.primary(primary(), 99, 2, out, ready)
                    : joiner.unselected(primary());
                require(code == (primarySeen ? ERROR_INVALID_DATA : 0), "filtered primary hid capture-scoped reuse");
                primarySeen = true;
            }
            failed = code != 0;
        }
        require(failed && joiner.stats().ambiguous == 1 && joiner.finish() == ERROR_INVALID_DATA,
            "selected/unselected/companion permutation did not fail stop");
    }
    StackJoiner joiner; joiner.reset(PID);
    require(joiner.unselected(primary()) == 0 && joiner.finish() == 0 && !joiner.stats().incomplete
        && !joiner.stats().orphanContinuations, "unselected missing companion failed stop or invented orphan");
    require(joiner.unselected(primary()) == ERROR_INVALID_DATA, "repeated unselected primary accepted");
    joiner.reset(PID);
    require(joiner.unselected(primary()) == 0 && joiner.continuation(companion(), out, ready) == 0
        && joiner.continuation(companion(), out, ready) == ERROR_INVALID_DATA && !ready,
        "unselected duplicate continuation accepted");
    joiner.reset(PID);
    auto earlier = companion(); earlier.time = 999;
    require(joiner.unselected(primary()) == 0
        && joiner.continuation(std::move(earlier), out, ready) == ERROR_INVALID_DATA && !ready,
        "unselected reversed timestamp accepted");
    joiner.reset(PID);
    earlier = companion(); earlier.time = 999;
    require(joiner.continuation(std::move(earlier), out, ready) == 0
        && joiner.unselected(primary()) == ERROR_INVALID_DATA, "unselected companion-first reversed timestamp accepted");
    joiner.reset(PID);
    require(joiner.unselected(both()) == 0 && joiner.finish() == 0
        && joiner.continuation(companion(), out, ready) == ERROR_INVALID_DATA, "inline unselected pair allowed redundant companion");
    joiner.reset(PID);
    auto noStack = primary(); noStack.stackCount = 0;
    require(joiner.unselected(noStack) == 0 && joiner.unselected(primary(0)) == 0
        && joiner.finish() == 0, "uncorrelated unselected primary required completion");
    joiner.reset(PID);
    require(joiner.unselected(primary(77, TID + 1)) == 0
        && joiner.primary(primary(), 1, 2, out, ready) == 0
        && joiner.continuation(companion(), out, ready) == 0 && ready
        && out.lifetime == 1 && out.counter == 2, "unselected identity contaminated another TID");
    joiner.reset(PID);
    auto foreign = primary(); ++foreign.pid;
    require(joiner.unselected(foreign) == ERROR_INVALID_DATA, "foreign unselected identity accepted");
    StackJoiner bounded({1, 32 * 1024 * 1024, 1}); bounded.reset(PID);
    require(bounded.unselected(primary()) == 0
        && bounded.continuation(companion(), out, ready) == 0 && !ready
        && bounded.unselected(primary(78)) == ERROR_BUFFER_OVERFLOW
        && bounded.stats().overflows == 1, "unselected identities escaped completed bound");
    StackJoiner sharedBound({1, 32 * 1024 * 1024, 1}); sharedBound.reset(PID);
    require(sharedBound.primary(both(), 1, 2, out, ready) == 0 && ready
        && sharedBound.unselected(primary(78)) == ERROR_BUFFER_OVERFLOW, "selected/unselected completed bound not shared");
    joiner.reset(PID);
    require(joiner.primary(both(), 7, 8, out, ready) == 0 && ready
        && joiner.unselected(primary(78)) == 0 && joiner.finish() == 0
        && out.counter == 8 && out.lifetime == 7 && joiner.stats().joined == 1,
        "unselected observation changed valid output");
}

struct Fixture {
    std::vector<unsigned char> storage;
    std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, 3> items{};
    EVENT_RECORD event{};
    explicit Fixture(bool wow64) : storage(1 + 8 + 2 * (wow64 ? 4 : 8), 0) {
        auto p = storage.data() + 1; // Exercise unaligned source reads.
        std::uint64_t match = 77, first = wow64 ? 0xf1234567 : USER, second = wow64 ? 0x12345678 : USER + 16;
        unsigned width = wow64 ? 4 : 8;
        std::memcpy(p, &match, 8); std::memcpy(p + 8, &first, width); std::memcpy(p + 8 + width, &second, width);
        items[0].ExtType = wow64 ? EVENT_HEADER_EXT_TYPE_STACK_TRACE32 : EVENT_HEADER_EXT_TYPE_STACK_TRACE64;
        items[0].DataSize = static_cast<USHORT>(storage.size() - 1); items[0].DataPtr = reinterpret_cast<uintptr_t>(p);
        items[0].Reserved1 = 0xffff; items[0].Linkage = 1;
        // Irrelevant provider schema, traits and values must never be followed.
        items[1].ExtType = 0x000b; items[1].DataSize = 0xffff; items[1].DataPtr = 1;
        items[2].ExtType = 0x000c; items[2].DataSize = 0xffff; items[2].DataPtr = 1;
        event.EventHeader.Size = sizeof(EVENT_HEADER); event.EventHeader.ProviderId = STACK_CONTINUATION_PROVIDER;
        event.EventHeader.ProcessId = PID; event.EventHeader.ThreadId = TID;
        event.EventHeader.EventDescriptor.Id = 18; event.EventHeader.EventDescriptor.Opcode = 24; event.EventHeader.EventDescriptor.Task = 6;
        event.EventHeader.TimeStamp.QuadPart = 2000; event.EventHeader.ActivityId.Data1 = 0xdeadbeef;
        event.EventHeader.KernelTime = 0xdeadbeef; event.EventHeader.UserTime = 0x12345678;
        event.EventHeader.EventDescriptor.Keyword = UINT64_MAX; event.EventHeader.EventDescriptor.Channel = 17;
        event.BufferContext.ProcessorIndex = 17; event.UserDataLength = 0xffff; event.UserData = reinterpret_cast<void*>(1);
        event.ExtendedDataCount = 3; event.ExtendedData = items.data(); event.UserContext = this;
    }
};
void parserAndSanitizer() {
    Selector selector; selector.provider = PROVIDER; selector.eventId = 123; selector.version = 4;
    Broker::ProviderRequest request; request.provider = PROVIDER; request.eventId = 123; request.version = 4; request.flags = Broker::Stacks;
    for (bool wow64 : {false, true}) {
        Fixture fixture(wow64);
        auto parsed = decode(fixture.event, selector, PID);
        require(parsed.kind == Kind::Continuation && parsed.stackCount == 1 && parsed.schema.empty()
            && parsed.stacks[0].depth == 2 && parsed.stacks[0].matchId == 77
            && parsed.stacks[0].pointerSize == (wow64 ? 4u : 8u), "continuation not recognized before selector filters");
        EVENT_RECORD filtered; bool accepted;
        std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, 2> scratch;
        require(Broker::providerEvent(request, PID, fixture.event, filtered, accepted, &scratch) == 0 && accepted, "valid continuation sanitation");
        EVENT_RECORD expected{};
        expected.EventHeader.Size = sizeof(EVENT_HEADER); expected.EventHeader.Flags = EVENT_HEADER_FLAG_EXTENDED_INFO;
        expected.EventHeader.ProviderId = STACK_CONTINUATION_PROVIDER; expected.EventHeader.ProcessId = PID;
        expected.EventHeader.ThreadId = TID; expected.EventHeader.TimeStamp.QuadPart = 2000;
        expected.EventHeader.EventDescriptor.Id = 18; expected.EventHeader.EventDescriptor.Opcode = 24; expected.EventHeader.EventDescriptor.Task = 6;
        expected.ExtendedData = scratch.data(); expected.ExtendedDataCount = 1;
        require(std::memcmp(&filtered, &expected, sizeof(filtered)) == 0
            && !scratch[0].Reserved1 && !scratch[0].Linkage, "continuation leaked values, context, header metadata or extension flags");
        std::vector<unsigned char> wire;
        Broker::DecodedEvent decoded;
        require(Broker::encodeEvent(filtered, wire) == 0 && Broker::decodeEvent(wire, nullptr, decoded) == 0, "continuation wire round trip");
        auto forwarded = decode(decoded.event, selector, PID);
        require(forwarded.kind == Kind::Continuation && forwarded.stacks[0].addresses == parsed.stacks[0].addresses
            && forwarded.stacks[0].pointerSize == parsed.stacks[0].pointerSize, "broker continuation changed stack data");
        StackJoiner joiner; joiner.reset(PID);
        JoinedStack out; bool ready;
        require(joiner.continuation(std::move(forwarded), out, ready) == 0 && !ready
            && joiner.primary(primary(), 9001, 999, out, ready) == 0 && ready
            && out.counter == 999 && out.lifetime == 9001 && out.record.time == 1000
            && out.record.cpu == 300 && out.record.stacks[1].depth == 2,
            "sanitized/decode/join pipeline lost primary attribution");
        std::memset(fixture.storage.data(), 0, fixture.storage.size());
        require(parsed.stacks[0].addresses[0] == (wow64 ? 0xf1234567 : USER)
            && out.record.stacks[1].addresses[0] == parsed.stacks[0].addresses[0], "decoded continuation borrowed callback storage");
    }
    for (unsigned variant = 0; variant < 20; ++variant) {
        Fixture fixture(false);
        auto& event = fixture.event; auto& item = fixture.items[0];
        ULONG expected = ERROR_INVALID_DATA;
        switch (variant) {
            case 0: event.EventHeader.EventDescriptor.Version = 1; expected = ERROR_NOT_SUPPORTED; break;
            case 1: event.EventHeader.EventDescriptor.Opcode = 25; expected = ERROR_NOT_SUPPORTED; break;
            case 2: event.EventHeader.EventDescriptor.Task = 7; expected = ERROR_NOT_SUPPORTED; break;
            case 3: event.EventHeader.ThreadId = 0; break;
            case 4: event.ExtendedDataCount = 0; break;
            case 5: event.ExtendedData = nullptr; break;
            case 6: fixture.items[1] = item; break;
            case 7: item.DataPtr = 0; break;
            case 8: item.DataSize = 7; break;
            case 9: item.DataSize = 9; break;
            case 10: item.DataSize = 8; break;
            case 11: item.DataSize = 8 + 8 * (MAX_STACK_FRAMES + 1); break;
            case 12: std::memset(fixture.storage.data() + 1, 0, 8); break;
            case 13: std::memset(fixture.storage.data() + 9, 0, 8); break;
            case 14: { auto pc = KERNEL; std::memcpy(fixture.storage.data() + 9, &pc, 8); break; }
            case 15: { std::uint64_t pc = 0x800000000000ULL; std::memcpy(fixture.storage.data() + 9, &pc, 8); break; }
            case 16: event.EventHeader.TimeStamp.QuadPart = 0; break;
            case 17: event.EventHeader.TimeStamp.QuadPart = -1; break;
            case 18: item.ExtType = 0xfffe; item.DataPtr = 1; break;
            case 19: item.DataSize = 8 + 8 * MAX_STACK_FRAMES; fixture.storage.resize(1 + item.DataSize);
                item.DataPtr = reinterpret_cast<uintptr_t>(fixture.storage.data() + 1);
                break; // Trailing zero PCs are invalid, even at the frame cap.
        }
        require(decode(event, selector, PID).kind == Kind::Malformed, "malformed continuation parser acceptance");
        EVENT_RECORD filtered; bool accepted;
        std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, 2> scratch;
        require(Broker::providerEvent(request, PID, event, filtered, accepted, &scratch) == expected && !accepted,
            "malformed continuation sanitizer acceptance");
    }
    for (bool wow64 : {false, true}) {
        Fixture maximum(wow64);
        auto width = wow64 ? 4u : 8u;
        maximum.storage.resize(1 + 8 + width * MAX_STACK_FRAMES);
        auto bytes = maximum.storage.data() + 1;
        for (size_t i = 0; i < MAX_STACK_FRAMES; ++i) {
            std::uint64_t pc = wow64 ? 0xf1234567 : USER;
            std::memcpy(bytes + 8 + i * width, &pc, width);
        }
        maximum.items[0].DataPtr = reinterpret_cast<uintptr_t>(bytes);
        maximum.items[0].DataSize = static_cast<USHORT>(8 + width * MAX_STACK_FRAMES);
        require(decode(maximum.event, selector, PID).kind == Kind::Continuation
            && decode(maximum.event, selector, PID).stacks[0].depth == MAX_STACK_FRAMES, "maximum continuation parser boundary");
        EVENT_RECORD filtered; bool accepted;
        std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, 2> scratch;
        require(Broker::providerEvent(request, PID, maximum.event, filtered, accepted, &scratch) == 0 && accepted,
            "maximum continuation sanitizer boundary");
    }
    Fixture fixture(false);
    EVENT_RECORD filtered; bool accepted;
    std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, 2> scratch;
    fixture.event.EventHeader.ProcessId++;
    fixture.event.ExtendedData = reinterpret_cast<EVENT_HEADER_EXTENDED_DATA_ITEM*>(1);
    require(decode(fixture.event, selector, PID).kind == Kind::Ignore
        && Broker::providerEvent(request, PID, fixture.event, filtered, accepted, &scratch) == 0 && !accepted,
        "foreign continuation reached pointers");
    fixture.event.EventHeader.ProcessId = PID; fixture.event.ExtendedData = fixture.items.data();
    auto disabled = request; disabled.flags = 0;
    require(Broker::providerEvent(disabled, PID, fixture.event, filtered, accepted, &scratch) == 0 && !accepted,
        "stack-disabled continuation forwarded");
    require(Broker::providerEvent(request, PID, fixture.event, filtered, accepted) == ERROR_INVALID_DATA && !accepted,
        "continuation without caller scratch forwarded");
    fixture.event.ExtendedDataCount = Broker::MAX_SOURCE_EXTENSIONS + 1;
    require(Broker::providerEvent(request, PID, fixture.event, filtered, accepted, &scratch) == ERROR_INVALID_DATA && !accepted,
        "source extension cap not enforced before pointer walk");
    fixture.event.ExtendedDataCount = 1;
    fixture.event.EventHeader.ProviderId = PROVIDER; fixture.event.EventHeader.EventDescriptor.Id = 123;
    fixture.event.EventHeader.EventDescriptor.Version = 4;
    require(decode(fixture.event, selector, PID).kind == Kind::Event, "selected primary became bookkeeping by opcode/task alone");
    fixture.event.EventHeader.ProviderId = STACK_CONTINUATION_PROVIDER;
    fixture.event.EventHeader.EventDescriptor.Id = 18; fixture.event.EventHeader.EventDescriptor.Version = 0;
    Selector own; own.provider = STACK_CONTINUATION_PROVIDER; own.eventId = 18;
    require(decode(fixture.event, own, PID).kind == Kind::Continuation, "continuation charged as selected primary");
}
}
int main() {
    arrivalOrders();
    isolationAndAmbiguity();
    rejectedShapes();
    limitsAndStop();
    unselectedPrimaries();
    parserAndSanitizer();
    std::printf("TRACEPOINT_STACK_OK checks=%u arrivalOrders=4 lifetime=1 primaryIdentity=1 ambiguity=1 limits=1 stop=1 unselected=1 provenance=1 sanitizedRoundTrip=1\n", checks);
}
