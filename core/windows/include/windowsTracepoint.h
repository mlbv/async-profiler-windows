/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <evntcons.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace WindowsProfiler::Tracepoint {
struct Selector {
    GUID provider{};
    USHORT eventId = 0;
    int version = -1;
    std::string name;
};

// Windows event IDs belong to a provider. Linux tracefs numeric IDs do not
// identify Windows events: trace:{provider-guid}/event-id[/version], or
// trace:{provider-guid}/@event-name with TDH metadata-based name matching.
const char* parseSelector(std::string_view text, Selector& selector);

constexpr size_t MAX_STACK_FRAMES = 256;
inline constexpr GUID STACK_CONTINUATION_PROVIDER = {0xb675ec37, 0xbdb6, 0x4648,
    {0xbc, 0x92, 0xf3, 0xfd, 0xc7, 0x4d, 0x3c, 0xa2}};
struct Stack {
    std::uint64_t matchId = 0;
    unsigned pointerSize = 0;
    size_t depth = 0;
    std::array<std::uint64_t, MAX_STACK_FRAMES> addresses{};
};
inline bool continuationDescriptor(const GUID& provider, const EVENT_DESCRIPTOR& descriptor) {
    return IsEqualGUID(provider, STACK_CONTINUATION_PROVIDER) && descriptor.Id == 18
        && descriptor.Version == 0 && descriptor.Opcode == 24 && descriptor.Task == 6;
}

enum class StackDomain { Empty, User, Kernel, Mixed, Invalid };
inline StackDomain stackDomain(const Stack& stack) {
    if (stack.depth > MAX_STACK_FRAMES || (stack.pointerSize != 4 && stack.pointerSize != 8)) return StackDomain::Invalid;
    if (!stack.depth) return StackDomain::Empty;
    bool user = false, kernel = false;
    for (size_t i = 0; i < stack.depth; ++i) {
        auto pc = stack.addresses[i];
        if (!pc || (stack.pointerSize == 4 && pc > UINT32_MAX)) return StackDomain::Invalid;
        // On this x86-64 port a 32-bit stack contains WOW64 user addresses.
        if (stack.pointerSize == 8 && pc >= 0xffff800000000000ULL) kernel = true;
        else if (pc < 0x800000000000ULL) user = true;
        else return StackDomain::Invalid;
    }
    return user && kernel ? StackDomain::Mixed : kernel ? StackDomain::Kernel : StackDomain::User;
}

// Copies stack data while the EVENT_RECORD's extended-data storage is alive.
inline bool decodeStack(const EVENT_HEADER_EXTENDED_DATA_ITEM& item, Stack& stack) {
    unsigned width = item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 ? 8
        : item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 ? 4 : 0;
    if (!width || !item.DataPtr || item.DataSize < 8 || (item.DataSize - 8) % width
            || (item.DataSize - 8) / width > MAX_STACK_FRAMES) return false;
    stack.pointerSize = width;
    stack.depth = (item.DataSize - 8) / width;
    auto bytes = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(item.DataPtr));
    std::memcpy(&stack.matchId, bytes, sizeof(stack.matchId));
    for (size_t i = 0; i < stack.depth; ++i) {
        stack.addresses[i] = 0;
        std::memcpy(&stack.addresses[i], bytes + 8 + i * width, width);
    }
    return true;
}
enum class Kind { Ignore, Event, Continuation, Malformed };
struct Record {
    Kind kind = Kind::Ignore;
    GUID provider{};
    EVENT_DESCRIPTOR descriptor{};
    // TraceLogging event IDs alone do not identify an event. Preserve its
    // inline schema bytes, which include its name, for identity and TDH.
    std::vector<unsigned char> schema;
    std::uint64_t time = 0;
    ULONG pid = 0, tid = 0;
    USHORT cpu = 0;
    size_t stackCount = 0;
    // ETW may provide kernel and user traces separately. MatchId must be
    // retained until the consumer has joined both halves; it is not a PC.
    std::array<Stack, 2> stacks{};
};

// Reads EVENT_ENABLE_PROPERTY_STACK_TRACE extended data, independent of
// provider payload layouts and TDH. Nonzero MatchId remains explicit.
// The header PID is mandatory: matching a provider does not authorize
// accepting unrelated processes. Providers that attribute work through a
// payload PID need a separate, explicitly decoded attribution contract.
Record decode(const EVENT_RECORD& event, const Selector& selector, ULONG targetPid);
}
