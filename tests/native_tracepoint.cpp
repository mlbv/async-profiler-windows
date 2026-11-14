/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsTracepoint.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using namespace WindowsProfiler::Tracepoint;
static void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
template<class T> static void put(std::vector<unsigned char>& data, size_t offset, T value) {
    std::memcpy(data.data() + offset, &value, sizeof(value));
}

int main() {
    constexpr auto text = "trace:{8C416C79-D49B-4F01-A467-E56D3AA8234C}/65535/255";
    Selector selector;
    require(!parseSelector(text, selector), "Valid provider/event/version rejected");
    constexpr GUID expected = {0x8c416c79, 0xd49b, 0x4f01, {0xa4,0x67,0xe5,0x6d,0x3a,0xa8,0x23,0x4c}};
    require(IsEqualGUID(selector.provider, expected) && selector.eventId == 65535 && selector.version == 255, "Provider/event/version decoded incorrectly");
    for (const auto* suffix : {"", "/", "65536", "-1", "+1", "0x1", "1/256", "1/-1", "1/2/3", "1x"}) {
        require(parseSelector(std::string("trace:{8c416c79-d49b-4f01-a467-e56d3aa8234c}/") + suffix, selector), "Invalid event selector accepted");
        require(IsEqualGUID(selector.provider, expected) && selector.eventId == 65535 && selector.version == 255, "Failed parse modified active selector");
    }
    for (const auto* invalid : {"trace:1234", "trace:{8c416c79-d49b-4f01-a467-e56d3aa8234g}/1",
            "trace:{8c416c79xd49b-4f01-a467-e56d3aa8234c}/1", "trace:{8c416c79-d49b-4f01-a467-e56d3aa8234c}/"}) {
        require(parseSelector(invalid, selector), "Invalid provider selector accepted");
    }
    require(!parseSelector("trace:{8c416c79-d49b-4f01-a467-e56d3aa8234c}/1", selector) && selector.version == -1, "Default version did not accept all versions");
    EVENT_RECORD event{};
    event.EventHeader.ProviderId = expected;
    event.EventHeader.EventDescriptor.Id = 1;
    event.EventHeader.EventDescriptor.Version = 7;
    event.EventHeader.TimeStamp.QuadPart = 123456789;
    event.EventHeader.ProcessId = 111;
    event.EventHeader.ThreadId = 222;
    event.BufferContext.ProcessorIndex = 300;
    require(decode(event, selector, 111).kind == Kind::Event && !decode(event, selector, 111).stackCount, "Stackless event misclassified");
    event.EventHeader.EventDescriptor.Id = 2;
    require(decode(event, selector, 111).kind == Kind::Ignore, "Foreign event ID accepted");
    event.EventHeader.EventDescriptor.Id = 1;
    ++event.EventHeader.ProviderId.Data1;
    require(decode(event, selector, 111).kind == Kind::Ignore, "Foreign provider accepted");
    event.EventHeader.ProviderId = expected;
    selector.version = 6;
    require(decode(event, selector, 111).kind == Kind::Ignore, "Foreign event version accepted");
    selector.version = -1;
    Selector named;
    require(!parseSelector("trace:{8c416c79-d49b-4f01-a467-e56d3aa8234c}/@燃烧𠮷", named)
            && named.name == "燃烧𠮷", "Unicode event name selector lost identity");
    require(parseSelector("trace:{8c416c79-d49b-4f01-a467-e56d3aa8234c}/@", named), "Empty name selector accepted");
    event.EventHeader.EventDescriptor.Id = 0;
    require(decode(event, named, 111).kind == Kind::Event, "Named selector incorrectly filtered descriptor ID");
    event.EventHeader.EventDescriptor.Id = 1;
    EVENT_HEADER_EXTENDED_DATA_ITEM items[3]{};
    event.ExtendedData = items;
    event.ExtendedDataCount = 1;
    for (bool x64 : {false, true}) {
        size_t width = x64 ? 8 : 4;
        std::vector<unsigned char> bytes(8 + 2 * width);
        put<std::uint64_t>(bytes, 0, 987654321);
        if (x64) {
            put<std::uint64_t>(bytes, 8, 0xfffff80012345678ULL);
            put<std::uint64_t>(bytes, 16, 0x7ffa12345678ULL);
        } else {
            put<ULONG>(bytes, 8, 0x81234567);
            put<ULONG>(bytes, 12, 0x12345678);
        }
        items[0].ExtType = x64 ? EVENT_HEADER_EXT_TYPE_STACK_TRACE64 : EVENT_HEADER_EXT_TYPE_STACK_TRACE32;
        items[0].DataPtr = reinterpret_cast<uintptr_t>(bytes.data());
        items[0].DataSize = static_cast<USHORT>(bytes.size());
        auto decoded = decode(event, selector, 111);
        require(decoded.kind == Kind::Event && decoded.pid == 111 && decoded.tid == 222 && decoded.cpu == 300
                && decoded.time == 123456789 && decoded.stackCount == 1 && decoded.stacks[0].depth == 2, "Event/stack identity lost");
        require(decoded.stacks[0].matchId == 987654321 && decoded.stacks[0].addresses[0] == (x64 ? 0xfffff80012345678ULL : 0x81234567)
                && decoded.stacks[0].addresses[1] == (x64 ? 0x7ffa12345678ULL : 0x12345678), "Stack addresses or match ID corrupted");
        for (USHORT shortSize = 0; shortSize < 8; ++shortSize) {
            items[0].DataSize = shortSize;
            require(decode(event, selector, 111).kind == Kind::Malformed, "Truncated stack header accepted");
        }
        items[0].DataSize = 9;
        require(decode(event, selector, 111).kind == Kind::Malformed, "Misaligned stack accepted");
        items[0].DataSize = static_cast<USHORT>(bytes.size());
        items[1] = items[0];
        event.ExtendedDataCount = 2;
        require(decode(event, selector, 111).kind == Kind::Event && decode(event, selector, 111).stackCount == 2, "Split kernel/user stack rejected");
        items[2] = items[0];
        event.ExtendedDataCount = 3;
        require(decode(event, selector, 111).kind == Kind::Malformed, "Excess stack items silently dropped");
        event.ExtendedDataCount = 1;
        items[0].DataPtr = 0;
        require(decode(event, selector, 111).kind == Kind::Malformed, "Null stack data accepted");
        bytes.resize(8 + MAX_STACK_FRAMES * width);
        items[0].DataPtr = reinterpret_cast<uintptr_t>(bytes.data());
        items[0].DataSize = static_cast<USHORT>(bytes.size());
        require(decode(event, selector, 111).kind == Kind::Event
                && decode(event, selector, 111).stacks[0].depth == MAX_STACK_FRAMES, "Maximum Windows stack rejected");
        bytes.resize(8 + 257 * width);
        items[0].DataPtr = reinterpret_cast<uintptr_t>(bytes.data());
        items[0].DataSize = static_cast<USHORT>(bytes.size());
        require(decode(event, selector, 111).kind == Kind::Malformed, "Oversized stack silently truncated");
    }
    event.EventHeader.ProcessId = 112;
    require(decode(event, selector, 111).kind == Kind::Ignore, "Foreign PID accepted");
    event.EventHeader.ProcessId = 111;
    event.EventHeader.EventDescriptor.Keyword = 0x8000000000000001ULL;
    event.EventHeader.EventDescriptor.Task = 123;
    event.EventHeader.EventDescriptor.Opcode = 4;
    std::vector<unsigned char> schema = {9, 0, 0, 'E', 'v', 'e', 'n', 't', 0};
    items[0].ExtType = 0x000b;
    items[0].DataPtr = reinterpret_cast<uintptr_t>(schema.data());
    items[0].DataSize = static_cast<USHORT>(schema.size());
    auto traced = decode(event, selector, 111);
    require(traced.kind == Kind::Event && IsEqualGUID(traced.provider, expected) && traced.schema == schema
            && traced.descriptor.Id == 1 && traced.descriptor.Version == 7 && traced.descriptor.Task == 123
            && traced.descriptor.Opcode == 4 && traced.descriptor.Keyword == 0x8000000000000001ULL, "Manifest or TraceLogging event identity lost");
    schema[3] = 'X';
    require(traced.schema[3] == 'E', "TraceLogging schema borrowed beyond callback lifetime");
    items[1] = items[0];
    event.ExtendedDataCount = 2;
    require(decode(event, selector, 111).kind == Kind::Malformed, "Duplicate TraceLogging schema accepted");
    event.ExtendedDataCount = 1;
    items[0].DataSize = 1;
    require(decode(event, selector, 111).kind == Kind::Malformed, "Truncated TraceLogging schema accepted");
    event.ExtendedData = nullptr;
    require(decode(event, selector, 111).kind == Kind::Malformed, "Missing extended data accepted");
    std::puts("Windows tracepoint selectors and extended stacks: PASS");
}
