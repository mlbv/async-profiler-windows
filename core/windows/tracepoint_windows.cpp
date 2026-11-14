/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsTracepoint.h"
#include <charconv>

namespace WindowsProfiler::Tracepoint {
namespace {
bool number(std::string_view text, unsigned maximum, unsigned& value, int base = 10) {
    if (text.empty()) return false;
    auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    return parsed.ec == std::errc() && parsed.ptr == text.data() + text.size() && value <= maximum;
}
}

const char* parseSelector(std::string_view text, Selector& selector) {
    constexpr std::string_view prefix = "trace:{";
    if (!text.starts_with(prefix)) return "Windows tracepoints require trace:{provider-guid}/event-id[/version]";
    text.remove_prefix(prefix.size());
    if (text.size() < 38 || text[36] != '}' || text[37] != '/') return "Invalid Windows tracepoint provider GUID";
    auto guid = text.substr(0, 36);
    if (guid[8] != '-' || guid[13] != '-' || guid[18] != '-' || guid[23] != '-') return "Invalid Windows tracepoint provider GUID";
    Selector parsed;
    unsigned value;
    if (!number(guid.substr(0, 8), UINT32_MAX, value, 16)) return "Invalid Windows tracepoint provider GUID";
    parsed.provider.Data1 = value;
    if (!number(guid.substr(9, 4), UINT16_MAX, value, 16)) return "Invalid Windows tracepoint provider GUID";
    parsed.provider.Data2 = static_cast<USHORT>(value);
    if (!number(guid.substr(14, 4), UINT16_MAX, value, 16)) return "Invalid Windows tracepoint provider GUID";
    parsed.provider.Data3 = static_cast<USHORT>(value);
    constexpr size_t offsets[] = {19, 21, 24, 26, 28, 30, 32, 34};
    for (size_t i = 0; i < std::size(offsets); ++i) {
        if (!number(guid.substr(offsets[i], 2), UINT8_MAX, value, 16)) return "Invalid Windows tracepoint provider GUID";
        parsed.provider.Data4[i] = static_cast<UCHAR>(value);
    }
    text.remove_prefix(38);
    if (text.starts_with('@')) {
        if (text.size() == 1 || text.find('\0') != std::string_view::npos) return "Invalid Windows tracepoint event name";
        parsed.name.assign(text.substr(1));
        selector = std::move(parsed);
        return nullptr;
    }
    auto slash = text.find('/');
    if (!number(text.substr(0, slash), UINT16_MAX, value)) return "Invalid Windows tracepoint event ID";
    parsed.eventId = static_cast<USHORT>(value);
    if (slash != std::string_view::npos) {
        if (!number(text.substr(slash + 1), UINT8_MAX, value)) return "Invalid Windows tracepoint event version";
        parsed.version = static_cast<int>(value);
    }
    selector = parsed;
    return nullptr;
}

Record decode(const EVENT_RECORD& event, const Selector& selector, ULONG targetPid) {
    Record result;
    if (event.EventHeader.ProcessId != targetPid) return result;
    bool continuation = IsEqualGUID(event.EventHeader.ProviderId, STACK_CONTINUATION_PROVIDER)
        && event.EventHeader.EventDescriptor.Id == 18;
    if (!continuation && (!IsEqualGUID(event.EventHeader.ProviderId, selector.provider)
            || (selector.name.empty() && event.EventHeader.EventDescriptor.Id != selector.eventId)
            || (selector.version >= 0 && event.EventHeader.EventDescriptor.Version != selector.version))) return result;
    result.kind = Kind::Malformed;
    if (continuation && (!continuationDescriptor(event.EventHeader.ProviderId, event.EventHeader.EventDescriptor)
            || !event.EventHeader.ThreadId || event.EventHeader.TimeStamp.QuadPart <= 0)) return result;
    if (event.ExtendedDataCount && !event.ExtendedData) return result;
    result.provider = event.EventHeader.ProviderId;
    result.descriptor = event.EventHeader.EventDescriptor;
    result.time = event.EventHeader.TimeStamp.QuadPart;
    result.pid = event.EventHeader.ProcessId;
    result.tid = event.EventHeader.ThreadId;
    result.cpu = event.BufferContext.ProcessorIndex;
    for (USHORT i = 0; i < event.ExtendedDataCount; ++i) {
        const auto& item = event.ExtendedData[i];
        // EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL (Windows SDK / PerfView).
        // Some MinGW headers predate the named constant.
        if (!continuation && item.ExtType == 0x000b) {
            if (!result.schema.empty() || !item.DataPtr || item.DataSize < sizeof(USHORT)) return result;
            auto bytes = reinterpret_cast<const unsigned char*>(static_cast<uintptr_t>(item.DataPtr));
            result.schema.assign(bytes, bytes + item.DataSize);
            continue;
        }
        if (item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64 && item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE32) continue;
        if (result.stackCount == result.stacks.size() || !decodeStack(item, result.stacks[result.stackCount])) return result;
        ++result.stackCount;
    }
    if (continuation && (result.stackCount != 1 || !result.stacks[0].matchId
            || stackDomain(result.stacks[0]) != StackDomain::User)) return result;
    result.kind = continuation ? Kind::Continuation : Kind::Event;
    return result;
}
}
