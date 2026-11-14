/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwBroker.h"
#include "windowsTracepointSession.h"
#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>

using namespace WindowsProfiler::Etw::Broker;
namespace {
void require(bool condition, const char* text) { if (!condition) throw std::runtime_error(text); }
template<class T> void set(std::vector<unsigned char>& data, size_t offset, const T& value) { std::memcpy(data.data() + offset, &value, sizeof(value)); }
}
int main() try {
    struct Stack64 { std::uint64_t match, first, second; } stack64{1234, 0x1122334455667788, 0x8877665544332211};
    struct Stack32 { std::uint64_t match; ULONG first, second; } stack32{1234, 0x12345678, 0x87654321};
    unsigned char schema[] = {6, 0, 'n', 'a', 'm', 'e'};
    unsigned char traits[] = {0x1c,0,'A','s','p','r','o','f','.','T','r','a','c','e','p','o','i','n','t','.','F','i','x','t','u','r','e',0};
    std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, 5> extensions{};
    extensions[0].ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE64; extensions[0].DataSize = sizeof(stack64); extensions[0].DataPtr = reinterpret_cast<std::uintptr_t>(&stack64);
    extensions[1].ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE32; extensions[1].DataSize = sizeof(stack32); extensions[1].DataPtr = reinterpret_cast<std::uintptr_t>(&stack32);
    extensions[2].ExtType = 0x000b; extensions[2].DataSize = sizeof(schema); extensions[2].DataPtr = reinterpret_cast<std::uintptr_t>(schema);
    // Unknown pointers must not be dereferenced or transmitted.
    extensions[3].ExtType = 0x000c; extensions[3].DataSize = sizeof(traits); extensions[3].DataPtr = reinterpret_cast<std::uintptr_t>(traits);
    extensions[4].ExtType = 0xfffe; extensions[4].DataSize = 65535; extensions[4].DataPtr = 1;
    ULONG values[] = {123, 456, 789};
    EVENT_RECORD source{};
    source.EventHeader.Size = sizeof(EVENT_HEADER); source.EventHeader.ProcessId = 123;
    source.EventHeader.EventDescriptor.Id = 9; source.EventHeader.EventDescriptor.Version = 7;
    source.EventHeader.TimeStamp.QuadPart = 987654; source.BufferContext.ProcessorIndex = 17;
    source.UserData = values; source.UserDataLength = sizeof(values);
    source.ExtendedData = extensions.data(); source.ExtendedDataCount = extensions.size();
    std::vector<unsigned char> wire;
    require(encodeEvent(source, wire) == 0, "encode supported extension set");
    DecodedEvent decoded;
    require(decodeEvent(wire, &source, decoded) == 0, "decode supported extension set");
    require(decoded.event.UserContext == &source && decoded.event.EventHeader.ProcessId == 123
        && decoded.event.EventHeader.EventDescriptor.Version == 7 && decoded.event.BufferContext.ProcessorIndex == 17, "header/context identity");
    require(decoded.event.ExtendedDataCount == 4 && (decoded.event.EventHeader.Flags & EVENT_HEADER_FLAG_EXTENDED_INFO), "known extensions only");
    for (size_t index = 0; index < 4; ++index) {
        auto& item = decoded.event.ExtendedData[index];
        auto first = reinterpret_cast<std::uintptr_t>(decoded.storage.data());
        require(item.DataPtr >= first && item.DataPtr - first <= decoded.storage.size() * 8 - item.DataSize
            && item.DataPtr % 8 == 0 && item.DataPtr != extensions[index].DataPtr, "aligned receiver-owned extension");
    }
    require(std::memcmp(reinterpret_cast<const void*>(decoded.extensions[0].DataPtr), &stack64, sizeof(stack64)) == 0, "stack64 match ID and PCs");
    require(std::memcmp(reinterpret_cast<const void*>(decoded.extensions[1].DataPtr), &stack32, sizeof(stack32)) == 0, "stack32 match ID and PCs");
    require(std::memcmp(reinterpret_cast<const void*>(decoded.extensions[2].DataPtr), schema, sizeof(schema)) == 0, "schema exact bytes");
    require(std::memcmp(reinterpret_cast<const void*>(decoded.extensions[3].DataPtr), traits, sizeof(traits)) == 0, "provider traits exact bytes");
    traits[0] = 27;
    require(encodeEvent(source, wire) == ERROR_INVALID_DATA, "traits total length mismatch");
    traits[0] = sizeof(traits); traits[2] = 0xc0; traits[3] = 0x80;
    require(encodeEvent(source, wire) == ERROR_INVALID_DATA, "traits invalid UTF-8");
    traits[2] = 'A'; traits[3] = 's'; traits[sizeof(traits) - 1] = 'x';
    require(encodeEvent(source, wire) == ERROR_INVALID_DATA, "traits missing name terminator");
    traits[sizeof(traits) - 1] = 0;
    std::vector<unsigned char> chunked(traits, traits + sizeof(traits));
    for (UCHAR type : {1, 2}) {
        chunked.push_back(19); chunked.push_back(0); chunked.push_back(type);
        chunked.insert(chunked.end(), sizeof(GUID), type);
    }
    chunked[0] = static_cast<unsigned char>(chunked.size());
    extensions[3].DataPtr = reinterpret_cast<std::uintptr_t>(chunked.data()); extensions[3].DataSize = static_cast<USHORT>(chunked.size());
    require(encodeEvent(source, wire) == 0 && decodeEvent(wire, nullptr, decoded) == 0, "known GUID traits");
    chunked[sizeof(traits) + 2] = 128;
    require(encodeEvent(source, wire) == ERROR_NOT_SUPPORTED, "custom trait payload rejected");
    chunked[sizeof(traits) + 2] = 1; chunked[sizeof(traits)] = 18;
    require(encodeEvent(source, wire) == ERROR_INVALID_DATA, "GUID trait exact size");
    extensions[3].DataPtr = reinterpret_cast<std::uintptr_t>(traits); extensions[3].DataSize = sizeof(traits);
    require(encodeEvent(source, wire) == 0, "restore traits");
    auto malformed = wire;
    Event header; std::memcpy(&header, wire.data(), sizeof(header));
    auto saved = header;
    header.length = 0xffffffff; set(malformed, 0, header);
    require(decodeEvent(malformed, nullptr, decoded) == ERROR_INVALID_DATA, "user length overflow");
    malformed = wire; header = saved; header.extendedCount = 0xffffffff; set(malformed, 0, header);
    require(decodeEvent(malformed, nullptr, decoded) == ERROR_INVALID_DATA, "extension count overflow");
    malformed = wire; Extension bad{EVENT_HEADER_EXT_TYPE_STACK_TRACE64, 0, 0xffffffff}; set(malformed, sizeof(Event), bad);
    require(decodeEvent(malformed, nullptr, decoded) == ERROR_INVALID_DATA, "extension size overflow");
    malformed = wire; malformed.push_back(0);
    require(decodeEvent(malformed, nullptr, decoded) == ERROR_INVALID_DATA, "trailing bytes");
    source.ExtendedDataCount = 65;
    require(encodeEvent(source, malformed) == ERROR_INVALID_DATA, "source count before pointer walk");
    source.ExtendedDataCount = 1; source.ExtendedData = &extensions[4]; source.EventHeader.Flags |= EVENT_HEADER_FLAG_EXTENDED_INFO;
    require(encodeEvent(source, malformed) == 0 && decodeEvent(malformed, nullptr, decoded) == 0
        && decoded.event.ExtendedDataCount == 0 && !(decoded.event.EventHeader.Flags & EVENT_HEADER_FLAG_EXTENDED_INFO), "dropped extensions normalize flag");

    ProviderRequest request; request.provider.Data1 = 42; request.eventId = 9; request.version = 7;
    source.EventHeader.ProviderId = request.provider; source.ExtendedData = extensions.data(); source.ExtendedDataCount = 4;
    EVENT_RECORD filtered; bool accepted;
    require(providerEvent(request, 123, source, filtered, accepted) == 0 && accepted && filtered.UserDataLength == 0 && !filtered.UserData, "strip own primary values");
    source.EventHeader.ProcessId = 124;
    require(providerEvent(request, 123, source, filtered, accepted) == 0 && !accepted, "reject foreign primary");
    request.flags = Named; request.eventId = 0; request.version = -1;
    source.EventHeader.ProcessId = 123; source.EventHeader.EventDescriptor.Id = 999;
    require(providerEvent(request, 123, source, filtered, accepted) == 0 && accepted, "named selection forwards any own ID");
    source.EventHeader.ProviderId = WindowsProfiler::Tracepoint::KERNEL_PROCESS_PROVIDER;
    source.EventHeader.ProcessId = 4; source.EventHeader.EventDescriptor.Id = 3; source.EventHeader.EventDescriptor.Version = 1;
    require(providerEvent(request, 123, source, filtered, accepted) == 0 && accepted && filtered.UserDataLength == 8
        && filtered.EventHeader.ProcessId == 0 && filtered.EventHeader.ThreadId == 0 && !filtered.ExtendedDataCount, "sanitize system lifecycle");
    source.EventHeader.ProcessId = 55;
    require(providerEvent(request, 123, source, filtered, accepted) == ERROR_NOT_SUPPORTED, "reject untrusted foreign lifecycle origin");
    source.EventHeader.ProcessId = 4; values[0] = 124;
    require(providerEvent(request, 123, source, filtered, accepted) == 0 && !accepted, "reject foreign lifecycle payload");
    std::puts("BROKER_CODEC_OK ownedPointers=1 bounded=1 payloadStripped=1 lifecycleSanitized=1 foreignRejected=1");
    return 0;
} catch (const std::exception& error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
