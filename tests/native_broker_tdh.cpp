/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwBroker.h"
#include <tdh.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string_view>

using namespace WindowsProfiler::Etw::Broker;
static void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
static ULONG eventName(EVENT_RECORD& event, std::wstring_view expected) {
    ULONG size = 0;
    auto status = TdhGetEventInformation(&event, 0, nullptr, nullptr, &size);
    if (status != ERROR_INSUFFICIENT_BUFFER) return status ? status : ERROR_INVALID_DATA;
    std::vector<unsigned char> buffer(size);
    auto info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
    status = TdhGetEventInformation(&event, 0, nullptr, info, &size);
    if (status) return status;
    auto offset = info->ActivityIDNameOffset; // SDK EventNameOffset union alias.
    if (!offset || offset % sizeof(WCHAR) || offset >= size) return ERROR_INVALID_DATA;
    auto name = reinterpret_cast<const WCHAR*>(buffer.data() + offset);
    size_t capacity = (size - offset) / sizeof(WCHAR), length = 0;
    while (length < capacity && name[length]) ++length;
    return length < capacity && std::wstring_view(name, length) == expected ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

int main() {
    // Actual SDK TraceLoggingWrite metadata from the fixed native fixture.
    // TraceLoggingProvider.h documents the provider/event metadata layouts.
    unsigned char schema[]{0x15,0,0,0xe7,0x87,0x83,0xe7,0x83,0xa7,0xf0,0xa0,0xae,0xb7,0,0x49,0x6e,0x64,0x65,0x78,0,7};
    unsigned char traits[]{0x1c,0,'A','s','p','r','o','f','.','T','r','a','c','e','p','o','i','n','t','.','F','i','x','t','u','r','e',0};
    std::uint64_t user[]{0, 0x7ffa12345678, 0x7ffa23456789}, kernel[]{0, 0xfffff80012345678};
    EVENT_HEADER_EXTENDED_DATA_ITEM extensions[4]{};
    extensions[0].ExtType = 0xb; extensions[0].DataSize = sizeof(schema); extensions[0].DataPtr = reinterpret_cast<ULONG_PTR>(schema);
    extensions[1].ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE64; extensions[1].DataSize = sizeof(user); extensions[1].DataPtr = reinterpret_cast<ULONG_PTR>(user);
    extensions[2].ExtType = EVENT_HEADER_EXT_TYPE_STACK_TRACE64; extensions[2].DataSize = sizeof(kernel); extensions[2].DataPtr = reinterpret_cast<ULONG_PTR>(kernel);
    extensions[3].ExtType = 0xc; extensions[3].DataSize = sizeof(traits); extensions[3].DataPtr = reinterpret_cast<ULONG_PTR>(traits);
    int payload = 0x1357acde;
    EVENT_RECORD source{};
    source.EventHeader.Size = sizeof(EVENT_HEADER);
    source.EventHeader.ProviderId = {0x2a94e71b,0x655a,0x4f69,{0x8c,0x64,0x30,0x2d,0x17,0x03,0x2a,0xe9}};
    source.EventHeader.ProcessId = GetCurrentProcessId(); source.EventHeader.ThreadId = GetCurrentThreadId();
    source.EventHeader.EventDescriptor.Channel = 11; source.EventHeader.EventDescriptor.Level = 5;
    source.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER | EVENT_HEADER_FLAG_EXTENDED_INFO;
    source.ExtendedData = extensions; source.ExtendedDataCount = 4;
    source.UserData = &payload; source.UserDataLength = sizeof(payload);
    require(!eventName(source, L"燃烧𠮷"), "Owned SDK event did not expose its exact TDH name");
    ProviderRequest request;
    request.provider = source.EventHeader.ProviderId; request.flags = Named | Stacks;
    EVENT_RECORD projected{}; bool accepted = false;
    require(!providerEvent(request, GetCurrentProcessId(), source, projected, accepted) && accepted, "Provider privacy projection rejected owned event");
    require(!projected.UserDataLength && !projected.UserData, "Primary provider payload was retained");
    require(!eventName(projected, L"燃烧𠮷"), "Stripped payload changed TDH name before encoding");
    std::vector<unsigned char> bytes;
    require(!encodeEvent(projected, bytes), "Production codec rejected valid SDK metadata");
    DecodedEvent decoded;
    require(!decodeEvent(bytes, nullptr, decoded), "Production codec failed to reconstruct SDK event");
    require(decoded.event.ExtendedDataCount == 4 && !decoded.event.UserDataLength && !decoded.event.UserData,
        "Required metadata was lost or payload was restored");
    require(bytes.size() == sizeof(Event) + 4 * sizeof(Extension) + sizeof(schema) + sizeof(traits) + sizeof(user) + sizeof(kernel),
        "Unexpected primary payload bytes in provider packet");
    std::fill(bytes.begin(), bytes.end(), 0);
    auto status = eventName(decoded.event, L"燃烧𠮷");
    if (status) { std::fprintf(stderr, "TDH roundtrip failed Windows=%lu\n", status); return 1; }
    require(!std::memcmp(reinterpret_cast<const void*>(decoded.event.ExtendedData[3].DataPtr), traits, sizeof(traits)),
        "Provider traits did not have receiver-owned lifetime");
    auto missing = projected; missing.ExtendedDataCount = 3;
    require(eventName(missing, L"燃烧𠮷") == ERROR_FILE_CORRUPT, "Missing traits regression no longer detects TDH corruption");
    std::puts("Provider codec TDH Unicode name: PASS payload=0 traits=owned missingTraits=1392");
}
