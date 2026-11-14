/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwBroker.h"
#include <array>
#include <cstring>
#include <limits>

namespace WindowsProfiler::Etw::Broker {
namespace {
constexpr USHORT schemaType = 0x000b;
constexpr USHORT traitsType = 0x000c;
bool supported(USHORT type) {
    return type == EVENT_HEADER_EXT_TYPE_STACK_TRACE32 || type == EVENT_HEADER_EXT_TYPE_STACK_TRACE64
        || type == schemaType || type == traitsType;
}
bool shape(USHORT type, ULONG size) {
    if (!supported(type) || size > std::numeric_limits<USHORT>::max()) return false;
    if (type == schemaType) return size >= sizeof(USHORT);
    if (type == traitsType) return size >= sizeof(USHORT) + 1;
    auto width = type == EVENT_HEADER_EXT_TYPE_STACK_TRACE64 ? 8u : 4u;
    return size >= 8 && (size - 8) % width == 0 && (size - 8) / width <= 256;
}
ULONG providerTraits(const unsigned char* bytes, ULONG size) {
    // https://learn.microsoft.com/windows/win32/etw/provider-traits
    // UINT16 total, UTF-8 name/NUL, then UINT16 size/UINT8 type/data.
    USHORT declared; std::memcpy(&declared, bytes, sizeof(declared));
    if (declared != size) return ERROR_INVALID_DATA;
    size_t end = sizeof(USHORT);
    while (end < size && bytes[end]) ++end;
    if (end == size) return ERROR_INVALID_DATA;
    auto nameSize = static_cast<int>(end - sizeof(USHORT));
    if (nameSize && !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            reinterpret_cast<const char*>(bytes + sizeof(USHORT)), nameSize, nullptr, 0)) return ERROR_INVALID_DATA;
    size_t offset = end + 1;
    bool group = false, decode = false;
    while (offset < size) {
        if (size - offset < 3) return ERROR_INVALID_DATA;
        USHORT length; std::memcpy(&length, bytes + offset, sizeof(length));
        if (length < 3 || length > size - offset) return ERROR_INVALID_DATA;
        auto type = bytes[offset + 2];
        // SDK ETW_PROVIDER_TRAIT_TYPE: Group=1, DecodeGuid=2. Both
        // contain exactly one GUID; custom/future trait bytes stay private.
        if (type != 1 && type != 2) return ERROR_NOT_SUPPORTED;
        if (length != 3 + sizeof(GUID)) return ERROR_INVALID_DATA;
        bool& present = type == 1 ? group : decode;
        if (present) return ERROR_INVALID_DATA;
        present = true; offset += length;
    }
    return ERROR_SUCCESS;
}
}
ULONG encodeEvent(const EVENT_RECORD& event, std::vector<unsigned char>& bytes) try {
    if ((event.UserDataLength && !event.UserData) || event.ExtendedDataCount > MAX_SOURCE_EXTENSIONS
            || (event.ExtendedDataCount && !event.ExtendedData)) return ERROR_INVALID_DATA;
    std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, MAX_RETAINED_EXTENSIONS> selected{};
    ULONG count = 0, extended = 0, stacks = 0, schemas = 0, traits = 0;
    for (USHORT index = 0; index < event.ExtendedDataCount; ++index) {
        auto& item = event.ExtendedData[index];
        if (!supported(item.ExtType)) continue;
        if (!item.DataPtr || !shape(item.ExtType, item.DataSize)) return ERROR_INVALID_DATA;
        if (item.ExtType == schemaType) { if (++schemas > 1) return ERROR_INVALID_DATA; }
        else if (item.ExtType == traitsType) {
            if (++traits > 1) return ERROR_INVALID_DATA;
            auto error = providerTraits(reinterpret_cast<const unsigned char*>(static_cast<std::uintptr_t>(item.DataPtr)), item.DataSize);
            if (error) return error;
        }
        else if (++stacks > 2) return ERROR_INVALID_DATA;
        if (count == selected.size() || item.DataSize > MAX_EXTENDED_BYTES - extended) return ERROR_INVALID_DATA;
        selected[count++] = item; extended += item.DataSize;
    }
    size_t size = sizeof(Event) + count * sizeof(Extension) + event.UserDataLength + extended;
    if (size > MAX_EVENT_PACKET) return ERROR_INVALID_DATA;
    bytes.assign(size, 0);
    Event header{event.EventHeader, event.BufferContext, event.UserDataLength, count, extended};
    if (count) header.header.Flags |= EVENT_HEADER_FLAG_EXTENDED_INFO;
    else header.header.Flags &= ~EVENT_HEADER_FLAG_EXTENDED_INFO;
    std::memcpy(bytes.data(), &header, sizeof(header));
    size_t user = sizeof(Event) + count * sizeof(Extension);
    if (event.UserDataLength) std::memcpy(bytes.data() + user, event.UserData, event.UserDataLength);
    size_t offset = user + event.UserDataLength;
    for (ULONG index = 0; index < count; ++index) {
        const auto& item = selected[index];
        Extension descriptor{item.ExtType, static_cast<USHORT>(item.Linkage), item.DataSize};
        std::memcpy(bytes.data() + sizeof(Event) + index * sizeof(Extension), &descriptor, sizeof(descriptor));
        std::memcpy(bytes.data() + offset, reinterpret_cast<const void*>(static_cast<std::uintptr_t>(item.DataPtr)), item.DataSize);
        offset += item.DataSize;
    }
    return ERROR_SUCCESS;
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }

ULONG decodeEvent(std::vector<unsigned char>& bytes, void* context, DecodedEvent& decoded) try {
    if (bytes.size() < sizeof(Event) || bytes.size() > MAX_EVENT_PACKET) return ERROR_INVALID_DATA;
    Event header;
    std::memcpy(&header, bytes.data(), sizeof(header));
    if (header.length > std::numeric_limits<USHORT>::max() || header.extendedCount > MAX_RETAINED_EXTENSIONS || header.extendedBytes > MAX_EXTENDED_BYTES) return ERROR_INVALID_DATA;
    if (((header.header.Flags & EVENT_HEADER_FLAG_EXTENDED_INFO) != 0) != (header.extendedCount != 0)) return ERROR_INVALID_DATA;
    size_t remaining = bytes.size() - sizeof(Event);
    if (header.extendedCount > remaining / sizeof(Extension)) return ERROR_INVALID_DATA;
    size_t descriptors = header.extendedCount * sizeof(Extension);
    remaining -= descriptors;
    if (header.length > remaining) return ERROR_INVALID_DATA;
    remaining -= header.length;
    if (remaining != header.extendedBytes) return ERROR_INVALID_DATA;
    std::array<Extension, MAX_RETAINED_EXTENSIONS> extensions{};
    size_t words = 0;
    size_t payload = sizeof(Event) + descriptors + header.length;
    ULONG stacks = 0, schemas = 0, traits = 0;
    for (ULONG index = 0; index < header.extendedCount; ++index) {
        auto& item = extensions[index];
        std::memcpy(&item, bytes.data() + sizeof(Event) + index * sizeof(Extension), sizeof(item));
        if (item.linkage > 1 || !shape(item.type, item.size) || item.size > remaining) return ERROR_INVALID_DATA;
        if (item.type == schemaType) { if (++schemas > 1) return ERROR_INVALID_DATA; }
        else if (item.type == traitsType) {
            if (++traits > 1) return ERROR_INVALID_DATA;
            auto error = providerTraits(bytes.data() + payload, item.size);
            if (error) return error;
        }
        else if (++stacks > 2) return ERROR_INVALID_DATA;
        remaining -= item.size;
        payload += item.size;
        words += (item.size + 7) / 8;
    }
    if (remaining) return ERROR_INVALID_DATA;
    decoded.extensions.assign(header.extendedCount, {});
    decoded.storage.assign(words, 0);
    decoded.event = {};
    decoded.event.EventHeader = header.header; decoded.event.BufferContext = header.context; decoded.event.UserContext = context;
    size_t offset = sizeof(Event) + descriptors;
    decoded.event.UserDataLength = static_cast<USHORT>(header.length);
    decoded.event.UserData = header.length ? bytes.data() + offset : nullptr;
    offset += header.length;
    size_t word = 0;
    for (ULONG index = 0; index < header.extendedCount; ++index) {
        auto& source = extensions[index]; auto& item = decoded.extensions[index];
        item.ExtType = source.type; item.Linkage = source.linkage; item.DataSize = static_cast<USHORT>(source.size);
        item.DataPtr = reinterpret_cast<std::uintptr_t>(decoded.storage.data() + word);
        std::memcpy(decoded.storage.data() + word, bytes.data() + offset, source.size);
        word += (source.size + 7) / 8; offset += source.size;
    }
    decoded.event.ExtendedDataCount = static_cast<USHORT>(header.extendedCount);
    decoded.event.ExtendedData = decoded.extensions.empty() ? nullptr : decoded.extensions.data();
    return ERROR_SUCCESS;
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
}
