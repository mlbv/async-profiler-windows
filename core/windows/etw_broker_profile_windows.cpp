/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwBroker.h"
#include <cstring>

namespace WindowsProfiler::Etw::Broker {
namespace {
constexpr GUID perfInfo = {0xce1dbfb4,0x137e,0x4da6,{0x87,0xb0,0x3f,0x59,0xaa,0x10,0x2c,0xbc}};
constexpr GUID stackWalk = {0xdef2fe46,0x7bd6,0x4b80,{0xbd,0x94,0xf5,0x7f,0xe2,0x0d,0x0c,0xe3}};
constexpr GUID threads = {0x3d6fa8d1,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
constexpr GUID image = {0x2cb15d1d,0x5fc1,0x11d2,{0xab,0xe1,0x00,0xa0,0xc9,0x11,0xf5,0x18}};
template<class T> T read(const unsigned char* value) { T result; std::memcpy(&result,value,sizeof(result)); return result; }
}
ULONG validateRequest(const Request& request) {
    if (request.stacks > 1 || request.images > 1 || request.explicitInterval > 1 || request.raw > 1 || !request.interval)
        return ERROR_INVALID_PARAMETER;
    auto software = static_cast<SoftwareKind>(request.software);
    if (software != SoftwareKind::None && software != SoftwareKind::PageFaults && software != SoftwareKind::ContextSwitches)
        return ERROR_INVALID_PARAMETER;
    if (software != SoftwareKind::None && (request.source || request.raw || request.rawConfig.config
            || request.rawConfig.family || request.rawConfig.model || request.rawConfig.stepping || request.rawConfig.vendor))
        return ERROR_INVALID_PARAMETER;
    return ERROR_SUCCESS;
}
ULONG profileEvent(ULONG targetPid, bool images, const EVENT_RECORD& source, ProfileView& output, SoftwareKind software) {
    output = {};
    auto& header = source.EventHeader;
    auto provider = header.ProviderId; auto opcode = header.EventDescriptor.Opcode;
    auto data = static_cast<const unsigned char*>(source.UserData); auto length = source.UserDataLength;
    size_t width = header.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
    auto& event = output.event;
    event.EventHeader.Size = sizeof(EVENT_HEADER);
    event.EventHeader.ProviderId = provider;
    event.EventHeader.EventDescriptor.Opcode = opcode;
    event.EventHeader.EventDescriptor.Version = header.EventDescriptor.Version;
    event.EventHeader.TimeStamp = header.TimeStamp;
    event.EventHeader.Flags = width == 4 ? EVENT_HEADER_FLAG_32_BIT_HEADER : EVENT_HEADER_FLAG_64_BIT_HEADER;
    output.time = header.TimeStamp.QuadPart;
    if (software != SoftwareKind::None) {
        auto record = decodeSoftware(software, source);
        if (record.kind != SoftwareRecordKind::Ignore) {
            // An explicit foreign fault cannot authorize forwarding its payload,
            // even when the target currently owns the same numeric TID.
            if (record.kind == SoftwareRecordKind::Sample && record.pid != targetPid) {
                output.kind = ProfileKind::ForeignSample; return ERROR_SUCCESS;
            }
            if (record.kind == SoftwareRecordKind::Malformed || record.kind == SoftwareRecordKind::Unsupported) {
                output.unsupportedFormat = (3u << 24) | (static_cast<ULONG>(header.EventDescriptor.Version) << 16)
                    | (static_cast<ULONG>(opcode) << 8) | static_cast<ULONG>(width);
                return record.kind == SoftwareRecordKind::Unsupported ? ERROR_NOT_SUPPORTED : ERROR_INVALID_DATA;
            }
            output.pid = record.pid; output.tid = record.tid;
            if (record.kind == SoftwareRecordKind::Switch) {
                // The router synthesizes ProvenSwitch records; no switch payload is forwarded.
                output.kind = ProfileKind::Switch; output.incomingTid = record.incomingTid;
                output.cpu = record.cpu; output.terminated = record.terminated;
                return ERROR_SUCCESS;
            }
            if (record.kind == SoftwareRecordKind::Sample) {
                output.kind = ProfileKind::Sample;
                event.EventHeader.ProcessId = record.pid;
                event.EventHeader.ThreadId = record.tid;
                event.BufferContext.ProcessorIndex = record.cpu;
                // Fault VA is private data, not the instruction pointer.
                std::memcpy(output.metadata.data() + width, data + width, width);
                event.UserDataLength = static_cast<USHORT>(2 * width);
            } else {
                output.kind = ProfileKind::Thread;
                if (record.pid != targetPid) return ERROR_SUCCESS;
                ULONG identity[] = {record.pid, record.tid};
                std::memcpy(output.metadata.data(), identity, sizeof(identity));
                event.EventHeader.EventDescriptor.Version = 2;
                event.UserDataLength = sizeof(identity);
            }
            event.UserData = output.metadata.data();
            event.EventHeader.Size += event.UserDataLength;
            return ERROR_SUCCESS;
        }
        // Software modes must never admit timer/PMC samples.
        if (IsEqualGUID(provider, perfInfo)) return ERROR_SUCCESS;
    }
    if (IsEqualGUID(provider, perfInfo) && (opcode == 46 || opcode == 47)) {
        if (header.ProcessId != targetPid && header.ProcessId != ULONG(-1)) { output.kind = ProfileKind::ForeignSample; return ERROR_SUCCESS; }
        if (!data || length < width + 8) {
            if (header.ProcessId == targetPid) return ERROR_INVALID_DATA;
            output.kind = ProfileKind::UnattributedSample; return ERROR_SUCCESS;
        }
        output.kind = header.ProcessId == targetPid ? ProfileKind::Sample : ProfileKind::UnknownSample;
        output.pid = header.ProcessId; output.tid = read<ULONG>(data + width);
        event.EventHeader.ProcessId = header.ProcessId;
        event.BufferContext.ProcessorIndex = source.BufferContext.ProcessorIndex;
        event.UserData = source.UserData; event.UserDataLength = static_cast<USHORT>(width + 8);
    } else if (IsEqualGUID(provider, stackWalk) && opcode == 32) {
        if (software != SoftwareKind::None) {
            auto flags = header.Flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER);
            if (header.EventDescriptor.Version != 2 || (flags != EVENT_HEADER_FLAG_32_BIT_HEADER && flags != EVENT_HEADER_FLAG_64_BIT_HEADER))
                return ERROR_NOT_SUPPORTED;
            if (!data || length < 16 || (length - 16) % width || (length - 16) / width > 256) return ERROR_INVALID_DATA;
        }
        if (!data || length < 16) return ERROR_SUCCESS;
        output.time = read<std::uint64_t>(data); output.pid = read<ULONG>(data + 8); output.tid = read<ULONG>(data + 12);
        output.kind = ProfileKind::Stack;
        if (output.pid != targetPid) return ERROR_SUCCESS;
        if ((length - 16) % width || (length - 16) / width > 256) return ERROR_INVALID_DATA;
        event.UserData = source.UserData; event.UserDataLength = length;
    } else if (IsEqualGUID(provider, threads) && opcode >= 1 && opcode <= 4) {
        if (!data || length < 8) return ERROR_SUCCESS;
        if (header.EventDescriptor.Version > 3) {
            output.unsupportedFormat = (1u << 24) | (static_cast<ULONG>(header.EventDescriptor.Version) << 16) | (static_cast<ULONG>(opcode) << 8) | 0x10u | static_cast<ULONG>(width);
            return ERROR_NOT_SUPPORTED;
        }
        // Classic Thread v0 reverses the two IDs; v1/v2/v3 use PID,TID.
        output.pid = read<ULONG>(data + (header.EventDescriptor.Version == 0 ? 4 : 0));
        output.tid = read<ULONG>(data + (header.EventDescriptor.Version == 0 ? 0 : 4)); output.kind = ProfileKind::Thread;
        if (output.pid != targetPid) return ERROR_SUCCESS;
        ULONG identity[] = {output.pid, output.tid}; std::memcpy(output.metadata.data(), identity, sizeof(identity));
        event.EventHeader.EventDescriptor.Version = 2;
        event.UserData = output.metadata.data(); event.UserDataLength = 8;
    } else if (images && IsEqualGUID(provider, image) && (opcode == 10 || opcode == 2 || opcode == 3 || opcode == 4)) {
        if (width != 8 || !data || length < 28) return ERROR_SUCCESS;
        auto base = read<std::uint64_t>(data), size = read<std::uint64_t>(data + 8);
        if (!(base >> 63)) return ERROR_SUCCESS;
        bool knownVersion = header.EventDescriptor.Version == 2 || header.EventDescriptor.Version == 3;
        if (!knownVersion || !size || size > ULONG(-1) || base + size < base) {
            ULONG reason = !knownVersion ? 1 : !size ? 2 : 3;
            output.unsupportedFormat = (2u << 24) | (static_cast<ULONG>(header.EventDescriptor.Version) << 16) | (static_cast<ULONG>(opcode) << 8) | (reason << 4) | static_cast<ULONG>(width);
            return ERROR_NOT_SUPPORTED;
        }
        output.kind = ProfileKind::KernelImage;
        std::memcpy(output.metadata.data(), data, 16);
        // Kernel identity only: no PID, name, emitter fields or extensions.
        std::memcpy(output.metadata.data() + 20, data + 20, 8);
        event.UserData = output.metadata.data(); event.UserDataLength = 28;
    } else return ERROR_SUCCESS;
    event.EventHeader.Size += event.UserDataLength;
    return ERROR_SUCCESS;
}
}
