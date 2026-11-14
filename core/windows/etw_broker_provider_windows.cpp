/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwBroker.h"
#include "windowsTracepointSession.h"
#include "windowsTracepoint.h"
#include <cstring>

namespace WindowsProfiler::Etw::Broker {
ULONG providerEvent(const ProviderRequest& request, ULONG targetPid, const EVENT_RECORD& event,
                    EVENT_RECORD& filtered, bool& accepted,
                    std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, 2>* continuation) {
    accepted = false;
    const auto& header = event.EventHeader;
    if (IsEqualGUID(header.ProviderId, Tracepoint::STACK_CONTINUATION_PROVIDER)
            && header.EventDescriptor.Id == 18) {
        if (!(request.flags & Stacks) || header.ProcessId != targetPid) return ERROR_SUCCESS;
        if (!Tracepoint::continuationDescriptor(header.ProviderId, header.EventDescriptor)) return ERROR_NOT_SUPPORTED;
        if (!header.ThreadId || header.TimeStamp.QuadPart <= 0 || !continuation || event.ExtendedDataCount > MAX_SOURCE_EXTENSIONS
                || (event.ExtendedDataCount && !event.ExtendedData)) return ERROR_INVALID_DATA;
        *continuation = {};
        size_t count = 0;
        for (USHORT i = 0; i < event.ExtendedDataCount; ++i) {
            const auto& item = event.ExtendedData[i];
            if (item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64 && item.ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE32) continue;
            Tracepoint::Stack stack;
            if (count || !Tracepoint::decodeStack(item, stack) || !stack.matchId
                    || Tracepoint::stackDomain(stack) != Tracepoint::StackDomain::User) return ERROR_INVALID_DATA;
            auto& kept = (*continuation)[count++];
            kept.ExtType = item.ExtType; kept.DataSize = item.DataSize; kept.DataPtr = item.DataPtr;
        }
        if (count != 1) return ERROR_INVALID_DATA;
        filtered = {};
        filtered.EventHeader.Size = sizeof(EVENT_HEADER);
        filtered.EventHeader.Flags = EVENT_HEADER_FLAG_EXTENDED_INFO;
        filtered.EventHeader.ProviderId = Tracepoint::STACK_CONTINUATION_PROVIDER;
        filtered.EventHeader.ProcessId = targetPid; filtered.EventHeader.ThreadId = header.ThreadId;
        filtered.EventHeader.TimeStamp = header.TimeStamp;
        filtered.EventHeader.EventDescriptor.Id = 18; filtered.EventHeader.EventDescriptor.Version = 0;
        filtered.EventHeader.EventDescriptor.Opcode = 24; filtered.EventHeader.EventDescriptor.Task = 6;
        filtered.ExtendedData = continuation->data(); filtered.ExtendedDataCount = 1;
        accepted = true;
        return ERROR_SUCCESS;
    }
    bool selected = IsEqualGUID(header.ProviderId, request.provider) && header.ProcessId == targetPid
        && ((request.flags & Named) || header.EventDescriptor.Id == request.eventId)
        && (request.version < 0 || header.EventDescriptor.Version == request.version);
    bool lifecycle = IsEqualGUID(header.ProviderId, Tracepoint::KERNEL_PROCESS_PROVIDER)
        && (header.EventDescriptor.Id == 3 || header.EventDescriptor.Id == 4);
    if (lifecycle) {
        bool origin = header.ProcessId == targetPid || header.ProcessId == 0 || header.ProcessId == 4;
        if (header.EventDescriptor.Version > 1) return origin ? ERROR_NOT_SUPPORTED : ERROR_SUCCESS;
        if (!event.UserData || event.UserDataLength < 8) return origin ? ERROR_INVALID_DATA : ERROR_SUCCESS;
        ULONG identity[2]; std::memcpy(identity, event.UserData, sizeof(identity));
        if (identity[0] != targetPid) return ERROR_SUCCESS;
        if (!origin) return ERROR_NOT_SUPPORTED;
        if (!identity[1]) return ERROR_INVALID_DATA;
        if (selected) filtered = event;
        else {
            // This is lifetime metadata, never an attributed provider sample.
            // Foreign emission context, payload tails and stacks stay private.
            filtered = {};
            filtered.EventHeader.Size = sizeof(EVENT_HEADER);
            filtered.EventHeader.ProviderId = Tracepoint::KERNEL_PROCESS_PROVIDER;
            filtered.EventHeader.EventDescriptor.Id = header.EventDescriptor.Id;
            filtered.EventHeader.EventDescriptor.Version = header.EventDescriptor.Version;
            filtered.EventHeader.TimeStamp = header.TimeStamp;
        }
        filtered.UserData = event.UserData; filtered.UserDataLength = sizeof(identity);
        accepted = true;
        return ERROR_SUCCESS;
    }
    if (!selected) return ERROR_SUCCESS;
    filtered = event;
    // Selection and TDH name lookup need headers/schema/stacks, not values.
    filtered.UserData = nullptr; filtered.UserDataLength = 0;
    accepted = true;
    return ERROR_SUCCESS;
}
}
