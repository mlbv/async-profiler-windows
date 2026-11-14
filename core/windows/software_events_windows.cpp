/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsSoftwareEvents.h"
#include <algorithm>
#include <cstring>

namespace WindowsProfiler::Etw {
namespace {
constexpr GUID pageFault = {0x3d6fa8d3,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
constexpr GUID thread = {0x3d6fa8d1,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
constexpr UCHAR terminatedState = 4;
const std::array<CLASSIC_EVENT_ID, 6> faults = [] {
    std::array<CLASSIC_EVENT_ID, 6> result{};
    for (size_t i = 0; i < result.size(); ++i) { result[i].EventGuid = pageFault; result[i].Type = static_cast<UCHAR>(10 + i); }
    return result;
}();
const std::array<CLASSIC_EVENT_ID, 1> switches = [] {
    std::array<CLASSIC_EVENT_ID, 1> result{}; result[0].EventGuid = thread; result[0].Type = 36; return result;
}();
template<class T> T read(const unsigned char* bytes) { T value; std::memcpy(&value, bytes, sizeof(value)); return value; }
bool validThread(ULONG tid) { return tid && tid != ULONG(-1); }
}
SoftwareKind softwareEvent(const char* name) {
    return std::strcmp(name, "page-faults") == 0 ? SoftwareKind::PageFaults
        : std::strcmp(name, "context-switches") == 0 ? SoftwareKind::ContextSwitches : SoftwareKind::None;
}
const char* softwareEventName(SoftwareKind kind) {
    return kind == SoftwareKind::PageFaults ? "page-faults" : kind == SoftwareKind::ContextSwitches ? "context-switches" : "";
}
std::uint64_t softwareDefaultPeriod(SoftwareKind kind) { return kind == SoftwareKind::ContextSwitches ? 2 : 1; }
ULONG softwareEnableFlags(SoftwareKind kind) {
    return kind == SoftwareKind::PageFaults ? EVENT_TRACE_FLAG_MEMORY_PAGE_FAULTS
        : kind == SoftwareKind::ContextSwitches ? EVENT_TRACE_FLAG_CSWITCH : 0;
}
std::span<const CLASSIC_EVENT_ID> softwareStackEvents(SoftwareKind kind) {
    if (kind == SoftwareKind::PageFaults) return faults;
    if (kind == SoftwareKind::ContextSwitches) return switches;
    return {};
}
SoftwareRecord decodeSoftware(SoftwareKind selected, const EVENT_RECORD& event) {
    SoftwareRecord result;
    const auto& header = event.EventHeader;
    auto opcode = header.EventDescriptor.Opcode;
    bool lifecycle = IsEqualGUID(header.ProviderId, thread) && opcode >= 1 && opcode <= 4;
    bool fault = selected == SoftwareKind::PageFaults && IsEqualGUID(header.ProviderId, pageFault) && opcode >= 10 && opcode <= 15;
    bool switched = selected == SoftwareKind::ContextSwitches && IsEqualGUID(header.ProviderId, thread) && opcode == 36;
    bool proven = selected == SoftwareKind::ContextSwitches && IsEqualGUID(header.ProviderId, provenSwitchProvider);
    if (!lifecycle && !fault && !switched && !proven) return result;
    result.kind = SoftwareRecordKind::Malformed;
    if (!event.UserData) return result;
    auto data = static_cast<const unsigned char*>(event.UserData);
    auto version = header.EventDescriptor.Version;
    result.time = header.TimeStamp.QuadPart; result.cpu = event.BufferContext.ProcessorIndex;
    if (proven) {
        if (opcode || version || event.UserDataLength != sizeof(ProvenSwitch)) return result;
        ProvenSwitch value; std::memcpy(&value, data, sizeof(value));
        if (!validThread(value.tid) || value.reserved) return result;
        result.pid = header.ProcessId; result.tid = value.tid; result.stackTime = value.stackTime;
        result.kind = SoftwareRecordKind::Sample;
        return result;
    }
    auto flags = header.Flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER);
    if (flags != EVENT_HEADER_FLAG_32_BIT_HEADER && flags != EVENT_HEADER_FLAG_64_BIT_HEADER) return result;
    size_t width = flags == EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
    if (lifecycle) {
        if (version > 3) { result.kind = SoftwareRecordKind::Unsupported; return result; }
        if (event.UserDataLength < 8) return result;
        result.pid = read<ULONG>(data + (version == 0 ? 4 : 0));
        result.tid = read<ULONG>(data + (version == 0 ? 0 : 4));
        result.kind = opcode == 2 ? SoftwareRecordKind::ThreadEnd : opcode == 1 ? SoftwareRecordKind::ThreadStart : SoftwareRecordKind::ThreadRundown;
    } else if (fault) {
        // https://learn.microsoft.com/windows/win32/etw/pagefault-typegroup1
        if (version != 2) { result.kind = SoftwareRecordKind::Unsupported; return result; }
        if (event.UserDataLength != 2 * width) return result;
        result.ip = width == 8 ? read<std::uint64_t>(data + width) : read<ULONG>(data + width);
        result.pid = header.ProcessId; result.tid = header.ThreadId; result.stackTime = result.time;
        // Faults are logged in the faulting thread's context.
        if (!validThread(result.tid) || result.pid == ULONG(-1)) return result;
        result.category = opcode; result.kind = SoftwareRecordKind::Sample;
    } else {
        // https://learn.microsoft.com/windows/win32/etw/cswitch
        // https://github.com/microsoft/perfview/blob/main/src/TraceEvent/Parsers/KernelTraceEventParser.cs
        // CSwitchTraceData retains the 24-byte prefix in later versions.
        if (version < 2 || version > 5) { result.kind = SoftwareRecordKind::Unsupported; return result; }
        if (event.UserDataLength < 24 || (version == 2 && event.UserDataLength != 24)) return result;
        result.incomingTid = read<ULONG>(data); result.tid = read<ULONG>(data + 4);
        result.terminated = data[14] == terminatedState;
        if (result.tid == ULONG(-1) || result.incomingTid == ULONG(-1)) return result;
        result.kind = result.tid || result.incomingTid ? SoftwareRecordKind::Switch : SoftwareRecordKind::Ignore;
    }
    return result;
}
ULONG SoftwareThreadPeriods::begin(ULONG tid, bool rundown, bool beforeCapture) {
    auto [found, added] = threads.try_emplace(tid);
    if (added || rundown) return ERROR_SUCCESS;
    if (!beforeCapture) return ERROR_INVALID_DATA;
    found->second.phase = 0;
    return ERROR_SUCCESS;
}
ULONG SoftwareThreadPeriods::count(ULONG tid, std::uint64_t period, bool& selected) {
    selected = false;
    if (!period) return ERROR_INVALID_PARAMETER;
    auto found = threads.find(tid);
    if (found == threads.end()) return ERROR_NOT_FOUND;
    // phase never reaches period, so UINT64_MAX is a valid period too.
    if (++found->second.phase == period) { found->second.phase = 0; selected = true; }
    return ERROR_SUCCESS;
}
ULONG SoftwareStacks::open(Sample sample) {
    if (_count == _limit) return ERROR_BUFFER_OVERFLOW;
    auto& samples = _threads[sample.tid];
    auto at = std::upper_bound(samples.begin(), samples.end(), sample.stackTime,
        [](std::uint64_t time, const Sample& value) { return time < value.stackTime; });
    if (at != samples.begin() && std::prev(at)->stackTime == sample.stackTime) return ERROR_DUP_NAME;
    samples.insert(at, std::move(sample));
    ++_count;
    return ERROR_SUCCESS;
}
void SoftwareStacks::release(std::vector<Sample>& samples, Ready& ready) {
    for (auto& sample : samples) ready.push_back(std::move(sample));
    _count -= samples.size();
    samples.clear();
}
void SoftwareStacks::part(ULONG tid, std::uint64_t stackTime, std::span<const std::uint64_t> frames, Ready& ready) {
    auto found = _threads.find(tid);
    if (found == _threads.end()) return;
    auto& samples = found->second;
    // A part holds a kernel prefix, a user stack, or both. User stacks keep their
    // order, including kernel frames of user-mode callbacks below the first user frame.
    auto split = std::find_if(frames.begin(), frames.end(), [](std::uint64_t pc) { return !(pc >> 63); });
    std::span<const std::uint64_t> kernel(frames.begin(), split), user(split, frames.end());
    auto append = [&](std::vector<std::uint64_t>& to, std::span<const std::uint64_t> from, bool& overflow) {
        auto count = std::min(from.size(), _frameLimit - std::min(_frameLimit, to.size()));
        to.insert(to.end(), from.begin(), from.begin() + count);
        overflow |= count < from.size();
    };
    for (auto& sample : samples) {
        if (sample.stackTime != stackTime || sample.userSeen) continue;
        if (!kernel.empty()) { append(sample.kernel, kernel, sample.overflow); sample.kernelSeen = true; }
        if (!sample.ip && !sample.kernel.empty()) sample.ip = sample.kernel.front();
    }
    std::vector<Sample> released;
    if (!user.empty()) {
        for (auto& sample : samples) {
            // A later key shares the part only if its thread was in kernel mode there.
            if (sample.userSeen || sample.stackTime < stackTime
                    || (sample.stackTime > stackTime && !sample.kernelSeen && !sample.kernelRequired)) continue;
            append(sample.user, user, sample.overflow);
            sample.userSeen = true; sample.shared = sample.stackTime != stackTime;
        }
    }
    // A key's kernel part precedes the user part of its interval: a sample holding
    // a user part, or waiting before this user part's key, is final.
    auto keep = std::stable_partition(samples.begin(), samples.end(), [&](const Sample& sample) {
        return !sample.userSeen && (user.empty() || sample.stackTime >= stackTime);
    });
    released.assign(std::make_move_iterator(keep), std::make_move_iterator(samples.end()));
    samples.erase(keep, samples.end());
    release(released, ready);
    if (samples.empty()) _threads.erase(found);
}
void SoftwareStacks::end(ULONG tid, Ready& ready) {
    auto found = _threads.find(tid);
    if (found == _threads.end()) return;
    release(found->second, ready);
    _threads.erase(found);
}
void SoftwareStacks::finish(Ready& ready) {
    for (auto& [tid, samples] : _threads) release(samples, ready);
    _threads.clear();
}
}
