/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtw.h"
#include "windowsProfiler.h"
#include <algorithm>
#include <cstddef>
#include <cstring>

namespace WindowsProfiler::Etw {
namespace {
constexpr GUID perfInfo = {0xce1dbfb4, 0x137e, 0x4da6, {0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc}};
constexpr GUID stackWalk = {0xdef2fe46, 0x7bd6, 0x4b80, {0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3}};
constexpr GUID thread = {0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
constexpr GUID imageLoad = {0x2cb15d1d, 0x5fc1, 0x11d2, {0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18}};
const HardwareAlias aliases[] = {
    {"instructions", {"InstructionRetired"}},
    {"cache-misses", {"CacheMisses"}},
    {"branch-misses", {"BranchMispredictions"}},
    // Named retired events are narrower contracts than BranchInstructions.
    // AMD FRRetiredBranches corresponds to retired branches, not the taken subset.
    // https://learn.microsoft.com/windows-hardware/test/wpt/wpr-command-line-options#pmcsources
    // https://github.com/torvalds/linux/blob/v6.12/arch/x86/events/amd/core.c
    {"branch-instructions", {"BranchInstructionRetired", "FRRetiredBranches"}},
    {"cache-references", {"LLCReference"}},
    {"ref-cycles", {"UnhaltedReferenceCycles"}},
    // TODO: add only enumerated equivalents with proved bus/load-only semantics.
    {"bus-cycles", {}},
    {"L1-dcache-load-misses", {}},
    {"LLC-load-misses", {}},
    {"dTLB-load-misses", {}},
};
const Source* namedSource(const std::vector<Source>& sources, const char* name) {
    for (const auto& source : sources)
        if (_stricmp(source.name.c_str(), name) == 0) return &source;
    return nullptr;
}
template<class T> T read(const void* address) {
    T result;
    std::memcpy(&result, address, sizeof(result));
    return result;
}
}

ULONG parseSources(const void* data, size_t size, std::vector<Source>& sources) {
    sources.clear();
    constexpr size_t header = offsetof(PROFILE_SOURCE_INFO, Description);
    auto bytes = static_cast<const unsigned char*>(data);
    size_t offset = 0;
    while (offset < size) {
        if (size - offset < header + sizeof(WCHAR)) return ERROR_INVALID_DATA;
        auto p = bytes + offset;
        ULONG next = read<ULONG>(p);
        size_t length = next ? next : size - offset;
        if (length > size - offset || length < header + sizeof(WCHAR) || length % sizeof(WCHAR)) return ERROR_INVALID_DATA;
        std::wstring name;
        bool terminated = false;
        for (size_t i = header; i + sizeof(WCHAR) <= length; i += sizeof(WCHAR)) {
            auto c = read<WCHAR>(p + i);
            if (c == 0) { terminated = true; break; }
            name.push_back(c);
        }
        if (!terminated) return ERROR_INVALID_DATA;
        sources.push_back({read<ULONG>(p + 4), read<ULONG>(p + 8), read<ULONG>(p + 12), WindowsProfiler::utf8(name)});
        if (sources.back().name.empty() || sources.back().minimum > sources.back().maximum) return ERROR_INVALID_DATA;
        if (!next) return ERROR_SUCCESS;
        offset += next;
    }
    return ERROR_INVALID_DATA;
}

ULONG querySources(std::vector<Source>& sources) {
    ULONG required = 0;
    ULONG result = TraceQueryInformation(0, TraceProfileSourceListInfo, nullptr, 0, &required);
    if (result != ERROR_BAD_LENGTH && result != ERROR_INSUFFICIENT_BUFFER && result != ERROR_SUCCESS) return result;
    if (required == 0 || required > 1024 * 1024) return ERROR_INVALID_DATA;
    std::vector<unsigned char> buffer(required);
    result = TraceQueryInformation(0, TraceProfileSourceListInfo, buffer.data(), required, &required);
    if (result != ERROR_SUCCESS) return result;
    if (required > buffer.size()) return ERROR_INVALID_DATA;
    return parseSources(buffer.data(), required, sources);
}

bool cpuTimerAlias(const char* name) {
    return std::strcmp(name, "cpu") == 0 || std::strcmp(name, "cpu-clock") == 0;
}

std::span<const HardwareAlias> hardwareAliases() { return aliases; }

bool hardwareAlias(const char* name) {
    for (const auto& alias : aliases) if (std::strcmp(alias.name, name) == 0) return true;
    return false;
}

const Source* findSource(const std::vector<Source>& sources, const char* name) {
    if (cpuTimerAlias(name)) {
        for (const auto& source : sources) if (source.id == 0) return &source;
        return nullptr;
    }
    // Explicit provider names bypass aliases, including names that happen to
    // equal a reserved alias. Source IDs are assigned by this host's HAL.
    if (std::strncmp(name, "etw:", 4) == 0) return namedSource(sources, name + 4);
    if (std::strcmp(name, "cycles") == 0) return namedSource(sources, "TotalCycles");
    for (const auto& alias : aliases) {
        if (std::strcmp(alias.name, name) != 0) continue;
        for (const auto* candidate : alias.sources)
            if (candidate) if (auto source = namedSource(sources, candidate)) return source;
        return nullptr;
    }
    return namedSource(sources, name);
}

Error validateTargetCpu(int cpu) {
    if (cpu == -1) return Error(nullptr);
    auto count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (!count) return Error("Cannot query active processors for target-cpu");
    return cpu < 0 || static_cast<DWORD>(cpu) >= count
        ? Error("target-cpu index is not active on this system") : Error(nullptr);
}

Record decode(const EVENT_RECORD& event) {
    Record result;
    const auto& guid = event.EventHeader.ProviderId;
    auto opcode = event.EventHeader.EventDescriptor.Opcode;
    bool profile = IsEqualGUID(guid, perfInfo) && (opcode == 46 || opcode == 47);
    bool stackProvider = IsEqualGUID(guid, stackWalk);
    bool stack = stackProvider && opcode == 32;
    if (stackProvider && !stack) { result.kind = Kind::UnsupportedStack; return result; }
    bool threads = IsEqualGUID(guid, thread) && opcode >= 1 && opcode <= 4;
    bool image = IsEqualGUID(guid, imageLoad) && (opcode == 10 || opcode == 2 || opcode == 3 || opcode == 4);
    if (!profile && !stack && !threads && !image) return result;
    result.kind = Kind::Malformed;
    auto data = static_cast<const unsigned char*>(event.UserData);
    size_t size = event.UserDataLength;
    if (!data) return result;
    size_t pointerSize = event.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : 8;
    result.time = event.EventHeader.TimeStamp.QuadPart;
    result.pid = event.EventHeader.ProcessId;
    result.cpu = event.BufferContext.ProcessorIndex;
    if (profile) {
        if (size < pointerSize + 8) return result;
        result.ip = pointerSize == 8 ? read<std::uint64_t>(data) : read<ULONG>(data);
        result.tid = read<ULONG>(data + pointerSize);
        if (opcode == 47) result.source = read<USHORT>(data + pointerSize + 4);
        else if (event.EventHeader.EventDescriptor.Version >= 2) {
            // DPC/ISR time belongs to the kernel, not the interrupted process.
            if (data[pointerSize + 6] & 3) { result.kind = Kind::Ignore; return result; }
            result.count = std::max<ULONG>(1, read<USHORT>(data + pointerSize + 4));
        }
        result.kind = Kind::Profile;
    } else if (stack) {
        if (size < 16 || (size - 16) % pointerSize) return result;
        result.depth = (size - 16) / pointerSize;
        if (result.depth > result.stack.size()) return result;
        result.time = read<std::uint64_t>(data);
        result.pid = read<ULONG>(data + 8);
        result.tid = read<ULONG>(data + 12);
        for (size_t i = 0; i < result.depth; ++i) {
            auto frame = data + 16 + i * pointerSize;
            result.stack[i] = pointerSize == 8 ? read<std::uint64_t>(frame) : read<ULONG>(frame);
        }
        result.kind = Kind::Stack;
    } else if (image) {
        if (event.EventHeader.EventDescriptor.Version < 2 || size < 2 * pointerSize + 12) return result;
        result.imageBase = pointerSize == 8 ? read<std::uint64_t>(data) : read<ULONG>(data);
        auto imageSize = pointerSize == 8 ? read<std::uint64_t>(data + pointerSize) : read<ULONG>(data + pointerSize);
        if (imageSize > ULONG(-1)) return result;
        result.imageSize = static_cast<ULONG>(imageSize);
        result.imageChecksum = read<ULONG>(data + 2 * pointerSize + 4);
        result.kind = opcode == 2 ? Kind::ImageUnload : opcode == 3 || opcode == 4 ? Kind::ImageRundown : Kind::ImageLoad;
    } else {
        if (size < 8) return result;
        result.pid = read<ULONG>(data);
        result.tid = read<ULONG>(data + 4);
        result.kind = opcode == 2 ? Kind::ThreadEnd : Kind::ThreadStart;
    }
    return result;
}
}
