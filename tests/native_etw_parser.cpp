/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtw.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace WindowsProfiler::Etw;
static void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
template<class T> static void put(std::vector<unsigned char>& bytes, size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}
static EVENT_RECORD event(std::vector<unsigned char>& data, const GUID& guid, UCHAR opcode, bool x64 = true) {
    EVENT_RECORD record{};
    record.EventHeader.ProviderId = guid;
    record.EventHeader.EventDescriptor.Opcode = opcode;
    record.EventHeader.EventDescriptor.Version = 2;
    record.EventHeader.Flags = x64 ? EVENT_HEADER_FLAG_64_BIT_HEADER : EVENT_HEADER_FLAG_32_BIT_HEADER;
    record.EventHeader.TimeStamp.QuadPart = 90001;
    record.EventHeader.ProcessId = 42;
    record.BufferContext.ProcessorIndex = 300;
    record.UserDataLength = static_cast<USHORT>(data.size());
    record.UserData = data.data();
    return record;
}
static void hardwareAliasesTest() {
    const std::vector<Source> legacy{
        {111,1,100,"InstructionRetired"}, {112,1,100,"CacheMisses"}, {113,1,100,"BranchMispredictions"},
    };
    require(findSource(legacy, "instructions") == &legacy[0] && findSource(legacy, "cache-misses") == &legacy[1]
        && findSource(legacy, "branch-misses") == &legacy[2], "Existing hardware aliases changed");
    const std::vector<Source> broad{
        {6,4096,2147483647,"BranchInstructions"},
        {21,4096,2147483647,"DcacheAccesses"},
        {8,4096,2147483647,"DcacheMisses"},
        {10,4096,2147483647,"CacheMisses"},
        {26,4096,2147483647,"ICFetch"},
        {31,4096,2147483647,"DCAccess"},
        {59,4096,2147483647,"FRRetiredTakenBranches"},
        {60,4096,2147483647,"FRRetiredBranchesMispredicted"},
    };
    for (auto name : {"branch-instructions", "cache-references", "ref-cycles", "bus-cycles",
            "L1-dcache-load-misses", "LLC-load-misses", "dTLB-load-misses"}) {
        require(hardwareAlias(name), "Unavailable hardware alias must remain reserved for ETW");
        require(findSource(broad, name) == nullptr, "Broader counter substituted for an exact hardware alias");
        require(findSource({}, name) == nullptr, "Missing HAL source must not synthesize a counter");
    }
    require(!hardwareAlias("etw:branch-instructions") && !hardwareAlias("nativeRoutine")
        && !hardwareAlias("page-faults") && !hardwareAlias("cpu-clock") && !hardwareAlias("cycles"),
        "Events with another engine's public meaning incorrectly reserved for ETW");
    for (const auto& alias : hardwareAliases())
        require(std::strcmp(alias.name, "cycles") != 0, "Public cycles polling sampler listed as ETW alias");
    require(findSource(broad, "etw:BranchInstructions") == &broad[0], "Explicit generic branch source changed");
    require(findSource(broad, "etw:DcacheMisses") == &broad[2], "Explicit generic cache source changed");
    require(!findSource(broad, "etw:branch-instructions"), "Explicit source name recursively expanded as alias");

    const std::vector<Source> amd{
        {6,4096,2147483647,"BranchInstructions"},
        {7311,4096,2147483647,"FRRetiredBranches"},
        {29,4096,2147483647,"NotRetiredBranches"},
    };
    require(findSource(amd, "branch-instructions") == &amd[1], "AMD retired branch alias uses enumerated name, not fixed ID");
    require(findSource(amd, "etw:FRRetiredBranches") == &amd[1], "AMD named event passthrough");
    const std::vector<Source> intel{
        {106,4096,2147483647,"BranchInstructions"},
        {8200,4096,2147483647,"BranchInstructionRetired"},
        {8201,4096,2147483647,"LLCReference"},
        {8202,4096,2147483647,"UnhaltedReferenceCycles"},
        {8203,4096,2147483647,"LLCMisses"},
    };
    require(findSource(intel, "branch-instructions") == &intel[1], "Intel retired branch source selected");
    require(findSource(intel, "cache-references") == &intel[2], "LLC references selected instead of generic data cache accesses");
    require(findSource(intel, "ref-cycles") == &intel[3], "Reference cycles selected instead of current-frequency cycles");
    require(!findSource(intel, "LLC-load-misses"), "All LLC misses substituted for load-only misses");
    const std::vector<Source> both{
        {7311,1,100,"FRRetiredBranches"}, {8200,2,200,"BranchInstructionRetired"},
    };
    require(findSource(both, "branch-instructions") == &both[1], "Alias selection depends on source enumeration order");
    const std::vector<Source> collision{
        {99,1,100,"branch-instructions"}, {100,1,100,"bus-cycles"}, {101,1,100,"cache-references"},
    };
    for (const auto& source : collision) {
        require(!findSource(collision, source.name.c_str()), "Bare alias selected an unproved same-name source");
        require(findSource(collision, ("etw:" + source.name).c_str()) == &source, "Explicit reserved-name source cannot be selected");
    }
    const std::vector<Source> insensitive{{512,1,100,"frretiredbranches"}};
    require(findSource(insensitive, "branch-instructions") == &insensitive[0], "HAL source case matching regressed");
    for (const auto& alias : hardwareAliases()) {
        require(hardwareAlias(alias.name), "Published hardware aliases must stay reserved");
        require(!findSource({}, alias.name), "Alias absent from host source inventory must be unavailable");
    }
}
int main(int argc, char** argv) {
    bool liveSources = argc == 2 && std::strcmp(argv[1], "--live-sources") == 0;
    require(argc == 1 || liveSources, "Use --live-sources only for explicit host enumeration");
    hardwareAliasesTest();
    constexpr GUID perf = {0xce1dbfb4, 0x137e, 0x4da6, {0x87,0xb0,0x3f,0x59,0xaa,0x10,0x2c,0xbc}};
    constexpr GUID stack = {0xdef2fe46, 0x7bd6, 0x4b80, {0xbd,0x94,0xf5,0x7f,0xe2,0x0d,0x0c,0xe3}};
    constexpr GUID thread = {0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
    constexpr GUID image = {0x2cb15d1d, 0x5fc1, 0x11d2, {0xab,0xe1,0x00,0xa0,0xc9,0x11,0xf5,0x18}};
    for (bool x64 : {false, true}) {
        size_t width = x64 ? 8 : 4;
        std::vector<unsigned char> bytes(width + 8);
        if (x64) put<std::uint64_t>(bytes, 0, 0x123456789abcULL);
        else put<ULONG>(bytes, 0, 0x12345678);
        put<ULONG>(bytes, width, 1234);
        put<USHORT>(bytes, width + 4, 25);
        auto input = event(bytes, perf, 47, x64);
        auto pmc = decode(input);
        require(pmc.kind == Kind::Profile && pmc.source == 25 && pmc.tid == 1234 && pmc.pid == 42 && pmc.cpu == 300, "PMC payload offsets/processor index");
        require(pmc.ip == (x64 ? 0x123456789abcULL : 0x12345678) && pmc.time == 90001 && pmc.count == 1, "PMC IP/time/count");
        for (size_t length = 0; length < bytes.size(); ++length) {
            input.UserDataLength = static_cast<USHORT>(length);
            require(decode(input).kind == Kind::Malformed, "Truncated PMC accepted");
        }
        input.UserDataLength = static_cast<USHORT>(bytes.size());
        input.EventHeader.EventDescriptor.Opcode = 46;
        put<USHORT>(bytes, width + 4, 3);
        auto timer = decode(input);
        require(timer.kind == Kind::Profile && timer.source == 0 && timer.count == 3, "Timer weighting");
        bytes[width + 6] = 1;
        require(decode(input).kind == Kind::Ignore, "DPC charged to process");
        bytes[width + 6] = 2;
        require(decode(input).kind == Kind::Ignore, "ISR charged to process");
        bytes.assign(16 + 2 * width, 0);
        put<std::uint64_t>(bytes, 0, 80000);
        put<ULONG>(bytes, 8, 77); put<ULONG>(bytes, 12, 99);
        if (x64) { put<std::uint64_t>(bytes, 16, 0xfffff80012345678ULL); put<std::uint64_t>(bytes, 24, 0x123456789abcULL); }
        else { put<ULONG>(bytes, 16, 0x12345678); put<ULONG>(bytes, 20, 0xabcdef01); }
        input = event(bytes, stack, 32, x64);
        auto walk = decode(input);
        require(walk.kind == Kind::Stack && walk.pid == 77 && walk.tid == 99 && walk.time == 80000 && walk.depth == 2, "Stack correlation key");
        require(walk.stack[0] == (x64 ? 0xfffff80012345678ULL : 0x12345678) && walk.stack[1] == (x64 ? 0x123456789abcULL : 0xabcdef01), "Stack pointer widths");
        --input.UserDataLength;
        require(decode(input).kind == Kind::Malformed, "Misaligned stack accepted");
        input.UserDataLength = 15;
        require(decode(input).kind == Kind::Malformed, "Truncated stack header accepted");
        bytes.assign(2 * width + 12, 0);
        if (x64) { put<std::uint64_t>(bytes, 0, 0xfffff80012340000ULL); put<std::uint64_t>(bytes, 8, 0x12000); }
        else { put<ULONG>(bytes, 0, 0x12340000); put<ULONG>(bytes, 4, 0x12000); }
        put<ULONG>(bytes, 2 * width + 4, 0xc96e51);
        for (UCHAR opcode : {10, 2, 3, 4}) {
            auto module = decode(event(bytes, image, opcode, x64));
            require(module.imageBase == (x64 ? 0xfffff80012340000ULL : 0x12340000) && module.imageSize == 0x12000
                && module.imageChecksum == 0xc96e51, "Image event layout");
            require(module.kind == (opcode == 2 ? Kind::ImageUnload : opcode == 10 ? Kind::ImageLoad : Kind::ImageRundown), "Image load/unload/rundown classification");
        }
    }
    std::vector<unsigned char> bytes(8);
    {
        // Current Windows emits 256-frame stacks (2064 bytes), exceeding the
        // older StackWalk MOF documentation's 192 named stack fields.
        std::vector<unsigned char> deep(16 + 256 * 8);
        put<std::uint64_t>(deep, 0, 70000);
        put<std::uint64_t>(deep, 16 + 255 * 8, 0x123456789abcULL);
        auto decoded = decode(event(deep, stack, 32));
        require(decoded.kind == Kind::Stack && decoded.depth == 256 && decoded.stack[255] == 0x123456789abcULL, "256-frame Windows stack rejected");
    }
    put<ULONG>(bytes, 0, 10); put<ULONG>(bytes, 4, 20);
    for (UCHAR opcode : {1, 2, 3, 4}) {
        auto decoded = decode(event(bytes, thread, opcode));
        require(decoded.pid == 10 && decoded.tid == 20 && decoded.kind == (opcode == 2 ? Kind::ThreadEnd : Kind::ThreadStart), "Thread lifetime/rundown");
    }
    require(decode(event(bytes, perf, 99)).kind == Kind::Ignore, "Unknown opcode");
    for (UCHAR opcode : {34, 35, 36, 37, 38}) {
        require(decode(event(bytes, stack, opcode)).kind == Kind::UnsupportedStack, "Undecoded StackWalk event silently ignored");
    }
    std::wstring name = L"\u8ba1\u6570\U0001f642";
    bytes.assign(24 + (name.size() + 1) * sizeof(WCHAR), 0);
    put<ULONG>(bytes, 4, 25); put<ULONG>(bytes, 8, 4096); put<ULONG>(bytes, 12, 2147483647);
    std::memcpy(bytes.data() + 24, name.c_str(), (name.size() + 1) * sizeof(WCHAR));
    std::vector<Source> sources;
    require(parseSources(bytes.data(), bytes.size(), sources) == ERROR_SUCCESS && sources.size() == 1 && sources[0].id == 25, "Source list parser");
    require(sources[0].name == "\xe8\xae\xa1\xe6\x95\xb0\xf0\x9f\x99\x82", "Source name UTF-8");
    require(parseSources(bytes.data(), 23, sources) == ERROR_INVALID_DATA, "Truncated source header");
    require(parseSources(bytes.data(), bytes.size() - 2, sources) == ERROR_INVALID_DATA, "Unterminated source name");
    put<ULONG>(bytes, 0, 0xffffffff);
    require(parseSources(bytes.data(), bytes.size(), sources) == ERROR_INVALID_DATA, "Source link outside buffer");
    put<ULONG>(bytes, 0, 2);
    require(parseSources(bytes.data(), bytes.size(), sources) == ERROR_INVALID_DATA, "Source link loops into header");
    if (liveSources) {
        require(querySources(sources) == ERROR_SUCCESS && !sources.empty(), "Live source query");
        for (const auto& source : sources) require(findSource(sources, ("etw:" + source.name).c_str()) == &source, "Enumerated source cannot be selected");
        auto instructions = findSource(sources, "etw:InstructionRetired");
        require(findSource(sources, "instructions") == instructions, "Instruction alias");
    }
    std::vector<Source> aliases{{0,1,100,"Localized timer"},{19,1,100,"TotalCycles"}};
    require(findSource(aliases, "cpu") == &aliases[0], "CPU alias uses timer identity");
    require(findSource(aliases, "cpu-clock") == &aliases[0], "CPU clock alias uses timer identity");
    require(findSource(aliases, "cycles") == &aliases[1], "Hardware cycles alias");
    require(!validateTargetCpu(-1) && !validateTargetCpu(0), "Active/default CPU selection");
    require(validateTargetCpu(static_cast<int>(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS))), "Inactive CPU rejected");
    std::printf("ETW_PARSER_OK hardwareAliases=1 exactSourceNames=1 unavailableReserved=1 noBroadSubstitution=1 explicitPassthrough=1 liveSources=%d\n", liveSources);
}
