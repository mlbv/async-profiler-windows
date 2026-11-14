/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Offline audit of return-site analysis over a real PE image. Every accepted
// epilogue is unwound by RtlVirtualUnwind at its original first instruction,
// with an INT3 there, and at every position of a displaced copy carrying the
// site's recipe; all results must equal the analysed post-return state.
#include "platform.h"
#include "windowsSoftwareFunction.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <tuple>
#include <string>
#include <vector>

using namespace WindowsProfiler;
namespace {
void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "SOFTWARE_FUNCTION_AUDIT_FAILURE %s\n", message); std::exit(1); }
}
DWORD64& reg(CONTEXT& context, unsigned index) { return (&context.Rax)[index]; }
struct Unwound { DWORD64 rip, rsp, registers[16]; bool operator==(const Unwound&) const = default; };
Unwound unwound(const CONTEXT& context) {
    Unwound result{context.Rip, context.Rsp, {}};
    for (unsigned index = 0; index < 16; ++index)
        if (index != 4 && (index == 3 || (index >= 5 && index <= 7) || index >= 12)) result.registers[index] = reg(const_cast<CONTEXT&>(context), index);
    return result;
}
Unwound virtualUnwind(DWORD64 base, const RUNTIME_FUNCTION& function, DWORD64 pc, CONTEXT context) {
    context.Rip = pc;
    void* data; DWORD64 frame;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, base, pc, const_cast<RUNTIME_FUNCTION*>(&function), &context, &data, &frame, nullptr);
    return unwound(context);
}
// A consistent context for a state: entry RSP fixed, frame register and
// MOV-saved registers holding what the state's slots describe.
CONTEXT stateContext(const NativeUnwind::BodyState& state, DWORD64 entry) {
    CONTEXT context{};
    for (unsigned index = 0; index < 16; ++index) reg(context, index) = 0x7000000000ull + index * 0x101;
    context.Rsp = entry - state.size;
    if (state.frameRegister) reg(context, state.frameRegister) = entry - state.frameSize;
    auto frameBase = state.frameRegister ? reg(context, state.frameRegister) - 16 * (state.recipe[3] >> 4) : context.Rsp;
    for (size_t slot = 0; slot < state.recipe[2];) {
        auto code = state.recipe.data() + 4 + slot * 2;
        unsigned operation = code[1] & 15, slots = operation == 4 || operation == 8 ? 2 : operation == 5 || operation == 9 ? 3
            : operation == 1 ? ((code[1] >> 4) ? 3 : 2) : 1;
        // An established frame register no longer holds its saved value.
        if ((operation == 4 || operation == 5) && (code[1] >> 4) != state.frameRegister) {
            DWORD offset = operation == 4 ? *reinterpret_cast<const std::uint16_t*>(code + 2) * 8u : *reinterpret_cast<const std::uint32_t*>(code + 2);
            reg(context, code[1] >> 4) = *reinterpret_cast<const DWORD64*>(frameBase + offset);
        }
        slot += slots;
    }
    return context;
}
size_t metadata(const unsigned char* info) {
    auto flags = info[0] >> 3;
    return 4 + ((info[2] + 1u) & ~1u) * 2 + (flags & 4 ? sizeof(RUNTIME_FUNCTION) : flags & 3 ? 4 : 0);
}
// Staging within rel32 reach of every image address, as the engine places displaced code.
unsigned char* nearImage(const unsigned char* base, DWORD size) {
    using Allocate2 = void* (WINAPI*)(HANDLE, void*, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG);
    auto allocate2 = reinterpret_cast<Allocate2>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "VirtualAlloc2"));
    require(allocate2 != nullptr, "VirtualAlloc2 is unavailable");
    SYSTEM_INFO system; GetSystemInfo(&system);
    auto begin = reinterpret_cast<std::uintptr_t>(base), end = begin + size;
    auto granularity = static_cast<std::uintptr_t>(system.dwAllocationGranularity);
    auto low = std::max(reinterpret_cast<std::uintptr_t>(system.lpMinimumApplicationAddress), end > INT32_MAX ? end - INT32_MAX : 0);
    auto high = std::min(reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress), begin + INT32_MAX - 4096);
    MEM_ADDRESS_REQUIREMENTS requirements{};
    requirements.LowestStartingAddress = reinterpret_cast<void*>((low + granularity - 1) & ~(granularity - 1));
    requirements.HighestEndingAddress = reinterpret_cast<void*>(((high + 1) & ~(granularity - 1)) - 1);
    requirements.Alignment = system.dwAllocationGranularity;
    MEM_EXTENDED_PARAMETER parameter{}; parameter.Type = MemExtendedParameterAddressRequirements; parameter.Pointer = &requirements;
    auto page = static_cast<unsigned char*>(allocate2(GetCurrentProcess(), nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE,
        &parameter, 1));
    require(page != nullptr, "Cannot reserve staging near the audited image");
    return page;
}
const unsigned char* opcodeOf(const unsigned char* bytes) {
    while (*bytes == 0x26 || *bytes == 0x2e || *bytes == 0x36 || *bytes == 0x3e || *bytes == 0x64 || *bytes == 0x65
            || *bytes == 0x66 || *bytes == 0x67 || *bytes == 0xf0 || *bytes == 0xf2 || *bytes == 0xf3 || (*bytes & 0xf0) == 0x40) ++bytes;
    return bytes;
}
}

int main(int argc, char** argv) {
    require(argc == 2 || argc == 3, "Pass one x86-64 PE image and an optional rejection to sample");
    auto module = LoadLibraryExA(argv[1], nullptr, DONT_RESOLVE_DLL_REFERENCES);
    require(module != nullptr, "Cannot map audited image");
    auto base = reinterpret_cast<unsigned char*>(module);
    auto pe = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto size = pe->OptionalHeader.SizeOfImage;
    auto directory = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    auto rows = reinterpret_cast<RUNTIME_FUNCTION*>(base + directory.VirtualAddress);
    size_t count = directory.Size / sizeof(RUNTIME_FUNCTION);
    // A private copy of the image receives the INT3 for the patched-source check.
    auto copy = static_cast<unsigned char*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    require(copy != nullptr, "Cannot allocate image copy");
    for (DWORD offset = 0; offset < size;) {
        MEMORY_BASIC_INFORMATION page{};
        require(VirtualQuery(base + offset, &page, sizeof(page)) != 0, "Cannot query audited image");
        auto length = static_cast<DWORD>(std::min<SIZE_T>(page.RegionSize, size - offset));
        if (page.State == MEM_COMMIT && !(page.Protect & (PAGE_NOACCESS | PAGE_GUARD))) std::memcpy(copy + offset, base + offset, length);
        offset += length;
    }
    auto root = [&](RUNTIME_FUNCTION row) {
        for (;;) {
            auto info = base + row.UnwindData;
            if (!(info[0] & 0x20)) return row;
            std::memcpy(&row, info + 4 + ((info[2] + 1u) & ~1u) * 2, sizeof(row));
        }
    };
    std::map<DWORD, std::vector<RUNTIME_FUNCTION>> functions;
    for (size_t index = 0; index < count; ++index) {
        if (rows[index].UnwindData & 1) continue;
        auto primary = root(rows[index]);
        auto& list = functions[primary.BeginAddress];
        if (!std::memcmp(&primary, &rows[index], sizeof(primary))) list.insert(list.begin(), rows[index]);
        else list.push_back(rows[index]);
    }
    std::map<std::string, unsigned> rejected;
    unsigned accepted = 0, chainedAccepted = 0, handlerAccepted = 0, epilogues = 0, positions = 0, jumps = 0, skipped = 0, bodyPositions = 0, exits = 0;
    unsigned bodySites = 0, rewritten = 0, transactions = 0, unrelocatable = 0, targetStates = 0;
    alignas(16) static DWORD64 stack[0x4000];
    alignas(16) static unsigned char displaced[256];
    auto staging = nearImage(base, size);
    for (auto& [begin, list] : functions) {
        std::sort(list.begin() + 1, list.end(), [](const RUNTIME_FUNCTION& a, const RUNTIME_FUNCTION& b) { return a.BeginAddress < b.BeginAddress; });
        std::vector<std::vector<NativeUnwind::ChainEntry>> chains(list.size());
        std::vector<SoftwareFunction::Fragment> fragments;
        bool handler = (base[list[0].UnwindData] >> 3) & 3;
        for (size_t index = 0; index < list.size(); ++index) {
            for (auto row = list[index];;) {
                auto info = base + row.UnwindData;
                if (!(info[0] & 0x20)) break;
                std::memcpy(&row, info + 4 + ((info[2] + 1u) & ~1u) * 2, sizeof(row));
                chains[index].push_back({row.BeginAddress, row.EndAddress, row.UnwindData,
                    {base + row.BeginAddress, row.EndAddress - row.BeginAddress}, {base + row.UnwindData, metadata(base + row.UnwindData)}});
            }
        }
        for (size_t index = 0; index < list.size(); ++index) {
            const auto& row = list[index];
            fragments.push_back({row.BeginAddress, {{base + row.BeginAddress, row.EndAddress - row.BeginAddress},
                {base + row.UnwindData, metadata(base + row.UnwindData)}, 0, chains[index]}});
        }
        SoftwareFunction::Analysis analysis;
        if (argc == 3 && !std::strcmp(argv[2], "trace")) std::fprintf(stderr, "function=%lx\n", begin);
        auto error = analysis.analyze(fragments, handler);
        // Body sites: the original OS unwind at the instruction, with an INT3
        // there, and at its continuation must equal the version-2 recipes.
        for (const auto& instruction : error ? std::span<const SoftwareFunction::Analysis::Instruction>{} : analysis.instructions()) {
            unsigned fragment;
            const SoftwareFunction::Epilogue* epilogue;
            auto position = analysis.classify(instruction.rva, fragment, epilogue);
            if ((position != SoftwareFunction::Position::Body && position != SoftwareFunction::Position::Prolog)
                    || SoftwareFunction::Analysis::calls(instruction) || base[instruction.rva] == 0xcc) continue;
            auto next = instruction.rva + instruction.length;
            if (!analysis.bodyEquivalent(next) && std::any_of(analysis.instructions().begin(), analysis.instructions().end(),
                    [&](const auto& other) { return other.rva == next; })) continue;
            auto offset = instruction.rva - fragments[fragment].begin;
            NativeUnwind::BodyState before, after;
            require(!NativeUnwind::bodyState(fragments[fragment].source, true, before, offset)
                && !NativeUnwind::bodyState(fragments[fragment].source, true, after, offset + instruction.length), "Body state failed");
            if (before.size != after.size || before.pushes != after.pushes || before.frameRegister != after.frameRegister
                    || before.frameSize != after.frameSize || before.size > 0x2000 || before.frameSize > 0x2000) continue;
            // The engine relocates every such site; a rewritten branch's taken
            // jump also needs the branch state at its target.
            InstructionDecoder::Relocation relocation;
            if (!InstructionDecoder::relocate(staging, InstructionDecoder::MAX_RELOCATED_BYTES, base + instruction.rva,
                    instruction.length, relocation) || relocation.sourceBytes != instruction.length) { ++unrelocatable; continue; }
            if (instruction.target >= 0)
                require(relocation.branchTarget == base + instruction.target, "Relocated branch target differs from the analysed target");
            auto opcode = opcodeOf(base + instruction.rva);
            if (opcode[0] == 0xc7 && opcode[1] == 0xf8) {
                require(relocation.destinationBytes == instruction.length && !relocation.taken
                    && !std::memcmp(staging, base + instruction.rva, instruction.length - 4), "XBEGIN relocation changed its form");
                ++transactions;
            }
            unsigned reached = fragment;
            if (relocation.taken) {
                auto branch = static_cast<std::uint32_t>(instruction.target);
                const SoftwareFunction::Epilogue* entered;
                auto target = analysis.classify(branch, reached, entered);
                NativeUnwind::BodyState state;
                if (target == SoftwareFunction::Position::EpilogueInterior || !analysis.bodyEquivalent(branch)
                        || NativeUnwind::bodyState(fragments[reached].source, true, state, branch - fragments[reached].begin)
                        || state.size != after.size || state.pushes != after.pushes || state.frameRegister != after.frameRegister
                        || state.frameSize != after.frameSize) { ++targetStates; continue; }
                ++rewritten;
            }
            ++bodySites;
            for (size_t index = 0; index < std::size(stack); ++index) stack[index] = 0x5000000000ull + index * 8;
            auto entry = reinterpret_cast<DWORD64>(&stack[0x3000]);
            if (argc == 3 && !std::strcmp(argv[2], "trace"))
                std::fprintf(stderr, "  body site=%x size=%llu frame=%u/%llu\n", instruction.rva, (unsigned long long)before.size,
                    before.frameRegister, (unsigned long long)before.frameSize);
            std::vector<std::tuple<const NativeUnwind::BodyState*, std::uint32_t, bool, const RUNTIME_FUNCTION*>> checks{
                {&before, instruction.rva, false, &list[fragment]}, {&before, instruction.rva, true, &list[fragment]},
                {&after, next, false, &list[fragment]}};
            if (relocation.taken) checks.push_back({&after, static_cast<std::uint32_t>(instruction.target), false, &list[reached]});
            for (auto [state, pc, patch, function] : checks) {
                const auto& row = *function;
                if (pc >= row.EndAddress) continue;
                auto context = stateContext(*state, entry);
                std::memcpy(displaced + 128, state->recipe.data(), state->recipe.size());
                displaced[128] = 2;
                RUNTIME_FUNCTION copied{0, 1, 128};
                auto recipe = virtualUnwind(reinterpret_cast<DWORD64>(displaced), copied, reinterpret_cast<DWORD64>(displaced), context);
                auto image = patch ? copy : base;
                auto saved = copy[pc];
                if (patch) copy[pc] = 0xcc;
                auto original = virtualUnwind(reinterpret_cast<DWORD64>(image), row, reinterpret_cast<DWORD64>(image + pc), context);
                copy[pc] = saved;
                if (!(original == recipe)) {
                    std::fprintf(stderr, "function=%lx site=%x pc=%x patch=%d\n", begin, instruction.rva, pc, int(patch));
                    require(false, "Body site unwinds differently from its displaced recipe");
                }
                ++bodyPositions;
            }
        }
        if (!error) error = analysis.returnError();
        if (error) {
            if (argc == 3 && !std::strcmp(argv[2], error) && rejected[error] < 6) std::printf("  sample %s=%lx\n", error, begin);
            ++rejected[error];
            continue;
        }
        if (analysis.epilogues().empty()) { ++rejected["no-return-site"]; continue; }
        if (argc == 3 && !std::strcmp(argv[2], "trace")) std::fprintf(stderr, "accepted=%lx\n", begin);
        ++accepted; chainedAccepted += list.size() > 1; handlerAccepted += handler;
        // A taken exit returns through the remaining epilogue from its own state.
        for (const auto& exit : analysis.exits()) {
            const auto& epilogue = analysis.epilogues()[exit.epilogue];
            unsigned fragment;
            const SoftwareFunction::Epilogue* inside;
            auto position = analysis.classify(exit.branch, fragment, inside);
            require(position == SoftwareFunction::Position::Body || position == SoftwareFunction::Position::Prolog,
                "Exit branch is not a body site");
            NativeUnwind::BodyState state;
            require(!NativeUnwind::bodyState(fragments[fragment].source, true, state, exit.branch - fragments[fragment].begin),
                "Exit state failed");
            for (size_t index = 0; index < std::size(stack); ++index) stack[index] = 0x5000000000ull + index * 8;
            auto entry = reinterpret_cast<DWORD64>(&stack[0x3000]);
            auto context = stateContext(state, entry);
            auto returned = context;
            for (unsigned index = exit.firstPop; index < epilogue.popCount; ++index) {
                reg(returned, epilogue.pops[index]) = *reinterpret_cast<DWORD64*>(returned.Rsp);
                returned.Rsp += 8;
            }
            require(returned.Rsp == entry, "Exit state does not reach the return address");
            returned.Rip = *reinterpret_cast<DWORD64*>(returned.Rsp);
            returned.Rsp += 8;
            auto original = virtualUnwind(reinterpret_cast<DWORD64>(base), list[fragment], reinterpret_cast<DWORD64>(base + exit.branch), context);
            if (!epilogue.immediate) require(original == unwound(returned), "OS unwind at an exit branch disagrees with its return");
            ++exits;
        }
        for (const auto& epilogue : analysis.epilogues()) {
            ++epilogues; jumps += epilogue.jump;
            const auto& state = analysis.state(epilogue.state);
            if (argc == 3 && !std::strcmp(argv[2], "trace"))
                std::fprintf(stderr, "  epilogue start=%x end=%x teardown=%d base=%u amount=%d pops=%u size=%llu frame=%u/%llu\n",
                    epilogue.start, epilogue.end, int(epilogue.teardown), epilogue.frameRegister, epilogue.amount, epilogue.popCount,
                    (unsigned long long)state.size, state.frameRegister, (unsigned long long)state.frameSize);
            if (state.size > 0x2000 || state.frameSize > 0x2000) { ++skipped; continue; }
            CONTEXT context{};
            for (unsigned index = 0; index < 16; ++index) reg(context, index) = 0x7000000000ull + index * 0x101;
            for (size_t index = 0; index < std::size(stack); ++index) stack[index] = 0x5000000000ull + index * 8;
            auto entry = reinterpret_cast<DWORD64>(&stack[0x3000]);
            context.Rsp = entry - state.size;
            if (state.frameRegister) reg(context, state.frameRegister) = entry - state.frameSize;
            // A non-frame teardown base holds whatever restores the push area.
            if ((epilogue.teardown == SoftwareFunction::Teardown::Move || epilogue.teardown == SoftwareFunction::Teardown::Lea)
                    && epilogue.frameRegister != state.frameRegister)
                reg(context, epilogue.frameRegister) = entry - 8 * epilogue.popCount - epilogue.amount;
            // Body code restores MOV-saved registers before the epilogue; their
            // slots still hold the same values when unwinding reads them.
            auto frameBase = state.frameRegister ? reg(context, state.frameRegister) - 16 * (state.recipe[3] >> 4) : context.Rsp;
            for (size_t slot = 0; slot < state.recipe[2];) {
                auto code = state.recipe.data() + 4 + slot * 2;
                unsigned operation = code[1] & 15, slots = operation == 4 || operation == 8 ? 2 : operation == 5 || operation == 9 ? 3
                    : operation == 1 ? ((code[1] >> 4) ? 3 : 2) : 1;
                if (operation == 4 || operation == 5) {
                    DWORD offset = operation == 4 ? *reinterpret_cast<const std::uint16_t*>(code + 2) * 8u
                        : *reinterpret_cast<const std::uint32_t*>(code + 2);
                    reg(context, code[1] >> 4) = *reinterpret_cast<const DWORD64*>(frameBase + offset);
                }
                slot += slots;
            }
            // The analysed teardown and pops, applied one instruction at a time.
            std::vector<CONTEXT> states{context};
            auto current = context;
            if (epilogue.teardown == SoftwareFunction::Teardown::Add) current.Rsp += epilogue.amount;
            else if (epilogue.teardown == SoftwareFunction::Teardown::Lea) current.Rsp = reg(current, epilogue.frameRegister) + epilogue.amount;
            else if (epilogue.teardown == SoftwareFunction::Teardown::Move) current.Rsp = reg(current, epilogue.frameRegister);
            if (epilogue.teardown != SoftwareFunction::Teardown::None) states.push_back(current);
            for (unsigned index = 0; index < epilogue.popCount; ++index) {
                reg(current, epilogue.pops[index]) = *reinterpret_cast<DWORD64*>(current.Rsp);
                current.Rsp += 8;
                states.push_back(current);
            }
            require(current.Rsp == entry, "Analysed teardown does not reach the return address");
            auto returned = current;
            returned.Rip = *reinterpret_cast<DWORD64*>(returned.Rsp);
            returned.Rsp += 8;
            auto expected = unwound(returned);
            const auto& row = list[epilogue.fragment];
            std::vector<std::uint32_t> starts;
            for (const auto& instruction : analysis.instructions())
                if (instruction.rva >= epilogue.start && instruction.rva < epilogue.end) starts.push_back(instruction.rva);
            require(starts.size() == states.size(), "Epilogue positions differ from analysed states");
            auto length = epilogue.end - epilogue.start;
            std::memcpy(displaced, base + epilogue.start, length);
            std::memcpy(displaced + 128, state.recipe.data(), state.recipe.size());
            RUNTIME_FUNCTION copied{0, length, 128};
            for (size_t index = 0; index < starts.size(); ++index) {
                auto original = virtualUnwind(reinterpret_cast<DWORD64>(base), row, reinterpret_cast<DWORD64>(base + starts[index]), states[index]);
                auto copy = virtualUnwind(reinterpret_cast<DWORD64>(displaced), copied,
                    reinterpret_cast<DWORD64>(displaced + (starts[index] - epilogue.start)), states[index]);
                // RET imm16 is unwound as RET by the OS in both code copies.
                if (!epilogue.immediate) require(original == expected, "OS unwind of original epilogue disagrees with analysis");
                require(copy == original, "Displaced epilogue unwinds differently from the original");
                ++positions;
            }
            auto saved = copy[epilogue.start];
            copy[epilogue.start] = 0xcc;
            auto patched = virtualUnwind(reinterpret_cast<DWORD64>(copy), row, reinterpret_cast<DWORD64>(copy + epilogue.start), states[0]);
            copy[epilogue.start] = saved;
            if (!epilogue.immediate && !(patched == expected)) {
                std::fprintf(stderr, "function=%lx start=%x rip=%llx/%llx rsp=%llx/%llx\n", begin, epilogue.start,
                    (unsigned long long)patched.rip, (unsigned long long)expected.rip, (unsigned long long)patched.rsp,
                    (unsigned long long)expected.rsp);
                for (unsigned index = 0; index < 16; ++index) if (patched.registers[index] != expected.registers[index])
                    std::fprintf(stderr, "  r%u %llx/%llx\n", index, (unsigned long long)patched.registers[index],
                        (unsigned long long)expected.registers[index]);
                require(false, "INT3 at the epilogue start changes the OS unwind");
            }
        }
    }
    std::printf("SOFTWARE_FUNCTION_AUDIT image=%s functions=%zu accepted=%u chained=%u handlers=%u epilogues=%u tailJumps=%u exits=%u positions=%u skipped=%u bodyPositions=%u\n",
        argv[1], functions.size(), accepted, chainedAccepted, handlerAccepted, epilogues, jumps, exits, positions, skipped, bodyPositions);
    std::printf("SOFTWARE_BODY_AUDIT image=%s sites=%u rewrittenBranches=%u transactions=%u unrelocatable=%u branchTargetStates=%u\n",
        argv[1], bodySites, rewritten, transactions, unrelocatable, targetStates);
    std::vector<std::pair<unsigned, std::string>> reasons;
    for (const auto& [reason, total] : rejected) reasons.push_back({total, reason});
    std::sort(reasons.rbegin(), reasons.rend());
    for (const auto& [total, reason] : reasons) std::printf("  rejected %s=%u\n", reason.c_str(), total);
}
