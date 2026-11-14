/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsSoftwareSites.h"
#include "windowsSoftwareEntryInstruction.h"
#include "windowsMutex.h"
#include "windowsMappedNativeUnwind.h"
#include "windowsProfiler.h"
#include "codeCache.h"
#include <tlhelp32.h>
#include <winternl.h>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <mutex>
#include <new>
#include <utility>
#include <limits>

namespace WindowsProfiler::SoftwareSites {
namespace {
constexpr size_t capacity = 4096;
alignas(PreparedSite) unsigned char storage[capacity * sizeof(PreparedSite)];
std::atomic<size_t> count{0};
struct ArmState {
    bool once = false, patched = false;
    // Set before the first INT3 is written and never cleared.
    std::atomic<bool> rescue{false};
};
ArmState arms[capacity];
WindowsMutex mutex;
const unsigned char endbr[]{0xf3, 0x0f, 0x1e, 0xfa};
PreparedSite* slot(size_t index) { return std::launder(reinterpret_cast<PreparedSite*>(storage + index * sizeof(PreparedSite))); }
bool read(const void* address, void* output, size_t size) {
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), address, output, size, &copied) && copied == size;
}
using AddTable = NTSTATUS (NTAPI*)(void**, RUNTIME_FUNCTION*, DWORD, DWORD, ULONG_PTR, ULONG_PTR);
using DeleteTable = void (NTAPI*)(void*);
using Allocate2 = void* (WINAPI*)(HANDLE, void*, SIZE_T, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG);
constexpr size_t tableOffset = 64, recipeOffset = 128, pageSize = 4096;
struct Code {
    unsigned char* page = nullptr;
    void* registration = nullptr;
    DeleteTable remove = nullptr;
    size_t size = 0;
    RUNTIME_FUNCTION* functions = nullptr;
    unsigned functionCount = 0;
    std::vector<std::uint8_t> continuations;
    std::vector<Position> positions;
    InstructionDecoder::Relocation relocation{};
    NativeUnwind::Recipe recipe;
    ~Code() {
        if (registration) remove(registration);
        if (page) VirtualFree(page, 0, MEM_RELEASE);
    }
};
// Reserves one page reachable by rel32 from every anchor.
const char* allocate(std::initializer_list<std::uintptr_t> anchors, Code& code) {
    auto allocate2 = reinterpret_cast<Allocate2>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "VirtualAlloc2"));
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    code.remove = reinterpret_cast<DeleteTable>(GetProcAddress(ntdll, "RtlDeleteGrowableFunctionTable"));
    if (!allocate2 || !code.remove || !GetProcAddress(ntdll, "RtlAddGrowableFunctionTable"))
        return "Required native software-probe code/unwind allocation APIs are unavailable";
    SYSTEM_INFO system; GetSystemInfo(&system);
    auto low = reinterpret_cast<std::uintptr_t>(system.lpMinimumApplicationAddress);
    auto high = reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
    for (auto anchor : anchors) {
        low = std::max<std::uintptr_t>(low, anchor > INT32_MAX ? anchor - INT32_MAX : 0);
        high = std::min<std::uintptr_t>(high, anchor < UINTPTR_MAX - INT32_MAX ? anchor + INT32_MAX - pageSize : UINTPTR_MAX);
    }
    auto granularity = static_cast<std::uintptr_t>(system.dwAllocationGranularity);
    low = (low + granularity - 1) & ~(granularity - 1);
    high = ((high + 1) & ~(granularity - 1)) - 1;
    if (high < low || high - low < pageSize - 1) return "No allocation-granularity-aligned native software-probe range";
    MEM_ADDRESS_REQUIREMENTS requirements{};
    requirements.LowestStartingAddress = reinterpret_cast<void*>(low);
    requirements.HighestEndingAddress = reinterpret_cast<void*>(high);
    requirements.Alignment = system.dwAllocationGranularity;
    MEM_EXTENDED_PARAMETER parameter{}; parameter.Type = MemExtendedParameterAddressRequirements; parameter.Pointer = &requirements;
    code.page = static_cast<unsigned char*>(allocate2(GetCurrentProcess(), nullptr, pageSize, MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE, &parameter, 1));
    return code.page ? nullptr : "Cannot reserve near native software-probe staging memory";
}
// Places recipes after the table, then publishes immutable RX code and its unwind ranges.
const char* finish(Code& code, std::initializer_list<std::pair<std::uint32_t, const std::vector<unsigned char>*>> ranges) {
    code.functions = reinterpret_cast<RUNTIME_FUNCTION*>(code.page + tableOffset);
    auto offset = recipeOffset;
    std::uint32_t begin = 0;
    for (auto [end, recipe] : ranges) {
        if (offset + recipe->size() > pageSize) return "Software-probe unwind recipe exceeds staging capacity";
        std::memcpy(code.page + offset, recipe->data(), recipe->size());
        code.functions[code.functionCount++] = {begin, end, static_cast<DWORD>(offset)};
        offset = (offset + recipe->size() + 3) & ~size_t(3);
        begin = end;
    }
    code.size = begin;
    DWORD old;
    if (!VirtualProtect(code.page, pageSize, PAGE_EXECUTE_READ, &old)
            || !FlushInstructionCache(GetCurrentProcess(), code.page, code.size)) return "Cannot finalize immutable software-probe code protection";
    auto add = reinterpret_cast<AddTable>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddGrowableFunctionTable"));
    auto status = add(&code.registration, code.functions, code.functionCount, code.functionCount,
        reinterpret_cast<ULONG_PTR>(code.page), reinterpret_cast<ULONG_PTR>(code.page + code.size));
    if (status < 0 || !code.registration) return "Cannot register native software-probe unwind ranges";
    return nullptr;
}
const char* buildCode(const NativeProbe::LoadedTarget& target, const RUNTIME_FUNCTION& function,
        const NativeUnwind::Source& source, size_t instructionLength, Code& code) {
    auto pc = static_cast<DWORD64>(target.imageBase + function.BeginAddress + source.probeOffset);
    auto instruction = source.code.subspan(source.probeOffset,instructionLength);
    std::array<unsigned char,InstructionDecoder::MAX_INSTRUCTION_BYTES> observed{};
    if (!read(reinterpret_cast<void*>(pc),observed.data(),instructionLength)
            || std::memcmp(observed.data(),instruction.data(),instructionLength))
        return "Software-probe source changed before relocation";
    if (auto error = allocate({pc}, code)) return error;
    auto& relocation = code.relocation;
    if (!InstructionDecoder::relocate(code.page, InstructionDecoder::MAX_RELOCATED_BYTES,
            reinterpret_cast<void*>(pc), source.code.size() - source.probeOffset, relocation))
        return "Software-probe instruction relocation is unsupported or out of range";
    if (relocation.sourceBytes != instructionLength
            || !read(reinterpret_cast<void*>(pc),observed.data(),instructionLength)
            || std::memcmp(observed.data(),instruction.data(),instructionLength))
        return "Software-probe source changed during relocation";
    auto& recipe = code.recipe;
    if (auto error = NativeUnwind::derive(source, relocation, recipe)) return error;
    auto jump = code.page + relocation.destinationBytes;
    auto delta = static_cast<std::int64_t>(pc + relocation.sourceBytes) - reinterpret_cast<std::intptr_t>(jump + 5);
    if (delta < INT32_MIN || delta > INT32_MAX) return "Software-probe continuation leaves rel32 range";
    jump[0] = 0xe9;
    auto relative = static_cast<std::int32_t>(delta); std::memcpy(jump + 1, &relative, sizeof(relative));
    auto end = static_cast<std::uint32_t>(relocation.destinationBytes);
    code.continuations = {0, static_cast<std::uint8_t>(end)};
    // Version-2 recipes without epilogue descriptors never classify the
    // continuation jump as an epilogue.
    return finish(code, {{end, &recipe.before}, {end + 5, &recipe.after}});
}
// RIP-relative memory or direct branch target of a terminator, or zero.
std::uintptr_t reference(std::span<const unsigned char> bytes, std::uintptr_t address) {
    size_t cursor = 0;
    while (cursor < bytes.size() && (bytes[cursor] == 0x2e || bytes[cursor] == 0x3e || bytes[cursor] == 0xf2
            || bytes[cursor] == 0xf3 || (bytes[cursor] & 0xf0) == 0x40)) ++cursor;
    auto next = address + bytes.size();
    std::int32_t displacement;
    if (cursor < bytes.size() && bytes[cursor] == 0xe9) {
        std::memcpy(&displacement, bytes.data() + bytes.size() - 4, 4); return next + displacement;
    }
    if (cursor < bytes.size() && bytes[cursor] == 0xeb) return next + static_cast<std::int8_t>(bytes.back());
    if (cursor + 6 <= bytes.size() && bytes[cursor] == 0xff && (bytes[cursor + 1] & 0xc7) == 0x05) {
        std::memcpy(&displacement, bytes.data() + cursor + 2, 4); return next + displacement;
    }
    return 0;
}
const char* buildReturnCode(const unsigned char* source, std::span<const unsigned char> bytes,
        std::span<const std::uint32_t> lengths, const std::vector<unsigned char>& recipe, Code& code) {
    auto address = reinterpret_cast<std::uintptr_t>(source);
    auto terminator = bytes.subspan(bytes.size() - lengths.back());
    auto target = reference(terminator, address + bytes.size() - lengths.back());
    if (auto error = target ? allocate({address, target}, code) : allocate({address}, code)) return error;
    size_t sourceOffset = 0, destination = 0;
    for (auto length : lengths) {
        if (destination > SoftwareMitigations::MAX_CODE_BYTES - InstructionDecoder::MAX_RELOCATED_BYTES)
            return "Software return-site copy exceeds displaced-code capacity";
        InstructionDecoder::Relocation relocation;
        if (!InstructionDecoder::relocate(code.page + destination, InstructionDecoder::MAX_RELOCATED_BYTES,
                source + sourceOffset, length, relocation) || relocation.sourceBytes != length)
            return "Software return-site relocation is unsupported or out of range";
        code.continuations.push_back(static_cast<std::uint8_t>(destination));
        sourceOffset += length;
        destination += relocation.destinationBytes;
    }
    std::array<unsigned char, MAX_ORIGINAL_BYTES> observed{};
    if (!read(source, observed.data(), bytes.size()) || std::memcmp(observed.data(), bytes.data(), bytes.size()))
        return "Software return-site source changed during relocation";
    return finish(code, {{static_cast<std::uint32_t>(destination), &recipe}});
}
}
struct Failure {
    DWORD error = 0;
    ~Failure() { if (error) SetLastError(error); }
};
struct Function;
struct Builder {
    static const char* epilogue(const NativeProbe::LoadedTarget& target, const Function& function,
        const SoftwareFunction::Epilogue& epilogue, const PreparedSite*& prepared, Failure& failure);
    static const char* body(const NativeProbe::LoadedTarget& target, const Function& function, std::uint32_t rva,
        unsigned fragment, const PreparedSite*& prepared, Failure& failure);
};
namespace {
// The slot stays unpublished until count includes it.
PreparedSite* construct(size_t size) { return new (storage + size * sizeof(PreparedSite)) PreparedSite(); }
SoftwareMitigations::Result mitigate(const Code& code) {
    return SoftwareMitigations::prepare(code.page, code.size, code.continuations);
}
}

bool PreparedSite::currentMapping() const { return _mappingEpoch && _cache->windowsLoadEpoch() == _mappingEpoch; }
SiteLease::SiteLease(SiteLease&& other) noexcept { *this = std::move(other); }
SiteLease& SiteLease::operator=(SiteLease&& other) noexcept {
    if (this == &other) return *this;
    reset(); _sites = std::move(other._sites); other._sites.clear(); _exits = std::move(other._exits); other._exits.clear();
    _module = std::exchange(other._module, nullptr);
    return *this;
}
SiteLease::~SiteLease() { reset(); }
void SiteLease::reset() {
    auto module = std::exchange(_module, nullptr);
    _sites.clear(); _exits.clear();
    // FreeLibrary can execute a source DLL's detach code. Never hold the
    // preparation lock or destroy immutable rescue data during this call.
    if (module) FreeLibrary(module);
}
const char* prepare(NativeProbe::LoadedTarget&& target, SiteLease& result) {
    Failure failure;
    if (!target.module() || !target.currentMapping()) return "Software-probe target mapping is no longer current";
    std::array<unsigned char, InstructionDecoder::MAX_INSTRUCTION_BYTES> bytes{};
    auto readable = std::min(target.readable, bytes.size());
    if (!readable || !read(target.address, bytes.data(), readable)) return "Cannot snapshot software-probe source bytes";
    auto requestedLength = InstructionDecoder::length(bytes.data(),readable);
    if (!requestedLength) return "Software-probe source instruction is unsupported or truncated";
    DWORD64 image = 0;
    auto found = lookupFunctionEntry(reinterpret_cast<DWORD64>(target.address),&image);
    if (!found || image != target.imageBase)
        return "Software-probe native function unwind metadata is unavailable or unsupported";
    auto original = *found;
    // Only the certified prolog subset keeps the Entry form.
    NativeUnwind::SourceSnapshot snapshot;
    if (NativeUnwind::snapshotMapped(target.module(),target.imageSize,original,
            reinterpret_cast<DWORD64>(target.address),requestedLength,snapshot)) return prepareBody(std::move(target), result);
    auto source = snapshot.source();
    if (NativeUnwind::validateBoundary(source,source.probeOffset)) return prepareBody(std::move(target), result);
    if (std::memcmp(bytes.data(),source.code.data() + source.probeOffset,requestedLength))
        return "Software-probe requested instruction changed";
    auto requested = source.code.subspan(source.probeOffset);
    if (requested.size() >= sizeof(endbr) && !std::memcmp(requested.data(),endbr,sizeof(endbr)))
        source.probeOffset += sizeof(endbr);
    if (NativeUnwind::validateBoundary(source,source.probeOffset)) return prepareBody(std::move(target), result);
    readable = std::min(bytes.size(),source.code.size() - source.probeOffset);
    std::memcpy(bytes.data(),source.code.data() + source.probeOffset,readable);
    if (bytes[0] == 0xcc) return "Software-probe source already contains a breakpoint";
    auto length = InstructionDecoder::length(bytes.data(),readable);
    if (!length) return "Software-probe source instruction is unsupported or truncated";
    auto patched = reinterpret_cast<const unsigned char*>(image + original.BeginAddress + source.probeOffset);
    unsigned prefix = source.code.size() >= sizeof(endbr) && !std::memcmp(source.code.data(),endbr,sizeof(endbr))
        ? sizeof(endbr) : 0;
    {
        std::array<unsigned char, InstructionDecoder::MAX_RELOCATED_BYTES> scratch{};
        InstructionDecoder::Relocation trial;
        NativeUnwind::Recipe certified;
        if (!InstructionDecoder::relocate(scratch.data(), scratch.size(), patched, source.code.size() - source.probeOffset, trial)
                || NativeUnwind::certifyInstruction(source, trial, certified)) return prepareBody(std::move(target), result);
    }
    const PreparedSite* prepared = nullptr;
    {
        std::lock_guard lock(mutex);
        if (!target.currentMapping()) return "Software-probe target mapping changed during preparation";
        auto size = count.load(std::memory_order_relaxed);
        for (size_t index = 0; index < size; ++index) {
            auto candidate = slot(index);
            if (candidate->kind() == SiteKind::Entry && candidate->source() == patched
                    && candidate->mappingEpoch() == target.mappingEpoch && candidate->currentMapping()) {
                if (std::memcmp(&candidate->_original,&original,sizeof(original)) || candidate->instruction().size() != length
                        || std::memcmp(candidate->instruction().data(),bytes.data(),length))
                    return "Prepared software-probe source changed";
                if (!candidate->_prologue.empty()
                        && (source.code.size() < candidate->_prologue.size()
                            || !std::equal(candidate->_prologue.begin(),candidate->_prologue.end(),source.code.begin())
                            || source.unwind.size() != candidate->_unwind.size()
                            || !std::equal(candidate->_unwind.begin(),candidate->_unwind.end(),source.unwind.begin())))
                    return "Prepared software-probe prologue/unwind certificate changed";
                NativeUnwind::Recipe recipe;
                if (auto error = NativeUnwind::derive(source,candidate->_relocation,recipe)) return error;
                if (recipe.before != candidate->_recipe.before || recipe.after != candidate->_recipe.after
                        || recipe.sourceVersion != candidate->_recipe.sourceVersion)
                    return "Prepared software-probe unwind recipe changed";
                if (auto error = validateSource(*candidate)) return error;
                prepared = candidate; break;
            }
        }
        if (!prepared) {
            if (size == capacity) return "Software-probe immutable site capacity exhausted";
            auto path = target.path;
            std::vector<unsigned char> prologue, unwind;
            if (!(source.unwind[0] >> 3)) {
                auto codeBytes = source.unwind[1] ? static_cast<size_t>(source.unwind[1]) : length;
                prologue.assign(source.code.begin(),source.code.begin() + codeBytes);
                unwind.assign(source.unwind.begin(),source.unwind.end());
            }
            Code code;
            if (auto error = buildCode(target,original,source,length,code)) return error;
            NativeUnwind::SourceSnapshot checked;
            if (auto error = NativeUnwind::snapshotMapped(target.module(),target.imageSize,original,
                    reinterpret_cast<DWORD64>(patched),length,checked)) return error;
            auto current = checked.source();
            NativeUnwind::Recipe recipe;
            if (auto error = NativeUnwind::derive(current,code.relocation,recipe)) return error;
            if (current.code.size() != source.code.size()
                    || std::memcmp(current.code.data() + current.probeOffset,bytes.data(),length)
                    || (!prologue.empty() && (!std::equal(prologue.begin(),prologue.end(),current.code.begin())
                        || current.unwind.size() != unwind.size() || !std::equal(unwind.begin(),unwind.end(),current.unwind.begin())))
                    || recipe.before != code.recipe.before || recipe.after != code.recipe.after
                    || recipe.sourceVersion != code.recipe.sourceVersion)
                return "Software-probe source/unwind certificate changed during preparation";
            if (!target.currentMapping()) return "Software-probe module changed while preparing code";
            auto mitigations = mitigate(code);
            if (mitigations.error && !mitigations.registrationPossible) {
                failure.error = mitigations.error;
                return "Cannot prepare software-probe mitigation metadata";
            }
            // Partial/uncertain registration retains immutable code under the ordinary site bound.
            auto site = construct(size);
            site->_kind = SiteKind::Entry;
            site->_entry = reinterpret_cast<const unsigned char*>(target.imageBase + original.BeginAddress);
            site->_source = patched; site->_imageBase = target.imageBase; site->_cache = target.cache;
            site->_mappingEpoch = target.mappingEpoch; site->_path = std::move(path);
            std::memcpy(site->_bytes.data(), bytes.data(), length);
            site->_length = static_cast<unsigned>(length); site->_prefix = prefix;
            site->_xol = code.page; site->_xolSize = code.size; site->_functions = code.functions;
            site->_functionCount = code.functionCount; site->_unwindRegistration = code.registration;
            site->_mitigations = mitigations; site->_original = original; site->_imageSize = target.imageSize;
            site->_prologue = std::move(prologue); site->_unwind = std::move(unwind);
            site->_relocation = code.relocation; site->_recipe = std::move(code.recipe);
            site->_positions = {{0, 0}, {code.continuations[1], static_cast<std::int16_t>(length)}};
            code.page = nullptr; code.registration = nullptr;
            count.store(size + 1, std::memory_order_release);
            prepared = site;
        }
        if (prepared->mitigations().error) {
            failure.error = prepared->mitigations().error;
            return "Cannot prepare software-probe mitigation metadata";
        }
    }
    SiteLease lease;
    lease._sites = {prepared}; lease._module = target.releaseModule();
    result = std::move(lease);
    return nullptr;
}
// One function's complete coverage, decoded from a snapshot that outlives it.
struct Function {
    RUNTIME_FUNCTION primary{};
    NativeUnwind::CoverageSnapshot coverage;
    std::vector<SoftwareFunction::Fragment> fragments;
    SoftwareFunction::Analysis analysis;
    const char* analyze(const NativeProbe::LoadedTarget& target, const RUNTIME_FUNCTION& row) {
        primary = row;
        for (unsigned depth = 0;; ++depth) {
            std::array<unsigned char, 4> header{};
            if (depth > NativeUnwind::MAX_MAPPED_CHAIN
                    || !read(reinterpret_cast<const void*>(target.imageBase + primary.UnwindData), header.data(), header.size()))
                return "mapped-unwind-chain-read";
            if (!(header[0] & 0x20)) break;
            auto padded = 4 + ((header[2] + 1u) & ~1u) * 2;
            if (!read(reinterpret_cast<const void*>(target.imageBase + primary.UnwindData + padded), &primary, sizeof(primary)))
                return "mapped-unwind-chain-read";
        }
        if (auto error = NativeUnwind::snapshotCoverage(target.module(), target.imageSize, primary, coverage)) return error;
        for (size_t index = 0; index < coverage.fragments(); ++index)
            fragments.push_back({coverage.identity(index).BeginAddress, coverage.source(index)});
        return analysis.analyze(fragments, coverage.handler());
    }
};
// Caller holds the site mutex; publishes or reuses the displaced epilogue.
const char* Builder::epilogue(const NativeProbe::LoadedTarget& target, const Function& function,
        const SoftwareFunction::Epilogue& epilogue, const PreparedSite*& prepared, Failure& failure) {
    std::array<unsigned char, MAX_ORIGINAL_BYTES> bytes{};
    std::vector<std::uint32_t> lengths;
    size_t length = 0;
    for (const auto& instruction : function.analysis.instructions()) {
        if (instruction.rva < epilogue.start || instruction.rva >= epilogue.end) continue;
        auto code = function.coverage.source(instruction.fragment).code;
        if (length + instruction.length > bytes.size()) return "Software return-site epilogue exceeds capacity";
        std::memcpy(bytes.data() + length, code.data() + (instruction.rva - function.fragments[instruction.fragment].begin),
            instruction.length);
        length += instruction.length;
        lengths.push_back(instruction.length);
    }
    auto source = reinterpret_cast<const unsigned char*>(target.imageBase + epilogue.start);
    const auto& recipe = function.analysis.state(epilogue.state).recipe;
    const auto& row = function.coverage.identity(epilogue.fragment);
    auto size = count.load(std::memory_order_relaxed);
    for (size_t index = 0; index < size; ++index) {
        auto candidate = slot(index);
        if (candidate->kind() != SiteKind::Return || candidate->source() != source
                || candidate->mappingEpoch() != target.mappingEpoch || !candidate->currentMapping()) continue;
        const auto& previous = candidate->_epilogue;
        if (candidate->_length != length || std::memcmp(candidate->_bytes.data(), bytes.data(), length)
                || std::memcmp(&candidate->_original, &row, sizeof(row)) || candidate->_recipe.before != recipe
                || previous.end != epilogue.end || previous.terminator != epilogue.terminator
                || previous.teardown != epilogue.teardown || previous.amount != epilogue.amount
                || previous.frameRegister != epilogue.frameRegister || previous.popCount != epilogue.popCount
                || previous.pops != epilogue.pops || previous.jump != epilogue.jump || previous.immediate != epilogue.immediate)
            return "Prepared software return site changed";
        if (auto error = validateSource(*candidate)) return error;
        prepared = candidate;
        break;
    }
    if (!prepared) {
        if (size == capacity) return "Software-probe immutable site capacity exhausted";
        Code code;
        if (auto error = buildReturnCode(source, {bytes.data(), length}, lengths, recipe, code)) return error;
        if (!target.currentMapping()) return "Software-probe module changed while preparing code";
        auto mitigations = mitigate(code);
        if (mitigations.error && !mitigations.registrationPossible) {
            failure.error = mitigations.error;
            return "Cannot prepare software-probe mitigation metadata";
        }
        auto site = construct(size);
        site->_kind = SiteKind::Return;
        site->_entry = reinterpret_cast<const unsigned char*>(target.imageBase + function.primary.BeginAddress);
        site->_source = source; site->_imageBase = target.imageBase;
        site->_cache = target.cache; site->_mappingEpoch = target.mappingEpoch; site->_path = target.path;
        site->_bytes = bytes; site->_length = static_cast<unsigned>(length);
        site->_xol = code.page; site->_xolSize = code.size; site->_functions = code.functions;
        site->_functionCount = code.functionCount; site->_unwindRegistration = code.registration;
        site->_mitigations = mitigations; site->_original = row; site->_imageSize = target.imageSize;
        site->_recipe.before = recipe; site->_recipe.sourceVersion = recipe[0];
        site->_epilogue = epilogue;
        size_t offset = 0;
        for (size_t index = 0; index < lengths.size(); ++index) {
            site->_positions.push_back({code.continuations[index], static_cast<std::int16_t>(offset)});
            offset += lengths[index];
        }
        code.page = nullptr; code.registration = nullptr;
        count.store(size + 1, std::memory_order_release);
        prepared = site;
    }
    if (prepared->mitigations().error) {
        failure.error = prepared->mitigations().error;
        return "Cannot prepare software-probe mitigation metadata";
    }
    return nullptr;
}
const char* prepareReturns(NativeProbe::LoadedTarget&& target, SiteLease& result) {
    Failure failure;
    if (!target.module() || !target.currentMapping()) return "Software-probe target mapping is no longer current";
    DWORD64 image = 0;
    auto found = lookupFunctionEntry(reinterpret_cast<DWORD64>(target.address), &image);
    if (!found || image != target.imageBase) return "Software return-probe function unwind metadata is unavailable";
    auto begin = reinterpret_cast<const unsigned char*>(target.imageBase + found->BeginAddress);
    std::array<unsigned char, sizeof(endbr)> head{};
    bool alias = target.address == begin + sizeof(endbr) && read(begin, head.data(), head.size())
        && !std::memcmp(head.data(), endbr, sizeof(endbr));
    if (target.address != begin && !alias) return "Software return probes require a function entry";
    Function function;
    if (auto error = function.analyze(target, *found)) return error;
    if (std::memcmp(&function.primary, found, sizeof(*found))) return "Software return probes require a primary function entry";
    if (auto error = function.analysis.returnError()) return error;
    if (function.analysis.epilogues().empty()) return "Software return-probe function has no normal return site";
    std::vector<const PreparedSite*> sites;
    std::lock_guard lock(mutex);
    if (!target.currentMapping()) return "Software-probe target mapping changed during preparation";
    for (const auto& epilogue : function.analysis.epilogues()) {
        const PreparedSite* prepared = nullptr;
        if (auto error = Builder::epilogue(target, function, epilogue, prepared, failure)) return error;
        sites.push_back(prepared);
    }
    std::vector<ExitPath> exits;
    for (const auto& exit : function.analysis.exits()) {
        unsigned fragment = 0;
        const SoftwareFunction::Epilogue* inside = nullptr;
        auto position = function.analysis.classify(exit.branch, fragment, inside);
        if (position != SoftwareFunction::Position::Body && position != SoftwareFunction::Position::Prolog)
            return "Software return-probe early exit is not a displaceable branch";
        const PreparedSite* prepared = nullptr;
        if (auto error = Builder::body(target, function, exit.branch, fragment, prepared, failure)) return error;
        const auto& epilogue = function.analysis.epilogues()[exit.epilogue];
        ExitPath path{prepared, exit.condition, static_cast<unsigned char>(epilogue.popCount - exit.firstPop), {}, epilogue.jump,
            epilogue.immediate};
        std::copy(epilogue.pops.begin() + exit.firstPop, epilogue.pops.begin() + epilogue.popCount, path.pops.begin());
        sites.push_back(prepared);
        exits.push_back(path);
    }
    SiteLease lease;
    lease._sites = std::move(sites); lease._exits = std::move(exits); lease._module = target.releaseModule();
    result = std::move(lease);
    return nullptr;
}
namespace {
// Displaced instruction and jump back with version-2 recipes, which never
// classify a jump as an epilogue. Every image address stays in rel32 reach.
// The jump ending a rewritten branch's taken path holds the after state too.
const char* buildBodyCode(const NativeProbe::LoadedTarget& target, const unsigned char* source, size_t length,
        const std::vector<unsigned char>& before, const std::vector<unsigned char>& after, Code& code) {
    if (auto error = allocate({target.imageBase, target.imageBase + target.imageSize - 1}, code)) return error;
    auto& relocation = code.relocation;
    if (!InstructionDecoder::relocate(code.page, InstructionDecoder::MAX_RELOCATED_BYTES, source, length, relocation)
            || relocation.sourceBytes != length)
        return "Software-probe instruction relocation is unsupported or out of range";
    auto jump = code.page + relocation.destinationBytes;
    auto delta = reinterpret_cast<std::intptr_t>(source + length) - reinterpret_cast<std::intptr_t>(jump + 5);
    if (delta < INT32_MIN || delta > INT32_MAX) return "Software-probe continuation leaves rel32 range";
    jump[0] = 0xe9;
    auto relative = static_cast<std::int32_t>(delta); std::memcpy(jump + 1, &relative, sizeof(relative));
    auto end = static_cast<std::uint8_t>(relocation.destinationBytes);
    auto completed = static_cast<std::uint8_t>(relocation.completed);
    auto next = static_cast<std::int16_t>(length);
    code.continuations = {0, completed};
    code.positions = {{0, 0}, {completed, next}};
    if (relocation.taken) {
        auto taken = static_cast<std::uint8_t>(relocation.taken);
        code.continuations.insert(code.continuations.end(), {taken, end});
        code.positions.insert(code.positions.end(), {{taken,
            static_cast<std::int16_t>(static_cast<const unsigned char*>(relocation.branchTarget) - source)}, {end, next}});
    }
    code.recipe.before = before; code.recipe.after = after;
    code.recipe.before[0] = code.recipe.after[0] = 2;
    return finish(code, {{completed, &code.recipe.before}, {static_cast<std::uint32_t>(end + 5), &code.recipe.after}});
}
}
// Caller holds the site mutex; publishes or reuses a displaced body instruction.
const char* Builder::body(const NativeProbe::LoadedTarget& target, const Function& function, std::uint32_t rva, unsigned fragment,
        const PreparedSite*& prepared, Failure& failure) {
    auto instructions = function.analysis.instructions();
    auto instruction = std::lower_bound(instructions.begin(), instructions.end(), rva,
        [](const SoftwareFunction::Analysis::Instruction& value, std::uint32_t key) { return value.rva < key; });
    auto source = reinterpret_cast<const unsigned char*>(target.imageBase + rva);
    if (*source == 0xcc) return "Software-probe source already contains a breakpoint";
    if (SoftwareFunction::Analysis::calls(*instruction))
        return "Software-probe call sites need return-address translation";
    auto offset = rva - function.fragments[fragment].begin;
    auto next = rva + instruction->length;
    NativeUnwind::BodyState before, after;
    const auto& state = function.fragments[fragment].source;
    if (auto error = NativeUnwind::bodyState(state, true, before, offset)) return error;
    if (auto error = NativeUnwind::bodyState(state, true, after, offset + instruction->length)) return error;
    if (before.size != after.size || before.pushes != after.pushes || before.frameRegister != after.frameRegister
            || before.frameSize != after.frameSize)
        return "Software-probe prolog operation needs a certified unwind effect";
    if (instruction + 1 != instructions.end() && instruction[1].rva == next && !function.analysis.bodyEquivalent(next))
        return "Software-probe continuation is an epilogue position the displaced code cannot reproduce";
    auto size = count.load(std::memory_order_relaxed);
    for (size_t index = 0; index < size && !prepared; ++index) {
        auto candidate = slot(index);
        if (candidate->kind() != SiteKind::Body || candidate->source() != source
                || candidate->mappingEpoch() != target.mappingEpoch || !candidate->currentMapping()) continue;
        if (candidate->_length != instruction->length || std::memcmp(candidate->_bytes.data(), source, instruction->length)
                || candidate->_recipe.before.size() != before.recipe.size()
                || !std::equal(before.recipe.begin() + 1, before.recipe.end(), candidate->_recipe.before.begin() + 1)
                || !std::equal(after.recipe.begin() + 1, after.recipe.end(), candidate->_recipe.after.begin() + 1))
            return "Prepared software-probe body site changed";
        if (auto error = validateSource(*candidate)) return error;
        prepared = candidate;
    }
    if (!prepared) {
        if (size == capacity) return "Software-probe immutable site capacity exhausted";
        Code code;
        if (auto error = buildBodyCode(target, source, instruction->length, before.recipe, after.recipe, code)) return error;
        if (code.relocation.taken) {
            // The displaced jump to the target stands for it with the branch's state.
            auto branch = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(code.relocation.branchTarget) - target.imageBase);
            unsigned reached = 0;
            const SoftwareFunction::Epilogue* entered = nullptr;
            auto position = function.analysis.classify(branch, reached, entered);
            NativeUnwind::BodyState state;
            if (position == SoftwareFunction::Position::EpilogueInterior || !function.analysis.bodyEquivalent(branch)
                    || NativeUnwind::bodyState(function.fragments[reached].source, true, state, branch - function.fragments[reached].begin)
                    || state.size != after.size || state.pushes != after.pushes || state.frameRegister != after.frameRegister
                    || state.frameSize != after.frameSize)
                return "Software-probe branch target has an unwind state the displaced jump cannot reproduce";
        }
        std::array<unsigned char, MAX_ORIGINAL_BYTES> bytes{};
        if (!read(source, bytes.data(), instruction->length)
                || std::memcmp(bytes.data(), function.coverage.source(fragment).code.data() + offset, instruction->length))
            return "Software-probe source changed during relocation";
        if (!target.currentMapping()) return "Software-probe module changed while preparing code";
        auto mitigations = mitigate(code);
        if (mitigations.error && !mitigations.registrationPossible) {
            failure.error = mitigations.error;
            return "Cannot prepare software-probe mitigation metadata";
        }
        auto site = construct(size);
        site->_kind = SiteKind::Body;
        site->_entry = reinterpret_cast<const unsigned char*>(target.imageBase + function.primary.BeginAddress);
        site->_source = source; site->_imageBase = target.imageBase;
        site->_cache = target.cache; site->_mappingEpoch = target.mappingEpoch; site->_path = target.path;
        site->_bytes = bytes; site->_length = instruction->length;
        site->_xol = code.page; site->_xolSize = code.size; site->_functions = code.functions;
        site->_functionCount = code.functionCount; site->_unwindRegistration = code.registration;
        site->_mitigations = mitigations; site->_original = function.coverage.identity(fragment); site->_imageSize = target.imageSize;
        site->_relocation = code.relocation; site->_recipe = std::move(code.recipe);
        site->_positions = std::move(code.positions);
        code.page = nullptr; code.registration = nullptr;
        count.store(size + 1, std::memory_order_release);
        prepared = site;
    }
    if (prepared->mitigations().error) {
        failure.error = prepared->mitigations().error;
        return "Cannot prepare software-probe mitigation metadata";
    }
    return nullptr;
}
const char* prepareBody(NativeProbe::LoadedTarget&& target, SiteLease& result) {
    Failure failure;
    if (!target.module() || !target.currentMapping()) return "Software-probe target mapping is no longer current";
    DWORD64 image = 0;
    auto found = lookupFunctionEntry(reinterpret_cast<DWORD64>(target.address), &image);
    if (!found || image != target.imageBase) return "Software-probe native function unwind metadata is unavailable or unsupported";
    Function function;
    if (auto error = function.analyze(target, *found)) return error;
    auto rva = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(target.address) - target.imageBase);
    auto primary = function.coverage.source(0).code;
    if (rva == function.primary.BeginAddress && primary.size() >= sizeof(endbr) && !std::memcmp(primary.data(), endbr, sizeof(endbr)))
        rva += sizeof(endbr);
    unsigned fragment = 0;
    const SoftwareFunction::Epilogue* epilogue = nullptr;
    auto position = function.analysis.classify(rva, fragment, epilogue);
    if (position == SoftwareFunction::Position::Unproven) return "Software-probe offset is not a proven instruction of its function";
    if (position == SoftwareFunction::Position::EpilogueInterior)
        return "Software-probe offset lies inside an epilogue, whose OS unwind an INT3 would change";
    const PreparedSite* prepared = nullptr;
    std::lock_guard lock(mutex);
    if (!target.currentMapping()) return "Software-probe target mapping changed during preparation";
    if (position == SoftwareFunction::Position::EpilogueStart) {
        if (auto error = Builder::epilogue(target, function, *epilogue, prepared, failure)) return error;
    } else if (auto error = Builder::body(target, function, rva, fragment, prepared, failure)) return error;    SiteLease lease;
    lease._sites = {prepared}; lease._module = target.releaseModule();
    result = std::move(lease);
    return nullptr;
}
const char* validateSource(const PreparedSite& site) {
    if (!site.currentMapping()) return "Prepared software-probe mapping was unloaded or replaced";
    std::array<unsigned char, MAX_ORIGINAL_BYTES> bytes{};
    if (site.preservedPrefix() && (!read(site.entry(), bytes.data(), sizeof(endbr)) || std::memcmp(bytes.data(), endbr, sizeof(endbr))))
        return "Prepared software-probe ENDBR prefix changed";
    auto instruction = site.instruction();
    if (!read(site.source(), bytes.data(), instruction.size()) || std::memcmp(bytes.data(), instruction.data(), instruction.size()))
        return "Prepared software-probe instruction bytes changed";
    if (site.kind() == SiteKind::Return) {
        DWORD64 image = 0;
        auto row = lookupFunctionEntry(reinterpret_cast<DWORD64>(site.source()), &image);
        if (!row || image != site.imageBase() || std::memcmp(row, &site._original, sizeof(*row)))
            return "Prepared software return-site native row changed";
    } else if (!site._prologue.empty()) {
        DWORD64 image = 0;
        auto row = lookupFunctionEntry(reinterpret_cast<DWORD64>(site.source()),&image);
        if (!row || image != site.imageBase() || std::memcmp(row,&site._original,sizeof(*row)))
            return "Prepared software-probe selected native row changed";
        NativeUnwind::SourceSnapshot snapshot;
        if (auto error = NativeUnwind::snapshotMapped(reinterpret_cast<HMODULE>(image),site._imageSize,site._original,
                reinterpret_cast<DWORD64>(site.source()),instruction.size(),snapshot)) return error;
        auto source = snapshot.source();
        if (source.code.size() < site._prologue.size()
                || !std::equal(site._prologue.begin(),site._prologue.end(),source.code.begin())
                || source.unwind.size() != site._unwind.size()
                || !std::equal(site._unwind.begin(),site._unwind.end(),source.unwind.begin())
                || std::memcmp(source.code.data() + source.probeOffset,instruction.data(),instruction.size()))
            return "Prepared software-probe prologue/unwind certificate changed";
        NativeUnwind::Recipe recipe;
        if (auto error = NativeUnwind::derive(source,site._relocation,recipe)) return error;
        if (recipe.before != site._recipe.before || recipe.after != site._recipe.after
                || recipe.sourceVersion != site._recipe.sourceVersion)
            return "Prepared software-probe unwind recipe changed";
    }
    return site.currentMapping() ? nullptr : "Prepared software-probe mapping changed during validation";
}
const char* validateEntry(const PreparedSite& site) {
    if (auto error = validateSource(site)) return error;
    if (site._prologue.empty()) return "Software probes require unchained native metadata without original handlers";
    NativeUnwind::Source source{site._prologue,site._unwind,
        reinterpret_cast<std::uintptr_t>(site.source()) - reinterpret_cast<std::uintptr_t>(site.entry())};
    NativeUnwind::Recipe recipe;
    if (auto error = NativeUnwind::certifyInstruction(source,site._relocation,recipe)) return error;
    if (recipe.before != site._recipe.before || recipe.after != site._recipe.after)
        return "Software-probe certified unwind recipe changed";
    if (site._relocation.sourceBytes != site._relocation.destinationBytes
            || std::memcmp(site.displaced(),site.instruction().data(),site.instruction().size()))
        return "Software-probe certified relocation changed";
    return nullptr;
}
namespace {
size_t indexOf(const PreparedSite* site) {
    return static_cast<size_t>(reinterpret_cast<const unsigned char*>(site) - storage) / sizeof(PreparedSite);
}
using QueryThread = NTSTATUS (NTAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
struct BasicThreadInformation {
    NTSTATUS exitStatus;
    void* teb;
    void* clientId[2];
    KAFFINITY affinity;
    LONG priority, basePriority;
};
bool trapAt(DWORD64 pc, std::span<const PreparedSite* const> sites) {
    for (auto site : sites) {
        auto source = reinterpret_cast<DWORD64>(site->source());
        if (pc == source || pc == source + 1) return true;
    }
    return false;
}
// A suspended thread can still deliver an earlier trap while its user context
// is at the trap or its stack holds KiUserExceptionDispatcher's frame for it.
// Reads stay within the thread's stack as long as PE metadata describes its
// frames, the same premise as sampled native unwinding.
bool deliveringTrap(HANDLE thread, std::span<const PreparedSite* const> sites, DWORD64 dispatcherBegin, DWORD64 dispatcherEnd,
        QueryThread query) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    BasicThreadInformation information{};
    if (!GetThreadContext(thread, &context) || query(thread, 0, &information, sizeof(information), nullptr) < 0)
        return WaitForSingleObject(thread, 0) != WAIT_OBJECT_0;
    if (trapAt(context.Rip, sites)) return true;
    auto stackBase = reinterpret_cast<DWORD64>(static_cast<const NT_TIB*>(information.teb)->StackBase);
    // Clang's GNU target catches only faults raised inside calls made from
    // __try; every stack read here happens inside RtlVirtualUnwind.
    __try {
        for (unsigned depth = 0; depth < 1024; ++depth) {
            DWORD64 image = 0;
            auto entry = lookupFunctionEntry(context.Rip, &image);
            if (!entry) return false;
            bool dispatcher = context.Rip >= dispatcherBegin && context.Rip < dispatcherEnd;
            auto previous = context.Rsp;
            void* handler; DWORD64 establisher;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, context.Rip, entry, &context, &handler, &establisher, nullptr);
            if (dispatcher && trapAt(context.Rip, sites)) return true;
            if (context.Rsp <= previous || context.Rsp >= stackBase || !context.Rip) return false;
        }
    } __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION || GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR
            ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {}
    return false;
}
const char* pendingTraps(std::span<const PreparedSite* const> sites) {
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto query = reinterpret_cast<QueryThread>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    auto dispatcher = reinterpret_cast<DWORD64>(GetProcAddress(ntdll, "KiUserExceptionDispatcher"));
    DWORD64 image = 0;
    auto row = dispatcher ? lookupFunctionEntry(dispatcher, &image) : nullptr;
    if (!query || !row) return "Cannot inspect earlier software-probe trap delivery";
    auto dispatcherBegin = image + row->BeginAddress, dispatcherEnd = image + row->EndAddress;
    auto deadline = GetTickCount64() + 1000;
    for (std::vector<DWORD> threads;; threads.clear()) {
        auto snapshot = toolhelpSnapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return "Cannot enumerate threads for software-probe rearm";
        THREADENTRY32 entry{sizeof(entry)};
        if (Thread32First(snapshot, &entry)) do {
            if (entry.th32OwnerProcessID == GetCurrentProcessId() && entry.th32ThreadID != GetCurrentThreadId())
                threads.push_back(entry.th32ThreadID);
        } while (Thread32Next(snapshot, &entry));
        CloseHandle(snapshot);
        bool pending = false;
        for (auto tid : threads) {
            auto thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE, FALSE, tid);
            if (!thread) continue;
            if (SuspendThread(thread) != static_cast<DWORD>(-1)) {
                // No allocation or lock acquisition while the thread is suspended.
                pending = deliveringTrap(thread, sites, dispatcherBegin, dispatcherEnd, query);
                ResumeThread(thread);
            }
            CloseHandle(thread);
            if (pending) break;
        }
        if (!pending) return nullptr;
        if (GetTickCount64() >= deadline) return "An earlier software-probe hit is still being dispatched; retry the recording";
        Sleep(1);
    }
}
// Caller holds the site mutex. False leaves ownership uncertain.
bool exchange(const PreparedSite& site, unsigned char expected, unsigned char replacement, const char*& error) {
    auto address = const_cast<unsigned char*>(site.source());
    DWORD protection = 0;
    if (!VirtualProtect(address,1,PAGE_EXECUTE_READWRITE,&protection)) { error = "Cannot make software-probe source writable"; return true; }
    auto previous = static_cast<unsigned char>(_InterlockedCompareExchange8(reinterpret_cast<volatile char*>(address),
        static_cast<char>(replacement),static_cast<char>(expected)));
    auto flushed = previous != expected || FlushInstructionCache(GetCurrentProcess(),address,1);
    DWORD ignored;
    auto protectedAgain = VirtualProtect(address,1,protection,&ignored);
    if (previous != expected) {
        error = replacement == 0xcc ? "Software-probe source byte changed before atomic installation"
            : "Software-probe source ownership was lost; foreign byte preserved";
        return protectedAgain;
    }
    auto& state = arms[indexOf(&site)];
    state.patched = replacement == 0xcc;
    if (state.patched) state.once = true;
    if (!flushed || !protectedAgain) { error = "Cannot finalize software-probe source protection/cache"; return false; }
    return true;
}
}
ArmResult arm(std::span<const PreparedSite* const> sites) {
    std::lock_guard lock(mutex);
    std::vector<const PreparedSite*> rearmed;
    for (auto site : sites) {
        auto& state = arms[indexOf(site)];
        if (state.patched) return {"Software-probe site is already armed",false};
        if (auto error = site->kind() == SiteKind::Entry ? validateEntry(*site) : validateSource(*site)) return {error,false};
        if (state.once) rearmed.push_back(site);
    }
    if (!rearmed.empty()) if (auto error = pendingTraps(rearmed)) return {error,false};
    ArmResult result;
    for (size_t armed = 0; armed < sites.size(); ++armed) {
        auto site = sites[armed];
        arms[indexOf(site)].rescue.store(true, std::memory_order_release);
        const char* error = nullptr;
        auto certain = exchange(*site, site->instruction()[0], 0xcc, error);
        result.rescueOwned |= arms[indexOf(site)].patched;
        if (!error) continue;
        result.error = error;
        result.retainLease = !certain;
        // Every site or none: restore the sites this call installed.
        for (size_t restored = 0; restored <= armed; ++restored) {
            if (!arms[indexOf(sites[restored])].patched) continue;
            const char* ignored = nullptr;
            if (!exchange(*sites[restored], 0xcc, sites[restored]->instruction()[0], ignored) || ignored) result.retainLease = true;
        }
        return result;
    }
    return result;
}
const char* disarm(std::span<const PreparedSite* const> sites) {
    std::lock_guard lock(mutex);
    const char* failed = nullptr;
    for (auto site : sites) {
        if (!arms[indexOf(site)].patched) continue;
        if (!site->currentMapping()) { failed = "Armed software-probe mapping changed before restoration"; continue; }
        const char* error = nullptr;
        exchange(*site, 0xcc, site->instruction()[0], error);
        if (error) failed = error;
    }
    return failed;
}
const PreparedSite* rescue(const void* address) noexcept {
    for (size_t index = 0, size = count.load(std::memory_order_acquire); index < size; ++index) {
        auto site = slot(index);
        if (site->source() == address && arms[index].rescue.load(std::memory_order_acquire) && site->currentMapping()) return site;
    }
    return nullptr;
}
bool translate(DWORD64 pc, DWORD64& original) noexcept {
    for (size_t index = 0, size = count.load(std::memory_order_acquire); index < size; ++index) {
        const auto* site = slot(index);
        auto base = reinterpret_cast<DWORD64>(site->displaced());
        if (pc < base || pc - base >= site->displacedSize()) continue;
        for (auto [displaced, source] : site->positions())
            if (pc - base == displaced) {
                original = reinterpret_cast<DWORD64>(site->source()) + static_cast<DWORD64>(static_cast<std::int64_t>(source));
                return true;
            }
        return false;
    }
    return false;
}
size_t preparedCount() { return count.load(std::memory_order_acquire); }
PRUNTIME_FUNCTION lookupUnwind(DWORD64 pc, DWORD64* imageBase) noexcept {
    for (size_t index = 0, size = count.load(std::memory_order_acquire); index < size; ++index) {
        const auto* prepared = slot(index);
        auto base = reinterpret_cast<DWORD64>(prepared->displaced());
        if (pc < base || pc - base >= prepared->displacedSize()) continue;
        *imageBase = base;
        for (const auto& function : prepared->functionTable())
            if (pc - base < function.EndAddress) return const_cast<PRUNTIME_FUNCTION>(&function);
    }
    return nullptr;
}
}
