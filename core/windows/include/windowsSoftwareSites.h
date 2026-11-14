/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsNativeProbeTarget.h"
#include "windowsInstructionDecoder.h"
#include "windowsSoftwareMitigations.h"
#include "windowsNativeUnwind.h"
#include "windowsSoftwareFunction.h"
#include <array>
#include <span>

namespace WindowsProfiler::SoftwareSites {
// Entry: one certified prolog instruction followed by a jump back.
// Return: a complete epilogue from its body-state first instruction through
// the terminating RET or leaving jump; the copy itself leaves the function.
// Body: one relocated instruction whose OS unwind state it does not change,
// followed by a jump back.
enum class SiteKind : unsigned char { Entry, Return, Body };
struct Builder;
constexpr size_t MAX_ORIGINAL_BYTES = 48;
// A displaced instruction start and the source-relative address it stands
// for, which is the branch target for the jump ending a rewritten branch.
using Position = std::pair<std::uint8_t, std::int16_t>;
class PreparedSite {
    friend const char* prepare(NativeProbe::LoadedTarget&&, class SiteLease&);
    friend const char* prepareReturns(NativeProbe::LoadedTarget&&, class SiteLease&);
    friend const char* prepareBody(NativeProbe::LoadedTarget&&, class SiteLease&);
    friend struct Builder;
    friend const char* validateSource(const PreparedSite&);
    friend const char* validateEntry(const PreparedSite&);
    SiteKind _kind = SiteKind::Entry;
    const unsigned char* _entry = nullptr;
    const unsigned char* _source = nullptr;
    std::uintptr_t _imageBase = 0;
    CodeCache* _cache = nullptr;
    std::uint64_t _mappingEpoch = 0;
    std::wstring _path;
    std::array<unsigned char, MAX_ORIGINAL_BYTES> _bytes{};
    unsigned _length = 0, _prefix = 0;
    const unsigned char* _xol = nullptr;
    size_t _xolSize = 0;
    const RUNTIME_FUNCTION* _functions = nullptr;
    unsigned _functionCount = 0;
    void* _unwindRegistration = nullptr;
    SoftwareMitigations::Result _mitigations{};
    RUNTIME_FUNCTION _original{};
    ULONG _imageSize = 0;
    std::vector<unsigned char> _prologue, _unwind;
    InstructionDecoder::Relocation _relocation{};
    NativeUnwind::Recipe _recipe;
    SoftwareFunction::Epilogue _epilogue{};
    std::vector<Position> _positions;
public:
    PreparedSite() = default;
    PreparedSite(const PreparedSite&) = delete;
    PreparedSite& operator=(const PreparedSite&) = delete;
    SiteKind kind() const { return _kind; }
    // Original PE function start; source() is the canonical patched address.
    const unsigned char* entry() const { return _entry; }
    const unsigned char* source() const { return _source; }
    std::uintptr_t imageBase() const { return _imageBase; }
    std::uint64_t mappingEpoch() const { return _mappingEpoch; }
    const std::wstring& path() const { return _path; }
    // Every original byte reproduced by the displaced code.
    std::span<const unsigned char> instruction() const { return {_bytes.data(), _length}; }
    unsigned preservedPrefix() const { return _prefix; }
    const unsigned char* displaced() const { return _xol; }
    size_t displacedSize() const { return _xolSize; }
    std::span<const RUNTIME_FUNCTION> functionTable() const { return {_functions, _functionCount}; }
    const SoftwareMitigations::Result& mitigations() const { return _mitigations; }
    // Image-relative layout; valid for SiteKind::Return.
    const SoftwareFunction::Epilogue& epilogue() const { return _epilogue; }
    std::span<const Position> positions() const { return _positions; }
    bool currentMapping() const;
};
// A return through a displaced branch, taken when its EFLAGS condition holds:
// the remaining epilogue pops and terminator then run from the branch state.
struct ExitPath {
    const PreparedSite* site;
    // x86 condition code, or 16 for an unconditional jump.
    unsigned char condition;
    unsigned char popCount;
    std::array<unsigned char, 16> pops;
    bool jump;
    std::uint16_t immediate;
};
class SiteLease {
    friend const char* prepare(NativeProbe::LoadedTarget&&, SiteLease&);
    friend const char* prepareReturns(NativeProbe::LoadedTarget&&, SiteLease&);
    friend const char* prepareBody(NativeProbe::LoadedTarget&&, SiteLease&);
    std::vector<const PreparedSite*> _sites;
    std::vector<ExitPath> _exits;
    HMODULE _module = nullptr;
public:
    SiteLease() = default;
    SiteLease(const SiteLease&) = delete;
    SiteLease& operator=(const SiteLease&) = delete;
    SiteLease(SiteLease&& other) noexcept;
    SiteLease& operator=(SiteLease&& other) noexcept;
    ~SiteLease();
    const PreparedSite* get() const { return _sites.empty() ? nullptr : _sites.front(); }
    std::span<const PreparedSite* const> sites() const { return _sites; }
    std::span<const ExitPath> exits() const { return _exits; }
    void reset();
};
// Snapshots source/mapping identity and builds checked RX displaced code with
// registered native pre/post body unwind ranges and the dynamic EH/CET metadata
// required by the process policy. Source bytes remain unchanged. Repeated
// preparation of the same patched source/mapping reuses immutable data, including a retained
// registration failure (GetLastError reports its Windows error). Failed/uncertain
// registrations consume the same bounded immutable capacity as successful sites.
// Exception/thread preparation and recording bindings remain arming prerequisites.
// Positions outside the certified prolog subset use prepareBody.
const char* prepare(NativeProbe::LoadedTarget&& target, SiteLease& result);
// Any proven instruction of a function's PE coverage except epilogue
// interiors and call sites: a matched epilogue start reuses the Return copy;
// another instruction must leave the OS unwind state unchanged and continue
// at a body-equivalent position, as must a rewritten branch's target.
const char* prepareBody(NativeProbe::LoadedTarget&& target, SiteLease& result);
// The target must be a primary PE function start or the instruction after its
// leading ENDBR64. Prepares one Return site per epilogue of the function's
// complete coverage, each patched at its body-state first instruction, where
// RtlVirtualUnwind's body rule equals its epilogue rule and an INT3 byte is
// never an epilogue form. Copies carry the source UNWIND_INFO version so the
// OS recognizes the same epilogue positions in them. A branch entering an
// epilogue from an equal state becomes a Body site with an ExitPath.
const char* prepareReturns(NativeProbe::LoadedTarget&& target, SiteLease& result);
const char* validateSource(const PreparedSite& site);
// Entry sites require a current bounded source/unwind certificate and exact
// instruction/recipe agreement at an entry or original prologue boundary.
const char* validateEntry(const PreparedSite& site);
struct ArmResult {
    const char* error = nullptr;
    bool retainLease = false;
    bool rescueOwned = false;
};
// Arms every site or none. On uncertain mutation/protection failure retain the
// module lease and all rescue state for process lifetime. A site armed before
// is rearmed only after no thread of this process can still deliver one of its
// earlier traps: each thread is suspended in turn and its stack is unwound
// through PE metadata, looking for a trap context at the source beneath
// exception dispatch. Frames without metadata end that thread's walk.
ArmResult arm(std::span<const PreparedSite* const> sites);
const char* disarm(std::span<const PreparedSite* const> sites);
// The armed-once site whose patched source is address, if its mapping is current.
const PreparedSite* rescue(const void* address) noexcept;
// Source address of a displaced instruction start, the boundary at which
// faults and traps of displaced code are reported.
bool translate(DWORD64 pc, DWORD64& original) noexcept;
size_t preparedCount();
// Immutable retained XOL metadata is also available to the cached walker.
// This lookup does not establish source mapping or trap ownership.
PRUNTIME_FUNCTION lookupUnwind(DWORD64 pc, DWORD64* imageBase) noexcept;
}
