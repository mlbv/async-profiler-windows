/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsSoftwareProbe.h"
#include "windowsSoftwareSites.h"
#include "windowsTrapThreads.h"
#include "windowsBreakpoints.h"
#include "windowsMutex.h"
#include "windowsNativeErrorState.h"
#include "windowsProfiler.h"
#include "profiler.h"
#include "threadFilter.h"
#include "writer.h"
#include "tsc.h"
#include <tlhelp32.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <memory>
#include <string>
#include <vector>

namespace {
WindowsProfiler::WindowsMutex control;
std::atomic<bool> broken{false};
PVOID handler = nullptr, continuation = nullptr;
// Exceptions of displaced code reported at their source; an unchanged resume
// returns to the displaced instruction instead of the patched source.
struct Translated { const EXCEPTION_RECORD* record; DWORD64 source, displaced; };
thread_local std::array<Translated, 4> translated{};
thread_local unsigned translations = 0;
std::atomic<std::uint64_t> faults{0};
std::atomic<std::uint64_t> hits{0}, samples{0}, dropped{0}, rescued{0}, unprepared{0}, recursive{0};
std::uint64_t recordings = 0;
}

struct WindowsSoftwareProbe::State {
    using Site = WindowsProfiler::SoftwareSites::PreparedSite;
    WindowsProfiler::SoftwareSites::SiteLease lease;
    std::vector<const Site*> sites;
    std::vector<WindowsProfiler::SoftwareSites::ExitPath> exits;
    bool returns = false;
    std::string selector;
    std::uint64_t period = 1, epoch = 0;
    static constexpr std::uint64_t closed = std::uint64_t{1} << 63;
    std::atomic<std::uint64_t> delivery{closed};
    std::atomic<DWORD> failure{0};
    bool started = false, retain = false;
    static constexpr size_t capacity = 4096;
    static std::array<std::atomic<State*>,capacity> records;
    static std::atomic<size_t> count;
    static std::atomic<State*> observing, active;
    void fail(DWORD error) noexcept {
        DWORD expected = 0;
        failure.compare_exchange_strong(expected,error,std::memory_order_acq_rel);
        broken.store(true,std::memory_order_release);
    }
    bool owns(const Site* site) const noexcept { return std::find(sites.begin(), sites.end(), site) != sites.end(); }
    const WindowsProfiler::SoftwareSites::ExitPath* exitOf(const Site* site) const noexcept {
        for (const auto& exit : exits) if (exit.site == site) return &exit;
        return nullptr;
    }
    bool enter() noexcept {
        auto value = delivery.load(std::memory_order_acquire);
        while (!(value & closed)) {
            if (delivery.compare_exchange_weak(value,value + 1,std::memory_order_acq_rel,std::memory_order_acquire)) return true;
        }
        return false;
    }
    void close() noexcept { delivery.fetch_or(closed,std::memory_order_acq_rel); }
    void drain() noexcept {
        for (auto pending = delivery.load(std::memory_order_acquire); pending != closed;
                pending = delivery.load(std::memory_order_acquire))
            WaitOnAddress(&delivery,&pending,sizeof(pending),INFINITE);
    }
    void leave() noexcept {
        if ((delivery.fetch_sub(1,std::memory_order_release) & ~closed) == 1) WakeByAddressAll(&delivery);
    }
};
std::array<std::atomic<WindowsSoftwareProbe::State*>,WindowsSoftwareProbe::State::capacity> WindowsSoftwareProbe::State::records{};
std::atomic<size_t> WindowsSoftwareProbe::State::count{0};
std::atomic<WindowsSoftwareProbe::State*> WindowsSoftwareProbe::State::observing{nullptr};
std::atomic<WindowsSoftwareProbe::State*> WindowsSoftwareProbe::State::active{nullptr};

bool WindowsSoftwareProbe::failed() { return broken.load(std::memory_order_acquire) || WindowsProfiler::Breakpoints::failed(); }
bool WindowsSoftwareProbe::accepts(const char* name) {
    return std::strncmp(name,"uprobe:",7) == 0 || std::strncmp(name,"uretprobe:",10) == 0;
}
const char* WindowsSoftwareProbe::type() { return _state ? _state->selector.c_str() : "uprobe"; }
int64_t WindowsSoftwareProbe::interval() { return _state ? static_cast<int64_t>(_state->period) : 1; }

bool WindowsSoftwareProbe::enroll(HANDLE thread,DWORD) {
    WindowsProfiler::SavedNativeErrorState saved;
    auto state = State::observing.load(std::memory_order_acquire);
    if (!state) return true;
    if (WindowsProfiler::TrapThreads::prepare(thread)) {
        if (WaitForSingleObject(thread,0) == WAIT_OBJECT_0) return true;
        state->fail(ERROR_NOT_ENOUGH_MEMORY);
        return false;
    }
    return true;
}
const char* WindowsSoftwareProbe::prepareThreads() {
    using namespace WindowsProfiler;
    // The existing CreateThread observer must be active before the snapshot.
    auto snapshot = toolhelpSnapshot(TH32CS_SNAPTHREAD,0);
    if (snapshot == INVALID_HANDLE_VALUE) return "Cannot enumerate software-probe threads";
    THREADENTRY32 entry{sizeof(entry)};
    bool valid = Thread32First(snapshot,&entry) != 0;
    if (valid) do {
        if (entry.th32OwnerProcessID != GetCurrentProcessId()) continue;
        auto thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT
            | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,FALSE,entry.th32ThreadID);
        if (!thread) { if (GetLastError() != ERROR_INVALID_PARAMETER) valid = false; continue; }
        if (!enroll(thread,entry.th32ThreadID) && WaitForSingleObject(thread,0) != WAIT_OBJECT_0) valid = false;
        CloseHandle(thread);
    } while (Thread32Next(snapshot,&entry));
    CloseHandle(snapshot);
    return valid ? nullptr : "Cannot enroll every software-probe thread";
}
Error WindowsSoftwareProbe::prepare(Arguments& args) {
    using namespace WindowsProfiler;
    if (failed()) return Error("A software-probe operation failed; restart the target before capture");
    NativeProbe::SoftwareSpec spec;
    if (auto error = NativeProbe::parseSoftware(args._event,spec)) return Error(error);
    if (args._interval < 0) return Error("Software probe period must be positive");
    if (args._target_cpu != -1 || args._alluser) return Error("Software probes do not accept target-cpu or alluser");
    if (auto error = importFailure()) return Error(error);
    NativeProbe::LoadedTarget target;
    if (auto error = NativeProbe::resolveSoftware(spec,target)) return Error(error);
    SoftwareSites::SiteLease lease;
    bool returns = spec.mode == NativeProbe::Mode::Return;
    if (returns) {
        if (auto error = SoftwareSites::prepareReturns(std::move(target),lease)) return Error(error);
    } else {
        if (auto error = SoftwareSites::prepare(std::move(target),lease)) return Error(error);
        if (lease.get()->kind() == SoftwareSites::SiteKind::Entry)
            if (auto error = SoftwareSites::validateEntry(*lease.get())) return Error(error);
    }
    std::lock_guard lock(control);
    auto size = State::count.load(std::memory_order_relaxed);
    std::string selector(args._event);
    auto period = args._interval ? static_cast<std::uint64_t>(args._interval) : 1;
    std::vector<const State::Site*> sites(lease.sites().begin(), lease.sites().end());
    for (size_t index = 0; index < size; ++index) {
        auto state = State::records[index].load(std::memory_order_relaxed);
        if (state->sites != sites || state->returns != returns) continue;
        state->selector.swap(selector);
        state->period = period;
        state->exits.assign(lease.exits().begin(), lease.exits().end());
        state->lease = std::move(lease);
        _state = state;
        return Error::OK;
    }
    if (size == State::capacity) return Error("Software-probe retained binding capacity exhausted");
    // Published bindings survive every stop; rescue itself belongs to the sites.
    auto state = std::make_unique<State>();
    state->selector = std::move(selector); state->period = period; state->returns = returns;
    state->sites = std::move(sites); state->exits.assign(lease.exits().begin(), lease.exits().end());
    state->lease = std::move(lease);
    _state = state.get();
    State::records[size].store(state.release(),std::memory_order_relaxed);
    State::count.store(size + 1,std::memory_order_release);
    return Error::OK;
}
Error WindowsSoftwareProbe::start(Arguments&) {
    using namespace WindowsProfiler;
    auto& state = *_state;
    std::lock_guard lock(control);
    if (failed()) return Error("A software-probe operation failed; restart the target before capture");
    if (auto error = prepareNativeErrorState()) return Error(error);
    if (!handler) {
        continuation = AddVectoredContinueHandler(1,resume);
        handler = continuation ? AddVectoredExceptionHandler(1,exception) : nullptr;
        if (!handler) { state.fail(GetLastError()); return Error("Cannot install software-probe exception rescue"); }
    }
    State::observing.store(&state,std::memory_order_release);
    // Shared with hardware breakpoints: no second CreateThread import family.
    if (auto error = Breakpoints::observeThreads(enroll)) {
        State::observing.store(nullptr,std::memory_order_release);
        return error;
    }
    if (auto error = prepareThreads()) {
        Breakpoints::stopObservingThreads();
        State::observing.store(nullptr,std::memory_order_release);
        return Error(error);
    }
    hits = 0; samples = 0; dropped = 0; rescued = 0; unprepared = 0; recursive = 0; faults = 0;
    // A fresh epoch restarts every thread's period for this recording.
    state.epoch = ++recordings;
    State::active.store(&state,std::memory_order_release);
    auto armed = SoftwareSites::arm(state.sites);
    // Only traps of this arming may enter; arm waits out earlier ones first.
    if (!armed.error) state.delivery.store(0,std::memory_order_release);
    if (armed.error) {
        state.retain = armed.retainLease;
        if (armed.retainLease) state.fail(ERROR_WRITE_FAULT);
        Breakpoints::stopObservingThreads();
        State::observing.store(nullptr,std::memory_order_release);
        state.drain();
        if (!state.retain) state.lease.reset();
        return Error(armed.error);
    }
    state.started = true;
    return Error::OK;
}
void WindowsSoftwareProbe::stop() {
    using namespace WindowsProfiler;
    if (!_state) return;
    auto& state = *_state;
    std::lock_guard lock(control);
    state.close();
    if (state.started) {
        if (SoftwareSites::disarm(state.sites)) { state.fail(ERROR_WRITE_FAULT); state.retain = true; }
        state.started = false;
    }
    Breakpoints::stopObservingThreads();
    State::observing.store(nullptr,std::memory_order_release);
    state.drain();
    if (state.failure.load(std::memory_order_acquire) || Breakpoints::failed()) state.retain = true;
    // Restored sources need no module lease: a thread with a pending trap or in
    // displaced code is still inside the source function, which the
    // application cannot unload without racing its own call.
    if (!state.retain) state.lease.reset();
}
Error WindowsSoftwareProbe::stopError() {
    return _state && (_state->failure.load(std::memory_order_acquire) || WindowsProfiler::Breakpoints::failed())
        ? Error("Software-probe capture or source restoration failed; restart the target") : Error::OK;
}
namespace {
DWORD64& reg(CONTEXT& context, unsigned index) { return (&context.Rax)[index]; }
// The caller's context after the remaining epilogue and its terminator, as the
// return probe's sample; a tail jump's target returns to the same caller state.
CONTEXT returned(CONTEXT result, const unsigned char* pops, unsigned popCount, bool jump, std::uint16_t immediate) {
    for (unsigned index = 0; index < popCount; ++index) {
        reg(result, pops[index]) = *reinterpret_cast<const DWORD64*>(result.Rsp);
        result.Rsp += sizeof(DWORD64);
    }
    result.Rip = *reinterpret_cast<const DWORD64*>(result.Rsp);
    result.Rsp += sizeof(DWORD64) + (jump ? 0 : immediate);
    return result;
}
CONTEXT returned(CONTEXT result, const WindowsProfiler::SoftwareFunction::Epilogue& epilogue) {
    using WindowsProfiler::SoftwareFunction::Teardown;
    if (epilogue.teardown == Teardown::Add) result.Rsp += epilogue.amount;
    else if (epilogue.teardown == Teardown::Lea) result.Rsp = reg(result, epilogue.frameRegister) + epilogue.amount;
    else if (epilogue.teardown == Teardown::Move) result.Rsp = reg(result, epilogue.frameRegister);
    return returned(result, epilogue.pops.data(), epilogue.popCount, epilogue.jump, epilogue.immediate);
}
// Whether a Jcc with this condition code jumps under these flags.
bool taken(unsigned char condition, DWORD flags) {
    if (condition == 16) return true;
    bool carry = flags & 0x1, parity = flags & 0x4, zero = flags & 0x40, sign = flags & 0x80, overflow = flags & 0x800;
    bool result[]{overflow, carry, zero, carry || zero, sign, parity, sign != overflow, zero || sign != overflow};
    return result[condition >> 1] != bool(condition & 1);
}
}
LONG CALLBACK WindowsSoftwareProbe::resume(EXCEPTION_POINTERS* pointers) {
    for (auto& entry : translated) {
        if (entry.record != pointers->ExceptionRecord) continue;
        if (pointers->ContextRecord->Rip == entry.source) pointers->ContextRecord->Rip = entry.displaced;
        entry = {};
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
LONG CALLBACK WindowsSoftwareProbe::exception(EXCEPTION_POINTERS* pointers) {
    auto& context = *pointers->ContextRecord;
    auto site = pointers->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT
        ? WindowsProfiler::SoftwareSites::rescue(pointers->ExceptionRecord->ExceptionAddress) : nullptr;
    if (!site) {
        DWORD64 source;
        if (!WindowsProfiler::SoftwareSites::translate(context.Rip, source)) return EXCEPTION_CONTINUE_SEARCH;
        translated[translations++ % translated.size()] = {pointers->ExceptionRecord, source, context.Rip};
        if (pointers->ExceptionRecord->ExceptionAddress == reinterpret_cast<void*>(context.Rip))
            pointers->ExceptionRecord->ExceptionAddress = reinterpret_cast<void*>(source);
        context.Rip = source;
        faults.fetch_add(1,std::memory_order_relaxed);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    WindowsProfiler::SavedNativeErrorState saved;
    auto original = context; original.Rip = reinterpret_cast<DWORD64>(site->source());
    // Rescue remains mandatory even when capture is disabled or reentrant.
    context.Rip = reinterpret_cast<DWORD64>(site->displaced());
    rescued.fetch_add(1,std::memory_order_relaxed);
    auto state = State::active.load(std::memory_order_acquire);
    if (!state || !state->owns(site) || !state->enter()) return EXCEPTION_CONTINUE_EXECUTION;
    // An early exit returns only when its branch is taken.
    auto exit = state->returns ? state->exitOf(site) : nullptr;
    if (exit && !taken(exit->condition, original.EFlags)) { state->leave(); return EXCEPTION_CONTINUE_EXECUTION; }
    auto thread = WindowsProfiler::TrapThreads::current();
    if (!thread) {
        unprepared.fetch_add(1,std::memory_order_relaxed); state->fail(ERROR_NOT_FOUND); state->leave();
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (thread.internal() || !thread.tryEnter()) {
        recursive.fetch_add(1,std::memory_order_relaxed); state->leave(); return EXCEPTION_CONTINUE_EXECUTION;
    }
    auto generation = sampleGeneration();
    auto& phase = thread.state();
    if (phase.eventEpoch != state->epoch) { phase.eventEpoch = state->epoch; phase.remainder = 0; }
    auto selected = ++phase.remainder == state->period;
    if (selected) phase.remainder = 0;
    hits.fetch_add(1,std::memory_order_relaxed);
    if (selected && !failed() && canSample(generation)) {
        auto filter = Profiler::instance()->threadFilter();
        if ((!filter->enabled() || filter->contains(thread.identity().tid)) && !failed() && canSample(generation)) {
            if (exit) original = returned(original, exit->pops.data(), exit->popCount, exit->jump, exit->immediate);
            else if (state->returns) original = returned(original, site->epilogue());
            ExecutionEvent event(TSC::ticks());
            if (Profiler::instance()->recordSample(&original,state->period,EXECUTION_SAMPLE,&event))
                samples.fetch_add(1,std::memory_order_relaxed);
            else dropped.fetch_add(1,std::memory_order_relaxed);
        }
    }
    state->leave();
    return EXCEPTION_CONTINUE_EXECUTION;
}
void WindowsSoftwareProbe::writeMetrics(Writer& out) {
    out << "windows_software_probe_hits " << u64(hits.load()) << '\n';
    out << "windows_software_probe_samples " << u64(samples.load()) << '\n';
    out << "windows_software_probe_dropped " << u64(dropped.load()) << '\n';
    out << "windows_software_probe_rescued " << u64(rescued.load()) << '\n';
    out << "windows_software_probe_unprepared " << u64(unprepared.load()) << '\n';
    out << "windows_software_probe_recursive " << u64(recursive.load()) << '\n';
    out << "windows_software_probe_translated_exceptions " << u64(faults.load()) << '\n';
    out << "windows_software_probe_failed " << int(failed()) << '\n';
}
