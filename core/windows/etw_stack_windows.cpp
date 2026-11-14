/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwStack.h"
#include "windowsJava.h"
#include "windowsJavaUnwind.h"
#include "windowsProfiler.h"
#include "profiler.h"
#include "stackWalker.h"
#include "threadFilter.h"
#include "tsc.h"
#include "writer.h"
#include "log.h"
#include "vmStructs.h"
#include <algorithm>
#include <cstring>
#include <limits>

namespace WindowsProfiler::Etw {
namespace {
bool kernelAddress(std::uint64_t address) { return (address >> 63) != 0; }
}

Error EventWindows::prepare(bool needed) {
    try { boundaries.resize(needed ? 65536 : 0); }
    catch (...) { return Error("Not enough memory to allocate ETW profiling windows"); }
    reset();
    return Error::OK;
}

void EventWindows::reset() {
    lock.lock();
    count = 0; overflowTime = 0; outside = 0;
    lock.unlock();
}

bool EventWindows::accepts(std::uint64_t time) {
    if (boundaries.empty()) return true;
    lock.lock();
    auto first = boundaries.begin(), last = first + count;
    auto found = std::upper_bound(first, last, time,
        [](std::uint64_t time, const Boundary& boundary) { return time < boundary.time; });
    bool accepted = found != first && (found - 1)->enabled && (!overflowTime || time < overflowTime);
    lock.unlock();
    if (!accepted) outside.fetch_add(1);
    return accepted;
}

bool EventWindows::enable(Engine& owner, bool enabled) {
    if (boundaries.empty()) { owner.Engine::enableEvents(enabled); return true; }
    lock.lock();
    if (count == 0 || boundaries[count - 1].enabled != enabled) {
        auto time = queryPerformanceCounter();
        if (count < boundaries.size()) boundaries[count++] = {time, enabled};
        else if (!overflowTime) overflowTime = time;
    }
    // Keep the timestamp order and base engine state in the same critical
    // section when several application threads cross window boundaries.
    owner.Engine::enableEvents(enabled);
    bool result = overflowTime == 0;
    lock.unlock();
    return result;
}

ULONG EventWindows::failure() const {
    lock.lock();
    auto result = overflowTime ? ERROR_BUFFER_OVERFLOW : ERROR_SUCCESS;
    lock.unlock();
    return result;
}

void EventWindows::writeMetrics(Writer& out, const char* prefix) const {
    lock.lock();
    auto size = count;
    bool overflow = overflowTime != 0;
    lock.unlock();
    out << prefix << "window_boundaries " << static_cast<u64>(size) << '\n';
    out << prefix << "window_overflow " << static_cast<u64>(overflow) << '\n';
    out << prefix << "outside_windows " << static_cast<u64>(outside.load()) << '\n';
}

Error StackPublisher::prepare(const Arguments& args) {
    if (args._features.vtable_target) return Error("vtable feature requires sampled receiver registers, unavailable in ETW stack events");
    if (args._features.comp_task) return Error("comptask feature requires the sampled compiler task, unavailable in ETW stack events");
    features = args._features;
    allUser = args._alluser;
    nativeFrames = args._cstack != CSTACK_NO;
    recordCpu = args._record_cpu;
    maxDepth = args._jstackdepth;
    truncatedDepth = std::clamp(args._truncated_stack_depth, 0, maxDepth);
    try {
        // Native transport frames must not consume the Java-only depth budget.
        callFrames.resize(static_cast<size_t>(maxDepth) + 2 * MAX_STACK_FRAMES + 8);
    } catch (...) { return Error("Not enough memory to allocate ETW stack buffers (try smaller jstackdepth)"); }
    return Error::OK;
}

void StackPublisher::reset() {
    libraries.clear();
    ambiguousNativePcs = 0;
    samples = 0; missingStacks = 0; missingUserStacks = 0; missingKernelStacks = 0;
    partialJava = 0; partialVm = 0; partialNative = 0; depthLimited = 0; truncatedStacks = 0;
    unprovenCfiStacks = 0;
}

void StackPublisher::rememberLibraries(std::uint64_t since) {
    auto all = Profiler::instance()->nativeLibs();
    for (int i = static_cast<int>(libraries.size()), count = all->count(); i < count; ++i) {
        auto cache = (*all)[i];
        Library library{cache, reinterpret_cast<std::uintptr_t>(cache->minAddress()), reinterpret_cast<std::uintptr_t>(cache->maxAddress())};
        auto epoch = cache->windowsLoadEpoch();
        auto now = queryPerformanceCounter();
        if (epoch && epoch == cache->windowsLoadEpoch()) {
            library.observedEpoch = epoch;
            // Capture begins after the initial snapshot. Even that snapshot
            // must not invent coverage before its known active observation.
            library.lifetimes.push_back({epoch, std::max(since, now), now});
        }
        libraries.push_back(std::move(library));
    }
}

void StackPublisher::observeLibrary(Library& library) {
    auto epoch = library.cache->windowsLoadEpoch();
    if (epoch) {
        auto now = queryPerformanceCounter();
        if (epoch == library.cache->windowsLoadEpoch()) {
            if (epoch == library.observedEpoch) {
                library.lifetimes.back().confirmedThrough = std::max(library.lifetimes.back().confirmedThrough, now);
                return;
            }
            if (library.observedEpoch) library.lifetimes.back().closed = true;
            library.lifetimes.push_back({epoch, now, now});
            library.observedEpoch = epoch;
            return;
        }
    }
    if (library.observedEpoch) library.lifetimes.back().closed = true;
    library.observedEpoch = 0;
}

const char* StackPublisher::nativeName(std::uint64_t address, std::uint64_t time) {
    bool uncertain = false;
    for (auto& library : libraries) {
        if (address < library.begin || address >= library.end) continue;
        observeLibrary(library);
        auto& lifetimes = library.lifetimes;
        auto found = std::upper_bound(lifetimes.begin(), lifetimes.end(), time,
            [](std::uint64_t time, const Lifetime& lifetime) { return time < lifetime.since; });
        if (found != lifetimes.begin()) {
            const auto& lifetime = *--found;
            // A closed interval excludes its final observed QPC tick: an
            // unload and another execution can share that coarse timestamp.
            if (time > lifetime.since && (lifetime.closed ? time < lifetime.confirmedThrough : time <= lifetime.confirmedThrough)) {
                return library.cache->binarySearch(reinterpret_cast<void*>(address));
            }
        }
        uncertain = true;
    }
    if (uncertain) ambiguousNativePcs.fetch_add(1);
    return nullptr;
}

void StackPublisher::calibrateClock() {
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency); qpcFrequency = frequency.QuadPart;
    clockQpc = queryPerformanceCounter(); clockTicks = TSC::ticks();
}

std::uint64_t StackPublisher::ticks(std::uint64_t time) const {
    auto delta = static_cast<std::int64_t>(time - clockQpc);
    auto converted = static_cast<std::int64_t>(static_cast<long double>(delta) * TSC::frequency() / qpcFrequency);
    return static_cast<std::uint64_t>(static_cast<std::int64_t>(clockTicks) + converted);
}

bool StackPublisher::accepts(ULONG tid) const {
    auto filter = Profiler::instance()->threadFilter();
    return !WindowsProfiler::isInternalThread(tid) && (!filter->enabled() || filter->contains(tid));
}

bool StackPublisher::publish(const StackSample& sample) {
    if (!accepts(sample.tid)) return false;
    auto stackWalkBegin = features.stats ? OS::nanotime() : 0;
    auto frames = callFrames.data();
    int capacity = static_cast<int>(std::min<size_t>(callFrames.size() - 8, std::numeric_limits<int>::max() - 8));
    int pcFrames = features.pc_addr ? 1 : 0;
    int count = pcFrames;
    if (pcFrames) frames[0] = {BCI_ADDRESS, 0, reinterpret_cast<jmethodID>(sample.ip)};
    bool java = false, vmCode = false, truncated = false;
    bool nativeRoot = false, unknownGenerated = false;
    bool unprovenCfi = false;
    unsigned pendingInterpreter = 0;
    auto addAddress = [&](std::uint64_t address) {
        if (!address || (allUser && kernelAddress(address))) return;
        if (count == capacity) { truncated = true; return; }
        bool generated = VM::loaded() && CodeHeap::contains(reinterpret_cast<void*>(address));
        vmCode |= generated;
        int found = VM::loaded() && !kernelAddress(address) ? Java::decode(address, sample.time, frames + count,
            capacity - count, truncated, generated) : 0;
        auto checkOutgoingStep = [&] {
            if (VM::loaded() && !kernelAddress(address)
                    && JavaUnwind::certainty(address,sample.time,generated,found != 0) == JavaUnwind::Certainty::Unproven) {
                unprovenCfi = true;
                unknownGenerated = true;
            }
        };
        if (found) {
            if (found == 1 && FrameType::decode(frames[count].bci) == FRAME_INTERPRETED) {
                if (pendingInterpreter) pendingInterpreter--;
            }
            if (count && found == 1 && FrameType::decode(frames[count].bci) == FRAME_INTERPRETED
                    && frames[count - 1].bci == BCI_NATIVE_FRAME
                    && std::strcmp(reinterpret_cast<const char*>(frames[count - 1].method_id), "Interpreter") == 0) {
                frames[count - 1] = frames[count];
            } else count += found;
            java = true;
            checkOutgoingStep();
            return;
        }
        const char* name = generated ? Profiler::instance()->findRuntimeStubName(reinterpret_cast<void*>(address)) : nullptr;
        if (!name) name = nativeName(address, sample.time);
        frames[count].bci = name ? BCI_NATIVE_FRAME : BCI_ADDRESS;
        frames[count++].method_id = name ? reinterpret_cast<jmethodID>(const_cast<char*>(name)) : reinterpret_cast<jmethodID>(address);
        // A thread's initial context enters user mode at LdrInitializeThunk, which
        // continues to RtlUserThreadStart on a fresh frame after loader setup.
        if (name && (std::strcmp(name, "RtlUserThreadStart") == 0 || std::strcmp(name, "LdrInitializeThunk") == 0)) nativeRoot = true;
        if (generated && name && std::strcmp(name, "Interpreter") == 0) {
            pendingInterpreter++;
            unknownGenerated |= JavaUnwind::incomplete(address);
        } else if (generated && !name) unknownGenerated = true;
        checkOutgoingStep();
    };
    if (sample.stacksRequested) {
        for (auto pc : sample.kernel) addAddress(pc);
        for (auto pc : sample.user) {
            if (unprovenCfi) break;
            addAddress(pc);
        }
    }
    if (!sample.complete) {
        missingStacks.fetch_add(1);
        if (sample.user.empty() && missingUserStacks.fetch_add(1) == 0) {
            Log::warn("ETW sample has no user stack: tid=%lu cpu=%u source=%lu qpc=%llu ip=%llx kernel=%zu",
                sample.tid, sample.cpu, sample.source, static_cast<unsigned long long>(sample.time),
                static_cast<unsigned long long>(sample.ip), sample.kernel.size());
        }
        if (kernelAddress(sample.ip) && sample.kernel.empty()) missingKernelStacks.fetch_add(1);
        if (count == pcFrames) addAddress(sample.ip);
    } else if (!sample.stacksRequested) addAddress(sample.ip);
    if (unprovenCfi) unprovenCfiStacks.fetch_add(1);
    truncated |= unprovenCfi || sample.overflow || (sample.rawLimit && sample.user.size() == sample.rawLimit && !nativeRoot);
    bool reconstructed = sample.complete && nativeRoot && !pendingInterpreter && !unknownGenerated && !truncated && !unprovenCfi;
    if (!nativeFrames && VM::loaded()) count = pcFrames + StackWalker::retainJavaFrames(frames + pcFrames, count - pcFrames);
    bool shortened = count >= maxDepth && truncatedDepth < maxDepth;
    if (count > maxDepth || shortened) depthLimited.fetch_add(1);
    count = shortened ? truncatedDepth : std::min(count, maxDepth);
    if (!sample.complete) frames[count++] = {BCI_ERROR, 0, reinterpret_cast<jmethodID>(const_cast<char*>("etw_stack_incomplete"))};
    if (java && !reconstructed) {
        partialJava.fetch_add(1);
        frames[count++] = {BCI_ERROR, 0, reinterpret_cast<jmethodID>(const_cast<char*>("etw_java_unwind_incomplete"))};
    } else if (!java && vmCode && !reconstructed) {
        partialVm.fetch_add(1);
        frames[count++] = {BCI_ERROR, 0, reinterpret_cast<jmethodID>(const_cast<char*>("etw_vm_unwind_incomplete"))};
    } else if (sample.stacksRequested && !java && !vmCode && !reconstructed) {
        partialNative.fetch_add(1);
        frames[count++] = {BCI_ERROR, 0, reinterpret_cast<jmethodID>(const_cast<char*>("etw_native_unwind_incomplete"))};
    }
    if (truncated || shortened) {
        truncatedStacks.fetch_add(1);
        frames[count++] = {BCI_ERROR, 0, reinterpret_cast<jmethodID>(const_cast<char*>("truncated"))};
    }
    if (!nativeFrames && VM::loaded() && count == 0) frames[count++] = {BCI_ERROR, 0, reinterpret_cast<jmethodID>(const_cast<char*>("no_Java_frame"))};
    if (recordCpu) frames[count++] = {BCI_CPU, 0, reinterpret_cast<jmethodID>(static_cast<std::uintptr_t>(sample.cpu | 0x8000))};
    if (count == 0) return false;
    if (features.stats) Profiler::instance()->addStackWalkTime(OS::nanotime() - stackWalkBegin);
    // Default state, like upstream's perf samples: converters select CPU samples by it.
    ExecutionEvent event(ticks(sample.time));
    event._counter = sample.counter;
    Profiler::instance()->recordExternalSample(event._counter, sample.tid, EXECUTION_SAMPLE, &event, count, frames);
    WindowsProfiler::markExternalSample(sample.tid, event._start_time, sample.time);
    samples.fetch_add(1);
    return true;
}

void StackPublisher::writeMetrics(Writer& out, const char* prefix) const {
    out << prefix << "module_lifetime_ambiguous_pcs " << static_cast<u64>(ambiguousNativePcs.load()) << '\n';
    out << prefix << "samples " << static_cast<u64>(samples.load()) << '\n';
    out << prefix << "missing_user_stacks " << static_cast<u64>(missingUserStacks.load()) << '\n';
    out << prefix << "missing_kernel_stacks " << static_cast<u64>(missingKernelStacks.load()) << '\n';
    out << prefix << "java_partial_stacks " << static_cast<u64>(partialJava.load()) << '\n';
    out << prefix << "vm_partial_stacks " << static_cast<u64>(partialVm.load()) << '\n';
    out << prefix << "native_partial_stacks " << static_cast<u64>(partialNative.load()) << '\n';
    out << prefix << "depth_limited_stacks " << static_cast<u64>(depthLimited.load()) << '\n';
    out << prefix << "truncated_stacks " << static_cast<u64>(truncatedStacks.load()) << '\n';
    out << prefix << "unproven_cfi_stacks " << static_cast<u64>(unprovenCfiStacks.load()) << '\n';
    out << prefix << "incomplete_stacks " << static_cast<u64>(missingStacks.load()) << '\n';
}
}
