/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtw.h"
#include "windowsEtwStack.h"
#include "windowsEtwWatcher.h"
#include "windowsEtwProfileShare.h"
#include "windowsEtwBroker.h"
#include "windowsEtwProfileRouter.h"
#include "windowsSoftwareEvents.h"
#include "windowsKernel.h"
#include "windowsRawPmu.h"
#include "windowsPrivilege.h"
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
#include <bcrypt.h>
#include <pthread.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <map>
#include <limits>
#include <mutex>
#include <set>

using namespace WindowsProfiler;
namespace {
constexpr GUID perfInfo = {0xce1dbfb4, 0x137e, 0x4da6, {0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc}};
bool kernelAddress(std::uint64_t address) { return (address >> 63) != 0; }
std::uint64_t qpc() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }

}

struct WindowsEtwEngine::State {
    using Properties = Etw::Properties;
    Properties properties{};
    Etw::SessionWatcher watcher;
    struct Key {
        std::uint64_t time;
        ULONG tid;
        bool operator<(const Key& other) const { return time < other.time || (time == other.time && tid < other.tid); }
    };
    struct Pending {
        Etw::Record sample;
        bool profile = false, overflow = false;
        std::vector<std::uint64_t> kernel, user;
    };
    Etw::Source source{};
    Etw::RawPmuConfig rawConfig{};
    bool rawSource = false;
    Etw::SoftwareKind software = Etw::SoftwareKind::None;
    Etw::Broker::ProfileRouter softwareRouter;
    Etw::SoftwareThreadPeriods softwarePeriods;
    Etw::SoftwareStacks softwareStacks{Etw::MAX_STACK_FRAMES, 65536};
    bool softwareMode() const { return software != Etw::SoftwareKind::None; }
    std::vector<Etw::SoftwareRecord> softwareCohort;
    struct SoftwarePart { ULONG tid; std::uint64_t time; std::vector<std::uint64_t> frames; };
    std::vector<SoftwarePart> softwareCohortParts;
    std::uint64_t softwareCohortTime = 0;
    std::atomic<std::uint64_t> softwareMatched{0}, softwareUnknownThreads{0}, softwareUnproven{0}, softwareSharedUserStacks{0};
    std::array<std::atomic<std::uint64_t>, 6> faultCategories{};
    std::map<Key, Pending> pending;
    std::set<ULONG> threads;
    Etw::StackPublisher publisher;
    std::string counterUnit, counterType, heading;
    char error[256]{};
    TRACEHANDLE session = 0, consumer = INVALID_PROCESSTRACE_HANDLE;
    Etw::ProfileShare share;
    Privilege privilege{L"SeSystemProfilePrivilege"};
    bool started = false;
    bool remote = false;
    DWORD brokerPid = 0;
    Etw::Broker::Result brokerResult{};
    std::mutex routerDiagnosticsMutex;
    Etw::Broker::RouterDiagnostics routerDiagnostics{};
    void publishRouterDiagnostics(const Etw::Broker::RouterDiagnostics& value) {
        std::lock_guard lock(routerDiagnosticsMutex);
        routerDiagnostics = value;
    }
    Etw::Broker::RouterDiagnostics readRouterDiagnostics() {
        std::lock_guard lock(routerDiagnosticsMutex);
        return routerDiagnostics;
    }
    // Software events always collect stacks: switch ownership and CSwitch PCs come from them.
    bool allUser = false, stacks = true, publishStacks = true;
    int targetCpu = -1;
    pthread_t worker{};
    // This capture's interval, in ns for the timer and events otherwise.
    std::uint64_t weight = 0;
    // The shared source's interval timeline: samples arrive at the finest interval
    // requested by its owners, and accumulate until they reach this capture's.
    std::vector<Etw::IntervalChange> intervals;
    std::uint64_t intervalPosition = 0, intervalHorizon = 0, accumulated = 0, intervalScale = 1;
    std::atomic<std::uint64_t> decimated{0}, intervalChanges{0};
    std::atomic<std::uint64_t> begin{0};
    std::atomic<std::uint64_t> end{0}, unmatchedStacks{0}, malformed{0}, lost{0};
    std::atomic<std::uint64_t> stackEvents{0}, stackOutsideTime{0};
    std::atomic<std::uint64_t> pendingEvictions{0};
    std::atomic<std::uint64_t> emptyStacks{0}, foreignThreadStacks{0}, unsupportedStacks{0};
    std::atomic<std::uint64_t> buffersLost{0}, realtimeBuffersLost{0};
    std::atomic<std::uint64_t> brokerForeign{0}, brokerUnattributed{0}, brokerPotentialLoss{0};
    std::atomic<ULONG> brokerCleanupError{0};
    std::atomic<ULONG> failure{0};
    Etw::EventWindows windows;

    Error fail(const char* operation, ULONG code) {
        std::snprintf(error, sizeof(error), "%s (Windows error %lu)", operation, code);
        return Error(error);
    }
    Error conflict(const Etw::ShareConflict& value) {
        using Kind = Etw::ShareConflictKind;
        if (value.kind == Kind::ExternalPmc) return fail("Cannot select ETW overflow sources while another PMC profiler is active", ERROR_BUSY);
        if (value.kind == Kind::ExternalTimer) {
            std::snprintf(error, sizeof(error), "Another ETW timer profiler uses %lluns; request that interval or leave interval unspecified",
                static_cast<unsigned long long>(value.interval) * 100);
            return Error(error);
        }
        std::string name;
        if (value.raw) {
            char raw[32];
            std::snprintf(raw, sizeof(raw), "r%llx", static_cast<unsigned long long>(value.rawConfig));
            name = raw;
        } else {
            std::vector<Etw::Source> sources;
            auto found = Etw::querySources(sources) ? sources.end()
                : std::find_if(sources.begin(), sources.end(), [&](const Etw::Source& item) { return item.id == value.source; });
            name = found == sources.end() ? "ETW source " + std::to_string(value.source) : "etw:" + found->name;
        }
        std::snprintf(error, sizeof(error), "Another async-profiler capture (pid %lu) uses %s; concurrent PMC captures must select the same overflow source",
            value.pid, name.c_str());
        return Error(error);
    }
    void rememberLibraries() { publisher.rememberLibraries(begin.load() ? qpc() : 0); }
    bool stackComplete(const Pending& item) const {
        return !stacks || (!item.user.empty() && (!kernelAddress(item.sample.ip) || !item.kernel.empty()));
    }
    // A sample weighs the interval in force at its timestamp. Local captures read
    // changes from the registry; the broker forwards them ahead of later samples.
    std::uint64_t intervalAt(std::uint64_t time) {
        if (!remote && time > intervalHorizon) {
            auto error = share.sync(watcher.state()->shareSlot, intervalPosition, intervals, intervalHorizon);
            if (error) { ULONG expected = 0; failure.compare_exchange_strong(expected, error); }
            intervalChanges = intervals.size() - 1;
        }
        auto next = std::upper_bound(intervals.begin(), intervals.end(), time,
            [](std::uint64_t value, const Etw::IntervalChange& change) { return value < change.qpc; });
        return (next - 1)->interval * intervalScale;
    }
    void publish(const Key& key, Pending& item) {
        if (!item.profile) { unmatchedStacks.fetch_add(1); return; }
        if (key.time < begin || (end.load() && key.time > end.load())) return;
        if (!windows.accepts(key.time)) return;
        const auto& sample = item.sample;
        if (!publisher.accepts(sample.tid)) return;
        accumulated += intervalAt(key.time) * sample.count;
        if (accumulated < weight) { decimated.fetch_add(1); return; }
        auto counter = accumulated;
        accumulated = 0;
        publisher.publish({.time = key.time, .ip = sample.ip, .counter = counter,
            .tid = sample.tid, .source = sample.source, .cpu = sample.cpu, .kernel = item.kernel, .user = item.user,
            .stacksRequested = stacks,
            .complete = stackComplete(item),
            .overflow = item.overflow});
    }
    void publishSoftware(Etw::SoftwareStacks::Ready& ready) {
        for (const auto& sample : ready) {
            if (sample.shared) softwareSharedUserStacks++;
            if (!windows.accepts(sample.time)) continue;
            // Like perf with a fault's user registers, a user-mode fault's stack starts at its PC.
            std::span<const std::uint64_t> kernel = sample.kernelRequired ? std::span<const std::uint64_t>(sample.kernel) : std::span<const std::uint64_t>();
            publisher.publish({.time = sample.time, .ip = sample.ip, .counter = weight, .tid = sample.tid,
                .source = source.id, .cpu = sample.cpu, .kernel = kernel, .user = sample.user,
                .stacksRequested = publishStacks, .complete = !publishStacks || sample.complete(), .overflow = sample.overflow});
        }
        ready.clear();
    }
    void softwareSample(const Etw::SoftwareRecord& record) {
        if (record.time < begin || (end.load() && record.time > end.load())) return;
        if (targetCpu >= 0 && record.cpu != targetCpu) return;
        // Context switches happen in kernel mode, like faults without a user PC.
        bool kernel = software == Etw::SoftwareKind::ContextSwitches || !record.ip || kernelAddress(record.ip);
        if (allUser && kernel) return;
        if (WindowsProfiler::isInternalThread(record.tid)) return;
        if (record.category >= 10 && record.category <= 15) faultCategories[record.category - 10]++;
        bool selected;
        auto result = softwarePeriods.count(record.tid, weight, selected);
        if (result) { softwareUnknownThreads++; failure = result; return; }
        softwareMatched++;
        if (!selected) return;
        Etw::SoftwareStacks::Sample sample;
        sample.time = record.time; sample.stackTime = record.stackTime; sample.ip = record.ip;
        sample.tid = record.tid; sample.cpu = record.cpu; sample.kernelRequired = kernel;
        result = softwareStacks.open(std::move(sample));
        if (result == ERROR_BUFFER_OVERFLOW) pendingEvictions++;
        if (result) failure = result;
    }
    bool beginThread(const Etw::SoftwareRecord& record) {
        auto result = softwarePeriods.begin(record.tid, record.kind == Etw::SoftwareRecordKind::ThreadRundown, record.time < begin);
        if (result) failure = result;
        return !result;
    }
    void softwarePart(ULONG tid, std::uint64_t time, std::span<const std::uint64_t> frames) {
        Etw::SoftwareStacks::Ready ready;
        softwareStacks.part(tid, time, frames, ready);
        publishSoftware(ready);
    }
    void endThread(ULONG tid) {
        Etw::SoftwareStacks::Ready ready;
        softwareStacks.end(tid, ready);
        publishSoftware(ready);
        softwarePeriods.end(tid);
    }
    void flushSoftwareCohort() {
        // A CPU tie does not establish a lifetime ordering. Starts precede
        // samples, ends follow samples; end/start reuse at one tick is unsafe.
        std::set<ULONG> ending;
        for (const auto& record : softwareCohort)
            if (record.kind == Etw::SoftwareRecordKind::ThreadEnd) ending.insert(record.tid);
        for (const auto& record : softwareCohort)
            if (record.kind == Etw::SoftwareRecordKind::ThreadStart && ending.contains(record.tid)) {
                failure = ERROR_INVALID_DATA; softwareCohort.clear(); softwareCohortParts.clear(); return;
            }
        for (const auto& record : softwareCohort)
            if ((record.kind == Etw::SoftwareRecordKind::ThreadStart || record.kind == Etw::SoftwareRecordKind::ThreadRundown)
                    && !beginThread(record)) { softwareCohort.clear(); softwareCohortParts.clear(); return; }
        for (const auto& record : softwareCohort) if (record.kind == Etw::SoftwareRecordKind::Sample && !failure.load()) softwareSample(record);
        for (const auto& part : softwareCohortParts) softwarePart(part.tid, part.time, part.frames);
        for (const auto& record : softwareCohort) if (record.kind == Etw::SoftwareRecordKind::ThreadEnd) endThread(record.tid);
        softwareCohort.clear(); softwareCohortParts.clear();
    }
    bool consumeSoftware(const EVENT_RECORD& event) {
        auto record = Etw::decodeSoftware(software, event);
        if (record.kind == Etw::SoftwareRecordKind::Ignore) return false;
        // Raw switches never leave the router.
        if (record.kind == Etw::SoftwareRecordKind::Malformed || record.kind == Etw::SoftwareRecordKind::Unsupported
                || record.kind == Etw::SoftwareRecordKind::Switch) {
            malformed++; failure = record.kind == Etw::SoftwareRecordKind::Unsupported ? ERROR_NOT_SUPPORTED : ERROR_INVALID_DATA;
            return true;
        }
        // Both local and broker streams pass the same exact-owner router.
        if (record.kind == Etw::SoftwareRecordKind::Sample && event.EventHeader.ProcessId != GetCurrentProcessId()) {
            softwareUnproven++; failure = ERROR_INVALID_DATA; return true;
        }
        if (software == Etw::SoftwareKind::ContextSwitches) {
            // Proven switches arrive with their switch-in stacks, in per-thread order.
            if (record.kind == Etw::SoftwareRecordKind::Sample) softwareSample(record);
            else if (record.kind == Etw::SoftwareRecordKind::ThreadEnd) endThread(record.tid);
            else beginThread(record);
            return true;
        }
        if (record.time < softwareCohortTime) { failure = ERROR_INVALID_DATA; return true; }
        if (!softwareCohort.empty() && record.time != softwareCohortTime) flushSoftwareCohort();
        if (failure.load()) return true;
        if (softwareCohort.size() == 65536) { failure = ERROR_BUFFER_OVERFLOW; return true; }
        softwareCohortTime = record.time; softwareCohort.push_back(record);
        return true;
    }
    void flush(bool all) {
        while (!pending.empty() && (all || pending.size() > 65536)) {
            auto item = pending.begin();
            if (!all) pendingEvictions.fetch_add(1);
            publish(item->first, item->second);
            pending.erase(item);
        }
    }
    void routeSoftware(const EVENT_RECORD& event) {
        Etw::Broker::ProfileView view;
        auto result = Etw::Broker::profileEvent(GetCurrentProcessId(), !allUser, event, view, software);
        Etw::Broker::ProfileRouter::Output output;
        if (!result) result = softwareRouter.route(view, threads.contains(view.tid), output);
        auto deliver = [&](std::vector<unsigned char>& packet) {
            if (packet.empty() || result) return;
            Etw::Broker::DecodedEvent decoded;
            result = Etw::Broker::decodeEvent(packet, this, decoded);
            if (!result) consume(decoded.event);
        };
        deliver(output.first); deliver(output.second);
        if (result) { ULONG expected = 0; failure.compare_exchange_strong(expected, result); }
    }
    void consume(const EVENT_RECORD& event) {
        if (software != Etw::SoftwareKind::None && consumeSoftware(event)) return;
        if (remote && IsEqualGUID(event.EventHeader.ProviderId, Etw::intervalChangeProvider)) {
            Etw::IntervalChange change;
            if (event.UserDataLength != sizeof(change)) { malformed.fetch_add(1); return; }
            std::memcpy(&change, event.UserData, sizeof(change));
            intervals.push_back(change);
            intervalChanges = intervals.size() - 1;
            return;
        }
        auto record = Etw::decode(event);
        switch (record.kind) {
            case Etw::Kind::Malformed:
                if (malformed.fetch_add(1) == 0) {
                    const auto& guid = event.EventHeader.ProviderId;
                    Log::warn("Malformed ETW event: provider=%08lx opcode=%u version=%u size=%u flags=%04x", guid.Data1,
                        event.EventHeader.EventDescriptor.Opcode, event.EventHeader.EventDescriptor.Version,
                        event.UserDataLength, event.EventHeader.Flags);
                }
                return;
            case Etw::Kind::Ignore: return;
            case Etw::Kind::UnsupportedStack:
                if (unsupportedStacks.fetch_add(1) == 0) {
                    Log::warn("Unsupported ETW StackWalk event: opcode=%u version=%u size=%u flags=%04x",
                        event.EventHeader.EventDescriptor.Opcode, event.EventHeader.EventDescriptor.Version,
                        event.UserDataLength, event.EventHeader.Flags);
                }
                return;
            case Etw::Kind::ImageLoad:
            case Etw::Kind::ImageUnload:
            case Etw::Kind::ImageRundown:
                WindowsProfiler::kernelImageChanged(record.imageBase, record.imageSize, record.imageChecksum,
                    record.kind == Etw::Kind::ImageUnload, record.kind == Etw::Kind::ImageRundown);
                return;
            case Etw::Kind::ThreadStart:
                if (record.pid == GetCurrentProcessId()) threads.insert(record.tid);
                else threads.erase(record.tid);
                return;
            case Etw::Kind::ThreadEnd: threads.erase(record.tid); return;
            case Etw::Kind::Profile:
                if (software != Etw::SoftwareKind::None) return;
                if (record.source != source.id || (targetCpu >= 0 && record.cpu != targetCpu)) return;
                if (record.pid != GetCurrentProcessId() && (record.pid != ULONG(-1) || !threads.contains(record.tid))) return;
                if (record.time < begin || (end.load() && record.time > end.load())) return;
                if (allUser && kernelAddress(record.ip)) return;
                if (WindowsProfiler::isInternalThread(record.tid)) return;
                break;
            case Etw::Kind::Stack:
                if (!stacks) return;
                if (record.pid != GetCurrentProcessId()) {
                    if (threads.contains(record.tid)) foreignThreadStacks.fetch_add(1);
                    return;
                }
                stackEvents.fetch_add(1);
                if (softwareMode()) {
                    // Parts complete already counted samples; their keys may lie
                    // outside the capture window. A fault cohort's tick is complete
                    // once a later header time arrives.
                    if (!record.depth) emptyStacks.fetch_add(1);
                    std::span<const std::uint64_t> frames(record.stack.data(), record.depth);
                    if (!softwareCohort.empty() && static_cast<std::uint64_t>(event.EventHeader.TimeStamp.QuadPart) <= softwareCohortTime) {
                        softwareCohortParts.push_back({record.tid, record.time, {frames.begin(), frames.end()}});
                        return;
                    }
                    if (!softwareCohort.empty()) flushSoftwareCohort();
                    softwarePart(record.tid, record.time, frames);
                    return;
                }
                if (record.time < begin || (end.load() && record.time > end.load())) { stackOutsideTime.fetch_add(1); return; }
                if (WindowsProfiler::isInternalThread(record.tid)) return;
                if (!record.depth) emptyStacks.fetch_add(1);
                break;
        }
        Key key{record.time, record.tid};
        auto& item = pending[key];
        if (record.kind == Etw::Kind::Profile) {
            item.sample = record;
            item.profile = true;
        } else {
            // Kernel frames before the first user frame form the kernel part;
            // user stacks keep the kernel frames of user-mode callbacks in place.
            bool user = false;
            for (size_t i = 0; i < record.depth; ++i) {
                auto pc = record.stack[i];
                user |= !kernelAddress(pc);
                auto& frames = user ? item.user : item.kernel;
                if (frames.size() < Etw::MAX_STACK_FRAMES) frames.push_back(pc);
                else item.overflow = true;
            }
        }
        if (item.profile && stackComplete(item)) {
            publish(key, item);
            pending.erase(key);
        }
        flush(false);
    }
    static void WINAPI onEvent(EVENT_RECORD* event) {
        auto self = static_cast<State*>(event->UserContext);
        if (self->failure.load()) return;
        try {
            if (self->remote) { WindowsProfiler::refreshModulesIfChanged(); self->rememberLibraries(); }
            if (!self->remote && self->softwareMode()) self->routeSoftware(*event);
            else self->consume(*event);
        }
        catch (...) { self->failure.store(ERROR_NOT_ENOUGH_MEMORY); }
    }
    static ULONG WINAPI onBuffer(EVENT_TRACE_LOGFILEW* logfile) {
        auto self = static_cast<State*>(logfile->Context);
        if (self->failure.load()) return FALSE;
        try { WindowsProfiler::refreshModulesIfChanged(); self->rememberLibraries(); }
        catch (...) { self->failure.store(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        return TRUE;
    }
    static void* process(void* data) {
        auto self = static_cast<State*>(data);
        WindowsProfiler::markInternalThread();
        auto result = self->remote ? Etw::Broker::consume(self, State::onEvent, self->brokerResult)
                                  : ProcessTrace(&self->consumer, 1, nullptr, nullptr);
        if (result != ERROR_SUCCESS && result != ERROR_CANCELLED) { ULONG expected = 0; self->failure.compare_exchange_strong(expected, result); }
        if (self->watcher.failed()) { ULONG expected = 0; self->failure.compare_exchange_strong(expected, ERROR_BROKEN_PIPE); }
        try {
            if (!self->remote && self->softwareMode()) {
                Etw::Broker::Result result;
                self->softwareRouter.finish(result);
                self->brokerResult.router = result.router;
                self->brokerForeign += result.foreignProfiles;
                self->brokerUnattributed += result.unattributedProfiles;
                self->brokerPotentialLoss += result.potentialTargetLoss;
                if (result.error) { ULONG expected = 0; self->failure.compare_exchange_strong(expected, result.error); }
            }
            self->publishRouterDiagnostics(self->brokerResult.router);
            self->flushSoftwareCohort();
            Etw::SoftwareStacks::Ready ready;
            self->softwareStacks.finish(ready);
            self->publishSoftware(ready);
            self->flush(true);
        }
        catch (...) { self->failure.store(ERROR_NOT_ENOUGH_MEMORY); }
        return nullptr;
    }
};

bool WindowsEtwEngine::accepts(const char* name) {
    // Upstream's cpu-clock forces perf_events; the ETW timer is its Windows counterpart.
    return std::strncmp(name, "etw:", 4) == 0 || std::strcmp(name, "cpu-clock") == 0 || Etw::hardwareAlias(name)
        || Etw::isRawPmu(name) || Etw::softwareEvent(name) != Etw::SoftwareKind::None;
}

Error WindowsEtwEngine::prepare(Arguments& args) {
    auto cpuError = Etw::validateTargetCpu(args._target_cpu);
    if (cpuError) return cpuError;
    auto software = Etw::softwareEvent(args._event);
    if (!_state) _state = new State();
    auto& state = *_state;
    auto stackError = state.publisher.prepare(args);
    if (stackError) return stackError;
    state.software = software;
    if (state.softwareMode()) {
        if (args._interval < 0) return Error("Windows software event intervals must be positive");
        auto requested = args._interval ? static_cast<std::uint64_t>(args._interval) : Etw::softwareDefaultPeriod(state.software);
        state.source = {0, 1, std::numeric_limits<ULONG>::max(), args._event};
        state.rawSource = false; state.rawConfig = {};
        state.weight = requested; state.heading = std::string(args._event) + " profile";
        state.counterUnit = "events"; state.counterType = args._event;
        auto error = state.windows.prepare(args._begin || args._end);
        if (error) return error;
        state.failure = 0;
        return Error::OK;
    }
    std::vector<Etw::Source> sources;
    Etw::Source raw{};
    const Etw::Source* source;
    state.rawSource = Etw::isRawPmu(args._event);
    if (state.rawSource) {
        auto error = Etw::parseRawPmu(args._event, state.rawConfig);
        if (error) return Error(error);
        // The kernel assigns the real ID at start, under the profile registry lock
        // and after the cleanup watcher can release the source.
        raw = {std::numeric_limits<ULONG>::max(), 1, std::numeric_limits<ULONG>::max(), args._event};
        source = &raw;
    } else {
        auto result = Etw::querySources(sources);
        if (result) return state.fail("Cannot enumerate Windows ETW profile sources", result);
        source = Etw::findSource(sources, args._event);
    }
    if (!source) return Error("Windows ETW profile source is unavailable; use list to see this host's sources");
    auto timerDefault = Etw::cpuTimerAlias(args._event) ? DEFAULT_INTERVAL : 1000000;
    auto requested = args._interval ? args._interval : state.rawSource ? 1000000 : source->id == 0 ? timerDefault
        : std::clamp<int64_t>(1000000, source->minimum, source->maximum);
    if (requested <= 0) return Error("Interval must be positive");
    if (source->id == 0 && requested % 100) return Error("ETW timer intervals must be multiples of 100ns");
    auto interval = source->id == 0 ? requested / 100 : requested;
    if (interval < source->minimum || interval > source->maximum) return Error("Interval is outside this Windows ETW source's supported range; use list");
    state.source = *source;
    state.weight = requested;
    state.heading = source->name + " profile";
    bool referenceCycles = _stricmp(source->name.c_str(), "UnhaltedReferenceCycles") == 0;
    state.counterUnit = source->id == 0 ? "ns" : referenceCycles || _stricmp(source->name.c_str(), "TotalCycles") == 0 ? "cycles"
        : _stricmp(source->name.c_str(), "InstructionRetired") == 0 ? "instructions" : "events";
    state.counterType = source->id == 0 ? (Etw::cpuTimerAlias(args._event) ? args._event : "cpu") : referenceCycles ? "ref-cycles"
        : state.counterUnit == "events" ? args._event : state.counterUnit;
    // Allocate before the trap callbacks can run; they must never allocate or
    // acquire a CRT lock while intercepting an arbitrary native function.
    auto windowError = state.windows.prepare(args._begin || args._end);
    if (windowError) return windowError;
    state.failure = 0;
    return Error::OK;
}

void WindowsEtwEngine::enableEvents(bool enabled) {
    if (!_state) { Engine::enableEvents(enabled); return; }
    if (!_state->windows.enable(*this, enabled)) _state->failure = ERROR_BUFFER_OVERFLOW;
}

const char* WindowsEtwEngine::type() { return _state ? _state->counterType.c_str() : "windows_etw"; }
const char* WindowsEtwEngine::title() { return _state ? _state->heading.c_str() : "Windows ETW profile"; }
const char* WindowsEtwEngine::units() { return _state ? _state->counterUnit.c_str() : "events"; }
int64_t WindowsEtwEngine::interval() { return _state ? _state->weight : 1; }

Error WindowsEtwEngine::start(Arguments& args) {
    auto& state = *_state;
    state.publisher.reset(); state.unmatchedStacks = 0; state.malformed = 0; state.lost = 0;
    state.stackEvents = 0; state.stackOutsideTime = 0;
    state.pendingEvictions = 0;
    state.emptyStacks = 0; state.foreignThreadStacks = 0; state.unsupportedStacks = 0;
    state.buffersLost = 0; state.realtimeBuffersLost = 0;
    state.brokerForeign = 0; state.brokerUnattributed = 0; state.brokerPotentialLoss = 0;
    state.brokerCleanupError = 0;
    state.pending.clear(); state.threads.clear();
    state.intervals.clear(); state.intervalPosition = state.intervalHorizon = state.accumulated = 0;
    state.decimated = 0; state.intervalChanges = 0;
    state.softwarePeriods.reset(); state.softwareStacks.reset(); state.softwareCohort.clear(); state.softwareCohortParts.clear();
    state.softwareCohortTime = 0;
    state.softwareMatched = 0; state.softwareUnknownThreads = 0; state.softwareUnproven = 0; state.softwareSharedUserStacks = 0;
    for (auto& category : state.faultCategories) category = 0;
    state.begin = 0; state.end = 0;
    state.allUser = args._alluser; state.publishStacks = args._cstack != CSTACK_NO || VM::loaded();
    state.stacks = state.softwareMode() || state.publishStacks;
    state.targetCpu = args._target_cpu;
    state.remote = false; state.brokerPid = 0; state.brokerResult = {};
    state.publishRouterDiagnostics({});
    state.softwareRouter = {};
    if (state.softwareMode()) state.softwareRouter.configureSoftware(GetCurrentProcessId(), true, state.software);
    if (Etw::Broker::connected()) {
        auto javaError = Java::start();
        if (javaError) { stop(); return javaError; }
        Etw::Broker::Request request;
        request.source = state.source.id;
        request.software = static_cast<ULONG>(state.software);
        // Software capture forwards every physical event. The target owns its
        // logical period and weight, including periods wider than this field.
        request.interval = state.softwareMode() ? 1 : static_cast<ULONG>(state.source.id == 0 ? state.weight / 100 : state.weight);
        request.stacks = state.stacks; request.images = !state.allUser; request.explicitInterval = args._interval != 0;
        request.raw = state.rawSource; request.rawConfig = state.rawConfig;
        Etw::Broker::Reply reply;
        auto result = Etw::Broker::start(request, reply);
        if (result) {
            stop();
            return result == ERROR_BUSY && reply.conflict.kind != Etw::ShareConflictKind::None ? state.conflict(reply.conflict)
                : state.fail("Cannot start capture through the privileged ETW broker", result);
        }
        state.remote = true; state.brokerPid = reply.pid;
        state.source.id = reply.source;
        if (!state.softwareMode()) {
            state.intervalScale = reply.source == 0 ? 100 : 1;
            state.weight = static_cast<std::uint64_t>(reply.interval) * state.intervalScale;
        }
        auto list = OS::listThreads();
        while (list->hasNext()) {
            auto tid = list->next(); state.threads.insert(tid);
            if (state.softwareMode()) state.softwarePeriods.seed(tid);
        }
        delete list;
        std::vector<WindowsProfiler::KernelModule> kernel;
        if (!state.allUser && Etw::Broker::kernelModules(kernel)) {
            for (const auto& module : kernel) WindowsProfiler::kernelImageChanged(module.base, module.size, module.checksum, false, true);
            WindowsProfiler::refreshModulesIfChanged();
        }
        state.rememberLibraries();
        state.publisher.calibrateClock(); state.begin = UINT64_MAX;
        result = Etw::Broker::activate();
        if (result) { stop(); return state.fail("Cannot activate the privileged ETW collector", result); }
        if (pthread_create(&state.worker, nullptr, State::process, &state) != 0) { stop(); return Error("Cannot create the ETW broker consumer thread"); }
        state.started = true; state.begin.store(qpc(), std::memory_order_release);
        return Error::OK;
    }
    auto result = state.privilege.enable();
    if (result) { stop(); return state.fail("ETW capture requires SeSystemProfilePrivilege (run the target elevated)", result); }
    auto javaError = Java::start();
    if (javaError) { stop(); return javaError; }
    state.properties = {};
    auto& properties = state.properties.p;
    properties.Wnode.BufferSize = sizeof(state.properties);
    properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.Wnode.ClientContext = 1;
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&properties.Wnode.Guid), sizeof(GUID), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        stop(); return Error("Cannot generate a private ETW session GUID");
    }
    std::swprintf(state.properties.name, 128, L"async-profiler-%lu-%llu", GetCurrentProcessId(), static_cast<unsigned long long>(qpc()));
    properties.LoggerNameOffset = offsetof(State::Properties, name);
    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    properties.BufferSize = 64; properties.MinimumBuffers = 64; properties.MaximumBuffers = 512; properties.FlushTimer = 1;
    if (!state.softwareMode() && (result = state.share.open())) {
        stop(); return state.fail("Cannot open the shared ETW profile configuration", result);
    }
    result = state.watcher.start(state.properties, state.softwareMode() ? nullptr : &state.share);
    if (result) { stop(); return state.fail("Cannot start asprof-helper.exe outside the target job; place it beside the DLL and permit job breakaway", result); }
    InterlockedExchange(&state.watcher.state()->sessionOwned, 1);
    result = StartTraceW(&state.session, state.properties.name, &properties);
    if (result) {
        InterlockedExchange(&state.watcher.state()->sessionOwned, 0);
        state.session = 0; stop(); return state.fail("Cannot start a private Windows system trace session", result);
    }
    if (state.stacks) {
        CLASSIC_EVENT_ID stackEvent{}; stackEvent.EventGuid = perfInfo; stackEvent.Type = state.source.id == 0 ? 46 : 47;
        auto events = state.softwareMode() ? Etw::softwareStackEvents(state.software) : std::span<const CLASSIC_EVENT_ID>(&stackEvent, 1);
        result = TraceSetInformation(state.session, TraceStackTracingInfo, const_cast<CLASSIC_EVENT_ID*>(events.data()), events.size_bytes());
        if (result) { stop(); return state.fail("Cannot enable ETW event stack capture", result); }
    }
    if (!state.softwareMode()) {
        Etw::ShareRequest request{state.source.id, static_cast<ULONG>(state.source.id == 0 ? state.weight / 100 : state.weight),
            GetCurrentProcessId(), args._interval != 0, state.rawSource, state.rawConfig};
        Etw::ShareGrant grant;
        result = state.share.join(*state.watcher.state(), request, grant);
        if (result) {
            stop();
            return result == ERROR_BUSY && grant.conflict.kind != Etw::ShareConflictKind::None ? state.conflict(grant.conflict)
                : state.fail(!state.rawSource ? "Cannot configure the shared ETW profile"
                    : result == ERROR_INVALID_PARAMETER ? "Raw PMU interval is outside this Windows source's supported range"
                    : "Cannot register this raw PMU event (processor and Windows support are required)", result);
        }
        state.intervalScale = grant.source == 0 ? 100 : 1;
        state.weight = static_cast<std::uint64_t>(grant.requested) * state.intervalScale;
        state.intervals = {{0, grant.interval, 0}};
        state.intervalPosition = grant.position;
        if (state.rawSource) { state.source.id = grant.source; state.source.minimum = grant.minimum; state.source.maximum = grant.maximum; }
    } else {
        ULONG lifecycle[8] = {EVENT_TRACE_FLAG_THREAD | (state.allUser ? 0 : EVENT_TRACE_FLAG_IMAGE_LOAD)};
        result = TraceSetInformation(state.session, TraceSystemTraceEnableFlagsInfo, lifecycle, sizeof(lifecycle));
        if (result) { stop(); return state.fail("Cannot enable Windows software-event thread lifetimes", result); }
    }
    auto list = OS::listThreads();
    while (list->hasNext()) {
        auto tid = list->next(); state.threads.insert(tid);
        if (state.softwareMode()) state.softwarePeriods.seed(tid);
    }
    delete list;
    state.rememberLibraries();
    state.publisher.calibrateClock(); state.begin = UINT64_MAX;
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = state.properties.name;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.EventRecordCallback = State::onEvent; logfile.BufferCallback = State::onBuffer; logfile.Context = &state;
    state.consumer = OpenTraceW(&logfile);
    if (state.consumer == INVALID_PROCESSTRACE_HANDLE) { result = GetLastError(); stop(); return state.fail("Cannot open the ETW realtime consumer", result); }
    if (pthread_create(&state.worker, nullptr, State::process, &state) != 0) { stop(); return Error("Cannot create the ETW consumer thread"); }
    state.started = true;
    ULONG flags[8] = {EVENT_TRACE_FLAG_THREAD | (state.softwareMode() ? Etw::softwareEnableFlags(state.software)
        : state.source.id == 0 ? EVENT_TRACE_FLAG_PROFILE : 0)};
    if (!state.allUser) flags[0] |= EVENT_TRACE_FLAG_IMAGE_LOAD;
    if (!state.softwareMode() && state.source.id != 0) flags[1] = Etw::PMC_PROFILE_MASK;
    result = TraceSetInformation(state.session, TraceSystemTraceEnableFlagsInfo, flags, sizeof(flags));
    if (result) { stop(); return state.fail("Cannot enable Windows profiling events", result); }
    result = state.watcher.activate();
    if (result) { stop(); return state.fail("The ETW session watcher exited during startup", result); }
    state.begin.store(qpc(), std::memory_order_release);
    return Error::OK;
}

void WindowsEtwEngine::stop() {
    if (!_state) return;
    auto& state = *_state;
    if (state.remote) {
        auto keepFailure = [&](ULONG code) {
            if (code) { ULONG previous = 0; state.failure.compare_exchange_strong(previous, code); }
        };
        state.end = qpc();
        auto error = Etw::Broker::stop();
        keepFailure(error);
        if (state.started) { pthread_join(state.worker, nullptr); state.started = false; }
        else {
            error = Etw::Broker::consume(&state, State::onEvent, state.brokerResult);
            keepFailure(error);
        }
        state.lost.fetch_add(state.brokerResult.eventsLost);
        state.buffersLost.fetch_add(state.brokerResult.buffersLost);
        state.realtimeBuffersLost.fetch_add(state.brokerResult.realtimeBuffersLost);
        state.brokerForeign.fetch_add(state.brokerResult.foreignProfiles);
        state.brokerUnattributed.fetch_add(state.brokerResult.unattributedProfiles);
        state.brokerPotentialLoss.fetch_add(state.brokerResult.potentialTargetLoss);
        state.brokerCleanupError = state.brokerResult.cleanupError;
        keepFailure(state.brokerResult.error);
        state.remote = false;
        Java::stop();
        return;
    }
    if (state.watcher.state()) {
        state.end = qpc();
        auto error = state.watcher.cleanup();
        if (error) {
            state.failure = error;
            Log::error("Cannot stop ETW session %s: %lu", WindowsProfiler::utf8(state.properties.name).c_str(), error);
            if (state.consumer != INVALID_PROCESSTRACE_HANDLE) CloseTrace(state.consumer);
        }
        state.session = 0;
    }
    if (state.started) { pthread_join(state.worker, nullptr); state.started = false; }
    Java::stop();
    if (state.consumer != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(state.consumer); state.consumer = INVALID_PROCESSTRACE_HANDLE; }
    auto result = state.watcher.finish();
    state.lost.fetch_add(result.eventsLost);
    state.buffersLost.fetch_add(result.buffersLost);
    state.realtimeBuffersLost.fetch_add(result.realtimeBuffersLost);
    if (result.error) { state.failure = result.error; Log::error("ETW session cleanup failed: %lu", result.error); }
    state.share.close();
    state.privilege.restore();
}

Error WindowsEtwEngine::stopError() {
    if (_state && _state->failure.load() && _state->brokerResult.unsupportedFormat) {
        auto format = _state->brokerResult.unsupportedFormat;
        std::snprintf(_state->error, sizeof(_state->error), "Windows ETW capture failed: record family=%lu version=%lu opcode=%lu width=%lu reason=%lu (Windows error %lu)",
            format >> 24, (format >> 16) & 255, (format >> 8) & 255, format & 15, (format >> 4) & 15, _state->failure.load());
        return Error(_state->error);
    }
    if (!_state) return Error::OK;
    auto error = _state->failure.load();
    return error ? _state->fail("Windows ETW capture failed", error) : Error::OK;
}

Error WindowsEtwEngine::list(Writer& out) {
    std::vector<Etw::Source> sources;
    auto result = Etw::querySources(sources);
    if (result) return Error("Cannot enumerate Windows ETW profile sources");
    out << "Windows ETW sources (capture requires SeSystemProfilePrivilege):\n";
    out << "  page-faults  interval=1..9223372036854775807 events  default=1\n";
    out << "  context-switches  interval=1..9223372036854775807 events  default=2\n";
    for (const auto& source : sources) {
        u64 multiplier = source.id == 0 ? 100 : 1;
        out << "  etw:" << source.name.c_str() << "  source=" << static_cast<u64>(source.id)
            << " interval=" << source.minimum * multiplier << ".." << source.maximum * multiplier;
        out << (source.id == 0 ? " ns\n" : " events\n");
    }
    out << "  cpu-clock -> etw:Timer\n";
    for (const auto& alias : Etw::hardwareAliases()) {
        auto source = Etw::findSource(sources, alias.name);
        out << "  " << alias.name;
        if (source) out << " -> etw:" << source->name.c_str() << "  interval="
            << u64(source->minimum) << ".." << u64(source->maximum) << " events\n";
        else out << "  unavailable: no equivalent HAL source\n";
    }
    return Error::OK;
}

void WindowsEtwEngine::writeMetrics(Writer& out) {
    if (!_state) return;
    _state->publisher.writeMetrics(out, "windows_etw_");
    out << "windows_etw_stack_events " << static_cast<u64>(_state->stackEvents.load()) << '\n';
    out << "windows_etw_stack_outside_time " << static_cast<u64>(_state->stackOutsideTime.load()) << '\n';
    out << "windows_etw_pending_evictions " << static_cast<u64>(_state->pendingEvictions.load()) << '\n';
    out << "windows_etw_empty_stacks " << static_cast<u64>(_state->emptyStacks.load()) << '\n';
    out << "windows_etw_foreign_thread_stacks " << static_cast<u64>(_state->foreignThreadStacks.load()) << '\n';
    out << "windows_etw_unsupported_stack_events " << static_cast<u64>(_state->unsupportedStacks.load()) << '\n';
    out << "windows_etw_unmatched_stacks " << static_cast<u64>(_state->unmatchedStacks.load()) << '\n';
    out << "windows_etw_malformed_events " << static_cast<u64>(_state->malformed.load()) << '\n';
    out << "windows_etw_events_lost " << static_cast<u64>(_state->lost.load()) << '\n';
    out << "windows_etw_buffers_lost " << static_cast<u64>(_state->buffersLost.load()) << '\n';
    out << "windows_etw_realtime_buffers_lost " << static_cast<u64>(_state->realtimeBuffersLost.load()) << '\n';
    out << "windows_etw_watchdog_pid " << static_cast<u64>(_state->watcher.pid()) << '\n';
    out << "windows_etw_decimated_samples " << static_cast<u64>(_state->decimated.load()) << '\n';
    out << "windows_etw_interval_changes " << static_cast<u64>(_state->intervalChanges.load()) << '\n';
    out << "windows_etw_broker_pid " << static_cast<u64>(_state->brokerPid) << '\n';
    out << "windows_etw_broker_foreign_profiles " << static_cast<u64>(_state->brokerForeign.load()) << '\n';
    out << "windows_etw_broker_unattributed_profiles " << static_cast<u64>(_state->brokerUnattributed.load()) << '\n';
    out << "windows_etw_broker_potential_target_loss " << static_cast<u64>(_state->brokerPotentialLoss.load()) << '\n';
    out << "windows_etw_broker_cleanup_error " << static_cast<u64>(_state->brokerCleanupError.load()) << '\n';
    out << "windows_etw_software_matched_events " << u64(_state->softwareMatched.load()) << '\n';
    out << "windows_etw_software_unknown_threads " << u64(_state->softwareUnknownThreads.load()) << '\n';
    out << "windows_etw_software_unproven_events " << u64(_state->softwareUnproven.load()) << '\n';
    auto router = _state->readRouterDiagnostics();
    out << "windows_etw_software_shared_user_stacks " << u64(_state->softwareSharedUserStacks.load()) << '\n';
    out << "windows_etw_software_router_reason " << u64(router.reason) << '\n';
    out << "windows_etw_software_router_samples " << u64(router.samples) << '\n';
    out << "windows_etw_software_router_stacks " << u64(router.stacks) << '\n';
    out << "windows_etw_software_router_target_stacks " << u64(router.targetStacks) << '\n';
    out << "windows_etw_software_router_switch_outs " << u64(router.switchOuts) << '\n';
    out << "windows_etw_software_router_switch_ins " << u64(router.switchIns) << '\n';
    out << "windows_etw_software_router_proven_target_switches " << u64(router.provenTarget) << '\n';
    out << "windows_etw_software_router_proven_foreign_switches " << u64(router.provenForeign) << '\n';
    out << "windows_etw_software_router_terminated_switches " << u64(router.terminatedSwitches) << '\n';
    out << "windows_etw_software_router_exiting_events " << u64(router.exitingEvents) << '\n';
    out << "windows_etw_software_router_sequence_breaks " << u64(router.sequenceBreaks) << '\n';
    out << "windows_etw_software_router_unresolved_switches " << u64(router.unresolved) << '\n';
    out << "windows_etw_software_router_switch_high_water " << u64(router.switchHighWater) << '\n';
    out << "windows_etw_software_router_exiting_high_water " << u64(router.exitingHighWater) << '\n';
    for (size_t i = 0; i < _state->faultCategories.size(); ++i)
        out << "windows_etw_page_fault_category_" << u64(10 + i) << ' ' << u64(_state->faultCategories[i].load()) << '\n';
    out << "windows_etw_failure " << static_cast<u64>(_state->failure.load()) << '\n';
    _state->windows.writeMetrics(out, "windows_etw_");
}
