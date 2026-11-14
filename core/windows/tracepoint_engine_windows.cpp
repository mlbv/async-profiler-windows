/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsTracepointEngine.h"
#include "windowsTracepoint.h"
#include "windowsTracepointStack.h"
#include "windowsTracepointSession.h"
#include "windowsEtwStack.h"
#include "windowsEtwWatcher.h"
#include "windowsEtwBroker.h"
#include "windowsKernel.h"
#include "windowsJava.h"
#include "profiler.h"
#include "threadFilter.h"
#include "writer.h"
#include "vmStructs.h"
#include <bcrypt.h>
#include <pthread.h>
#include <tdh.h>
#include <atomic>
#include <cwchar>
#include <cstring>
#include <map>
#include <set>
#include <vector>

using namespace WindowsProfiler;
namespace {
std::uint64_t tracepointQpc() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }
constexpr auto kernelProcess = Tracepoint::KERNEL_PROCESS_PROVIDER;
}

struct WindowsTracepointEngine::State {
    Tracepoint::Selector selector;
    Etw::Properties properties{};
    Etw::SessionWatcher watcher;
    Tracepoint::ProviderLease provider;
    Etw::StackPublisher publisher;
    Etw::EventWindows windows;
    TRACEHANDLE session = 0, consumer = INVALID_PROCESSTRACE_HANDLE;
    pthread_t worker{};
    bool started = false, stacks = true, remote = false;
    DWORD brokerPid = 0;
    Etw::Broker::Result brokerResult{};
    std::atomic<ULONG> brokerCleanupError{0};
    ULONG pid = 0;
    int targetCpu = -1;
    std::uint64_t weight = 1;
    std::atomic<std::uint64_t> begin{0}, end{0};
    std::atomic<std::uint64_t> matched{0}, wrongName{0}, malformed{0}, cpuFiltered{0};
    std::atomic<std::uint64_t> threadStarts{0}, threadEnds{0}, unknownThreads{0};
    std::atomic<std::uint64_t> observedSelected{0}, versionMismatches{0}, headerPidRejections{0};
    struct HeaderTuple { std::atomic<ULONG> id{0}, version{0}, pid{0}, tid{0}; };
    std::array<HeaderTuple, 4> firstHeaders;
    std::atomic<unsigned> firstHeaderCount{0};
    std::atomic<ULONG> failure{0};
    ULONG eventsLost = 0, buffersLost = 0, realtimeBuffersLost = 0;
    char error[256]{};
    HMODULE tdh = nullptr;
    decltype(&TdhGetEventInformation) eventInformation = nullptr;
    std::wstring eventName;
    std::vector<unsigned char> metadata;
    struct ThreadPhase { std::uint64_t phase = 0, lifetime = 0; };
    std::map<ULONG, ThreadPhase> phases;
    std::uint64_t nextLifetime = 0;
    Tracepoint::StackJoiner stackJoiner;
    enum class PendingKind { Start, Sample, End };
    struct Pending { PendingKind kind; std::uint64_t time; ULONG tid; Tracepoint::Record record; };
    std::vector<Pending> cohort;
    std::uint64_t cohortTime = 0;

    Error fail(const char* operation, ULONG code) {
        std::snprintf(error, sizeof(error), "%s (Windows error %lu)", operation, code);
        return Error(error);
    }
    void finishJava() {
        Java::stop();
        if (tdh) { FreeLibrary(tdh); tdh = nullptr; eventInformation = nullptr; }
    }
    bool namedEvent(const EVENT_RECORD& event) {
        if (eventName.empty()) return true;
        ULONG needed = 0;
        auto result = eventInformation(const_cast<EVENT_RECORD*>(&event), 0, nullptr, nullptr, &needed);
        if (result != ERROR_INSUFFICIENT_BUFFER || needed < offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray) || needed > 1024 * 1024) {
            failure = result ? result : ERROR_INVALID_DATA; return false;
        }
        metadata.resize(needed);
        auto info = reinterpret_cast<TRACE_EVENT_INFO*>(metadata.data());
        result = eventInformation(const_cast<EVENT_RECORD*>(&event), 0, nullptr, info, &needed);
        if (result || needed < offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray) || needed > metadata.size()) {
            failure = result ? result : ERROR_INVALID_DATA; return false;
        }
        if (static_cast<unsigned>(info->DecodingSource) != 0 && static_cast<unsigned>(info->DecodingSource) != 3) {
            failure = ERROR_NOT_SUPPORTED; return false;
        }
        // Current SDK calls this union member EventNameOffset for XML/Tlg.
        // MinGW's older headers retain its WBEM alias ActivityIDNameOffset.
        ULONG offset = info->ActivityIDNameOffset;
        if (!offset || offset % sizeof(WCHAR) || offset >= needed) { failure = ERROR_INVALID_DATA; return false; }
        auto name = reinterpret_cast<const WCHAR*>(metadata.data() + offset);
        size_t capacity = (needed - offset) / sizeof(WCHAR), length = 0;
        while (length < capacity && name[length]) ++length;
        if (length == capacity) { failure = ERROR_INVALID_DATA; return false; }
        return std::wstring_view(name, length) == eventName;
    }
    void publish(const Tracepoint::JoinedStack& joined) {
        const auto& record = joined.record;
        std::array<std::uint64_t, 2 * Tracepoint::MAX_STACK_FRAMES> kernel{}, user{};
        size_t kernels = 0, users = 0;
        for (size_t i = 0; i < record.stackCount; ++i) {
            const auto& stack = record.stacks[i];
            for (size_t frame = 0; frame < stack.depth; ++frame) {
                auto pc = stack.addresses[frame];
                if (pc >> 63) kernel[kernels++] = pc;
                else user[users++] = pc;
            }
        }
        Etw::StackSample sample;
        sample.time = record.time; sample.tid = record.tid; sample.cpu = record.cpu;
        sample.ip = users ? user[0] : kernels ? kernel[0] : 0;
        sample.counter = joined.counter; sample.stacksRequested = stacks;
        sample.kernel = {kernel.data(), kernels}; sample.user = {user.data(), users};
        sample.complete = users || kernels;
        sample.rawLimit = Tracepoint::MAX_STACK_FRAMES;
        publisher.publish(sample);
    }
    void unselected(const Tracepoint::Record& record) {
        auto result = stackJoiner.unselected(record);
        if (result) { ULONG expected = 0; failure.compare_exchange_strong(expected, result); }
    }
    void select(Tracepoint::Record&& record) {
        auto phase = phases.find(record.tid);
        if (phase == phases.end()) { unknownThreads++; failure = ERROR_INVALID_DATA; return; }
        matched++;
        if (++phase->second.phase != weight) { unselected(record); return; }
        phase->second.phase = 0;
        if (!windows.accepts(record.time)) { unselected(record); return; }
        Tracepoint::JoinedStack joined;
        bool ready;
        auto result = stackJoiner.primary(std::move(record), phase->second.lifetime, weight, joined, ready);
        if (result) { failure = result; return; }
        if (ready) publish(joined);
    }
    void finishStacks() {
        if (!failure.load()) flushCohort();
        auto result = stackJoiner.finish();
        if (result) { ULONG expected = 0; failure.compare_exchange_strong(expected, result); }
    }
    void flushCohort() {
        // ProcessTrace orders valid QPC records, but ties across CPUs are
        // unordered. Establish thread lifetimes before samples at that tick.
        std::set<ULONG> ending;
        for (const auto& item : cohort) if (item.kind == PendingKind::End) ending.insert(item.tid);
        for (const auto& item : cohort) if (item.kind == PendingKind::Start) {
            if (ending.contains(item.tid)) { failure = ERROR_INVALID_DATA; cohort.clear(); return; }
            if (phases.contains(item.tid) && item.time >= begin) { failure = ERROR_INVALID_DATA; cohort.clear(); return; }
            phases[item.tid] = {0, ++nextLifetime}; threadStarts++;
        }
        for (auto& item : cohort) if (item.kind == PendingKind::Sample && !failure.load()) select(std::move(item.record));
        for (const auto& item : cohort) if (item.kind == PendingKind::End) { phases.erase(item.tid); threadEnds++; }
        cohort.clear();
    }
    void queue(Pending item) {
        if (!cohort.empty() && item.time < cohortTime) { failure = ERROR_INVALID_DATA; return; }
        if (!cohort.empty() && item.time != cohortTime) flushCohort();
        if (failure.load()) return;
        if (cohort.size() == 65536) { failure = ERROR_BUFFER_OVERFLOW; return; }
        cohortTime = item.time; cohort.push_back(std::move(item));
    }
    void consume(const EVENT_RECORD& event) {
        if (failure.load()) return;
        if (remote && modulesChanged()) {
            refreshModulesIfChanged();
            publisher.rememberLibraries(tracepointQpc());
        }
        auto time = static_cast<std::uint64_t>(event.EventHeader.TimeStamp.QuadPart);
        if (time >= begin && (!end.load() || time <= end.load())
                && IsEqualGUID(event.EventHeader.ProviderId, selector.provider)
                && (selector.name.empty() ? event.EventHeader.EventDescriptor.Id == selector.eventId : true)) {
            observedSelected++;
            if (selector.version >= 0 && event.EventHeader.EventDescriptor.Version != selector.version) versionMismatches++;
            if (event.EventHeader.ProcessId != pid) headerPidRejections++;
            auto index = firstHeaderCount.load(std::memory_order_relaxed);
            if (index < firstHeaders.size()) {
                auto& tuple = firstHeaders[index];
                tuple.id = event.EventHeader.EventDescriptor.Id; tuple.version = event.EventHeader.EventDescriptor.Version;
                tuple.pid = event.EventHeader.ProcessId; tuple.tid = event.EventHeader.ThreadId;
                firstHeaderCount.store(index + 1, std::memory_order_release);
            }
        }
        if (IsEqualGUID(event.EventHeader.ProviderId, kernelProcess)) {
            auto id = event.EventHeader.EventDescriptor.Id;
            if (id == 3 || id == 4) {
                if (!event.UserData || event.UserDataLength < 8) { failure = ERROR_INVALID_DATA; return; }
                ULONG identity[2]; std::memcpy(identity, event.UserData, sizeof(identity));
                if (identity[0] == pid) {
                    if (event.EventHeader.EventDescriptor.Version > 1) { failure = ERROR_NOT_SUPPORTED; return; }
                    queue({id == 3 ? PendingKind::Start : PendingKind::End,
                        static_cast<std::uint64_t>(event.EventHeader.TimeStamp.QuadPart), identity[1], {}});
                }
            }
            if (!IsEqualGUID(selector.provider, kernelProcess)) return;
        }
        auto record = Tracepoint::decode(event, selector, pid);
        if (record.kind == Tracepoint::Kind::Ignore) return;
        if (record.kind == Tracepoint::Kind::Malformed) { malformed++; failure = ERROR_INVALID_DATA; return; }
        if (record.kind == Tracepoint::Kind::Continuation) {
            if (record.time < begin) return;
            Tracepoint::JoinedStack joined;
            bool ready;
            auto result = stackJoiner.continuation(std::move(record), joined, ready);
            if (result) { failure = result; return; }
            if (ready) publish(joined);
            return;
        }
        if (record.time < begin || (end.load() && record.time > end.load())) { unselected(record); return; }
        if (targetCpu != -1 && record.cpu != targetCpu) { cpuFiltered++; unselected(record); return; }
        if (isInternalThread(record.tid)) { unselected(record); return; }
        auto filter = Profiler::instance()->threadFilter();
        if (filter->enabled() && !filter->contains(record.tid)) { unselected(record); return; }
        if (!namedEvent(event)) { if (!failure.load()) { wrongName++; unselected(record); } return; }
        if (eventName.empty() && !record.schema.empty()) { failure = ERROR_NOT_SUPPORTED; return; }
        queue({PendingKind::Sample, record.time, record.tid, std::move(record)});
    }
    static void WINAPI onEvent(EVENT_RECORD* event) {
        auto self = static_cast<State*>(event->UserContext);
        try { self->consume(*event); }
        catch (...) { self->failure = ERROR_NOT_ENOUGH_MEMORY; }
    }
    static ULONG WINAPI onBuffer(EVENT_TRACE_LOGFILEW* log) {
        auto self = static_cast<State*>(log->Context);
        if (self->watcher.failed()) { self->failure = ERROR_BROKEN_PIPE; return FALSE; }
        try {
            refreshModulesIfChanged();
            self->publisher.rememberLibraries(tracepointQpc());
        } catch (...) { self->failure = ERROR_NOT_ENOUGH_MEMORY; }
        return self->failure.load() ? FALSE : TRUE;
    }
    static void* process(void* data) {
        auto self = static_cast<State*>(data);
        markInternalThread();
        auto result = self->remote ? Etw::Broker::consume(self, onEvent, self->brokerResult)
            : ProcessTrace(&self->consumer, 1, nullptr, nullptr);
        if (result != ERROR_SUCCESS && result != ERROR_CANCELLED) self->failure = result;
        try { self->finishStacks(); }
        catch (...) { self->failure = ERROR_NOT_ENOUGH_MEMORY; }
        return nullptr;
    }
};

bool WindowsTracepointEngine::accepts(const char* event) { return std::strncmp(event, "trace:", 6) == 0; }
int64_t WindowsTracepointEngine::interval() { return _state ? _state->weight : 1; }
Error WindowsTracepointEngine::prepare(Arguments& args) {
    auto cpuError = Etw::validateTargetCpu(args._target_cpu);
    if (cpuError) return cpuError;
    if (args._alluser) return Error("alluser requires privilege-origin filtering, unavailable in Windows provider event headers");
    if (args._features.vtable_target) return Error("vtable feature requires sampled receiver registers, unavailable in ETW tracepoint events");
    if (args._features.comp_task) return Error("comptask feature requires the sampled compiler task, unavailable in ETW tracepoint events");
    if (args._interval < 0) return Error("Tracepoint interval must be positive");
    if (!_state) _state = new State();
    auto& state = *_state;
    if (auto error = Tracepoint::parseSelector(args._event, state.selector)) return Error(error);
    state.weight = args._interval ? args._interval : 1;
    state.targetCpu = args._target_cpu;
    state.stacks = args._cstack != CSTACK_NO || VM::loaded();
    auto error = state.publisher.prepare(args);
    if (error) return error;
    error = state.windows.prepare(args._begin || args._end);
    if (error) return error;
    state.eventName = state.selector.name.empty() ? std::wstring() : wide(state.selector.name);
    return Error::OK;
}

Error WindowsTracepointEngine::start(Arguments& args) {
    auto& state = *_state;
    state.failure = 0; state.matched = 0; state.wrongName = 0; state.malformed = 0; state.cpuFiltered = 0;
    state.threadStarts = 0; state.threadEnds = 0; state.unknownThreads = 0;
    state.observedSelected = 0; state.versionMismatches = 0; state.headerPidRejections = 0; state.firstHeaderCount = 0;
    state.phases.clear(); state.nextLifetime = 0; state.cohort.clear(); state.cohortTime = 0;
    state.stackJoiner.reset(GetCurrentProcessId());
    state.begin = UINT64_MAX; state.end = 0;
    state.remote = false; state.brokerPid = 0; state.brokerResult = {}; state.brokerCleanupError = 0;
    state.pid = GetCurrentProcessId();
    state.eventsLost = state.buffersLost = state.realtimeBuffersLost = 0;
    state.publisher.reset();
    if (!state.eventName.empty()) {
        state.tdh = LoadLibraryExW(L"tdh.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!state.tdh) return state.fail("Cannot load Windows TDH for named tracepoints", GetLastError());
        state.eventInformation = reinterpret_cast<decltype(state.eventInformation)>(GetProcAddress(state.tdh, "TdhGetEventInformation"));
        if (!state.eventInformation) {
            auto result = GetLastError(); stop(); return state.fail("Windows TDH event information is unavailable", result);
        }
    }
    auto error = Java::start();
    if (error) { stop(); return error; }
    state.publisher.rememberLibraries(0); state.publisher.calibrateClock();
    if (Etw::Broker::connected()) {
        Etw::Broker::ProviderRequest request;
        request.provider = state.selector.provider; request.eventId = state.selector.eventId; request.version = state.selector.version;
        request.flags = Etw::Broker::Stacks | (state.selector.name.empty() ? 0 : Etw::Broker::Named)
            | (args._cstack == CSTACK_NO ? 0 : Etw::Broker::Images);
        Etw::Broker::Reply reply;
        auto result = Etw::Broker::startProvider(request, reply);
        if (result) { stop(); return state.fail("Cannot start provider capture through the privileged ETW broker", result); }
        state.remote = true; state.brokerPid = reply.pid;
        auto threads = OS::listThreads();
        while (threads->hasNext()) state.phases.emplace(threads->next(), State::ThreadPhase{0, ++state.nextLifetime});
        delete threads;
        if (request.flags & Etw::Broker::Images) {
            std::vector<KernelModule> kernel;
            if (Etw::Broker::kernelModules(kernel)) {
                for (const auto& module : kernel) kernelImageChanged(module.base, module.size, module.checksum, false, true);
                refreshModulesIfChanged(); state.publisher.rememberLibraries(0);
            }
        }
        result = Etw::Broker::activate();
        if (result) { stop(); return state.fail("Cannot activate the privileged tracepoint collector", result); }
        if (pthread_create(&state.worker, nullptr, State::process, &state) != 0) {
            stop(); return Error("Cannot create tracepoint broker consumer thread");
        }
        state.started = true; state.begin = tracepointQpc();
        return Error::OK;
    }
    state.properties = {};
    auto& properties = state.properties.p;
    properties.Wnode.BufferSize = sizeof(state.properties); properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.Wnode.ClientContext = 1;
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&properties.Wnode.Guid), sizeof(GUID), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        stop(); return Error("Cannot generate a private ETW tracepoint session GUID");
    }
    std::swprintf(state.properties.name, 128, L"async-profiler-%lu-%llu", GetCurrentProcessId(),
        static_cast<unsigned long long>(tracepointQpc()));
    properties.LoggerNameOffset = offsetof(Etw::Properties, name);
    properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties.BufferSize = 64; properties.MinimumBuffers = 16; properties.MaximumBuffers = 128; properties.FlushTimer = 1;
    auto result = state.watcher.start(state.properties, nullptr);
    if (result) { stop(); return state.fail("Cannot start tracepoint cleanup watcher", result); }
    InterlockedExchange(&state.watcher.state()->sessionOwned, 1);
    result = StartTraceW(&state.session, state.properties.name, &properties);
    if (result) { InterlockedExchange(&state.watcher.state()->sessionOwned, 0); state.session = 0; stop(); return state.fail("Cannot start private ETW tracepoint session (target elevation may be required)", result); }
    state.pid = GetCurrentProcessId();
    state.provider = {state.session, properties.Wnode.Guid, state.pid,
        {state.selector.provider, state.selector.eventId, !state.selector.name.empty(), true}};
    result = Tracepoint::enableLifecycle(state.provider);
    if (result) { stop(); return state.fail("Cannot track ETW tracepoint thread lifetimes", result); }
    auto threads = OS::listThreads();
    while (threads->hasNext()) state.phases.emplace(threads->next(), State::ThreadPhase{0, ++state.nextLifetime});
    delete threads;
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = state.properties.name;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.Context = &state; logfile.EventRecordCallback = State::onEvent; logfile.BufferCallback = State::onBuffer;
    state.consumer = OpenTraceW(&logfile);
    if (state.consumer == INVALID_PROCESSTRACE_HANDLE) { result = GetLastError(); stop(); return state.fail("Cannot open tracepoint realtime consumer", result); }
    if (pthread_create(&state.worker, nullptr, State::process, &state) != 0) { stop(); return Error("Cannot create ETW tracepoint consumer thread"); }
    state.started = true;
    result = Tracepoint::enableSelected(state.provider);
    if (result) { stop(); return state.fail("Cannot enable requested ETW tracepoint provider and stacks", result); }
    result = state.watcher.activate();
    if (result) { stop(); return state.fail("Tracepoint cleanup watcher exited during startup", result); }
    state.begin = tracepointQpc();
    return Error::OK;
}

void WindowsTracepointEngine::enableEvents(bool enabled) {
    if (_state) {
        if (!_state->windows.enable(*this, enabled)) _state->failure = ERROR_BUFFER_OVERFLOW;
    } else Engine::enableEvents(enabled);
}

void WindowsTracepointEngine::stop() {
    if (!_state) return;
    auto& state = *_state;
    state.end = tracepointQpc();
    if (state.remote) {
        auto result = Etw::Broker::stop();
        if (result) state.failure = result;
        if (state.started) { pthread_join(state.worker, nullptr); state.started = false; }
        else {
            result = Etw::Broker::consume(&state, State::onEvent, state.brokerResult);
            if (result) state.failure = result;
            state.finishStacks();
        }
        state.eventsLost += state.brokerResult.eventsLost;
        state.buffersLost += state.brokerResult.buffersLost;
        state.realtimeBuffersLost += state.brokerResult.realtimeBuffersLost;
        state.brokerCleanupError = state.brokerResult.cleanupError;
        if (state.brokerResult.error) state.failure = state.brokerResult.error;
        state.remote = false; state.finishJava();
        return;
    }
    auto providerError = Tracepoint::disableProviders(state.provider);
    if (providerError) state.failure = providerError;
    if (state.watcher.state()) {
        auto result = state.watcher.cleanup();
        if (result) { state.failure = result; if (state.consumer != INVALID_PROCESSTRACE_HANDLE) CloseTrace(state.consumer); }
        state.session = 0;
    }
    if (state.started) { pthread_join(state.worker, nullptr); state.started = false; }
    if (state.consumer != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(state.consumer); state.consumer = INVALID_PROCESSTRACE_HANDLE; }
    state.finishJava();
    auto result = state.watcher.finish();
    state.eventsLost += result.eventsLost; state.buffersLost += result.buffersLost; state.realtimeBuffersLost += result.realtimeBuffersLost;
    if (result.error) state.failure = result.error;
}

Error WindowsTracepointEngine::stopError() {
    return _state && _state->failure.load() ? _state->fail("Windows ETW tracepoint capture failed", _state->failure.load()) : Error::OK;
}
void WindowsTracepointEngine::writeMetrics(Writer& out) {
    if (!_state) return;
    auto& state = *_state;
    state.publisher.writeMetrics(out, "windows_tracepoint_");
    state.windows.writeMetrics(out, "windows_tracepoint_");
    out << "windows_tracepoint_matched_events " << u64(state.matched.load()) << '\n';
    out << "windows_tracepoint_name_filtered_events " << u64(state.wrongName.load()) << '\n';
    out << "windows_tracepoint_cpu_filtered_events " << u64(state.cpuFiltered.load()) << '\n';
    out << "windows_tracepoint_malformed_events " << u64(state.malformed.load()) << '\n';
    const auto joined = state.stackJoiner.stats();
    out << "windows_tracepoint_incomplete_stack_pairs " << u64(joined.incomplete) << '\n';
    out << "windows_tracepoint_joined_stack_pairs " << u64(joined.joined) << '\n';
    out << "windows_tracepoint_orphan_stack_continuations " << u64(joined.orphanContinuations) << '\n';
    out << "windows_tracepoint_ambiguous_stack_pairs " << u64(joined.ambiguous) << '\n';
    out << "windows_tracepoint_stack_join_overflows " << u64(joined.overflows) << '\n';
    out << "windows_tracepoint_pending_stack_pairs " << u64(joined.pending) << '\n';
    out << "windows_tracepoint_stack_join_bytes " << u64(joined.retainedBytes) << '\n';
    out << "windows_tracepoint_thread_starts " << u64(state.threadStarts.load()) << '\n';
    out << "windows_tracepoint_thread_ends " << u64(state.threadEnds.load()) << '\n';
    out << "windows_tracepoint_unknown_threads " << u64(state.unknownThreads.load()) << '\n';
    out << "windows_tracepoint_observed_selected_events " << u64(state.observedSelected.load()) << '\n';
    out << "windows_tracepoint_version_mismatches " << u64(state.versionMismatches.load()) << '\n';
    out << "windows_tracepoint_header_pid_rejections " << u64(state.headerPidRejections.load()) << '\n';
    for (unsigned index = 0, count = state.firstHeaderCount.load(std::memory_order_acquire); index < count; ++index) {
        const auto& tuple = state.firstHeaders[index];
        out << "windows_tracepoint_header_" << u64(index) << "_id " << u64(tuple.id.load()) << '\n';
        out << "windows_tracepoint_header_" << u64(index) << "_version " << u64(tuple.version.load()) << '\n';
        out << "windows_tracepoint_header_" << u64(index) << "_pid " << u64(tuple.pid.load()) << '\n';
        out << "windows_tracepoint_header_" << u64(index) << "_tid " << u64(tuple.tid.load()) << '\n';
    }
    out << "windows_tracepoint_events_lost " << u64(state.eventsLost) << '\n';
    out << "windows_tracepoint_buffers_lost " << u64(state.buffersLost) << '\n';
    out << "windows_tracepoint_realtime_buffers_lost " << u64(state.realtimeBuffersLost) << '\n';
    out << "windows_tracepoint_failure " << u64(state.failure.load()) << '\n';
    out << "windows_tracepoint_broker_pid " << u64(state.brokerPid) << '\n';
    out << "windows_tracepoint_broker_cleanup_error " << u64(state.brokerCleanupError.load()) << '\n';
}
