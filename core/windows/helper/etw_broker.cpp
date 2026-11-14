/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwBrokerPrivate.h"
#include "windowsEtwBootstrap.h"
#include "windowsEtwWatcher.h"
#include "windowsPrivilege.h"
#include "windowsKernel.h"
#include "windowsEtwControllerSecurity.h"
#include "windowsTracepointSession.h"
#include "windowsEtwProfileRouter.h"
#include <bcrypt.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <set>
#include <thread>

namespace WindowsProfiler::Etw::Broker {
namespace {
constexpr GUID perfInfo = {0xce1dbfb4, 0x137e, 0x4da6, {0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc}};
constexpr GUID stackWalk = {0xdef2fe46, 0x7bd6, 0x4b80, {0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0xd, 0xc, 0xe3}};
constexpr GUID threadProvider = {0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x0, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
constexpr GUID imageProvider = {0x2cb15d1d, 0x5fc1, 0x11d2, {0xab, 0xe1, 0x0, 0xa0, 0xc9, 0x11, 0xf5, 0x18}};
std::uint64_t qpc() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }
template<class T> T read(const unsigned char* p) { T value; std::memcpy(&value, p, sizeof(value)); return value; }
struct Capture {
    HANDLE pipe, target;
    DWORD targetPid;
    Request request;
    HANDLE bootstrap;
    ULONG sequence = 0;
    bool providerMode = false;
    ProviderRequest providerRequest{};
    Tracepoint::ProviderLease providerLease{};
    ProfileRouter profileRouter;
    Properties properties{};
    SessionWatcher watcher;
    TRACEHANDLE session = 0, consumer = INVALID_PROCESSTRACE_HANDLE;
    ProfileShare share;
    // The shared source's interval at joining and its later changes, forwarded to the target.
    std::uint64_t intervalPosition = 0, intervalHorizon = 0;
    ULONG initialInterval = 0;
    HANDLE workerDone = nullptr;
    std::atomic<bool> stopping{false};
    std::atomic<ULONG> failure{0};
    std::atomic<ULONG> unsupportedFormat{0};
    std::set<ULONG> threads;
    std::thread worker;
    ULONG modules() {
        std::vector<KernelModule> images;
        auto error = WindowsProfiler::kernelModules(images);
        if (error) return error;
        std::vector<unsigned char> bytes;
        for (const auto& image : images) {
            if (image.path.empty() || image.path.size() > 32767) return ERROR_INVALID_DATA;
            Module value{image.base, image.size, image.checksum, image.timestamp, static_cast<ULONG>(image.path.size())};
            auto offset = bytes.size();
            auto size = sizeof(value) + image.path.size() * sizeof(WCHAR);
            if (offset + size > MAX_PACKET) return ERROR_BUFFER_OVERFLOW;
            bytes.resize(offset + size);
            std::memcpy(bytes.data() + offset, &value, sizeof(value));
            std::memcpy(bytes.data() + offset + sizeof(value), image.path.data(), image.path.size() * sizeof(WCHAR));
        }
        return send(pipe, Type::Modules, bytes.data(), static_cast<ULONG>(bytes.size()), target, bootstrap, sequence);
    }
    ULONG prepareProperties(bool system) {
        properties.p.Wnode.BufferSize = sizeof(properties);
        properties.p.Wnode.Flags = WNODE_FLAG_TRACED_GUID; properties.p.Wnode.ClientContext = 1;
        if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&properties.p.Wnode.Guid), sizeof(GUID), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return ERROR_GEN_FAILURE;
        std::swprintf(properties.name, 128, L"async-profiler-%lu-%llu", GetCurrentProcessId(), static_cast<unsigned long long>(qpc()));
        properties.p.LoggerNameOffset = offsetof(Properties, name);
        properties.p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | (system ? EVENT_TRACE_SYSTEM_LOGGER_MODE : 0);
        properties.p.BufferSize = 64; properties.p.MinimumBuffers = system ? 64 : 16;
        properties.p.MaximumBuffers = system ? 512 : 128; properties.p.FlushTimer = 1;
        return ERROR_SUCCESS;
    }
    ULONG openConsumer() {
        EVENT_TRACE_LOGFILEW logfile{}; logfile.LoggerName = properties.name;
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        logfile.EventRecordCallback = event; logfile.BufferCallback = buffer; logfile.Context = this;
        consumer = OpenTraceW(&logfile);
        return consumer == INVALID_PROCESSTRACE_HANDLE ? GetLastError() : ERROR_SUCCESS;
    }
    ULONG snapshotThreads() {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return GetLastError();
        THREADENTRY32 entry{sizeof(entry)};
        for (BOOL next = Thread32First(snapshot, &entry); next; next = Thread32Next(snapshot, &entry))
            if (entry.th32OwnerProcessID == targetPid) threads.insert(entry.th32ThreadID);
        auto error = GetLastError(); CloseHandle(snapshot);
        return error == ERROR_NO_MORE_FILES ? ERROR_SUCCESS : error;
    }
    ULONG sendInterval(const IntervalChange& change) {
        EVENT_RECORD record{};
        record.EventHeader.Size = sizeof(EVENT_HEADER);
        record.EventHeader.ProviderId = intervalChangeProvider;
        record.EventHeader.TimeStamp.QuadPart = static_cast<LONGLONG>(change.qpc);
        record.EventHeader.ProcessId = targetPid;
        record.UserData = const_cast<IntervalChange*>(&change); record.UserDataLength = sizeof(change);
        std::vector<unsigned char> bytes;
        auto error = encodeEvent(record, bytes);
        return error ? error : send(pipe, Type::Event, bytes.data(), static_cast<ULONG>(bytes.size()), target, bootstrap, sequence);
    }
    // Changes reach the target before any later sample, which it weights by its timestamp.
    ULONG forwardIntervals(std::uint64_t time) {
        if (time <= intervalHorizon) return ERROR_SUCCESS;
        std::vector<IntervalChange> changes;
        auto error = share.sync(watcher.state()->shareSlot, intervalPosition, changes, intervalHorizon);
        for (const auto& change : changes) if (!error) error = sendInterval(change);
        return error;
    }
    static void WINAPI event(EVENT_RECORD* event) {
        auto self = static_cast<Capture*>(event->UserContext);
        if (self->failure.load()) return;
        try {
            if (!self->providerMode) {
                if (!self->request.software) {
                    auto error = self->forwardIntervals(event->EventHeader.TimeStamp.QuadPart);
                    if (error) { self->failure = error; return; }
                }
                ProfileView filtered;
                auto error = profileEvent(self->targetPid, self->request.images != 0, *event, filtered,
                    static_cast<SoftwareKind>(self->request.software));
                if (error) { self->unsupportedFormat = filtered.unsupportedFormat; self->failure = error; return; }
                if (filtered.kind == ProfileKind::Thread) {
                    if (filtered.pid == self->targetPid && event->EventHeader.EventDescriptor.Opcode != 2) self->threads.insert(filtered.tid);
                    else self->threads.erase(filtered.tid);
                }
                if (filtered.kind == ProfileKind::KernelImage
                        && (event->EventHeader.EventDescriptor.Opcode == 10 || event->EventHeader.EventDescriptor.Opcode == 2)) {
                    error = self->modules();
                    if (error) { self->failure = error; return; }
                }
                ProfileRouter::Output output;
                // A live-TID hint affects loss diagnostics only, never ownership.
                error = self->profileRouter.route(filtered, self->threads.contains(filtered.tid), output);
                if (!error && !output.first.empty()) error = send(self->pipe, Type::Event, output.first.data(), static_cast<ULONG>(output.first.size()), self->target, self->bootstrap, self->sequence);
                if (!error && !output.second.empty()) error = send(self->pipe, Type::Event, output.second.data(), static_cast<ULONG>(output.second.size()), self->target, self->bootstrap, self->sequence);
                if (error) self->failure = error;
                return;
            }
            EVENT_RECORD filtered;
            std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, 2> continuation;
            bool accepted;
            auto error = providerEvent(self->providerRequest, self->targetPid, *event, filtered, accepted, &continuation);
            if (error) { self->failure = error; return; }
            if (!accepted) return;
            std::vector<unsigned char> data;
            error = encodeEvent(filtered, data);
            if (!error) error = send(self->pipe, Type::Event, data.data(), static_cast<ULONG>(data.size()), self->target, self->bootstrap, self->sequence);
            if (error) self->failure = error;
        } catch (...) { self->failure = ERROR_NOT_ENOUGH_MEMORY; }
    }
    static ULONG WINAPI buffer(EVENT_TRACE_LOGFILEW* logfile) {
        return !static_cast<Capture*>(logfile->Context)->failure.load();
    }
    ULONG startProvider(Reply& reply) {
        if (providerRequest.eventId > 65535 || providerRequest.version < -1 || providerRequest.version > 255
                || (providerRequest.flags & ~(Named | Stacks | Images)) || providerRequest.reserved
                || ((providerRequest.flags & Named) && (providerRequest.eventId || providerRequest.version != -1))) return ERROR_INVALID_PARAMETER;
        // This ordinary ETW session has no machine-wide PMU or interval share.
        auto initialized = prepareProperties(false);
        if (initialized) return initialized;
        auto error = watcher.start(properties, nullptr, true);
        if (error) return error;
        InterlockedExchange(&watcher.state()->sessionOwned, 1);
        error = StartTraceW(&session, properties.name, &properties.p);
        if (error) { InterlockedExchange(&watcher.state()->sessionOwned, 0); return error; }
        error = verifyController(GetCurrentProcess(), true);
        if (!error) error = verifyController(watcher.process(), true);
        if (error) return error;
        providerLease.session = session; providerLease.source = properties.p.Wnode.Guid; providerLease.pid = targetPid;
        providerLease.selected = {providerRequest.provider, static_cast<USHORT>(providerRequest.eventId),
            (providerRequest.flags & Named) != 0, (providerRequest.flags & Stacks) != 0};
        error = Tracepoint::enableLifecycle(providerLease);
        if (error) return error;
        error = openConsumer();
        if (error) return error;
        if ((providerRequest.flags & Images) && (error = modules())) return error;
        reply = {ERROR_SUCCESS, 0, 1, GetCurrentProcessId()};
        return ERROR_SUCCESS;
    }
    ULONG enableSoftware(bool samples) {
        ULONG flags[8] = {EVENT_TRACE_FLAG_THREAD
            | (samples ? softwareEnableFlags(static_cast<SoftwareKind>(request.software)) : 0)};
        if (request.images) flags[0] |= EVENT_TRACE_FLAG_IMAGE_LOAD;
        return TraceSetInformation(session, TraceSystemTraceEnableFlagsInfo, flags, sizeof(flags));
    }
    ULONG startSoftware(Reply& reply) {
        profileRouter.configureSoftware(targetPid, request.stacks != 0, static_cast<SoftwareKind>(request.software));
        // The watchdog owns only this session: no machine-wide interval or PMU
        // is selected, queried, restored, or shared for software events.
        auto initialized = prepareProperties(true);
        if (initialized) return initialized;
        auto error = watcher.start(properties, nullptr, true);
        if (error) return error;
        InterlockedExchange(&watcher.state()->sessionOwned, 1);
        error = StartTraceW(&session, properties.name, &properties.p);
        if (error) { InterlockedExchange(&watcher.state()->sessionOwned, 0); return error; }
        // A CSwitch header does not identify either thread's process. Even
        // stackless clients therefore require switch-in StackWalk ownership.
        auto selected = softwareStackEvents(static_cast<SoftwareKind>(request.software));
        error = TraceSetInformation(session, TraceStackTracingInfo, const_cast<CLASSIC_EVENT_ID*>(selected.data()),
            static_cast<ULONG>(selected.size_bytes()));
        if (error) return error;
        // Subscribe before the snapshot so a thread born during preparation is
        // represented by the snapshot, its lifecycle event, or both.
        error = enableSoftware(false);
        if (!error) error = snapshotThreads();
        if (!error) error = openConsumer();
        if (!error && request.images) error = modules();
        if (error) return error;
        reply = {ERROR_SUCCESS, 0, request.interval, GetCurrentProcessId()};
        return ERROR_SUCCESS;
    }
    ULONG start(Reply& reply) {
        if (WaitForSingleObject(bootstrap, 0) != WAIT_TIMEOUT || WaitForSingleObject(target, 0) != WAIT_TIMEOUT) return ERROR_PROCESS_ABORTED;
        if (providerMode) return startProvider(reply);
        auto validated = validateRequest(request);
        if (validated) return validated;
        if (request.software) return startSoftware(reply);
        profileRouter.configure(targetPid, request.stacks != 0);
        // The broker, rather than the unprivileged target, owns every mutation
        // of the machine-wide profiling configuration and its recovery records.
        auto error = share.open();
        if (error) return error;
        auto initialized = prepareProperties(true);
        if (initialized) return initialized;
        error = watcher.start(properties, &share, true);
        if (error) return error;
        InterlockedExchange(&watcher.state()->sessionOwned, 1);
        error = StartTraceW(&session, properties.name, &properties.p);
        if (error) { InterlockedExchange(&watcher.state()->sessionOwned, 0); return error; }
        {
            // Even stackless output needs exact PID ownership for ETW records
            // whose profile header has no process ID. Proof stacks stay private.
            CLASSIC_EVENT_ID stack{}; stack.EventGuid = perfInfo; stack.Type = request.source == 0 && !request.raw ? 46 : 47;
            error = TraceSetInformation(session, TraceStackTracingInfo, &stack, sizeof(stack));
            if (error) return error;
        }
        ShareGrant grant;
        error = share.join(*watcher.state(), {request.source, request.interval, targetPid, request.explicitInterval != 0,
            request.raw != 0, request.rawConfig}, grant);
        reply.conflict = grant.conflict;
        if (error) return error;
        request.source = grant.source;
        initialInterval = grant.interval; intervalPosition = grant.position;
        error = snapshotThreads();
        if (error) return error;
        error = openConsumer();
        if (error) return error;
        if (request.images && (error = modules())) return error;
        reply = {ERROR_SUCCESS, request.source, grant.requested, GetCurrentProcessId()};
        return ERROR_SUCCESS;
    }
    ULONG activate() {
        if (WaitForSingleObject(bootstrap, 0) != WAIT_TIMEOUT || WaitForSingleObject(target, 0) != WAIT_TIMEOUT) return ERROR_PROCESS_ABORTED;
        auto checked = verifyController(GetCurrentProcess(), true);
        if (!checked) checked = verifyController(watcher.process(), true);
        if (checked) return checked;
        if (providerMode) {
            auto error = Tracepoint::enableSelected(providerLease);
            return error ? error : watcher.activate();
        }
        if (request.software) {
            auto error = enableSoftware(true);
            return error ? error : watcher.activate();
        }
        ULONG flags[8] = {static_cast<ULONG>(EVENT_TRACE_FLAG_THREAD | (request.source == 0 ? EVENT_TRACE_FLAG_PROFILE : 0))};
        if (request.images) flags[0] |= EVENT_TRACE_FLAG_IMAGE_LOAD;
        if (request.source) flags[1] = PMC_PROFILE_MASK;
        auto error = TraceSetInformation(session, TraceSystemTraceEnableFlagsInfo, flags, sizeof(flags));
        return error ? error : watcher.activate();
    }
    ULONG run() {
        if (!providerMode && !request.software) {
            auto error = sendInterval({0, initialInterval, 0});
            if (error) return error;
        }
        workerDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!workerDone) return GetLastError();
        worker = std::thread([this] {
            auto error = ProcessTrace(&consumer, 1, nullptr, nullptr);
            if (error != ERROR_SUCCESS && error != ERROR_CANCELLED) failure = error;
            if (!stopping.load()) {
                if (!failure.load()) failure = ERROR_BROKEN_PIPE;
            }
            SetEvent(workerDone);
        });
        return ERROR_SUCCESS;
    }
    Result stop() {
        Result result;
        auto primary = failure.load();
        stopping = true;
        if (providerMode) result.cleanupError = Tracepoint::disableProviders(providerLease);
        if (watcher.state()) {
            auto error = watcher.cleanup();
            if (!result.cleanupError) result.cleanupError = error;
        }
        if (result.cleanupError && consumer != INVALID_PROCESSTRACE_HANDLE) CloseTrace(consumer);
        if (worker.joinable()) worker.join();
        result.unsupportedFormat = unsupportedFormat.load();
        if (!providerMode) profileRouter.finish(result);
        if (workerDone) { CloseHandle(workerDone); workerDone = nullptr; }
        if (consumer != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(consumer); consumer = INVALID_PROCESSTRACE_HANDLE; }
        auto final = watcher.finish();
        if (!result.cleanupError) result.cleanupError = final.error;
        result.error = primary ? primary : result.cleanupError ? result.cleanupError : failure.load() ? failure.load() : result.error;
        result.eventsLost = final.eventsLost; result.buffersLost = final.buffersLost; result.realtimeBuffersLost = final.realtimeBuffersLost;
        share.close();
        return result;
    }
    ~Capture() { stop(); }
};
ULONG authenticate(HANDLE pipe, HANDLE target, DWORD targetPid, const FILETIME& created, const std::vector<unsigned char>& targetUser, HANDLE bootstrap) {
    ULONG actual = 0;
    if (!GetNamedPipeClientProcessId(pipe, &actual)) return GetLastError();
    if (actual != targetPid || WaitForSingleObject(target, 0) != WAIT_TIMEOUT) return ERROR_ACCESS_DENIED;
    Type type; std::vector<unsigned char> data;
    ULONG sequence;
    auto received = receive(pipe, type, data, target, 10000, nullptr, bootstrap, &sequence);
    if (received) return received;
    if (sequence || type != Type::Hello || data.size() != sizeof(Hello)) return ERROR_INVALID_DATA;
    Hello hello; std::memcpy(&hello, data.data(), sizeof(hello));
    if (hello.pid != targetPid || CompareFileTime(&hello.created, &created) != 0) return ERROR_ACCESS_DENIED;
    if (!ImpersonateNamedPipeClient(pipe)) return GetLastError();
    HANDLE token = nullptr;
    auto opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token);
    auto error = opened ? ERROR_SUCCESS : GetLastError();
    // Do not allocate or initialize libraries while impersonating the client:
    // a runtime-created thread would inherit the client's object defaults.
    if (!RevertToSelf()) {
        auto fatal = GetLastError();
        ExitProcess(fatal ? fatal : ERROR_CANNOT_IMPERSONATE);
    }
    if (!opened) return error;
    DWORD length = 0; std::vector<unsigned char> user;
    GetTokenInformation(token, TokenUser, nullptr, 0, &length); user.resize(length);
    error = GetTokenInformation(token, TokenUser, user.data(), length, &length) && sameUser(user, targetUser)
        ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
    CloseHandle(token);
    return error;
}
ULONG acknowledgement(HANDLE pipe, HANDLE target, HANDLE bootstrap, Type reply, ULONG sequence) {
    auto deadline = GetTickCount64() + 10000;
    for (;;) {
        auto now = GetTickCount64();
        if (now >= deadline) return ERROR_TIMEOUT;
        Type type; std::vector<unsigned char> data; ULONG received;
        auto error = receive(pipe, type, data, target, static_cast<DWORD>(deadline - now), nullptr, bootstrap, &received);
        if (error) return error;
        if (received != sequence) return ERROR_INVALID_DATA;
        // An unsolicited consumer failure can finish while the target starts
        // its Stop call. Controls are already released; wait for the ACK too.
        if (reply == Type::Finished && type == Type::Stop && data.empty()) continue;
        if (type != Type::Acknowledge || data.size() != sizeof(Acknowledgement)) return ERROR_INVALID_DATA;
        Acknowledgement ack; std::memcpy(&ack, data.data(), sizeof(ack));
        return ack.reply == static_cast<ULONG>(reply) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
    }
}
}
int collector(DWORD targetPid, const WCHAR* pipeName, HANDLE bootstrap, HANDLE ready, bool once) try {
    if (!targetPid || !pipePath(pipeName)) return ERROR_INVALID_PARAMETER;
    HANDLE target = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, targetPid);
    if (!target) return GetLastError();
    FILETIME created; std::vector<unsigned char> targetUser, brokerUser;
    auto error = processCreated(target, created);
    if (!error) error = tokenUser(target, targetUser);
    if (!error) error = tokenUser(GetCurrentProcess(), brokerUser);
    if (!error && !sameUser(targetUser, brokerUser)) error = ERROR_ACCESS_DENIED;
    if (!error) error = hardenControllerIdentity();
    Privilege privilege(L"SeSystemProfilePrivilege");
    if (!error) error = privilege.enable();
    LPWSTR sid = nullptr;
    if (!error && !ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(targetUser.data())->User.Sid, &sid)) error = GetLastError();
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!error) {
        std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + std::wstring(sid) + L")S:(ML;;NW;;;LW)";
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) error = GetLastError();
    }
    if (sid) LocalFree(sid);
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    HANDLE pipe = INVALID_HANDLE_VALUE;
    if (!error) {
        pipe = CreateNamedPipeW(pipeName, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 256 * 1024, 4096, 0, &security);
        if (pipe == INVALID_HANDLE_VALUE) error = GetLastError();
    }
    if (descriptor) LocalFree(descriptor);
    if (!error && !SetEvent(ready)) error = GetLastError();
    while (!error && WaitForSingleObject(target, 0) == WAIT_TIMEOUT && WaitForSingleObject(bootstrap, 0) == WAIT_TIMEOUT) {
        OVERLAPPED connection{}; connection.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!connection.hEvent) { error = GetLastError(); break; }
        BOOL connected = ConnectNamedPipe(pipe, &connection);
        auto status = connected ? ERROR_SUCCESS : GetLastError();
        if (status == ERROR_IO_PENDING) {
            HANDLE events[] = {connection.hEvent, target, bootstrap};
            auto waited = WaitForMultipleObjects(3, events, FALSE, once ? 30000 : INFINITE);
            if (waited != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &connection); DWORD ignored; GetOverlappedResult(pipe, &connection, &ignored, TRUE);
                status = waited == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_PROCESS_ABORTED;
            }
            else { DWORD ignored; if (!GetOverlappedResult(pipe, &connection, &ignored, FALSE)) status = GetLastError(); else status = ERROR_SUCCESS; }
        } else if (status == ERROR_PIPE_CONNECTED) status = ERROR_SUCCESS;
        CloseHandle(connection.hEvent);
        if (status) { error = status == ERROR_PROCESS_ABORTED ? ERROR_SUCCESS : status; break; }
        status = authenticate(pipe, target, targetPid, created, targetUser, bootstrap);
        Reply hello{status, 0, 0, GetCurrentProcessId()};
        if (!status) status = send(pipe, Type::Ready, &hello, sizeof(hello), target, bootstrap);
        ULONG lastSequence = 0;
        while (!status && WaitForSingleObject(target, 0) == WAIT_TIMEOUT && WaitForSingleObject(bootstrap, 0) == WAIT_TIMEOUT) {
            Type type; std::vector<unsigned char> data;
            ULONG sequence;
            status = receive(pipe, type, data, target, INFINITE, nullptr, bootstrap, &sequence);
            bool provider = !status && type == Type::StartProvider;
            if (!status && (!sequence || sequence != lastSequence + 1 || (type != Type::Start && !provider)
                    || data.size() != (provider ? sizeof(ProviderRequest) : sizeof(Request)))) status = ERROR_INVALID_DATA;
            if (!status) {
                Capture capture{pipe, target, targetPid, {}, bootstrap}; Reply reply;
                capture.sequence = lastSequence = sequence;
                capture.providerMode = provider;
                if (provider) std::memcpy(&capture.providerRequest, data.data(), sizeof(ProviderRequest));
                else std::memcpy(&capture.request, data.data(), sizeof(Request));
                status = capture.start(reply); reply.error = status;
                bool prepared = !status, stopped = false;
                Result result;
                auto sent = send(pipe, Type::Ready, &reply, sizeof(reply), target, bootstrap, sequence);
                if (!status && !sent) {
                    ULONG controlSequence;
                    status = receive(pipe, type, data, target, INFINITE, nullptr, bootstrap, &controlSequence);
                    if (!status && controlSequence != sequence) status = ERROR_INVALID_DATA;
                    if (!status && type == Type::Activate && data.empty()) {
                        reply.error = capture.activate();
                        status = send(pipe, Type::Ready, &reply, sizeof(reply), target, bootstrap, sequence);
                        if (!status && !reply.error) {
                            status = capture.run();
                            if (!status) status = receive(pipe, type, data, target, INFINITE, capture.workerDone, bootstrap, &controlSequence);
                            if (!status && controlSequence != sequence) status = ERROR_INVALID_DATA;
                        } else if (!status) {
                            // Release controls immediately, but retain the pipe
                            // until the client has read the failure and stopped.
                            result = capture.stop(); stopped = true;
                            status = receive(pipe, type, data, target, 10000, nullptr, bootstrap, &controlSequence);
                            if (!status && controlSequence != sequence) status = ERROR_INVALID_DATA;
                        }
                    }
                    if (!status && (type != Type::Stop || !data.empty())) status = ERROR_INVALID_DATA;
                }
                if (!stopped) result = capture.stop();
                if (!sent && !prepared) {
                    // DisconnectNamedPipe discards unread bytes. The explicit
                    // acknowledgment proves delivery of a failed start reply.
                    acknowledgement(pipe, target, bootstrap, Type::Ready, sequence);
                } else if (!sent && prepared) {
                    if (reply.error) result.error = reply.error;
                    else if (!result.error) result.error = status;
                    auto delivered = send(pipe, Type::Finished, &result, sizeof(result), target, bootstrap, sequence);
                    if (!delivered) delivered = acknowledgement(pipe, target, bootstrap, Type::Finished, sequence);
                    if (!status) status = delivered ? delivered : result.error;
                }
            }
        }
        CancelIoEx(pipe, nullptr); DisconnectNamedPipe(pipe);
        if (once) break;
    }
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
    CloseHandle(target); return error;
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
}
