/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "os.h"
#include "vmEntry.h"
#include "vmStructs.h"
#include "windowsBreakpoints.h"
#include "windowsAsyncJava.h"
#include "writer.h"
#include "stackWalker.h"
#include "profiler.h"
#include "windowsTrapThreads.h"
#include <array>
#include <atomic>
#include <mutex>
#include <cstdlib>
#include <utility>

namespace WindowsProfiler {
namespace {
constexpr DWORD reservedId = 0xffffffff;
constexpr unsigned writerReservation = 1u << 31;
enum class ApcPhase { Idle, Preparing, Queued, Running, Done, Cancelled, Retiring };
struct ApcRequest {
    std::atomic<ApcPhase> phase{ApcPhase::Idle};
    std::atomic<bool> retained{false};
    ASGCT_CallTrace trace{};
    AsyncNativeStack native{};
    int maximum = 0;
    bool verifyJNI = false;
    bool compilerTask = false;
    HANDLE ready = NULL;
};
struct alignas(64) ThreadSlot {
    std::atomic<DWORD> tid{0};
    std::atomic<unsigned> readers{0};
    std::atomic<VMThread*> vm{NULL};
    HANDLE handle = NULL;
    const NT_TIB* tib = NULL;
    std::uint64_t creation = 0;
    std::atomic<bool> internal{false};
    std::atomic<bool> counterPresent{false};
    std::uint64_t counterStarted = 0;
    asprof_thread_local_data counter{};
    ApcRequest apc;
    std::uint64_t epoch = 0;
    std::atomic<bool> trapEntered{false};
    TrapThreads::State trapState{};
};
std::array<ThreadSlot, 65536> threads;
std::recursive_mutex registryMutex;
std::uint64_t registryEpoch = 0;
thread_local ThreadSlot* currentSlot;
thread_local bool internalThread;
thread_local std::uint64_t requestedWeight;

struct Sample {
    ThreadSlot* slot = NULL;
    int tid = 0;
    int state = THREAD_UNKNOWN;
    bool suspended = false;
    bool counterPresent = false;
    std::uintptr_t stackLow = 0, stackHigh = 0;
};
thread_local Sample sample;

using QueueUserApc2 = BOOL (WINAPI*)(PAPCFUNC, HANDLE, ULONG_PTR, unsigned);
QueueUserApc2 queueUserApc2 = reinterpret_cast<QueueUserApc2>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "QueueUserAPC2"));
// QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC | QUEUE_USER_APC_CALLBACK_DATA_CONTEXT.
constexpr unsigned contextualSpecialApc = 0x10001;
struct ApcCallbackData { ULONG_PTR parameter; PCONTEXT context; ULONG_PTR reserved[2]; };
struct ApcCounters {
    std::atomic<std::uint64_t> queued{0}, calls{0}, cancelled{0}, failed{0}, timedOut{0}, pending{0};
};
ApcCounters javaApcs, compilerApcs;
std::atomic<std::uint64_t> jniChecks, compilerTasks;

ApcCounters& counters(const ApcRequest& request) { return request.compilerTask ? compilerApcs : javaApcs; }

void releaseApcReader(ThreadSlot& slot) {
    if (slot.apc.retained.exchange(false, std::memory_order_acq_rel)) {
        counters(slot.apc).pending.fetch_sub(1, std::memory_order_relaxed);
        slot.readers.fetch_sub(1, std::memory_order_release);
    }
}

void retireExitedApc(ThreadSlot& slot) {
    auto expected = ApcPhase::Cancelled;
    if (slot.apc.phase.compare_exchange_strong(expected, ApcPhase::Retiring, std::memory_order_acq_rel)) {
        // A signalled thread handle guarantees that its queued APC cannot run.
        // Keep the request unavailable until its old pin and counter are gone.
        releaseApcReader(slot);
        slot.apc.phase.store(ApcPhase::Idle, std::memory_order_release);
    }
}

void reapExitedApcRequests() {
    if (javaApcs.pending.load(std::memory_order_acquire) == 0 && compilerApcs.pending.load(std::memory_order_acquire) == 0) return;
    std::lock_guard lock(registryMutex);
    for (auto& slot : threads) {
        if (slot.apc.phase.load(std::memory_order_acquire) == ApcPhase::Cancelled
                && slot.handle && WaitForSingleObject(slot.handle, 0) == WAIT_OBJECT_0) {
            retireExitedApc(slot);
        }
    }
}

void CALLBACK captureJavaApc(ULONG_PTR value) {
    auto previousError = GetLastError();
    auto data = reinterpret_cast<ApcCallbackData*>(value);
    auto slot = reinterpret_cast<ThreadSlot*>(data->parameter);
    auto& request = slot->apc;
    auto expected = ApcPhase::Queued;
    if (request.phase.compare_exchange_strong(expected, ApcPhase::Running, std::memory_order_acq_rel)) {
        if (request.verifyJNI) {
            // GetEnv here reads the real target's TLS. On the polling thread,
            // VM::jni() deliberately returns the bridged sampled JNIEnv.
            if (VM::jni() != request.trace.env) std::abort();
            jniChecks.fetch_add(1, std::memory_order_relaxed);
        }
        request.native.pc = data->context->Rip;
        if (request.native.capacity > 0) {
            request.native.count = request.native.mode == CSTACK_DWARF
                    ? StackWalker::walkDwarf(data->context, request.native.frames, request.native.capacity)
                    : StackWalker::walkFP(data->context, request.native.frames, request.native.capacity);
        }
        counters(request).calls.fetch_add(1, std::memory_order_relaxed);
        if (request.compilerTask) {
            // A compiler frame in this exact native callchain establishes the
            // CompilerThread layout before reading its compilation environment.
            for (int i = 0; i < request.native.count; i++) {
                const char* name = Profiler::instance()->findNativeMethod(request.native.frames[i]);
                if (name != NULL && NativeFunc::mark(name) == MARK_COMPILER_ENTRY) {
                    // JVMTI hides C1/C2 threads. GetEnv on this target observes
                    // their genuine JavaThread without retaining a hidden pointer.
                    auto thread = VMThread::current();
                    auto method = thread != NULL ? thread->compiledMethod() : NULL;
                    request.native.compilerMethod = method != NULL ? method->validatedId() : NULL;
                    if (request.native.compilerMethod != NULL) compilerTasks.fetch_add(1, std::memory_order_relaxed);
                    break;
                }
            }
            request.trace.num_frames = request.native.count;
        } else {
            VM::_asyncGetCallTrace(&request.trace, request.maximum, data->context);
        }
        // Publish the event before Done so a reused request cannot receive a
        // late notification from its predecessor.
        SetEvent(request.ready);
        releaseApcReader(*slot);
        request.phase.store(ApcPhase::Done, std::memory_order_release);
    } else {
        // Cancellation happens only before AGCT starts. The caller's trace
        // buffer is no longer valid and must not be read or written here.
        releaseApcReader(*slot);
        request.phase.store(ApcPhase::Idle, std::memory_order_release);
    }
    SetLastError(previousError);
}

std::uint64_t threadCreation(HANDLE thread) {
    FILETIME creation, exit, kernel, user;
    if (!GetThreadTimes(thread, &creation, &exit, &kernel, &user)) return 0;
    return (std::uint64_t(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
}

// The TEB starts with the thread's NT_TIB and stays mapped for the thread's lifetime.
const NT_TIB* threadInformationBlock(HANDLE thread) {
    struct BasicInformation { LONG exitStatus; PVOID teb, process, thread; KAFFINITY affinity; LONG priority, basePriority; } information;
    using Query = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    return thread && query(thread, 0, &information, sizeof(information), NULL) >= 0 ? static_cast<const NT_TIB*>(information.teb) : NULL;
}
void publishThread(ThreadSlot& slot, DWORD tid, HANDLE retained, std::uint64_t creation, bool pin, bool internal) {
    // The writer reservation excludes lock-free read pins before the old
    // handle closes and releases its thread ID for possible reuse.
    slot.tid.store(reservedId, std::memory_order_release);
    if (slot.handle) CloseHandle(slot.handle);
    slot.handle = retained;
    slot.tib = threadInformationBlock(retained);
    slot.creation = creation;
    slot.epoch = retained ? ++registryEpoch : 0;
    slot.vm.store(NULL, std::memory_order_relaxed);
    slot.internal.store(internal, std::memory_order_relaxed);
    slot.counterPresent.store(false, std::memory_order_relaxed);
    __atomic_store_n(&slot.counter.sample_counter, std::uint64_t(0), __ATOMIC_RELAXED);
    slot.trapEntered.store(false, std::memory_order_relaxed);
    slot.trapState = {};
    slot.tid.store(tid, std::memory_order_release);
    slot.readers.store(pin ? 1u : 0u, std::memory_order_release);
}

ThreadSlot* registerThread(DWORD tid, HANDLE handle, std::uint64_t creation, bool pin = false, bool internal = false) {
    std::lock_guard lock(registryMutex);
    size_t first = (tid >> 2) % threads.size();
    ThreadSlot* available = NULL;
    for (size_t offset = 0; offset < threads.size(); ++offset) {
        auto& slot = threads[(first + offset) % threads.size()];
        DWORD key = slot.tid.load(std::memory_order_acquire);
        if (key == tid && slot.creation == creation) {
            if (available) available->readers.store(0, std::memory_order_release);
            if (internal) slot.internal.store(true, std::memory_order_release);
            if (pin) slot.readers.fetch_add(1, std::memory_order_relaxed);
            return &slot;
        }
        bool exited = slot.handle && WaitForSingleObject(slot.handle, 0) == WAIT_OBJECT_0;
        if (exited) retireExitedApc(slot);
        if (!available && (key == 0 || key == reservedId || exited)) {
            unsigned expected = 0;
            if (slot.readers.compare_exchange_strong(expected, writerReservation, std::memory_order_acq_rel)) available = &slot;
        }
        if (!key) break;
    }
    if (!available) return NULL;
    HANDLE retained;
    if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), &retained, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        available->readers.store(0, std::memory_order_release);
        return NULL;
    }
    publishThread(*available, tid, retained, creation, pin, internal);
    return available;
}

ThreadSlot* ownSlot() {
    if (!currentSlot) {
        currentSlot = registerThread(GetCurrentThreadId(), GetCurrentThread(), threadCreation(GetCurrentThread()), false, internalThread);
        if (currentSlot) currentSlot->internal.store(internalThread, std::memory_order_release);
    }
    return currentSlot;
}

ThreadSlot* findThread(DWORD tid) {
    size_t first = (tid >> 2) % threads.size();
    for (size_t offset = 0; offset < threads.size(); ++offset) {
        auto& slot = threads[(first + offset) % threads.size()];
        auto key = slot.tid.load(std::memory_order_acquire);
        if (key == tid) return &slot;
        if (!key) break;
    }
    return nullptr;
}

bool readPin(ThreadSlot& slot, DWORD tid, std::uint64_t epoch = 0) {
    auto readers = slot.readers.load(std::memory_order_relaxed);
    do {
        if (readers >= writerReservation - 1) return false;
    } while (!slot.readers.compare_exchange_weak(readers, readers + 1, std::memory_order_acquire, std::memory_order_relaxed));
    if (slot.tid.load(std::memory_order_acquire) != tid || (epoch && slot.epoch != epoch)) {
        slot.readers.fetch_sub(1, std::memory_order_release);
        return false;
    }
    return true;
}

void updateSampleCounter(ThreadSlot* slot, std::uint64_t timestamp) {
    auto previous = __atomic_load_n(&slot->counter.sample_counter, __ATOMIC_RELAXED);
    while (timestamp > previous && !__atomic_compare_exchange_n(&slot->counter.sample_counter, &previous, timestamp, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {}
}
}

namespace TrapThreads {
Lease::Lease(Lease&& other) noexcept : _slot(std::exchange(other._slot, nullptr)), _entered(std::exchange(other._entered, false)) {}
Lease& Lease::operator=(Lease&& other) noexcept {
    if (this != &other) {
        reset(); _slot = std::exchange(other._slot, nullptr); _entered = std::exchange(other._entered, false);
    }
    return *this;
}
Lease::~Lease() { reset(); }
void Lease::reset() noexcept {
    auto slot = static_cast<ThreadSlot*>(std::exchange(_slot, nullptr));
    if (!slot) return;
    if (_entered) { slot->trapEntered.store(false, std::memory_order_release); _entered = false; }
    slot->readers.fetch_sub(1, std::memory_order_release);
}
Identity Lease::identity() const noexcept {
    auto slot = static_cast<ThreadSlot*>(_slot);
    return {static_cast<std::uint32_t>(slot - threads.data()), slot->tid.load(std::memory_order_relaxed), slot->creation, slot->epoch};
}
bool Lease::internal() const noexcept { return static_cast<ThreadSlot*>(_slot)->internal.load(std::memory_order_acquire); }
State& Lease::state() const noexcept { return static_cast<ThreadSlot*>(_slot)->trapState; }
bool Lease::tryEnter() noexcept {
    if (_entered) return true;
    _entered = !static_cast<ThreadSlot*>(_slot)->trapEntered.exchange(true, std::memory_order_acq_rel);
    return _entered;
}
Lease current() noexcept {
    DWORD tid;
    __asm__("movl %%gs:0x48, %0" : "=r"(tid));
    auto slot = findThread(tid);
    return slot && readPin(*slot, tid) ? Lease(slot) : Lease();
}
Lease pin(const Identity& identity) noexcept {
    if (!identity.tid || !identity.epoch || identity.slot >= threads.size()) return {};
    auto& slot = threads[identity.slot];
    if (!readPin(slot, identity.tid, identity.epoch)) return {};
    if (slot.creation != identity.creation) { slot.readers.fetch_sub(1, std::memory_order_release); return {}; }
    return Lease(&slot);
}
const char* prepare(HANDLE thread, Identity* identity) noexcept {
    if (identity) *identity = {};
    auto tid = GetThreadId(thread);
    if (!tid || GetProcessIdOfThread(thread) != GetCurrentProcessId()) return "Trap thread handle must identify a local thread";
    constexpr DWORD access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;
    HANDLE sampling;
    if (!DuplicateHandle(GetCurrentProcess(), thread, GetCurrentProcess(), &sampling, access, FALSE, 0))
        return "Cannot retain sampling-safe trap thread handle";
    auto creation = threadCreation(sampling);
    if (!creation || WaitForSingleObject(sampling, 0) != WAIT_TIMEOUT) {
        CloseHandle(sampling); return "Trap thread has exited or its birth cannot be queried";
    }
    try {
        auto slot = registerThread(tid, sampling, creation, true);
        CloseHandle(sampling);
        if (!slot) return "Cannot enroll trap thread in the fixed registry";
        if (identity) *identity = {static_cast<std::uint32_t>(slot - threads.data()), tid, creation, slot->epoch};
        slot->readers.fetch_sub(1, std::memory_order_release);
        return nullptr;
    } catch (...) { CloseHandle(sampling); return "Cannot lock trap thread registry"; }
}
std::size_t reapExited() {
    std::lock_guard lock(registryMutex);
    std::size_t reaped = 0;
    for (auto& slot : threads) {
        if (!slot.handle || WaitForSingleObject(slot.handle, 0) != WAIT_OBJECT_0) continue;
        retireExitedApc(slot);
        unsigned expected = 0;
        if (!slot.readers.compare_exchange_strong(expected, writerReservation, std::memory_order_acq_rel)) continue;
        publishThread(slot, reservedId, NULL, 0, false, false);
        reaped++;
    }
    return reaped;
}
}

bool capturingThread() { return sample.suspended; }
int sampledThreadId() { return sample.tid; }
int sampledThreadState() { return sample.state; }
// A running thread, once suspended, reports its suspension rather than a blocking call.
std::uint64_t sampledThreadFingerprint() { return sample.state == THREAD_SLEEPING ? threadFingerprint(sample.slot->handle) : 0; }
VMThread* sampledVMThread() { return sample.slot ? sample.slot->vm.load(std::memory_order_acquire) : NULL; }
JNIEnv* sampledJNI() { auto thread = sampledVMThread(); return thread ? thread->jni() : NULL; }
void setSampleWeight(std::uint64_t value) { requestedWeight = value; }
std::uint64_t sampleWeight() { return requestedWeight; }
void markInternalThread() { internalThread = true; auto slot = ownSlot(); if (slot) slot->internal.store(true, std::memory_order_release); }
bool isInternalThread(int tid) {
    std::lock_guard lock(registryMutex);
    auto slot = findThread(static_cast<DWORD>(tid));
    return slot && slot->internal.load(std::memory_order_acquire);
}

void resumeSamplingTarget() {
    if (sample.suspended) {
        ResumeThread(sample.slot->handle);
        sample.suspended = false;
    }
}

Error prepareAsyncJavaTrace() {
    if (!VM::loaded() || VM::_asyncGetCallTrace == NULL) return Error("agct feature requires a JVM exporting AsyncGetCallTrace");
    if (!queueUserApc2) return Error("agct feature requires QueueUserAPC2 with interrupted-context support (Windows 11 or later)");
    return Error::OK;
}

Error prepareCompilerTrace() {
    if (!queueUserApc2) return Error("comptask feature requires QueueUserAPC2 with interrupted-context support (Windows 11 or later)");
    return Error::OK;
}

static int captureAsyncTrace(ASGCT_CallTrace* trace, int maximum, AsyncNativeStack& native, bool verifyJNI, bool compilerTask) {
    auto slot = sample.slot;
    auto& request = slot->apc;
    auto expected = ApcPhase::Idle;
    if (!request.phase.compare_exchange_strong(expected, ApcPhase::Preparing, std::memory_order_acq_rel)) return ticks_skipped;
    request.compilerTask = compilerTask;
    auto& metrics = counters(request);
    if (!request.ready) request.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!request.ready) {
        request.phase.store(ApcPhase::Idle, std::memory_order_release);
        metrics.failed.fetch_add(1, std::memory_order_relaxed);
        return ticks_skipped;
    }
    ResetEvent(request.ready);
    request.trace = *trace;
    request.native = native;
    request.maximum = maximum;
    request.verifyJNI = verifyJNI;
    slot->readers.fetch_add(1, std::memory_order_relaxed);
    metrics.pending.fetch_add(1, std::memory_order_relaxed);
    request.retained.store(true, std::memory_order_relaxed);
    request.phase.store(ApcPhase::Queued, std::memory_order_release);
    if (!queueUserApc2(captureJavaApc, slot->handle, reinterpret_cast<ULONG_PTR>(slot), contextualSpecialApc)) {
        releaseApcReader(*slot);
        request.phase.store(ApcPhase::Idle, std::memory_order_release);
        metrics.failed.fetch_add(1, std::memory_order_relaxed);
        return ticks_skipped;
    }
    metrics.queued.fetch_add(1, std::memory_order_relaxed);
    resumeSamplingTarget();
    HANDLE handles[] = {request.ready, slot->handle};
    DWORD timeout = 20;
    for (;;) {
        auto phase = request.phase.load(std::memory_order_acquire);
        if (phase == ApcPhase::Done) {
            int result = request.trace.num_frames;
            native = request.native;
            request.phase.store(ApcPhase::Idle, std::memory_order_release);
            return result;
        }
        DWORD result = WaitForMultipleObjects(2, handles, FALSE, timeout);
        if (result == WAIT_OBJECT_0 && WaitForSingleObject(slot->handle, 0) != WAIT_OBJECT_0) {
            // The callback sets Done immediately after signalling the event.
            YieldProcessor();
            continue;
        }
        if (result == WAIT_OBJECT_0 + 1 || (result == WAIT_OBJECT_0 && WaitForSingleObject(slot->handle, 0) == WAIT_OBJECT_0)) {
            // No callback can access the trace after the target has exited.
            releaseApcReader(*slot);
            request.phase.store(ApcPhase::Idle, std::memory_order_release);
            return ticks_thread_exit;
        }
        expected = ApcPhase::Queued;
        if (request.phase.compare_exchange_strong(expected, ApcPhase::Cancelled, std::memory_order_acq_rel)) {
            metrics.cancelled.fetch_add(1, std::memory_order_relaxed);
            if (result == WAIT_TIMEOUT) metrics.timedOut.fetch_add(1, std::memory_order_relaxed);
            else metrics.failed.fetch_add(1, std::memory_order_relaxed);
            return ticks_skipped;
        }
        // Once AGCT starts, its output buffer must remain alive until it
        // returns. A queued, cancelled callback never touches that buffer.
        timeout = INFINITE;
    }
}

int captureJavaAsync(ASGCT_CallTrace* trace, int maximum, AsyncNativeStack& native, bool verifyJNI) {
    return captureAsyncTrace(trace, maximum, native, verifyJNI, false);
}

int captureCompilerAsync(AsyncNativeStack& native) {
    ASGCT_CallTrace trace{};
    return captureAsyncTrace(&trace, 0, native, false, true);
}

static void writeApcMetrics(Writer& out, const char* prefix, const ApcCounters& metrics) {
    out << prefix << "_apcs_queued " << u64(metrics.queued.load()) << '\n';
    out << prefix << "_calls " << u64(metrics.calls.load()) << '\n';
    out << prefix << "_apcs_cancelled " << u64(metrics.cancelled.load()) << '\n';
    out << prefix << "_apc_failures " << u64(metrics.failed.load()) << '\n';
    out << prefix << "_apc_timeouts " << u64(metrics.timedOut.load()) << '\n';
    out << prefix << "_apcs_pending " << u64(metrics.pending.load()) << '\n';
}

void writeAsyncJavaMetrics(Writer& out) {
    reapExitedApcRequests();
    writeApcMetrics(out, "windows_agct", javaApcs);
    out << "windows_agct_jnienv_checks " << u64(jniChecks.load()) << '\n';
    writeApcMetrics(out, "windows_comptask", compilerApcs);
    out << "windows_comptask_frames " << u64(compilerTasks.load()) << '\n';
}

static bool captureThread(int tid, int signal, const std::uint64_t* expectedCreation) {
    if (tid == static_cast<int>(GetCurrentThreadId()) || sample.slot) return false;
    if (Breakpoints::handling(static_cast<DWORD>(tid))) return false;
    HANDLE handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid);
    if (!handle) return false;
    auto creation = threadCreation(handle);
    if (GetProcessIdOfThread(handle) != GetCurrentProcessId()
            || !creation || (expectedCreation && creation != *expectedCreation)
            || WaitForSingleObject(handle,0) != WAIT_TIMEOUT) {
        CloseHandle(handle);
        return false;
    }
    // Keep this identity pinned until the registry retains the same object.
    auto slot = registerThread(tid, handle, creation, true);
    CloseHandle(handle);
    if (!slot) return false;
    if (slot->internal.load(std::memory_order_acquire)) { slot->readers.fetch_sub(1); return false; }
    if (slot->tid.load(std::memory_order_acquire) != static_cast<DWORD>(tid)) { slot->readers.fetch_sub(1); return false; }
    sample = {slot, tid, OS::threadState(tid), false, false};
    bool success = false;
    if (SuspendThread(slot->handle) != DWORD(-1)) {
        sample.suspended = true;
        sample.counterPresent = slot->counterPresent.load(std::memory_order_acquire);
        CONTEXT context{}; context.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(slot->handle, &context)) {
            sample.stackLow = reinterpret_cast<std::uintptr_t>(slot->tib->StackLimit);
            sample.stackHigh = reinterpret_cast<std::uintptr_t>(slot->tib->StackBase);
            siginfo_t info{}; info.si_signo = signal;
            deliverSample(signal, &info, &context);
            success = true;
        }
        resumeSamplingTarget();
    }
    sample = {};
    slot->readers.fetch_sub(1, std::memory_order_release);
    return success;
}
bool sampleThread(int tid, int signal) { return captureThread(tid,signal,nullptr); }
void stackLimits(std::uintptr_t& low, std::uintptr_t& high) {
    if (sample.slot) { low = sample.stackLow; high = sample.stackHigh; return; }
    auto tib = reinterpret_cast<const NT_TIB*>(NtCurrentTeb());
    low = reinterpret_cast<std::uintptr_t>(tib->StackLimit);
    high = reinterpret_cast<std::uintptr_t>(tib->StackBase);
}
bool sampleThread(int tid, int signal, std::uint64_t expectedCreation) {
    return captureThread(tid,signal,&expectedCreation);
}

void registerJavaThread(JNIEnv* env, jthread thread) {
    if (!VMStructs::hasNativeThreadId()) return;
    std::lock_guard lock(registryMutex);
    auto vm = VMThread::fromJavaThread(env, thread);
    if (!vm) return;
    int tid = vm->osThreadId();
    HANDLE handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, tid);
    if (!handle) return;
    auto slot = registerThread(tid, handle, threadCreation(handle));
    CloseHandle(handle);
    if (slot) {
        slot->vm.store(vm, std::memory_order_release);
        if (tid == static_cast<int>(GetCurrentThreadId())) { currentSlot = slot; slot->internal.store(internalThread, std::memory_order_release); }
    }
}
void unregisterJavaThread(JNIEnv*, jthread) { std::lock_guard lock(registryMutex); auto slot = ownSlot(); if (slot) slot->vm.store(NULL, std::memory_order_release); }
void registerExistingJavaThreads(JNIEnv* env) {
    if (!VMStructs::hasNativeThreadId()) return;
    jint count; jthread* values;
    if (VM::jvmti()->GetAllThreads(&count, &values) != JVMTI_ERROR_NONE) return;
    for (int i = 0; i < count; ++i) { registerJavaThread(env, values[i]); env->DeleteLocalRef(values[i]); }
    VM::jvmti()->Deallocate(reinterpret_cast<unsigned char*>(values));
}
asprof_thread_local_data* threadData(bool create) {
    auto slot = sample.slot ? sample.slot : create ? ownSlot() : currentSlot;
    if (!slot) return NULL;
    if (create && !slot->counterPresent.load(std::memory_order_acquire)) {
        __atomic_store_n(&slot->counter.sample_counter, std::uint64_t(0), __ATOMIC_RELAXED);
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        slot->counterStarted = now.QuadPart;
        slot->counterPresent.store(true, std::memory_order_release);
    }
    return slot->counterPresent.load(std::memory_order_acquire) ? &slot->counter : NULL;
}
void markSample(int tid, std::uint64_t timestamp) {
    auto slot = sample.slot && sample.tid == tid ? sample.slot
            : currentSlot && currentSlot->tid.load(std::memory_order_acquire) == static_cast<DWORD>(tid) ? currentSlot : NULL;
    if (!slot || (sample.slot && !sample.counterPresent) || !slot->counterPresent.load(std::memory_order_acquire)) return;
    updateSampleCounter(slot, timestamp);
}
void markExternalSample(int tid, std::uint64_t timestamp, std::uint64_t captureQpc) {
    std::lock_guard lock(registryMutex);
    auto slot = findThread(static_cast<DWORD>(tid));
    // The slot may have been reused, or the client may have requested its data
    // after ETW captured this event. Neither case may update the new counter.
    if (slot && slot->counterPresent.load(std::memory_order_acquire) && captureQpc >= slot->counterStarted
            && !slot->internal.load(std::memory_order_acquire)) updateSampleCounter(slot, timestamp);
}
}
