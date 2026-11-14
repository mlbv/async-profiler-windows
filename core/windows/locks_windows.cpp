/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "importHooks.h"
#include "nativeLockTracer.h"
#include "profiler.h"
#include "tsc.h"
#include "log.h"

u64 NativeLockTracer::_interval;
double NativeLockTracer::_ticks_to_nanos;
Mutex NativeLockTracer::_patch_lock;
int NativeLockTracer::_patched_libs;
bool NativeLockTracer::_initialized;
volatile bool NativeLockTracer::_running;
volatile u64 NativeLockTracer::_total_duration;

namespace WindowsProfiler::Imports {
std::atomic<unsigned> lockReaders{0};
std::atomic<std::uint64_t> lockGeneration{0};
using RtlTry = BOOLEAN (NTAPI*)(void*);
RtlTry tryRtlCritical;

struct TryCritical { static bool acquire(CRITICAL_SECTION* lock) { return TryEnterCriticalSection(lock) != 0; } };
struct TryExclusive { static bool acquire(SRWLOCK* lock) { return TryAcquireSRWLockExclusive(lock) != 0; } };
struct TryShared { static bool acquire(SRWLOCK* lock) { return TryAcquireSRWLockShared(lock) != 0; } };
template<class Try> struct LockPolicy {
    template<class Function, class Lock> static void invoke(Function original, Lock lock) {
        if (!NativeLockTracer::running() || allocation_depth) { original(lock); return; }
        Depth depth(allocation_depth);
        DWORD error = GetLastError();
        if (Try::acquire(lock)) { SetLastError(error); return; }
        SetLastError(error);
        auto epoch = lockGeneration.load(std::memory_order_acquire);
        u64 start = TSC::ticks();
        original(lock);
        WindowsError errors;
        lockReaders.fetch_add(1, std::memory_order_acquire);
        if (NativeLockTracer::running() && epoch == lockGeneration.load(std::memory_order_acquire)) NativeLockTracer::recordNativeLock(lock, start, TSC::ticks());
        lockReaders.fetch_sub(1, std::memory_order_release);
    }
};
struct RtlCriticalPolicy {
    static LONG invoke(LONG (NTAPI* original)(void*), void* lock) {
        if (!NativeLockTracer::running() || allocation_depth) return original(lock);
        Depth depth(allocation_depth);
        DWORD error = GetLastError();
        if (tryRtlCritical(lock)) { SetLastError(error); return 0; }
        SetLastError(error);
        auto epoch = lockGeneration.load(std::memory_order_acquire);
        u64 start = TSC::ticks();
        LONG result = original(lock);
        WindowsError errors;
        lockReaders.fetch_add(1, std::memory_order_acquire);
        if (result >= 0 && NativeLockTracer::running() && epoch == lockGeneration.load(std::memory_order_acquire)) NativeLockTracer::recordNativeLock(lock, start, TSC::ticks());
        lockReaders.fetch_sub(1, std::memory_order_release);
        return result;
    }
};
using Critical = FunctionHooks<LockPolicy<TryCritical>, decltype(&EnterCriticalSection)>;
using Exclusive = FunctionHooks<LockPolicy<TryExclusive>, decltype(&AcquireSRWLockExclusive)>;
using Shared = FunctionHooks<LockPolicy<TryShared>, decltype(&AcquireSRWLockShared)>;
using RtlCritical = FunctionHooks<RtlCriticalPolicy, LONG (NTAPI*)(void*)>;
template<class Family> void* lockReplacement(void* original, bool create) {
    if (!lockHooksEnabled.load(std::memory_order_acquire)) return NULL;
    return import_replacement<Family>(original, create);
}
void appendLockRules() {
    tryRtlCritical = reinterpret_cast<RtlTry>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlTryEnterCriticalSection"));
    import_rules.insert(import_rules.end(), {
        {"EnterCriticalSection", windows_library, lockReplacement<Critical>, &lockHooksEnabled}, {"RtlEnterCriticalSection", windows_library, lockReplacement<RtlCritical>, &lockHooksEnabled},
        {"AcquireSRWLockExclusive", windows_library, lockReplacement<Exclusive>, &lockHooksEnabled}, {"RtlAcquireSRWLockExclusive", windows_library, lockReplacement<Exclusive>, &lockHooksEnabled},
        {"AcquireSRWLockShared", windows_library, lockReplacement<Shared>, &lockHooksEnabled}, {"RtlAcquireSRWLockShared", windows_library, lockReplacement<Shared>, &lockHooksEnabled}
    });
}
}

void NativeLockTracer::initialize() { WindowsProfiler::Imports::initializeImportRules(); }
void NativeLockTracer::patchLibraries() {
    try { WindowsProfiler::Imports::refresh_imports(); }
    catch (const std::exception& error) { WindowsProfiler::Imports::failImport(error.what(), "native lock imports"); Log::error("Cannot intercept native locks: %s", error.what()); }
}
Error NativeLockTracer::start(Arguments& args) {
    initialize();
    if (WindowsProfiler::Imports::import_failed.load()) return Error("A Windows import hook failed; restart the target");
    _ticks_to_nanos = 1e9 / TSC::frequency();
    _interval = static_cast<u64>(args._nativelock * (TSC::frequency() / 1e9)); _total_duration = 0;
    WindowsProfiler::Imports::lockGeneration.fetch_add(1);
    WindowsProfiler::Imports::lockHooksEnabled.store(true, std::memory_order_release);
    patchLibraries();
    if (WindowsProfiler::Imports::import_failed.load()) return Error("Cannot install Windows native-lock hooks");
    _running = true; WindowsProfiler::Imports::import_consumers.fetch_add(1);
    return Error::OK;
}
void NativeLockTracer::stop() {
    if (_running) { _running = false; WindowsProfiler::Imports::lockGeneration.fetch_add(1); WindowsProfiler::Imports::import_consumers.fetch_sub(1); }
    while (WindowsProfiler::Imports::lockReaders.load(std::memory_order_acquire)) SwitchToThread();
}
void NativeLockTracer::recordNativeLock(void* address, u64 start, u64 end) {
    if (!_running || !_enabled || end < start || !updateCounter(_total_duration, end - start, _interval)) return;
    NativeLockEvent event; event._start_time = start; event._end_time = end; event._address = reinterpret_cast<uintptr_t>(address);
    CONTEXT context; WindowsProfiler::captureContext(context);
    Profiler::instance()->recordSample(&context, static_cast<u64>((end - start) * _ticks_to_nanos), NATIVE_LOCK_SAMPLE, &event);
}
