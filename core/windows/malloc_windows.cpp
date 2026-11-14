/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "importHooks.h"
#include "mallocTracer.h"
#include "nativeLockTracer.h"
#include "profiler.h"
#include "tsc.h"
#include "hooks.h"
#include "log.h"
#include "windowsProbe.h"
#include <cstdio>
#include <cerrno>

u64 MallocTracer::_interval;
bool MallocTracer::_nofree;
volatile u64 MallocTracer::_allocated_bytes;
Mutex MallocTracer::_patch_lock;
int MallocTracer::_patched_libs;
bool MallocTracer::_initialized;
volatile bool MallocTracer::_running;

namespace WindowsProfiler::Imports {
std::atomic<unsigned> heapReaders{0};
thread_local unsigned loader_depth;
struct HeapReader {
    bool active;
    HeapReader() { heapReaders.fetch_add(1, std::memory_order_acquire); active = MallocTracer::running(); }
    ~HeapReader() { heapReaders.fetch_sub(1, std::memory_order_release); }
};
#include "heap_policies.inc"

void refresh_after_load() {
    bool symbols = import_consumers.load(std::memory_order_acquire) != 0;
    if (!symbols && !processHooksEnabled.load(std::memory_order_acquire)) return;
    try {
        if (symbols) Profiler::instance()->updateSymbols(false);
        refresh_imports();
    } catch (const std::exception& error) {
        failImport(error.what(), "loaded library refresh");
        Log::error("Windows import interception failed: %s", error.what());
    }
}
struct LoadPolicy {
    template<class Function, class... Args> static HMODULE invoke(Function original, Args... args) {
        Depth depth(loader_depth);
        Depth allocation(allocation_depth);
        HMODULE result = original(args...);
        WindowsError saved;
        // Already-mapped module => loader generation unchanged; NVIDIA's GL driver reloads one every present.
        if (result && depth.outer && (!moduleTrackingAvailable() || modulesChanged())) refresh_after_load();
        return result;
    }
};
using LoadA = FunctionHooks<LoadPolicy, decltype(&LoadLibraryA)>;
using LoadW = FunctionHooks<LoadPolicy, decltype(&LoadLibraryW)>;
using LoadExA = FunctionHooks<LoadPolicy, decltype(&LoadLibraryExA)>;
using LoadExW = FunctionHooks<LoadPolicy, decltype(&LoadLibraryExW)>;

struct ProcPolicy {
    static FARPROC invoke(decltype(&GetProcAddress) original, HMODULE module, LPCSTR name) {
        FARPROC result = original(module, name);
        WindowsError saved;
        if (!result || loader_depth || reinterpret_cast<std::uintptr_t>(name) <= 65535) return result;
        bool relevant = false;
        for (auto& rule : import_rules) relevant |= rule.active() && rule.name == name;
        if (!relevant) return result;
        wchar_t path[MAX_PATH];
        DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
        if (!length || length == MAX_PATH) { failImport("GetModuleFileNameW", name, GetLastError()); return result; }
        auto base = wcsrchr(path, L'\\'); base = base ? base + 1 : path;
        char library[MAX_PATH]; unsigned i = 0;
        while (base[i] && i < MAX_PATH - 1) { library[i] = static_cast<char>(base[i]); ++i; }
        library[i] = 0;
        if (auto rule = import_rule(library, name)) {
            Depth allocation(allocation_depth);
            try {
                auto address = reinterpret_cast<void*>(result);
                auto replacement = rule->resolve(address, false);
                if (!replacement) {
                    std::unique_lock lock(import_mutex, std::try_to_lock);
                    require(lock.owns_lock(), "Concurrent dynamic lookup could not be intercepted");
                    replacement = rule->resolve(address, true);
                }
                if (replacement) result = reinterpret_cast<FARPROC>(replacement);
            } catch (const std::exception& error) { failImport(error.what(), name); Log::error("Dynamic import interception failed for %s: %s", name, error.what()); }
        }
        return result;
    }
};
using Proc = FunctionHooks<ProcPolicy, decltype(&GetProcAddress)>;

void initializeImportRules() {
    std::lock_guard lock(import_mutex);
    if (!import_rules.empty()) return;
    import_rules.insert(import_rules.end(), {
        {"malloc", allocator_library, memory_replacement<MallocHooks>, &memoryHooksEnabled}, {"calloc", allocator_library, memory_replacement<CallocHooks>, &memoryHooksEnabled},
        {"aligned_alloc", allocator_library, memory_replacement<AlignedAllocHooks>, &memoryHooksEnabled},
        {"posix_memalign", allocator_library, memory_replacement<PosixMemalignHooks>, &memoryHooksEnabled},
        {"realloc", allocator_library, memory_replacement<ReallocHooks>, &memoryHooksEnabled}, {"free", allocator_library, memory_replacement<FreeHooks>, &memoryHooksEnabled},
        {"_malloc_base", allocator_library, memory_replacement<MallocHooks>, &memoryHooksEnabled},
        {"_calloc_base", allocator_library, memory_replacement<CallocHooks>, &memoryHooksEnabled},
        {"_realloc_base", allocator_library, memory_replacement<ReallocHooks>, &memoryHooksEnabled},
        {"_free_base", allocator_library, memory_replacement<FreeHooks>, &memoryHooksEnabled},
        {"_expand", allocator_library, memory_replacement<ExpandHooks>, &memoryHooksEnabled},
        {"_aligned_malloc", allocator_library, memory_replacement<AlignedMallocHooks>, &memoryHooksEnabled},
        {"_aligned_offset_malloc", allocator_library, memory_replacement<AlignedOffsetMallocHooks>, &memoryHooksEnabled},
        {"_aligned_realloc", allocator_library, memory_replacement<AlignedReallocHooks>, &memoryHooksEnabled},
        {"_aligned_offset_realloc", allocator_library, memory_replacement<AlignedOffsetReallocHooks>, &memoryHooksEnabled},
        {"_aligned_free", allocator_library, memory_replacement<FreeHooks>, &memoryHooksEnabled},
        {"_recalloc", allocator_library, memory_replacement<RecallocHooks>, &memoryHooksEnabled},
        {"_aligned_recalloc", allocator_library, memory_replacement<AlignedRecallocHooks>, &memoryHooksEnabled},
        {"_aligned_offset_recalloc", allocator_library, memory_replacement<AlignedOffsetRecallocHooks>, &memoryHooksEnabled},
        {"_malloc_dbg", allocator_library, memory_replacement<DebugMallocHooks>, &memoryHooksEnabled},
        {"_calloc_dbg", allocator_library, memory_replacement<DebugCallocHooks>, &memoryHooksEnabled},
        {"_realloc_dbg", allocator_library, memory_replacement<DebugReallocHooks>, &memoryHooksEnabled},
        {"_recalloc_dbg", allocator_library, memory_replacement<DebugRecallocHooks>, &memoryHooksEnabled},
        {"_free_dbg", allocator_library, memory_replacement<DebugFreeHooks>, &memoryHooksEnabled},
        {"_expand_dbg", allocator_library, memory_replacement<DebugExpandHooks>, &memoryHooksEnabled},
        {"_aligned_malloc_dbg", allocator_library, memory_replacement<DebugAlignedMallocHooks>, &memoryHooksEnabled},
        {"_aligned_offset_malloc_dbg", allocator_library, memory_replacement<DebugAlignedOffsetMallocHooks>, &memoryHooksEnabled},
        {"_aligned_realloc_dbg", allocator_library, memory_replacement<DebugAlignedReallocHooks>, &memoryHooksEnabled},
        {"_aligned_offset_realloc_dbg", allocator_library, memory_replacement<DebugAlignedOffsetReallocHooks>, &memoryHooksEnabled},
        {"_aligned_recalloc_dbg", allocator_library, memory_replacement<DebugAlignedRecallocHooks>, &memoryHooksEnabled},
        {"_aligned_offset_recalloc_dbg", allocator_library, memory_replacement<DebugAlignedOffsetRecallocHooks>, &memoryHooksEnabled},
        {"_aligned_free_dbg", allocator_library, memory_replacement<FreeHooks>, &memoryHooksEnabled},
        {"LoadLibraryA", windows_library, import_replacement<LoadA>}, {"LoadLibraryW", windows_library, import_replacement<LoadW>},
        {"LoadLibraryExA", windows_library, import_replacement<LoadExA>}, {"LoadLibraryExW", windows_library, import_replacement<LoadExW>},
        {"GetProcAddress", windows_library, import_replacement<Proc>}
    });
    appendLockRules();
    appendExitRules();
    appendProcessRules();
    WindowsProbe::initialize();
}
}

void WindowsProfiler::allocatorModuleUnloaded(void* base) {
    for (unsigned i = 0, count = Imports::allocator_owner_count.load(std::memory_order_acquire); i < count; ++i) {
        if (Imports::allocator_owners[i].base.load(std::memory_order_acquire) == base) {
            Imports::allocator_owners[i].epoch.store(0, std::memory_order_release);
        }
    }
}

void WindowsProfiler::refreshModulesIfChanged() {
    if (modulesChanged()) Imports::refresh_after_load();
}

void MallocTracer::initialize() { WindowsProfiler::Imports::initializeImportRules(); }
void MallocTracer::patchLibraries() {
    try { WindowsProfiler::Imports::refresh_imports(); }
    catch (const std::exception& error) { WindowsProfiler::Imports::failImport(error.what(), "allocator imports"); Log::error("Cannot patch allocator imports: %s", error.what()); }
}
Error MallocTracer::start(Arguments& args) {
    initialize();
    if (WindowsProfiler::Imports::import_failed.load()) return Error("A Windows import hook failed; restart the target");
    _interval = args._nativemem > 0 ? args._nativemem : 0; _nofree = args._nofree; _allocated_bytes = 0;
    WindowsProfiler::Imports::memoryHooksEnabled.store(true, std::memory_order_release);
    patchLibraries();
    if (WindowsProfiler::Imports::import_failed.load()) return Error("Cannot install Windows allocator hooks");
    _running = true;
    WindowsProfiler::Imports::import_consumers.fetch_add(1);
    return Error::OK;
}
void MallocTracer::stop() {
    if (_running) { _running = false; WindowsProfiler::Imports::import_consumers.fetch_sub(1); }
    while (WindowsProfiler::Imports::heapReaders.load(std::memory_order_acquire)) SwitchToThread();
}
void MallocTracer::recordMalloc(void* address, size_t size) {
    if (!_running || !_enabled || !address || !size || !updateCounter(_allocated_bytes, size, _interval)) return;
    MallocEvent event; event._start_time = TSC::ticks(); event._address = reinterpret_cast<uintptr_t>(address); event._size = size;
    CONTEXT context; WindowsProfiler::captureContext(context);
    Profiler::instance()->recordSample(&context, size, MALLOC_SAMPLE, &event);
}
void MallocTracer::recordFree(void* address) {
    if (!_running || !_enabled || _nofree || !address) return;
    MallocEvent event; event._start_time = TSC::ticks(); event._address = reinterpret_cast<uintptr_t>(address); event._size = 0;
    Profiler::instance()->recordEventOnly(MALLOC_SAMPLE, &event);
}
