/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "hooks.h"
#include "profiler.h"
#include "log.h"
#include "mallocTracer.h"
#include "nativeLockTracer.h"
#include "importHooks.h"
#include "writer.h"

Mutex Hooks::_patch_lock;
int Hooks::_patched_libs = 0;
bool Hooks::_initialized = false;

bool Hooks::init(bool attach) {
    MutexLocker lock(_patch_lock);
    if (_initialized) return false;
    HMODULE pinned;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(Hooks::init), &pinned)) {
        Log::error("Cannot retain the profiler module: %lu", GetLastError());
        return false;
    }
    _initialized = true;
    Profiler::setupSignalHandlers();
    if (attach) Profiler::instance()->updateSymbols(false);
    return true;
}

void Hooks::shutdown() { Profiler::instance()->shutdown(_global_args); }

namespace WindowsProfiler::Imports {
// Upstream registers Hooks::shutdown with atexit. ExitProcess is the Windows point before the
// other threads terminate; kernel32's implementation calls RtlExitUserProcess through its own import.
using Exit = void (WINAPI*)(UINT);
struct ExitPolicy {
    static void invoke(Exit original, UINT code) {
        Hooks::shutdown();
        original(code);
    }
};
using ExitHooks = FunctionHooks<ExitPolicy, Exit>;
void appendExitRules() {
    import_rules.insert(import_rules.end(), {
        {"ExitProcess", windows_library, import_replacement<ExitHooks>},
        {"RtlExitUserProcess", windows_library, import_replacement<ExitHooks>}
    });
}
}

void Hooks::patchLibraries() {
    WindowsProfiler::Imports::initializeImportRules();
    try { WindowsProfiler::Imports::refresh_imports(); }
    catch (const std::exception& error) { WindowsProfiler::Imports::failImport(error.what(), "library hooks"); Log::error("Windows import interception failed: %s", error.what()); }
}

bool WindowsProfiler::installLibraryHooks() {
    Hooks::patchLibraries();
    return !Imports::import_failed.load(std::memory_order_acquire);
}

const char* WindowsProfiler::importFailure() {
    if (!Imports::import_failed.load(std::memory_order_acquire)) return nullptr;
    return Imports::import_failure_ready.load(std::memory_order_acquire) == 2
        ? Imports::import_failure_message : "Windows import interception failed";
}

void WindowsProfiler::Imports::writeImportFailure(Writer& out) {
    if (import_failure_ready.load(std::memory_order_acquire) == 2) {
        out << "windows_import_failure_message " << import_failure_message << '\n';
    }
}

void WindowsProfiler::enableLibraryTracking(bool enabled) {
    if (enabled) Imports::import_consumers.fetch_add(1, std::memory_order_release);
    else Imports::import_consumers.fetch_sub(1, std::memory_order_release);
}
