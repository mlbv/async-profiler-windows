/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Upstream's LD_PRELOAD and ASPROF_COMMAND are inherited, so every descendant of a preloaded process starts
// profiling. A preloaded process intercepts process creation and preloads children that inherit ASPROF_COMMAND.
#include "platform.h"
#include "windowsProfiler.h"
#include "windowsOutput.h"
#include "windowsPreload.h"
#include "importHooks.h"
#include "hooks.h"
#include "log.h"
#include <cwchar>
#include <tuple>

namespace {
std::vector<std::wstring> preloadLibraries;
// Wrappers in kernel32 and advapi32 call the patched imports again; the outermost call preloads the child.
thread_local bool creatingChild;

template<class Char> bool definesCommand(const Char* block) {
    constexpr char name[] = "ASPROF_COMMAND=";
    for (auto entry = block; *entry; ++entry) {
        size_t i = 0;
        while (name[i] && (entry[i] == name[i] || (name[i] >= 'A' && name[i] <= 'Z' && entry[i] == name[i] + ('a' - 'A')))) ++i;
        if (!name[i]) return true;
        while (*entry) ++entry;
    }
    return false;
}

bool inheritsCommand(DWORD flags, const void* environment) {
    if (!environment) {
        std::string value;
        return WindowsProfiler::environmentValue("ASPROF_COMMAND", value) != WindowsProfiler::EnvironmentResult::Missing;
    }
    return flags & CREATE_UNICODE_ENVIRONMENT ? definesCommand(static_cast<const wchar_t*>(environment))
                                              : definesCommand(static_cast<const char*>(environment));
}

template<class Create> BOOL preloadChild(DWORD flags, const void* environment, PROCESS_INFORMATION* info, Create create) {
    if (creatingChild || !inheritsCommand(flags, environment)) return create(flags);
    creatingChild = true;
    struct Outermost { ~Outermost() { creatingChild = false; } } outermost;
    if (flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) {
        // Its loader events would wait for the debugger loop of the thread that is creating it.
        Log::warn("Not preloading a process created for debugging");
        return create(flags);
    }
    if (!create(flags | CREATE_SUSPENDED)) return FALSE;
    WindowsProfiler::Imports::WindowsError created;
    WindowsProfiler::Preload::Injector injector(info->hProcess, info->hThread);
    std::wstring message;
    auto error = injector.load(preloadLibraries, message);
    if (error) {
        Log::warn("Not preloading process %lu: %s (Windows error %lu)", info->dwProcessId,
            WindowsProfiler::utf8(message).c_str(), error);
    }
    injector.release(error == ERROR_SUCCESS, (flags & CREATE_SUSPENDED) != 0);
    return TRUE;
}

// Flags is the index of dwCreationFlags; lpEnvironment follows it and lpProcessInformation is four places later.
template<std::size_t Flags> struct CreatePolicy {
    template<class Function, class... A> static BOOL invoke(Function original, A... arguments) {
        auto values = std::make_tuple(arguments...);
        auto create = [&](DWORD flags) {
            auto call = values;
            std::get<Flags>(call) = flags;
            return std::apply(original, call);
        };
        return preloadChild(std::get<Flags>(values), std::get<Flags + 1>(values), std::get<Flags + 4>(values), create);
    }
};

using CreateInternalW = BOOL (WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);
using CreateInternalA = BOOL (WINAPI*)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION, PHANDLE);
}

namespace WindowsProfiler::Imports {
using CreateW = FunctionHooks<CreatePolicy<5>, decltype(&CreateProcessW)>;
using CreateA = FunctionHooks<CreatePolicy<5>, decltype(&CreateProcessA)>;
using AsUserW = FunctionHooks<CreatePolicy<6>, decltype(&CreateProcessAsUserW)>;
using AsUserA = FunctionHooks<CreatePolicy<6>, decltype(&CreateProcessAsUserA)>;
using InternalW = FunctionHooks<CreatePolicy<6>, CreateInternalW>;
using InternalA = FunctionHooks<CreatePolicy<6>, CreateInternalA>;

static bool processLibrary(std::string_view name) { return windows_library(name) || _stricmp(name.data(), "advapi32.dll") == 0; }
// Windows' own CreateProcess exports in these modules forward through their imports. Patching only the caller's
// import intercepts each call once and leaves this DLL's helper launches, which pass through kernel32, alone.
static bool processWrapper(HMODULE importer) {
    return importer == GetModuleHandleW(L"kernel32.dll") || importer == GetModuleHandleW(L"kernelbase.dll")
        || importer == GetModuleHandleW(L"advapi32.dll");
}

void appendProcessRules() {
    import_rules.insert(import_rules.end(), {
        {"CreateProcessW", processLibrary, import_replacement<CreateW>, &processHooksEnabled, processWrapper},
        {"CreateProcessA", processLibrary, import_replacement<CreateA>, &processHooksEnabled, processWrapper},
        {"CreateProcessAsUserW", processLibrary, import_replacement<AsUserW>, &processHooksEnabled, processWrapper},
        {"CreateProcessAsUserA", processLibrary, import_replacement<AsUserA>, &processHooksEnabled, processWrapper},
        {"CreateProcessInternalW", processLibrary, import_replacement<InternalW>, &processHooksEnabled, processWrapper},
        {"CreateProcessInternalA", processLibrary, import_replacement<InternalA>, &processHooksEnabled, processWrapper}
    });
}
}

void WindowsProfiler::Preload::inherit(wchar_t* libraries) {
    for (auto library = libraries; *library; library += std::wcslen(library) + 1) preloadLibraries.emplace_back(library);
    VirtualFree(libraries, 0, MEM_RELEASE);
    // Patched imports point into this module for the rest of the process.
    HMODULE pinned;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, reinterpret_cast<LPCWSTR>(&inherit), &pinned);
    Imports::processHooksEnabled.store(true, std::memory_order_release);
    Hooks::patchLibraries();
}
