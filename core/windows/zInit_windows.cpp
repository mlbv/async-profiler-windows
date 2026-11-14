/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Windows counterpart of zInit.cpp's LateInitializer.
#include "platform.h"
#include "windowsOutput.h"
#include "windowsPreload.h"
#include "arguments.h"
#include "hooks.h"
#include "log.h"
#include "os.h"
#include "profiler.h"
#include "symbols.h"
#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>

// A running JVM loading this library for Agent_OnAttach prints its dynamic-agent warning after the load returns
// and before calling the agent, unless EnableDynamicAgentLoading came from the command line. As upstream does
// when the library is loaded into a created VM, a default flag is marked as set on the command line. This runs
// under the loader lock, so it only reads jvm.dll's exported VMStructs tables and writes the flag's origin word.
static void markDynamicAgentLoading() {
    HMODULE jvm = GetModuleHandleW(L"jvm.dll");
    auto structs = jvm ? reinterpret_cast<char**>(GetProcAddress(jvm, "gHotSpotVMStructs")) : nullptr;
    if (!structs) return;
    auto exported = [jvm](const char* name) { return *reinterpret_cast<const std::uint64_t*>(GetProcAddress(jvm, name)); };
    auto at = [](const char* entry, std::uint64_t offset) { return entry + offset; };
    auto typeName = exported("gHotSpotVMStructEntryTypeNameOffset"), fieldName = exported("gHotSpotVMStructEntryFieldNameOffset");
    auto fieldOffset = exported("gHotSpotVMStructEntryOffsetOffset"), address = exported("gHotSpotVMStructEntryAddressOffset");
    auto stride = exported("gHotSpotVMStructEntryArrayStride");
    char* const* heap = nullptr;
    char* flags = nullptr;
    std::size_t count = 0, size = 0, nameOffset = SIZE_MAX, originOffset = SIZE_MAX;
    for (const char* entry = *structs; auto type = *reinterpret_cast<const char* const*>(at(entry, typeName)); entry += stride) {
        auto field = *reinterpret_cast<const char* const*>(at(entry, fieldName));
        auto value = *reinterpret_cast<char* const*>(at(entry, address));
        if (std::strcmp(type, "Universe") == 0 && std::strcmp(field, "_collectedHeap") == 0) heap = reinterpret_cast<char* const*>(value);
        if (std::strcmp(type, "JVMFlag") != 0) continue;
        if (std::strcmp(field, "_name") == 0) nameOffset = *reinterpret_cast<const std::uint64_t*>(at(entry, fieldOffset));
        else if (std::strcmp(field, "_flags") == 0) originOffset = *reinterpret_cast<const std::uint64_t*>(at(entry, fieldOffset));
        else if (std::strcmp(field, "flags") == 0) flags = *reinterpret_cast<char* const*>(value);
        else if (std::strcmp(field, "numFlags") == 0) count = *reinterpret_cast<const std::size_t*>(value);
    }
    auto types = *reinterpret_cast<char**>(GetProcAddress(jvm, "gHotSpotVMTypes"));
    auto typeStride = exported("gHotSpotVMTypeEntryArrayStride"), typeTypeName = exported("gHotSpotVMTypeEntryTypeNameOffset");
    auto typeSize = exported("gHotSpotVMTypeEntrySizeOffset");
    for (const char* entry = types; auto type = *reinterpret_cast<const char* const*>(at(entry, typeTypeName)); entry += typeStride) {
        if (std::strcmp(type, "JVMFlag") == 0) size = *reinterpret_cast<const std::uint64_t*>(at(entry, typeSize));
    }
    // The heap exists once the VM is created, after a startup -agentpath load. JDK 8 names the table Flag and never warns.
    if (!heap || !*heap || !flags || !size || nameOffset == SIZE_MAX || originOffset == SIZE_MAX) return;
    // HotSpot's JVMFlag origin occupies the low four bits (0: default); bit 17 records a command-line setting.
    constexpr int originMask = 15, setOnCommandLine = 1 << 17;
    for (std::size_t i = 0; i < count; ++i) {
        auto flag = flags + i * size;
        auto name = *reinterpret_cast<const char* const*>(flag + nameOffset);
        if (!name || std::strcmp(name, "EnableDynamicAgentLoading") != 0) continue;
        auto& origin = *reinterpret_cast<int*>(flag + originOffset);
        if ((origin & originMask) == 0) origin |= setOnCommandLine;
        return;
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        markDynamicAgentLoading();
    } else if (reason == DLL_THREAD_ATTACH || reason == DLL_THREAD_DETACH) {
        // Thread IDs are reused; upstream clears them in its pthread_setspecific hook.
        ThreadFilter* filter = Profiler::instance()->threadFilter();
        if (filter->enabled()) filter->remove(GetCurrentThreadId());
    }
    return TRUE;
}

static std::atomic<bool> launcherStarted{false};

bool OS::checkPreloaded() { return launcherStarted.load(std::memory_order_acquire); }

// The launcher queues this as the last user APC on the primary thread: after every preload DLL is loaded,
// outside the loader lock and before the executable's entry point. It is not part of the public C API.
extern "C" __declspec(dllexport) void NTAPI asprof_preload_start(void* libraries, void*, void*) {
    launcherStarted.store(true, std::memory_order_release);
    WindowsProfiler::Preload::inherit(static_cast<wchar_t*>(libraries));
    std::string command;
    auto result = WindowsProfiler::environmentValue("ASPROF_COMMAND", command);
    if (result == WindowsProfiler::EnvironmentResult::Missing) return;
    if (result == WindowsProfiler::EnvironmentResult::Error) {
        Log::error("Cannot read ASPROF_COMMAND");
        return;
    }

    // As upstream, a process that already contains a JVM is left to the JVM agent entry points.
    Profiler* profiler = Profiler::instance();
    Symbols::parseLibraries(profiler->nativeLibs(), false, true);
    if (profiler->findLibraryByName("jvm.dll") != NULL || !Hooks::init(false)) return;

    Error error = _global_args.parse(command.c_str());
    _global_args._preloaded = true;
    Log::open(_global_args);
    if (error || (error = profiler->run(_global_args))) {
        Log::error("%s", error.message());
    }
}
