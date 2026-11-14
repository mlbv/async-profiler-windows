/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace WindowsProfiler::Preload {
// asprof-helper --preload DLL [--preload DLL ...] -- EXE [ARGS...]
// Returns EXE's exit code, or the Windows error that stopped preloading.
int launch(int argc, WCHAR** argv);

// Loads DLLs into a process created suspended. User APCs on its primary thread load them after process
// initialization, outside the loader lock and before the executable's entry point, and park between loads.
class Injector {
    HANDLE _process, _thread;
    HANDLE _loaded = nullptr, _resume = nullptr, _remoteLoaded = nullptr, _remoteResume = nullptr;
    void* _remote = nullptr;
    void* _libraries = nullptr;
    ULONG_PTR _start = 0;
    bool _running = false;

  public:
    Injector(HANDLE process, HANDLE thread) : _process(process), _thread(thread) {}
    Injector(const Injector&) = delete;
    Injector& operator=(const Injector&) = delete;
    ~Injector();

    // Loads each library in order and finds the one profiler DLL. On failure the process has not run or is parked
    // between loads; message names the failing step. A 32-bit process fails with ERROR_BAD_EXE_FORMAT before running.
    DWORD load(const std::vector<std::wstring>& libraries, std::wstring& message);
    // Calls the profiler DLL's asprof_preload_start when start is set, then leaves the primary thread running or
    // suspended once. The start entry receives the library list, so the process can preload its own children.
    void release(bool start, bool suspended);
};

// Called by asprof_preload_start in a preloaded process: takes ownership of the NUL-separated library list
// and preloads it into child processes that inherit ASPROF_COMMAND.
void inherit(wchar_t* libraries);
}
