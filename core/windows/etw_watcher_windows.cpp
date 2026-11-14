/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ASPROF_HELPER
#include "platform.h"
#include "windowsProfiler.h"
#include "log.h"
#endif
#include "windowsEtwWatcher.h"
#include "windowsEtwProfileShare.h"
#include "windowsEtwControllerSecurity.h"
#include <cwchar>
#include <string>
#include <thread>
#include <vector>

namespace WindowsProfiler::Etw {
namespace {
struct Attributes {
    std::vector<unsigned char> storage;
    LPPROC_THREAD_ATTRIBUTE_LIST list = nullptr;
    PSECURITY_DESCRIPTOR security = nullptr;
    ~Attributes() { if (list) DeleteProcThreadAttributeList(list); if (security) LocalFree(security); }
};
ULONG detachedCreationFlags(DWORD& flags) {
    flags = CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | NORMAL_PRIORITY_CLASS;
    BOOL inJob;
    if (!IsProcessInJob(GetCurrentProcess(), nullptr, &inJob)) return GetLastError();
    if (!inJob) return ERROR_SUCCESS;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION job{};
    if (!QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation, &job, sizeof(job), nullptr)) return GetLastError();
    auto limits = job.BasicLimitInformation.LimitFlags;
    if (limits & JOB_OBJECT_LIMIT_BREAKAWAY_OK) flags |= CREATE_BREAKAWAY_FROM_JOB;
    else if (!(limits & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)) return ERROR_ACCESS_DENIED;
    return ERROR_SUCCESS;
}
}

ULONG controlScheduling(HANDLE process) {
    DWORD_PTR processMask, systemMask;
    return GetProcessAffinityMask(process, &processMask, &systemMask) && SetProcessAffinityMask(process, systemMask)
        ? ERROR_SUCCESS : GetLastError();
}

void SessionWatcher::stopWaiting() {
    if (_wait) {
        SetThreadpoolWait(_wait, nullptr, nullptr);
        WaitForThreadpoolWaitCallbacks(_wait, TRUE);
        CloseThreadpoolWait(_wait);
        _wait = nullptr;
    }
}

void SessionWatcher::close() {
    stopWaiting();
    if (_state) { UnmapViewOfFile(_state); _state = nullptr; }
    for (auto object : {&_mapping, &_ready, &_done, &_parent, &_space, &_lock, &_section, &_process}) {
        if (*object) { CloseHandle(*object); *object = nullptr; }
    }
    _pid = 0;
    _share = nullptr;
}

ULONG SessionWatcher::start(const Properties& properties, ProfileShare* share, bool secure) try {
    if (_process || _state) return ERROR_ALREADY_INITIALIZED;
    _phase.store(0, std::memory_order_release);
    DWORD creationFlags;
    auto result = detachedCreationFlags(creationFlags);
    if (result) return result;
    SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
    _mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0, sizeof(WatchState), nullptr);
    if (!_mapping) return GetLastError();
    _state = static_cast<WatchState*>(MapViewOfFile(_mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(WatchState)));
    if (!_state) { result = GetLastError(); close(); return result; }
    *_state = {};
    _state->protocol = WATCH_PROTOCOL; _state->size = sizeof(WatchState);
    _state->ownerPid = GetCurrentProcessId();
    _state->guid = properties.p.Wnode.Guid;
    std::wmemcpy(_state->name, properties.name, 128);
    _share = share;
    _ready = CreateEventW(&security, TRUE, FALSE, nullptr);
    _done = CreateEventW(&security, TRUE, FALSE, nullptr);
    if (!_ready || !_done
            || !DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &_parent,
                SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, TRUE, 0)
            || (share && (!DuplicateHandle(GetCurrentProcess(), share->space(), GetCurrentProcess(), &_space, 0, TRUE, DUPLICATE_SAME_ACCESS)
            || !DuplicateHandle(GetCurrentProcess(), share->lock(), GetCurrentProcess(), &_lock,
                SYNCHRONIZE | MUTEX_MODIFY_STATE, TRUE, 0)
            || !DuplicateHandle(GetCurrentProcess(), share->section(), GetCurrentProcess(), &_section,
                FILE_MAP_READ | FILE_MAP_WRITE, TRUE, 0)))) {
        result = GetLastError(); close(); return result;
    }
    std::vector<HANDLE> handles{_mapping, _ready, _done, _parent};
    if (share) handles.insert(handles.end(), {_space, _lock, _section});
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    Attributes attributes;
    attributes.storage.resize(size);
    auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.storage.data());
    if (!InitializeProcThreadAttributeList(list, 1, 0, &size)) { result = GetLastError(); close(); return result; }
    attributes.list = list;
    if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.data(), handles.size() * sizeof(HANDLE), nullptr, nullptr)) {
        result = GetLastError(); close(); return result;
    }
    std::vector<WCHAR> path(32768);
    DWORD length = GetModuleFileNameW(
#ifdef ASPROF_HELPER
        nullptr,
#else
        WindowsProfiler::selfModule(),
#endif
        path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) { result = length ? ERROR_FILENAME_EXCED_RANGE : GetLastError(); close(); return result; }
    std::wstring executable(path.data(), length);
    executable.resize(executable.find_last_of(L"\\/") + 1);
    executable += L"asprof-helper.exe";
    std::wstring command = L"\"" + executable + (secure ? L"\" --etw-watch-broker" : L"\" --etw-watch");
    for (auto handle : {_mapping, _ready, _done, _parent, _space, _lock, _section}) command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.lpAttributeList = list;
    PROCESS_INFORMATION child{};
    SECURITY_ATTRIBUTES controller{sizeof(controller), nullptr, FALSE};
    if (secure) {
        result = controllerSecurity(attributes.security);
        if (result) { close(); return result; }
        controller.lpSecurityDescriptor = attributes.security;
    }
    if (!CreateProcessW(executable.c_str(), command.data(), secure ? &controller : nullptr, secure ? &controller : nullptr, TRUE, creationFlags,
            nullptr, nullptr, &startup.StartupInfo, &child)) {
        result = GetLastError(); close(); return result;
    }
    _process = child.hProcess; _pid = child.dwProcessId;
    BOOL childInJob = TRUE;
    bool detached = IsProcessInJob(child.hProcess, nullptr, &childInJob) && !childInJob;
    result = detached ? controlScheduling(child.hProcess) : ERROR_ACCESS_DENIED;
    if (result || ResumeThread(child.hThread) == DWORD(-1)) {
        if (!result) result = GetLastError();
        TerminateProcess(child.hProcess, result);
        WaitForSingleObject(child.hProcess, 5000);
        CloseHandle(child.hThread); close(); return result;
    }
    CloseHandle(child.hThread);
    for (auto handle : handles) {
        if (!SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0)) {
            result = GetLastError(); finish(); return result;
        }
    }
    HANDLE events[] = {_ready, _process};
    auto ready = WaitForMultipleObjects(2, events, FALSE, 10000);
    if (ready == WAIT_OBJECT_0 && InterlockedCompareExchange(&_state->ready, 0, 0) == 1
            && WaitForSingleObject(_process, 0) == WAIT_TIMEOUT) {
        _wait = CreateThreadpoolWait(helperExited, this, nullptr);
        if (!_wait) { result = GetLastError(); finish(); return result; }
        SetThreadpoolWait(_wait, _process, nullptr);
        return ERROR_SUCCESS;
    }
    result = ready == WAIT_TIMEOUT ? ERROR_TIMEOUT : _state->startupError;
    if (!result) result = ERROR_BROKEN_PIPE;
    finish();
    return result;
} catch (...) {
    finish();
    return ERROR_NOT_ENOUGH_MEMORY;
}

void CALLBACK SessionWatcher::helperExited(PTP_CALLBACK_INSTANCE, void* context, PTP_WAIT, TP_WAIT_RESULT) {
    auto self = static_cast<SessionWatcher*>(context);
    auto phase = self->_phase.load(std::memory_order_acquire);
    do {
        if (phase & EXIT_EXPECTED) return;
    } while (!self->_phase.compare_exchange_weak(phase, phase | HELPER_FAILED,
        std::memory_order_acq_rel, std::memory_order_acquire));
    if (phase & CAPTURE_ACTIVE) {
#ifndef ASPROF_HELPER
        Log::error("ETW session watcher exited unexpectedly; stopping capture");
#endif
        self->cleanup();
    }
}

ULONG SessionWatcher::activate() {
    if (WaitForSingleObject(_process, 0) != WAIT_TIMEOUT) _phase.fetch_or(HELPER_FAILED, std::memory_order_acq_rel);
    auto phase = _phase.fetch_or(CAPTURE_ACTIVE, std::memory_order_acq_rel);
    if (!(phase & HELPER_FAILED)) return ERROR_SUCCESS;
    cleanup();
    return ERROR_BROKEN_PIPE;
}

ULONG SessionWatcher::cleanup() {
    AcquireSRWLockExclusive(&_control);
    ULONG result = ERROR_NOT_ENOUGH_MEMORY;
    try {
        // Stopping ETW on a sampled application thread can suppress its stack
        // walks in subsequent sessions. Keep this control operation on a
        // disposable internal thread, including recovery after helper death.
        std::thread control([&] {
#ifndef ASPROF_HELPER
            WindowsProfiler::markInternalThread();
#endif
            try { cleanupSession(*_state, _share); }
            catch (...) { _state->stopError = ERROR_NOT_ENOUGH_MEMORY; }
        });
        control.join();
        result = _state->stopError;
    } catch (...) { }
    ReleaseSRWLockExclusive(&_control);
    return result;
}

WatchResult SessionWatcher::finish() {
    WatchResult result;
    if (_wait && WaitForSingleObject(_process, 0) == WAIT_OBJECT_0) {
        _phase.fetch_or(HELPER_FAILED, std::memory_order_acq_rel);
    }
    _phase.fetch_or(EXIT_EXPECTED, std::memory_order_acq_rel);
    if (_process) {
        SetEvent(_done);
        auto wait = WaitForSingleObject(_process, 10000);
        if (wait != WAIT_OBJECT_0) {
            result.error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
            TerminateProcess(_process, result.error);
            WaitForSingleObject(_process, 5000);
        } else if (!GetExitCodeProcess(_process, &result.error)) result.error = GetLastError();
    }
    if (_state) {
        stopWaiting();
        if (!result.error) result.error = _state->stopError ? _state->stopError : _state->restoreError;
        result.eventsLost = _state->eventsLost;
        result.buffersLost = _state->buffersLost;
        result.realtimeBuffersLost = _state->realtimeBuffersLost;
    }
    if (failed()) result.error = ERROR_BROKEN_PIPE;
    close();
    return result;
}
}
