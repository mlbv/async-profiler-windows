/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsPreload.h"
#include <winternl.h>
#include <cstring>
#include <cwchar>

extern "C" __declspec(dllimport) NTSTATUS NTAPI NtQueueApcThread(HANDLE thread, PVOID routine, PVOID argument1,
    PVOID argument2, PVOID argument3);

namespace WindowsProfiler::Preload {
namespace {
constexpr char START_EXPORT[] = "asprof_preload_start";
// x64 TEB::LastErrorValue directly follows ProcessEnvironmentBlock.
constexpr ULONG_PTR TEB_LAST_ERROR = 0x68;

struct ThreadBasics {
    NTSTATUS exitStatus;
    PVOID teb;
    CLIENT_ID clientId;
    KAFFINITY affinity;
    LONG priority, basePriority;
};

// The child records each load outcome here before parking.
struct LoadResult {
    HMODULE module;
    DWORD error;
};

template<class T> bool readRemote(HANDLE process, ULONG_PTR address, T* value, size_t count = 1) {
    return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), value, sizeof(T) * count, nullptr) != 0;
}

// Resolves START_EXPORT in a module the child's loader has mapped; entry stays 0 when it is absent.
DWORD startEntry(HANDLE process, ULONG_PTR base, ULONG_PTR& entry) {
    entry = 0;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 nt;
    if (!readRemote(process, base, &dos) || !readRemote(process, base + dos.e_lfanew, &nt)) return GetLastError();
    auto directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT || !directory.VirtualAddress) return ERROR_SUCCESS;
    ULONG_PTR imageSize = nt.OptionalHeader.SizeOfImage;
    auto inside = [imageSize](ULONG_PTR rva, ULONG_PTR bytes) { return rva <= imageSize && bytes <= imageSize - rva; };
    IMAGE_EXPORT_DIRECTORY exports;
    if (!inside(directory.VirtualAddress, sizeof(exports))) return ERROR_BAD_EXE_FORMAT;
    if (!readRemote(process, base + directory.VirtualAddress, &exports)) return GetLastError();
    ULONG_PTR count = exports.NumberOfNames;
    if (!inside(exports.AddressOfNames, count * sizeof(DWORD)) || !inside(exports.AddressOfNameOrdinals, count * sizeof(WORD))
            || !inside(exports.AddressOfFunctions, ULONG_PTR(exports.NumberOfFunctions) * sizeof(DWORD)))
        return ERROR_BAD_EXE_FORMAT;
    if (!count) return ERROR_SUCCESS;
    std::vector<DWORD> names(count);
    std::vector<WORD> ordinals(count);
    if (!readRemote(process, base + exports.AddressOfNames, names.data(), count)
            || !readRemote(process, base + exports.AddressOfNameOrdinals, ordinals.data(), count)) return GetLastError();
    for (ULONG_PTR i = 0; i < count; ++i) {
        // A name that cannot hold START_EXPORT before the image ends is a different, shorter name.
        char name[sizeof(START_EXPORT)];
        if (!inside(names[i], sizeof(name))) continue;
        if (!readRemote(process, base + names[i], name, sizeof(name))) return GetLastError();
        if (std::memcmp(name, START_EXPORT, sizeof(name)) != 0) continue;
        DWORD rva;
        if (ordinals[i] >= exports.NumberOfFunctions) return ERROR_BAD_EXE_FORMAT;
        if (!readRemote(process, base + exports.AddressOfFunctions + ordinals[i] * sizeof(DWORD), &rva)) return GetLastError();
        bool forwarded = rva >= directory.VirtualAddress && rva - directory.VirtualAddress < directory.Size;
        if (forwarded || !inside(rva, 1)) return ERROR_BAD_EXE_FORMAT;
        entry = base + rva;
        return ERROR_SUCCESS;
    }
    return ERROR_SUCCESS;
}

// Known DLLs have one per-boot base in every process, so these addresses are valid in the child.
DWORD queue(HANDLE thread, const void* routine, const void* first = nullptr, const void* second = nullptr, const void* third = nullptr) {
    auto queued = NtQueueApcThread(thread, const_cast<void*>(routine), const_cast<void*>(first), const_cast<void*>(second),
        const_cast<void*>(third));
    return NT_SUCCESS(queued) ? ERROR_SUCCESS : RtlNtStatusToDosError(queued);
}

// The error is evaluated before the message is stored, which may allocate.
DWORD failed(std::wstring& message, const wchar_t* text, DWORD error) {
    message = text;
    return error;
}

void* copyRemote(HANDLE process, const std::vector<unsigned char>& bytes) {
    auto remote = VirtualAllocEx(process, nullptr, bytes.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote && !WriteProcessMemory(process, remote, bytes.data(), bytes.size(), nullptr)) {
        auto error = GetLastError();
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        SetLastError(error);
        return nullptr;
    }
    return remote;
}
}

Injector::~Injector() {
    if (_loaded) CloseHandle(_loaded);
    if (_resume) CloseHandle(_resume);
}

DWORD Injector::load(const std::vector<std::wstring>& libraries, std::wstring& message) {
    BOOL wow64;
    if (!IsWow64Process(_process, &wow64)) return failed(message, L"Cannot inspect the process", GetLastError());
    if (wow64) return failed(message, L"A 32-bit process cannot load x64 DLLs", ERROR_BAD_EXE_FORMAT);
    ThreadBasics basic;
    auto status = NtQueryInformationThread(_thread, ThreadBasicInformation, &basic, sizeof(basic), nullptr);
    if (!NT_SUCCESS(status)) return failed(message, L"Cannot locate the primary thread environment", RtlNtStatusToDosError(status));

    std::vector<unsigned char> block(libraries.size() * sizeof(LoadResult)), list;
    std::vector<size_t> pathOffsets;
    for (const auto& library : libraries) {
        auto bytes = reinterpret_cast<const unsigned char*>(library.c_str());
        pathOffsets.push_back(block.size());
        block.insert(block.end(), bytes, bytes + (library.size() + 1) * sizeof(WCHAR));
        list.insert(list.end(), bytes, bytes + (library.size() + 1) * sizeof(WCHAR));
    }
    list.insert(list.end(), sizeof(WCHAR), 0);
    _loaded = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    _resume = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!_loaded || !_resume) return failed(message, L"Cannot create preload events", GetLastError());
    if (!(_remote = copyRemote(_process, block)) || !(_libraries = copyRemote(_process, list)))
        return failed(message, L"Cannot write preload paths", GetLastError());
    if (!DuplicateHandle(GetCurrentProcess(), _loaded, _process, &_remoteLoaded, EVENT_MODIFY_STATE, FALSE, 0)
            || !DuplicateHandle(GetCurrentProcess(), _resume, _process, &_remoteResume, SYNCHRONIZE, FALSE, 0))
        return failed(message, L"Cannot share preload events", GetLastError());

    auto remote = static_cast<unsigned char*>(_remote);
    auto moveMemory = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlMoveMemory");
    ULONG_PTR profiler = 0;
    for (size_t i = 0; i < libraries.size(); ++i) {
        auto result = reinterpret_cast<LoadResult*>(remote) + i;
        auto path = remote + pathOffsets[i];
        auto error = queue(_thread, reinterpret_cast<void*>(&LoadLibraryExW), path, nullptr, reinterpret_cast<void*>(LOAD_WITH_ALTERED_SEARCH_PATH));
        if (!error) error = queue(_thread, reinterpret_cast<void*>(moveMemory), &result->error,
            static_cast<unsigned char*>(basic.teb) + TEB_LAST_ERROR, reinterpret_cast<void*>(sizeof(DWORD)));
        if (!error) error = queue(_thread, reinterpret_cast<void*>(&GetModuleHandleExW),
            reinterpret_cast<void*>(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT), path, &result->module);
        if (!error) error = queue(_thread, reinterpret_cast<void*>(&SetEvent), _remoteLoaded);
        if (!error) error = queue(_thread, reinterpret_cast<void*>(&WaitForSingleObject), _remoteResume, reinterpret_cast<void*>(INFINITE));
        if (error) {
            message = L"Cannot queue preloading of " + libraries[i];
            return error;
        }
        if (_running ? !SetEvent(_resume) : ResumeThread(_thread) == static_cast<DWORD>(-1))
            return failed(message, L"Cannot resume the process", GetLastError());
        _running = true;
        HANDLE waits[]{_loaded, _process};
        auto signaled = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (signaled == WAIT_OBJECT_0 + 1) {
            message = L"The process exited while loading " + libraries[i];
            return ERROR_PROCESS_ABORTED;
        }
        if (signaled != WAIT_OBJECT_0) return failed(message, L"Cannot wait for preloading", GetLastError());
        LoadResult outcome;
        if (!readRemote(_process, reinterpret_cast<ULONG_PTR>(result), &outcome)) return failed(message, L"Cannot read the preload result", GetLastError());
        if (!outcome.module) {
            message = L"Cannot load " + libraries[i];
            return outcome.error;
        }
        ULONG_PTR module = reinterpret_cast<ULONG_PTR>(outcome.module), entry;
        if (auto failure = startEntry(_process, module, entry)) {
            message = L"Cannot read the exports of " + libraries[i];
            return failure;
        }
        if (entry && profiler && profiler != module)
            return failed(message, L"More than one preload DLL exports asprof_preload_start", ERROR_INVALID_PARAMETER);
        if (entry) {
            profiler = module;
            _start = entry;
        }
    }
    return ERROR_SUCCESS;
}

void Injector::release(bool start, bool suspended) {
    if (!_running) {
        // Nothing was queued: undo the setup the process has not seen.
        for (auto handle : {_remoteLoaded, _remoteResume}) {
            if (handle) DuplicateHandle(_process, handle, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
        }
        for (auto memory : {_remote, _libraries}) {
            if (memory) VirtualFreeEx(_process, memory, 0, MEM_RELEASE);
        }
        if (!suspended) ResumeThread(_thread);
        return;
    }
    // The parked thread closes its copies of the events and, with start, takes ownership of the library list.
    queue(_thread, reinterpret_cast<void*>(&CloseHandle), _remoteLoaded);
    queue(_thread, reinterpret_cast<void*>(&CloseHandle), _remoteResume);
    if (start && _start) queue(_thread, reinterpret_cast<void*>(_start), _libraries);
    else VirtualFreeEx(_process, _libraries, 0, MEM_RELEASE);
    VirtualFreeEx(_process, _remote, 0, MEM_RELEASE);
    if (suspended) SuspendThread(_thread);
    SetEvent(_resume);
}
}
