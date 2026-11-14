/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Preload DLL variants for asprof-helper --preload tests:
// PRELOAD_INTERPOSER fills the executable's malloc results with 0xff, standing in for upstream's
// symbol-interposing libmalloc; PRELOAD_CALLS_MALLOC is upstream's libcallsmalloc; PRELOAD_DEPENDENT
// depends on it; PRELOAD_FAIL rejects DLL_PROCESS_ATTACH.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdlib>
#include <cstring>

#if defined(PRELOAD_INTERPOSER)
using Malloc = void* (*)(size_t);
static Malloc original;

static void* interposedMalloc(size_t size) {
    void* memory = original(size);
    std::memset(memory, 0xff, size);
    return memory;
}

// Windows binds imports per module, so the interposer replaces the executable's own malloc slot.
static bool interposeExecutable() {
    auto base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (auto descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress); descriptor->Name; ++descriptor) {
        auto names = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + descriptor->OriginalFirstThunk);
        auto slots = reinterpret_cast<void**>(base + descriptor->FirstThunk);
        for (size_t i = 0; names[i].u1.AddressOfData; ++i) {
            if (IMAGE_SNAP_BY_ORDINAL64(names[i].u1.Ordinal)) continue;
            if (std::strcmp(reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names[i].u1.AddressOfData)->Name, "malloc") != 0) continue;
            DWORD protection;
            if (!VirtualProtect(slots + i, sizeof(void*), PAGE_READWRITE, &protection)) return false;
            original = reinterpret_cast<Malloc>(slots[i]);
            slots[i] = reinterpret_cast<void*>(interposedMalloc);
            return VirtualProtect(slots + i, sizeof(void*), protection, &protection) != 0;
        }
    }
    return false;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, void*) {
    return reason != DLL_PROCESS_ATTACH || interposeExecutable();
}
#elif defined(PRELOAD_CALLS_MALLOC)
extern "C" __declspec(dllexport) void* call_malloc(size_t size) {
    return malloc(size);
}
#elif defined(PRELOAD_DEPENDENT)
// Imports call_malloc from preload-calls-malloc.dll, which is found only beside this DLL.
extern "C" __declspec(dllimport) void* call_malloc(size_t size);
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, void*) {
    if (reason == DLL_PROCESS_ATTACH) free(call_malloc(1));
    return TRUE;
}
#elif defined(PRELOAD_FAIL)
BOOL WINAPI DllMain(HINSTANCE, DWORD reason, void*) {
    return reason != DLL_PROCESS_ATTACH;
}
#else
#error Select a preload library variant
#endif
