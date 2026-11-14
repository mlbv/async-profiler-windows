/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Derived from upstream test/native/libs/malloc.c; modified for Windows x86-64.
 */

// Windows variant of malloc.c. Imports bind per module, so rather than interposing the malloc symbol for
// the process, the DLL replaces the executable's malloc import when it is loaded.

#include <string.h>
#include <windows.h>

typedef void* (*malloc_t)(size_t);
static malloc_t _orig_malloc = NULL;

static void* interposed_malloc(size_t size) {
    void* ptr = _orig_malloc(size);
    memset(ptr, 0xff, size);
    return ptr;
}

static BOOL interpose_executable(void) {
    unsigned char* base = (unsigned char*)GetModuleHandleW(NULL);
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + ((IMAGE_DOS_HEADER*)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    for (IMAGE_IMPORT_DESCRIPTOR* module = (IMAGE_IMPORT_DESCRIPTOR*)(base + imports.VirtualAddress); module->Name; module++) {
        IMAGE_THUNK_DATA64* names = (IMAGE_THUNK_DATA64*)(base + module->OriginalFirstThunk);
        void** slots = (void**)(base + module->FirstThunk);
        for (size_t i = 0; names[i].u1.AddressOfData; i++) {
            if (IMAGE_SNAP_BY_ORDINAL64(names[i].u1.Ordinal)
                    || strcmp((const char*)((IMAGE_IMPORT_BY_NAME*)(base + names[i].u1.AddressOfData))->Name, "malloc") != 0) {
                continue;
            }
            DWORD protection;
            if (!VirtualProtect(slots + i, sizeof(void*), PAGE_READWRITE, &protection)) {
                return FALSE;
            }
            _orig_malloc = (malloc_t)slots[i];
            slots[i] = (void*)interposed_malloc;
            return VirtualProtect(slots + i, sizeof(void*), protection, &protection);
        }
    }
    return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    return reason != DLL_PROCESS_ATTACH || interpose_executable();
}
