/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * The dlfcn subset used by upstream's native test programs, over the Windows loader.
 */

#ifndef _UPSTREAM_TESTS_DLFCN_H
#define _UPSTREAM_TESTS_DLFCN_H

#include <stdio.h>
#include <windows.h>

#define RTLD_LAZY 0
#define RTLD_NOW 0
#define RTLD_LOCAL 0
#define RTLD_GLOBAL 0

static inline void* dlopen(const char* path, int mode) {
    (void)mode;
    return (void*)LoadLibraryA(path);
}

static inline void* dlsym(void* lib, const char* name) {
    return (void*)GetProcAddress((HMODULE)lib, name);
}

static inline int dlclose(void* lib) {
    return FreeLibrary((HMODULE)lib) ? 0 : -1;
}

static inline char* dlerror(void) {
    static char message[64];
    DWORD error = GetLastError();
    if (error == 0) {
        return NULL;
    }
    SetLastError(0);
    snprintf(message, sizeof(message), "Windows loader error %lu", error);
    return message;
}

#endif // _UPSTREAM_TESTS_DLFCN_H
