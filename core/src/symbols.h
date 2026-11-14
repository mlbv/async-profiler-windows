/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _SYMBOLS_H
#define _SYMBOLS_H

#include "codeCache.h"
#include "mutex.h"


class Symbols {
  private:
    static Mutex _parse_lock;
    static bool _have_kernel_symbols;
    static bool _libs_limit_reported;

  public:
    static void parseKernelSymbols(CodeCache* cc);
    static void parseLibraries(CodeCacheArray* array, bool kernel_symbols, bool essential_only = false);
#ifdef _WIN32
    struct NativeFunction {
        const char* name;
        // Return type followed by arguments. Named types use C++ pointer
        // suffixes, optional :size and | alternatives; builtins are void/uint64.
        const char* const* signature;
        unsigned count;
        const void* address = NULL;
    };
    // Requires an exact matching PDB and returns only unambiguous prototypes.
    static bool findNativeFunctions(CodeCache* cache, NativeFunction* functions, size_t count);
#endif

    static bool haveKernelSymbols() {
        return _have_kernel_symbols;
    }
};

class UnloadProtection {
  private:
    void* _lib_handle;
    bool _valid;

  public:
    UnloadProtection(const CodeCache *cc);
    ~UnloadProtection();

    UnloadProtection& operator=(const UnloadProtection& other) = delete;

    bool isValid() const { return _valid; }
};

#endif // _SYMBOLS_H
