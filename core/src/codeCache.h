/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _CODECACHE_H
#define _CODECACHE_H

#include <jvmti.h>
#include <atomic>
#include <vector>
#include "arch.h"


#define NO_MIN_ADDRESS  ((const void*)-1)
#define NO_MAX_ADDRESS  ((const void*)0)

const int INITIAL_CODE_CACHE_CAPACITY = 1000;
const int MAX_NATIVE_LIBS = 2048;


enum ImportId {
    im_dlopen,
    im_pthread_create,
    im_pthread_exit,
    im_pthread_mutex_lock,
    im_pthread_rwlock_rdlock,
    im_pthread_rwlock_wrlock,
    im_pthread_setspecific,
    im_poll,
    im_malloc,
    im_calloc,
    im_realloc,
    im_free,
    im_posix_memalign,
    im_aligned_alloc,
    NUM_IMPORTS
};

enum ImportType {
    PRIMARY,
    SECONDARY,
    NUM_IMPORT_TYPES
};

enum Mark {
    MARK_VM_RUNTIME = 1,
    MARK_INTERPRETER = 2,
    MARK_COMPILER_ENTRY = 3,
    MARK_ASYNC_PROFILER = 4, // async-profiler internals such as native hooks.
};


class NativeFunc {
  private:
    short _lib_index;
    char _mark;
    char _reserved;
    char _name[0];

    static NativeFunc* from(const char* name) {
        return (NativeFunc*)(name - sizeof(NativeFunc));
    }

  public:
    static char* create(const char* name, short lib_index);
    static void destroy(char* name);

    static size_t usedMemory(const char* name);

    static short libIndex(const char* name) {
        return from(name)->_lib_index;
    }

    static char mark(const char* name) {
        return from(name)->_mark;
    }

    static void mark(const char* name, char value) {
        from(name)->_mark = value;
    }
};


class CodeBlob {
  public:
    const void* _start;
    const void* _end;
    char* _name;

    static int comparator(const void* c1, const void* c2) {
        CodeBlob* cb1 = (CodeBlob*)c1;
        CodeBlob* cb2 = (CodeBlob*)c2;
        if (cb1->_start < cb2->_start) {
            return -1;
        } else if (cb1->_start > cb2->_start) {
            return 1;
        } else if (cb1->_end == cb2->_end) {
            return 0;
        } else {
            return cb1->_end > cb2->_end ? -1 : 1;
        }
    }
};


class FrameDesc;

class CodeCache {
  private:
    char* _name;
    short _lib_index;
    const void* _min_address;
    const void* _max_address;
    const char* _text_base;
    const char* _image_base;
    std::atomic<bool> _active{true};
#ifdef _WIN32
    u64 _image_signature = 0;
    void* _windows_unwind_table = NULL;
    u32 _windows_unwind_count = 0;
    static std::atomic<u64> _next_windows_load_epoch;
    std::atomic<u64> _windows_load_epoch{0};
#endif

    unsigned int _plt_offset;
    unsigned int _plt_size;

    void** _imports[NUM_IMPORTS][NUM_IMPORT_TYPES];
    bool _imports_patchable;
    bool _debug_symbols;

    FrameDesc* _dwarf_table;
    int _dwarf_table_length;

    int _capacity;
    int _count;
    CodeBlob* _blobs;

    void expand();
    bool makeImportsPatchable();
    void saveImport(ImportId id, void** entry);

  public:
    CodeCache(const char* name,
              short lib_index = -1,
              const void* min_address = NO_MIN_ADDRESS,
              const void* max_address = NO_MAX_ADDRESS,
              const char* image_base = NULL);

    ~CodeCache();

    const char* name() const {
        return _name;
    }

    const void* minAddress() const {
        return _min_address;
    }

    const void* maxAddress() const {
        return _max_address;
    }

    const char* imageBase() const {
        return _image_base;
    }

    bool active() const { return _active.load(std::memory_order_acquire); }
#ifdef _WIN32
    void setActive(bool active);
    u64 windowsLoadEpoch() const {
        auto epoch = _windows_load_epoch.load(std::memory_order_acquire);
        return epoch && active() && epoch == _windows_load_epoch.load(std::memory_order_acquire) ? epoch : 0;
    }
#else
    void setActive(bool active) { _active.store(active, std::memory_order_release); }
#endif
#ifdef _WIN32
    u64 imageSignature() const { return _image_signature; }
    void setImageSignature(u64 signature) { _image_signature = signature; }
    bool setWindowsUnwindTable(const void* table, u32 count);
    void* findWindowsUnwindEntry(uintptr_t pc) const;
#endif

    bool contains(const void* address) const {
        return active() && address >= _min_address && address < _max_address;
    }

    void setTextBase(const char* text_base) {
        _text_base = text_base;
    }

    void setPlt(unsigned int plt_offset, unsigned int plt_size) {
        _plt_offset = plt_offset;
        _plt_size = plt_size;
    }

    bool hasDebugSymbols() const {
        return _debug_symbols;
    }

    void setDebugSymbols(bool debug_symbols) {
        _debug_symbols = debug_symbols;
    }

    bool hasDwarfTable() const {
        return _dwarf_table != NULL;
    }

    void add(const void* start, int length, const char* name, bool update_bounds = false);
    void updateBounds(const void* start, const void* end);
    void sort();

    template <typename NamePredicate>
    inline void mark(NamePredicate predicate, char value) {
        for (int i = 0; i < _count; i++) {
            const char* blob_name = _blobs[i]._name;
            if (blob_name != NULL && predicate(blob_name)) {
                NativeFunc::mark(blob_name, value);
            }
        }

        if (value == MARK_VM_RUNTIME && _name != NULL) {
            // In case a library has no debug symbols
            NativeFunc::mark(_name, value);
        }
    }

    void addImport(void** entry, const char* name);
    void** findImport(ImportId id);
    void patchImport(ImportId id, void* hook_func);

    CodeBlob* findBlob(const char* name);
    CodeBlob* findBlobByAddress(const void* address);
#ifdef _WIN32
    void snapshot(std::vector<CodeBlob>& result) const { result.assign(_blobs, _blobs + _count); }
#endif
    const char* binarySearch(const void* address);
    const void* findSymbol(const char* name);
    const void* findSymbolByPrefix(const char* prefix);
    const void* findSymbolByPrefix(const char* prefix, int prefix_len);

    void setDwarfTable(FrameDesc* table, int length);
    FrameDesc* findFrameDesc(const void* pc);

    size_t usedMemory();

    friend class UnloadProtection;
};


class CodeCacheArray {
  private:
    CodeCache* _libs[MAX_NATIVE_LIBS];
    int _count;
    std::atomic<size_t> _used_memory;

  public:
    CodeCacheArray() : _count(0), _used_memory(0) {
    }

    CodeCache* operator[](int index) {
        return _libs[index];
    }

    int count() {
        return loadAcquire(_count);
    }

    size_t usedMemory() {
        return _used_memory.load(std::memory_order_relaxed);
    }

    void add(CodeCache* lib) {
        int index = loadAcquire(_count);
        _libs[index] = lib;
        _used_memory.fetch_add(lib->usedMemory(), std::memory_order_relaxed);
        storeRelease(_count, index + 1);
    }
};

#endif // _CODECACHE_H
