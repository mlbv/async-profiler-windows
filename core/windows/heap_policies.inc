/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Shared instrumentation CRT state is distinct from an allocator's private CRT.
using Errno = int* (*)();
struct AllocatorOwner {
    std::atomic<void*> base{nullptr};
    std::atomic<std::uint64_t> epoch{0};
};
std::array<AllocatorOwner, 128> allocator_owners{};
std::atomic<unsigned> allocator_owner_count{0};
std::atomic<std::uint64_t> allocator_next_epoch{1};
struct AllocatorErrno {
    std::atomic<void*> address{nullptr};
    std::atomic<Errno> getter{nullptr};
    std::atomic<std::uint64_t> epoch{0};
};
std::array<AllocatorErrno, 128> runtime_errno{};
std::atomic<unsigned> runtime_errno_count{0};
std::array<Errno, 8> instrumentation_errno{};
unsigned instrumentation_errno_count = 0;
std::array<HMODULE, 64> instrumentation_modules{};
unsigned instrumentation_module_count = 0;
bool instrumentation_checked = false;

inline bool executable_code(void* address) {
    MEMORY_BASIC_INFORMATION page{};
    return VirtualQuery(address, &page, sizeof(page)) && page.State == MEM_COMMIT && page.Type == MEM_IMAGE
            && !(page.Protect & (PAGE_GUARD | PAGE_NOACCESS))
            && (page.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}

inline void retain_code(void* address, ModuleReference& module) {
    require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            reinterpret_cast<LPCWSTR>(address), &module.value) != 0, "Cannot retain an allocator implementation");
    require(executable_code(address), "Allocator target is not executable image code");
}

inline bool crt_module(HMODULE module) {
    wchar_t path[32768];
    auto length = GetModuleFileNameW(module, path, static_cast<DWORD>(std::size(path)));
    require(length && length < std::size(path), "Cannot identify allocator runtime");
    auto name = wcsrchr(path, L'\\'); name = name ? name + 1 : path;
    return _wcsnicmp(name, L"ucrtbase", 8) == 0 || _wcsnicmp(name, L"msvcr", 5) == 0;
}

inline void remember_instrumentation_errno(Errno getter) {
    require(getter != nullptr, "Instrumentation CRT has no errno accessor");
    for (unsigned i = 0; i < instrumentation_errno_count; ++i) if (instrumentation_errno[i] == getter) return;
    require(instrumentation_errno_count < instrumentation_errno.size(), "Too many instrumentation CRT errno accessors");
    ModuleReference owner;
    retain_code(reinterpret_cast<void*>(getter), owner);
    require(crt_module(owner.value), "Instrumentation errno accessor has an unknown runtime owner");
    instrumentation_errno[instrumentation_errno_count++] = getter;
}

void inspect_instrumentation(HMODULE module, bool inspect_dbghelp) {
    bool dbghelp_checked = false;
    patch_module(module, [&](std::string_view library, std::string_view name, void* original) -> void* {
        if (!executable_code(original)) return nullptr;
        ModuleReference owner;
        retain_code(original, owner);
        bool known = false;
        for (unsigned i = 0; i < instrumentation_module_count; ++i) known |= instrumentation_modules[i] == owner.value;
        if (!known) {
            require(instrumentation_module_count < instrumentation_modules.size(), "Too many instrumentation dependencies");
            instrumentation_modules[instrumentation_module_count++] = owner.value;
        }
        if (crt_library(library) && crt_module(owner.value)) {
            auto getter = reinterpret_cast<Errno>(GetProcAddress(owner.value, name.starts_with("_o_") ? "_o__errno" : "_errno"));
            remember_instrumentation_errno(getter);
        }
        if (inspect_dbghelp && !dbghelp_checked && _stricmp(library.data(), "dbghelp.dll") == 0) {
            dbghelp_checked = true;
            inspect_instrumentation(owner.value, false);
        }
        return nullptr;
    });
}

bool AllocatorHookLifetime::current(std::uint64_t epoch) {
    if (!epoch) return false;
    for (unsigned i = 0, count = allocator_owner_count.load(std::memory_order_acquire); i < count; ++i) {
        if (allocator_owners[i].epoch.load(std::memory_order_acquire) == epoch) return true;
    }
    return false;
}

std::uint64_t AllocatorHookLifetime::acquire(void* address) {
    require(WindowsProfiler::moduleTrackingAvailable(), "Allocator module lifetime tracking is unavailable");
    if (!instrumentation_checked) {
        remember_instrumentation_errno(&::_errno);
        inspect_instrumentation(WindowsProfiler::selfModule(), true);
        instrumentation_checked = true;
    }
    ModuleReference module;
    retain_code(address, module);
    std::uint64_t epoch = 0;
    auto owners = allocator_owner_count.load(std::memory_order_acquire);
    unsigned owner_index = owners;
    for (unsigned i = 0; i < owners; ++i) {
        auto current_epoch = allocator_owners[i].epoch.load(std::memory_order_acquire);
        if (current_epoch && allocator_owners[i].base.load(std::memory_order_acquire) == module.value) { epoch = current_epoch; break; }
        if (!current_epoch && owner_index == owners) owner_index = i;
    }
    if (!epoch) {
        require(owner_index < allocator_owners.size(), "Too many live allocator provider modules");
        epoch = allocator_next_epoch.fetch_add(1, std::memory_order_relaxed);
        require(epoch != 0, "Allocator module epoch overflow");
        allocator_owners[owner_index].base.store(module.value, std::memory_order_release);
        allocator_owners[owner_index].epoch.store(epoch, std::memory_order_release);
        if (owner_index == owners) allocator_owner_count.store(owners + 1, std::memory_order_release);
    }
    auto getter = reinterpret_cast<Errno>(GetProcAddress(module.value, "_errno"));
    ModuleReference getter_owner;
    if (getter) retain_code(reinterpret_cast<void*>(getter), getter_owner);
    if (!getter) {
        for (unsigned i = 0; i < instrumentation_module_count; ++i) {
            require(instrumentation_modules[i] != module.value, "Allocator used by instrumentation has no public errno accessor");
        }
    }
    auto count = runtime_errno_count.load(std::memory_order_acquire);
    unsigned index = count;
    for (unsigned i = 0; i < count; ++i) {
        if (runtime_errno[i].address.load(std::memory_order_acquire) == address) {
            if (runtime_errno[i].epoch.load(std::memory_order_acquire) == epoch) return epoch;
            index = i;
            break;
        }
        if (index == count && !current(runtime_errno[i].epoch.load(std::memory_order_acquire))) index = i;
    }
    require(index < runtime_errno.size(), "Too many live allocator targets");
    runtime_errno[index].address.store(nullptr, std::memory_order_release);
    runtime_errno[index].getter.store(getter, std::memory_order_release);
    runtime_errno[index].epoch.store(epoch, std::memory_order_release);
    runtime_errno[index].address.store(address, std::memory_order_release);
    if (index == count) runtime_errno_count.store(count + 1, std::memory_order_release);
    return epoch;
}

inline Errno saved_errno(void* function) {
    for (unsigned i = 0, count = runtime_errno_count.load(std::memory_order_acquire); i < count; ++i) {
        if (runtime_errno[i].address.load(std::memory_order_acquire) == function) return runtime_errno[i].getter.load(std::memory_order_acquire);
    }
    return nullptr;
}

struct AllocationErrors {
    DWORD windows;
    std::array<std::pair<int*, int>, 9> slots{};
    unsigned count = 0;
    void remember(Errno getter) {
        auto location = getter();
        for (unsigned i = 0; i < count; ++i) if (slots[i].first == location) return;
        slots[count++] = {location, *location};
    }
    explicit AllocationErrors(void* function) : windows(GetLastError()) {
        for (unsigned i = 0; i < instrumentation_errno_count; ++i) remember(instrumentation_errno[i]);
        if (auto provider = saved_errno(function)) remember(provider);
    }
    ~AllocationErrors() {
        for (unsigned i = 0; i < count; ++i) *slots[i].first = slots[i].second;
        SetLastError(windows);
    }
};

template<class Function, class Address, class... A>
auto allocation_request(Function original, std::size_t size, Address address, A... arguments) {
    if (!MallocTracer::running()) return original(arguments...);
    HeapReader session;
    Depth depth(allocation_depth);
    auto result = original(arguments...);
    AllocationErrors errors(reinterpret_cast<void*>(original));
    if (depth.outer && session.active) MallocTracer::recordMalloc(address(result), size);
    return result;
}
struct MallocPolicy {
    template<class... A> static void* invoke(void* (*original)(std::size_t, A...), std::size_t size, A... arguments) {
        return allocation_request(original, size, [](void* result) { return result; }, size, arguments...);
    }
};
struct CallocPolicy {
    template<class... A> static void* invoke(void* (*original)(std::size_t, std::size_t, A...), std::size_t count, std::size_t size, A... arguments) {
        auto requested = count && size <= SIZE_MAX / count ? count * size : 0;
        return allocation_request(original, requested, [](void* result) { return result; }, count, size, arguments...);
    }
};
struct AlignedAllocPolicy {
    static void* invoke(void* (*original)(std::size_t, std::size_t), std::size_t alignment, std::size_t size) {
        return allocation_request(original, size, [](void* result) { return result; }, alignment, size);
    }
};
struct PosixMemalignPolicy {
    static int invoke(int (*original)(void**, std::size_t, std::size_t), void** output, std::size_t alignment, std::size_t size) {
        return allocation_request(original, size, [output](int result) -> void* { return result == 0 ? *output : nullptr; }, output, alignment, size);
    }
};
template<bool FreesOnZero> struct ResizePolicy {
    template<class... A> static void* invoke(void* (*original)(void*, std::size_t, A...), void* address, std::size_t size, A... arguments) {
        if (!MallocTracer::running()) return original(address, size, arguments...);
        HeapReader session;
        Depth depth(allocation_depth);
        auto result = original(address, size, arguments...);
        AllocationErrors errors(reinterpret_cast<void*>(original));
        // realloc(input, 0) frees its input even when it returns null.
        // _expand never frees on failure, including a failed zero resize.
        if (depth.outer && session.active && (result || (FreesOnZero && size == 0))) {
            MallocTracer::recordFree(address);
            MallocTracer::recordMalloc(result, size);
        }
        return result;
    }
};
using ReallocPolicy = ResizePolicy<true>;
using ExpandPolicy = ResizePolicy<false>;
struct RecallocPolicy {
    template<class... A> static void* invoke(void* (*original)(void*, std::size_t, std::size_t, A...),
            void* address, std::size_t count, std::size_t size, A... arguments) {
        if (!MallocTracer::running()) return original(address, count, size, arguments...);
        HeapReader session;
        Depth depth(allocation_depth);
        auto result = original(address, count, size, arguments...);
        AllocationErrors errors(reinterpret_cast<void*>(original));
        if (depth.outer && session.active && (!count || size <= SIZE_MAX / count)) {
            auto total = count * size;
            if (result || total == 0) { MallocTracer::recordFree(address); MallocTracer::recordMalloc(result, total); }
        }
        return result;
    }
};
struct FreePolicy {
    template<class... A> static void invoke(void (*original)(void*, A...), void* address, A... arguments) {
        if (!address || !MallocTracer::running()) { original(address, arguments...); return; }
        HeapReader session;
        Depth depth(allocation_depth);
        // Publish the lifetime end before another thread can reuse the address.
        {
            AllocationErrors errors(reinterpret_cast<void*>(original));
            if (depth.outer && session.active) MallocTracer::recordFree(address);
        }
        original(address, arguments...);
    }
};
template<class Policy, class Function> using AllocatorFunctionHooks = FunctionHooks<Policy, Function, AllocatorHookLifetime>;
using MallocHooks = AllocatorFunctionHooks<MallocPolicy, void* (*)(std::size_t)>;
using AlignedAllocHooks = AllocatorFunctionHooks<AlignedAllocPolicy, void* (*)(std::size_t, std::size_t)>;
using PosixMemalignHooks = AllocatorFunctionHooks<PosixMemalignPolicy, int (*)(void**, std::size_t, std::size_t)>;
using CallocHooks = AllocatorFunctionHooks<CallocPolicy, void* (*)(std::size_t, std::size_t)>;
using ReallocHooks = AllocatorFunctionHooks<ReallocPolicy, void* (*)(void*, std::size_t)>;
using FreeHooks = AllocatorFunctionHooks<FreePolicy, void (*)(void*)>;
using AlignedMallocHooks = AllocatorFunctionHooks<MallocPolicy, void* (*)(std::size_t, std::size_t)>;
using AlignedOffsetMallocHooks = AllocatorFunctionHooks<MallocPolicy, void* (*)(std::size_t, std::size_t, std::size_t)>;
using AlignedReallocHooks = AllocatorFunctionHooks<ReallocPolicy, void* (*)(void*, std::size_t, std::size_t)>;
using AlignedOffsetReallocHooks = AllocatorFunctionHooks<ReallocPolicy, void* (*)(void*, std::size_t, std::size_t, std::size_t)>;
using RecallocHooks = AllocatorFunctionHooks<RecallocPolicy, void* (*)(void*, std::size_t, std::size_t)>;
using AlignedRecallocHooks = AllocatorFunctionHooks<RecallocPolicy, void* (*)(void*, std::size_t, std::size_t, std::size_t)>;
using AlignedOffsetRecallocHooks = AllocatorFunctionHooks<RecallocPolicy, void* (*)(void*, std::size_t, std::size_t, std::size_t, std::size_t)>;
using ExpandHooks = AllocatorFunctionHooks<ExpandPolicy, void* (*)(void*, std::size_t)>;
using DebugMallocHooks = AllocatorFunctionHooks<MallocPolicy, void* (*)(std::size_t, int, const char*, int)>;
using DebugCallocHooks = AllocatorFunctionHooks<CallocPolicy, void* (*)(std::size_t, std::size_t, int, const char*, int)>;
using DebugReallocHooks = AllocatorFunctionHooks<ReallocPolicy, void* (*)(void*, std::size_t, int, const char*, int)>;
using DebugRecallocHooks = AllocatorFunctionHooks<RecallocPolicy, void* (*)(void*, std::size_t, std::size_t, int, const char*, int)>;
using DebugFreeHooks = AllocatorFunctionHooks<FreePolicy, void (*)(void*, int)>;
using DebugAlignedMallocHooks = AllocatorFunctionHooks<MallocPolicy, void* (*)(std::size_t, std::size_t, const char*, int)>;
using DebugAlignedOffsetMallocHooks = AllocatorFunctionHooks<MallocPolicy, void* (*)(std::size_t, std::size_t, std::size_t, const char*, int)>;
using DebugAlignedReallocHooks = AllocatorFunctionHooks<ReallocPolicy, void* (*)(void*, std::size_t, std::size_t, const char*, int)>;
using DebugAlignedOffsetReallocHooks = AllocatorFunctionHooks<ReallocPolicy, void* (*)(void*, std::size_t, std::size_t, std::size_t, const char*, int)>;
using DebugAlignedRecallocHooks = AllocatorFunctionHooks<RecallocPolicy, void* (*)(void*, std::size_t, std::size_t, std::size_t, const char*, int)>;
using DebugAlignedOffsetRecallocHooks = AllocatorFunctionHooks<RecallocPolicy, void* (*)(void*, std::size_t, std::size_t, std::size_t, std::size_t, const char*, int)>;
using DebugExpandHooks = AllocatorFunctionHooks<ExpandPolicy, void* (*)(void*, std::size_t, int, const char*, int)>;

template<class Family> void* memory_replacement(void* original, bool create) {
    if (auto known = Family::existing(original)) return known;
    if (!create || !memoryHooksEnabled.load(std::memory_order_acquire)) return nullptr;
    return Family::replacement(original);
}
