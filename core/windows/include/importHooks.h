/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Named PE import interception. Every thunk retains its actual original target.
#pragma once
#include <tlhelp32.h>
#include <utility>
#include <atomic>
#include <array>
#include <cstdint>
#include <vector>
#include <mutex>
#include <string_view>
#include <stdexcept>
#include <cstring>
#include <cstdio>
#include "windowsProfiler.h"

extern "C" __declspec(dllimport) BOOLEAN NTAPI RtlDllShutdownInProgress();

namespace WindowsProfiler::Imports {
inline void require(bool valid, const char* message) { if (!valid) throw std::runtime_error(message); }

inline std::recursive_mutex import_mutex;
inline std::atomic<bool> import_failed{false};
inline std::atomic<unsigned> import_failure_ready{0};
inline char import_failure_message[384]{};
inline void failImport(const char* operation, const char* name, DWORD error = 0) {
    unsigned expected = 0;
    if (import_failure_ready.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) {
        std::snprintf(import_failure_message, sizeof(import_failure_message), "%s: %s (Windows error %lu)", operation, name, error);
        import_failure_ready.store(2, std::memory_order_release);
    }
    import_failed.store(true, std::memory_order_release);
}
void writeImportFailure(Writer& out);
inline std::atomic<unsigned> import_consumers{0};
inline std::atomic<bool> memoryHooksEnabled{false};
inline std::atomic<bool> lockHooksEnabled{false};
// Set in a preloaded process; also keeps newly loaded modules patched without profiling.
inline std::atomic<bool> processHooksEnabled{false};
void initializeImportRules();
void appendLockRules();
void appendExitRules();
void appendProcessRules();
inline thread_local unsigned allocation_depth;

struct Depth {
    unsigned& depth;
    bool outer;
    explicit Depth(unsigned& value) : depth(value), outer(value++ == 0) {}
    ~Depth() { --depth; }
};

struct WindowsError {
    DWORD saved = GetLastError();
    ~WindowsError() { SetLastError(saved); }
};

struct ModuleReference {
    HMODULE value = nullptr;
    ~ModuleReference() { if (value) FreeLibrary(value); }
};

struct ProcessHookLifetime {
    static constexpr bool tracked = false;
    static std::uint64_t acquire(void*) { return 1; }
    static bool current(std::uint64_t) { return true; }
};
struct AllocatorHookLifetime {
    static constexpr bool tracked = true;
    static std::uint64_t acquire(void* address);
    static bool current(std::uint64_t epoch);
};

template<class Policy, class Function, class Lifetime = ProcessHookLifetime> struct FunctionHooks;
template<class Policy, class Lifetime, class R, class... A> struct FunctionHooks<Policy, R (*)(A...), Lifetime> {
    using Function = R (*)(A...);
    static constexpr std::size_t capacity = 32;
    static inline std::array<std::atomic<Function>, capacity> originals{};
    static inline std::array<std::atomic<std::uint64_t>, capacity> epochs{};
    static inline std::atomic<std::size_t> count{0};

    template<std::size_t I> static R invoke(A... arguments) {
        // Other DLLs can call patched imports after our CRT destructors run.
        // Only the trivial original-target array remains safe during detach.
        auto original = originals[I].load(std::memory_order_acquire);
        if (RtlDllShutdownInProgress()) return original(arguments...);
        return Policy::invoke(original, arguments...);
    }
    template<std::size_t... I> static constexpr auto thunks(std::index_sequence<I...>) {
        return std::array<Function, capacity>{&invoke<I>...};
    }
    static inline constexpr auto replacements = thunks(std::make_index_sequence<capacity>{});

    static void* existing(void* address) {
        auto published = count.load(std::memory_order_acquire);
        for (std::size_t i = 0; i < published; ++i) {
            if constexpr (Lifetime::tracked) {
                if (!Lifetime::current(epochs[i].load(std::memory_order_acquire))) continue;
            }
            if (address == reinterpret_cast<void*>(replacements[i])) return address;
            if (address == reinterpret_cast<void*>(originals[i].load(std::memory_order_acquire))) return reinterpret_cast<void*>(replacements[i]);
        }
        return nullptr;
    }
    static void* replacement(void* address) {
        if (auto known = existing(address)) return known;
        auto index = count.load(std::memory_order_relaxed);
        if constexpr (Lifetime::tracked) {
            for (std::size_t i = 0; i < index; ++i) if (!Lifetime::current(epochs[i].load(std::memory_order_acquire))) { index = i; break; }
        }
        require(index < capacity, "Too many live targets for one imported function");
        auto epoch = Lifetime::acquire(address);
        originals[index].store(reinterpret_cast<Function>(address), std::memory_order_release);
        epochs[index].store(epoch, std::memory_order_release);
        if (index == count.load(std::memory_order_relaxed)) count.store(index + 1, std::memory_order_release);
        return reinterpret_cast<void*>(replacements[index]);
    }
};

inline bool crt_library(std::string_view name) {
    return _strnicmp(name.data(), "api-ms-win-crt-", 14) == 0 || _strnicmp(name.data(), "msvcr", 5) == 0
            || _strnicmp(name.data(), "ucrtbase", 8) == 0;
}

inline bool allocator_library(std::string_view) { return true; }

inline bool windows_library(std::string_view name) {
    return _stricmp(name.data(), "kernel32.dll") == 0 || _stricmp(name.data(), "kernelbase.dll") == 0
            || _stricmp(name.data(), "ntdll.dll") == 0 || _strnicmp(name.data(), "api-ms-win-core-", 16) == 0;
}

struct ImportRule {
    std::string_view name;
    bool (*library)(std::string_view);
    void* (*resolve)(void*, bool);
    const std::atomic<bool>* enabled = nullptr;
    // Importing modules whose slots stay unpatched; dynamic lookups have no importer and are not exempt.
    bool (*exempt)(HMODULE) = nullptr;
    bool active() const { return enabled == nullptr || enabled->load(std::memory_order_acquire); }
};
inline std::vector<ImportRule> import_rules;

template<class Family> void* import_replacement(void* original, bool create) {
    if (auto known = Family::existing(original)) return known;
    return create ? Family::replacement(original) : nullptr;
}

inline const ImportRule* import_rule(std::string_view library, std::string_view name) {
    for (const auto& rule : import_rules) if (rule.active() && name == rule.name && rule.library(library)) return &rule;
    return nullptr;
}

// Returns true only for a changed slot. Resolved targets are published atomically.
inline bool patch_import(void** slot, void* replacement) {
    if (*slot == replacement) return false;
    DWORD protection;
    require(VirtualProtect(slot, sizeof(*slot), PAGE_READWRITE, &protection) != 0, "Cannot make an import slot writable");
    InterlockedExchangePointer(slot, replacement);
    DWORD ignored;
    require(VirtualProtect(slot, sizeof(*slot), protection, &ignored) != 0, "Cannot restore import slot protection");
    return true;
}

template<class Resolve> unsigned patch_module(HMODULE handle, Resolve resolve) {
    auto base = reinterpret_cast<unsigned char*>(handle);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    auto pe = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (pe->Signature != IMAGE_NT_SIGNATURE || pe->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
    auto directory = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!directory.VirtualAddress) return 0;
    unsigned patched = 0;
    auto descriptors = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress);
    for (auto descriptor = descriptors; descriptor->Name; ++descriptor) {
        if (!descriptor->OriginalFirstThunk) continue; // Bound imports have no recoverable names.
        auto library = reinterpret_cast<const char*>(base + descriptor->Name);
        auto names = reinterpret_cast<const IMAGE_THUNK_DATA64*>(base + descriptor->OriginalFirstThunk);
        auto slots = reinterpret_cast<void**>(base + descriptor->FirstThunk);
        for (std::size_t i = 0; names[i].u1.AddressOfData; ++i) {
            if (IMAGE_SNAP_BY_ORDINAL64(names[i].u1.Ordinal)) continue;
            auto name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + names[i].u1.AddressOfData)->Name;
            if (auto replacement = resolve(library, name, slots[i])) patched += patch_import(slots + i, replacement);
        }
    }
    return patched;
}

template<class Resolve> unsigned patch_modules(Resolve resolve) {
    struct Snapshot {
        HANDLE handle;
        ~Snapshot() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
    } snapshot{WindowsProfiler::toolhelpSnapshot(TH32CS_SNAPMODULE, GetCurrentProcessId())};
    if (snapshot.handle == INVALID_HANDLE_VALUE) failImport("CreateToolhelp32Snapshot", "module import refresh", GetLastError());
    require(snapshot.handle != INVALID_HANDLE_VALUE, "Cannot enumerate loaded modules");
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    unsigned patched = 0;
    require(Module32FirstW(snapshot.handle, &entry) != 0, "Cannot read loaded modules");
    do {
        if (entry.hModule == WindowsProfiler::selfModule()) continue;
        // Take a temporary reference so a concurrent FreeLibrary cannot unmap the PE.
        ModuleReference retained;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                reinterpret_cast<LPCWSTR>(entry.modBaseAddr), &retained.value)) continue;
        patched += patch_module(retained.value, [&](std::string_view library, std::string_view name, void* original) {
            return resolve(retained.value, library, name, original);
        });
    } while (Module32NextW(snapshot.handle, &entry));
    return patched;
}

inline unsigned refresh_imports() {
    std::lock_guard guard(import_mutex);
    Depth depth(allocation_depth);
    return patch_modules([](HMODULE importer, std::string_view library, std::string_view name, void* original) -> void* {
        auto rule = import_rule(library, name);
        return rule && !(rule->exempt && rule->exempt(importer)) ? rule->resolve(original, true) : nullptr;
    });
}

}
