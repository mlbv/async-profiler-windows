/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsNativeProbeTarget.h"
#include "windowsMappedImage.h"
#include "windowsProfiler.h"
#include "profiler.h"
#include "codeCache.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace WindowsProfiler::NativeProbe {
namespace {
struct File {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct Module {
    HMODULE value = nullptr;
    ~Module() { if (value) FreeLibrary(value); }
};
bool modulePath(HMODULE module, std::wstring& result) {
    std::wstring buffer(32768, L'\0');
    // The loader's saved path can name a replacement file after a mapped DLL
    // is renamed. Query the actual section backing path instead.
    auto size = GetMappedFileNameW(GetCurrentProcess(), module, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!size || size == buffer.size()) return false;
    buffer.resize(size);
    if (buffer.starts_with(L"\\Device\\")) buffer = L"\\\\?\\GLOBALROOT" + buffer;
    else if (buffer.starts_with(L"\\??\\")) buffer = L"\\\\?\\" + buffer.substr(4);
    File file{CreateFileW(buffer.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr)};
    if (file.value == INVALID_HANDLE_VALUE) return false;
    std::wstring canonical(32768, L'\0');
    size = GetFinalPathNameByHandleW(file.value, canonical.data(), static_cast<DWORD>(canonical.size()), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (!size || size >= canonical.size()) return false;
    canonical.resize(size); result = std::move(canonical); return true;
}
bool fileIdentity(const std::wstring& path, BY_HANDLE_FILE_INFORMATION& identity) {
    File file{CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr)};
    return file.value != INVALID_HANDLE_VALUE && GetFileInformationByHandle(file.value, &identity);
}
bool sameFile(const BY_HANDLE_FILE_INFORMATION& first, const BY_HANDLE_FILE_INFORMATION& second) {
    return first.dwVolumeSerialNumber == second.dwVolumeSerialNumber && first.nFileIndexHigh == second.nFileIndexHigh
        && first.nFileIndexLow == second.nFileIndexLow;
}
const char* loadedFile(const std::wstring& path, Module& selected) {
    BY_HANDLE_FILE_INFORMATION requested{};
    if (!fileIdentity(path, requested)) return "Cannot identify the requested software-probe file";
    auto snapshot = toolhelpSnapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return "Cannot enumerate loaded software-probe modules";
    File owned{snapshot};
    MODULEENTRY32W entry{sizeof(entry)};
    if (!Module32FirstW(snapshot, &entry)) return "Cannot enumerate loaded software-probe modules";
    do {
        Module candidate;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(entry.modBaseAddr), &candidate.value)) continue;
        std::wstring name;
        BY_HANDLE_FILE_INFORMATION actual{};
        if (!modulePath(candidate.value, name) || !fileIdentity(name, actual) || !sameFile(requested, actual)) continue;
        if (selected.value && selected.value != candidate.value) return "Software-probe file has multiple loaded image mappings";
        if (!selected.value) { selected.value = candidate.value; candidate.value = nullptr; }
    } while (Module32NextW(snapshot, &entry));
    return selected.value ? nullptr : "Software-probe file must already be loaded in this process";
}
bool read(const void* source, void* output, size_t size) {
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), source, output, size, &copied) && copied == size;
}
const char* loadedHeaders(HMODULE module, IMAGE_DOS_HEADER& dos, IMAGE_NT_HEADERS64& pe) {
    if (!read(module, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0
            || !read(reinterpret_cast<const unsigned char*>(module) + dos.e_lfanew, &pe, sizeof(pe))
            || pe.Signature != IMAGE_NT_SIGNATURE || pe.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
            || pe.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || !pe.OptionalHeader.SizeOfImage)
        return "Loaded software-probe target is not a readable x86-64 PE image";
    return nullptr;
}
const char* protectTarget(const void* address, HMODULE module, ULONG imageSize, size_t& readable) {
    auto value = reinterpret_cast<std::uintptr_t>(address), base = reinterpret_cast<std::uintptr_t>(module);
    if (value < base || value - base >= imageSize) return "Software-probe offset leaves the selected loaded image";
    MEMORY_BASIC_INFORMATION page{};
    if (!VirtualQuery(address, &page, sizeof(page)) || page.State != MEM_COMMIT || page.AllocationBase != module
            || (page.Protect & (PAGE_GUARD | PAGE_NOACCESS))
            || !(page.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return "Software-probe target is not accessible executable image memory";
    if (module == selfModule()) return "Cannot instrument profiler implementation code";
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    for (auto name : {"NtContinue", "ZwContinue", "RtlRestoreContext", "KiUserExceptionDispatcher", "RtlDispatchException", "RtlRaiseException", "RtlRaiseStatus"}) {
        auto entry = reinterpret_cast<DWORD64>(GetProcAddress(ntdll, name));
        if (!entry) continue;
        DWORD64 owner = 0;
        auto function = RtlLookupFunctionEntry(entry, &owner, nullptr);
        if (value == entry || (function && value >= owner + function->BeginAddress && value < owner + function->EndAddress))
            return "Cannot instrument Windows exception-dispatch machinery";
    }
    readable = static_cast<size_t>(std::min<std::uintptr_t>(imageSize - (value - base),
        page.RegionSize - (value - reinterpret_cast<std::uintptr_t>(page.BaseAddress))));
    return nullptr;
}
}

LoadedTarget::LoadedTarget(LoadedTarget&& other) noexcept { *this = std::move(other); }
LoadedTarget& LoadedTarget::operator=(LoadedTarget&& other) noexcept {
    if (this == &other) return *this;
    if (_module) FreeLibrary(_module);
    _module = std::exchange(other._module, nullptr);
    address = other.address; imageBase = other.imageBase; imageSize = other.imageSize; rva = other.rva;
    cache = other.cache; mappingEpoch = other.mappingEpoch; readable = other.readable; path = std::move(other.path);
    return *this;
}
LoadedTarget::~LoadedTarget() { if (_module) FreeLibrary(_module); }
HMODULE LoadedTarget::releaseModule() { return std::exchange(_module, nullptr); }
void LoadedTarget::adoptModule(HMODULE module) { if (_module) FreeLibrary(_module); _module = module; }
bool LoadedTarget::currentMapping() const { return cache && mappingEpoch && cache->windowsLoadEpoch() == mappingEpoch; }

const char* resolveSoftware(const SoftwareSpec& spec, LoadedTarget& result) {
    SymbolResolutionScope resolution;
    Module selected;
    const void* symbol = nullptr;
    if (spec.kind == TargetKind::FileOffset) {
        if (spec.offset < 0) return "A PE file offset must not be negative";
        if (auto error = loadedFile(wide(spec.target), selected)) return error;
    } else {
        symbol = resolveLoadedSymbol(spec.target.c_str());
        if (!symbol) return "Software-probe symbol is unavailable or ambiguous in already loaded modules";
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(symbol), &selected.value))
            return "Cannot retain the loaded software-probe module";
    }
    LoadedTarget target;
    target.adoptModule(std::exchange(selected.value, nullptr));
    if (!modulePath(target.module(), target.path)) return "Cannot identify the loaded software-probe module path";
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS64 pe{};
    if (auto error = loadedHeaders(target.module(), dos, pe)) return error;
    target.imageBase = reinterpret_cast<std::uintptr_t>(target.module()); target.imageSize = pe.OptionalHeader.SizeOfImage;
    MappedImage image;
    auto status = image.open(target.path, {target.imageSize, pe.OptionalHeader.CheckSum, pe.FileHeader.TimeDateStamp}, ImageIdentityPolicy::User);
    if (status) return "Software-probe backing file does not match the loaded PE identity or layout";
    auto fileHeaders = image.headers();
    if (pe.FileHeader.NumberOfSections != fileHeaders->FileHeader.NumberOfSections
            || pe.FileHeader.SizeOfOptionalHeader != fileHeaders->FileHeader.SizeOfOptionalHeader
            || pe.OptionalHeader.SizeOfHeaders != fileHeaders->OptionalHeader.SizeOfHeaders)
        return "Loaded and file PE section layouts differ";
    auto offset = static_cast<std::uint64_t>(dos.e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + pe.FileHeader.SizeOfOptionalHeader;
    auto sections = image.sections();
    std::vector<IMAGE_SECTION_HEADER> actual(sections.size());
    if (offset > target.imageSize || actual.size() * sizeof(IMAGE_SECTION_HEADER) > target.imageSize - offset
            || !read(reinterpret_cast<const unsigned char*>(target.imageBase) + offset, actual.data(), actual.size() * sizeof(IMAGE_SECTION_HEADER))
            || std::memcmp(actual.data(), sections.data(), actual.size() * sizeof(IMAGE_SECTION_HEADER)))
        return "Loaded and file PE section identities differ";
    size_t sectionRemaining = 0;
    if (spec.kind == TargetKind::FileOffset) {
        if (auto error = image.executableFileOffset(static_cast<std::uint64_t>(spec.offset), target.rva, sectionRemaining)) return error;
    } else {
        auto address = reinterpret_cast<std::uintptr_t>(symbol);
        if (spec.offset >= 0) {
            if (address > std::numeric_limits<std::uintptr_t>::max() - static_cast<std::uint64_t>(spec.offset)) return "Software-probe symbol offset overflows";
            address += static_cast<std::uint64_t>(spec.offset);
        } else {
            auto magnitude = static_cast<std::uint64_t>(-(spec.offset + 1)) + 1;
            if (address < magnitude) return "Software-probe symbol offset underflows";
            address -= magnitude;
        }
        if (address < target.imageBase || address - target.imageBase >= target.imageSize) return "Software-probe offset leaves the selected image";
        target.rva = static_cast<ULONG>(address - target.imageBase);
        for (const auto& section : sections) {
            auto size = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) && target.rva >= section.VirtualAddress && target.rva - section.VirtualAddress < size)
                sectionRemaining = size - (target.rva - section.VirtualAddress);
        }
        if (!sectionRemaining) return "Software-probe symbol is outside executable PE section data";
    }
    target.address = reinterpret_cast<const unsigned char*>(target.imageBase) + target.rva;
    if (auto error = protectTarget(target.address, target.module(), target.imageSize, target.readable)) return error;
    target.readable = std::min(target.readable, sectionRemaining);
    Profiler::instance()->updateSymbols(false);
    target.cache = Profiler::instance()->findLibraryByAddress(target.address);
    target.mappingEpoch = target.cache ? target.cache->windowsLoadEpoch() : 0;
    if (!moduleTrackingAvailable() || !target.currentMapping()) return "Software-probe module lifetime tracking is unavailable";
    result = std::move(target);
    return nullptr;
}
}
