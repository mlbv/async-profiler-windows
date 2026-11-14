/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "windowsSoftwareSites.h"
#include "symbols.h"
#include "hooks.h"
#include "log.h"
#include "profiler.h"
#include "writer.h"
#include "windowsKernel.h"
#include <dbghelp.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <algorithm>
#include <atomic>
#include <string>
#include <cstdlib>
#include <limits>
#include <map>

Mutex Symbols::_parse_lock;
bool Symbols::_have_kernel_symbols = false;
bool Symbols::_libs_limit_reported = false;

namespace {
HANDLE symbolProcess;
bool symbolSession;
void* notificationCookie;
std::atomic<bool> notificationsReady{false};
std::atomic<std::uint64_t> moduleGeneration{1}, parsedGeneration{0};
std::atomic<bool> kernelRequested{false};
std::atomic<ULONG> kernelError{0};
std::atomic<unsigned> kernelMismatches{0};
// Kernel images that failed to open, by base and signature; guarded by Symbols::_parse_lock.
std::vector<std::pair<std::uintptr_t, std::uint64_t>> failedKernelImages;
std::atomic<unsigned> kernelWarningReady{0};
char kernelWarning[512]{};
std::atomic<std::uint64_t> pdbNameLengthCorrections{0};
thread_local bool parsingSymbols;
thread_local WindowsProfiler::SymbolResolutionScope* resolutionScope;
struct DllNotification {
    ULONG flags;
    const UNICODE_STRING* fullName;
    const UNICODE_STRING* baseName;
    void* base;
    ULONG size;
};
union DllNotificationData { DllNotification loaded, unloaded; };
using Notification = void (NTAPI*)(ULONG, const DllNotificationData*, void*);
using RegisterNotification = NTSTATUS (NTAPI*)(ULONG, Notification, void*, void**);

void NTAPI moduleChanged(ULONG reason, const DllNotificationData* data, void* parameter) {
    // Loader callbacks may not call other modules, allocate, or acquire locks.
    if (reason != 1 && reason != 2) return;
    if (reason == 2) WindowsProfiler::allocatorModuleUnloaded(data->unloaded.base);
    auto libraries = static_cast<CodeCacheArray*>(parameter);
    auto base = static_cast<const char*>(data->loaded.base);
    for (int i = 0, count = libraries->count(); i < count; ++i) {
        auto cache = (*libraries)[i];
        if (cache->imageBase() == base) cache->setActive(false);
    }
    moduleGeneration.fetch_add(1, std::memory_order_release);
}

bool initializeSymbols(CodeCacheArray* libraries) {
    if (!notificationCookie) {
        auto registerNotification = reinterpret_cast<RegisterNotification>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrRegisterDllNotification"));
        if (!registerNotification || registerNotification(0, moduleChanged, libraries, &notificationCookie) < 0) {
            Log::error("Cannot track Windows module loads and unloads");
            return false;
        }
        notificationsReady.store(true, std::memory_order_release);
    }
    if (symbolProcess) return true;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &symbolProcess, 0, FALSE, DUPLICATE_SAME_ACCESS)) return false;
    SymSetOptions(SymGetOptions() | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS | SYMOPT_EXACT_SYMBOLS);
    symbolSession = SymInitializeW(symbolProcess, L"", FALSE) != FALSE;
    if (!symbolSession) Log::warn("DbgHelp initialization failed; PDB symbols are unavailable");
    return true;
}

std::string debugSymbolName(PSYMBOL_INFOW symbol) {
    auto name = std::wstring_view(symbol->Name);
    if (name.size() != symbol->NameLen) pdbNameLengthCorrections.fetch_add(1, std::memory_order_relaxed);
    return WindowsProfiler::utf8(name);
}
BOOL CALLBACK addDebugSymbol(PSYMBOL_INFOW symbol, ULONG, void* data) {
    constexpr ULONG functionTag = 5;
    if (symbol->Tag != functionTag && !(symbol->Flags & SYMFLAG_FUNCTION)) return TRUE;
    auto cache = static_cast<CodeCache*>(data);
    auto name = debugSymbolName(symbol);
    cache->add(reinterpret_cast<void*>(symbol->Address), static_cast<int>(std::min<ULONG>(symbol->Size, INT_MAX)), name.c_str());
    return TRUE;
}

std::uint64_t fingerprint(unsigned char* base, const IMAGE_NT_HEADERS64* pe) {
    std::uint64_t value = 14695981039346656037ULL;
    auto append = [&](const void* data, size_t size) {
        auto bytes = static_cast<const unsigned char*>(data);
        for (size_t i = 0; i < size; ++i) value = (value ^ bytes[i]) * 1099511628211ULL;
    };
    append(&pe->FileHeader.TimeDateStamp, sizeof(DWORD));
    append(&pe->OptionalHeader.SizeOfImage, sizeof(DWORD));
    for (unsigned index : {IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_EXCEPTION}) {
        auto directory = pe->OptionalHeader.DataDirectory[index];
        append(&directory, sizeof(directory));
        if (directory.VirtualAddress && directory.Size) append(base + directory.VirtualAddress, directory.Size);
    }
    auto debug = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debug.VirtualAddress) {
        auto entries = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(base + debug.VirtualAddress);
        for (size_t i = 0; i < debug.Size / sizeof(*entries); ++i) {
            if (entries[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW && entries[i].AddressOfRawData) {
                append(base + entries[i].AddressOfRawData, entries[i].SizeOfData);
            }
        }
    }
    return value;
}

void parseExports(CodeCache* cache, HMODULE module) {
    auto base = reinterpret_cast<unsigned char*>(module);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto pe = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto exportInfo = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportInfo.VirtualAddress) return;
    auto table = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + exportInfo.VirtualAddress);
    auto names = reinterpret_cast<DWORD*>(base + table->AddressOfNames);
    auto indices = reinterpret_cast<WORD*>(base + table->AddressOfNameOrdinals);
    auto addresses = reinterpret_cast<DWORD*>(base + table->AddressOfFunctions);
    for (DWORD i = 0; i < table->NumberOfNames; ++i) {
        DWORD rva = addresses[indices[i]];
        // Forwarders belong to another module; GetProcAddress resolves them.
        if (rva >= exportInfo.VirtualAddress && rva < exportInfo.VirtualAddress + exportInfo.Size) continue;
        cache->add(base + rva, 0, reinterpret_cast<const char*>(base + names[i]));
    }
}

struct ModuleRef {
    HMODULE value = nullptr;
    ~ModuleRef() { if (value) FreeLibrary(value); }
};
bool readDebugSymbols(CodeCache* cache, const WCHAR* filename, DWORD64 address, ULONG size,
        PSYM_ENUMERATESYMBOLS_CALLBACKW callback, void* data) {
    if (!symbolSession) return false;
    std::wstring search(filename);
    search.resize(search.find_last_of(L"\\/"));
    WCHAR extra[32768];
    auto length = GetEnvironmentVariableW(L"ASYNC_PROFILER_SYMBOL_PATH", extra, 32768);
    if (length && length < 32768) search.append(L";").append(extra, length);
    SymSetSearchPathW(symbolProcess, search.c_str());
    SymLoadModuleExW(symbolProcess, nullptr, filename, nullptr, address, size, nullptr, 0);
    bool read = SymEnumSymbolsW(symbolProcess, address, nullptr, callback, data) != FALSE;
    IMAGEHLP_MODULEW64 info{sizeof(info)};
    bool pdb = read && SymGetModuleInfoW64(symbolProcess, address, &info) && info.SymType == SymPdb && !info.PdbUnmatched;
    cache->setDebugSymbols(pdb);
    SymUnloadModule64(symbolProcess, address);
    return pdb;
}

bool nativeTypeName(ULONG index, DWORD64 module, std::string& name, ULONG64& size, unsigned depth = 0) {
    if (depth > 16) return false;
    DWORD tag;
    if (!SymGetTypeInfo(symbolProcess, module, index, TI_GET_SYMTAG, &tag)) return false;
    if (tag == 17 || tag == 20) { // SymTagTypedef / SymTagFunctionArgType
        ULONG underlying;
        return SymGetTypeInfo(symbolProcess, module, index, TI_GET_TYPEID, &underlying)
            && nativeTypeName(underlying, module, name, size, depth + 1);
    }
    if (tag == 14) { // SymTagPointerType
        ULONG underlying;
        if (!SymGetTypeInfo(symbolProcess, module, index, TI_GET_TYPEID, &underlying)
                || !nativeTypeName(underlying, module, name, size, depth + 1)) return false;
        name += '*';
        return SymGetTypeInfo(symbolProcess, module, index, TI_GET_LENGTH, &size) && size == sizeof(void*);
    }
    size = 0;
    if (tag == 16) { // SymTagBaseType
        DWORD base;
        if (!SymGetTypeInfo(symbolProcess, module, index, TI_GET_BASETYPE, &base)) return false;
        if (base == 1) { name = "void"; return true; }
        if (!SymGetTypeInfo(symbolProcess, module, index, TI_GET_LENGTH, &size)) return false;
        if ((base == 7 || base == 14) && size == 8) { name = "uint64"; return true; }
        return false;
    }
    if (tag != 11) return false; // SymTagUDT
    WCHAR* typeName = nullptr;
    if (!SymGetTypeInfo(symbolProcess, module, index, TI_GET_SYMNAME, &typeName)) return false;
    name = WindowsProfiler::utf8(typeName);
    LocalFree(typeName);
    // Forward declarations can omit their length; pointers to them still have
    // a complete ABI. By-value descriptors require an explicit matching size.
    SymGetTypeInfo(symbolProcess, module, index, TI_GET_LENGTH, &size);
    return true;
}

bool nativeTypeMatches(ULONG index, DWORD64 module, const char* expected) {
    std::string name;
    ULONG64 size;
    if (!nativeTypeName(index, module, name, size)) return false;
    for (std::string_view choices(expected); !choices.empty();) {
        auto separator = choices.find('|');
        auto choice = choices.substr(0, separator);
        auto colon = choice.find(':');
        if (name == choice.substr(0, colon)
                && (colon == std::string_view::npos || size == std::strtoull(choice.data() + colon + 1, nullptr, 10))) return true;
        if (separator == std::string_view::npos) break;
        choices.remove_prefix(separator + 1);
    }
    return false;
}

struct NativeFunctionQuery {
    Symbols::NativeFunction* functions;
    size_t count;
    struct Match { const void* address = nullptr; bool ambiguous = false; };
    std::vector<Match> matches;
};

BOOL CALLBACK findNativeFunction(PSYMBOL_INFOW symbol, ULONG, void* parameter) {
    if (symbol->Tag != 5 && !(symbol->Flags & SYMFLAG_FUNCTION)) return TRUE;
    auto& query = *static_cast<NativeFunctionQuery*>(parameter);
    auto name = debugSymbolName(symbol);
    for (size_t i = 0; i < query.count; ++i) {
        auto& function = query.functions[i];
        if (name != function.name || !function.count || function.count > 16) continue;
        DWORD tag, callingConvention, children, result;
        auto module = symbol->ModBase;
        auto index = symbol->TypeIndex;
        if (!SymGetTypeInfo(symbolProcess, module, index, TI_GET_SYMTAG, &tag) || tag != 13
                || !SymGetTypeInfo(symbolProcess, module, index, TI_GET_CALLING_CONVENTION, &callingConvention) || callingConvention != 0
                || !SymGetTypeInfo(symbolProcess, module, index, TI_GET_CHILDRENCOUNT, &children) || children != function.count - 1
                || !SymGetTypeInfo(symbolProcess, module, index, TI_GET_TYPEID, &result)
                || !nativeTypeMatches(result, module, function.signature[0])) continue;
        struct Children { ULONG count, start, ids[16]; } arguments{};
        arguments.count = children;
        if (children && !SymGetTypeInfo(symbolProcess, module, index, TI_FINDCHILDREN, &arguments)) continue;
        bool valid = true;
        for (unsigned j = 0; j < children; ++j) valid &= nativeTypeMatches(arguments.ids[j], module, function.signature[j + 1]);
        if (!valid) continue;
        auto& match = query.matches[i];
        auto address = reinterpret_cast<const void*>(symbol->Address);
        match.ambiguous |= match.address && match.address != address;
        match.address = address;
    }
    return TRUE;
}

struct KernelFunction { ULONG end; std::string name; };
struct KernelFunctions {
    const WindowsProfiler::KernelModule& module;
    std::map<ULONG, KernelFunction> functions;
    std::string label;
    std::string fallback(ULONG rva) const {
        char offset[24]; std::snprintf(offset, sizeof(offset), "+0x%lx_[k]", rva);
        return label + offset;
    }
    void name(ULONG rva, ULONG size, std::string name) {
        if (rva >= module.size) return;
        auto exact = functions.find(rva);
        if (exact != functions.end()) { exact->second.name = label + "!" + name + "_[k]"; return; }
        auto next = functions.upper_bound(rva);
        if (next != functions.begin() && std::prev(next)->second.end > rva) return;
        ULONG end = rva + std::max<ULONG>(1, std::min(size, module.size - rva));
        if (next != functions.end()) end = std::min(end, next->first);
        functions.emplace(rva, KernelFunction{end, label + "!" + name + "_[k]"});
    }
};
BOOL CALLBACK addKernelSymbol(PSYMBOL_INFOW symbol, ULONG, void* data) {
    auto& target = *static_cast<KernelFunctions*>(data);
    if (symbol->Address < target.module.base || symbol->Address - target.module.base >= target.module.size) return TRUE;
    auto rva = static_cast<ULONG>(symbol->Address - target.module.base);
    // Public kernel PDBs contain function symbols without private type records.
    // A .pdata function boundary also distinguishes those from data symbols.
    if (symbol->Tag != 5 && !(symbol->Flags & SYMFLAG_FUNCTION) && !target.functions.contains(rva)) return TRUE;
    target.name(rva, symbol->Size, debugSymbolName(symbol));
    return TRUE;
}

void readKernelSymbols(CodeCacheArray* libraries) {
    std::vector<WindowsProfiler::KernelModule> modules;
    auto error = WindowsProfiler::kernelModules(modules);
    auto previousError = kernelError.exchange(error);
    if (error) {
        if (previousError != error) Log::warn("Windows kernel symbols are unavailable: %lu", error);
        for (int i = 0; i < libraries->count(); ++i) {
            auto cache = (*libraries)[i];
            if (reinterpret_cast<std::uintptr_t>(cache->imageBase()) >> 63) cache->setActive(false);
        }
        return;
    }
    for (int i = 0; i < libraries->count(); ++i) {
        auto cache = (*libraries)[i];
        if (!(reinterpret_cast<std::uintptr_t>(cache->imageBase()) >> 63)) continue;
        bool present = false;
        for (const auto& module : modules) present |= reinterpret_cast<std::uintptr_t>(cache->imageBase()) == module.base
            && cache->imageSignature() == module.signature();
        if (!present) cache->setActive(false);
    }
    for (const auto& module : modules) {
        auto path = WindowsProfiler::utf8(module.path);
        std::replace(path.begin(), path.end(), '\\', '/');
        bool known = false;
        for (int i = 0; i < libraries->count(); ++i) {
            auto cache = (*libraries)[i];
            if (reinterpret_cast<std::uintptr_t>(cache->imageBase()) == module.base
                    && cache->imageSignature() == module.signature() && path == cache->name()) {
                cache->setActive(true); known = true;
            }
        }
        if (known) continue;
        WindowsProfiler::KernelImage image;
        error = image.open(module);
        if (error) {
            // Only this image's frames stay unresolved; kernelError reports global unavailability.
            std::pair identity{module.base, module.signature()};
            if (std::find(failedKernelImages.begin(), failedKernelImages.end(), identity) != failedKernelImages.end()) continue;
            failedKernelImages.push_back(identity);
            if (error == ERROR_REVISION_MISMATCH) kernelMismatches.fetch_add(1);
            unsigned expected = 0;
            if (kernelWarningReady.compare_exchange_strong(expected, 1)) {
                std::snprintf(kernelWarning, sizeof(kernelWarning), "%s (Windows error %lu)", path.c_str(), error);
                kernelWarningReady.store(2, std::memory_order_release);
                Log::warn("Kernel image symbols unavailable: %s", kernelWarning);
            }
            continue;
        }
        if (libraries->count() == MAX_NATIVE_LIBS) { kernelError = ERROR_NOT_ENOUGH_MEMORY; return; }
        auto base = reinterpret_cast<const char*>(module.base);
        auto cache = new CodeCache(path.c_str(), static_cast<short>(libraries->count()), base, base + module.size, base);
        cache->setImageSignature(module.signature());
        KernelFunctions symbols{module, {}, WindowsProfiler::utf8(module.name)};
        auto pe = image.headers();
        auto directory = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        auto functions = reinterpret_cast<const RUNTIME_FUNCTION*>(image.data(directory.VirtualAddress, directory.Size));
        if (functions) for (size_t i = 0; i < directory.Size / sizeof(*functions); ++i) {
            auto begin = functions[i].BeginAddress, end = functions[i].EndAddress;
            if (begin < end && end <= module.size) symbols.functions.emplace(begin, KernelFunction{end, symbols.fallback(begin)});
        }
        readDebugSymbols(cache, image.path().c_str(), module.base, module.size, addKernelSymbol, &symbols);
        ULONG cursor = 0;
        for (auto entry = symbols.functions.begin(); entry != symbols.functions.end(); ++entry) {
            auto begin = entry->first;
            auto end = entry->second.end;
            if (auto next = std::next(entry); next != symbols.functions.end()) end = std::min(end, next->first);
            if (cursor < begin) cache->add(base + cursor, static_cast<int>(begin - cursor), symbols.fallback(cursor).c_str());
            cache->add(base + begin, static_cast<int>(end - begin), entry->second.name.c_str());
            cursor = end;
        }
        if (cursor < module.size) cache->add(base + cursor, static_cast<int>(module.size - cursor), symbols.fallback(cursor).c_str());
        cache->sort();
        libraries->add(cache);
    }
}
struct Snapshot {
    HANDLE value;
    ~Snapshot() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct ParseScope {
    ParseScope() { parsingSymbols = true; }
    ~ParseScope() { parsingSymbols = false; }
};
void retainResolvedModule(HMODULE module) {
    if (resolutionScope) resolutionScope->retain(module);
    else FreeLibrary(module);
}
} // namespace

void Symbols::parseLibraries(CodeCacheArray* libraries, bool wantKernel, bool essentialOnly) {
    if (parsingSymbols) return; // DbgHelp may load DLLs while parsing a PDB.
    MutexLocker lock(_parse_lock);
    ParseScope parsing;
    if (!initializeSymbols(libraries)) return;
    if (wantKernel) kernelRequested.store(true);
    auto generation = moduleGeneration.load(std::memory_order_acquire);
    Snapshot snapshot{WindowsProfiler::toolhelpSnapshot(TH32CS_SNAPMODULE, GetCurrentProcessId())};
    if (snapshot.value == INVALID_HANDLE_VALUE) { Log::warn("Cannot enumerate Windows modules: %lu", GetLastError()); return; }
    MODULEENTRY32W entry{sizeof(entry)};
    if (Module32FirstW(snapshot.value, &entry)) do {
        if (essentialOnly && _wcsicmp(entry.szModule, L"jvm.dll") != 0 && entry.hModule != WindowsProfiler::selfModule()) continue;
        ModuleRef retained;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(entry.modBaseAddr), &retained.value)) continue;
        auto base = reinterpret_cast<unsigned char*>(retained.value);
        bool known = false;
        for (int i = 0; i < libraries->count(); ++i) {
            auto cache = (*libraries)[i];
            known |= cache->active() && cache->imageBase() == reinterpret_cast<char*>(base);
        }
        if (known) continue;
        wchar_t filename[32768];
        DWORD pathLength = GetModuleFileNameW(retained.value, filename, 32768);
        if (!pathLength || pathLength == 32768) continue;
        auto pe = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
        auto path = WindowsProfiler::utf8(std::wstring_view(filename, pathLength));
        std::replace(path.begin(), path.end(), '\\', '/');
        auto signature = fingerprint(base, pe);
        CodeCache* cache = nullptr;
        for (int i = 0; i < libraries->count(); ++i) {
            auto previous = (*libraries)[i];
            if (previous->imageBase() == reinterpret_cast<char*>(base) && previous->imageSignature() == signature
                    && strcmp(previous->name(), path.c_str()) == 0) { cache = previous; break; }
        }
        if (cache) { cache->setActive(true); continue; }
        if (libraries->count() == MAX_NATIVE_LIBS) {
            if (!_libs_limit_reported) { _libs_limit_reported = true; Log::warn("Native library version limit reached"); }
            break;
        }
        cache = new CodeCache(path.c_str(), static_cast<short>(libraries->count()), base,
                base + pe->OptionalHeader.SizeOfImage, reinterpret_cast<char*>(base));
        cache->setImageSignature(signature);
        auto unwind = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (!cache->setWindowsUnwindTable(base + unwind.VirtualAddress, unwind.VirtualAddress ? unwind.Size / sizeof(RUNTIME_FUNCTION) : 0)) {
            delete cache;
            Log::error("Cannot allocate Windows unwind metadata");
            return;
        }
        parseExports(cache, retained.value);
        readDebugSymbols(cache, filename, reinterpret_cast<DWORD64>(base), pe->OptionalHeader.SizeOfImage, addDebugSymbol, cache);
        cache->sort();
        libraries->add(cache);
    } while (Module32NextW(snapshot.value, &entry));
    if (!essentialOnly && kernelRequested.load()) {
        readKernelSymbols(libraries);
        _have_kernel_symbols = false;
        for (int i = 0; i < libraries->count(); ++i) _have_kernel_symbols |= (*libraries)[i]->active()
            && (reinterpret_cast<std::uintptr_t>((*libraries)[i]->imageBase()) >> 63) != 0;
    }
    if (!essentialOnly) parsedGeneration.store(generation, std::memory_order_release);
}

bool Symbols::findNativeFunctions(CodeCache* cache, NativeFunction* functions, size_t count) try {
    MutexLocker lock(_parse_lock);
    ParseScope parsing;
    if (!symbolSession || !cache->hasDebugSymbols() || !cache->active()) return false;
    ModuleRef module;
    auto base = reinterpret_cast<HMODULE>(const_cast<char*>(cache->imageBase()));
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(base), &module.value)) return false;
    WCHAR filename[32768];
    auto length = GetModuleFileNameW(module.value, filename, 32768);
    if (!length || length == 32768) return false;
    auto bytes = reinterpret_cast<const unsigned char*>(base);
    auto pe = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes + reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes)->e_lfanew);
    NativeFunctionQuery query{functions, count, std::vector<NativeFunctionQuery::Match>(count)};
    if (!readDebugSymbols(cache, filename, reinterpret_cast<DWORD64>(base), pe->OptionalHeader.SizeOfImage,
            findNativeFunction, &query)) return false;
    for (size_t i = 0; i < count; ++i) functions[i].address = query.matches[i].ambiguous ? nullptr : query.matches[i].address;
    return true;
} catch (...) { return false; }

UnloadProtection::UnloadProtection(const CodeCache* cache) : _lib_handle(NULL), _valid(false) {
    HMODULE module;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(cache->imageBase()), &module)) {
        if (cache->active()) { _lib_handle = module; _valid = true; }
        else FreeLibrary(module);
    }
}
UnloadProtection::~UnloadProtection() { if (_lib_handle) FreeLibrary(static_cast<HMODULE>(_lib_handle)); }

namespace WindowsProfiler {
void requestKernelSymbols(bool needed) { kernelRequested.store(needed); }
SymbolResolutionScope::SymbolResolutionScope() : _previous(resolutionScope) { resolutionScope = this; }
SymbolResolutionScope::~SymbolResolutionScope() {
    resolutionScope = _previous;
    for (auto module : _retained) FreeLibrary(module);
}
void SymbolResolutionScope::retain(HMODULE module) {
    for (auto existing : _retained) if (existing == module) { FreeLibrary(module); return; }
    _retained.push_back(module);
}
bool modulesChanged() { return moduleGeneration.load(std::memory_order_acquire) != parsedGeneration.load(std::memory_order_acquire); }
bool moduleTrackingAvailable() { return notificationsReady.load(std::memory_order_acquire); }

void writeSymbolMetrics(Writer& out) {
    auto libraries = Profiler::instance()->nativeLibs();
    int count = libraries->count(), active = 0;
    for (int i = 0; i < count; ++i) active += (*libraries)[i]->active();
    out << "windows_native_modules " << active << '\n';
    out << "windows_native_versions " << count << '\n';
    out << "windows_module_generation " << u64(moduleGeneration.load(std::memory_order_acquire)) << '\n';
    unsigned kernel = 0, pdb = 0;
    for (int i = 0; i < count; ++i) if ((*libraries)[i]->active() && (reinterpret_cast<std::uintptr_t>((*libraries)[i]->imageBase()) >> 63)) {
        ++kernel; pdb += (*libraries)[i]->hasDebugSymbols();
    }
    out << "windows_kernel_modules " << u64(kernel) << '\n';
    out << "windows_kernel_pdb_modules " << u64(pdb) << '\n';
    out << "windows_kernel_image_mismatches " << u64(kernelMismatches.load()) << '\n';
    out << "windows_kernel_symbol_error " << u64(kernelError.load()) << '\n';
    out << "windows_pdb_name_length_corrections " << u64(pdbNameLengthCorrections.load()) << '\n';
    if (kernelWarningReady.load(std::memory_order_acquire) == 2) out << "windows_kernel_first_image_error " << kernelWarning << '\n';
}

void kernelImageChanged(std::uint64_t base, ULONG size, ULONG checksum, bool unloaded, bool rundown) {
    if (!(base >> 63) || !kernelRequested.load()) return;
    auto libraries = Profiler::instance()->nativeLibs();
    bool changed = true;
    auto signature = (std::uint64_t(checksum) << 32) | size;
    for (int i = 0; i < libraries->count(); ++i) {
        auto cache = (*libraries)[i];
        if (reinterpret_cast<std::uintptr_t>(cache->imageBase()) != base) continue;
        if (rundown && cache->active() && static_cast<std::uint64_t>(cache->imageSignature() & 0xffffffff) == size
                && (!checksum || cache->imageSignature() == signature)) { changed = false; continue; }
        if (unloaded || cache->imageSignature() != signature) cache->setActive(false);
        else if (cache->active()) changed = false;
    }
    if (changed || unloaded) moduleGeneration.fetch_add(1);
}

PRUNTIME_FUNCTION lookupFunctionEntry(DWORD64 pc, DWORD64* imageBase) {
    if (auto function = SoftwareSites::lookupUnwind(pc, imageBase)) return function;
    auto cache = Profiler::instance()->findLibraryByAddress(reinterpret_cast<void*>(pc));
    if (!cache) return nullptr;
    *imageBase = reinterpret_cast<DWORD64>(cache->imageBase());
    return static_cast<PRUNTIME_FUNCTION>(cache->findWindowsUnwindEntry(pc));
}

static const void* resolveSymbolImpl(const char* input, bool resolveForwarders) {
    Profiler::instance()->updateSymbols(false);
    std::string name(input);
    uintptr_t offset = 0;
    if (auto plus = name.rfind('+'); plus != std::string::npos && plus + 1 < name.size()
            && name[plus + 1] >= '0' && name[plus + 1] <= '9') {
        char* end;
        errno = 0;
        offset = std::strtoull(name.c_str() + plus + 1, &end, 0);
        if (*end || errno == ERANGE) return NULL;
        name.resize(plus);
    }
    uintptr_t result = 0;
    if (name.starts_with("0x")) {
        char* end;
        errno = 0;
        result = std::strtoull(name.c_str(), &end, 16);
        if (*end || errno == ERANGE) return NULL;
        if (result && result <= std::numeric_limits<uintptr_t>::max() - offset) {
            HMODULE provider;
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    reinterpret_cast<LPCWSTR>(result + offset), &provider)) retainResolvedModule(provider);
        }
    } else {
        HMODULE selected = nullptr;
        if (auto separator = name.find('!'); separator != std::string::npos) {
            selected = GetModuleHandleW(wide(std::string_view(name).substr(0, separator)).c_str());
            if (!selected) return nullptr;
            name.erase(0, separator + 1);
        }
        Snapshot snapshot{WindowsProfiler::toolhelpSnapshot(TH32CS_SNAPMODULE, GetCurrentProcessId())};
        if (snapshot.value == INVALID_HANDLE_VALUE) return nullptr;
        MODULEENTRY32W entry{sizeof(entry)};
        bool ambiguous = false;
        if (Module32FirstW(snapshot.value, &entry)) do {
            if (selected && selected != entry.hModule) continue;
            ModuleRef retained;
            if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(entry.modBaseAddr), &retained.value)) continue;
            const void* found = selected && resolveForwarders ? reinterpret_cast<void*>(GetProcAddress(retained.value, name.c_str())) : nullptr;
            auto cache = Profiler::instance()->findLibraryByAddress(retained.value);
            if (!found && cache && cache->active()) {
                found = name.ends_with('*') ? cache->findSymbolByPrefix(name.c_str(), name.size() - 1) : cache->findSymbol(name.c_str());
                if (!found && name.find("::") != std::string::npos) found = cache->findSymbolByPrefix((name + "(").c_str());
            }
            if (!found) continue;
            ambiguous |= result && result != reinterpret_cast<uintptr_t>(found);
            result = reinterpret_cast<uintptr_t>(found);
            retainResolvedModule(retained.value);
            retained.value = nullptr;
        } while (Module32NextW(snapshot.value, &entry));
        if (ambiguous) return nullptr;
    }
    return result && result <= std::numeric_limits<uintptr_t>::max() - offset ? reinterpret_cast<void*>(result + offset) : nullptr;
}
const void* resolveSymbol(const char* input) { return resolveSymbolImpl(input, true); }
const void* resolveLoadedSymbol(const char* input) { return resolveSymbolImpl(input, false); }
} // namespace WindowsProfiler
