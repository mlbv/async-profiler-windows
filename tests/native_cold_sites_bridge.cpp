/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ASPROF_NATIVE_PREP_TEST_BRIDGE
#error This bridge belongs only to the private native preparation test artifact.
#endif
#include "platform.h"
#include "asprof.h"
#include "profiler.h"
#include "windowsNativeProbeTarget.h"
#include "windowsSoftwareSites.h"
#include "windowsTrapThreads.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void success(const char* error) { if (error) throw std::runtime_error(error); }
const WindowsProfiler::SoftwareSites::PreparedSite* resumeSite = nullptr;
unsigned resumed = 0;

__attribute__((naked, noinline)) std::uint64_t redirectEntry(DWORD) {
    __asm__ volatile("int3\n\tud2");
}
LONG CALLBACK redirectToPreparedCode(EXCEPTION_POINTERS* exception) {
    if (exception->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT
            || exception->ExceptionRecord->ExceptionAddress != reinterpret_cast<void*>(redirectEntry))
        return EXCEPTION_CONTINUE_SEARCH;
    exception->ContextRecord->Rip = reinterpret_cast<DWORD64>(resumeSite->displaced());
    ++resumed;
    return EXCEPTION_CONTINUE_EXECUTION;
}

struct Module {
    HMODULE value = nullptr;
    ~Module() { reset(); }
    void reset() { if (value) { auto old = value; value = nullptr; FreeLibrary(old); } }
};
std::uint64_t physicalOffset(HMODULE module, const void* address) {
    auto base = reinterpret_cast<const unsigned char*>(module);
    auto pe = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto sections = IMAGE_FIRST_SECTION(pe);
    auto rva = reinterpret_cast<std::uintptr_t>(address) - reinterpret_cast<std::uintptr_t>(base);
    for (unsigned index = 0; index < pe->FileHeader.NumberOfSections; ++index) {
        const auto& section = sections[index];
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) && rva >= section.VirtualAddress
                && rva - section.VirtualAddress < section.SizeOfRawData)
            return section.PointerToRawData + (rva - section.VirtualAddress);
    }
    throw std::runtime_error("Owned exported function has no physical executable file offset");
}
}

extern "C" __declspec(dllexport) DWORD asprof_test_native_cold_sites(const WCHAR* fixture, char* report, DWORD capacity) {
    try {
        using namespace WindowsProfiler;
        asprof_init();
        TrapThreads::Identity identity;
        success(TrapThreads::prepare(GetCurrentThread(), &identity));
        {
            auto thread = TrapThreads::current();
            require(thread && thread.identity() == identity && !thread.internal() && thread.tryEnter(), "Cold trap-thread enrollment failed");
            auto nested = TrapThreads::pin(identity);
            require(nested && !nested.tryEnter(), "Trap-thread reentrancy guard admitted a nested owner");
            thread.state().eventEpoch = 0x1234; thread.state().remainder = 3;
        }
        {
            auto thread = TrapThreads::current();
            require(thread && thread.tryEnter() && thread.state().eventEpoch == 0x1234 && thread.state().remainder == 3,
                "Live prepared trap-thread state did not survive guard release");
        }
        require(!GetModuleHandleW(fixture), "Owned fixture must start unloaded");
        NativeProbe::SoftwareSpec before;
        success(NativeProbe::parseSoftware("uprobe:" + utf8(fixture) + "+0", before));
        NativeProbe::LoadedTarget absent;
        require(NativeProbe::resolveSoftware(before, absent) && !absent.module() && !GetModuleHandleW(fixture),
            "Resolver implicitly loaded an absent target");
        Module caller{LoadLibraryW(fixture)};
        require(caller.value != nullptr, "Explicit owned fixture load failed");
        auto entry = GetProcAddress(caller.value, "RunReloadWork");
        require(entry != nullptr, "Owned fixture export missing");
        auto fileOffset = physicalOffset(caller.value, reinterpret_cast<const void*>(entry));
        char offset[32]; std::snprintf(offset, sizeof(offset), "+0x%llx", static_cast<unsigned long long>(fileOffset));
        auto retired = std::wstring(fixture) + L".retired";
        require(MoveFileExW(fixture, retired.c_str(), 0) && CopyFileW(retired.c_str(), fixture, TRUE),
            "Owned loaded-image rename/replacement failed");
        NativeProbe::SoftwareSpec replacementSpec;
        success(NativeProbe::parseSoftware("uprobe:" + utf8(fixture) + offset, replacementSpec));
        NativeProbe::LoadedTarget replacement;
        require(NativeProbe::resolveSoftware(replacementSpec, replacement) && !replacement.module(),
            "Replacement filesystem object was confused with the older mapped section");
        NativeProbe::SoftwareSpec byFile, bySymbol;
        success(NativeProbe::parseSoftware("uprobe:" + utf8(retired) + offset, byFile));
        success(NativeProbe::parseSoftware("uprobe:" + utf8(fixture) + "!RunReloadWork", bySymbol));
        NativeProbe::LoadedTarget file, symbol;
        success(NativeProbe::resolveSoftware(byFile, file));
        success(NativeProbe::resolveSoftware(bySymbol, symbol));
        require(file.address == reinterpret_cast<const unsigned char*>(entry) && file.address == symbol.address
                && file.mappingEpoch == symbol.mappingEpoch && file.mappingEpoch, "File/symbol resolution identity mismatch");
        auto initialCount = SoftwareSites::preparedCount();
        SoftwareSites::SiteLease first, second;
        success(SoftwareSites::prepare(std::move(file), first));
        success(SoftwareSites::prepare(std::move(symbol), second));
        require(first.get() == second.get() && SoftwareSites::preparedCount() == initialCount + 1,
            "Same mapping preparation did not reuse immutable data");
        const auto* old = first.get();
        success(SoftwareSites::validateSource(*old));
        require(old->displaced() && old->displacedSize() && old->functionTable().size() == 2, "XOL/unwind preparation missing");
        const auto& mitigation = old->mitigations();
        require(!mitigation.error, "Prepared site retained a mitigation registration failure");
        if (mitigation.policyFlags & 4) require(mitigation.continuationMask == 3, "Both certified EH continuations were not processed");
        if (mitigation.policyFlags & 1) require(mitigation.rangeProcessed == 1, "Dynamic CET-compatible range was not processed");
        std::printf("COLD_SITE_MITIGATIONS policy=%lx continuations=%lu range=%lu possible=%lu\n",
            mitigation.policyFlags, mitigation.continuationMask, mitigation.rangeProcessed, mitigation.registrationPossible);
        DWORD64 dynamicBase = 0;
        auto dynamic = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(old->displaced()), &dynamicBase, nullptr);
        require(dynamic && dynamicBase == reinterpret_cast<DWORD64>(old->displaced()) && dynamic->BeginAddress == 0,
            "Prepared XOL body unwind table was not registered");
        DWORD64 cachedBase = 0;
        auto cached = lookupFunctionEntry(reinterpret_cast<DWORD64>(old->displaced()), &cachedBase);
        require(cached == dynamic && cachedBase == dynamicBase, "Cached native walker missed retained XOL unwind data");
        using Work = std::uint64_t (*)(DWORD);
        auto expected = reinterpret_cast<Work>(entry)(7);
        require(reinterpret_cast<Work>(const_cast<unsigned char*>(old->displaced()))(7) == expected,
            "Prepared displaced entry changed owned function behavior");
        resumeSite = old;
        auto redirect = AddVectoredExceptionHandler(1, redirectToPreparedCode);
        require(redirect != nullptr, "Cannot install owned continuation test handler");
        auto resumedValue = redirectEntry(7);
        require(RemoveVectoredExceptionHandler(redirect) != 0, "Cannot remove owned continuation test handler");
        resumeSite = nullptr;
        require(resumedValue == expected && resumed == 1, "Prepared EH continuation changed source call semantics");
        success(SoftwareSites::validateSource(*old));
        NativeProbe::LoadedTarget rejected;
        require(NativeProbe::resolveSoftware(before, rejected) && !rejected.module(), "Header file offset was accepted as code");
        auto oldEpoch = old->mappingEpoch();
        auto originalBase = caller.value;
        first.reset(); second.reset();
        require(GetModuleHandleW(fixture) == caller.value && old->currentMapping(), "Our lease release unloaded a caller-owned mapping");
        caller.reset();
        require(!GetModuleHandleW(fixture) && !old->currentMapping() && SoftwareSites::validateSource(*old),
            "Unloaded mapping remained eligible");
        caller.value = LoadLibraryW(fixture);
        require(caller.value == originalBase, "Fixed-base owned fixture did not reuse its address");
        NativeProbe::LoadedTarget reloaded;
        success(NativeProbe::resolveSoftware(replacementSpec, reloaded));
        require(reloaded.mappingEpoch && reloaded.mappingEpoch != oldEpoch, "Identical reload reused an old mapping epoch");
        SoftwareSites::SiteLease next;
        success(SoftwareSites::prepare(std::move(reloaded), next));
        require(next.get() != old && !old->currentMapping() && SoftwareSites::preparedCount() == initialCount + 2,
            "Old immutable record was reactivated for a new mapping");
        success(SoftwareSites::validateSource(*next.get()));
        next.reset(); caller.reset();
        require(!GetModuleHandleW(fixture), "Cold preparation leaked a source module reference");
        std::snprintf(report, capacity, "NATIVE_COLD_SITES_PASS noImplicitLoad=1 sectionIdentity=1 sameMappingReuse=1 sourceUnchanged=1 xol=1 unwind=2 continuation=1 lease=1 reloadEpoch=1\n");
        return 0;
    } catch (const std::exception& error) {
        std::snprintf(report, capacity, "NATIVE_COLD_SITES_FAIL %s Windows=%lu\n", error.what(), GetLastError());
        return 1;
    }
}
