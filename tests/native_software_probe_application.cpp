/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include <windows.h>
#include "asprof.h"
#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <filesystem>
#include <xmmintrin.h>
#include <string>

namespace {
using Work = std::uint64_t (*)(std::uint64_t);
asprof_execute_t execute;
Work target, alternate, windowTarget, immediateTarget, comparisonTarget, prologueTarget;
using FloatingWork = double (*)(double, double);
FloatingWork floatingTarget;
volatile unsigned gateSink = 0;
using GetStatus = LONG (WINAPI*)();
GetStatus getStatus;
std::string response;
void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "SOFTWARE_ENTRY_FAIL %s Windows=%lu\n", message, GetLastError()); std::exit(1); }
}
void output(const char* bytes, size_t size) { response.append(bytes, size); }
void command(const std::string& value) {
    response.clear();
    if (auto error = execute(value.c_str(), output)) {
        std::fprintf(stderr, "SOFTWARE_ENTRY_COMMAND_FAIL %s: %s\n", value.c_str(), error);
        std::exit(1);
    }
}
std::string rejected(const std::string& value) {
    response.clear();
    auto error = execute(value.c_str(), output);
    require(error != nullptr, "Unsupported command succeeded");
    return error;
}
std::uint64_t fileOffset(HMODULE module, const void* entry) {
    auto base = reinterpret_cast<const unsigned char*>(module);
    auto pe = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto sections = IMAGE_FIRST_SECTION(pe);
    auto rva = reinterpret_cast<std::uintptr_t>(entry) - reinterpret_cast<std::uintptr_t>(base);
    for (unsigned i = 0; i < pe->FileHeader.NumberOfSections; ++i) {
        auto& section = sections[i];
        if (rva >= section.VirtualAddress && rva - section.VirtualAddress < section.SizeOfRawData
                && (section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            return section.PointerToRawData + rva - section.VirtualAddress;
    }
    require(false, "Fixture export lacks a physical executable offset");
    return 0;
}
std::string selector(const char* prefix, const std::string& path, HMODULE module, Work function) {
    char offset[32];
    std::snprintf(offset, sizeof(offset), "+0x%llx",
        static_cast<unsigned long long>(fileOffset(module, reinterpret_cast<const void*>(function))));
    return prefix + path + offset;
}
DWORD WINAPI shortWorker(void*) {
    for (unsigned i = 0; i < 7; ++i) {
        SetLastError(0x127ace);
        auto status = getStatus();
        require(target(i) == i + 1 && GetLastError() == 0x127ace && getStatus() == status, "Worker call or error state changed");
    }
    return 0;
}
std::uint64_t sumFile(const std::filesystem::path& path) {
    auto file = std::fopen(path.string().c_str(), "rb");
    require(file != nullptr, "Open collapsed fixture result");
    std::string text;
    char bytes[4096];
    for (size_t size; (size = std::fread(bytes, 1, sizeof(bytes), file)) != 0;) text.append(bytes, size);
    require(std::fclose(file) == 0, "Close collapsed fixture result");
    std::uint64_t total = 0;
    for (size_t first = 0; first < text.size();) {
        auto end = text.find('\n', first);
        if (end == std::string::npos) end = text.size();
        auto separator = text.rfind(' ', end);
        require(separator != std::string::npos && separator >= first, "Collapsed fixture row");
        total += std::strtoull(text.c_str() + separator + 1, nullptr, 10);
        first = end + 1;
    }
    return total;
}
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t NativeSoftwareEntryCaller(unsigned calls) {
    std::uint64_t sum = 0;
    for (unsigned i = 0; i < calls; ++i) {
        SetLastError(0x127ace);
        auto status = getStatus();
        auto value = target(i);
        require(GetLastError() == 0x127ace && getStatus() == status, "Entry sampling changed native error state");
        sum += value;
    }
    return sum;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t NativeSoftwareAlternatePrefix() {
    return alternate(1) + alternate(2);
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t NativeSoftwareAlternateSelected() {
    volatile std::uint64_t value = alternate(3);
    return value;
}

extern "C" __declspec(dllexport) __declspec(noinline) void NativeSoftwareGateBegin() { gateSink = 1; }
extern "C" __declspec(dllexport) __declspec(noinline) void NativeSoftwareGateEnd() { gateSink = 0; }
extern "C" __declspec(dllexport) __declspec(noinline) void NativeSoftwareWindowInside(unsigned count) {
    for (unsigned i = 0; i < count; ++i) require(windowTarget(i) == i + 9, "Window target changed return");
}
extern "C" __declspec(dllexport) __declspec(noinline) void NativeSoftwareWindowOutside(unsigned count) {
    for (unsigned i = 0; i < count; ++i) require(windowTarget(i) == i + 9, "Window target changed return");
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t NativeSoftwareImmediateCaller() {
    volatile auto value = immediateTarget(10);
    return value;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t NativeSoftwareComparisonCaller(std::uint64_t argument) {
    volatile auto value = comparisonTarget(argument);
    return value;
}

extern "C" __declspec(dllexport) __declspec(noinline) double NativeSoftwareFloatingCaller() {
    auto csr = _mm_getcsr();
    auto requested = (csr & ~0x6000u) | 0x6000u;
    unsigned short control, requestedControl, observedControl;
    __asm__ volatile("fnstcw %0" : "=m"(control));
    requestedControl = static_cast<unsigned short>((control & ~0x0c00u) | 0x0c00u);
    __asm__ volatile("fldcw %0" :: "m"(requestedControl) : "memory");
    _mm_setcsr(requested);
    auto value = floatingTarget(3.5, 2.25);
    auto observed = _mm_getcsr();
    __asm__ volatile("fnstcw %0" : "=m"(observedControl));
    _mm_setcsr(csr);
    __asm__ volatile("fldcw %0" :: "m"(control) : "memory");
    require(value == 5.75 && observed == requested && observedControl == requestedControl,
        "Entry observation changed floating arguments, result or controls");
    return value;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t NativeSoftwarePrologueCaller(std::uint64_t argument) {
    SetLastError(0x127ace);
    auto status = getStatus();
    volatile auto value = prologueTarget(argument);
    require(GetLastError() == 0x127ace && getStatus() == status, "Prologue sampling changed native error state");
    return value;
}

static void prologueCases(HMODULE fixture, const std::string& path, const std::filesystem::path& directory) {
    auto resolve = [&](const char* name) {
        auto address = reinterpret_cast<const unsigned char*>(GetProcAddress(fixture,name));
        require(address != nullptr,"Missing prologue fixture export");
        return address;
    };
    auto event = [&](const unsigned char* address) {
        return selector("uprobe:",path,fixture,reinterpret_cast<Work>(const_cast<unsigned char*>(address)));
    };
    auto rejectAt = [&](const unsigned char* address) {
        auto saved = *address;
        rejected("start,event=" + event(address) + ",jfr,file=" + (directory / "rejected.jfr").string());
        require(*address == saved,"Rejected prologue selector changed source");
    };
    auto neutral = resolve("SoftwarePrologueNeutral");
    rejectAt(neutral + 6); // Inside SUB's immediate instruction.
    rejectAt(resolve("SoftwarePrologueEmbedded") + 6); // ENDBR bytes inside MOV's immediate.
    auto selected = event(neutral + 9);
    rejected("start,event=" + selected + ",jfr,file=" + (directory / "absent" / "prepare.jfr").string());
    auto base = reinterpret_cast<unsigned char*>(fixture);
    auto pe = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto table = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    auto rows = reinterpret_cast<RUNTIME_FUNCTION*>(base + table.VirtualAddress);
    RUNTIME_FUNCTION* row = nullptr;
    auto rva = static_cast<DWORD>(neutral - base);
    for (unsigned index = 0; index < table.Size / sizeof(*rows); ++index)
        if (rows[index].BeginAddress == rva) { row = rows + index; break; }
    require(row != nullptr,"Owned prologue exception row missing");
    auto patch = [&](unsigned char* location,unsigned char value) {
        DWORD previous, ignored;
        require(VirtualProtect(location,1,PAGE_READWRITE,&previous),"Make owned certificate byte writable");
        *location = value;
        require(FlushInstructionCache(GetCurrentProcess(),location,1)
            && VirtualProtect(location,1,previous,&ignored),"Restore owned certificate byte protection");
    };
    auto allocationCode = base + row->UnwindData + 5;
    for (auto location : {const_cast<unsigned char*>(neutral + 4),const_cast<unsigned char*>(neutral + 10),
                         allocationCode,reinterpret_cast<unsigned char*>(&row->BeginAddress)}) {
        auto original = *location;
        patch(location,original ^ (location == allocationCode ? 0x10 : 1));
        rejected("start,event=" + selected + ",jfr,file=" + (directory / "stale.jfr").string());
        require(neutral[9] == 0x85,"Stale prologue certificate patched the source");
        patch(location,original);
    }
    std::puts("PROLOGUE_CERTIFICATE_REJECTIONS_OK mutations=4");
    struct Case {
        const char* name;
        const char* symbol;
        unsigned offset, period, calls, increment;
        bool predicate, symbolic;
    };
    const Case cases[]{
        {"prologue-neutral","SoftwarePrologueNeutral",9,2,5,0,true,true},
        {"prologue-allocate","SoftwarePrologueAllocate",1,1,1,13,false,false},
        {"prologue-frame","SoftwarePrologueFrame",1,1,1,17,false,false},
        {"prologue-anchored","SoftwarePrologueAnchored",8,1,3,0,true,false}
    };
    auto capture = [&](const char* name,const char* symbol,const std::string& selected,
                       const unsigned char* source,unsigned period,unsigned calls,unsigned increment,bool predicate) {
        auto original = *source;
        command("start,event=" + selected + ",interval=" + std::to_string(period)
            + ",cstack=dwarf,jfr,file=" + (directory / (std::string(name) + ".jfr")).string());
        require(*source == 0xcc,"Prologue breakpoint missing");
        for (unsigned i = 0; i < calls; ++i)
            require(NativeSoftwarePrologueCaller(i) == (predicate ? std::uint64_t{i == 0} : i + increment),
                "Prologue displacement changed return or flags");
        command("stop");
        require(*source == original,"Prologue source not restored");
        command("dump,collapsed,total,file=" + (directory / (std::string(name) + ".total.collapsed")).string());
        command("dump,otlp,total,file=" + (directory / (std::string(name) + ".native.otlp")).string());
        auto samples = calls / period, total = samples * period;
        require(sumFile(directory / (std::string(name) + ".total.collapsed")) == total,"Prologue weights changed");
        std::printf("PROLOGUE_CAPTURE name=%s frame=%s period=%u samples=%u total=%u selector=%s\n",
            name,symbol,period,samples,total,selected.c_str());
    };
    for (const auto& item : cases) {
        auto function = resolve(item.symbol);
        prologueTarget = reinterpret_cast<Work>(const_cast<unsigned char*>(function));
        auto selected = item.symbolic ? "uprobe:" + std::filesystem::path(path).filename().string()
            + "!" + item.symbol + "+" + std::to_string(item.offset) : event(function + item.offset);
        capture(item.name,item.symbol,selected,function + item.offset,item.period,item.calls,item.increment,item.predicate);
    }
    // A prolog PUSH and the first body instruction of the same function.
    prologueTarget = reinterpret_cast<Work>(const_cast<unsigned char*>(neutral));
    capture("prologue-push","SoftwarePrologueNeutral",event(neutral + 4),neutral + 4,1,3,0,true);
    capture("prologue-body","SoftwarePrologueNeutral",event(neutral + 11),neutral + 11,1,2,0,true);
    for (unsigned order = 0; order < 2; ++order) {
        auto symbol = order ? "SoftwarePrologueAliasB" : "SoftwarePrologueAliasA";
        auto function = resolve(symbol);
        auto base = event(function), offset = event(function + 4);
        auto first = order ? offset : base, second = order ? base : offset;
        // Prepare through one alias without consuming its one permitted arm.
        rejected("start,event=" + first + ",jfr,file=" + (directory / "absent" / "alias.jfr").string());
        require(function[0] == 0xf3 && function[4] == 0x48,"Alias preparation changed ENDBR/source");
        prologueTarget = reinterpret_cast<Work>(const_cast<unsigned char*>(function));
        capture(order ? "prologue-alias-b" : "prologue-alias-a",symbol,second,function + 4,1,1,19,false);
        // The other alias rearms the same patched instruction.
        capture(order ? "prologue-alias-b-rearm" : "prologue-alias-a-rearm",symbol,first,function + 4,1,2,19,false);
        require(function[0] == 0xf3 && function[4] == 0x48,"Alias rearm changed source");
    }
    command("metrics");
    std::printf("%s",response.c_str());
    std::puts("SOFTWARE_PROLOGUE_APPLICATION_OK captures=10 aliases=2 rearmed=2 push=1 body=1 sourceRestored=1");
}

int main(int argc, char** argv) {
    require(argc == 4 || argc == 5, "Pass library, owned fixture DLL and evidence directory");
    bool ioFailure = argc == 5 && std::strcmp(argv[4], "io-failure") == 0;
    bool prologues = argc == 5 && std::strcmp(argv[4], "prologues") == 0;
    if (argc == 5 && !ioFailure && !prologues) {
        DWORD policy = 0;
        bool strict = std::strcmp(argv[4], "strict") == 0;
        DWORD required = strict ? 0x15u : 0x5u;
        require(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &policy, sizeof(policy))
            && (policy & required) == required && !(policy & 0x20au)
            && bool(policy & 0x10) == strict, "Owned software-entry CET enforcement");
        std::printf("SOFTWARE_ENTRY_CET_POLICY flags=%lx strict=%u\n", policy, strict ? 1u : 0u);
    }
    auto library = LoadLibraryA(argv[1]);
    auto fixture = LoadLibraryA(argv[2]);
    require(library && fixture, "Load owned profiler and target");
    auto initialize = std::bit_cast<asprof_init_t>(GetProcAddress(library, "asprof_init"));
    execute = std::bit_cast<asprof_execute_t>(GetProcAddress(library, "asprof_execute"));
    target = std::bit_cast<Work>(GetProcAddress(fixture, "SoftwareEntryTarget"));
    alternate = std::bit_cast<Work>(GetProcAddress(fixture, "SoftwareEntryAlternate"));
    windowTarget = std::bit_cast<Work>(GetProcAddress(fixture, "SoftwareEntryWindow"));
    floatingTarget = std::bit_cast<FloatingWork>(GetProcAddress(fixture, "SoftwareEntryFloating"));
    immediateTarget = std::bit_cast<Work>(GetProcAddress(fixture, "SoftwareEntryImmediate"));
    comparisonTarget = std::bit_cast<Work>(GetProcAddress(fixture, "SoftwareEntryComparison"));
    auto unsupported = std::bit_cast<Work>(GetProcAddress(fixture, "SoftwareEntryRejected"));
    getStatus = std::bit_cast<GetStatus>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetLastNtStatus"));
    require(initialize && execute && target && alternate && windowTarget && floatingTarget && immediateTarget
        && comparisonTarget && unsupported && getStatus, "Resolve fixture APIs");
    initialize();
    std::string path = std::filesystem::absolute(argv[2]).string();
    auto directory = std::filesystem::absolute(argv[3]);
    std::filesystem::create_directories(directory);
    if (prologues) { prologueCases(fixture,path,directory); return 0; }
    auto entry = selector("uprobe:", path, fixture, target);
    auto other = selector("uprobe:", path, fixture, alternate);
    // Call sites stay unsupported: a displaced CALL pushes an XOL return address.
    char rejectedOffset[32];
    std::snprintf(rejectedOffset, sizeof(rejectedOffset), "+0x%llx", static_cast<unsigned long long>(
        fileOffset(fixture, reinterpret_cast<const unsigned char*>(unsupported) + 4)));
    auto invalid = "uprobe:" + path + rejectedOffset;
    auto initial = *reinterpret_cast<const unsigned char*>(target);
    if (ioFailure) {
        using ErrnoGetter = int* (__cdecl*)();
        auto getter = std::bit_cast<ErrnoGetter>(GetProcAddress(GetModuleHandleW(L"ucrtbase.dll"), "_errno"));
        require(getter && getter() == &errno, "Fixture uses the shared UCRT error domain");
        auto outputPath = directory / "locked.jfr";
        command("start,event=" + entry + ",cstack=dwarf,jfr,file=" + outputPath.string());
        auto locked = CreateFileW(outputPath.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        require(locked != INVALID_HANDLE_VALUE, "Open shared JFR lock handle");
        OVERLAPPED range{};
        require(LockFileEx(locked, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
            MAXDWORD, MAXDWORD, &range), "Lock owned JFR writes");
        for (unsigned i = 0; i < 12000; ++i) {
            require(_set_doserrno(0x123456) == 0, "Set owned CRT DOS error");
            errno = 0x217a;
            SetLastError(0x127ace);
            auto status = getStatus();
            auto value = target(i);
            require(value == i + 1 && errno == 0x217a, "Sampling I/O changed caller errno");
            unsigned long dosError;
            require(_get_doserrno(&dosError) == 0 && dosError == 0x123456, "Sampling I/O changed caller DOS errno");
            require(GetLastError() == 0x127ace && getStatus() == status, "Sampling I/O changed caller TEB errors");
        }
        require(UnlockFileEx(locked, 0, MAXDWORD, MAXDWORD, &range) && CloseHandle(locked), "Release owned write lock");
        auto error = rejected("stop");
        require(error.find("write complete JFR") != std::string::npos, "JFR flush failure was not retained");
        require(*reinterpret_cast<const unsigned char*>(target) == initial, "I/O failure stop did not restore source");
        command("start,event=" + other + ",cstack=dwarf,jfr,file=" + (directory / "recovery.jfr").string());
        require(NativeSoftwareAlternateSelected() == 10, "New recording after output failure changed native return");
        command("stop");
        command("dump,collapsed,total,file=" + (directory / "recovery.total.collapsed").string());
        require(sumFile(directory / "recovery.total.collapsed") == 1, "Output failure leaked into replacement recording");
        command("metrics");
        std::printf("%s", response.c_str());
        std::puts("SOFTWARE_ENTRY_IO_TRANSPARENCY_OK sharedCrt=1 errno=1 doserrno=1 tebErrors=1 stickyWriteError=1 sourceRestored=1 recovery=1");
        return 0;
    }
    auto rejectedByte = reinterpret_cast<const unsigned char*>(unsupported)[4];
    require(rejected("start,event=" + invalid + ",jfr,file=" + (directory / "unsupported.jfr").string()).find("call sites")
        != std::string::npos, "Call site was not rejected as such");
    require(reinterpret_cast<const unsigned char*>(unsupported)[4] == rejectedByte, "Rejected instruction changed source");


    rejected("start,event=" + entry + ",interval=5,cstack=dwarf,jfr,file=" + (directory / "absent" / "entry.jfr").string());
    require(*reinterpret_cast<const unsigned char*>(target) == initial, "Failed recording output changed source");
    command("start,event=" + entry + ",interval=5,cstack=dwarf,jfr,file=" + (directory / "entry.jfr").string());
    require(*reinterpret_cast<const unsigned char*>(target) == 0xcc, "Software entry did not own a source breakpoint");
    HANDLE workers[4];
    for (auto& worker : workers) {
        worker = CreateThread(nullptr, 0, shortWorker, nullptr, 0, nullptr);
        require(worker != nullptr, "Create observed native worker");
    }
    require(WaitForMultipleObjects(4, workers, TRUE, 10000) == WAIT_OBJECT_0, "Join owned workers");
    for (auto worker : workers) {
        DWORD exit;
        require(GetExitCodeThread(worker, &exit) && exit == 0, "Owned worker completed");
        CloseHandle(worker);
    }
    require(NativeSoftwareEntryCaller(12) == 78, "Entry function return changed");
    command("stop");
    require(*reinterpret_cast<const unsigned char*>(target) == initial, "Stop did not restore source");
    command("dump,collapsed,total,file=" + (directory / "entry.total.collapsed").string());
    command("dump,collapsed,samples,file=" + (directory / "entry.samples.collapsed").string());
    require(sumFile(directory / "entry.total.collapsed") == 30
        && sumFile(directory / "entry.samples.collapsed") == 6, "Per-thread entry period or weight changed");
    command("start,event=" + entry + ",interval=5,cstack=dwarf,jfr,file=" + (directory / "rearm.jfr").string());
    require(*reinterpret_cast<const unsigned char*>(target) == 0xcc && NativeSoftwareEntryCaller(9) == 45, "Rearmed entry execution");
    command("stop");
    require(*reinterpret_cast<const unsigned char*>(target) == initial, "Rearm stop did not restore source");
    command("dump,collapsed,total,file=" + (directory / "rearm.total.collapsed").string());
    require(sumFile(directory / "rearm.total.collapsed") == 5, "Rearm did not start a fresh per-thread period");

    command("start,event=" + other + ",interval=3,cstack=dwarf,jfr,file=" + (directory / "alternate.jfr").string());
    require(NativeSoftwareAlternatePrefix() == 17 && NativeSoftwareAlternateSelected() == 10, "Alternate source execution changed");
    command("stop");
    command("dump,collapsed,total,file=" + (directory / "alternate.total.collapsed").string());
    command("dump,collapsed,samples,file=" + (directory / "alternate.samples.collapsed").string());
    require(sumFile(directory / "alternate.total.collapsed") == 3
        && sumFile(directory / "alternate.samples.collapsed") == 1, "Recording epoch did not reset the thread period");
    auto window = selector("uprobe:", path, fixture, windowTarget);
    command("start,event=" + window + ",interval=5,cstack=dwarf,jfr,begin=NativeSoftwareGateBegin,end=NativeSoftwareGateEnd,file="
        + (directory / "window.jfr").string());
    NativeSoftwareWindowOutside(2);
    NativeSoftwareGateBegin();
    NativeSoftwareWindowInside(3);
    NativeSoftwareGateEnd();
    NativeSoftwareWindowOutside(3);
    NativeSoftwareGateBegin();
    NativeSoftwareWindowInside(2);
    NativeSoftwareGateEnd();
    command("stop");
    command("dump,collapsed,total,file=" + (directory / "window.total.collapsed").string());
    command("dump,collapsed,samples,file=" + (directory / "window.samples.collapsed").string());
    require(sumFile(directory / "window.total.collapsed") == 10
        && sumFile(directory / "window.samples.collapsed") == 2, "Window gates reset the software event phase");
    auto floating = selector("uprobe:", path, fixture, std::bit_cast<Work>(floatingTarget));
    command("start,event=" + floating + ",cstack=dwarf,jfr,file=" + (directory / "floating.jfr").string());
    require(NativeSoftwareFloatingCaller() == 5.75, "Observed floating function result");
    command("stop");
    command("dump,collapsed,total,file=" + (directory / "floating.total.collapsed").string());
    require(sumFile(directory / "floating.total.collapsed") == 1, "Floating entry event count");
    auto immediate = selector("uprobe:", path, fixture, immediateTarget);
    auto immediateByte = *reinterpret_cast<const unsigned char*>(immediateTarget);
    command("start,event=" + immediate + ",cstack=dwarf,jfr,file=" + (directory / "immediate.jfr").string());
    require(*reinterpret_cast<const unsigned char*>(immediateTarget) == 0xcc && NativeSoftwareImmediateCaller() == 3,
        "Immediate entry sign extension or source ownership");
    command("stop");
    require(*reinterpret_cast<const unsigned char*>(immediateTarget) == immediateByte, "Immediate source not restored");
    command("dump,collapsed,total,file=" + (directory / "immediate.total.collapsed").string());
    require(sumFile(directory / "immediate.total.collapsed") == 1, "Immediate entry count");
    auto comparison = selector("uprobe:", path, fixture, comparisonTarget);
    auto comparisonByte = *reinterpret_cast<const unsigned char*>(comparisonTarget);
    command("start,event=" + comparison + ",cstack=dwarf,jfr,file=" + (directory / "comparison.jfr").string());
    require(*reinterpret_cast<const unsigned char*>(comparisonTarget) == 0xcc
        && NativeSoftwareComparisonCaller(7) == 1 && NativeSoftwareComparisonCaller(6) == 0
        && NativeSoftwareComparisonCaller(8) == 0, "Comparison entry changed result flags");
    command("stop");
    require(*reinterpret_cast<const unsigned char*>(comparisonTarget) == comparisonByte, "Comparison source not restored");
    command("dump,collapsed,total,file=" + (directory / "comparison.total.collapsed").string());
    require(sumFile(directory / "comparison.total.collapsed") == 3, "Comparison entry count");
    command("metrics");
    std::printf("%s", response.c_str());
    std::printf("SOFTWARE_ENTRY_APPLICATION_OK perThread=1 phaseReset=1 windowPhase=1 fpState=1 sourceRestored=1 unsupportedBeforePatch=1 rearmed=1 target=%s alternate=%s\n",
        entry.c_str(), other.c_str());
    return 0;
}
