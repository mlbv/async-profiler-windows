/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include <windows.h>
#include <cpuid.h>
#include "asprof.h"
#include <atomic>
#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <tuple>
#include <string>
#include <string_view>
#include <vector>

namespace {
using Work = std::uint64_t (*)(std::uint64_t);
using Driver = std::uint64_t (*)(unsigned);
asprof_execute_t execute;
HMODULE fixture, module;
std::string response, fixtureName, fixturePath;
std::filesystem::path directory;
using GetStatus = LONG (WINAPI*)();
GetStatus getStatus;
void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "SOFTWARE_RETURN_FAIL %s Windows=%lu\n", message, GetLastError()); std::exit(1); }
}
void output(const char* bytes, size_t size) { response.append(bytes, size); }
void command(const std::string& value) {
    response.clear();
    if (auto error = execute(value.c_str(), output)) {
        std::fprintf(stderr, "SOFTWARE_RETURN_COMMAND_FAIL %s: %s\n", value.c_str(), error);
        std::exit(1);
    }
}
std::string rejected(const std::string& value) {
    response.clear();
    auto error = execute(value.c_str(), output);
    require(error != nullptr, "Unsupported command succeeded");
    return error;
}
template<class T> T resolve(const char* name) {
    auto address = GetProcAddress(module, name);
    require(address != nullptr, "Missing return fixture export");
    return std::bit_cast<T>(address);
}
std::string readFile(const std::filesystem::path& path) {
    auto file = std::fopen(path.string().c_str(), "rb");
    require(file != nullptr, "Open fixture result");
    std::string text;
    char bytes[4096];
    for (size_t size; (size = std::fread(bytes, 1, sizeof(bytes), file)) != 0;) text.append(bytes, size);
    require(std::fclose(file) == 0, "Close fixture result");
    return text;
}
// Sums weights and requires every stack to end in leaf with parent as an earlier frame.
std::uint64_t collapsed(const std::filesystem::path& path, const char* leaf, const char* parent) {
    auto text = readFile(path);
    std::uint64_t total = 0;
    for (size_t first = 0; first < text.size();) {
        auto end = text.find('\n', first);
        if (end == std::string::npos) end = text.size();
        auto separator = text.rfind(' ', end);
        require(separator != std::string::npos && separator >= first, "Collapsed fixture row");
        auto stack = text.substr(first, separator - first);
        auto last = stack.rfind(';');
        auto top = stack.substr(last == std::string::npos ? 0 : last + 1);
        bool expected = false;
        for (size_t begin = 0, next; begin <= std::strlen(leaf); begin = next + 1) {
            next = std::string_view(leaf).find('|', begin);
            if (next == std::string_view::npos) next = std::strlen(leaf);
            expected |= top.find(std::string_view(leaf).substr(begin, next - begin)) != std::string::npos;
        }
        if (!expected || stack.find(parent) == std::string::npos) {
            std::fprintf(stderr, "SOFTWARE_RETURN_STACK %s\n", stack.c_str());
            require(false, "Return sample does not end at the expected caller chain");
        }
        total += std::strtoull(text.c_str() + separator + 1, nullptr, 10);
        first = end + 1;
    }
    return total;
}
std::vector<unsigned char> window(const void* function) {
    DWORD64 base = 0;
    auto row = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(function), &base, nullptr);
    require(row != nullptr, "Fixture function has no unwind row");
    auto bytes = reinterpret_cast<const unsigned char*>(base);
    return {bytes + row->BeginAddress, bytes + row->EndAddress};
}
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t NativeReturnCaller(Work work, unsigned calls, std::uint64_t base) {
    std::uint64_t sum = 0;
    for (unsigned index = 0; index < calls; ++index) {
        SetLastError(0x127ace);
        auto status = getStatus();
        auto value = work(base + index);
        require(GetLastError() == 0x127ace && getStatus() == status, "Return sampling changed native error state");
        sum += value;
    }
    return sum;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t NativeReturnDriver(Driver driver, unsigned count) {
    volatile auto value = driver(count);
    return value;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t NativeReturnCase(const std::function<std::uint64_t()>& run) {
    volatile auto value = run();
    return value;
}

namespace {
void capture(const char* name, const char* symbol, unsigned period, std::uint64_t samples, const char* leaf,
        const std::function<std::uint64_t()>& run, std::uint64_t expected, const char* parent = "NativeReturnCase") {
    auto function = resolve<const void*>(symbol);
    auto before = window(function);
    char path[MAX_PATH];
    require(GetModuleFileNameA(module, path, MAX_PATH) > 0, "Probed module name");
    auto selector = "uretprobe:" + std::filesystem::path(path).filename().string() + "!" + symbol;
    command("start,event=" + selector + ",interval=" + std::to_string(period) + ",cstack=dwarf,jfr,file="
        + (directory / (std::string(name) + ".jfr")).string());
    require(window(function) != before, "Return probe did not own an epilogue breakpoint");
    require(NativeReturnCase(run) == expected, "Probed function results changed");
    command("stop");
    require(window(function) == before, "Return probe sources were not restored");
    auto prefix = directory / name;
    command("dump,collapsed,total,file=" + prefix.string() + ".total.collapsed");
    command("dump,collapsed,samples,file=" + prefix.string() + ".samples.collapsed");
    command("dump,otlp,total,file=" + prefix.string() + ".native.otlp");
    auto total = samples * period;
    require(collapsed(prefix.string() + ".total.collapsed", leaf, parent) == total
        && collapsed(prefix.string() + ".samples.collapsed", leaf, parent) == samples, "Return event period or weight changed");
    std::printf("RETURN_CAPTURE name=%s leaf=%s period=%u samples=%llu total=%llu selector=%s\n", name, leaf, period,
        static_cast<unsigned long long>(samples), static_cast<unsigned long long>(total), selector.c_str());
}

// Single-steps one return through its displaced epilogue. Every stopped
// context, including the INT3 at the patched source, is unwound with the OS
// function lookup until the caller, and must equal the real state after return.
struct Stepping {
    std::atomic<DWORD> thread{0};
    const unsigned char *function = nullptr, *functionEnd = nullptr, *caller = nullptr, *callerEnd = nullptr;
    bool trapped = false, compared = false, redirected = false;
    // Dispatch mode lets every stopped position reach an outer SEH filter.
    bool dispatch = false, armSource = false, sourceDispatched = false;
    DWORD64 source = 0;
    unsigned filtered = 0;
    unsigned steps = 0, unwinds = 0;
    // RtlVirtualUnwind treats RET imm16 as RET, in original code too.
    DWORD64 released = 0;
    CONTEXT unwound{};
} stepping;
// Spans every exception-directory row chained to the function's primary row.
std::pair<const unsigned char*, const unsigned char*> range(const void* function) {
    DWORD64 base = 0;
    auto primary = RtlLookupFunctionEntry(reinterpret_cast<DWORD64>(function), &base, nullptr);
    require(primary != nullptr, "Stepped function has no unwind row");
    auto bytes = reinterpret_cast<const unsigned char*>(base);
    auto pe = reinterpret_cast<const IMAGE_NT_HEADERS64*>(bytes + reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes)->e_lfanew);
    auto directory = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    auto rows = reinterpret_cast<const RUNTIME_FUNCTION*>(bytes + directory.VirtualAddress);
    auto begin = primary->BeginAddress, end = primary->EndAddress;
    for (size_t index = 0; index < directory.Size / sizeof(RUNTIME_FUNCTION); ++index) {
        auto row = rows[index];
        for (;;) {
            auto info = bytes + row.UnwindData;
            if (!(info[0] & 0x20)) break;
            std::memcpy(&row, info + 4 + ((info[2] + 1) & ~1) * 2, sizeof(row));
        }
        if (!std::memcmp(&row, primary, sizeof(row))) {
            begin = std::min(begin, rows[index].BeginAddress);
            end = std::max(end, rows[index].EndAddress);
        }
    }
    return {bytes + begin, bytes + end};
}
bool inside(DWORD64 pc, const unsigned char* begin, const unsigned char* end) {
    return pc >= reinterpret_cast<DWORD64>(begin) && pc < reinterpret_cast<DWORD64>(end);
}
void unwindToCaller(CONTEXT context) {
    for (unsigned depth = 0; !inside(context.Rip, stepping.caller, stepping.callerEnd); ++depth) {
        require(depth < 8, "OS unwind did not reach the return caller");
        DWORD64 base = 0;
        auto row = RtlLookupFunctionEntry(context.Rip, &base, nullptr);
        if (!row) {
            context.Rip = *reinterpret_cast<DWORD64*>(context.Rsp);
            context.Rsp += 8;
            continue;
        }
        void* data; DWORD64 frame;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, base, context.Rip, row, &context, &data, &frame, nullptr);
    }
    auto same = [](const CONTEXT& a, const CONTEXT& b) {
        return a.Rip == b.Rip && a.Rsp == b.Rsp && a.Rbx == b.Rbx && a.Rbp == b.Rbp && a.Rsi == b.Rsi && a.Rdi == b.Rdi
            && a.R12 == b.R12 && a.R13 == b.R13 && a.R14 == b.R14 && a.R15 == b.R15;
    };
    if (stepping.unwinds++) require(same(context, stepping.unwound), "Stopped epilogue positions unwind to different callers");
    stepping.unwound = context;
}
void stepped(CONTEXT& context) {
    ++stepping.steps;
    unwindToCaller(context);
    context.EFlags |= 0x100;
}
LONG CALLBACK stepReturn(EXCEPTION_POINTERS* pointers) {
    if (GetCurrentThreadId() != stepping.thread) return EXCEPTION_CONTINUE_SEARCH;
    auto& context = *pointers->ContextRecord;
    auto code = pointers->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT && inside(context.Rip, stepping.function, stepping.functionEnd)) {
        require(*reinterpret_cast<const unsigned char*>(context.Rip) == 0xcc, "Return trap is not at an owned INT3");
        if (!stepping.trapped) unwindToCaller(context);
        stepping.trapped = true;
        stepping.source = context.Rip;
        context.EFlags |= 0x100;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (code != EXCEPTION_SINGLE_STEP || !stepping.trapped) return EXCEPTION_CONTINUE_SEARCH;
    if (inside(context.Rip, stepping.caller, stepping.callerEnd)) {
        auto returned = context;
        returned.Rsp -= stepping.released;
        unwindToCaller(returned);
        stepping.compared = true;
        context.EFlags &= ~0x100u;
        if (stepping.armSource) {
            // The next call stops at the patched INT3 before executing it.
            stepping.armSource = false;
            stepping.dispatch = true;
            stepping.unwinds = 0;
            context.ContextFlags |= CONTEXT_DEBUG_REGISTERS;
            context.Dr0 = stepping.source;
            context.Dr7 = 1;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (stepping.dispatch) return EXCEPTION_CONTINUE_SEARCH;
    stepped(context);
    return EXCEPTION_CONTINUE_EXECUTION;
}
int stepFilter(EXCEPTION_POINTERS* pointers) {
    if (GetCurrentThreadId() != stepping.thread || pointers->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;
    auto& context = *pointers->ContextRecord;
    ++stepping.filtered;
    if (context.Rip == stepping.source) {
        require(*reinterpret_cast<const unsigned char*>(context.Rip) == 0xcc, "Debug stop is not at the owned INT3");
        stepping.sourceDispatched = true;
        unwindToCaller(context);
        context.ContextFlags |= CONTEXT_DEBUG_REGISTERS;
        context.Dr7 = 0; context.Dr6 = 0;
        context.EFlags |= 0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    stepped(context);
    return EXCEPTION_CONTINUE_EXECUTION;
}
// The rescue's final context is the first displaced position; TF traps only after it.
LONG CALLBACK stepRedirected(EXCEPTION_POINTERS* pointers) {
    auto& context = *pointers->ContextRecord;
    if (GetCurrentThreadId() != stepping.thread || !stepping.trapped || stepping.redirected
            || pointers->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
    require(!inside(context.Rip, stepping.function, stepping.functionEnd), "Return trap was not redirected");
    stepping.redirected = true;
    ++stepping.steps;
    unwindToCaller(context);
    return EXCEPTION_CONTINUE_SEARCH;
}
void step(const std::string& module, const void* function, const char* symbol, const void* callerAddress,
        const std::function<std::uint64_t()>& run, std::uint64_t expected, unsigned minimum, DWORD64 released = 0, bool dispatch = false) {
    stepping.released = released;
    auto selector = "uretprobe:" + module + "!" + symbol;
    command("start,event=" + selector + ",jfr,file=" + (directory / "stepping.jfr").string());
    std::tie(stepping.function, stepping.functionEnd) = range(function);
    std::tie(stepping.caller, stepping.callerEnd) = range(callerAddress);
    stepping.trapped = stepping.compared = stepping.redirected = stepping.dispatch = stepping.sourceDispatched = false;
    stepping.armSource = dispatch;
    stepping.steps = stepping.unwinds = stepping.filtered = 0;
    stepping.thread = GetCurrentThreadId();
    require(run() == expected, "Stepped return changed its result");
    if (dispatch) {
        auto steps = stepping.steps;
        stepping.compared = false;
        require(run() == expected && stepping.sourceDispatched && stepping.steps - steps + 1 >= minimum,
            "SEH dispatch did not reach the outer filter from every stopped position");
    }
    stepping.thread = 0;
    command("stop");
    require(stepping.trapped && stepping.redirected && stepping.compared && stepping.steps >= minimum,
        "Return stepping did not cover the displaced epilogue");
    std::printf("RETURN_STEPPED name=%s positions=%u unwinds=%u dispatched=%u\n", symbol, stepping.steps + 1, stepping.unwinds,
        stepping.filtered);
}
void step(const char* symbol, const char* callerSymbol, Work work, std::uint64_t argument, std::uint64_t expected, unsigned minimum,
        DWORD64 released = 0) {
    auto callerAddress = callerSymbol ? resolve<const void*>(callerSymbol) : reinterpret_cast<const void*>(NativeReturnCaller);
    step(fixtureName, resolve<const void*>(symbol), symbol, callerAddress,
        [=] { return NativeReturnCaller(work, 1, argument); }, expected, minimum, released);
}

// Records one software probe at symbol+offset and checks its exports.
void probe(const char* name, const char* symbol, unsigned offset, unsigned period, std::uint64_t samples, const char* leaf,
        const std::function<std::uint64_t()>& run, std::uint64_t expected, const char* parent = "NativeReturnCase") {
    char path[MAX_PATH];
    require(GetModuleFileNameA(module, path, MAX_PATH) > 0, "Probed module name");
    auto source = resolve<const unsigned char*>(symbol) + offset;
    auto original = *source;
    auto selector = "uprobe:" + std::filesystem::path(path).filename().string() + "!" + symbol + "+" + std::to_string(offset);
    command("start,event=" + selector + ",interval=" + std::to_string(period) + ",cstack=dwarf,jfr,file="
        + (directory / (std::string(name) + ".jfr")).string());
    require(*source == 0xcc, "Software probe did not own its source instruction");
    require(NativeReturnCase(run) == expected, "Probed function results changed");
    command("stop");
    require(*source == original, "Software probe source was not restored");
    auto prefix = directory / name;
    command("dump,collapsed,total,file=" + prefix.string() + ".total.collapsed");
    command("dump,collapsed,samples,file=" + prefix.string() + ".samples.collapsed");
    command("dump,otlp,total,file=" + prefix.string() + ".native.otlp");
    require(collapsed(prefix.string() + ".total.collapsed", leaf, parent) == samples * period
        && collapsed(prefix.string() + ".samples.collapsed", leaf, parent) == samples, "Software probe period or weight changed");
    std::printf("RETURN_CAPTURE name=%s leaf=%s period=%u samples=%llu total=%llu selector=%s\n", name, leaf, period,
        static_cast<unsigned long long>(samples), static_cast<unsigned long long>(samples * period), selector.c_str());
}
void unprobed(const char* symbol, unsigned offset, const char* reason) {
    char path[MAX_PATH];
    require(GetModuleFileNameA(module, path, MAX_PATH) > 0, "Probed module name");
    auto source = resolve<const unsigned char*>(symbol) + offset;
    auto original = *source;
    auto error = rejected("start,event=uprobe:" + std::filesystem::path(path).filename().string() + "!" + symbol + "+"
        + std::to_string(offset) + ",jfr,file=" + (directory / "rejected.jfr").string());
    if (error.find(reason) == std::string::npos) std::fprintf(stderr, "SOFTWARE_RETURN_REJECTION %s\n", error.c_str());
    require(error.find(reason) != std::string::npos && *source == original, "Software probe was not rejected unchanged");
}
std::uint64_t repaired = 77;
DWORD64 faultingSource = 0;
unsigned repairs = 0;
// Appended after the profiler's handler, so it sees the translated source.
LONG CALLBACK repairLoad(EXCEPTION_POINTERS* pointers) {
    auto& context = *pointers->ContextRecord;
    if (pointers->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || context.Rip != faultingSource
            || pointers->ExceptionRecord->ExceptionAddress != reinterpret_cast<void*>(faultingSource)) return EXCEPTION_CONTINUE_SEARCH;
    context.Rcx = reinterpret_cast<DWORD64>(&repaired);
    ++repairs;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Single-steps displaced LOOP/JRCXZ copies. The first handler sees displaced
// positions and unwinds them; the last sees them translated, where every stop
// must report the address the original branch lands at.
struct Branching {
    std::atomic<DWORD> thread{0};
    DWORD64 source = 0, next = 0, target = 0, raw = 0;
    const unsigned char *function = nullptr, *functionEnd = nullptr;
    bool active = false, taken = false;
    bool (*takes)(const CONTEXT&) = nullptr;
    unsigned hits = 0, displaced = 0, landings = 0;
} branching;
LONG CALLBACK branchFirst(EXCEPTION_POINTERS* pointers) {
    if (GetCurrentThreadId() != branching.thread) return EXCEPTION_CONTINUE_SEARCH;
    auto& context = *pointers->ContextRecord;
    auto code = pointers->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_BREAKPOINT && context.Rip == branching.source) {
        branching.taken = branching.takes(context);
        branching.active = true;
        ++branching.hits;
        stepping.unwinds = 0;
        unwindToCaller(context);
        context.EFlags |= 0x100;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (code != EXCEPTION_SINGLE_STEP || !branching.active) return EXCEPTION_CONTINUE_SEARCH;
    branching.raw = context.Rip;
    if (!inside(context.Rip, branching.function, branching.functionEnd)) unwindToCaller(context);
    return EXCEPTION_CONTINUE_SEARCH;
}
LONG CALLBACK branchLast(EXCEPTION_POINTERS* pointers) {
    if (GetCurrentThreadId() != branching.thread || pointers->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP
            || !branching.active) return EXCEPTION_CONTINUE_SEARCH;
    auto& context = *pointers->ContextRecord;
    require(context.Rip == (branching.taken ? branching.target : branching.next), "Displaced branch stop is not reported where it lands");
    if (context.Rip == branching.raw) {
        ++branching.landings;
        branching.active = false;
        context.EFlags &= ~0x100u;
    } else {
        ++branching.displaced;
        context.EFlags |= 0x100;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}
unsigned branchStep(const char* symbol, unsigned offset, unsigned length, unsigned target, bool (*takes)(const CONTEXT&),
        std::initializer_list<std::uint64_t> arguments, std::uint64_t expected, unsigned hits) {
    auto work = resolve<Work>(symbol);
    auto function = reinterpret_cast<const unsigned char*>(work);
    branching.source = reinterpret_cast<DWORD64>(function + offset);
    branching.next = branching.source + length;
    branching.target = reinterpret_cast<DWORD64>(function + target);
    std::tie(branching.function, branching.functionEnd) = range(function);
    std::tie(stepping.caller, stepping.callerEnd) = range(reinterpret_cast<const void*>(NativeReturnCaller));
    branching.takes = takes;
    branching.hits = branching.displaced = branching.landings = 0;
    command("start,event=uprobe:" + fixtureName + "!" + symbol + "+" + std::to_string(offset) + ",jfr,file="
        + (directory / "branch-stepping.jfr").string());
    auto first = AddVectoredExceptionHandler(1, branchFirst), last = AddVectoredExceptionHandler(0, branchLast);
    require(first && last, "Install branch steppers");
    branching.thread = GetCurrentThreadId();
    std::uint64_t sum = 0;
    for (auto value : arguments) sum += NativeReturnCaller(work, 1, value);
    branching.thread = 0;
    require(RemoveVectoredExceptionHandler(first) && RemoveVectoredExceptionHandler(last), "Remove branch steppers");
    command("stop");
    require(sum == expected && branching.hits == hits && branching.landings == hits && branching.displaced >= hits && !branching.active,
        "Displaced branch stepping did not cover every hit");
    std::printf("RETURN_BRANCH_STEPPED name=%s+%u hits=%u displacedStops=%u\n", symbol, offset, branching.hits, branching.displaced);
    return branching.displaced;
}
unsigned undefinedTransactions = 0;
DWORD64 transactionSource = 0;
int undefinedFilter(EXCEPTION_POINTERS* pointers) {
    if (pointers->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION) return EXCEPTION_CONTINUE_SEARCH;
    require(pointers->ExceptionRecord->ExceptionAddress == reinterpret_cast<void*>(transactionSource)
        && pointers->ContextRecord->Rip == transactionSource, "XBEGIN #UD is not reported at its source");
    ++undefinedTransactions;
    return EXCEPTION_EXECUTE_HANDLER;
}
// Clang's GNU target catches only faults raised inside calls made from __try.
__declspec(noinline) std::uint64_t guardedTransaction(Work work, std::uint64_t value) {
    __try { return NativeReturnCaller(work, 1, value); }
    __except (undefinedFilter(GetExceptionInformation())) { return value + 100; }
}
bool restrictedTransactionalMemory() {
    unsigned a, b, c, d;
    return __get_cpuid_count(7, 0, &a, &b, &c, &d) && (b & (1u << 11));
}

HANDLE release, held;
std::atomic<DWORD> heldThread{0};
std::atomic<bool> holding{false};
const unsigned char* heldFunction;
// Registered after the profiler's handler, so it runs first and keeps one
// return trap pending inside exception dispatch.
LONG CALLBACK holdTrap(EXCEPTION_POINTERS* pointers) {
    auto address = static_cast<const unsigned char*>(pointers->ExceptionRecord->ExceptionAddress);
    if (pointers->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT || GetCurrentThreadId() != heldThread
            || address < heldFunction || address >= heldFunction + 64 || !holding.exchange(false)) return EXCEPTION_CONTINUE_SEARCH;
    SetEvent(held);
    WaitForSingleObject(release, INFINITE);
    return EXCEPTION_CONTINUE_SEARCH;
}
DWORD WINAPI heldWorker(void* parameter) {
    heldThread = GetCurrentThreadId();
    return static_cast<DWORD>(NativeReturnCaller(std::bit_cast<Work>(parameter), 1, 40));
}
struct Workers {
    HANDLE start = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<HANDLE> threads;
};
DWORD WINAPI concurrentWorker(void* parameter) {
    auto& workers = *static_cast<Workers*>(parameter);
    WaitForSingleObject(workers.start, INFINITE);
    return static_cast<DWORD>(NativeReturnCaller(resolve<Work>("ReturnFramed"), 9, 0) != 9 * 2 + 36);
}
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    require(argc == 4 || argc == 5, "Pass library, owned fixture DLL, evidence directory and optional CET mode");
    if (argc == 5) {
        DWORD policy = 0;
        bool strict = std::strcmp(argv[4], "strict") == 0;
        DWORD required = strict ? 0x15u : 0x5u;
        require(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessUserShadowStackPolicy, &policy, sizeof(policy))
            && (policy & required) == required && !(policy & 0x20au) && bool(policy & 0x10) == strict, "Owned CET enforcement");
        std::printf("SOFTWARE_RETURN_CET_POLICY flags=%lx strict=%u\n", policy, strict ? 1u : 0u);
    }
    auto library = LoadLibraryA(argv[1]);
    fixture = module = LoadLibraryA(argv[2]);
    auto msvc = LoadLibraryW((std::filesystem::absolute(argv[2]).parent_path() / "softwareReturnMsvc.dll").c_str());
    require(library && fixture && msvc, "Load owned profiler and fixtures");
    auto initialize = std::bit_cast<asprof_init_t>(GetProcAddress(library, "asprof_init"));
    execute = std::bit_cast<asprof_execute_t>(GetProcAddress(library, "asprof_execute"));
    getStatus = std::bit_cast<GetStatus>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetLastNtStatus"));
    require(initialize && execute && getStatus, "Resolve profiler APIs");
    initialize();
    fixturePath = std::filesystem::absolute(argv[2]).string();
    fixtureName = std::filesystem::path(fixturePath).filename().string();
    directory = std::filesystem::absolute(argv[3]);
    std::filesystem::create_directories(directory);

    for (auto [symbol, reason] : {std::pair{"ReturnJumpTable", "unproven"}, std::pair{"ReturnInterior", "interior"}}) {
        auto function = resolve<const void*>(symbol);
        auto before = window(function);
        auto error = rejected(std::string("start,event=uretprobe:") + fixtureName + "!" + symbol + ",jfr,file="
            + (directory / "rejected.jfr").string());
        require(error.find(reason) != std::string::npos, error.c_str());
        require(window(function) == before, "Rejected return probe changed source");
    }
    rejected(std::string("start,event=uretprobe:") + fixtureName + "!ReturnFramed+1,jfr,file=" + (directory / "rejected.jfr").string());
    auto bare = resolve<const unsigned char*>("ReturnBare");
    auto bareByte = bare[4];
    require(rejected(std::string("start,event=uretprobe:") + fixtureName + "!ReturnBare,jfr,file=" + (directory / "rejected.jfr").string())
        .find("unwind metadata") != std::string::npos && bare[4] == bareByte, "Metadata-less leaf was not rejected unchanged");
    std::puts("RETURN_REJECTIONS_OK unproven=1 interior=1 nonEntry=1 noMetadata=1");

    auto leaf = resolve<Work>("ReturnLeaf"), framed = resolve<Work>("ReturnFramed");
    auto caller = [](Work work, unsigned calls, std::uint64_t base) {
        return [=] { return NativeReturnCaller(work, calls, base); };
    };
    capture("leaf", "ReturnLeaf", 1, 5, "NativeReturnCaller", caller(leaf, 5, 0), 5 * 1 + 10);
    capture("framed", "ReturnFramed", 2, 3, "NativeReturnCaller", caller(framed, 7, 0), 7 * 2 + 21);
    capture("multiple", "ReturnMultiple", 1, 6, "NativeReturnCaller", caller(resolve<Work>("ReturnMultiple"), 6, 0),
        (1 + 3 + 5) + 3 * 3 + (0 + 2 + 4) + 3 * 4);
    capture("tail", "ReturnTail", 1, 4, "NativeReturnCaller", caller(resolve<Work>("ReturnTail"), 4, 0), 6 + 4 * 4);
    capture("indirect-tail", "ReturnIndirectTail", 1, 3, "NativeReturnCaller", caller(resolve<Work>("ReturnIndirectTail"), 3, 0), 3 + 3 * 6);
    capture("import-tail", "ReturnImportTail", 1, 3, "NativeReturnCaller", caller(resolve<Work>("ReturnImportTail"), 3, 0), 3 + 3 * 8);
    capture("recursive", "ReturnRecursive", 1, 5 + 6, "NativeReturnCaller|ReturnRecursive", caller(resolve<Work>("ReturnRecursive"), 2, 4),
        (4 + 3 + 2 + 1) + (5 + 4 + 3 + 2 + 1));
    capture("self-tail", "ReturnSelfTail", 1, 4 + 5, "NativeReturnCaller", caller(resolve<Work>("ReturnSelfTail"), 2, 3), 14);
    capture("frame-pointer", "ReturnFramePointer", 1, 4, "NativeReturnCaller", caller(resolve<Work>("ReturnFramePointer"), 4, 1),
        (1 + 2 + 3 + 4) + 4 * 9);
    capture("frame-move", "ReturnFrameMove", 1, 4, "NativeReturnCaller", caller(resolve<Work>("ReturnFrameMove"), 4, 1),
        (1 + 2 + 3 + 4) + 4 * 10);
    capture("repeat", "ReturnRepeat", 1, 2, "NativeReturnCaller", caller(resolve<Work>("ReturnRepeat"), 2, 0), 1 + 2 * 11);
    capture("immediate", "ReturnImmediate", 1, 3, "ReturnImmediateCaller", caller(resolve<Work>("ReturnImmediateCaller"), 3, 0),
        3 + 3 * 12, "NativeReturnCaller");
    std::uint64_t slot = reinterpret_cast<std::uint64_t>(leaf);
    capture("faulting", "ReturnFaulting", 1, 3, "NativeReturnCaller", [&] {
        auto faulting = resolve<std::uint64_t (*)(std::uint64_t*)>("ReturnFaulting");
        std::uint64_t sum = 0;
        for (unsigned index = 0; index < 3; ++index) sum += NativeReturnCaller(std::bit_cast<Work>(faulting), 1,
            reinterpret_cast<std::uint64_t>(&slot));
        return sum;
    }, 3 * (reinterpret_cast<std::uint64_t>(&slot) + 18));
    auto driver = [](const char* name, unsigned count) {
        auto function = resolve<Driver>(name);
        return [=] { return NativeReturnDriver(function, count); };
    };
    auto destroyed = resolve<volatile std::uint64_t*>("ReturnDestroyed");
    auto initialDestroyed = *destroyed;
    capture("cxx", "ReturnCxx", 1, 4, "ReturnCxxDriver", driver("ReturnCxxDriver", 8), 4, "NativeReturnDriver");
    require(*destroyed - initialDestroyed == 8, "Exceptional exits skipped destructors");
    capture("catch", "ReturnCatch", 1, 6, "ReturnCatchDriver", driver("ReturnCatchDriver", 6), 8 + 10 + 12 + 1 + 3 + 5,
        "NativeReturnDriver");

    capture("pass-through", "ReturnPassThrough", 1, 3, "ReturnPassThroughDriver", driver("ReturnPassThroughDriver", 6), 3,
        "NativeReturnDriver");
    // Shrink-wrapped early exits count only when their branch is taken.
    auto values = [](Work work, std::initializer_list<std::uint64_t> arguments) {
        std::vector<std::uint64_t> copied(arguments);
        return [=] {
            std::uint64_t sum = 0;
            for (auto value : copied) sum += NativeReturnCaller(work, 1, value);
            return sum;
        };
    };
    auto wrapped = resolve<Work>("ReturnShrinkWrapped"), shrinkJump = resolve<Work>("ReturnShrinkJump");
    capture("shrink", "ReturnShrinkWrapped", 1, 7, "NativeReturnCaller", values(wrapped, {0, 1, 0, 2, 0, 3, 0}), 6 + 7 + 8);
    capture("shrink-period", "ReturnShrinkWrapped", 2, 3, "NativeReturnCaller", values(wrapped, {0, 1, 0, 2, 0, 3, 0}), 6 + 7 + 8);
    capture("shrink-jump", "ReturnShrinkJump", 1, 6, "NativeReturnCaller", values(shrinkJump, {1, 2, 1, 3, 1, 4}), 3 * 9 + 8 + 9 + 10);
    std::puts("RETURN_SHAPES_OK");

    auto stepper = AddVectoredExceptionHandler(1, stepReturn);
    auto redirected = AddVectoredContinueHandler(1, stepRedirected);
    require(stepper && redirected, "Install return stepper");
    step("ReturnLeaf", nullptr, leaf, 3, 4, 1);
    step("ReturnFramed", nullptr, framed, 3, 5, 3);
    step("ReturnMultiple", nullptr, resolve<Work>("ReturnMultiple"), 3, 6, 3);
    step("ReturnMultiple", nullptr, resolve<Work>("ReturnMultiple"), 4, 8, 3);
    step("ReturnTail", nullptr, resolve<Work>("ReturnTail"), 3, 7, 2);
    step("ReturnIndirectTail", nullptr, resolve<Work>("ReturnIndirectTail"), 3, 9, 2);
    step("ReturnImportTail", nullptr, resolve<Work>("ReturnImportTail"), 3, 11, 2);
    step("ReturnFramePointer", nullptr, resolve<Work>("ReturnFramePointer"), 3, 12, 3);
    step("ReturnFrameMove", nullptr, resolve<Work>("ReturnFrameMove"), 3, 13, 2);
    step("ReturnRepeat", nullptr, resolve<Work>("ReturnRepeat"), 3, 14, 1);
    step("ReturnImmediate", "ReturnImmediateCaller", resolve<Work>("ReturnImmediateCaller"), 3, 15, 1, 8);
    step("ReturnShrinkWrapped", nullptr, resolve<Work>("ReturnShrinkWrapped"), 0, 0, 2);
    step("ReturnShrinkWrapped", nullptr, resolve<Work>("ReturnShrinkWrapped"), 3, 8, 4);
    step("ReturnShrinkJump", nullptr, resolve<Work>("ReturnShrinkJump"), 1, 9, 2);
    step("ReturnShrinkJump", nullptr, resolve<Work>("ReturnShrinkJump"), 2, 8, 3);
    module = msvc;
    using Filtered = std::uint64_t (*)(int (*)(EXCEPTION_POINTERS*), Work, std::uint64_t);
    auto filtered = resolve<Filtered>("MsvcFiltered");
    auto shrink = resolve<Work>("MsvcShrink");
    volatile std::uint64_t cell = 40;
    // Each copy's positions after the first; TF observes the first only through the rescue.
    for (auto [symbol, argument, expected, copied] : {std::tuple{"MsvcShrink", std::uint64_t{2}, std::uint64_t{6}, 3u},
            std::tuple{"MsvcShrink", std::uint64_t{9}, std::uint64_t{19 + 2 * (19 ^ 9) + 1 + 2 * (2 * (19 ^ 9) + 1 + 9) + 1 + 9}, 3u},
            std::tuple{"MsvcCxx", std::uint64_t{4}, std::uint64_t{10}, 3u}, std::tuple{"MsvcCatch", std::uint64_t{4}, std::uint64_t{12}, 3u},
            std::tuple{"MsvcSeh", reinterpret_cast<std::uint64_t>(&cell), std::uint64_t{41}, 1u}}) {
        auto work = resolve<Work>(symbol);
        step("softwareReturnMsvc.dll", reinterpret_cast<const void*>(work), symbol, reinterpret_cast<const void*>(filtered),
            [=] { return filtered(stepFilter, work, argument); }, expected, copied, 0, true);
    }
    module = fixture;
    require(RemoveVectoredExceptionHandler(stepper) && RemoveVectoredContinueHandler(redirected), "Remove return stepper");
    std::puts("RETURN_UNWIND_STEPPING_OK sehDispatch=1");

    module = msvc;
    auto msvcDestroyed = resolve<volatile std::uint64_t*>("MsvcDestroyed");
    auto initialMsvc = *msvcDestroyed;
    capture("msvc-seh", "MsvcSeh", 1, 6, "MsvcSehDriver", driver("MsvcSehDriver", 6), 3 * 6 + 3 * 99, "NativeReturnDriver");
    capture("msvc-cxx", "MsvcCxx", 1, 4, "MsvcCxxDriver", driver("MsvcCxxDriver", 8), 4, "NativeReturnDriver");
    require(*msvcDestroyed - initialMsvc == 8, "MSVC exceptional exits skipped destructors");
    capture("msvc-catch", "MsvcCatch", 1, 6, "NativeReturnCaller", caller(resolve<Work>("MsvcCatch"), 6, 0), 8 + 10 + 12 + 1 + 3 + 5);
    std::uint64_t shrunk = 0;
    for (std::uint64_t value = 0; value < 8; ++value) {
        if (value < 4) { shrunk += value * 3; continue; }
        auto first = value * 2 + 1, second = (first ^ value) * 2 + 1, third = (second + value) * 2 + 1;
        shrunk += first + second + third + value;
    }
    capture("msvc-shrink", "MsvcShrink", 1, 8, "NativeReturnCaller", caller(shrink, 8, 0), shrunk);
    module = fixture;
    std::puts("RETURN_MSVC_OK seh=1 cxx=1 chained=1");

    // Software probes at arbitrary instruction offsets.
    probe("uprobe-body", "ReturnFramed", 5, 1, 4, "ReturnFramed", caller(framed, 4, 0), 6 + 4 * 2, "NativeReturnCaller");
    probe("uprobe-epilogue", "ReturnFramed", 9, 1, 3, "ReturnFramed", caller(framed, 3, 0), 3 + 3 * 2, "NativeReturnCaller");
    probe("uprobe-branch", "ReturnMultiple", 9, 2, 3, "ReturnMultiple", caller(resolve<Work>("ReturnMultiple"), 6, 0),
        (1 + 3 + 5) + 3 * 3 + (0 + 2 + 4) + 3 * 4, "NativeReturnCaller");
    // The same branch counts every execution as a uprobe.
    probe("uprobe-shrink-branch", "ReturnShrinkWrapped", 6, 1, 7, "ReturnShrinkWrapped", [&] {
        std::uint64_t sum = 0;
        for (std::uint64_t value : {0, 1, 0, 2, 0, 3, 0}) sum += NativeReturnCaller(resolve<Work>("ReturnShrinkWrapped"), 1, value);
        return sum;
    }, 6 + 7 + 8, "NativeReturnCaller");
    unprobed("ReturnFramed", 13, "inside an epilogue");
    unprobed("ReturnFramed", 14, "inside an epilogue");
    unprobed("ReturnFramed", 6, "not a proven instruction");
    unprobed("ReturnRecursive", 19, "call sites");
    faultingSource = reinterpret_cast<DWORD64>(resolve<const unsigned char*>("ReturnLoad") + 4);
    auto repairer = AddVectoredExceptionHandler(0, repairLoad);
    require(repairer != nullptr, "Install load repair handler");
    probe("uprobe-repaired", "ReturnLoad", 4, 1, 2, "ReturnLoad", [] {
        auto load = resolve<std::uint64_t (*)(const std::uint64_t*)>("ReturnLoad");
        std::uint64_t value = 5;
        return load(nullptr) + load(&value);
    }, 77 + 5, "NativeReturnCase");
    require(RemoveVectoredExceptionHandler(repairer) && repairs == 1, "Displaced load fault was not translated and resumed once");
    module = msvc;
    probe("uprobe-seh-fault", "MsvcSeh", 0, 1, 6, "MsvcSeh", driver("MsvcSehDriver", 6), 3 * 6 + 3 * 99, "MsvcSehDriver");
    probe("uprobe-jump", "MsvcSeh", 6, 1, 3, "MsvcSeh", driver("MsvcSehDriver", 6), 3 * 6 + 3 * 99, "MsvcSehDriver");
    module = fixture;
    std::puts("RETURN_UPROBE_PARITY_OK body=1 epilogueStart=1 branch=1 jump=1 faults=1 resumed=1 exitBranch=1");

    // rel8-only LOOPcc/JRCXZ forms run as rewritten copies: JRCXZ is taken for
    // zero, LOOP n - 1 times in a call. 2^32 is zero to the ECX forms only.
    auto loop = resolve<Work>("ReturnLoop"), loopEcx = resolve<Work>("ReturnLoopEcx");
    constexpr std::uint64_t high = std::uint64_t{1} << 32;
    probe("uprobe-jrcxz", "ReturnLoop", 2, 1, 4, "ReturnLoop", values(loop, {0, 3, 0, 2}), 6 + 3, "NativeReturnCaller");
    probe("uprobe-loop", "ReturnLoop", 7, 1, 5, "ReturnLoop", values(loop, {0, 3, 0, 2}), 6 + 3, "NativeReturnCaller");
    probe("uprobe-jecxz", "ReturnLoopEcx", 2, 1, 4, "ReturnLoopEcx", values(loopEcx, {high, high + 2, 3, 0}), 2 + 3,
        "NativeReturnCaller");
    probe("uprobe-loop-ecx", "ReturnLoopEcx", 8, 1, 5, "ReturnLoopEcx", values(loopEcx, {high, high + 2, 3, 0}), 2 + 3,
        "NativeReturnCaller");
    // Counter and ZF exits: LOOPE stops at the fourth iteration, LOOPNE before a multiple of four.
    probe("uprobe-loope", "ReturnLoopEqual", 9, 1, 2 + 4 + 4, "ReturnLoopEqual", values(resolve<Work>("ReturnLoopEqual"), {2, 9, 4, 0}),
        2 + 4 + 4, "NativeReturnCaller");
    probe("uprobe-loopne", "ReturnLoopNotEqual", 10, 1, 3 + 3 + 1, "ReturnLoopNotEqual",
        values(resolve<Work>("ReturnLoopNotEqual"), {6, 3, 8, 0}), 3 + 3 + 1, "NativeReturnCaller");
    auto stops = branchStep("ReturnLoop", 2, 2, 9, [](const CONTEXT& context) { return context.Rcx == 0; }, {0, 1}, 1, 2)
        + branchStep("ReturnLoop", 7, 2, 4, [](const CONTEXT& context) { return context.Rcx != 1; }, {2}, 3, 2)
        + branchStep("ReturnLoopEcx", 2, 3, 11, [](const CONTEXT& context) { return !static_cast<DWORD>(context.Rcx); },
            {high, high + 1}, 1, 2);
    // Without RTM the displaced XBEGIN raises #UD, reported at its source as unprobed;
    // with RTM, either the commit or the original abort target returns.
    auto transaction = resolve<Work>("ReturnTransaction");
    transactionSource = reinterpret_cast<DWORD64>(transaction);
    auto rtm = restrictedTransactionalMemory();
    auto outcome = [&](std::uint64_t value) {
        auto result = guardedTransaction(transaction, value);
        return rtm ? result == value + 5 || result == value + 9 : result == value + 100;
    };
    require(outcome(7), "Unprobed XBEGIN outcome");
    probe("uprobe-xbegin", "ReturnTransaction", 0, 1, 3, "ReturnTransaction", [&] {
        std::uint64_t outcomes = 0;
        for (std::uint64_t value : {1, 2, 3}) outcomes += outcome(value);
        return outcomes;
    }, 3, "NativeReturnCaller");
    require(undefinedTransactions == (rtm ? 0u : 4u), "XBEGIN #UD count changed");
    std::printf("RETURN_UPROBE_BRANCHES_OK loop=1 jrcxz=1 ecx=2 loope=1 loopne=1 stepped=3 displacedStops=%u xbegin=1 rtm=%u undefined=%u\n",
        stops, rtm ? 1u : 0u, undefinedTransactions);

    // Stop, restart and rearm of the same sites in consecutive recordings.
    for (unsigned round = 0; round < 3; ++round) {
        auto name = "rearm-" + std::to_string(round);
        capture(name.c_str(), "ReturnFramed", 1, 3 + round, "NativeReturnCaller", caller(framed, 3 + round, 0), (3 + round) * 2
            + (3 + round) * (2 + round) / 2);
    }
    // Existing and newly created threads, concurrently, with per-thread periods.
    capture("threads", "ReturnFramed", 2, 4 * 4 + 2, "NativeReturnCaller", [&] {
        Workers workers;
        for (unsigned index = 0; index < 4; ++index) {
            workers.threads.push_back(CreateThread(nullptr, 0, concurrentWorker, &workers, 0, nullptr));
            require(workers.threads.back() != nullptr, "Create return worker");
        }
        SetEvent(workers.start);
        auto own = NativeReturnCaller(framed, 5, 0);
        require(WaitForMultipleObjects(4, workers.threads.data(), TRUE, 10000) == WAIT_OBJECT_0, "Join return workers");
        for (auto thread : workers.threads) {
            DWORD exit;
            require(GetExitCodeThread(thread, &exit) && exit == 0, "Return worker result");
            CloseHandle(thread);
        }
        CloseHandle(workers.start);
        return own;
    }, 5 * 2 + 10, "");

    // An earlier trap still inside exception dispatch blocks rearm and is never counted later.
    release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    held = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    heldFunction = static_cast<const unsigned char*>(resolve<const void*>("ReturnFramed"));
    auto vectored = AddVectoredExceptionHandler(1, holdTrap);
    require(vectored != nullptr, "Install pending-trap holder");
    auto selector = std::string("uretprobe:") + fixtureName + "!ReturnFramed";
    command("start,event=" + selector + ",jfr,file=" + (directory / "held.jfr").string());
    holding = true;
    auto worker = CreateThread(nullptr, 0, heldWorker, std::bit_cast<void*>(framed), 0, nullptr);
    require(worker && WaitForSingleObject(held, 10000) == WAIT_OBJECT_0, "Hold one return trap in dispatch");
    command("stop");
    auto error = rejected("start,event=" + selector + ",jfr,file=" + (directory / "held-rearm.jfr").string());
    require(error.find("still being dispatched") != std::string::npos, error.c_str());
    SetEvent(release);
    require(WaitForSingleObject(worker, 10000) == WAIT_OBJECT_0, "Release held return trap");
    DWORD exit;
    require(GetExitCodeThread(worker, &exit) && exit == 42, "Held trap changed the return value");
    CloseHandle(worker);
    require(RemoveVectoredExceptionHandler(vectored) != 0, "Remove pending-trap holder");
    capture("after-held", "ReturnFramed", 1, 2, "NativeReturnCaller", caller(framed, 2, 0), 2 * 2 + 1);
    std::puts("RETURN_REARM_GATE_OK pending=1 released=1 uncounted=1");

    command("metrics");
    std::printf("%s", response.c_str());
    std::puts("SOFTWARE_RETURN_APPLICATION_OK");
    return 0;
}
