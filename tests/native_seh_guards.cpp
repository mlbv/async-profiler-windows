/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Faults inside each SEH-guarded region must reach its handler: SafeAccess, the FP, PE-unwind and VM stack
// walkers, and the Java method probe. Without the guarded calls these faults terminate the process.
#include "../core/windows/java_windows.cpp"
#include "safeAccess.h"
#include "stackWalker.h"
#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }

struct StackStructs : VMStructs {
    static void enable() { _has_stack_structs = true; }
};

// A readable page followed by an inaccessible one
struct Pages {
    unsigned char* base;
    Pages() : base(static_cast<unsigned char*>(VirtualAlloc(nullptr, 2 * 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
        DWORD previous;
        require(base && VirtualProtect(base + 4096, 4096, PAGE_NOACCESS, &previous), "Cannot prepare guard pages");
    }
    ~Pages() { VirtualFree(base, 0, MEM_RELEASE); }
    std::uintptr_t readable() const { return reinterpret_cast<std::uintptr_t>(base) + 4096 - 16; }
    std::uintptr_t inaccessible() const { return reinterpret_cast<std::uintptr_t>(base) + 4096; }
};

// Outside every module and the code heap, so the walkers fall back to reading the stack directly
constexpr DWORD64 UNKNOWN_PC = 0x10000;

CONTEXT context(DWORD64 sp, DWORD64 fp) {
    CONTEXT result{};
    result.ContextFlags = CONTEXT_FULL;
    result.Rip = UNKNOWN_PC;
    result.Rsp = sp;
    result.Rbp = fp;
    return result;
}
}

// With an argument, runs only that case: safeaccess, fp, dwarf, vm or probe
int main(int argc, char** argv) try {
    auto selected = [&](const char* name) { return argc < 2 || std::strcmp(argv[1], name) == 0; };
    Pages pages;
    auto bad = reinterpret_cast<void**>(pages.inaccessible());
    int value = 7;
    void* word = &value;

    if (selected("safeaccess")) {
        require(SafeAccess::load(bad, &value) == &value, "SafeAccess::load did not return the fallback");
        require(SafeAccess::load(&word) == &value, "SafeAccess::load misread a valid word");
        require(SafeAccess::load32(reinterpret_cast<int32_t*>(bad), 3) == 3, "SafeAccess::load32 did not return the fallback");
        require(SafeAccess::load32(&value, 3) == 7, "SafeAccess::load32 misread a valid value");
    }

    const void* callchain[8];
    if (selected("fp")) {
        auto fpContext = context(pages.readable(), pages.inaccessible());
        require(StackWalker::walkFP(&fpContext, callchain, 8) == 1, "walkFP did not stop at the faulting frame pointer");
    }
    if (selected("dwarf")) {
        auto dwarfContext = context(pages.inaccessible(), 0);
        require(StackWalker::walkDwarf(&dwarfContext, callchain, 8) == 1, "walkDwarf did not stop at the faulting return address");
    }
    if (selected("vm")) {
        StackStructs::enable();
        ASGCT_CallFrame frames[8];
        auto vmContext = context(pages.inaccessible(), 0);
        int depth = StackWalker::walkVM(&vmContext, frames, 8, 0, StackWalkFeatures{}, EXECUTION_SAMPLE);
        require(depth > 0 && frames[depth - 1].bci == BCI_ERROR
                && std::strcmp(reinterpret_cast<const char*>(frames[depth - 1].method_id), "break_not_walkable") == 0,
                "walkVM did not report the fault as break_not_walkable");
    }
    if (selected("probe")) {
        // Any VMKlass field offset lands inside the inaccessible page; without a fault, index -1 succeeds
        WindowsProfiler::Java::MethodProbe probed{};
        require(!WindowsProfiler::Java::probe(reinterpret_cast<VMKlass*>(pages.inaccessible() + 2048), -1, probed),
                "probe did not report the fault");
    }
    std::puts("SEH guards passed");
    return 0;
} catch (const std::exception& error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
}
