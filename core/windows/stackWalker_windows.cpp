/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "stackWalker.h"
#include "stackFrame.h"
#include "profiler.h"
#include "safeAccess.h"
#include "vmStructs.h"
#include "windowsSeh.h"
#include "windowsInstructionDecoder.h"

namespace WindowsProfiler {
void captureContext(CONTEXT& context) {
    RtlCaptureContext(&context);
    auto base = reinterpret_cast<unsigned char*>(selfModule());
    auto pe = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
    auto begin = reinterpret_cast<std::uintptr_t>(base);
    auto end = begin + pe->OptionalHeader.SizeOfImage;
    ULONG_PTR low, high; GetCurrentThreadStackLimits(&low, &high);
    for (int i = 0; i < 64 && context.Rip >= begin && context.Rip < end; ++i) {
        if (context.Rsp < low || context.Rsp >= high) break;
        DWORD64 image;
        auto entry = WindowsProfiler::lookupFunctionEntry(context.Rip, &image);
        if (entry) {
            void* handler; DWORD64 establisher;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, context.Rip, entry, &context, &handler, &establisher, NULL);
        } else {
            context.Rip = *reinterpret_cast<DWORD64*>(context.Rsp);
            context.Rsp += sizeof(void*);
        }
    }
}
}

namespace {
// Walks read only the walked thread's committed stack [StackLimit, StackBase). Below it
// lies the thread's guard page and above it the next stack's reservation, whose low end
// holds HotSpot's guard zones; Windows disarms a guard page on first access, after which
// the owning thread's stack overflows unchecked.
// RtlVirtualUnwind reads the frame from RSP, or from the frame register's establisher once
// a frame-register prolog ran, up to the return address above every push and allocation,
// or a save slot. The frame must fit below the stack base.
bool unwindable(const CONTEXT& context, DWORD64 image, PRUNTIME_FUNCTION function, std::uintptr_t low, std::uintptr_t high) {
    if (context.Rsp < low || context.Rsp >= high) return false;
    auto unsigned16 = [](const unsigned char* at) { return std::uint64_t(at[0]) | std::uint64_t(at[1]) << 8; };
    auto unsigned32 = [&](const unsigned char* at) { return unsigned16(at) | unsigned16(at + 2) << 16; };
    std::uint64_t base = context.Rsp, size = sizeof(void*), saved = 0;
    for (;;) {
        auto info = reinterpret_cast<const unsigned char*>(image + function->UnwindData);
        unsigned count = info[2];
        auto codes = info + 4;
        if (unsigned frameRegister = info[3] & 15) {
            auto established = (&context.Rax)[frameRegister] - 16 * (info[3] >> 4);
            if (established < context.Rsp || established >= high) return false;
            base = std::max<std::uint64_t>(base, established);
        }
        for (unsigned index = 0; index < count;) {
            auto code = codes + 2 * index;
            unsigned operation = code[1] & 15, operand = code[1] >> 4;
            switch (operation) {
                case 0: size += 8; index += 1; break;
                case 1: size += operand ? unsigned32(code + 2) : 8 * unsigned16(code + 2); index += operand ? 3 : 2; break;
                case 2: size += 8 * operand + 8; index += 1; break;
                case 4: saved = std::max(saved, 8 * unsigned16(code + 2) + 8); index += 2; break;
                case 5: saved = std::max(saved, unsigned32(code + 2) + 8); index += 3; break;
                case 8: saved = std::max(saved, 16 * unsigned16(code + 2) + 16); index += 2; break;
                case 9: saved = std::max(saved, unsigned32(code + 2) + 16); index += 3; break;
                case 6: index += 2; break;
                case 10: size += operand ? 48 : 40; index += 1; break;
                default: index += 1; break;
            }
        }
        if (!((info[0] >> 3) & UNW_FLAG_CHAININFO)) break;
        function = reinterpret_cast<PRUNTIME_FUNCTION>(const_cast<unsigned char*>(codes) + ((count + 1) & ~1u) * 2);
    }
    return base + std::max(size, saved) <= high;
}

#include "../windows/walk_vm_body.inc"

int walkFilter(unsigned code) {
    return code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR || code == EXCEPTION_DATATYPE_MISALIGNMENT
            ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}
}

int StackWalker::walkVM(void* input, ASGCT_CallFrame* frames, int maximum, int, StackWalkFeatures features, EventType type) {
    if (maximum <= 0) return 0;
    CONTEXT captured;
    if (!input) { WindowsProfiler::captureContext(captured); input = &captured; }
    volatile int depth = 0;
    __try { return WindowsProfiler::guarded([&] { return walk_vm_body(input, frames, maximum, depth, features, type); }); }
    __except(walkFilter(GetExceptionCode())) {
        if (depth < maximum) fillFrame(frames[depth++], BCI_ERROR, "break_not_walkable");
        return depth;
    }
}

int StackWalker::walkFP(void* input, const void** output, int maximum) {
    CONTEXT captured;
    if (!input) { WindowsProfiler::captureContext(captured); input = &captured; }
    auto& context = *static_cast<CONTEXT*>(input);
    auto pc = reinterpret_cast<const void*>(context.Rip);
    auto sp = context.Rsp, fp = context.Rbp;
    std::uintptr_t low, high;
    WindowsProfiler::stackLimits(low, high);
    volatile int depth = 0;
    __try {
        WindowsProfiler::guarded([&] {
            while (depth < maximum && !inDeadZone(pc) && !CodeHeap::contains(pc)) {
                output[depth++] = pc;
                if (fp < sp || fp < low || fp + 2 * sizeof(void*) > high || fp >= sp + MAX_FRAME_SIZE
                        || fp >= context.Rsp + MAX_WALK_SIZE || !aligned(fp)) break;
                pc = reinterpret_cast<const void**>(fp)[1];
                sp = fp + 2 * sizeof(void*);
                fp = *reinterpret_cast<std::uintptr_t*>(fp);
            }
        });
    } __except(walkFilter(GetExceptionCode())) { }
    return depth;
}

int StackWalker::walkDwarf(void* input, const void** output, int maximum) {
    // PE/COFF exception unwind tables are Windows' native unwind metadata.
    CONTEXT context;
    if (input) context = *static_cast<CONTEXT*>(input); else WindowsProfiler::captureContext(context);
    DWORD64 initialSP = context.Rsp;
    std::uintptr_t low, high;
    WindowsProfiler::stackLimits(low, high);
    volatile int depth = 0;
    __try {
        WindowsProfiler::guarded([&] {
            while (depth < maximum && context.Rip && !CodeHeap::contains(reinterpret_cast<void*>(context.Rip))) {
                output[depth++] = reinterpret_cast<void*>(context.Rip);
                DWORD64 previousSP = context.Rsp, image;
                auto entry = WindowsProfiler::lookupFunctionEntry(context.Rip, &image);
                if (entry ? !unwindable(context, image, entry, low, high) : context.Rsp < low || context.Rsp + sizeof(void*) > high) break;
                if (entry) {
                    void* handler; DWORD64 establisher;
                    RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, context.Rip, entry, &context, &handler, &establisher, NULL);
                } else {
                    context.Rip = *reinterpret_cast<DWORD64*>(context.Rsp);
                    context.Rsp += sizeof(void*);
                }
                if (context.Rsp <= previousSP || context.Rsp >= previousSP + MAX_FRAME_SIZE || context.Rsp >= high
                        || context.Rsp >= initialSP + MAX_WALK_SIZE) break;
            }
        });
    } __except(walkFilter(GetExceptionCode())) { }
    return depth;
}
void StackWalker::checkFault() {} // SEH contains Windows stack-read faults locally.
