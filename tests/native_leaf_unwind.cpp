/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsLeafUnwind.h"
#include "windowsInstructionDecoder.h"
#include <windows.h>
#include <cassert>
#include <cstdio>
#include <cstring>


int main() {
    // GraalVM 21 code for EtwJavaSmoke.adapterTarget; context tests never execute it.
    std::vector<unsigned char> code{0x89,0x84,0x24,0x00,0x80,0xff,0xff,0x48,0x83,0xec,0x38,0x90,0x41,0x81,0x7f,0x20,0x01,0x00,0x00,0x00,0x0f,0x85,0x2e,0x00,0x00,0x00,0x48,0x81,0xf2,0x0b,0x27,0xed,0x51,0x48,0xc1,0xc2,0x07,0x48,0xb8,0xb3,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x48,0x0f,0xaf,0xd0,0x48,0x8b,0xc2,0x48,0x83,0xc4,0x38,0x49,0x3b,0xa7,0x50,0x04,0x00,0x00,0x0f,0x87,0x0e,0x00,0x00,0x00,0xc3,0x48,0x89,0x6c,0x24,0x30,0xe8,0xce,0xb9,0x4f,0xff,0xeb,0xc6,0xf4,0x48,0x8d,0x0d,0xde,0xff,0xff,0xff,0x49,0x89,0x8f,0x68,0x04,0x00,0x00,0xe9,0x98,0xcb,0x51,0xff,0xf4,0xe8,0x12,0x9c,0x97,0xff,0x90,0xe8,0x4c,0xe2,0x51,0xff,0x90,0xf4,0xf4,0xf4};
    assert(code.size() == 120);
    WindowsProfiler::InstructionDecoder::initialize();
    using WindowsProfiler::JavaUnwind::Leaf::savedRbpSlot;
    assert(!savedRbpSlot(code.data(),code.size(),0,12,56));
    const unsigned char conventional[]{0x89,0x84,0x24,0,0x80,0xff,0xff,0x55,0x48,0x83,0xec,0x30};
    assert(savedRbpSlot(conventional,sizeof(conventional),0,sizeof(conventional),56));
    assert(!savedRbpSlot(conventional,sizeof(conventional),0,sizeof(conventional),64));
    assert(!savedRbpSlot(conventional,sizeof(conventional),0,sizeof(conventional) - 1,56));
    const unsigned char framePointer[]{0x55,0x48,0x8b,0xec,0x48,0x83,0xec,0x30};
    assert(savedRbpSlot(framePointer,sizeof(framePointer),0,sizeof(framePointer),56));
    const unsigned char unsupported[]{0x55,0x48,0xc3};
    assert(!savedRbpSlot(unsupported,sizeof(unsupported),0,sizeof(unsupported),56));
    auto c1 = std::vector<unsigned char>(conventional,conventional + sizeof(conventional));
    c1.insert(c1.end(),{0x41,0x81,0x7f,0x20,1,0,0,0,0x74,5,0xe8,0,0,0,0});
    assert(savedRbpSlot(c1.data(),c1.size(),0,c1.size(),56));
    auto realigned = std::vector<unsigned char>(conventional,conventional + sizeof(conventional));
    realigned.insert(realigned.end(),{0x48,0x83,0xe4,0xf0});
    assert(!savedRbpSlot(realigned.data(),realigned.size(),0,realigned.size(),56));
    using WindowsProfiler::JavaUnwind::Leaf::prologueEnd;
    unsigned prologueChecks = 0;
    auto prologue = [&](std::vector<unsigned char> bytes,std::size_t entry,std::size_t complete,std::uint32_t allocation,std::size_t end) {
        assert(prologueEnd(bytes.data(),bytes.size(),entry,allocation) == end);
        assert(savedRbpSlot(bytes.data(),bytes.size(),entry,complete,allocation) == (end != 0));
        ++prologueChecks;
    };
    // Temurin 25 C2 OSR nmethods: INT3-poisoned verified entry, OSR prologue at 16.
    std::vector<unsigned char> osrPush{0xcc,0x0f,0x1f,0x84,0,0,0,0,0,0x0f,0x1f,0x80,0,0,0,0,
        0x89,0x84,0x24,0,0x80,0xff,0xff,0x55,0x48,0x83,0xec,0x40,0x41,0x81,0x7f,0x20,1,0,0,0,0x0f,0x85,0x10,2,0,0};
    prologue(osrPush,16,42,72,28);
    prologue(osrPush,0,42,72,0);
    prologue(osrPush,16,42,64,0);
    std::vector<unsigned char> osrStore{0xcc,0x0f,0x1f,0x84,0,0,0,0,0,0x0f,0x1f,0x80,0,0,0,0,
        0x48,0x81,0xec,0x38,0,0,0,0x48,0x89,0x6c,0x24,0x30,0x41,0x81,0x7f,0x20,1,0,0,0,0x0f,0x85,0x1c,2,0,0};
    prologue(osrStore,16,42,56,28);
    // Temurin 27 uses the short SUB and pads with a prefixed NOP before its barrier.
    std::vector<unsigned char> shortStore{0x48,0x83,0xec,0x38,0x48,0x89,0x6c,0x24,0x30,0x66,0x66,0x90,
        0x41,0x81,0x7f,0x20,1,0,0,0,0x0f,0x85,0x1c,2,0,0};
    prologue(shortStore,0,shortStore.size(),56,9);
    auto wrongSlot = shortStore; wrongSlot[8] = 0x28;
    prologue(wrongSlot,0,wrongSlot.size(),56,0);
    auto negativeSlot = shortStore; negativeSlot[8] = 0xf0;
    prologue(negativeSlot,0,negativeSlot.size(),56,0);
    auto wrongReserve = shortStore; wrongReserve[3] = 0x30;
    prologue(wrongReserve,0,wrongReserve.size(),56,0);
    std::vector<unsigned char> farStore{0x48,0x81,0xec,0x00,0x01,0,0,0x48,0x89,0xac,0x24,0xf8,0,0,0};
    prologue(farStore,0,farStore.size(),256,15);
    // The push form completes at its SUB; a later store is not a frame step.
    std::vector<unsigned char> mixed{0x55,0x48,0x83,0xec,0x30,0x48,0x89,0x6c,0x24,0x30};
    assert(prologueEnd(mixed.data(),mixed.size(),0,56) == 5 && !savedRbpSlot(mixed.data(),mixed.size(),0,mixed.size(),56));
    ++prologueChecks;
    // RBP must be saved before a guard can leave the prologue.
    prologue({0x48,0x83,0xec,0x38,0x0f,0x85,0,0,0,0,0x48,0x89,0x6c,0x24,0x30},0,15,56,0);
    // C1 frame setup is the same at its verified and OSR entries.
    prologue({0x89,0x84,0x24,0,0x80,0xff,0xff,0x55,0x48,0x83,0xec,0x60,0x41,0x81,0x7f,0x20,1,0,0,0,0x74,5,0xe8,0,0,0,0},0,27,104,12);
    prologue({0x55,0x48,0x8b,0xec,0x66,0x0f,0x1f,0x44,0,0},0,10,8,1);
    std::vector<WindowsProfiler::JavaUnwind::Leaf::Span> spans;
    assert(WindowsProfiler::JavaUnwind::Leaf::preservedRbp(code.data(),code.size(),56,spans));
    assert(spans.size() == 3);
    assert(spans[0].begin == 0 && spans[0].end == 11 && spans[0].returnOffset == 0);
    assert(spans[1].begin == 11 && spans[1].end == 58 && spans[1].returnOffset == 56);
    assert(spans[2].begin == 58 && spans[2].end == 72 && spans[2].returnOffset == 0);
    auto page = static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    assert(page);
    std::memcpy(page,code.data(),code.size());
    unsigned tests = 0;
    constexpr DWORD64 originalRbp = 0x1122334455667788, callerIp = 0x12345678;
    DWORD64 stack[256];
    for (auto& value : stack) value = 0xbad0bad0bad0bad0;
    auto returnAddress = stack + 128;
    *returnAddress = callerIp;
    for (const auto& span : spans) {
        auto info = page + 4096;
        std::memset(info,0,16);
        info[0] = 2;
        if (span.returnOffset) {
            info[2] = 1;
            info[5] = static_cast<unsigned char>(((span.returnOffset / 8 - 1) << 4) | 2);
        }
        RUNTIME_FUNCTION function{span.begin,span.end,4096};
        for (auto offset = span.begin; offset < span.end; ++offset) {
            CONTEXT context{};
            context.Rip = reinterpret_cast<DWORD64>(page + offset);
            context.Rsp = reinterpret_cast<DWORD64>(returnAddress) - span.returnOffset;
            context.Rbp = originalRbp;
            void* handler;
            DWORD64 establisher;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(page),context.Rip,&function,&context,&handler,&establisher,nullptr);
            assert(context.Rip == callerIp);
            assert(context.Rsp == reinterpret_cast<DWORD64>(returnAddress + 1));
            assert(context.Rbp == originalRbp);
            ++tests;
        }
    }
    // The old fixed save-slot rule reads a slot this Graal leaf never writes.
    auto oldInfo = page + 4096;
    const unsigned char oldBytes[]{2,0,2,0,0,0x52,0,0x50};
    std::memcpy(oldInfo,oldBytes,sizeof(oldBytes));
    RUNTIME_FUNCTION oldFunction{0,120,4096};
    for (auto offset : {11u,12u,54u}) {
        CONTEXT context{};
        context.Rip = reinterpret_cast<DWORD64>(page + offset);
        context.Rsp = reinterpret_cast<DWORD64>(returnAddress) - 56;
        context.Rbp = originalRbp;
        void* handler;
        DWORD64 establisher;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(page),context.Rip,&oldFunction,&context,&handler,&establisher,nullptr);
        assert(context.Rbp != originalRbp);
    }
    auto reject = [&](std::vector<unsigned char> changed,std::uint32_t allocation = 56) {
        std::vector<WindowsProfiler::JavaUnwind::Leaf::Span> rejected;
        assert(!WindowsProfiler::JavaUnwind::Leaf::preservedRbp(changed.data(),changed.size(),allocation,rejected));
        assert(rejected.empty());
    };
    auto changed = code;
    changed[0x34] = 0x8b; changed[0x35] = 0xea; // mov rbp,rdx
    reject(changed);
    changed = code; changed[0x1a] = 0xe8; // A call cannot preserve an untracked caller RBP.
    reject(changed);
    reject(code,48);
    changed = code; changed.resize(71); reject(changed);
    changed = code; changed[0x16] = 0; changed[0x17] = 0; changed[0x18] = 0; changed[0x19] = 0; reject(changed);
    VirtualFree(page,0,MEM_RELEASE);
    std::printf("LEAF_PC_RULES_OK contexts=%u oldRuleFailures=3 negativeLayouts=5 prologues=%u\n",tests,prologueChecks);
}
