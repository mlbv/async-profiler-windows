/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifdef __x86_64__

#include <errno.h>
#include "stackFrame.h"
#include "vmStructs.h"
#ifdef _WIN32
#include "windowsInstructionDecoder.h"
#endif


#define WIN_REG_RIP Rip
#define WIN_REG_RSP Rsp
#define WIN_REG_RBP Rbp
#define WIN_REG_RAX Rax
#define WIN_REG_RBX Rbx
#define WIN_REG_RCX Rcx
#define WIN_REG_RDX Rdx
#define WIN_REG_RDI Rdi
#define WIN_REG_RSI Rsi
#define WIN_REG_R8 R8
#define WIN_REG_R9 R9
#define WIN_REG_R10 R10
#define WIN_REG_R13 R13
#define REG(l, m) _ucontext->WIN_REG_##l


uintptr_t& StackFrame::pc() {
    return (uintptr_t&)REG(RIP, rip);
}

uintptr_t& StackFrame::sp() {
    return (uintptr_t&)REG(RSP, rsp);
}

uintptr_t& StackFrame::fp() {
    return (uintptr_t&)REG(RBP, rbp);
}

uintptr_t& StackFrame::retval() {
    return (uintptr_t&)REG(RAX, rax);
}

uintptr_t StackFrame::link() {
    // No link register on x86
    return 0;
}

uintptr_t StackFrame::arg0() {
    return (uintptr_t)REG(RCX, unused);
}

uintptr_t StackFrame::arg1() {
    return (uintptr_t)REG(RDX, unused);
}

uintptr_t StackFrame::arg2() {
    return (uintptr_t)REG(R8, unused);
}

uintptr_t StackFrame::arg3() {
    return (uintptr_t)REG(R9, unused);
}

uintptr_t StackFrame::jarg0() {
    // HotSpot's Java receiver uses c_rarg1 (RDX on Windows x64).
    return arg1();
}

uintptr_t StackFrame::method() {
    return (uintptr_t)REG(RBX, rbx);
}

uintptr_t StackFrame::senderSP() {
    return (uintptr_t)REG(R13, r13);
}

void StackFrame::ret() {
    pc() = stackAt(0);
    sp() += 8;
}


bool StackFrame::unwindStub(instruction_t* entry, const char* name, uintptr_t& pc, uintptr_t& sp, uintptr_t& fp) {
    instruction_t* ip = (instruction_t*)pc;
    if (ip == entry || *ip == 0xc3
        || startsWith(name, "itable")
        || startsWith(name, "vtable")
        || streq(name, "InlineCacheBuffer"))
    {
        pc = ((uintptr_t*)sp)[0] - 1;
        sp += 8;
        return true;
    } else if (entry != NULL && (*(unsigned int*)entry == 0xec8b4855 || *(unsigned int*)entry == 0xe5894855)) {
        // The stub begins with
        //   push rbp
        //   mov  rbp, rsp
        if (ip == entry + 1) {
            pc = ((uintptr_t*)sp)[1] - 1;
            sp += 16;
            return true;
        } else if (withinCurrentStack(fp)) {
            sp = fp + 16;
            fp = ((uintptr_t*)sp)[-2];
            pc = ((uintptr_t*)sp)[-1] - 1;
            return true;
        }
    }
    return false;
}

static inline bool isFrameComplete(instruction_t* entry, instruction_t* ip) {
    // Frame is fully constructed after rsp is decremented by the frame size.
    // Check if there is such an instruction anywhere between
    // the method entry and the current instruction pointer.
    for (ip -= 4; ip >= entry; ip--) {
        if (ip[0] == 0x48 && ip[2] == 0xec && (ip[1] & 0xfd) == 0x81) {  // sub rsp, frame_size
            return true;
        }
    }
    return false;
}

bool StackFrame::unwindPrologue(NMethod* nm, uintptr_t& pc, uintptr_t& sp, uintptr_t& fp) {
    //  0:   mov    %eax,-0x14000(%rsp)
    //  7:   push   %rbp
    //  8:   mov    %rsp,%rbp  ; for native methods only
    // 11:   sub    $0x50,%rsp
    instruction_t* ip = (instruction_t*)pc;
    instruction_t* entry = (instruction_t*)nm->entry();
#ifdef _WIN32
    // JVMCI prologues have no push rbp: the stack bang is followed by sub rsp,
    // and RBP keeps the caller's value until after the frame-complete marker.
    bool unpushed = entry[0] == 0x89 && entry[1] == 0x84 && entry[2] == 0x24
        && entry[7] == 0x48 && entry[9] == 0xec && (entry[8] & 0xfd) == 0x81;
    if (ip <= entry || (unpushed && ip == entry + 7) || *ip == 0x55 || nm->frameSize() == 0) {  // push rbp
#else
    if (ip <= entry || *ip == 0x55 || nm->frameSize() == 0) {  // push rbp
#endif
        pc = ((uintptr_t*)sp)[0] - 1;
        sp += 8;
        return true;
    } else if (ip <= entry + 15 && ip[-1] == 0x55) {  // right after push rbp
        pc = ((uintptr_t*)sp)[1] - 1;
        sp += 16;
        return true;
    } else if (ip <= entry + 31 && isFrameComplete(entry, ip)) {
        sp += nm->frameSize() * sizeof(void*);
#ifdef _WIN32
        if (!unpushed) fp = ((uintptr_t*)sp)[-2];
#else
        fp = ((uintptr_t*)sp)[-2];
#endif
        pc = ((uintptr_t*)sp)[-1];
        return true;
    }
    return false;
}

static inline bool isPollReturn(instruction_t* ip) {
    // JDK 17+
    //   pop    %rbp
    //   cmp    0x348(%r15),%rsp
    //   ja     offset_32
    //   ret
    if (ip[0] == 0x49 && ip[1] == 0x3b && (ip[2] == 0x67 || ip[2] == 0xa7) && ip[-1] == 0x5d) {
        // cmp, preceded by pop rbp
        return true;
    } else if (ip[0] == 0x0f && ip[1] == 0x87 && ip[6] == 0xc3) {
        // ja, followed by ret
        return true;
    }
#ifdef _WIN32
    // JVMCI frames have no saved RBP to pop: cmp follows add rsp,imm8/imm32
    if (ip[0] == 0x49 && ip[1] == 0x3b && (ip[2] == 0x67 || ip[2] == 0xa7)
            && ((ip[-4] == 0x48 && ip[-3] == 0x83 && ip[-2] == 0xc4) || (ip[-7] == 0x48 && ip[-6] == 0x81 && ip[-5] == 0xc4))) {
        return true;
    }
#endif

    // JDK 11
    //   pop    %rbp
    //   mov    0x108(%r15),%r10
    //   test   %eax,(%r10)
    //   ret
    if (ip[0] == 0x4d && ip[1] == 0x8b && ip[2] == 0x97 && ip[-1] == 0x5d) {
        // mov, preceded by pop rbp
        return true;
    } else if (ip[0] == 0x41 && ip[1] == 0x85 && ip[2] == 0x02 && ip[3] == 0xc3) {
        // test, followed by ret
        return true;
    }

    // JDK 8
    //   pop    %rbp
    //   test   %eax,offset(%rip)
    //   ret
    if (ip[0] == 0x85 && ip[1] == 0x05 && ip[6] == 0xc3) {
        // test, followed by ret
        return true;
    }

    return false;
}

bool StackFrame::unwindEpilogue(NMethod* nm, uintptr_t& pc, uintptr_t& sp, uintptr_t& fp) {
    //  add    $0x40,%rsp
    //  pop    %rbp
    //  {poll_return}
    //  ret
    instruction_t* ip = (instruction_t*)pc;
    if (*ip == 0xc3 || isPollReturn(ip)) {  // ret
        pc = ((uintptr_t*)sp)[0] - 1;
        sp += 8;
        return true;
    } else if (*ip == 0x5d) {  // pop rbp
        fp = ((uintptr_t*)sp)[0];
        pc = ((uintptr_t*)sp)[1] - 1;
        sp += 16;
        return true;
    }
    return false;
}

bool StackFrame::unwindAtomicStub(const void*& pc) {
    // Not needed
    return false;
}

#ifdef _WIN32
// movss/movsd between an XMM register and [rsp] (SSE F2/F3 [REX] 0F or VEX 0F map)
static size_t xmmAtRsp(const instruction_t* ip, instruction_t opcode) {
    size_t i;
    if (ip[0] == 0xc5) i = 2;
    else if (ip[0] == 0xc4 && (ip[1] & 0x1f) == 1) i = 3;
    else if (ip[0] == 0xf2 || ip[0] == 0xf3) {
        i = 1 + ((ip[1] & 0xf0) == 0x40);
        if (ip[i++] != 0x0f) return 0;
    } else return 0;
    return ip[i] == opcode && (ip[i + 1] & 0xc7) == 0x04 && ip[i + 2] == 0x24 ? i + 3 : 0;
}

// fld/fstp m32/m64 at [rsp]; group is 0 for fld, 3 for fstp
static size_t x87AtRsp(const instruction_t* ip, int group) {
    return (ip[0] == 0xd9 || ip[0] == 0xdd) && ip[1] == (0x04 | group << 3) && ip[2] == 0x24 ? 3 : 0;
}

static const instruction_t* skipNops(const instruction_t* ip) {
    while (true) {
        auto op = ip + (ip[0] == 0x66);
        if (op[0] == 0x90) ip = op + 1;
        else if (op[0] == 0x0f && op[1] == 0x1f) ip += WindowsProfiler::InstructionDecoder::length(ip, WindowsProfiler::InstructionDecoder::MAX_INSTRUCTION_BYTES);
        else return ip;
    }
}

// Graal's FREM/DREM (AMD64Arithmetic.FPDivRemOp) lowers RSP by 8 around an
// x87 FPREM loop: sub rsp,8; store y; fld; store x; fld; L: fprem; fwait;
// fnstsw ax; test eax,0x400; jnz L; fxch; ffree; fincstp; fstp; load; add rsp,8.
// Returns the add, or null when start does not begin that sequence.
static const instruction_t* remainderEnd(const instruction_t* start) {
    auto p = start;
    if (p[0] != 0x48 || p[1] != 0x83 || p[2] != 0xec || p[3] != 0x08) return NULL;
    p += 4;
    for (int operand = 0; operand < 2; operand++) {
        size_t n = xmmAtRsp(p, 0x11);
        if (n == 0) return NULL;
        p += n;
        if ((n = x87AtRsp(p, 0)) == 0) return NULL;
        p += n;
    }
    auto loop = p;
    if (p[0] != 0xd9 || p[1] != 0xf8 || p[2] != 0x9b || p[3] != 0xdf || p[4] != 0xe0) return NULL;
    p = skipNops(p + 5);
    if (p[0] == 0xa9 && *(const int*)(p + 1) == 0x400) p += 5;
    else if (p[0] == 0xf7 && p[1] == 0xc0 && *(const int*)(p + 2) == 0x400) p += 6;
    else return NULL;
    if (p[0] == 0x75 && p + 2 + (signed char)p[1] == loop) p += 2;
    else if (p[0] == 0x0f && p[1] == 0x85 && p + 6 + *(const int*)(p + 2) == loop) p += 6;
    else return NULL;
    if (p[0] != 0xd9 || p[1] != 0xc9 || p[2] != 0xdd || p[3] != 0xc0 || p[4] != 0xd9 || p[5] != 0xf7) return NULL;
    p += 6;
    size_t n = x87AtRsp(p, 3);
    if (n == 0) return NULL;
    p += n;
    if ((n = xmmAtRsp(p, 0x10)) == 0) return NULL;
    p += n;
    return p[0] == 0x48 && p[1] == 0x83 && p[2] == 0xc4 && p[3] == 0x08 ? p : NULL;
}

void StackFrame::adjustSP(const void* entry, const void* pc, uintptr_t& sp) {
    // The sequence is at most 80 bytes; RSP is lowered from after its sub up to its add.
    auto ip = (const instruction_t*)pc;
    auto first = (const instruction_t*)entry;
    for (auto start = ip - 4; start >= first && start > ip - 80; start--) {
        auto end = remainderEnd(start);
        if (end != NULL && ip <= end) {
            sp += 8;
            return;
        }
    }
}
#else
void StackFrame::adjustSP(const void* entry, const void* pc, uintptr_t& sp) {
    // Not needed
}
#endif

bool StackFrame::checkInterruptedSyscall() {
    return false; // No POSIX signal restart on Windows.
}

bool StackFrame::isSyscall(instruction_t* pc) {
    return pc[0] == 0x0f && pc[1] == 0x05;
}

#endif // __x86_64__
