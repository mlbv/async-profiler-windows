/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include <windows.h>
#include <cstdint>
#include <jni.h>

using Callback = void (*)(std::uint64_t);
using Work = std::uint64_t (*)(std::uint64_t);
extern "C" {
__declspec(dllexport) std::uint64_t ReturnLeaf(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnFramed(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnMultiple(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnTail(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnIndirectTail(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnImportTail(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnRecursive(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnSelfTail(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnFramePointer(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnFrameMove(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnRepeat(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnImmediateCaller(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnPassThrough(Work, std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnFaulting(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnJumpTable(std::uint64_t);
__declspec(dllexport) std::uint64_t ReturnInterior(std::uint64_t);
__declspec(dllexport) volatile std::uint64_t ReturnDestroyed = 0;
// Indirect tail-call slot used by ReturnImportTail's JMP [RIP+disp32].
__declspec(dllexport) std::uint64_t (*ReturnImportSlot)(std::uint64_t) = ReturnLeaf;
}

namespace {
struct Guard {
    ~Guard() { ReturnDestroyed = ReturnDestroyed + 1; }
};
}

// Compiled language-handler functions: destructors and catch clauses.
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t ReturnCxx(std::uint64_t value, Callback callback) {
    Guard guard;
    callback(value);
    return value + 6;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t ReturnCatch(std::uint64_t value, Callback callback) {
    try {
        callback(value);
        return value + 8;
    } catch (int thrown) {
        return static_cast<std::uint64_t>(thrown);
    }
}

// Throwing and catching stay inside this module's C++ runtime.
namespace {
void thrower(std::uint64_t value) { if (value & 1) throw static_cast<int>(value); }
std::uint64_t throwingWork(std::uint64_t value) {
    if (value & 1) throw static_cast<int>(value);
    return value + 13;
}
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t ReturnCxxDriver(unsigned count) {
    std::uint64_t returned = 0;
    for (unsigned index = 0; index < count; ++index) {
        try { returned += ReturnCxx(index, thrower) == index + 6; } catch (int) {}
    }
    return returned;
}
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t ReturnCatchDriver(unsigned count) {
    std::uint64_t sum = 0;
    for (unsigned index = 0; index < count; ++index) sum += ReturnCatch(index, thrower);
    return sum;
}

extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t ReturnPassThroughDriver(unsigned count) {
    std::uint64_t returned = 0;
    for (unsigned index = 0; index < count; ++index) {
        try { returned += ReturnPassThrough(throwingWork, index) == index + 13; } catch (int) {}
    }
    return returned;
}
extern "C" JNIEXPORT jlong JNICALL Java_SoftwareReturnJava_framed(JNIEnv*, jclass, jlong value) {
    return static_cast<jlong>(ReturnFramed(static_cast<std::uint64_t>(value)));
}
// Not a tail call: the JNI function keeps its own PE unwind row.
extern "C" JNIEXPORT __declspec(noinline) jlong JNICALL Java_SoftwareReturnJava_multiple(JNIEnv*, jclass, jlong value) {
    volatile auto result = ReturnMultiple(static_cast<std::uint64_t>(value));
    return static_cast<jlong>(result + 1);
}

__asm__(
    ".section .drectve,\"yn\"\n"
    ".ascii \" -export:ReturnLeaf -export:ReturnFramed -export:ReturnMultiple -export:ReturnTail -export:ReturnIndirectTail\"\n"
    ".ascii \" -export:ReturnImportTail -export:ReturnRecursive -export:ReturnSelfTail -export:ReturnFramePointer\"\n"
    ".ascii \" -export:ReturnFrameMove -export:ReturnRepeat -export:ReturnImmediate -export:ReturnImmediateCaller\"\n"
    ".ascii \" -export:ReturnPassThrough -export:ReturnFaulting -export:ReturnJumpTable -export:ReturnInterior -export:ReturnBare\"\n"
    ".ascii \" -export:ReturnLoad -export:ReturnShrinkWrapped -export:ReturnShrinkJump\"\n"
    ".ascii \" -export:ReturnLoop -export:ReturnLoopEcx -export:ReturnLoopEqual -export:ReturnLoopNotEqual -export:ReturnTransaction\"\n"
    ".text\n"
    // rel8-only branches: JRCXZ at +2 skips the loop for zero, LOOP at +7 sums n..1.
    ".p2align 4\n.globl ReturnLoop\n.seh_proc ReturnLoop\nReturnLoop:\n"
    ".seh_endprologue\n"
    "xorl %eax, %eax\n"
    "jrcxz 2f\n"
    "1:\n"
    "addq %rcx, %rax\n"
    "loop 1b\n"
    "2:\n"
    "ret\n"
    ".seh_endproc\n"
    // Address-size forms count in ECX: JECXZ at +2, LOOP at +8 counts ECX down.
    ".p2align 4\n.globl ReturnLoopEcx\n.seh_proc ReturnLoopEcx\nReturnLoopEcx:\n"
    ".seh_endprologue\n"
    "xorl %eax, %eax\n"
    "jecxz 2f\n"
    "1:\n"
    "incq %rax\n"
    ".byte 0x67\n"
    "loop 1b\n"
    "2:\n"
    "ret\n"
    ".seh_endproc\n"
    // LOOPE at +9 stops at the counter or at the fourth iteration.
    ".p2align 4\n.globl ReturnLoopEqual\n.seh_proc ReturnLoopEqual\nReturnLoopEqual:\n"
    ".seh_endprologue\n"
    "xorl %eax, %eax\n"
    "jrcxz 2f\n"
    "1:\n"
    "incq %rax\n"
    "testb $4, %al\n"
    "loope 1b\n"
    "2:\n"
    "ret\n"
    ".seh_endproc\n"
    // LOOPNE at +10 stops at the counter or before a multiple of four.
    ".p2align 4\n.globl ReturnLoopNotEqual\n.seh_proc ReturnLoopNotEqual\nReturnLoopNotEqual:\n"
    ".seh_endprologue\n"
    "xorl %eax, %eax\n"
    "jrcxz 2f\n"
    "1:\n"
    "incq %rax\n"
    "testb $3, %cl\n"
    "loopne 1b\n"
    "2:\n"
    "ret\n"
    ".seh_endproc\n"
    // XBEGIN at +0; XEND commits, an abort reaches its second return.
    ".p2align 4\n.globl ReturnTransaction\n.seh_proc ReturnTransaction\nReturnTransaction:\n"
    ".seh_endprologue\n"
    "xbegin 1f\n"
    "xend\n"
    "leaq 5(%rcx), %rax\n"
    "ret\n"
    "1:\n"
    "leaq 9(%rcx), %rax\n"
    "ret\n"
    ".seh_endproc\n"
    // Frameless: the RET itself is the only epilogue instruction.
    ".p2align 4\n.globl ReturnLeaf\n.seh_proc ReturnLeaf\nReturnLeaf:\n"
    ".seh_endprologue\n"
    "leaq 1(%rcx), %rax\n"
    "ret\n"
    ".seh_endproc\n"
    ".p2align 4\n.globl ReturnFramed\n.seh_proc ReturnFramed\nReturnFramed:\n"
    "pushq %rbx\n.seh_pushreg %rbx\n"
    "subq $32, %rsp\n.seh_stackalloc 32\n"
    ".seh_endprologue\n"
    "leaq 2(%rcx), %rax\n"
    "addq $32, %rsp\n"
    "popq %rbx\n"
    "ret\n"
    ".seh_endproc\n"
    // Two epilogues on separate paths.
    ".p2align 4\n.globl ReturnMultiple\n.seh_proc ReturnMultiple\nReturnMultiple:\n"
    "pushq %rbx\n.seh_pushreg %rbx\n"
    "pushq %rsi\n.seh_pushreg %rsi\n"
    "subq $40, %rsp\n.seh_stackalloc 40\n"
    ".seh_endprologue\n"
    "testb $1, %cl\n"
    "jz 1f\n"
    "leaq 3(%rcx), %rax\n"
    "addq $40, %rsp\n"
    "popq %rsi\n"
    "popq %rbx\n"
    "ret\n"
    "1:\n"
    "leaq 4(%rcx), %rax\n"
    "addq $40, %rsp\n"
    "popq %rsi\n"
    "popq %rbx\n"
    "ret\n"
    ".seh_endproc\n"
    // Direct tail call after a complete teardown.
    ".p2align 4\n.globl ReturnTail\n.seh_proc ReturnTail\nReturnTail:\n"
    "subq $40, %rsp\n.seh_stackalloc 40\n"
    ".seh_endprologue\n"
    "addq $3, %rcx\n"
    "addq $40, %rsp\n"
    "jmp ReturnLeaf\n"
    ".seh_endproc\n"
    // REX.W register tail call.
    ".p2align 4\n.globl ReturnIndirectTail\n.seh_proc ReturnIndirectTail\nReturnIndirectTail:\n"
    "pushq %rbx\n.seh_pushreg %rbx\n"
    ".seh_endprologue\n"
    "leaq ReturnLeaf(%rip), %rax\n"
    "addq $5, %rcx\n"
    "popq %rbx\n"
    "rex64 jmpq *%rax\n"
    ".seh_endproc\n"
    // Unprefixed JMP [RIP+disp32] tail call.
    ".p2align 4\n.globl ReturnImportTail\n.seh_proc ReturnImportTail\nReturnImportTail:\n"
    "subq $40, %rsp\n.seh_stackalloc 40\n"
    ".seh_endprologue\n"
    "addq $7, %rcx\n"
    "addq $40, %rsp\n"
    "jmpq *ReturnImportSlot(%rip)\n"
    ".seh_endproc\n"
    // Real recursion: every activation returns through the same epilogue.
    ".p2align 4\n.globl ReturnRecursive\n.seh_proc ReturnRecursive\nReturnRecursive:\n"
    "pushq %rbx\n.seh_pushreg %rbx\n"
    "subq $32, %rsp\n.seh_stackalloc 32\n"
    ".seh_endprologue\n"
    "movq %rcx, %rbx\n"
    "xorl %eax, %eax\n"
    "testq %rcx, %rcx\n"
    "jz 1f\n"
    "leaq -1(%rcx), %rcx\n"
    "call ReturnRecursive\n"
    "1:\n"
    "addq %rbx, %rax\n"
    "addq $32, %rsp\n"
    "popq %rbx\n"
    "ret\n"
    ".seh_endproc\n"
    // Tail recursion through the function's own entry.
    ".p2align 4\n.globl ReturnSelfTail\n.seh_proc ReturnSelfTail\nReturnSelfTail:\n"
    ".seh_endprologue\n"
    "testq %rcx, %rcx\n"
    "jz 1f\n"
    "decq %rcx\n"
    "jmp ReturnSelfTail\n"
    "1:\n"
    "movl $7, %eax\n"
    "ret\n"
    ".seh_endproc\n"
    // Frame-pointer epilogue after dynamic allocation: LEA RSP, [RBP+0].
    ".p2align 4\n.globl ReturnFramePointer\n.seh_proc ReturnFramePointer\nReturnFramePointer:\n"
    "pushq %rbp\n.seh_pushreg %rbp\n"
    "pushq %rbx\n.seh_pushreg %rbx\n"
    "subq $32, %rsp\n.seh_stackalloc 32\n"
    "leaq 32(%rsp), %rbp\n.seh_setframe %rbp, 32\n"
    ".seh_endprologue\n"
    "subq %rcx, %rsp\n"
    "andq $-16, %rsp\n"
    "leaq 9(%rcx), %rax\n"
    ".byte 0x48, 0x8d, 0x65, 0x00\n"
    "popq %rbx\n"
    "popq %rbp\n"
    "ret\n"
    ".seh_endproc\n"
    // MOV RSP, RBP teardown, which the OS unwinds as a body instruction.
    ".p2align 4\n.globl ReturnFrameMove\n.seh_proc ReturnFrameMove\nReturnFrameMove:\n"
    "pushq %rbp\n.seh_pushreg %rbp\n"
    "subq $48, %rsp\n.seh_stackalloc 48\n"
    "leaq 48(%rsp), %rbp\n.seh_setframe %rbp, 48\n"
    ".seh_endprologue\n"
    "subq %rcx, %rsp\n"
    "leaq 10(%rcx), %rax\n"
    "movq %rbp, %rsp\n"
    "popq %rbp\n"
    "ret\n"
    ".seh_endproc\n"
    ".p2align 4\n.globl ReturnRepeat\n.seh_proc ReturnRepeat\nReturnRepeat:\n"
    ".seh_endprologue\n"
    "leaq 11(%rcx), %rax\n"
    "rep ret\n"
    ".seh_endproc\n"
    // RET imm16 releases one caller-pushed quadword.
    ".p2align 4\n.globl ReturnImmediate\n.seh_proc ReturnImmediate\nReturnImmediate:\n"
    ".seh_endprologue\n"
    "movq 8(%rsp), %rax\n"
    "addq $12, %rax\n"
    "ret $8\n"
    ".seh_endproc\n"
    ".p2align 4\n.globl ReturnImmediateCaller\n.seh_proc ReturnImmediateCaller\nReturnImmediateCaller:\n"
    "pushq %rbp\n.seh_pushreg %rbp\n"
    "subq $32, %rsp\n.seh_stackalloc 32\n"
    "leaq 32(%rsp), %rbp\n.seh_setframe %rbp, 32\n"
    ".seh_endprologue\n"
    "pushq %rcx\n"
    "call ReturnImmediate\n"
    "nop\n"
    "addq $32, %rsp\n"
    "popq %rbp\n"
    "ret\n"
    ".seh_endproc\n"
    // Handler-free frame whose callee return address is the patched epilogue start.
    ".p2align 4\n.globl ReturnPassThrough\n.seh_proc ReturnPassThrough\nReturnPassThrough:\n"
    "pushq %rbx\n.seh_pushreg %rbx\n"
    "subq $32, %rsp\n.seh_stackalloc 32\n"
    ".seh_endprologue\n"
    "movq %rcx, %rax\n"
    "movq %rdx, %rcx\n"
    "call *%rax\n"
    "addq $32, %rsp\n"
    "popq %rbx\n"
    "ret\n"
    ".seh_endproc\n"
    // Tail call through a faulting memory operand.
    ".p2align 4\n.globl ReturnFaulting\n.seh_proc ReturnFaulting\nReturnFaulting:\n"
    "subq $40, %rsp\n.seh_stackalloc 40\n"
    ".seh_endprologue\n"
    "movq %rcx, %rax\n"
    "leaq 17(%rcx), %rcx\n"
    "addq $40, %rsp\n"
    "rex64 jmpq *(%rax)\n"
    ".seh_endproc\n"
    // A return reachable only through an unresolved indirect jump is rejected.
    ".p2align 4\n.globl ReturnJumpTable\n.seh_proc ReturnJumpTable\nReturnJumpTable:\n"
    ".seh_endprologue\n"
    "leaq 1f(%rip), %rax\n"
    "jmpq *%rax\n"
    "1:\n"
    "movl $3, %eax\n"
    "ret\n"
    ".seh_endproc\n"
    // A body load whose fault a later handler repairs and resumes.
    ".p2align 4\n.globl ReturnLoad\n.seh_proc ReturnLoad\nReturnLoad:\n"
    "subq $40, %rsp\n.seh_stackalloc 40\n"
    ".seh_endprologue\n"
    "movq (%rcx), %rax\n"
    "addq $40, %rsp\n"
    "ret\n"
    ".seh_endproc\n"
    // Shrink-wrapped early exit: a prolog-region JZ straight to the final RET.
    ".p2align 4\n.globl ReturnShrinkWrapped\n.seh_proc ReturnShrinkWrapped\nReturnShrinkWrapped:\n"
    "movq %rcx, %rax\n"
    "testq %rcx, %rcx\n"
    "jz 1f\n"
    "pushq %rbx\n.seh_pushreg %rbx\n"
    "subq $32, %rsp\n.seh_stackalloc 32\n"
    ".seh_endprologue\n"
    "leaq 5(%rcx), %rax\n"
    "addq $32, %rsp\n"
    "popq %rbx\n"
    "1:\n"
    "ret\n"
    ".seh_endproc\n"
    // A JMP after the first push enters the epilogue at that push's POP.
    ".p2align 4\n.globl ReturnShrinkJump\n.seh_proc ReturnShrinkJump\nReturnShrinkJump:\n"
    "pushq %rbx\n.seh_pushreg %rbx\n"
    "cmpq $1, %rcx\n"
    "jne 2f\n"
    "movl $9, %eax\n"
    "jmp 1f\n"
    "2:\n"
    "subq $32, %rsp\n.seh_stackalloc 32\n"
    ".seh_endprologue\n"
    "leaq 6(%rcx), %rax\n"
    "addq $32, %rsp\n"
    "1:\n"
    "popq %rbx\n"
    "ret\n"
    ".seh_endproc\n"
    // A leaf without an exception-directory row has no bounded coverage.
    ".p2align 4\n.globl ReturnBare\nReturnBare:\n"
    "leaq 1(%rcx), %rax\n"
    "ret\n"
    // A direct branch into an epilogue interior is rejected.
    ".p2align 4\n.globl ReturnInterior\n.seh_proc ReturnInterior\nReturnInterior:\n"
    "pushq %rbx\n.seh_pushreg %rbx\n"
    ".seh_endprologue\n"
    "testq %rcx, %rcx\n"
    "jz 1f\n"
    "popq %rbx\n"
    "1:\n"
    "ret\n"
    ".seh_endproc\n");
