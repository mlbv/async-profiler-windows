/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Replaces libgcc's ___chkstk_ms, which pushes RCX and RAX without unwind data. A
// probe that faults in a new stack page left ETW reading the saved RAX (the frame
// size) as the return address, so page-fault stacks of large profiler frames
// ended in a bogus caller.
asm(R"(
    .text
    .globl ___chkstk_ms
    .def ___chkstk_ms; .scl 2; .type 32; .endef
    .seh_proc ___chkstk_ms
___chkstk_ms:
    pushq %rcx
    .seh_pushreg %rcx
    pushq %rax
    .seh_pushreg %rax
    .seh_endprologue
    cmpq $0x1000, %rax
    leaq 24(%rsp), %rcx
    jb 2f
1:
    subq $0x1000, %rcx
    orq $0, (%rcx)
    subq $0x1000, %rax
    cmpq $0x1000, %rax
    ja 1b
2:
    subq %rax, %rcx
    orq $0, (%rcx)
    popq %rax
    popq %rcx
    ret
    .seh_endproc
)");
