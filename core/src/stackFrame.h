/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _STACKFRAME_H
#define _STACKFRAME_H

#include <stdint.h>
using ucontext_t = CONTEXT;
#include "arch.h"


class NMethod;

class StackFrame {
  private:
    ucontext_t* _ucontext;

    bool withinCurrentStack(uintptr_t address) const {
        // Windows sampling can run on a different stack from the captured one.
        return address - _ucontext->Rsp <= 0xffff;
    }

  public:
    StackFrame(void* ucontext) {
        _ucontext = (ucontext_t*)ucontext;
    }

    uintptr_t stackAt(int slot) {
        return ((uintptr_t*)sp())[slot];
    }

    uintptr_t& pc();
    uintptr_t& sp();
    uintptr_t& fp();

    uintptr_t& retval();
    uintptr_t link();
    uintptr_t arg0();
    uintptr_t arg1();
    uintptr_t arg2();
    uintptr_t arg3();
    uintptr_t jarg0();
    uintptr_t method();
    uintptr_t senderSP();

    void ret();

    bool unwindStub(instruction_t* entry, const char* name, uintptr_t& pc, uintptr_t& sp, uintptr_t& fp);
    bool unwindAtomicStub(const void*& pc);

    bool unwindPrologue(NMethod* nm, uintptr_t& pc, uintptr_t& sp, uintptr_t& fp);
    bool unwindEpilogue(NMethod* nm, uintptr_t& pc, uintptr_t& sp, uintptr_t& fp);

    void adjustSP(const void* entry, const void* pc, uintptr_t& sp);

    bool checkInterruptedSyscall();

    // Check if PC points to a syscall instruction
    static bool isSyscall(instruction_t* pc);
};

#endif // _STACKFRAME_H
