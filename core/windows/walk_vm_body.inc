/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Derived from upstream src/stackWalker.cpp; modified for Windows x86-64.
 */
const uintptr_t MAX_WALK_SIZE = 0x100000;
const intptr_t MAX_FRAME_SIZE = 0x40000;
const intptr_t MAX_INTERPRETER_FRAME_SIZE = 0x1000;
const intptr_t DEAD_ZONE = 0x1000;



static inline bool aligned(uintptr_t ptr) {
    return (ptr & (sizeof(uintptr_t) - 1)) == 0;
}

static inline bool inDeadZone(const void* ptr) {
    return ptr < (const void*)DEAD_ZONE || ptr > (const void*)-DEAD_ZONE;
}

// AArch64: on Linux, frame link is stored at the top of the frame,
// while on macOS, frame link is at the bottom.
static inline uintptr_t defaultSenderSP(uintptr_t sp, uintptr_t fp) {
#ifdef __APPLE__
    return sp + 2 * sizeof(void*);
#else
    return fp;
#endif
}

static inline void fillFrame(ASGCT_CallFrame& frame, ASGCT_CallFrameType type, const char* name) {
    frame.bci = type;
    frame.method_id = (jmethodID)name;
}

static inline void fillFrame(ASGCT_CallFrame& frame, ASGCT_CallFrameType type, u32 class_id) {
    frame.bci = type;
    frame.method_id = (jmethodID)(uintptr_t)class_id;
}

static inline void fillFrame(ASGCT_CallFrame& frame, FrameTypeId type, int bci, jmethodID method) {
    frame.bci = FrameType::encode(type, bci);
    frame.method_id = method;
}

static jmethodID getMethodId(VMMethod* method) {
    if (!inDeadZone(method) && aligned((uintptr_t)method)) {
        return method->validatedId();
    }
    return NULL;
}

// Whether a frame-complete nmethod has stored the caller RBP below its return
// address at pc. JVMCI prologues allocate the frame without push rbp, and Graal
// stores RBP there only in nmethods with debug information, as the first body
// instruction after the frame-complete entry barrier
// (AMD64HotSpotLIRGenerator.beforeRegisterAllocation); every call follows it.
// Before that store, and throughout nmethods without it, RBP is not saved and
// keeps the caller's value unless the register allocator reuses it.
static bool storedCallerRbp(NMethod* nm, const void* pc) {
    auto entry = (const unsigned char*)nm->entry();
    bool unpushed = entry[0] == 0x89 && entry[1] == 0x84 && entry[2] == 0x24
        && entry[7] == 0x48 && entry[9] == 0xec && (entry[8] & 0xfd) == 0x81;
    if (!unpushed) return true;
    auto slot = nm->frameSize() * (int)sizeof(void*) - 16;
    bool barrier = false;
    for (auto at = (const unsigned char*)nm->code() + nm->frameCompleteOffset(); at < (const unsigned char*)pc;) {
        auto length = WindowsProfiler::InstructionDecoder::length(at, WindowsProfiler::InstructionDecoder::MAX_INSTRUCTION_BYTES);
        if (length == 0) return false;
        // mov [rsp + disp8/disp32], rbp
        if (at[0] == 0x48 && at[1] == 0x89 && at[3] == 0x24) {
            if (length == 5 && at[2] == 0x6c) return (signed char)at[4] == slot;
            if (length == 8 && at[2] == 0xac) return *(const int*)(at + 4) == slot;
        }
        auto op = at + ((at[0] & 0xf0) == 0x40);
        bool jump = (op[0] >= 0x70 && op[0] <= 0x7f) || (op[0] == 0x0f && op[1] >= 0x80 && op[1] <= 0x8f);
        if (jump && barrier) {
            barrier = false;
        } else if (jump || op[0] == 0xe8 || op[0] == 0xe9 || op[0] == 0xeb || op[0] == 0xc2 || op[0] == 0xc3 || op[0] == 0xff) {
            return false;
        } else {
            // Entry-barrier compare against the thread's disarmed value
            barrier = at[0] == 0x41 && at[1] == 0x81 && (at[2] == 0x7f || at[2] == 0xbf);
        }
        at += length;
    }
    return false;
}


static int walk_vm_body(void* ucontext, ASGCT_CallFrame* frames, int max_depth, volatile int& depth,
                        StackWalkFeatures features, EventType event_type) {
    const void* pc;
    uintptr_t fp;
    uintptr_t sp;
    uintptr_t bottom;

    StackFrame frame(ucontext);
    pc = (const void*)frame.pc();
    fp = frame.fp();
    sp = frame.sp();
    CONTEXT native_context = *static_cast<CONTEXT*>(ucontext);
    // Reads stay within the walked thread's committed stack (see unwindable()), and as
    // upstream's, a walk ends MAX_WALK_SIZE above its first frame.
    uintptr_t low, high;
    WindowsProfiler::stackLimits(low, high);
    bottom = low <= sp && sp < high ? std::min<uintptr_t>(high, sp + MAX_WALK_SIZE) : sp;

    Profiler* profiler = Profiler::instance();
    int bcp_offset = InterpreterFrame::bcp_offset();

    depth = 0;

    // Show extended frame types and stub frames for execution-type events
    bool details = event_type <= MALLOC_SAMPLE || features.mixed;

    JavaFrameAnchor* anchor = NULL;
    // A frame restored from the anchor is stopped at a call into the VM, so a stub's frame there is complete.
    // Upstream unwinds it with the frame-pointer default frame, which matches only two-word stub frames;
    // Windows x64 stub frames also hold the register home area of their call.
    bool restored = false;
    VMThread* vm_thread = VMThread::current();
    if (vm_thread != NULL && vm_thread->isJavaThread()) {
        // For simple stack traces (e.g. for allocation profiling)
        // jump directly to the first Java frame
        if (details) {
            anchor = vm_thread->anchor();
        } else if (!vm_thread->anchor()->restoreFrame(pc, sp, fp)) {
            return 0;
        } else {
            restored = true;
        }
    }

    unwind_loop:
    uintptr_t prev_sp = sp;
    while (depth < max_depth) {
        // As an extra safety measure, verify stack pointer invariants on every iteration
        if (sp < prev_sp || sp >= bottom || !aligned(sp)) {
            fillFrame(frames[depth++], BCI_ERROR, "break_stack_range");
            break;
        }
        prev_sp = sp;

        CodeCache* native_lib = NULL;
        if (CodeHeap::contains(pc)) {
            NMethod* nm = CodeHeap::findNMethod(pc);
            if (nm == NULL) {
                if (anchor == NULL) {
                    // Add an error frame only if we cannot recover
                    fillFrame(frames[depth++], BCI_ERROR, "unknown_nmethod");
                }
                break;
            }

            // Always prefer JavaFrameAnchor when it is available,
            // since it provides reliable SP and FP.
            // Do not treat the topmost stub as Java frame.
            if (anchor != NULL && (depth > 0 || !nm->isStub())) {
                if (anchor->getFrame(pc, sp, fp) && !nm->contains(pc)) {
                    anchor = NULL;
                    continue;  // NMethod has changed as a result of correction
                }
                anchor = NULL;
            }

            if (nm->isInterpreter()) {
                if (vm_thread != NULL && vm_thread->inDeopt()) {
                    fillFrame(frames[depth++], BCI_ERROR, "break_deopt");
                    break;
                }

                bool is_plausible_interpreter_frame = !inDeadZone((const void*)fp) && aligned(fp)
                    && sp > fp - MAX_INTERPRETER_FRAME_SIZE
                    && sp < fp + bcp_offset * sizeof(void*)
                    && fp + std::min<int>(InterpreterFrame::method_offset, bcp_offset) * (intptr_t)sizeof(void*) >= low
                    && fp + 2 * sizeof(void*) <= bottom;

                if (is_plausible_interpreter_frame) {
                    VMMethod* method = ((VMMethod**)fp)[InterpreterFrame::method_offset];
                    jmethodID method_id = getMethodId(method);
                    if (method_id != NULL) {
                        const char* bytecode_start = method->bytecode();
                        const char* bcp = ((const char**)fp)[bcp_offset];
                        int bci = bytecode_start == NULL || bcp < bytecode_start ? 0 : bcp - bytecode_start;
                        fillFrame(frames[depth++], FRAME_INTERPRETED, bci, method_id);

                        sp = ((uintptr_t*)fp)[InterpreterFrame::sender_sp_offset];
                        if (sp < fp + 2 * sizeof(void*)) {
                            sp = fp + 2 * sizeof(void*);
                        }
                        pc = stripPointer(((void**)fp)[FRAME_PC_SLOT]);
                        fp = *(uintptr_t*)fp;
                        continue;
                    }
                }

                if (depth == 0) {
                    VMMethod* method = (VMMethod*)frame.method();
                    jmethodID method_id = getMethodId(method);
                    if (method_id != NULL) {
                        fillFrame(frames[depth++], FRAME_INTERPRETED, 0, method_id);

                        if (is_plausible_interpreter_frame) {
                            pc = stripPointer(((void**)fp)[FRAME_PC_SLOT]);
                            sp = frame.senderSP();
                            fp = *(uintptr_t*)fp;
                        } else {
                            pc = stripPointer(*(void**)sp);
                            sp = frame.senderSP();
                        }
                        continue;
                    }
                }

                fillFrame(frames[depth++], BCI_ERROR, "break_interpreted");
                break;
            } else if (nm->isNMethod()) {
                int level = nm->level();
                FrameTypeId type = details && level >= 1 && level <= 3 ? FRAME_C1_COMPILED : FRAME_JIT_COMPILED;
                fillFrame(frames[depth++], type, 0, nm->method()->id());

                bool frameless = nm->isFrameless();
                if (frameless || nm->isFrameCompleteAt(pc)) {
                    if (!frameless && depth == 1 && frame.unwindEpilogue(nm, (uintptr_t&)pc, sp, fp)) {
                        continue;
                    }

                    int scope_offset = nm->findScopeOffset(pc);
                    if (scope_offset > 0) {
                        depth--;
                        ScopeDesc scope(nm);
                        do {
                            scope_offset = scope.decode(scope_offset);
                            if (details) {
                                type = scope_offset > 0 ? FRAME_INLINED :
                                       level >= 1 && level <= 3 ? FRAME_C1_COMPILED : FRAME_JIT_COMPILED;
                            }
                            fillFrame(frames[depth++], type, scope.bci(), scope.method()->id());
                        } while (scope_offset > 0 && depth < max_depth);
                    }

                    if (frameless) {
                        pc = *reinterpret_cast<const void**>(sp);
                        sp += sizeof(void*);
                        continue;
                    }

                    // Handle situations when sp is temporarily changed in the compiled code
                    frame.adjustSP(nm->entry(), pc, sp);

                    bool stored = storedCallerRbp(nm, pc);
                    sp += nm->frameSize() * sizeof(void*);
                    if (stored) fp = ((uintptr_t*)sp)[-FRAME_PC_SLOT - 1];
                    pc = ((const void**)sp)[-FRAME_PC_SLOT];
                    continue;
                } else if (frame.unwindPrologue(nm, (uintptr_t&)pc, sp, fp)) {
                    continue;
                }

                fillFrame(frames[depth++], BCI_ERROR, "break_compiled");
                break;
            } else if (nm->isEntryFrame(pc) && !features.mixed) {
                JavaFrameAnchor* next_anchor;
                if (fp < sp || fp >= bottom || !aligned(fp) || (next_anchor = JavaFrameAnchor::fromEntryFrame(fp)) == NULL) {
                    fillFrame(frames[depth++], BCI_ERROR, "break_entry_frame");
                    break;
                }
                if (!next_anchor->getFrame(pc, sp, fp)) {
                    // End of Java stack
                    break;
                }
                continue;
            } else {
                if (features.vtable_target && nm->isVTableStub() && depth == 0) {
                    uintptr_t receiver = frame.jarg0();
                    if (receiver != 0) {
                        VMSymbol* symbol = VMKlass::fromOop(receiver)->name();
                        u32 class_id = WindowsProfiler::lookupJavaClass(profiler->classMap(), std::string_view(symbol->body(), symbol->length()));
                        fillFrame(frames[depth++], BCI_ALLOC, class_id);
                    }
                }

                CodeBlob* stub = profiler->findRuntimeStub(pc);
                const void* start = stub != NULL ? stub->_start : nm->code();
                const char* name = stub != NULL ? stub->_name : nm->name();

                if (details) {
                    fillFrame(frames[depth++], BCI_NATIVE_FRAME, name);
                }

                if (startsWith(name, "cont") || startsWith(name, "Cont ")) {
                    // Walking past virtual thread continuation barriers is not currently supported
                    break;
                }

                if (frame.unwindStub((instruction_t*)start, name, (uintptr_t&)pc, sp, fp)) {
                    continue;
                }

                // A sampled stub frame is complete past its marker except in the
                // epilogue, as for nmethods. JVMCI stubs have no push rbp prologue.
                bool complete = nm->frameSize() > 0 && nm->isFrameCompleteAt(pc);
                if (complete && depth <= 1 && !restored && frame.unwindEpilogue(nm, (uintptr_t&)pc, sp, fp)) {
                    continue;
                }
                if (nm->frameSize() > 0 && (depth > 1 || restored || complete)) {
                    sp += nm->frameSize() * sizeof(void*);
                    fp = ((uintptr_t*)sp)[-FRAME_PC_SLOT - 1];
                    pc = ((const void**)sp)[-FRAME_PC_SLOT];
                    if (inDeadZone(pc)) {
                        fillFrame(frames[depth++], BCI_ERROR, "break_stub");
                        break;
                    }
                    continue;
                }
            }
        } else {
            native_lib = profiler->findLibraryByAddress(pc);
            const char* method_name = native_lib != NULL ? native_lib->binarySearch(pc) : NULL;
            char mark;
            if (method_name != NULL && (mark = NativeFunc::mark(method_name)) != 0) {
                if (mark == MARK_ASYNC_PROFILER && (event_type == MALLOC_SAMPLE || event_type == NATIVE_LOCK_SAMPLE)) {
                    // Skip all internal frames above hook functions, leave the hook itself
                    depth = 0;
                } else if (mark == MARK_COMPILER_ENTRY && features.comp_task && vm_thread != NULL) {
                    // Insert current compile task as a pseudo Java frame
                    VMMethod* method = vm_thread->compiledMethod();
                    jmethodID method_id = method != NULL ? method->id() : NULL;
                    if (method_id != NULL) {
                        fillFrame(frames[depth++], FRAME_JIT_COMPILED, 0, method_id);
                    }
                }
            }
            if (method_name != NULL) {
                fillFrame(frames[depth++], BCI_NATIVE_FRAME, method_name);
            } else {
                frames[depth++] = {BCI_ADDRESS,0,reinterpret_cast<jmethodID>(const_cast<void*>(pc))};
            }
        }

        const void* prev_pc = pc;
        native_context.Rip = (DWORD64)pc;
        native_context.Rsp = sp;
        native_context.Rbp = fp;
        DWORD64 image;
        auto function = WindowsProfiler::lookupFunctionEntry(native_context.Rip, &image);
        if (function && !unwindable(native_context, image, function, low, high)) break;
        if (function) {
            void* handler;
            DWORD64 establisher;
            RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, native_context.Rip, function, &native_context, &handler, &establisher, nullptr);
        } else {
            native_context.Rip = *(DWORD64*)native_context.Rsp;
            native_context.Rsp += sizeof(void*);
        }
        pc = (const void*)native_context.Rip;
        sp = native_context.Rsp;
        fp = native_context.Rbp;
        if (sp < prev_sp || sp >= prev_sp + MAX_FRAME_SIZE || sp >= bottom || !aligned(sp)
                || inDeadZone(pc) || (pc == prev_pc && sp == prev_sp)) break;

    }

    // If we did not meet Java frame but current thread has JavaFrameAnchor set,
    // retry stack walking from the anchor
    if (anchor != NULL && anchor->getFrame(pc, sp, fp)) {
        anchor = NULL;
        while (depth > 0 && frames[depth - 1].method_id == NULL) depth--;  // pop unknown frames
        goto unwind_loop;
    }


    return depth;
}
