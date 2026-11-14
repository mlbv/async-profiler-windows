/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include "allocTracer.h"
#include "profiler.h"
#include "stackFrame.h"
#include "tsc.h"
#include "vmStructs.h"
#ifdef _WIN32
#include "symbols.h"
#endif


int AllocTracer::_trap_kind;
Trap AllocTracer::_in_new_tlab(0);
Trap AllocTracer::_outside_tlab(1);

u64 AllocTracer::_interval;
volatile u64 AllocTracer::_allocated_bytes;


Error AllocTracer::initialize() {
    if (_in_new_tlab.entry() == 0 || _outside_tlab.entry() == 0) {
        CodeCache* libjvm = VMStructs::libjvm();
        const void* ne;
        const void* oe;

#ifdef _WIN32
        // PDB display names omit the prototype. Check the typed records before
        // choosing the register layout, including old by-value KlassHandle.
        const char* modern_new[] = {"void", "Klass*", "HeapWord*|HeapWordImpl**", "uint64", "uint64", "Thread*|JavaThread*"};
        const char* modern_outside[] = {"void", "Klass*", "HeapWord*|HeapWordImpl**", "uint64", "Thread*|JavaThread*"};
        const char* handle_new[] = {"void", "KlassHandle:8", "HeapWord*|HeapWordImpl**", "uint64", "uint64", "Thread*|JavaThread*"};
        const char* handle_outside[] = {"void", "KlassHandle:8", "HeapWord*|HeapWordImpl**", "uint64", "Thread*|JavaThread*"};
        const char* legacy_new[] = {"void", "KlassHandle:8", "uint64", "uint64"};
        const char* legacy_outside[] = {"void", "KlassHandle:8", "uint64"};
        Symbols::NativeFunction functions[] = {
            {"AllocTracer::send_allocation_in_new_tlab", modern_new, 6},
            {"AllocTracer::send_allocation_outside_tlab", modern_outside, 5},
            {"AllocTracer::send_allocation_in_new_tlab_event", handle_new, 6},
            {"AllocTracer::send_allocation_outside_tlab_event", handle_outside, 5},
            {"AllocTracer::send_allocation_in_new_tlab_event", legacy_new, 4},
            {"AllocTracer::send_allocation_outside_tlab_event", legacy_outside, 3},
        };
        if (!Symbols::findNativeFunctions(libjvm, functions, sizeof(functions) / sizeof(functions[0]))) {
            return Error("Cannot read matching JVM debug symbols; set ASYNC_PROFILER_SYMBOL_PATH to the exact jvm.dll PDB directory");
        }
        ne = oe = NULL;
        for (unsigned i = 0; i < 6; i += 2) {
            if (functions[i].address && functions[i + 1].address) {
                ne = functions[i].address;
                oe = functions[i + 1].address;
                _trap_kind = i == 4 ? 2 : 1;
                break;
            }
        }
        if (!ne || !oe) return Error("Unsupported AllocTracer function signatures in matching JVM debug symbols");
#else
        if ((ne = libjvm->findSymbolByPrefix("_ZN11AllocTracer27send_allocation_in_new_tlab")) != NULL &&
            (oe = libjvm->findSymbolByPrefix("_ZN11AllocTracer28send_allocation_outside_tlab")) != NULL) {
            _trap_kind = 1;  // JDK 10+
        } else if ((ne = libjvm->findSymbolByPrefix("_ZN11AllocTracer33send_allocation_in_new_tlab_eventE11KlassHandleP8HeapWord")) != NULL &&
                   (oe = libjvm->findSymbolByPrefix("_ZN11AllocTracer34send_allocation_outside_tlab_eventE11KlassHandleP8HeapWord")) != NULL) {
            _trap_kind = 1;  // JDK 8u262+
        } else if ((ne = libjvm->findSymbolByPrefix("_ZN11AllocTracer33send_allocation_in_new_tlab_event")) != NULL &&
                   (oe = libjvm->findSymbolByPrefix("_ZN11AllocTracer34send_allocation_outside_tlab_event")) != NULL) {
            _trap_kind = 2;  // JDK 7-9
        } else {
            return Error("No AllocTracer symbols found. Are JDK debug symbols installed?");
        }
#endif

        _in_new_tlab.assign(ne);
        _outside_tlab.assign(oe);
        _in_new_tlab.pair(_outside_tlab);
    }

    if (!_in_new_tlab.prepare() || !_outside_tlab.prepare()) {
        _in_new_tlab.release();
        _outside_tlab.release();
        return Error("Cannot prepare allocation breakpoints");
    }
    return Error::OK;
}

// Called whenever our breakpoint trap is hit
void AllocTracer::trapHandler(int signo, siginfo_t* siginfo, void* ucontext) {
    StackFrame frame(ucontext);
    EventType event_type;
    uintptr_t total_size;
    uintptr_t instance_size;

    // PC points either to BREAKPOINT instruction or to the next one
    if (_in_new_tlab.covers(frame.pc())) {
        // send_allocation_in_new_tlab(Klass* klass, HeapWord* obj, size_t tlab_size, size_t alloc_size, Thread* thread)
        // send_allocation_in_new_tlab_event(KlassHandle klass, size_t tlab_size, size_t alloc_size)
        event_type = ALLOC_SAMPLE;
        total_size = _trap_kind == 1 ? frame.arg2() : frame.arg1();
        instance_size = _trap_kind == 1 ? frame.arg3() : frame.arg2();
    } else if (_outside_tlab.covers(frame.pc())) {
        // send_allocation_outside_tlab(Klass* klass, HeapWord* obj, size_t alloc_size, Thread* thread)
        // send_allocation_outside_tlab_event(KlassHandle klass, size_t alloc_size);
        event_type = ALLOC_OUTSIDE_TLAB;
        total_size = _trap_kind == 1 ? frame.arg2() : frame.arg1();
        instance_size = 0;
    } else {
        // Not our trap
        Profiler::instance()->trapHandler(signo, siginfo, ucontext);
        return;
    }

    // Leave the trapped function by simulating "ret" instruction
    uintptr_t klass = frame.arg0();
    frame.ret();

    if (_enabled && updateCounter(_allocated_bytes, total_size, _interval)) {
        recordAllocation(ucontext, event_type, klass, total_size, instance_size);
    }
}

void AllocTracer::recordAllocation(void* ucontext, EventType event_type, uintptr_t rklass,
                                   uintptr_t total_size, uintptr_t instance_size) {
    AllocEvent event;
    event._start_time = TSC::ticks();
    event._total_size = total_size;
    event._instance_size = instance_size;

    if (VMStructs::hasClassNames()) {
        VMSymbol* symbol = VMKlass::fromHandle(rklass)->name();
        event.setClassName(symbol->body(), symbol->length());
    }

    Profiler::instance()->recordSample(ucontext, total_size, event_type, &event);
}

Error AllocTracer::start(Arguments& args) {
    if (args._live && !args._all) {
        // This engine is only going to be selected in Profiler::selectAllocEngine
        // when can_generate_sampled_object_alloc_events is not available, i.e. JDK<11.
        return Error("'live' option is supported on OpenJDK 11+");
    }

    Error error = initialize();
    if (error) return error;

    _interval = args._alloc > 0 ? args._alloc : 0;
    _allocated_bytes = 0;

    if (!_in_new_tlab.install() || !_outside_tlab.install()) {
        stop();
        return Error("Cannot install allocation breakpoints");
    }

    return Error::OK;
}

void AllocTracer::stop() {
    _in_new_tlab.release();
    _outside_tlab.release();
}
