/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsCompiledUnwind.h"
#include "native_compiled_unwind_oracle.h"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>

using namespace WindowsProfiler::JavaUnwind::Compiled;
namespace {
using Bytes = std::vector<unsigned char>;
unsigned checks, cases, faults, continuations, unwindContexts;
void require(bool condition,const char* message) {
    ++checks;
    if (!condition) { std::fprintf(stderr,"COMPILED_FAULT_EXECUTION_FAILURE %s\n",message); std::exit(1); }
}
const Span& at(const std::vector<Span>& spans,std::size_t pc) {
    for (const auto& span : spans) if (pc >= span.begin && pc < span.end) return span;
    std::abort();
}
void append(Bytes& code,std::initializer_list<unsigned char> bytes) { code.insert(code.end(),bytes); }
struct Observation { DWORD64 sp = 0, rbp = 0, ip = 0, restoredRbp = 0, restoredSp = 0; };
struct Execution {
    unsigned char* page;
    Observation observed;
    std::vector<Span> spans;
    unsigned source, target, allocation;
    DWORD exception, thread;
    DWORD64 rax, rdx;
    bool saved, precise, access, write;
    unsigned faults = 0, continuations = 0;
};
Execution* current;
void unwind(const CONTEXT& actual,unsigned offset) {
    auto& execution = *current;
    auto context = actual;
    const auto& span = at(execution.spans,offset);
    require(span.proven,"Executed context has no frame proof");
    auto info = execution.page + 4096;
    unwindInfo(info,span);
    RUNTIME_FUNCTION function{span.begin,span.end,4096};
    void* handler;
    DWORD64 establisher;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(execution.page),context.Rip,
        &function,&context,&handler,&establisher,nullptr);
    require(context.Rip == execution.observed.ip,"Actual exception context lost its caller PC");
    require(context.Rsp == execution.observed.sp + 8,"Actual exception context lost its caller SP");
    require(context.Rbp == execution.observed.rbp,"Actual exception context lost its caller RBP");
    ++unwindContexts;
}
LONG CALLBACK handle(EXCEPTION_POINTERS* pointers) {
    auto execution = current;
    if (!execution) return EXCEPTION_CONTINUE_SEARCH;
    auto& context = *pointers->ContextRecord;
    auto source = reinterpret_cast<DWORD64>(execution->page + execution->source);
    auto target = reinterpret_cast<DWORD64>(execution->page + execution->target);
    if ((context.Rip != source && context.Rip != target) || GetCurrentThreadId() != execution->thread
            || reinterpret_cast<DWORD64>(pointers->ExceptionRecord->ExceptionAddress) != context.Rip)
        return EXCEPTION_CONTINUE_SEARCH;
    require(context.Rsp == execution->observed.sp - execution->allocation,"Fault changed the allocated stack");
    require(context.Rbp == (execution->saved ? 0 : execution->observed.rbp),"Fault committed its RBP destination");
    require(context.Rax == execution->rax && context.Rdx == execution->rdx,"Fault committed arithmetic destinations");
    if (context.Rip == source) {
        require(execution->faults++ == 0,"Fault source executed twice");
        if (pointers->ExceptionRecord->ExceptionCode != execution->exception)
            std::fprintf(stderr,"case=%u expectedException=%08lx actualException=%08lx source=%u\n",
                cases,execution->exception,pointers->ExceptionRecord->ExceptionCode,execution->source);
        require(pointers->ExceptionRecord->ExceptionCode == execution->exception,"Unexpected synchronous exception");
        if (execution->access) {
            require(pointers->ExceptionRecord->NumberParameters >= 2,"Access violation lost its address");
            require(pointers->ExceptionRecord->ExceptionInformation[0] == (execution->write ? 1u : 0u)
                && pointers->ExceptionRecord->ExceptionInformation[1] == context.R11,"Fault used an unexpected memory operand");
        }
        unwind(context,execution->source);
        context.Rip = target;
        ++faults;
    } else {
        require(execution->faults == 1 && execution->continuations++ == 0,"Continuation preceded its fault");
        require(pointers->ExceptionRecord->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION,"Continuation trap was lost");
        if (execution->precise) unwind(context,execution->target);
        else require(!at(execution->spans,execution->target).proven,"Memory writer gained an exceptional frame proof");
        context.Rip += 2;
        ++continuations;
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}
void execute(const Bytes& op,const Bytes& preparation,unsigned allocation,bool saved,bool precise,
        DWORD exception,DWORD64 rax,DWORD64 rdx,const void* operand,bool access = false,bool write = false) {
    // Observe the real ABI entry outside the solver's entry, independently of
    // its frame recipe. R11 keeps the fault operand when division uses RDX.
    Bytes code{0x48,0x89,0x21,0x48,0x89,0x69,0x08,0x48,0x8b,0x04,0x24,0x48,0x89,0x41,0x10,
        0x49,0x89,0xd3,0x49,0x89,0xca};
    auto entry = code.size();
    if (allocation) append(code,{0x48,0x83,0xec,static_cast<unsigned char>(allocation)});
    if (saved) append(code,{0x48,0x89,0x6c,0x24,static_cast<unsigned char>(allocation - 8),0x48,0x31,0xed});
    code.insert(code.end(),preparation.begin(),preparation.end());
    auto source = static_cast<unsigned>(code.size());
    code.insert(code.end(),op.begin(),op.end());
    auto finish = [&](unsigned value) {
        append(code,{0xb8,static_cast<unsigned char>(value),0,0,0});
        if (saved) append(code,{0x48,0x8b,0x6c,0x24,static_cast<unsigned char>(allocation - 8)});
        if (allocation) append(code,{0x48,0x83,0xc4,static_cast<unsigned char>(allocation)});
        append(code,{0x49,0x89,0x6a,0x18,0x49,0x89,0x62,0x20,0xc3});
    };
    finish(0);
    auto target = static_cast<unsigned>(code.size());
    // UD2 gives an actual second OS context at the continuation, after Windows
    // has resumed the first exception's context. It terminates the analysed CFG.
    append(code,{0x0f,0x0b});
    finish(1);
    auto page = static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    require(page != nullptr,"Cannot allocate executed fault fixture");
    std::memcpy(page,code.data(),code.size());
    Execution execution{page,{}, {},source,target,allocation,exception,GetCurrentThreadId(),rax,rdx,saved,precise,access,write};
    Layout layout{reinterpret_cast<std::uintptr_t>(page),0,entry,allocation,true,true};
    const FaultEdge edge{source,target};
    require(analyse(code.data(),code.size(),layout,execution.spans,{},std::span(&edge,1)),
        "Executed fault CFG was rejected");
    require(at(execution.spans,source).proven && at(execution.spans,target).proven == precise,
        "Fault source/continuation has the wrong eligibility");
    DWORD previous;
    require(VirtualProtect(page,4096,PAGE_EXECUTE_READ,&previous)
        && FlushInstructionCache(GetCurrentProcess(),page,code.size()),"Cannot publish executed fault fixture");
    current = &execution;
    auto result = reinterpret_cast<unsigned (*)(Observation*,const void*)>(page)(&execution.observed,operand);
    current = nullptr;
    require(result == 1 && execution.faults == 1 && execution.continuations == 1,"Fault did not resume and return through its continuation");
    require(execution.observed.restoredRbp == execution.observed.rbp && execution.observed.restoredSp == execution.observed.sp,
        "Continuation failed to restore the actual ABI frame");
    require(VirtualFree(page,0,MEM_RELEASE),"Cannot release executed fault fixture");
    ++cases;
}
}
int main() {
    auto inaccessible = VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
    require(inaccessible != nullptr,"Cannot allocate inaccessible operand");
    auto handler = AddVectoredExceptionHandler(1,handle);
    require(handler != nullptr,"Cannot install owned-fault handler");
    const Bytes values{0xb8,7,0,0,0,0xba,3,0,0,0};
    for (auto allocation : {0u,56u}) {
        execute({0x49,0x8b,0x2b},values,allocation,false,true,EXCEPTION_ACCESS_VIOLATION,7,3,inaccessible,true);
        execute({0x49,0x8b,0x03},values,allocation,false,true,EXCEPTION_ACCESS_VIOLATION,7,3,inaccessible,true);
    }
    execute({0x49,0x8b,0x2b},values,56,true,true,EXCEPTION_ACCESS_VIOLATION,7,3,inaccessible,true);
    execute({0x49,0x89,0x03},values,56,true,false,EXCEPTION_ACCESS_VIOLATION,7,3,inaccessible,true,true);
    const Bytes divideZero{0xb8,7,0,0,0,0x31,0xd2,0x31,0xc9};
    const Bytes overflow32{0xb8,0,0,0,0x80,0x99,0xb9,0xff,0xff,0xff,0xff};
    const Bytes overflow64{0x48,0xb8,0,0,0,0,0,0,0,0x80,0x48,0x99,0x48,0xc7,0xc1,0xff,0xff,0xff,0xff};
    const DWORD64 zero = 0;
    for (auto saved : {false,true}) {
        execute({0xf7,0xf9},divideZero,56,saved,true,EXCEPTION_INT_DIVIDE_BY_ZERO,7,0,nullptr);
        execute({0x48,0xf7,0xf9},divideZero,56,saved,true,EXCEPTION_INT_DIVIDE_BY_ZERO,7,0,nullptr);
        execute({0xf7,0xf9},overflow32,56,saved,true,EXCEPTION_INT_OVERFLOW,0x80000000,0xffffffff,nullptr);
        execute({0x48,0xf7,0xf9},overflow64,56,saved,true,EXCEPTION_INT_OVERFLOW,0x8000000000000000ull,~0ull,nullptr);
        execute({0x49,0xf7,0x3b},divideZero,56,saved,true,EXCEPTION_ACCESS_VIOLATION,7,0,inaccessible,true);
        execute({0x49,0xf7,0x3b},divideZero,56,saved,true,EXCEPTION_INT_DIVIDE_BY_ZERO,7,0,&zero);
    }
    require(RemoveVectoredExceptionHandler(handler) != 0,"Cannot remove owned-fault handler");
    require(VirtualFree(inaccessible,0,MEM_RELEASE),"Cannot release inaccessible operand");
    std::printf("COMPILED_FAULT_EXECUTION_PASS cases=%u checks=%u faults=%u continuations=%u osContexts=%u actualInputState=1 writerCutoff=1\n",
        cases,checks,faults,continuations,unwindContexts);
}
