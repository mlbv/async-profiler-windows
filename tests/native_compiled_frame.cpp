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
unsigned checks, cases, osContexts;
void require(bool condition,const char* message) {
    ++checks;
    if (!condition) {
        std::fprintf(stderr,"COMPILED_FRAME_FAILURE case=%u %s\n",cases,message);
        std::exit(1);
    }
}
const Span& at(const std::vector<Span>& spans,unsigned pc) {
    for (const auto& span : spans) if (span.begin <= pc && pc < span.end) return span;
    std::abort();
}
void expect(const std::vector<Span>& spans,unsigned pc,bool proven,unsigned delta = 0,int fp = -1) {
    const auto& rule = at(spans,pc);
    if (rule.proven != proven || (proven && (rule.returnOffset != delta || rule.fpOffset != fp)))
        std::fprintf(stderr,"pc=%u expected=%d/%u/%d observed=%d/%u/%d\n",
            pc,proven,delta,fp,rule.proven,rule.returnOffset,rule.fpOffset);
    require(rule.proven == proven && (!proven || (rule.returnOffset == delta && rule.fpOffset == fp)),
        "Unexpected frame rule");
}
unsigned append(Bytes& code,std::initializer_list<unsigned char> bytes) {
    auto pc = static_cast<unsigned>(code.size());
    code.insert(code.end(),bytes);
    return pc;
}
struct Fixture {
    Bytes code;
    unsigned allocation, entry = 0;
    std::uintptr_t barrier = 0;
    std::vector<HandlerEdge> handlers;
    std::vector<FaultEdge> faults;
    Layout layout() const {
        return {reinterpret_cast<std::uintptr_t>(code.data()),barrier,entry,allocation,handlers.empty(),true};
    }
    std::vector<Span> verify(bool oracle = true) const {
        ++cases;
        std::vector<Span> spans;
        require(analyse(code.data(),code.size(),layout(),spans,handlers,faults),"Valid frame CFG rejected");
        if (oracle) osContexts += contexts(code,spans);
        return spans;
    }
    void reject() const {
        ++cases;
        std::vector<Span> spans{{17,23,40,32,true}};
        require(!analyse(code.data(),code.size(),layout(),spans,handlers,faults),"Unsupported frame CFG accepted");
        require(spans.size() == 1 && spans[0].begin == 17 && spans[0].end == 23
            && spans[0].returnOffset == 40 && spans[0].fpOffset == 32 && spans[0].proven,
            "Rejected analysis changed prior result");
    }
};
void canonical() {
    Fixture pushed{{0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x10,0x90,
        0x48,0x83,0xc4,0x10,0x5d,0xc3},24};
    auto spans = pushed.verify();
    expect(spans,0,true);
    expect(spans,1,true,8);
    expect(spans,4,true,8,0);
    expect(spans,8,true,24,16);
    expect(spans,13,true,8,0);
    expect(spans,14,true);
    Fixture stored{{0x48,0x83,0xec,0x18,0x48,0x89,0x6c,0x24,0x10,
        0x48,0x31,0xed,0x48,0x83,0xc4,0x10,0x5d,0xc3},24};
    spans = stored.verify();
    expect(spans,12,true,24,16);
    expect(spans,16,true,8,0);
    expect(spans,17,true);
    Fixture bare{{0x55,0x5d,0xc3},8};
    spans = bare.verify();
    expect(spans,1,true,8);
    expect(spans,2,true);
    Fixture entry{{0x0f,0x31,0x55,0x48,0x31,0xed,0x5d,0xc3},8,2};
    spans = entry.verify();
    expect(spans,0,false);
    expect(spans,2,true);
    expect(spans,6,true,8,0);
    expect(spans,7,true);
}
void encodings() {
    for (unsigned prefix : {0u,0x40u,0x42u,0x44u,0x46u,0x48u,0x4au,0x4cu,0x4eu}) {
        Fixture fixture{{},8};
        if (prefix) fixture.code.push_back(static_cast<unsigned char>(prefix));
        append(fixture.code,{0x55});
        auto clobber = append(fixture.code,{0x48,0x31,0xed});
        auto pop = static_cast<unsigned>(fixture.code.size());
        if (prefix) fixture.code.push_back(static_cast<unsigned char>(prefix));
        append(fixture.code,{0x5d,0xc3});
        auto spans = fixture.verify();
        expect(spans,clobber,true,8);
        expect(spans,pop,true,8,0);
        expect(spans,fixture.code.size() - 1,true);
    }
    for (unsigned opcode : {0x55u,0x5du}) {
        auto byte = static_cast<unsigned char>(opcode);
        for (unsigned prefix : {0x66u,0xf0u,0xf2u,0xf3u,0x26u,0x2eu,0x36u,0x3eu,0x64u,0x65u,0x67u,
                0x41u,0x43u,0x45u,0x47u,0x49u,0x4bu,0x4du,0x4fu})
            Fixture{{static_cast<unsigned char>(prefix),byte,0xc3},8}.reject();
        for (auto prefixes : {Bytes{0x40,0x48},Bytes{0x48,0x66},Bytes{0x66,0x48}}) {
            prefixes.insert(prefixes.end(),{byte,0xc3});
            Fixture{prefixes,8}.reject();
        }
    }
    for (unsigned opcode = 0x50; opcode <= 0x5f; ++opcode) if (opcode != 0x55 && opcode != 0x5d)
        Fixture{{static_cast<unsigned char>(opcode),0xc3},8}.reject();
    Fixture{{0xff,0xf5,0xc3},8}.reject();
    Fixture{{0x8f,0xc5,0xc3},8}.reject();
    Fixture{{0x48},8}.reject();
    Fixture{{0x55},8}.reject();
    Fixture comparison{{0x55,0x3d,0,0,0,0,0x5d,0xc3},8};
    auto spans = comparison.verify();
    expect(spans,1,true,8);
    expect(spans,6,true,8);
    expect(spans,7,true);
    Fixture{{0x55,0x3c,0,0x5d,0xc3},8}.reject();
}
void slotTransfers() {
    Fixture nested{{0x55,0x48,0x31,0xed,0x55,0x5d,0x90,0x5d,0xc3},8};
    auto spans = nested.verify();
    expect(spans,5,true,16,8);
    expect(spans,6,true,8,0);
    expect(spans,8,true);
    Fixture clobbered{{0x48,0x31,0xed,0x55,0x5d,0xc3},8};
    spans = clobbered.verify();
    expect(spans,3,false);
    expect(spans,4,false);
    expect(spans,5,false);
    Fixture absent{{0x48,0x83,0xec,8,0x55,0x48,0x31,0xed,0x5d,0x90,
        0x48,0x83,0xc4,8,0xc3},16};
    spans = absent.verify();
    expect(spans,4,true,8);
    expect(spans,5,true,16);
    expect(spans,9,false);
    expect(spans,14,false);
    Fixture untracked{{0x55,0x48,0x83,0xec,8,0x5d,0x90,0x5d,0xc3},16};
    spans = untracked.verify();
    expect(spans,5,true,16);
    expect(spans,6,true,8,0);
    expect(spans,8,true);
    Fixture underflow{{0x5d,0x55,0x5d,0xc3},8};
    spans = underflow.verify();
    expect(spans,0,true);
    expect(spans,1,false);
    expect(spans,3,false);
    Fixture unaligned{{0x48,0x83,0xec,4,0x55,0x5d,0x48,0x83,0xc4,4,0xc3},8};
    spans = unaligned.verify();
    expect(spans,4,false);
    expect(spans,10,false);
    Fixture overflow{{0x48,0x81,0xec,0xf8,0xff,0xff,0x7f,0x48,0x81,0xec,0xf8,0xff,0xff,0x7f,
        0x55,0x55,0x5d,0xc3},8};
    // The shared Windows oracle reserves 128 bytes; this case tests the delta bound only.
    spans = overflow.verify(false);
    expect(spans,15,true,0xfffffff8);
    expect(spans,16,false);
    expect(spans,17,false);
}
void aliases() {
    struct Store { Bytes code; bool retained; };
    for (const auto& store : {
            Store{{0x48,0x89,0x08},true},Store{{0xc5,0xfb,0x11,0x01},true},Store{{0x48,0x89,0x4c,0x04,0x20},false},
            Store{{0x48,0x89,0x4c,0x24,0x20},false},Store{{0x48,0x89,0x6c,0x24,0x20},false},
            Store{{0x48,0x89,0x4c,0x24,0x19},false},Store{{0x89,0x4c,0x24,0x1d},false},
            Store{{0x48,0x89,0x4c,0x24,0x18},true},Store{{0x89,0x4c,0x24,0x1c},true}}) {
        Fixture fixture{{0x55,0x48,0x83,0xec,0x20,0x48,0x31,0xed},40};
        fixture.code.insert(fixture.code.end(),store.code.begin(),store.code.end());
        auto after = append(fixture.code,{0x90,0x48,0x83,0xc4,0x20,0x5d,0xc3});
        auto spans = fixture.verify();
        expect(spans,8,true,40,32);
        expect(spans,after,store.retained,40,32);
        expect(spans,after + 5,store.retained,8,0);
        expect(spans,after + 6,store.retained);
    }
    Fixture live{{0x55,0x48,0x89,0x08,0x90,0x5d,0xc3},8};
    auto spans = live.verify();
    expect(spans,4,true,8);
    expect(spans,5,true,8);
    expect(spans,6,true);
    Fixture indexed{{0x55,0x48,0x89,0x0c,0x04,0x90,0x5d,0xc3},8};
    spans = indexed.verify();
    expect(spans,5,true,8);
    expect(spans,6,true,8);
    expect(spans,7,false);
    Fixture allocation{{0x48,0x83,0xec,8,0x48,0x89,0x2c,0x24,0x48,0x31,0xed,0x5d,0xc3},40};
    spans = allocation.verify();
    expect(spans,11,false);
    expect(spans,12,false);
}
void calls() {
    struct Call { unsigned allocated, declared; bool extra, barrier; };
    for (auto call : {Call{32,32,false,false},Call{40,40,false,false},Call{40,32,false,false},
            Call{40,40,true,false},Call{32,32,false,true},Call{40,40,false,true}}) {
        auto locals = static_cast<unsigned char>(call.allocated - 8);
        Fixture fixture{{0x55,0x48,0x83,0xec,locals},call.declared};
        if (call.extra) append(fixture.code,{0x55});
        auto source = append(fixture.code,{0xe8,0,0,1,0});
        auto delta = call.allocated + (call.extra ? 8 : 0);
        auto release = static_cast<unsigned char>(delta - 8);
        auto normal = append(fixture.code,{0x90,0x48,0x83,0xc4,release,0x5d,0xc3});
        auto handler = append(fixture.code,{0x90,0x48,0x83,0xc4,release,0x5d,0xc3});
        fixture.handlers = {{normal,handler,true}};
        if (call.barrier) fixture.barrier = reinterpret_cast<std::uintptr_t>(fixture.code.data()) + source + 5 + 0x10000;
        auto spans = fixture.verify();
        bool slot = delta == call.declared && delta >= 40;
        expect(spans,source,true,delta);
        expect(spans,normal,slot || call.barrier,delta,call.barrier ? -1 : static_cast<int>(delta - 8));
        expect(spans,handler,slot,delta,delta - 8);
        expect(spans,normal + 6,slot);
        expect(spans,handler + 6,slot);
    }
}
void faults() {
    for (const auto& instruction : {Bytes{0x48,0x8b,0x01},Bytes{0xf7,0xf9}}) {
        Fixture fixture{{0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x20},40};
        auto source = static_cast<unsigned>(fixture.code.size());
        fixture.code.insert(fixture.code.end(),instruction.begin(),instruction.end());
        auto normal = append(fixture.code,{0x48,0x83,0xc4,0x20,0x5d,0xc3});
        auto target = append(fixture.code,{0x90,0x48,0x83,0xc4,0x20,0x5d,0xc3});
        fixture.faults = {{source,target}};
        auto spans = fixture.verify();
        expect(spans,source,true,40,32);
        expect(spans,normal,true,40,32);
        expect(spans,target,true,40,32);
        expect(spans,target + 5,true,8,0);
        expect(spans,target + 6,true);
    }
    Fixture readZero{{0x48,0x8b,0x01,0x55,0x48,0x31,0xed,0x5d,0xc3,0x90,0xc3},8};
    readZero.faults = {{0,9}};
    auto spans = readZero.verify();
    expect(spans,9,true);
    Fixture pushZero{{0x55,0x48,0x31,0xed,0x5d,0xc3,0x90,0x55,0x5d,0xc3},8};
    pushZero.faults = {{0,6}};
    spans = pushZero.verify();
    expect(spans,0,true);
    expect(spans,5,true);
    expect(spans,6,false);
    expect(spans,9,false);
    for (bool live : {false,true}) {
        Fixture fixture{{0x55,0x48,0x83,0xec,0x20},40};
        if (!live) append(fixture.code,{0x48,0x31,0xed});
        auto source = append(fixture.code,{0x55});
        auto normal = append(fixture.code,{0x48,0x83,0xc4,0x28,0x5d,0xc3});
        auto target = append(fixture.code,{0x90,0x48,0x83,0xc4,0x28,0x5d,0xc3});
        fixture.faults = {{source,target}};
        spans = fixture.verify();
        expect(spans,source,true,40,live ? -1 : 32);
        expect(spans,normal,true,48,live ? -1 : 40);
        expect(spans,target,false);
        expect(spans,target + 6,false);
    }
    Fixture pop{{0x55,0x48,0x31,0xed,0x5d,0xc3,0x90,0xc3},8};
    pop.faults = {{4,6}};
    spans = pop.verify();
    expect(spans,4,true,8,0);
    expect(spans,5,true);
    expect(spans,6,false);
}
void joins() {
    Fixture delta{{0x74,1,0x55,0x90,0x5d,0xc3},8};
    auto spans = delta.verify();
    expect(spans,2,true);
    expect(spans,3,false);
    expect(spans,5,false);
    Fixture slot{{0x74,3,0x55,0xeb,4,0x48,0x83,0xec,8,0x48,0x31,0xed,0x5d,0xc3},8};
    spans = slot.verify();
    expect(spans,9,true,8);
    expect(spans,12,false);
    expect(spans,13,false);
    Fixture same{{0x74,3,0x55,0xeb,2,0x48,0x55,0x48,0x31,0xed,0x5d,0xc3},8};
    spans = same.verify();
    expect(spans,10,true,8,0);
    expect(spans,11,true);
}
void ownership() {
    Fixture fixture{{0x48,0x55,0x48,0x31,0xed,0x48,0x5d,0xc3,0x90,0xc3},8};
    fixture.verify();
    for (unsigned middle : {1u,6u}) {
        fixture.faults = {{middle,8}};
        fixture.reject();
        fixture.faults = {{2,middle}};
        fixture.reject();
    }
    fixture.faults = {{0,0}};
    fixture.reject();
    fixture.faults = {{5,5}};
    fixture.reject();
    Fixture{{0x74,1,0x48,0x55,0x5d,0xc3},8}.reject();
    Fixture{{0x55,0x74,1,0x48,0x5d,0xc3},8}.reject();
    Fixture{{0x55,0x5d,0xc3},7}.reject();
}
}
int main() {
    canonical();
    encodings();
    slotTransfers();
    aliases();
    calls();
    faults();
    joins();
    ownership();
    std::printf("COMPILED_FRAME_OK cases=%u checks=%u osContexts=%u\n",cases,checks,osContexts);
}
