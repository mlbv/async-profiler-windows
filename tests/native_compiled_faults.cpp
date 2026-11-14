/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsCompiledUnwind.h"
#include "native_compiled_unwind_oracle.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <charconv>
#include <fstream>
#include <iterator>
#include <string_view>

using namespace WindowsProfiler::JavaUnwind::Compiled;
using Bytes = std::vector<unsigned char>;
static unsigned checks, osContexts, cases;
static void require(bool condition,const char* message) {
    ++checks;
    if (!condition) { std::fprintf(stderr,"COMPILED_FAULT_FAILURE %s\n",message); std::exit(1); }
}
static const Span& at(const std::vector<Span>& spans,std::size_t pc) {
    for (const auto& span : spans) if (pc >= span.begin && pc < span.end) return span;
    std::abort();
}
struct Fixture {
    Bytes code;
    std::uint32_t source,normal,target,allocation;
    std::vector<HandlerEdge> handlers;
    std::vector<FaultEdge> faults;
    Layout layout() const {
        return {reinterpret_cast<std::uintptr_t>(code.data()),0,0,allocation,handlers.empty(),true};
    }
    std::vector<Span> analyseSpans() const {
        std::vector<Span> spans;
        require(analyse(code.data(),code.size(),layout(),spans,handlers,faults),"Valid fault CFG rejected");
        return spans;
    }
};
static void append(Bytes& code,std::initializer_list<unsigned char> bytes) { code.insert(code.end(),bytes); }
static Fixture framed(const Bytes& op,bool call = true,unsigned allocation = 56) {
    Fixture fixture{{0x48,0x83,0xec,static_cast<unsigned char>(allocation),
        0x48,0x89,0x6c,0x24,static_cast<unsigned char>(allocation - 8)},0,0,0,allocation,{},{}};
    if (call) append(fixture.code,{0xe8,0,0,1,0});
    fixture.source = static_cast<std::uint32_t>(fixture.code.size());
    fixture.code.insert(fixture.code.end(),op.begin(),op.end());
    fixture.normal = static_cast<std::uint32_t>(fixture.code.size());
    auto finish = [&] {
        append(fixture.code,{0x48,0x8b,0x6c,0x24,static_cast<unsigned char>(allocation - 8),
            0x48,0x83,0xc4,static_cast<unsigned char>(allocation),0xc3});
    };
    finish();
    fixture.target = static_cast<std::uint32_t>(fixture.code.size());
    append(fixture.code,{0x90}); finish();
    fixture.faults.push_back({fixture.source,fixture.target});
    return fixture;
}
static void proveRead(const Bytes& op) {
    auto fixture = framed(op);
    auto spans = fixture.analyseSpans();
    require(at(spans,fixture.target).proven && at(spans,fixture.target).returnOffset == 56
        && at(spans,fixture.target).fpOffset == 48,"Precise read/divide lost input saved frame");
    require(at(spans,fixture.target + 6).proven && at(spans,fixture.target + 6).fpOffset == -1,
        "Fault continuation could not restore input RBP slot");
    osContexts += contexts(fixture.code,spans);
    ++cases;
}
static void poison(const Bytes& op) {
    auto fixture = framed(op);
    auto spans = fixture.analyseSpans();
    require(at(spans,fixture.source).proven,"Unsafe exceptional source lost its reachable input frame");
    require(!at(spans,fixture.target).proven && !at(spans,fixture.target + 6).proven,
        "Unproved fault source received an input-frame proof");
    osContexts += contexts(fixture.code,spans);
    ++cases;
}
static void inputState() {
    Fixture zero{{0x48,0x8b,0x29,0xc3,0x90,0xc3},0,3,4,0,{},{{0,4}}};
    auto spans = zero.analyseSpans();
    require(at(spans,0).proven && !at(spans,3).proven && at(spans,4).proven,
        "Faulting MOV RBP used its successful destination instead of input RBP");
    osContexts += contexts(zero.code,spans);
    auto restore = framed({0x48,0x8b,0x6c,0x24,0x30});
    spans = restore.analyseSpans();
    require(at(spans,restore.normal).proven && at(spans,restore.normal).fpOffset == -1,
        "Successful MOV RBP did not restore the protected frame slot");
    require(at(spans,restore.target).proven && at(spans,restore.target).fpOffset == 48,
        "Faulting MOV RBP borrowed its successful restore");
    osContexts += contexts(restore.code,spans);
    // Faults preserve the live incoming RBP even without a saved slot.
    Fixture allocated{{0x48,0x83,0xec,0x38,0x48,0x8b,0x29,0x48,0x83,0xc4,0x38,0xc3,
        0x90,0x48,0x83,0xc4,0x38,0xc3},4,7,12,56,{},{{4,12}}};
    spans = allocated.analyseSpans();
    require(!at(spans,allocated.normal).proven && at(spans,allocated.target).proven
        && at(spans,allocated.target).fpOffset == -1 && at(spans,allocated.target).returnOffset == 56,
        "Fault edge treated unchanged live RBP as a call-handler clobber");
    osContexts += contexts(allocated.code,spans);
    zero.faults = {{0,3}};
    spans = zero.analyseSpans();
    require(!at(spans,3).proven,"Fault input state overwrote incompatible ordinary-path facts at a join");
    osContexts += contexts(zero.code,spans);
    cases += 4;
}
static void eligibility() {
    for (const auto& op : {
            Bytes{0x48,0x8b,0x01},Bytes{0x8b,0x29},Bytes{0x48,0x63,0x29},
            Bytes{0x48,0x03,0x29},Bytes{0x48,0x0b,0x29},Bytes{0x48,0x23,0x29},
            Bytes{0x48,0x2b,0x29},Bytes{0x48,0x33,0x29},Bytes{0x48,0x0f,0xaf,0x29},
            Bytes{0x48,0x69,0x29,2,0,0,0},Bytes{0x48,0x6b,0x29,2},
            Bytes{0xc4,0xe3,0xfb,0xf0,0x29,1}, // RORX RBP,[RCX],1.
            Bytes{0x48,0x39,0x01},Bytes{0x48,0x3b,0x01},Bytes{0x48,0x85,0x01},
            Bytes{0x80,0x39,1},Bytes{0x48,0x81,0x39,1,0,0,0},Bytes{0x48,0x83,0x39,1},
            Bytes{0x48,0x0f,0x44,0x29},Bytes{0x48,0x0f,0x45,0x29},
            Bytes{0xc5,0xfb,0x10,0x01},Bytes{0xc5,0xfa,0x10,0x01},
            Bytes{0x62,0xf1,0xff,0x08,0x10,0x01},
            Bytes{0xf7,0xf1},Bytes{0xf7,0xf9},Bytes{0x48,0xf7,0xf1},Bytes{0x48,0xf7,0xf9},
            Bytes{0x66,0xf7,0xf1},Bytes{0x66,0xf7,0xf9},Bytes{0x48,0xf7,0xfd},Bytes{0xf7,0xf4},
            Bytes{0xf7,0x31},Bytes{0x48,0xf7,0x39},Bytes{0x66,0xf7,0x39}})
        proveRead(op);
    for (const auto& op : {
            Bytes{0x90},Bytes{0x48,0x8d,0x01},Bytes{0x48,0x89,0xc0},Bytes{0x48,0x39,0xc0},
            Bytes{0x3d,0,0,0,0x80},Bytes{0x48,0x3d,0,0,0,0x80},
            Bytes{0x48,0x89,0x01},Bytes{0x48,0xc7,0x01,1,0,0,0},Bytes{0x48,0x01,0x01},
            Bytes{0xf0,0x48,0x01,0x01},Bytes{0x48,0xff,0x01},Bytes{0x48,0xc1,0x21,1},
            Bytes{0xc5,0xfb,0x11,0x01},Bytes{0x62,0xf1,0xff,0x08,0x11,0x01},
            Bytes{0xc5,0xfb,0x58,0x01},Bytes{0x62,0xf1,0xff,0x08,0x59,0x01}})
        poison(op);
}
static void partialStores() {
    // A successful save establishes the slot, but a fault cannot borrow that
    // effect. Conversely, an existing slot can be partially overwritten.
    for (auto call : {false,true}) for (auto storeRbp : {false,true}) {
        auto fixture = framed(storeRbp ? Bytes{0x48,0x89,0x6c,0x24,0x30}
            : Bytes{0x48,0x89,0x44,0x24,0x30},call);
        auto spans = fixture.analyseSpans();
        require(!at(spans,fixture.target).proven,"Faulting stack writer borrowed the input/successful slot");
        osContexts += contexts(fixture.code,spans); ++cases;
    }
    auto fixture = framed({0x48,0x83,0xec,8},false);
    auto spans = fixture.analyseSpans();
    require(!at(spans,fixture.target).proven,"Stack adjustment received a precise read fault edge");
    ++cases;
}
static void callAndHomeArea() {
    for (auto allocation : {32u,40u,56u}) {
        auto fixture = framed({0x48,0x8b,0x01},false,allocation);
        fixture.code.resize(fixture.target);
        append(fixture.code,{0xe8,0,0,1,0,0x90,0x48,0x8b,0x6c,0x24,static_cast<unsigned char>(allocation - 8),
            0x48,0x83,0xc4,static_cast<unsigned char>(allocation),0xc3});
        auto spans = fixture.analyseSpans();
        require(at(spans,fixture.target).proven,"Fault continuation input frame was lost before its runtime call");
        require(at(spans,fixture.target + 5).proven == (allocation >= 40),
            "Continuation call ignored outgoing home-area ownership");
        if (allocation >= 40) require(at(spans,fixture.target + 5).fpOffset == static_cast<int>(allocation - 8),
            "Continuation call retained a live RBP promise");
        osContexts += contexts(fixture.code,spans); ++cases;
    }
    auto mismatch = framed({0x48,0x8b,0x01});
    mismatch.allocation = 64;
    auto mismatchSpans = mismatch.analyseSpans();
    require(!at(mismatchSpans,mismatch.target).proven,"Fault edge recovered a slot invalidated by allocation mismatch");
    ++cases;
    auto call = framed({0xe8,0,0,1,0});
    auto spans = call.analyseSpans();
    require(!at(spans,call.target).proven,"CALL start was confused with a precise fault site");
    call.handlers = {{call.normal,call.target,true}};
    call.faults.clear();
    spans = call.analyseSpans();
    require(at(spans,call.target).proven && at(spans,call.target).fpOffset == 48,
        "Existing call-return handler proof regressed");
    call.faults.push_back({call.source,call.target});
    spans = call.analyseSpans();
    require(!at(spans,call.target).proven,"Unknown fault edge failed to poison a shared call-handler target");
    osContexts += contexts(call.code,spans); ++cases;
}
static void unmatchedAndJoins() {
    auto fixture = framed({0x48,0x8b,0x01});
    // Source lies in dead bytes past the normal and fault returns.
    auto dead = static_cast<std::uint32_t>(fixture.code.size());
    append(fixture.code,{0x90,0x90});
    fixture.faults.push_back({dead,fixture.target});
    auto spans = fixture.analyseSpans();
    require(!at(spans,fixture.target).proven && at(spans,fixture.normal).proven,
        "Unmatched source failed to poison an otherwise proved target");
    std::reverse(fixture.faults.begin(),fixture.faults.end());
    auto reversed = fixture.analyseSpans();
    for (std::size_t pc = 0; pc < fixture.code.size(); ++pc)
        require(at(spans,pc).proven == at(reversed,pc).proven,"Fault proof depended on metadata order");
    osContexts += contexts(fixture.code,spans); ++cases;
    // A metadata edge at a supported but nonfaulting RET is also unknown.
    Fixture terminal{{0xc3,0x90,0xc3},0,1,1,0,{},{{0,1}}};
    spans = terminal.analyseSpans();
    require(!at(spans,1).proven,"Nonfaulting return source gained frame proof");
    ++cases;
    // Unknown instructions still reject the complete analysis; they acquire no
    // ordinary-path proof merely because implicit metadata names their source.
    Fixture unknown{{0x0f,0x31,0xc3,0x90,0xc3},0,2,3,0,{},{{0,3}}};
    spans.clear();
    require(!analyse(unknown.code.data(),unknown.code.size(),unknown.layout(),spans,{},unknown.faults)
        && spans.empty(),"Unknown fault instruction expanded decoder eligibility");
    ++cases;
}
static void invalidEdges() {
    auto fixture = framed({0x48,0x8b,0x01});
    auto reject = [&](std::vector<FaultEdge> faults,const char* message) {
        std::vector<Span> spans{{1,2,3,4,true}};
        require(!analyse(fixture.code.data(),fixture.code.size(),fixture.layout(),spans,{},faults),message);
        require(spans.size() == 1 && spans[0].begin == 1 && spans[0].end == 2 && spans[0].returnOffset == 3
            && spans[0].fpOffset == 4 && spans[0].proven,"Rejected fault metadata changed result");
        ++cases;
    };
    reject({{fixture.source,0}},"Zero fault target accepted");
    reject({{fixture.source,static_cast<std::uint32_t>(fixture.code.size())}},"Outside fault target accepted");
    reject({{static_cast<std::uint32_t>(fixture.code.size()),fixture.target}},"Outside fault source accepted");
    reject({{fixture.source,fixture.source}},"Self fault edge accepted");
    reject({{fixture.source,fixture.target},{fixture.source,fixture.target}},"Duplicate fault source accepted");
    reject({{fixture.source,fixture.target},{fixture.source,fixture.normal}},"Conflicting duplicate fault source accepted");
    reject({{fixture.source + 1,fixture.target}},"Fault source inside a decoded instruction accepted");
    reject({{fixture.source,fixture.source + 1}},"Fault target inside a decoded instruction accepted");
}
static std::uint64_t number(std::string_view text,int base = 10) {
    std::uint64_t value;
    auto parsed = std::from_chars(text.data(),text.data() + text.size(),value,base);
    require(!text.empty() && parsed.ec == std::errc() && parsed.ptr == text.data() + text.size(),
        "Invalid captured metadata number");
    return value;
}
static std::uint32_t offset(std::string_view text) {
    auto value = number(text);
    require(value <= UINT32_MAX,"Captured metadata offset overflow");
    return static_cast<std::uint32_t>(value);
}
template<class Consume> static void edges(std::string_view text,Consume consume) {
    if (text == "-") return;
    require(!text.empty(),"Missing captured edge list");
    while (!text.empty()) {
        auto end = text.find(',');
        consume(text.substr(0,end));
        if (end == std::string_view::npos) break;
        text.remove_prefix(end + 1);
        require(!text.empty(),"Trailing captured edge separator");
    }
}
static unsigned captured(char** argv,bool unprovenFault = false) {
    std::ifstream input(argv[1],std::ios::binary);
    require(input.good(),"Cannot open captured method code");
    Bytes code{std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};
    std::vector<FaultEdge> faults;
    std::vector<HandlerEdge> handlers;
    edges(argv[6],[&](std::string_view edge) {
        auto separator = edge.find(':');
        require(separator != std::string_view::npos,"Captured fault edge lacks target");
        faults.push_back({offset(edge.substr(0,separator)),offset(edge.substr(separator + 1))});
    });
    edges(argv[7],[&](std::string_view edge) {
        auto first = edge.find(':'), last = edge.rfind(':');
        require(first != std::string_view::npos && first != last,"Captured handler edge lacks classification");
        auto known = number(edge.substr(last + 1));
        require(known <= 1,"Captured handler classification is invalid");
        handlers.push_back({offset(edge.substr(0,first)),offset(edge.substr(first + 1,last - first - 1)),known != 0});
    });
    require(!faults.empty() || !handlers.empty(),"Captured method has no exceptional edges");
    Layout layout{static_cast<std::uintptr_t>(number(argv[2],16)),static_cast<std::uintptr_t>(number(argv[3],16)),
        static_cast<std::size_t>(number(argv[4])),offset(argv[5]),handlers.empty(),true};
    std::vector<Span> spans;
    require(analyse(code.data(),code.size(),layout,spans,handlers,faults),"Captured fault CFG declined proof");
    require(!unprovenFault || !faults.empty(),"Negative captured fixture has no fault edges");
    for (const auto& edge : faults)
        require(unprovenFault ? !at(spans,edge.source).proven && !at(spans,edge.target).proven
            : at(spans,edge.source).proven && at(spans,edge.target).proven,
            "Captured fault source/continuation has the wrong frame eligibility");
    for (const auto& edge : handlers)
        require(edge.callReturn && at(spans,edge.target).proven && at(spans,edge.target).fpOffset >= 0,
            "Captured handler has no protected call-return frame proof");
    auto count = contexts(code,spans);
    require(count != 0,"Captured exceptional CFG has no OS unwind contexts");
    std::printf("%s bytes=%zu faults=%zu handlers=%zu osContexts=%u\n",
        unprovenFault ? "COMPILED_FAULT_CAPTURE_UNPROVEN" : faults.empty() ? "COMPILED_HANDLER_CAPTURE" : "COMPILED_FAULT_CAPTURE",
        code.size(),faults.size(),handlers.size(),count);
    return count;
}
int main(int argc,char** argv) {
    auto unprovenFault = argc == 9 && std::string_view(argv[1]) == "--unproven-fault";
    if (unprovenFault) { --argc; ++argv; }
    require(argc == 1 || argc == 8,"Expected [--unproven-fault] code/address/barrier/entry/allocation/faults/handlers");
    if (argc == 8) { captured(argv,unprovenFault); return 0; }
    inputState(); eligibility(); partialStores(); callAndHomeArea(); unmatchedAndJoins(); invalidEdges();
    std::printf("COMPILED_FAULTS_PASS cases=%u checks=%u osContexts=%u\n",cases,checks,osContexts);
}
