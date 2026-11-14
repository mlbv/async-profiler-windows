/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsCompiledUnwind.h"
#include "native_compiled_unwind_oracle.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
using namespace WindowsProfiler::JavaUnwind::Compiled;
namespace {
unsigned checks;
void require(bool condition,const char* message) {
    ++checks;
    if (!condition) { std::fprintf(stderr,"COMPILED_REACHABILITY_FAILURE %s\n",message); std::exit(1); }
}
const Span& at(const std::vector<Span>& spans,unsigned pc) {
    for (const auto& span : spans) if (pc >= span.begin && pc < span.end) return span;
    std::abort();
}
bool has(const std::vector<std::uint32_t>& starts,unsigned pc) {
    return std::binary_search(starts.begin(),starts.end(),pc);
}
void unchanged(const std::vector<Span>& spans,const std::vector<std::uint32_t>& starts) {
    require(spans.size() == 1 && spans[0].begin == 17 && spans[0].end == 19
        && spans[0].returnOffset == 40 && spans[0].fpOffset == 32 && spans[0].proven,
        "Rejected analysis changed the prior frame result");
    require(starts == std::vector<std::uint32_t>{17,19},"Rejected analysis changed prior reachability");
}
}
int main() {
    const std::vector<unsigned char> code{
        0x48,0x83,0xec,0x38,
        0x48,0x89,0x6c,0x24,0x30,
        0xe8,0,0,1,0,
        0x48,0x8b,0x6c,0x24,0x30,
        0x48,0x83,0xc4,0x38,0xc3,
        0x90,0x48,0x8b,0x6c,0x24,0x30,0x48,0x83,0xc4,0x38,0xc3,
        0x0f,0x31
    };
    Layout layout{reinterpret_cast<std::uintptr_t>(code.data()),0,0,56,false,true};
    HandlerEdge edge{14,24,true};
    std::vector<Span> full;
    std::vector<std::uint32_t> reached;
    require(analyse(code.data(),code.size(),layout,full,std::span{&edge,1},{},&reached),
        "Protected exceptional route failed analysis");
    require(reached == std::vector<std::uint32_t>{0,4,9,14,19,23,24,25,30,34},
        "Reachability lost instruction starts or included instruction interiors/dead bytes");
    require(at(full,24).proven && at(full,24).fpOffset == 48,"Exceptional route lost its saved frame");
    auto osContexts = contexts(code,full);
    std::vector<Span> ordinary;
    std::vector<std::uint32_t> ordinaryReached;
    layout.handlersEmpty = true;
    require(analyse(code.data(),code.size(),layout,ordinary,{},{},&ordinaryReached),
        "Ordinary-entry route failed analysis");
    require(ordinaryReached == std::vector<std::uint32_t>{0,4,9,14,19,23},
        "Ordinary-entry traversal invented an exceptional ingress");
    require(has(reached,24) && !has(ordinaryReached,24) && has(ordinaryReached,14),
        "Exceptional-only and normal call-return sites were confused");
    require(!at(ordinary,24).proven,"Unreachable handler acquired an ordinary frame proof");
    layout.handlersEmpty = false;
    edge.callReturn = false;
    require(analyse(code.data(),code.size(),layout,full,std::span{&edge,1},{},&reached),
        "Unknown exceptional state failed analysis");
    require(has(reached,24) && !at(full,24).proven,
        "Reached unproved state was confused with unreachable code");
    require(!has(reached,26) && !has(reached,35),"Reachability included interior or dead instructions");
    // A fault target is also exceptional-only, independently of call-return edges.
    const std::vector<unsigned char> faultCode{0x48,0x8b,0x01,0xc3,0x90,0xc3};
    Layout faultLayout{reinterpret_cast<std::uintptr_t>(faultCode.data()),0,0,0,true,true};
    FaultEdge fault{0,4};
    require(analyse(faultCode.data(),faultCode.size(),faultLayout,full,{},std::span{&fault,1},&reached),
        "Precise fault route failed analysis");
    require(reached == std::vector<std::uint32_t>{0,3,4,5} && at(full,4).proven,
        "Fault continuation reachability or input frame was lost");
    require(analyse(faultCode.data(),faultCode.size(),faultLayout,ordinary,{},{},&ordinaryReached)
        && ordinaryReached == std::vector<std::uint32_t>{0,3},"Ordinary route followed a missing fault edge");
    // Failed analysis must publish neither output, even after traversal began.
    edge = {14,27,true};
    full = {{17,19,40,32,true}}; reached = {17,19};
    require(!analyse(code.data(),code.size(),layout,full,std::span{&edge,1},{},&reached),
        "Interior exceptional target was accepted");
    unchanged(full,reached);
    layout.entry = 35; layout.handlersEmpty = true;
    require(!analyse(code.data(),code.size(),layout,full,{},{},&reached),"Unknown root instruction was accepted");
    unchanged(full,reached);
    layout.entry = code.size();
    require(!analyse(code.data(),code.size(),layout,full,{},{},&reached),"Invalid root was accepted");
    unchanged(full,reached);
    // A caller that does not request reachability retains the original result.
    std::vector<Span> without;
    layout.entry = 0;
    require(analyse(code.data(),code.size(),layout,without),"Default output mode failed");
    require(analyse(code.data(),code.size(),layout,ordinary,{},{},&ordinaryReached),
        "Optional output mode failed");
    require(without.size() == ordinary.size(),"Optional reachability changed frame span count");
    for (std::size_t index = 0; index < without.size(); ++index) {
        const auto& a = without[index]; const auto& b = ordinary[index];
        require(a.begin == b.begin && a.end == b.end && a.returnOffset == b.returnOffset
            && a.fpOffset == b.fpOffset && a.proven == b.proven,"Optional reachability changed frame rules");
    }
    std::printf("COMPILED_REACHABILITY_PASS checks=%u osContexts=%u exceptionalOnly=1 unknownReached=1 unchangedFailure=1\n",
        checks,osContexts);
}
