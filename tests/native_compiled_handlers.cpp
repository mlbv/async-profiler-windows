/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsCompiledHandlers.h"
#include "native_compiled_unwind_oracle.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

using namespace WindowsProfiler::JavaUnwind::Compiled;
static unsigned checks;
static void require(bool value,const char* message) {
    ++checks;
    if (!value) { std::fprintf(stderr,"COMPILED_HANDLER_FAILURE %s\n",message); std::exit(1); }
}
static const Span& at(const std::vector<Span>& spans,std::uint32_t pc) {
    for (const auto& span : spans) if (pc >= span.begin && pc < span.end) return span;
    std::abort();
}
static std::vector<unsigned char> code() {
    return {
        0x48,0x83,0xec,0x38,             // 0: allocate declared 56 bytes.
        0x48,0x89,0x6c,0x24,0x30,        // 4: protect incoming RBP above callee home area.
        0xe8,0,0,1,0,                   // 9: external CALL; exceptional source is 14.
        0x48,0x8b,0x6c,0x24,0x30,        // 14: normal restore.
        0x48,0x83,0xc4,0x38,0xc3,        // 19: normal release/return.
        0x90,                            // 24: handler entry; live RBP is unknown.
        0x48,0x8b,0x6c,0x24,0x30,        // 25: handler restore.
        0x48,0x83,0xc4,0x38,0xc3         // 30: handler release/return.
    };
}
static unsigned edgeCases() {
    unsigned total = 0;
    auto bytes = code();
    Layout layout{reinterpret_cast<std::uintptr_t>(bytes.data()),0,0,56,false,true};
    std::vector<HandlerEdge> edges{{14,24,true}};
    std::vector<Span> spans;
    auto analyseCase = [&] {
        spans.clear();
        layout.address = reinterpret_cast<std::uintptr_t>(bytes.data());
        return analyse(bytes.data(),bytes.size(),layout,spans,edges);
    };
    require(analyseCase(),"Exact protected call-return edge was rejected");
    require(at(spans,24).proven && at(spans,24).fpOffset == 48 && at(spans,24).returnOffset == 56,
            "Handler entry used the live RBP register");
    require(at(spans,30).proven && at(spans,30).fpOffset == -1 &&
            at(spans,34).proven && at(spans,34).returnOffset == 0,"Handler restore was not propagated");
    total += contexts(bytes,spans);
    edges[0].callReturn = false;
    require(analyseCase() && !at(spans,24).proven && at(spans,14).proven,
            "Unknown or method-handle source received a handler proof");
    edges[0].callReturn = true;
    edges[0].source = 19;
    require(analyseCase() && !at(spans,24).proven,"Non-call source received a handler proof");
    edges = {{14,24,true},{19,24,false}};
    require(analyseCase() && !at(spans,24).proven,"Unknown incoming edge did not poison shared handler");
    std::reverse(edges.begin(),edges.end());
    require(analyseCase() && !at(spans,24).proven,"Handler proof depended on edge order");
    edges = {{14,24,true},{14,25,true}};
    require(analyseCase() && at(spans,24).proven && at(spans,25).proven,
            "One call could not reach multiple handler targets");
    total += contexts(bytes,spans);
    edges = {{14,24,true}};
    bytes[6] = 0x44;
    require(analyseCase() && !at(spans,24).proven,"Unprotected RBP slot received exceptional proof");
    bytes = code();
    bytes[3] = 32; bytes[8] = bytes[18] = bytes[29] = 24;
    bytes[22] = bytes[33] = 32; layout.allocation = 32;
    require(analyseCase() && !at(spans,24).proven,"Callee home-area slot received exceptional proof");
    bytes = code(); layout.allocation = 64;
    require(analyseCase() && !at(spans,24).proven,"Mismatched outgoing allocation received exceptional proof");
    layout.allocation = 56;
    edges = {{14,27,true}};
    require(!analyseCase() && spans.empty(),"Handler entry in the middle of an instruction was accepted");
    edges = {{0,24,true}};
    require(!analyseCase() && spans.empty(),"Zero source offset was accepted");
    edges = {{static_cast<std::uint32_t>(bytes.size()),24,true}};
    require(!analyseCase() && spans.empty(),"Source outside code was accepted");
    edges = {{14,static_cast<std::uint32_t>(bytes.size()),true}};
    require(!analyseCase() && spans.empty(),"Handler target outside code was accepted");
    edges = {{14,24,true}}; layout.handlersEmpty = true;
    require(!analyseCase(),"Empty-handler metadata accepted supplied edges");
    layout.handlersEmpty = false; edges.clear();
    require(!analyseCase(),"Missing nonempty handler snapshot was accepted");
    edges = {{14,24,true}}; layout.singleEntry = false;
    require(!analyseCase(),"Secondary entry received a handler proof");
    layout.singleEntry = true;
    bytes = code(); bytes.resize(24);
    bytes.insert(bytes.end(),{0xe8,0,0,1,0,0x48,0x8b,0x6c,0x24,0x30,0x48,0x83,0xc4,0x38,0xc3});
    bytes.insert(bytes.end(),{0x90,0x48,0x8b,0x6c,0x24,0x30,0x48,0x83,0xc4,0x38,0xc3});
    edges = {{14,24,true},{29,39,true}};
    require(analyseCase() && at(spans,24).proven && at(spans,39).proven,
            "Nested protected handler call lost its saved slot");
    total += contexts(bytes,spans);
    edges.push_back({23,24,false});
    require(analyseCase() && !at(spans,24).proven && !at(spans,39).proven,
            "Unknown handler entry did not propagate through nested call");
    return total;
}
static unsigned legacyEmptyMetadata(unsigned version) {
    auto bytes = code();
    std::vector<unsigned char> descriptors(48), table;
    auto integer = [&](std::size_t offset,std::int32_t value) {
        std::memcpy(descriptors.data() + offset,&value,sizeof(value));
    };
    integer(0,-1); integer(16,14); integer(32,static_cast<std::int32_t>(bytes.size() + 1));
    Handlers::Source source{version,reinterpret_cast<std::uintptr_t>(bytes.data()),0,56,true,
        {16,0,12},bytes,table,descriptors,Handlers::ImplicitExceptionProof::EmptyByExtent};
    Handlers::Snapshot snapshot;
    auto error = Handlers::parse(source,snapshot);
    require(!error,error ? error : "Legacy empty-handler metadata was rejected");
    Layout layout{snapshot.address(),0,snapshot.entry(),snapshot.allocation(),true,true};
    std::vector<Span> spans;
    require(analyse(snapshot.code().data(),snapshot.code().size(),layout,spans,snapshot.edges()) &&
            at(spans,14).proven,"Legacy empty-handler call lost its frame proof");
    auto total = contexts(bytes,spans);
    integer(28,2);
    require(Handlers::parse(source,snapshot) != nullptr,"Legacy method-handle return escaped metadata cutoff");
    integer(28,0);
    source.implicitExceptionProof = Handlers::ImplicitExceptionProof::Unproved;
    require(Handlers::parse(source,snapshot) != nullptr,"Legacy implicit continuation escaped metadata cutoff");
    source.implicitExceptionProof = Handlers::ImplicitExceptionProof::EmptyByExtent;
    source.singleEntry = false;
    require(Handlers::parse(source,snapshot) != nullptr,"Legacy secondary entry escaped metadata cutoff");
    return total;
}
static void instructionEffects() {
    const std::vector<unsigned char> before{
        0x55,0xbd,0x02,0,0,0,            // Preserve caller RBP; use two as the divisor.
        0x48,0x83,0xec,0x38,
        0x48,0xc7,0x44,0x24,0x30,0x02,0,0,0,
        0x49,0x89,0xe8,0x49,0x89,0xe1,    // mov r8,rbp; mov r9,rsp
        0xb8,0x10,0,0,0,0x31,0xd2,0xb9,0x02,0,0,0
    };
    const std::vector<unsigned char> after{
        0x4c,0x39,0xc5,0x0f,0x94,0xc0, // cmp rbp,r8; sete al
        0x4c,0x39,0xcc,0x0f,0x94,0xc2, // cmp rsp,r9; sete dl
        0x20,0xd0,
        0x48,0x83,0x7c,0x24,0x30,0x02,0x0f,0x94,0xc2, // Slot remains unchanged.
        0x20,0xd0,0x0f,0xb6,0xc0,0x48,0x83,0xc4,0x38,0x5d,0xc3
    };
    for (const auto& op : {std::vector<unsigned char>{0x99},{0x48,0x99},
            {0xf7,0xf1},{0xf7,0xf9},{0x48,0xf7,0xf1},{0x48,0xf7,0xf9},
            {0x66,0xf7,0xf1},{0x66,0xf7,0xf9},{0xc5,0xf8,0x77},
            {0xf7,0xf5},{0x48,0xf7,0xfd},{0x48,0xf7,0x7c,0x24,0x30},
            {0xf7,0x74,0x24,0x30},{0x66,0xf7,0x7c,0x24,0x30}}) {
        auto bytes = before;
        bytes.insert(bytes.end(),op.begin(),op.end());
        bytes.insert(bytes.end(),after.begin(),after.end());
        auto memory = static_cast<unsigned char*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
        require(memory != nullptr,"Cannot allocate instruction effect fixture");
        std::memcpy(memory,bytes.data(),bytes.size());
        DWORD previous;
        require(VirtualProtect(memory,4096,PAGE_EXECUTE_READ,&previous) &&
                FlushInstructionCache(GetCurrentProcess(),memory,bytes.size()),"Cannot prepare instruction effect fixture");
        require(reinterpret_cast<unsigned (*)()>(memory)() == 1,"Admitted neutral instruction changed RSP/RBP");
        require(VirtualFree(memory,0,MEM_RELEASE),"Cannot release instruction effect fixture");
    }
}
static std::vector<unsigned char> file(const char* path) {
    std::ifstream input(path,std::ios::binary);
    require(input.good(),"Cannot open saved compiled-handler fixture");
    return {std::istreambuf_iterator<char>(input),std::istreambuf_iterator<char>()};
}
static unsigned captured(char** argv) {
    auto bytes = file(argv[1]), table = file(argv[2]), descriptors = file(argv[3]);
    auto address = reinterpret_cast<std::uintptr_t>(bytes.data());
    auto displacement = std::stoll(argv[4],nullptr,0);
    auto allocation = static_cast<std::uint32_t>(std::stoul(argv[5]));
    auto version = static_cast<unsigned>(std::stoul(argv[6]));
    Handlers::Source source{version,address,0,allocation,true,{16,0,12},bytes,table,descriptors,Handlers::ImplicitExceptionProof::EmptyByExtent};
    Handlers::Snapshot snapshot;
    auto error = Handlers::parse(source,snapshot);
    require(error == nullptr,error ? error : "Captured handler metadata parse failed");
    auto edges = std::vector<HandlerEdge>(snapshot.edges().begin(),snapshot.edges().end());
    auto ownedCode = std::vector<unsigned char>(snapshot.code().begin(),snapshot.code().end());
    // The solver consumes the owning snapshot after all input buffers die.
    std::fill(bytes.begin(),bytes.end(),0xcc);
    std::fill(table.begin(),table.end(),0);
    std::fill(descriptors.begin(),descriptors.end(),0);
    std::vector<unsigned char>().swap(bytes);
    std::vector<unsigned char>().swap(table);
    std::vector<unsigned char>().swap(descriptors);
    Layout layout{snapshot.address(),std::uintptr_t(std::intptr_t(address) + displacement),
        snapshot.entry(),snapshot.allocation(),snapshot.edges().empty(),true};
    std::vector<Span> spans;
    require(analyse(snapshot.code().data(),snapshot.code().size(),layout,spans,snapshot.edges()),
            "Captured handler CFI analysis failed");
    for (const auto& edge : edges) {
        require(edge.callReturn,"Captured handler lost exact PcDesc classification");
        require(at(spans,edge.target).proven && at(spans,edge.target).fpOffset >= 0,
                "Captured handler entry did not restore from a proved slot");
    }
    auto total = contexts(ownedCode,spans);
    std::printf("COMPILED_HANDLER_CAPTURE version=%u bytes=%zu edges=%zu contexts=%u\n",
        version,ownedCode.size(),edges.size(),total);
    return total;
}
int main(int argc,char** argv) {
    require(argc == 1 || argc == 7,"Expected optional code/table/pcdesc/barrier-displacement/allocation/version");
    auto total = edgeCases();
    for (unsigned version : {8u,11u,17u}) total += legacyEmptyMetadata(version);
    instructionEffects();
    if (argc == 7) total += captured(argv);
    std::printf("COMPILED_HANDLERS_OK contexts=%u checks=%u\n",total,checks);
}
