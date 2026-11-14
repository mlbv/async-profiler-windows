/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsCompiledUnwind.h"
#include "windowsInstructionDecoder.h"
#include "native_compiled_unwind_oracle.h"
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <fstream>
#include <iterator>

namespace {
using namespace WindowsProfiler::JavaUnwind::Compiled;
unsigned cases = 0, checked = 0;
const Span& at(const std::vector<Span>& spans, unsigned pc) {
    for (const auto& span : spans) if (span.begin <= pc && pc < span.end) return span;
    std::abort();
}
void instruction(const std::vector<unsigned char>& bytes, bool supported, bool saved = true) {
    std::vector<unsigned char> code{0x48,0x83,0xec,0x38,0x48,0x89,0x6c,0x24,0x30,0x48,0x31,0xed};
    code.insert(code.end(), bytes.begin(), bytes.end());
    auto after = static_cast<unsigned>(code.size());
    code.insert(code.end(), {0x90,0x48,0x8b,0x6c,0x24,0x30,0x48,0x83,0xc4,0x38,0xc3});
    Layout layout{reinterpret_cast<std::uintptr_t>(code.data()),0,0,56,true,true};
    std::vector<Span> spans;
    if (!supported) spans.push_back({1,2,40,32,true});
    auto accepted = analyse(code.data(),code.size(),layout,spans);
    if (accepted != supported) {
        std::fprintf(stderr,"SCALAR_ENCODING_FAILURE case=%u expected=%d bytes=",cases,supported);
        for (auto byte : bytes) std::fprintf(stderr,"%02x",byte);
        std::fputc('\n',stderr);
    }
    assert(accepted == supported);
    if (supported) {
        assert(at(spans,after).proven == saved);
        if (saved) assert(at(spans,after).fpOffset == 48 && at(spans,after).returnOffset == 56);
        checked += contexts(code,spans);
    } else assert(spans.size() == 1 && spans[0].begin == 1 && spans[0].end == 2
        && spans[0].returnOffset == 40 && spans[0].fpOffset == 32 && spans[0].proven);
    ++cases;
}
void unchanged(const std::vector<Span>& spans) {
    assert(spans.size() == 1 && spans[0].begin == 1 && spans[0].end == 2
        && spans[0].returnOffset == 40 && spans[0].fpOffset == 32 && spans[0].proven);
}
void fmaFrame(const std::vector<unsigned char>& bytes,unsigned frame) {
    std::vector<unsigned char> code{0x48,0x83,0xec,0x38,0x48,0x89,0x6c,0x24,0x30};
    if (frame != 1) code.insert(code.end(),{0x48,0x31,0xed});
    if (frame == 2) code.insert(code.end(),{0x48,0x89,0x4c,0x04,0x28});
    if (frame == 3) code.insert(code.end(),{0x48,0x83,0xec,4});
    auto source = static_cast<unsigned>(code.size());
    code.insert(code.end(),bytes.begin(),bytes.end());
    auto after = static_cast<unsigned>(code.size());
    code.insert(code.end(),{0x90,0x48,0x8b,0x6c,0x24,0x30,0x48,0x83,0xc4,0x38,0xc3});
    Layout layout{reinterpret_cast<std::uintptr_t>(code.data()),0,0,56,true,true};
    std::vector<Span> spans;
    assert(analyse(code.data(),code.size(),layout,spans));
    const auto& beforeRule = at(spans,source);
    const auto& afterRule = at(spans,after);
    assert(beforeRule.proven == (frame < 2) && beforeRule.proven == afterRule.proven
        && beforeRule.returnOffset == afterRule.returnOffset && beforeRule.fpOffset == afterRule.fpOffset);
    if (beforeRule.proven) {
        assert(beforeRule.returnOffset == 56 && beforeRule.fpOffset == (frame == 1 ? -1 : 48));
        unsigned char before[16], afterInfo[16];
        unwindInfo(before,beforeRule); unwindInfo(afterInfo,afterRule);
        assert(!std::memcmp(before,afterInfo,sizeof(before)));
    }
    assert(at(spans,after + 10).proven == (frame < 2));
    checked += contexts(code,spans);
    ++cases;
}
void fmaFault(const std::vector<unsigned char>& bytes,bool live) {
    std::vector<unsigned char> code{0x48,0x83,0xec,0x38,0x48,0x89,0x6c,0x24,0x30};
    if (!live) code.insert(code.end(),{0x48,0x31,0xed});
    auto source = static_cast<unsigned>(code.size());
    code.insert(code.end(),bytes.begin(),bytes.end());
    auto normal = static_cast<unsigned>(code.size());
    code.insert(code.end(),{0x48,0x8b,0x6c,0x24,0x30,0x48,0x83,0xc4,0x38,0xc3});
    auto target = static_cast<unsigned>(code.size());
    code.insert(code.end(),{0x90,0x48,0x8b,0x6c,0x24,0x30,0x48,0x83,0xc4,0x38,0xc3});
    Layout layout{reinterpret_cast<std::uintptr_t>(code.data()),0,0,56,true,true};
    FaultEdge edge{source,target};
    std::vector<Span> spans;
    assert(analyse(code.data(),code.size(),layout,spans,{},std::span{&edge,1}));
    assert(at(spans,source).proven && at(spans,normal).proven
        && at(spans,source).fpOffset == (live ? -1 : 48));
    for (auto pc : {target,target + 1,target + 6,target + 10}) assert(!at(spans,pc).proven);
    checked += contexts(code,spans);
    edge.target = source;
    spans = {{1,2,40,32,true}};
    assert(!analyse(code.data(),code.size(),layout,spans,{},std::span{&edge,1}));
    unchanged(spans);
    edge = {source + 1,target};
    assert(!analyse(code.data(),code.size(),layout,spans,{},std::span{&edge,1}));
    unchanged(spans);
    edge = {source,source + 1};
    assert(!analyse(code.data(),code.size(),layout,spans,{},std::span{&edge,1}));
    unchanged(spans);
    cases += 4;
}
void truncated(const std::vector<unsigned char>& bytes) {
    assert(WindowsProfiler::InstructionDecoder::length(bytes.data(),bytes.size()) == bytes.size());
    for (size_t length = 0; length < bytes.size(); ++length) {
        assert(!WindowsProfiler::InstructionDecoder::length(bytes.data(),length));
        Layout layout{reinterpret_cast<std::uintptr_t>(bytes.data()),0,0,0,true,true};
        std::vector<Span> spans{{1,2,40,32,true}};
        assert(!analyse(bytes.data(),length,layout,spans));
        unchanged(spans);
        ++cases;
    }
}
void fma() {
    for (unsigned opcode : {0x99u,0xa9u,0xb9u}) {
        auto op = static_cast<unsigned char>(opcode);
        for (const auto& bytes : {std::vector<unsigned char>{0xc4,0xe2,0xf9,op,0xe5},
                {0xc4,0x02,0xd1,op,0xe5},{0xc4,0xe2,0xf9,op,0x6c,0x24,0x30},
                {0xc4,0xc2,0xd1,op,0x6c,0x24,0x30},{0xc4,0xa2,0xf9,op,0x6c,0x24,0x30},
                {0xc4,0xe2,0xf9,op,0x6c,0x0c,0x30},{0xc4,0xe2,0xf9,op,0x6d,0},
                {0xc4,0xe2,0xf9,op,0x2d,0,0,0,0},{0xc4,0xe2,0xd1,op,0xa4,0x24,0x30,0,0,0},
                {0x62,0xf2,0xfd,0x08,op,0xe5},{0x62,0x02,0xd5,0x08,op,0xe5},
                {0x62,0xf2,0xfd,0x08,op,0x6c,0x24,6},{0x62,0xf2,0xfd,0x08,op,0x6c,0x24,0xff},
                {0x62,0xf2,0xfd,0x08,op,0x6c,0x24,0x80},{0x62,0xf2,0xfd,0x08,op,0x6c,0x24,0x7f},
                {0x62,0xd2,0xd5,0x08,op,0x6c,0x24,6},{0x62,0xb2,0xfd,0x08,op,0x6c,0x24,6},
                {0x62,0xf2,0xfd,0x08,op,0x6c,0x0c,6},{0x62,0xf2,0xfd,0x08,op,0x6d,0},
                {0x62,0xf2,0xfd,0x08,op,0x2d,0,0,0,0},{0x62,0xf2,0xd5,0x08,op,0xa4,0x24,0x30,0,0,0}}) {
            instruction(bytes,true);
        }
        for (const auto& bytes : {std::vector<unsigned char>{0xc4,0xe2,0xf9,op,0xe5},
                {0xc4,0xe2,0xf9,op,0x6c,0x24,0x30},{0xc4,0xe2,0xd1,op,0x08},
                {0x62,0xf2,0xfd,0x08,op,0xe5},{0x62,0xf2,0xfd,0x08,op,0x6c,0x24,6},
                {0x62,0xf2,0xd5,0x08,op,0x08}}) {
            for (unsigned frame = 0; frame < 4; ++frame) fmaFrame(bytes,frame);
            fmaFault(bytes,false);
            fmaFault(bytes,true);
            truncated(bytes);
            for (auto prefix : {0x66,0xf0,0xf2,0xf3,0x48,0x67,0x65}) {
                auto prefixed = bytes;
                prefixed.insert(prefixed.begin(),static_cast<unsigned char>(prefix));
                instruction(prefixed,false);
            }
        }
        for (unsigned prefix : {0x79u,0xfdu,0xf8u,0xfau,0xfbu})
            instruction({0xc4,0xe2,static_cast<unsigned char>(prefix),op,0xe5},false);
        for (unsigned map : {0xe0u,0xe1u,0xe3u,0xe6u})
            instruction({0xc4,static_cast<unsigned char>(map),0xf9,op,0xe5},false);
        instruction({0xc5,0xf9,op,0xe5},false);
        for (unsigned prefix : {0x7du,0xf9u,0xfcu,0xfeu,0xffu})
            instruction({0x62,0xf2,static_cast<unsigned char>(prefix),0x08,op,0xe5},false);
        for (unsigned controls : {0x00u,0x09u,0x18u,0x28u,0x48u,0x88u})
            instruction({0x62,0xf2,0xfd,static_cast<unsigned char>(controls),op,0xe5},false);
        for (unsigned map : {0xf0u,0xf1u,0xf3u,0xf6u})
            instruction({0x62,static_cast<unsigned char>(map),0xfd,0x08,op,0xe5},false);
    }
    for (unsigned opcode : {0x98u,0xa8u,0xb8u,0x9bu,0xabu,0xbbu,0x9du,0xadu,0xbdu,0x9fu,0xafu,0xbfu}) {
        instruction({0xc4,0xe2,0xf9,static_cast<unsigned char>(opcode),0xe5},false);
        instruction({0x62,0xf2,0xfd,0x08,static_cast<unsigned char>(opcode),0xe5},false);
    }
    // Independent register-vector moves retain the captured workload's cutoff.
    instruction({0xc5,0xf9,0x28,0xda},false);
    instruction({0xc5,0xf9,0x10,0xc3},false);
    instruction({0x62,0xf1,0xfd,0x08,0x10,0xd9},false);
}
}
int main(int argc, char** argv) {
    bool unsupported = argc == 7 && std::strcmp(argv[1],"--unsupported") == 0;
    if (argc == 6 || unsupported) {
        if (unsupported) { ++argv; --argc; }
        std::ifstream input(argv[1],std::ios::binary);
        assert(input);
        std::vector<unsigned char> code((std::istreambuf_iterator<char>(input)),std::istreambuf_iterator<char>());
        Layout layout{std::strtoull(argv[2],nullptr,16),std::strtoull(argv[3],nullptr,16),
            static_cast<std::size_t>(std::strtoull(argv[4],nullptr,10)),
            static_cast<std::uint32_t>(std::strtoul(argv[5],nullptr,10)),true,true};
        std::vector<Span> spans;
        if (unsupported) spans.push_back({1,2,40,32,true});
        bool accepted = analyse(code.data(),code.size(),layout,spans);
        if (unsupported) {
            assert(!accepted);
            unchanged(spans);
            std::printf("COMPILED_SCALAR_UNSUPPORTED_OK bytes=%zu resultUnchanged=1\n",code.size());
            return 0;
        }
        assert(accepted);
        unsigned proven = 0;
        for (const auto& span : spans) if (span.proven) proven += span.end - span.begin;
        auto count = contexts(code,spans);
        assert(count && proven > code.size() / 2);
        std::printf("COMPILED_SCALAR_CAPTURE bytes=%zu contexts=%u proven=%u\n",code.size(),count,proven);
        return 0;
    }
    assert(argc == 1);
    fma();
    for (const auto& bytes : {std::vector<unsigned char>{0x3d,1,0,0,0},
            {0x66,0x3d,1,0},{0x48,0x3d,1,0,0,0}}) {
        instruction(bytes,true);
        fmaFrame(bytes,1);
        fmaFault(bytes,false);
        auto locked = bytes;
        locked.insert(locked.begin(),0xf0);
        instruction(locked,false);
        truncated(bytes);
    }
    instruction({0x3c,1},false);
    for (auto prefix : {0xfau,0xfbu}) for (auto opcode : {0x51u,0x58u,0x59u,0x5cu,0x5du,0x5eu,0x5fu}) {
        instruction({0xc5,static_cast<unsigned char>(prefix),static_cast<unsigned char>(opcode),0xe5},true);
        instruction({0xc4,0x01,static_cast<unsigned char>(prefix & 0x7f),static_cast<unsigned char>(opcode),0xe5},true);
        instruction({0xc5,static_cast<unsigned char>(prefix),static_cast<unsigned char>(opcode),0x6c,0x24,0x30},true);
    }
    instruction({0xc5,0xfb,0x10,0x6c,0x24,0x30},true);
    instruction({0xc5,0xfa,0x10,0x6c,0x24,0x30},true);
    instruction({0xc5,0xeb,0x10,0xe5},true); // Register merge reads VEX.vvvv.
    instruction({0xc5,0xeb,0x11,0xe5},true);
    instruction({0xc5,0xfb,0x11,0x64,0x24,0x28},true); // Ends exactly below the saved slot.
    instruction({0xc5,0xfa,0x11,0x64,0x24,0x2c},true);
    instruction({0xc5,0xfb,0x11,0x64,0x24,0x29},true,false);
    instruction({0xc5,0xfa,0x11,0x64,0x24,0x2d},true,false);
    instruction({0xc5,0xfb,0x11,0x64,0x24,0x30},true,false);
    instruction({0xc5,0xfb,0x11,0x64,0x24,0x38},true);
    instruction({0xc5,0xfb,0x11,0xa4,0x24,0x30,0x00,0x00,0x00},true,false);
    instruction({0xc5,0xfb,0x11,0x64,0x0c,0x28},true,false); // Unknown indexed address.
    instruction({0xc4,0xc1,0x7b,0x11,0x64,0x24,0x28},true,true); // An R12 base is not RSP.
    instruction({0xc4,0xa1,0x7b,0x11,0x64,0x24,0x28},true,false); // RSP with an R12 index can alias.
    instruction({0xc5,0xfb,0x11,0x25,0,0,0,0},true,true); // A RIP-relative store is not RSP-based.
    instruction({0xc5,0xeb,0x10,0x6c,0x24,0x30},false); // Memory forms reserve vvvv.
    instruction({0xc5,0xeb,0x11,0x6c,0x24,0x30},false);
    instruction({0xc5,0xff,0x59,0xe5},false); // L must be zero in this proof.
    instruction({0xc4,0xe1,0xfb,0x59,0xe5},false); // W=1 remains outside this subset.
    instruction({0xc4,0xe2,0x7b,0x59,0xe5},false);
    instruction({0xc5,0xf9,0x59,0xe5},false); // Packed arithmetic is not scalar.
    instruction({0xc5,0xf8,0x59,0xe5},false);
    instruction({0xc5,0xfb,0x2c,0xe5},false); // GPR conversion destination could be RSP.
    instruction({0xc5,0xfb,0x2d,0xed},false); // Or RBP.
    instruction({0xc5,0xfb,0x7e,0xed},false);
    instruction({0x66,0xc5,0xfb,0x59,0xe5},false);
    instruction({0xf0,0xc5,0xfb,0x59,0xe5},false);
    instruction({0xc5,0xfb,0x59},false);
    instruction({0xc4,0xe1,0x7b,0x59},false);
    instruction({0x62,0xf1,0xf7,0x08,0x58,0xe5},true); // XMM4/XMM5 are not stack registers.
    instruction({0x62,0xe1,0xf7,0x08,0x59,0xe5},true); // High vector destination.
    instruction({0x62,0x91,0xf7,0x08,0x58,0xe5},true); // High vector r/m source.
    instruction({0x62,0xf1,0xff,0x08,0x10,0x6c,0x24,0x06},true);
    instruction({0x62,0xf1,0xff,0x08,0x59,0x6c,0x24,0x80},true);
    instruction({0x62,0xf1,0xff,0x08,0x11,0x64,0x24,0x05},true);
    instruction({0x62,0xf1,0xff,0x08,0x11,0x64,0x24,0x06},true,false); // Encoded 6 addresses +48.
    instruction({0x62,0xf1,0xff,0x08,0x11,0x64,0x24,0x07},true);
    instruction({0x62,0xf1,0xff,0x08,0x11,0x64,0x24,0xff},true); // Signed -1 addresses -8.
    instruction({0x62,0xf1,0xff,0x08,0x11,0x64,0x24,0x80},true);
    instruction({0x62,0xf1,0xff,0x08,0x11,0x64,0x24,0x7f},true);
    instruction({0x62,0xf1,0xff,0x08,0x11,0xa4,0x24,0x29,0,0,0},true,false); // disp32 is unscaled.
    instruction({0x62,0xf1,0xff,0x08,0x11,0xa4,0x24,0x38,0,0,0},true);
    instruction({0x62,0xd1,0xff,0x08,0x11,0x64,0x24,0x05},true,true); // R12 base.
    instruction({0x62,0xb1,0xff,0x08,0x11,0x64,0x24,0x05},true,false); // R12 index.
    instruction({0x62,0xf1,0xff,0x08,0x11,0x64,0x0c,0x05},true,false);
    instruction({0x62,0xf1,0xff,0x08,0x11,0x25,0,0,0,0},true,true);
    instruction({0x62,0xf1,0xf7,0x08,0x10,0x6c,0x24,0x06},false);
    instruction({0x62,0xf1,0xf7,0x08,0x11,0x6c,0x24,0x06},false);
    instruction({0x62,0xf1,0xff,0x08,0x10,0xe5},false); // Register merge is outside this profile.
    instruction({0x62,0xf1,0xff,0x08,0x11,0xe5},false);
    instruction({0x62,0xf1,0xf7,0x09,0x58,0xe5},false); // Masking.
    instruction({0x62,0xf1,0xf7,0x88,0x58,0xe5},false); // Zeroing.
    instruction({0x62,0xf1,0xf7,0x18,0x58,0xe5},false); // Embedded rounding/broadcast.
    instruction({0x62,0xf1,0xf7,0x28,0x58,0xe5},false); // LIG variant outside the narrow profile.
    instruction({0x62,0xf1,0xf7,0x00,0x58,0xe5},false); // High NDS source outside the profile.
    instruction({0x62,0xf1,0x77,0x08,0x58,0xe5},false); // Wrong W for SD.
    instruction({0x62,0xf1,0xf6,0x08,0x58,0xe5},false); // Wrong mandatory prefix.
    instruction({0x62,0xf1,0xf3,0x08,0x58,0xe5},false); // Missing fixed prefix bit.
    instruction({0x62,0xf2,0xf7,0x08,0x58,0xe5},false); // Wrong opcode map.
    instruction({0x62,0xf5,0xf7,0x08,0x58,0xe5},false); // Reserved map bits.
    instruction({0x62,0xf1,0xf7,0x08,0x5c,0xe5},false); // No automatic widening to other scalar opcodes.
    instruction({0x66,0x62,0xf1,0xf7,0x08,0x58,0xe5},false);
    std::printf("COMPILED_SCALAR_OK cases=%u contexts=%u savedSlotAliasing=1 xmmNotGpr=1 evexDisp8Scale=8 fmaSd=3 fmaFaultProof=0\n",cases,checked);
}
