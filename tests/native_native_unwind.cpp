/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsNativeUnwind.h"
#include <windows.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <utility>

namespace {
using namespace WindowsProfiler;
struct Fixture {
    // PUSH RBX; SUB RSP,64; MOV [RSP+32],RSI; MOVUPS [RSP+48],XMM6.
    // The following NOP keeps the last post-state outside an epilog.
    std::vector<unsigned char> code{0x53,0x48,0x83,0xec,0x40,0x48,0x89,0x74,0x24,0x20,
        0x0f,0x11,0x74,0x24,0x30,0x90,0xc3};
    std::vector<unsigned char> unwind{1,15,6,0,15,0x68,3,0,10,0x64,4,0,5,0x72,1,0x30};
    NativeUnwind::Source source(size_t probe) const { return {code,unwind,probe}; }
};
constexpr unsigned farAllocation = 0x100040, farGprOffset = 0x80008, farXmmOffset = 0x100000;
enum class Shape { General, Framed, Far, FramedFar };
Fixture farFixture(bool framed) {
    Fixture fixture;
    fixture.code = {0x48,0x81,0xec,0x40,0,0x10,0};
    if (framed) {
        fixture.code.insert(fixture.code.begin(),0x55);
        fixture.code.insert(fixture.code.end(),{0x48,0x8d,0x6c,0x24,0x20});
    }
    fixture.code.insert(fixture.code.end(),{0x48,0x89,0xb4,0x24,8,0,8,0,0x0f,0x11,0xb4,0x24,0,0,0x10,0,0x90,0xc3});
    unsigned allocationEnd = framed ? 8 : 7, frameEnd = framed ? 13 : 7, gprEnd = frameEnd + 8, xmmEnd = gprEnd + 8;
    fixture.unwind = {1,static_cast<unsigned char>(xmmEnd),static_cast<unsigned char>(framed ? 11 : 9),
        static_cast<unsigned char>(framed ? 0x25 : 0),static_cast<unsigned char>(xmmEnd),0x69,0,0,0x10,0,
        static_cast<unsigned char>(gprEnd),0x65,8,0,8,0};
    if (framed) fixture.unwind.insert(fixture.unwind.end(),{static_cast<unsigned char>(frameEnd),0x53});
    fixture.unwind.insert(fixture.unwind.end(),{static_cast<unsigned char>(allocationEnd),0x11,0x40,0,0x10,0});
    if (framed) fixture.unwind.insert(fixture.unwind.end(),{1,0x50});
    while (fixture.unwind.size() % 4) fixture.unwind.push_back(0);
    return fixture;
}
Fixture longFixture(unsigned operation, unsigned detail, std::uint32_t value, unsigned slots = 3) {
    Fixture fixture;
    fixture.unwind = {1,5,static_cast<unsigned char>(slots),0,5,static_cast<unsigned char>((detail << 4) | operation)};
    for (unsigned byte = 0; byte < (slots - 1) * 2; ++byte)
        fixture.unwind.push_back(static_cast<unsigned char>(value >> (byte * 8)));
    while (fixture.unwind.size() % 4) fixture.unwind.push_back(0);
    return fixture;
}
void append32(std::vector<unsigned char>& bytes, std::uint32_t value) {
    for (unsigned byte = 0; byte < 4; ++byte) bytes.push_back(static_cast<unsigned char>(value >> (byte * 8)));
}
void trailer(std::vector<unsigned char>& info, const NativeUnwind::ChainEntry& parent) {
    info[0] = (info[0] & 7) | (4 << 3);
    info.resize(4 + ((static_cast<size_t>(info[2]) + 1) & ~size_t(1)) * 2);
    append32(info,parent.begin); append32(info,parent.end); append32(info,parent.unwindRva);
}
struct ChainedFixture {
    bool framed, usesFar, nested;
    std::uint32_t primaryBegin = 0, primaryEnd, primaryRva = 4096;
    std::uint32_t middleBegin = 128, middleEnd, middleRva = 4160;
    std::vector<unsigned char> primaryCode, primaryInfo, middleCode, middleInfo, sourceCode, sourceInfo;
    ChainedFixture(unsigned version, bool anchored, bool distant, bool multiple)
        : framed(anchored), usesFar(distant), nested(multiple) {
        auto frame = static_cast<unsigned char>(framed ? 0x25 : 0);
        if (usesFar) {
            auto complete = farFixture(framed);
            primaryCode.assign(complete.code.begin(),complete.code.begin() + (framed ? 13 : 7));
            primaryCode.insert(primaryCode.end(),{0x90,0xc3});
            primaryInfo = framed ? std::vector<unsigned char>{1,13,5,0x25,13,0x53,8,0x11,0x40,0,0x10,0,1,0x50,0,0}
                : std::vector<unsigned char>{1,7,3,0,7,0x11,0x40,0,0x10,0,0,0};
            sourceCode = {0x48,0x89,0xb4,0x24,8,0,8,0,0x0f,0x11,0xb4,0x24,0,0,0x10,0,0x90,0xc3};
            sourceInfo = {1,16,6,frame,16,0x69,0,0,0x10,0,8,0x65,8,0,8,0};
        } else {
            primaryCode = framed ? std::vector<unsigned char>{0x55,0x48,0x83,0xec,0x40,0x48,0x8d,0x6c,0x24,0x20,0x90,0xc3}
                : std::vector<unsigned char>{0x53,0x48,0x83,0xec,0x40,0x90,0xc3};
            primaryInfo = framed ? std::vector<unsigned char>{1,10,3,0x25,10,0x53,5,0x72,1,0x50,0,0}
                : std::vector<unsigned char>{1,5,2,0,5,0x72,1,0x30};
            sourceCode = {0x48,0x89,0x7c,0x24,0x28,0x90,0xc3};
            sourceInfo = {1,5,2,frame,5,0x74,5,0};
            if (nested) {
                middleCode = {0x48,0x89,0x74,0x24,0x20,0x90,0xc3};
                middleInfo = {static_cast<unsigned char>(version),5,2,frame,5,0x64,4,0};
            } else {
                sourceCode.insert(sourceCode.begin(),{0x48,0x89,0x74,0x24,0x20});
                sourceInfo = {1,10,4,frame,10,0x74,5,0,5,0x64,4,0};
            }
        }
        primaryInfo[0] = sourceInfo[0] = static_cast<unsigned char>(version);
        primaryEnd = static_cast<std::uint32_t>(primaryCode.size());
        middleEnd = middleBegin + static_cast<std::uint32_t>(middleCode.size());
        syncTrailers();
    }
    std::vector<NativeUnwind::ChainEntry> parents() const {
        NativeUnwind::ChainEntry primary{primaryBegin,primaryEnd,primaryRva,primaryCode,primaryInfo};
        if (nested) return {{middleBegin,middleEnd,middleRva,middleCode,middleInfo},primary};
        return {primary};
    }
    void syncTrailers() {
        auto entries = parents();
        if (nested) trailer(middleInfo,entries.back());
        trailer(sourceInfo,entries.front());
    }
    NativeUnwind::Source source(size_t probe, std::span<const NativeUnwind::ChainEntry> entries) const {
        return {sourceCode,sourceInfo,probe,entries};
    }
};
unsigned rejectedCases, unsignedPayloadCases, chainBoundaryCases;
void rejectSource(const NativeUnwind::Source& source, InstructionDecoder::Relocation relocation, const char* expected) {
    NativeUnwind::Recipe result{{0xaa},{0xbb},99};
    auto error = NativeUnwind::derive(source, relocation, result);
    if (!error || std::strcmp(error,expected)) {
        std::fprintf(stderr,"Expected %s, received %s\n",expected,error ? error : "success");
        std::abort();
    }
    assert(result.before == std::vector<unsigned char>{0xaa} && result.after == std::vector<unsigned char>{0xbb}
        && result.sourceVersion == 99);
    ++rejectedCases;
}
void reject(const Fixture& fixture, size_t probe, InstructionDecoder::Relocation relocation, const char* expected) {
    rejectSource(fixture.source(probe),relocation,expected);
}
CONTEXT unwind(CONTEXT context, unsigned char* image, RUNTIME_FUNCTION function, DWORD64& frame) {
    void* handlerData = nullptr;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(image),context.Rip,&function,
        &context,&handlerData,&frame,nullptr);
    return context;
}
unsigned contexts(unsigned version, Shape shape = Shape::General) {
    bool framed = shape == Shape::Framed || shape == Shape::FramedFar;
    bool usesFar = shape == Shape::Far || shape == Shape::FramedFar;
    Fixture fixture;
    if (usesFar) fixture = farFixture(framed);
    else if (framed) {
        // MASM emits SET_FPREG as 0x53 for RBP; its OpInfo nibble is unused.
        // The header establishes RBP as RSP+32 after the LEA completes.
        fixture.code = {0x55,0x48,0x83,0xec,0x40,0x48,0x8d,0x6c,0x24,0x20,0x90,0xc3};
        fixture.unwind = {1,10,3,0x25,10,0x53,5,0x72,1,0x50,0,0};
    }
    fixture.unwind[0] = static_cast<unsigned char>(version);
    auto image = static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE));
    assert(image);
    std::memcpy(image,fixture.code.data(),fixture.code.size());
    std::memcpy(image + 4096,fixture.unwind.data(),fixture.unwind.size());
    constexpr DWORD64 caller = 0x12345678, rbx = 0x1122334455667788, rsi = 0x8877665544332211,
        rbp = 0x1357135713571357, poison = 0xbad0bad0bad0bad0;
    constexpr M128A xmm{0x1234123412341234,0x5678567856785678};
    unsigned checked = 0;
    auto probes = usesFar ? (framed ? std::vector<size_t>{0,1,8,13,21} : std::vector<size_t>{0,7,15})
        : (framed ? std::vector<size_t>{0,1,5} : std::vector<size_t>{0,1,5,10});
    for (auto probe : probes) {
        auto length = InstructionDecoder::length(fixture.code.data() + probe,fixture.code.size() - probe);
        NativeUnwind::Recipe recipe;
        assert(!NativeUnwind::derive(fixture.source(probe),{length,length,nullptr},recipe));
        assert(recipe.sourceVersion == version && recipe.before[1] == 0 && recipe.after[1] == 0);
        std::memcpy(image + 64,fixture.code.data() + probe,length);
        std::memcpy(image + 4160,recipe.before.data(),recipe.before.size());
        std::memcpy(image + 4224,recipe.after.data(),recipe.after.size());
        for (bool post : {false,true}) {
            auto completed = probe + (post ? length : 0);
            std::vector<DWORD64> stack((usesFar ? farAllocation / 8 : 0) + 128);
            auto returnAddress = stack.data() + (usesFar ? farAllocation / 8 : 0) + 64;
            *returnAddress = caller;
            returnAddress[-1] = framed ? rbp : rbx;
            if (usesFar) {
                auto frame = reinterpret_cast<unsigned char*>(returnAddress) - farAllocation - (framed ? 8 : 0);
                std::memcpy(frame + farGprOffset,&rsi,sizeof(rsi));
                std::memcpy(frame + farXmmOffset,&xmm,sizeof(xmm));
            } else {
                returnAddress[-5] = rsi;
                std::memcpy(returnAddress - 3,&xmm,sizeof(xmm));
            }
            auto delta = usesFar ? (completed >= (framed ? 8u : 7u) ? farAllocation + (framed ? 8 : 0)
                    : framed && completed >= 1 ? 8u : 0u)
                : completed >= 5 ? 72u : completed >= 1 ? 8u : 0u;
            CONTEXT context{};
            context.Rip = reinterpret_cast<DWORD64>(image + completed);
            context.Rsp = reinterpret_cast<DWORD64>(returnAddress) - delta;
            context.Rbx = !framed && !usesFar && completed >= 1 ? poison : rbx;
            context.Rsi = (!framed || usesFar) && completed >= (usesFar ? (framed ? 21u : 15u) : 10u) ? poison : rsi;
            context.Rbp = framed && completed >= (usesFar ? 13u : 10u) ? context.Rsp + 32 : rbp;
            context.Xmm6 = (!framed || usesFar) && completed >= (usesFar ? (framed ? 29u : 23u) : 15u)
                ? M128A{poison,static_cast<LONGLONG>(poison)} : xmm;
            DWORD64 nativeFrame = 0, copiedFrame = 0;
            auto native = unwind(context,image,{0,static_cast<DWORD>(fixture.code.size()),4096},nativeFrame);
            context.Rip = reinterpret_cast<DWORD64>(image + 64 + (post ? length : 0));
            auto begin = static_cast<DWORD>(64 + (post ? length : 0));
            auto end = static_cast<DWORD>(64 + (post ? length + 2 : length));
            auto copied = unwind(context,image,{begin,end,post ? 4224u : 4160u},copiedFrame);
            assert(native.Rip == caller && native.Rsp == reinterpret_cast<DWORD64>(returnAddress + 1)
                && native.Rbx == rbx && native.Rsi == rsi && native.Rbp == rbp && !std::memcmp(&native.Xmm6,&xmm,sizeof(xmm)));
            assert(copied.Rip == native.Rip && copied.Rsp == native.Rsp && copied.Rbx == native.Rbx
                && copied.Rsi == native.Rsi && copied.Rbp == native.Rbp
                && !std::memcmp(&copied.Xmm6,&native.Xmm6,sizeof(xmm)) && copiedFrame == nativeFrame);
            ++checked;
        }
    }
    assert(VirtualFree(image,0,MEM_RELEASE));
    return checked;
}
unsigned chainContexts(unsigned version, bool framed, bool usesFar, bool nested) {
    ChainedFixture fixture(version,framed,usesFar,nested);
    // Mixed versions retain their own per-record interpretation while walking
    // the chain: a v2 secondary may inherit a complete v1 primary state.
    if (nested && version == 2) fixture.primaryInfo[0] = 1;
    auto parents = fixture.parents();
    auto image = static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE));
    assert(image);
    std::memcpy(image,fixture.primaryCode.data(),fixture.primaryCode.size());
    std::memcpy(image + 4096,fixture.primaryInfo.data(),fixture.primaryInfo.size());
    if (nested) {
        std::memcpy(image + 128,fixture.middleCode.data(),fixture.middleCode.size());
        std::memcpy(image + 4160,fixture.middleInfo.data(),fixture.middleInfo.size());
    }
    std::memcpy(image + 256,fixture.sourceCode.data(),fixture.sourceCode.size());
    std::memcpy(image + 4224,fixture.sourceInfo.data(),fixture.sourceInfo.size());
    constexpr DWORD64 caller = 0x12345678, rbx = 0x1122334455667788, rsi = 0x8877665544332211,
        rdi = 0x2468246824682468, rbp = 0x1357135713571357, poison = 0xbad0bad0bad0bad0;
    constexpr M128A xmm{0x1234123412341234,0x5678567856785678};
    unsigned checked = 0;
    auto probes = nested ? std::vector<size_t>{0} : (usesFar ? std::vector<size_t>{0,8} : std::vector<size_t>{0,5});
    for (auto probe : probes) {
        auto length = InstructionDecoder::length(fixture.sourceCode.data() + probe,fixture.sourceCode.size() - probe);
        NativeUnwind::Recipe recipe;
        assert(!NativeUnwind::derive(fixture.source(probe,parents),{length,length,nullptr},recipe));
        assert(recipe.sourceVersion == version);
        std::memcpy(image + 512,fixture.sourceCode.data() + probe,length);
        std::memcpy(image + 4352,recipe.before.data(),recipe.before.size());
        std::memcpy(image + 4480,recipe.after.data(),recipe.after.size());
        for (bool post : {false,true}) {
            auto completed = probe + (post ? length : 0);
            auto delta = usesFar ? farAllocation + (framed ? 8 : 0) : 72u;
            std::vector<DWORD64> stack(delta / 8 + 128);
            auto returnAddress = stack.data() + delta / 8 + 64;
            *returnAddress = caller;
            returnAddress[-1] = framed ? rbp : rbx;
            auto frame = reinterpret_cast<unsigned char*>(returnAddress) - delta;
            std::memcpy(frame + (usesFar ? farGprOffset : 32),&rsi,sizeof(rsi));
            std::memcpy(frame + 40,&rdi,sizeof(rdi));
            if (usesFar) std::memcpy(frame + farXmmOffset,&xmm,sizeof(xmm));
            CONTEXT context{};
            context.Rip = reinterpret_cast<DWORD64>(image + 256 + completed);
            context.Rsp = reinterpret_cast<DWORD64>(frame);
            context.Rbp = framed ? context.Rsp + 32 : rbp;
            context.Rbx = !framed && !usesFar ? poison : rbx;
            context.Rsi = nested || completed >= (usesFar ? 8u : 5u) ? poison : rsi;
            context.Rdi = !usesFar && completed >= (nested ? 5u : 10u) ? poison : rdi;
            context.Xmm6 = usesFar && completed >= 16 ? M128A{poison,static_cast<LONGLONG>(poison)} : xmm;
            DWORD64 nativeFrame = 0, copiedFrame = 0;
            auto native = unwind(context,image,{256,256 + static_cast<DWORD>(fixture.sourceCode.size()),4224},nativeFrame);
            context.Rip = reinterpret_cast<DWORD64>(image + 512 + (post ? length : 0));
            auto begin = static_cast<DWORD>(512 + (post ? length : 0));
            auto end = static_cast<DWORD>(512 + (post ? length + 2 : length));
            auto copied = unwind(context,image,{begin,end,post ? 4480u : 4352u},copiedFrame);
            assert(native.Rip == caller && native.Rsp == reinterpret_cast<DWORD64>(returnAddress + 1)
                && native.Rbx == rbx && native.Rsi == rsi && native.Rdi == rdi && native.Rbp == rbp
                && !std::memcmp(&native.Xmm6,&xmm,sizeof(xmm)));
            assert(copied.Rip == native.Rip && copied.Rsp == native.Rsp && copied.Rbx == native.Rbx
                && copied.Rsi == native.Rsi && copied.Rdi == native.Rdi && copied.Rbp == native.Rbp
                && !std::memcmp(&copied.Xmm6,&native.Xmm6,sizeof(xmm)) && copiedFrame == nativeFrame);
            ++checked;
        }
    }
    assert(VirtualFree(image,0,MEM_RELEASE));
    return checked;
}
void negatives() {
    auto change = [](auto edit) { Fixture fixture; edit(fixture); return fixture; };
    reject(change([](auto& f) { f.unwind.resize(3); }),0,{1,1,nullptr},"truncated-unwind-header");
    reject(change([](auto& f) { f.unwind[0] = 3; }),0,{1,1,nullptr},"unsupported-unwind-version");
    reject(change([](auto& f) { f.unwind[0] |= 4 << 3; }),0,{1,1,nullptr},"truncated-unwind-chain");
    reject(change([](auto& f) { f.unwind[0] |= 8 << 3; }),0,{1,1,nullptr},"invalid-unwind-flags");
    reject(change([](auto& f) { f.unwind[2] = 255; }),0,{1,1,nullptr},"truncated-unwind-codes");
    reject(change([](auto& f) { f.unwind[0] |= 1 << 3; }),0,{1,1,nullptr},"truncated-unwind-handler");
    reject(change([](auto& f) { f.unwind[0] |= 1 << 3; f.unwind.insert(f.unwind.end(),4,0); }),0,{1,1,nullptr},"language-handler-needs-forwarding");
    reject(Fixture{},0,{0,1,nullptr},"instruction-range");
    reject(Fixture{},0,{1,33,nullptr},"instruction-range");
    reject(Fixture{},17,{1,1,nullptr},"instruction-range");
    reject(change([](auto& f) { f.unwind[1] = 255; }),0,{1,1,nullptr},"prolog-outside-function");
    reject(Fixture{},15,{1,1,nullptr},"body-state-needs-proof");
    reject(Fixture{},2,{3,3,nullptr},"probe-inside-instruction");
    reject(Fixture{},0,{5,5,nullptr},"relocation-length-mismatch");
    reject(Fixture{},0,{1,1,reinterpret_cast<void*>(1)},"control-transfer-needs-proof");
    reject(change([](auto& f) { f.unwind[4] = 14; }),0,{1,1,nullptr},"malformed-unwind-codes");
    reject(change([](auto& f) { f.unwind[4] = 1; }),0,{1,1,nullptr},"malformed-unwind-codes");
    reject(change([](auto& f) { f.unwind[15] = 0x40; }),0,{1,1,nullptr},"invalid-push-register");
    reject(change([](auto& f) { f.unwind[9] = 0x04; }),0,{1,1,nullptr},"invalid-save-register");
    reject(change([](auto& f) { f.unwind[5] = 0x58; }),0,{1,1,nullptr},"invalid-xmm-register");
    reject(change([](auto& f) { f.unwind[3] = 0x10; }),0,{1,1,nullptr},"invalid-frame-register");
    reject(change([](auto& f) { f.unwind[3] = 4; }),0,{1,1,nullptr},"invalid-frame-register");
    reject(change([](auto& f) { f.unwind[3] = 5; }),0,{1,1,nullptr},"missing-frame-operation");
    reject(change([](auto& f) { f.unwind[15] = 3; }),0,{1,1,nullptr},"invalid-frame-operation");
    reject(change([](auto& f) { f.unwind = {1,5,3,0,5,0x21,0,0,0x10,0,0,0}; }),0,{1,1,nullptr},"invalid-alloc-large");
    reject(change([](auto& f) { f.unwind = {1,5,1,0,5,1,0,0}; }),0,{1,1,nullptr},"truncated-unwind-operation");
    reject(change([](auto& f) { f.unwind = {1,5,2,0,5,1,0,0}; }),0,{1,1,nullptr},"invalid-alloc-large");
    reject(change([](auto& f) { f.unwind[9] = 0x6a; }),0,{1,1,nullptr},"unsupported-unwind-operation");
    reject(change([](auto& f) { f.unwind[0] = 2; f.unwind[5] = 6; }),0,{1,1,nullptr},"unsupported-unwind-operation");
    for (auto code : {std::vector<unsigned char>{0xe8,0,0,0,0},{0xeb,0},{0xff,0xd0},{0xc3},{0x0f,0x05}}) {
        Fixture fixture;
        fixture.code = std::move(code);
        fixture.unwind = {1,0,0,0};
        reject(fixture,0,{fixture.code.size(),fixture.code.size(),nullptr},"control-transfer-needs-proof");
    }
    Fixture ripRelative;
    ripRelative.code = {0x48,0x8b,0x05,0,0,0,0};
    ripRelative.unwind = {2,0,0,0};
    NativeUnwind::Recipe result;
    assert(!NativeUnwind::derive(ripRelative.source(0),{7,7,nullptr},result));
    assert(result.before == std::vector<unsigned char>({2,0,0,0}) && result.after == result.before);

    reject(longFixture(1,1,0,2),0,{1,1,nullptr},"truncated-unwind-operation");
    reject(longFixture(1,1,0),0,{1,1,nullptr},"invalid-alloc-large");
    reject(longFixture(1,1,0x100001),0,{1,1,nullptr},"unaligned-stack-allocation");
    reject(longFixture(1,1,0xffffffff),0,{1,1,nullptr},"unaligned-stack-allocation");
    reject(longFixture(5,6,0x80008,2),0,{1,1,nullptr},"truncated-unwind-operation");
    reject(longFixture(9,6,0x100000,2),0,{1,1,nullptr},"truncated-unwind-operation");
    reject(longFixture(5,4,0x80008),0,{1,1,nullptr},"invalid-save-register");
    reject(longFixture(9,5,0x100000),0,{1,1,nullptr},"invalid-xmm-register");
    reject(longFixture(5,6,0x80001),0,{1,1,nullptr},"unaligned-save-offset");
    reject(longFixture(9,6,0x100008),0,{1,1,nullptr},"unaligned-save-offset");
    reject(longFixture(5,6,0xffffffff),0,{1,1,nullptr},"unaligned-save-offset");
    reject(longFixture(9,6,0xffffffff),0,{1,1,nullptr},"unaligned-save-offset");
    auto malformedFar = farFixture(false);
    malformedFar.unwind[4] = 22;
    reject(malformedFar,0,{7,7,nullptr},"malformed-unwind-codes");
    auto maximum = (std::numeric_limits<size_t>::max)();
    reject(Fixture{},maximum,{1,1,nullptr},"instruction-range");
    reject(Fixture{},1,{maximum,1,nullptr},"instruction-range");
    reject(Fixture{},1,{4,maximum,nullptr},"instruction-range");
    for (auto operation : {1u,5u,9u}) {
        auto fixture = longFixture(operation,operation == 1 ? 1 : 6,0x100000);
        fixture.unwind.resize(9);
        reject(fixture,0,{1,1,nullptr},"truncated-unwind-codes");
    }

    // These metadata-only boundary cases must retain unsigned high bits and
    // the legal maximum aligned 32-bit payload without signed narrowing or
    // endpoint wrap. No live stack address is formed from these values.
    for (auto [operation,value] : {std::pair<unsigned,std::uint32_t>{1,0x80000008u},{1,0xfffffff8u},
            {5,0x80000008u},{5,0xfffffff8u},{9,0x80000010u},{9,0xfffffff0u}}) {
        auto fixture = longFixture(operation,operation == 1 ? 1 : 6,value);
        NativeUnwind::Recipe recipe;
        assert(!NativeUnwind::derive(fixture.source(1),{4,4,nullptr},recipe));
        auto expected = fixture.unwind;
        expected[0] = 2; expected[1] = 0; expected[4] = 0;
        assert(recipe.before == std::vector<unsigned char>({2,0,0,0}) && recipe.after == expected);
        ++unsignedPayloadCases;
    }
}
void chainNegatives() {
    auto rejectChain = [](auto change, const char* expected) {
        ChainedFixture fixture(1,false,false,false);
        change(fixture);
        auto entries = fixture.parents();
        auto length = InstructionDecoder::length(fixture.sourceCode.data(),fixture.sourceCode.size());
        rejectSource(fixture.source(0,entries),{length,length,nullptr},expected);
    };
    rejectChain([](auto& f) { ++f.primaryBegin; },"chained-entry-mismatch");
    rejectChain([](auto& f) { ++f.primaryEnd; },"chained-entry-mismatch");
    rejectChain([](auto& f) { f.primaryRva += 4; },"chained-entry-mismatch");
    rejectChain([](auto& f) { f.primaryBegin = f.primaryEnd; f.syncTrailers(); },"chained-function-range");
    rejectChain([](auto& f) { ++f.primaryEnd; f.syncTrailers(); },"chained-function-range");
    rejectChain([](auto& f) { ++f.primaryRva; f.syncTrailers(); },"chained-function-range");
    rejectChain([](auto& f) { f.primaryInfo.resize(3); },"truncated-unwind-header");
    rejectChain([](auto& f) { f.primaryInfo[0] = 3; },"unsupported-unwind-version");
    rejectChain([](auto& f) { f.primaryInfo[0] |= 1 << 3; f.primaryInfo.insert(f.primaryInfo.end(),4,0); },"language-handler-needs-forwarding");
    rejectChain([](auto& f) { f.sourceInfo[3] = 0x25; },"chained-frame-layout-mismatch");
    rejectChain([](auto& f) { f.primaryInfo[4] = 4; },"malformed-unwind-codes");
    rejectChain([](auto& f) { f.sourceInfo[0] &= 7; },"unexpected-unwind-chain");
    rejectChain([](auto& f) { f.sourceInfo[3] = f.primaryInfo[3] = 0x25; },"missing-frame-operation");
    rejectChain([](auto& f) { f.primaryInfo[0] |= 4 << 3; },"truncated-unwind-chain");
    rejectChain([](auto& f) { f.primaryInfo[0] |= 4 << 3; f.primaryInfo.insert(f.primaryInfo.end(),12,0); },"chained-prolog-state-needs-proof");
    rejectChain([](auto& f) { f.primaryInfo[0] |= 5 << 3; },"invalid-unwind-flags");
    rejectChain([](auto& f) {
        f.sourceCode = {0x48,0x83,0xc4,0x40,0xc3};
        f.sourceInfo = {1,0,0,0}; f.syncTrailers();
    },"chained-body-state-needs-proof");
    rejectChain([](auto& f) {
        f.sourceCode = {0x53,0x90,0xc3};
        f.sourceInfo = {1,1,1,0,1,0x30,0,0}; f.syncTrailers();
    },"chained-prolog-state-needs-proof");
    ChainedFixture fixture(1,false,false,false);
    rejectSource(fixture.source(0,{}),{5,5,nullptr},"unresolved-unwind-chain");
    auto entries = fixture.parents();
    entries.push_back(entries.front());
    rejectSource(fixture.source(0,entries),{5,5,nullptr},"cyclic-unwind-chain");
    entries = fixture.parents(); entries.front().unwind = fixture.sourceInfo;
    rejectSource(fixture.source(0,entries),{5,5,nullptr},"cyclic-unwind-chain");
    entries = fixture.parents();
    auto extra = entries.front(); extra.unwindRva += 4; entries.push_back(extra);
    rejectSource(fixture.source(0,entries),{5,5,nullptr},"unexpected-unwind-chain");
    ChainedFixture nested(1,true,false,true);
    auto incomplete = nested.parents(); incomplete.resize(1);
    rejectSource(nested.source(0,incomplete),{5,5,nullptr},"unresolved-unwind-chain");

    // Exactly 255 inherited slots fit the output; the 256th cannot wrap the
    // byte-sized CountOfCodes. Source operations outside this instruction's
    // completed state do not consume output slots.
    ChainedFixture capacity(1,false,false,false);
    capacity.primaryCode.assign(255,0x53);
    capacity.primaryInfo = {1,255,255,0};
    for (unsigned offset = 255; offset; --offset)
        capacity.primaryInfo.insert(capacity.primaryInfo.end(),{static_cast<unsigned char>(offset),0x30});
    capacity.primaryInfo.insert(capacity.primaryInfo.end(),2,0);
    capacity.primaryEnd = 255;
    capacity.sourceCode = {0x90,0xc3}; capacity.sourceInfo = {1,1,0,0}; capacity.syncTrailers();
    auto capacityEntries = capacity.parents();
    NativeUnwind::Recipe recipe;
    assert(!NativeUnwind::derive(capacity.source(0,capacityEntries),{1,1,nullptr},recipe));
    assert(recipe.before[2] == 255 && recipe.after[2] == 255 && recipe.before.size() == 516);
    ++chainBoundaryCases;

    ChainedFixture oversized(1,false,false,false);
    oversized.primaryCode.assign(160,0x53);
    oversized.primaryInfo = {1,160,160,0};
    for (unsigned offset = 160; offset; --offset)
        oversized.primaryInfo.insert(oversized.primaryInfo.end(),{static_cast<unsigned char>(offset),0x30});
    oversized.primaryEnd = 160;
    oversized.sourceCode.clear(); oversized.sourceInfo = {1,250,100,0};
    for (unsigned instruction = 0; instruction < 50; ++instruction)
        oversized.sourceCode.insert(oversized.sourceCode.end(),{0x48,0x89,0x74,0x24,0x20});
    for (unsigned offset = 250; offset; offset -= 5)
        oversized.sourceInfo.insert(oversized.sourceInfo.end(),{static_cast<unsigned char>(offset),0x64,4,0});
    oversized.syncTrailers();
    auto oversizedEntries = oversized.parents();
    assert(!NativeUnwind::derive(oversized.source(0,oversizedEntries),{5,5,nullptr},recipe));
    assert(recipe.before[2] == 160 && recipe.after[2] == 162);
    ++chainBoundaryCases;
    rejectSource(oversized.source(245,oversizedEntries),{5,5,nullptr},"flattened-unwind-too-large");
}
}
int main() {
    negatives();
    chainNegatives();
    unsigned checked = 0;
    for (auto shape : {Shape::General,Shape::Framed,Shape::Far,Shape::FramedFar})
        checked += contexts(1,shape) + contexts(2,shape);
    unsigned chainChecked = 0;
    for (unsigned version : {1u,2u}) for (bool framed : {false,true}) {
        chainChecked += chainContexts(version,framed,false,false);
        chainChecked += chainContexts(version,framed,true,false);
        chainChecked += chainContexts(version,framed,false,true);
    }
    std::printf("NATIVE_UNWIND_PASS contexts=%u rejected=%u unsignedPayloads=%u chainContexts=%u chainBoundaries=%u versions=1,2 source-unexecuted=1\n",
        checked + chainChecked,rejectedCases,unsignedPayloadCases,chainChecked,chainBoundaryCases);
}
