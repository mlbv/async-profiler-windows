/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsSoftwareEntryInstruction.h"
#include "windowsNativeUnwind.h"
#include <array>
#include <cstdio>
#include <cstdlib>

using namespace WindowsProfiler;
using Bytes = std::vector<unsigned char>;
static unsigned checks, executed, unwindContexts, certifications;
static void require(bool value,const char* message) {
    ++checks;
    if (!value) { std::fprintf(stderr,"SOFTWARE_ENTRY_INSTRUCTION_FAILURE %s\n",message); std::exit(1); }
}
static const Bytes empty{2,0,0,0};
static bool accepts(const Bytes& bytes) {
    return SoftwareSites::nonstackEntryInstruction(bytes,empty,empty);
}
static void integer(Bytes& bytes,std::uint64_t value,unsigned size) {
    for (unsigned i = 0; i < size; ++i) bytes.push_back(static_cast<unsigned char>(value >> (8 * i)));
}
static void immediate(Bytes& bytes) { integer(bytes,0x80000081u,4); }
static bool volatileRegister(unsigned reg) { return reg <= 2 || (reg >= 8 && reg <= 11); }

struct alignas(16) Observed {
    std::uint64_t registers[16];
    std::uint64_t flags;
    std::uint64_t simd[32];
};
static constexpr std::uint64_t initial(unsigned reg) { return 0x8033221100000081ull + 0x101010101010101ull * reg; }
static void movabs(Bytes& bytes,unsigned reg,std::uint64_t value) {
    bytes.push_back(reg >= 8 ? 0x49 : 0x48);
    bytes.push_back(static_cast<unsigned char>(0xb8 | (reg & 7)));
    integer(bytes,value,8);
}
static void store(Bytes& bytes,unsigned reg,unsigned offset) {
    bytes.insert(bytes.end(),{static_cast<unsigned char>(reg >= 8 ? 0x4c : 0x48),0x89,
        static_cast<unsigned char>(0x80 | ((reg & 7) << 3))});
    integer(bytes,offset,4);
}
static Bytes wrapper(const Bytes& op,std::uint32_t flags,unsigned allocation = 0) {
    Bytes bytes{0x53,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x51};
    for (unsigned reg = 0; reg < 16; ++reg) {
        if (reg != 4) movabs(bytes,reg,initial(reg));
        bytes.push_back(0x66);
        if (reg >= 8) bytes.push_back(0x45);
        bytes.insert(bytes.end(),{0x0f,0x76,static_cast<unsigned char>(0xc0 | ((reg & 7) << 3) | (reg & 7))});
    }
    bytes.push_back(0x68); integer(bytes,flags,4); bytes.push_back(0x9d);
    bytes.insert(bytes.end(),op.begin(),op.end());
    bytes.insert(bytes.end(),{0x9c,0x50,0x48,0x8b,0x84,0x24});
    integer(bytes,0x10 + allocation,4); // Saved output pointer above the selected allocation.
    for (unsigned reg = 1; reg < 16; ++reg) if (reg != 4) store(bytes,reg,reg * 8);
    bytes.insert(bytes.end(),{0x48,0x8d,0x54,0x24,0x10}); store(bytes,2,4 * 8);
    bytes.insert(bytes.end(),{0x48,0x8b,0x14,0x24}); store(bytes,2,0);
    bytes.insert(bytes.end(),{0x48,0x8b,0x54,0x24,0x08}); store(bytes,2,offsetof(Observed,flags));
    for (unsigned reg = 0; reg < 16; ++reg) {
        bytes.push_back(0xf3);
        if (reg >= 8) bytes.push_back(0x44);
        bytes.insert(bytes.end(),{0x0f,0x7f,static_cast<unsigned char>(0x80 | ((reg & 7) << 3))});
        integer(bytes,offsetof(Observed,simd) + reg * 16,4);
    }
    bytes.insert(bytes.end(),{0x48,0x81,0xc4}); integer(bytes,0x18 + allocation,4);
    bytes.insert(bytes.end(),{0x41,0x5f,0x41,0x5e,0x41,0x5d,0x41,0x5c,0x5f,0x5e,0x5d,0x5b,0xc3});
    return bytes;
}
static Observed run(const Bytes& bytes) {
    auto memory = static_cast<unsigned char*>(VirtualAlloc(nullptr,4096,MEM_RESERVE | MEM_COMMIT,PAGE_READWRITE));
    require(memory && bytes.size() < 4096,"Cannot allocate instruction-effect fixture");
    std::memcpy(memory,bytes.data(),bytes.size());
    DWORD old;
    require(VirtualProtect(memory,4096,PAGE_EXECUTE_READ,&old)
        && FlushInstructionCache(GetCurrentProcess(),memory,bytes.size()),"Cannot finalize instruction-effect fixture");
    Observed result{};
    reinterpret_cast<void (*)(Observed*)>(memory)(&result);
    require(VirtualFree(memory,0,MEM_RELEASE) != 0,"Cannot release instruction-effect fixture");
    return result;
}
static void effectsOracle(const Bytes& op,const Bytes& copied,int destination = -1,std::uint64_t value = 0,
        bool flagsPreserved = true,unsigned allocation = 0,bool frame = false) {
    for (auto flags : {0x202u,0xad7u}) {
        auto original = run(wrapper(op,flags,allocation));
        auto displaced = run(wrapper(copied,flags,allocation));
        auto opcode = op[0] >= 0x40 && op[0] <= 0x4f ? op[1] : op[0];
        // Logical instructions leave AF undefined.
        auto mask = opcode == 0x85 || opcode == 0xa9 || opcode == 0xf7 || opcode == 0x31 || opcode == 0x33
            ? ~std::uint64_t{0x10} : ~std::uint64_t{0};
        require(!std::memcmp(original.registers,displaced.registers,sizeof(original.registers))
            && !((original.flags ^ displaced.flags) & mask)
            && !std::memcmp(original.simd,displaced.simd,sizeof(original.simd)),"Relocation changed GPR/RSP/RFLAGS/XMM effects");
        for (unsigned reg = 0; reg < 16; ++reg) if (reg != 4)
            require(original.registers[reg] == (frame && reg == 5 ? original.registers[4]
                : static_cast<int>(reg) == destination ? value : initial(reg)),
                "Instruction changed an unexpected register or immediate extension");
        if (flagsPreserved) require(!((original.flags ^ flags) & 0x8d5),"Instruction changed arithmetic flags");
        if (allocation) {
            auto baseline = run(wrapper({0x90},flags));
            require(original.registers[4] + allocation == baseline.registers[4],"SUB RSP changed the wrong allocation");
        }
        for (auto lane : original.simd) require(lane == UINT64_MAX,"Integer instruction changed SIMD state");
        ++executed;
    }
}
static void oracle(const Bytes& op,int destination = -1,std::uint64_t value = 0,bool flagsPreserved = false) {
    require(SoftwareSites::entryInstructionEffect(op).kind != SoftwareSites::EntryEffectKind::Unsupported,
        "Certified encoding rejected");
    std::array<unsigned char,InstructionDecoder::MAX_RELOCATED_BYTES> relocated{};
    InstructionDecoder::Relocation relocation;
    require(InstructionDecoder::length(op.data(),op.size()) == op.size()
        && InstructionDecoder::relocate(relocated.data(),relocated.size(),op.data(),op.size(),relocation)
        && relocation.sourceBytes == op.size() && relocation.destinationBytes == op.size() && !relocation.branchTarget
        && !std::memcmp(relocated.data(),op.data(),op.size()),"Relocation changed certified instruction");
    NativeUnwind::Recipe recipe;
    require(!NativeUnwind::certifyInstruction({op,empty,0},relocation,recipe)
        && recipe.before == empty && recipe.after == empty,"Certified instruction changed native unwind state");
    Bytes copied(relocated.begin(),relocated.begin() + relocation.destinationBytes);
    auto opcode = op[0] >= 0x40 && op[0] <= 0x4f ? op[1] : op[0];
    effectsOracle(op,copied,destination,value,flagsPreserved || (destination >= 0 && opcode != 0x31 && opcode != 0x33));
    alignas(16) unsigned char image[256]{};
    std::memcpy(image,op.data(),op.size()); std::memcpy(image + 64,copied.data(),copied.size());
    std::memcpy(image + 128,empty.data(),empty.size());
    for (auto offset : {size_t{0},size_t{64},size_t{64} + copied.size()}) {
        std::uint64_t stack[]{0x123456780ull,0};
        CONTEXT context{}; context.Rip = reinterpret_cast<DWORD64>(image + offset);
        context.Rsp = reinterpret_cast<DWORD64>(stack); context.Rbp = 0x76543210;
        RUNTIME_FUNCTION function{static_cast<DWORD>(offset),static_cast<DWORD>(offset + 1),128};
        DWORD64 frame = 0; void* data = nullptr;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(image),context.Rip,&function,&context,&data,&frame,nullptr);
        require(context.Rip == stack[0] && context.Rsp == reinterpret_cast<DWORD64>(stack + 1)
            && context.Rbp == 0x76543210,"Zero-state OS unwind changed caller");
        ++unwindContexts;
    }
}
static void encodings() {
    for (unsigned width : {0u,8u}) for (unsigned reg = 0; reg < 16; ++reg) for (unsigned rm = 0; rm < 16; ++rm) {
        for (auto opcode : {0x85u,0x39u,0x3bu}) {
            Bytes bytes; auto rex = width | (reg >= 8 ? 4u : 0u) | (rm >= 8 ? 1u : 0u);
            if (rex) bytes.push_back(static_cast<unsigned char>(0x40 | rex));
            bytes.insert(bytes.end(),{static_cast<unsigned char>(opcode),static_cast<unsigned char>(0xc0 | ((reg & 7) << 3) | (rm & 7))});
            require(accepts(bytes),"Register TEST/CMP family rejected");
            require(InstructionDecoder::length(bytes.data(),bytes.size()) == bytes.size(),"Register instruction length mismatch");
        }
    }
    for (unsigned width : {0u,8u}) for (unsigned reg = 0; reg < 16; ++reg) {
        auto rex = width | (reg >= 8 ? 1u : 0u);
        auto prefix = [&] { Bytes bytes; if (rex) bytes.push_back(static_cast<unsigned char>(0x40 | rex)); return bytes; };
        auto mov = prefix(); mov.push_back(static_cast<unsigned char>(0xb8 | (reg & 7)));
        integer(mov,0x8877665580000081ull,width ? 8 : 4);
        require(accepts(mov) == volatileRegister(reg),"MOV opcode register policy mismatch");
        auto grouped = prefix(); grouped.insert(grouped.end(),{0xc7,static_cast<unsigned char>(0xc0 | (reg & 7))}); immediate(grouped);
        require(accepts(grouped) == volatileRegister(reg),"MOV grouped register policy mismatch");
        for (auto opcode : {0xf7u,0x81u,0x83u}) {
            auto bytes = prefix();
            bytes.insert(bytes.end(),{static_cast<unsigned char>(opcode),
                static_cast<unsigned char>(0xc0 | (opcode == 0xf7 ? 0 : 0x38) | (reg & 7))});
            integer(bytes,0x80000081u,opcode == 0x83 ? 1 : 4);
            require(accepts(bytes),"Immediate TEST/CMP family rejected");
            for (size_t count = 0; count < bytes.size(); ++count)
                require(!accepts(Bytes(bytes.begin(),bytes.begin() + count)),"Truncated instruction accepted");
            bytes.push_back(0x90); require(!accepts(bytes),"Trailing instruction accepted");
            auto modrm = rex ? 2 : 1;
            bytes.pop_back(); bytes[modrm] &= 0x3f;
            require(!accepts(bytes),"Memory operand accepted");
        }
    }
    for (auto bytes : {Bytes{0x85,0xc0},Bytes{0x48,0x83,0xfc,0x81},Bytes{0xb8,1,0,0,0}}) {
        for (auto prefix : {0x66,0xf0,0xf2,0xf3,0x67,0x65,0x48}) {
            auto invalid = bytes; invalid.insert(invalid.begin(),static_cast<unsigned char>(prefix));
            if (prefix == 0x48 && bytes[0] == 0x85) continue;
            require(!accepts(invalid),"Uncertified prefix accepted");
        }
        for (auto metadata : {Bytes{1,0,0,0},Bytes{2,0,1,0},Bytes{2,0,0,5},Bytes{2,1,0,0},Bytes{2,0,0}}) {
            require(!SoftwareSites::nonstackEntryInstruction(bytes,metadata,empty)
                && !SoftwareSites::nonstackEntryInstruction(bytes,empty,metadata),"Unproved unwind state accepted");
        }
    }
    for (auto bytes : {Bytes{0x55},Bytes{0x48,0x8b,0x01},Bytes{0x48,0x89,0x01},Bytes{0xc3},
            Bytes{0xe8,0,0,0,0},Bytes{0xeb,0},Bytes{0x0f,0x05},Bytes{0xf7,0xf1},
            Bytes{0x48,0xc7,0xf8,0,0,0,0},Bytes{0x48,0x81,0xec,8,0,0,0},Bytes{0x84,0xc0}})
        require(!accepts(bytes),"Faulting/control/stack/uncertified instruction accepted");
    Bytes test{0x48,0x85,0xc0}, mismatch{1,3,1,0,3,2,0,0};
    NativeUnwind::Recipe recipe;
    require(!NativeUnwind::derive({test,mismatch,0},{3,3,nullptr},recipe)
        && !SoftwareSites::nonstackEntryInstruction(test,recipe.before,recipe.after),
        "Opcode/unwind disagreement was not rejected");
}
static void rejectCertificate(const NativeUnwind::Source& source,const InstructionDecoder::Relocation& relocation) {
    NativeUnwind::Recipe recipe{{3,1},{4,2},99};
    require(NativeUnwind::certifyInstruction(source,relocation,recipe)
        && recipe.before == Bytes({3,1}) && recipe.after == Bytes({4,2}) && recipe.sourceVersion == 99,
        "Rejected execution certificate changed prior recipe");
}
static void prologueUnwind(const Bytes& code,const Bytes& unwind,size_t probe,
        const InstructionDecoder::Relocation& relocation,const NativeUnwind::Recipe& recipe,unsigned before,unsigned after) {
    alignas(16) unsigned char image[2048]{};
    std::memcpy(image,code.data(),code.size());
    std::memcpy(image + 512,code.data() + probe,relocation.sourceBytes);
    std::memcpy(image + 1024,unwind.data(),unwind.size());
    std::memcpy(image + 1280,recipe.before.data(),recipe.before.size());
    std::memcpy(image + 1536,recipe.after.data(),recipe.after.size());
    constexpr DWORD64 caller = 0x12345678, callerRbp = 0x8877665544332211;
    for (bool completed : {false,true}) {
        DWORD64 stack[128]{};
        auto returnAddress = stack + 96;
        *returnAddress = caller; returnAddress[-1] = callerRbp; returnAddress[-2] = 0x33445566;
        CONTEXT expected{};
        expected.Rsp = reinterpret_cast<DWORD64>(returnAddress) - (completed ? after : before);
        const auto& body = completed ? recipe.after : recipe.before;
        expected.Rbp = body[3] ? expected.Rsp : callerRbp;
        expected.Rbx = 0xbad0bad0;
        auto observed = expected;
        expected.Rip = reinterpret_cast<DWORD64>(image + probe + (completed ? relocation.sourceBytes : 0));
        observed.Rip = reinterpret_cast<DWORD64>(image + 512 + (completed ? relocation.destinationBytes : 0));
        RUNTIME_FUNCTION original{0,static_cast<DWORD>(code.size()),1024};
        RUNTIME_FUNCTION displaced{static_cast<DWORD>(completed ? 512 + relocation.destinationBytes : 512),
            static_cast<DWORD>(513 + relocation.destinationBytes),static_cast<DWORD>(completed ? 1536 : 1280)};
        void* data; DWORD64 frame;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(image),expected.Rip,&original,&expected,&data,&frame,nullptr);
        RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(image),observed.Rip,&displaced,&observed,&data,&frame,nullptr);
        require(expected.Rip == caller && expected.Rsp == reinterpret_cast<DWORD64>(returnAddress + 1)
            && expected.Rbp == callerRbp,"Original prologue OS unwind changed caller");
        require(observed.Rip == expected.Rip && observed.Rsp == expected.Rsp && observed.Rbp == expected.Rbp
            && observed.Rbx == expected.Rbx,"Displaced prologue OS unwind disagreed with original");
        unwindContexts += 2;
    }
}
static void certifyPrologue(const Bytes& code,const Bytes& unwind,size_t probe,unsigned before,unsigned after,
        bool execute = false,unsigned allocation = 0,bool frame = false) {
    std::array<unsigned char,InstructionDecoder::MAX_RELOCATED_BYTES> copied{};
    InstructionDecoder::Relocation relocation;
    require(InstructionDecoder::relocate(copied.data(),copied.size(),code.data() + probe,code.size() - probe,relocation),
        "Cannot relocate prologue fixture");
    NativeUnwind::Source source{code,unwind,probe};
    NativeUnwind::Recipe recipe;
    require(!NativeUnwind::validateBoundary(source,probe)
        && !NativeUnwind::certifyInstruction(source,relocation,recipe),"Valid prologue instruction was not certified");
    ++certifications;
    if (before == after && !frame) require(recipe.before == recipe.after,"Neutral prologue changed complete unwind state");
    prologueUnwind(code,unwind,probe,relocation,recipe,before,after);
    if (execute) {
        Bytes op(code.begin() + probe,code.begin() + probe + relocation.sourceBytes);
        Bytes displaced(copied.begin(),copied.begin() + relocation.destinationBytes);
        effectsOracle(op,displaced,-1,0,frame,allocation,frame);
    }
}
static void prologues() {
    for (const auto& op : {Bytes{0x90},Bytes{0x48,0x89,0xc8},Bytes{0x48,0x31,0xc0},
            Bytes{0x48,0x8d,0x04,0x11},Bytes{0x48,0x85,0xe4},Bytes{0xb8,1,0,0,0},
            Bytes{0x49,0xc7,0xc3,1,0,0,0}}) {
        Bytes code{0xf3,0x0f,0x1e,0xfa,0x55,0x48,0x83,0xec,0x20};
        code.insert(code.end(),op.begin(),op.end());
        auto prolog = static_cast<unsigned char>(code.size());
        code.push_back(0x90);
        certifyPrologue(code,{1,prolog,2,0,9,0x32,5,0x50},9,40,40);
    }
    // Previously executed stores/CALLs need their native unwind state, not selected-op eligibility.
    certifyPrologue({0x55,0x48,0x83,0xec,0x20,0x48,0x89,0x5c,0x24,0x18,0x85,0xc9,0x90},
        {1,12,4,0,10,0x34,3,0,5,0x32,1,0x50},10,40,40);
    certifyPrologue({0x55,0x48,0x83,0xec,0x20,0xe8,0,0,0,0,0x85,0xc9,0x90},
        {1,12,2,0,5,0x32,1,0x50},10,40,40);
    certifyPrologue({0x55,0x48,0x83,0xec,0x20,0x90},{1,5,2,0,5,0x32,1,0x50},1,8,40,true,32);
    for (auto unwind : {Bytes{1,8,3,0,8,0x01,0x40,0,1,0x50,0,0},
            Bytes{1,8,4,0,8,0x11,0,2,0,0,1,0x50}})
        certifyPrologue({0x55,0x48,0x81,0xec,0,2,0,0,0x90},unwind,1,8,520,true,512);
    for (auto op : {Bytes{0x48,0x89,0xe5},Bytes{0x48,0x8b,0xec}}) {
        Bytes code{0x55}; code.insert(code.end(),op.begin(),op.end()); code.push_back(0x90);
        certifyPrologue(code,{1,4,2,5,4,3,1,0x50},1,8,8,true,0,true);
    }
    certifyPrologue({0x55,0x48,0x83,0xec,0x20,0x48,0x89,0xe5,0x85,0xc9,0x90},
        {1,10,3,5,8,3,5,0x32,1,0x50,0,0},8,40,40);
    for (auto op : {Bytes{0x48,0x89,0xc5},Bytes{0x48,0x31,0xed},Bytes{0x89,0xc5}}) {
        Bytes code{0x55,0x48,0x83,0xec,0x20,0x48,0x89,0xe5};
        code.insert(code.end(),op.begin(),op.end());
        Bytes unwind{1,static_cast<unsigned char>(code.size()),3,5,8,3,5,0x32,1,0x50,0,0};
        rejectCertificate({code,unwind,8},{op.size(),op.size(),nullptr});
    }
    Bytes push{0x55}, pushInfo{1,1,1,0,1,0x50,0,0};
    NativeUnwind::Recipe cold;
    require(!NativeUnwind::derive({push,pushInfo,0},{1,1,nullptr},cold),"Cold PUSH preparation regressed");
    // Displaced PUSH faults are reported at the source instruction.
    certifyPrologue({0x55,0x90},pushInfo,0,0,8,true,8);
    certifyPrologue({0x41,0x54,0x90},{1,2,1,0,2,0xc0,0,0},0,0,8,true,8);
    certifyPrologue({0x55,0x53,0x90},{1,2,2,0,2,0x30,1,0x50},1,8,16,true,8);
    rejectCertificate({Bytes{0x53,0x90},pushInfo,0},{1,1,nullptr});
    Bytes child{0x90}, chainInfo{33,1,0,0};
    integer(chainInfo,0x100,4); integer(chainInfo,0x101,4); integer(chainInfo,0x200,4);
    NativeUnwind::ChainEntry parent{0x100,0x101,0x200,push,pushInfo};
    NativeUnwind::Source chained{child,chainInfo,0,{&parent,1}};
    require(!NativeUnwind::derive(chained,{1,1,nullptr},cold),"Cold chained preparation regressed");
    rejectCertificate(chained,{1,1,nullptr});
    Bytes sub{0x55,0x48,0x83,0xec,0x20,0x90};
    for (auto unwind : {Bytes{1,5,1,0,1,0x50,0,0},Bytes{1,5,2,0,5,0x22,1,0x50},
            Bytes{1,5,4,0,5,0x32,5,0x34,0,0,1,0x50}})
        rejectCertificate({sub,unwind,1},{4,4,nullptr});
    Bytes frame32{0x55,0x89,0xe5}, frame32Info{1,3,2,5,3,3,1,0x50};
    rejectCertificate({frame32,frame32Info,1},{2,2,nullptr});
    Bytes frameWrong{0x55,0x48,0x89,0xe3}, frameInfo{1,4,2,5,4,3,1,0x50};
    rejectCertificate({frameWrong,frameInfo,1},{3,3,nullptr});
    frameWrong[3] = 0xe5; frameInfo[3] = 0x15;
    rejectCertificate({frameWrong,frameInfo,1},{3,3,nullptr});
    Bytes nop{0x55,0x90}, nopAlloc{1,2,2,0,2,2,1,0x50};
    rejectCertificate({nop,nopAlloc,1},{1,1,nullptr});
    Bytes nopSave{1,2,3,0,2,0x34,0,0,1,0x50,0,0};
    rejectCertificate({nop,nopSave,1},{1,1,nullptr});
    Bytes load{0x55,0x48,0x8b,0x01}, loadInfo{1,4,1,0,1,0x50,0,0};
    rejectCertificate({load,loadInfo,1},{3,3,nullptr});
    Bytes endbr{0xf3,0x0f,0x1e,0xfa,0x55,0x48,0x83,0xec,0x20,0x85,0xc9,0x90};
    Bytes endbrInfo{1,11,2,0,9,0x32,5,0x50};
    for (size_t boundary : {0u,4u,5u,9u})
        require(!NativeUnwind::validateBoundary({endbr,endbrInfo,9},boundary),"Original prologue boundary rejected");
    for (size_t boundary : {1u,2u,3u,6u,7u,8u,10u,11u})
        require(NativeUnwind::validateBoundary({endbr,endbrInfo,9},boundary),"Interior/body boundary accepted");
    Bytes zero{0x90,0x90};
    require(!NativeUnwind::validateBoundary({zero,empty,0},0)
        && NativeUnwind::validateBoundary({zero,empty,0},1),"Zero-prologue offset policy changed");
    Bytes interior{0x48,0xb8,0xf3,0x0f,0x1e,0xfa,0,0,0,0,0x90}, interiorInfo{1,11,0,0};
    require(NativeUnwind::validateBoundary({interior,interiorInfo,2},2),"Interior ENDBR request bypassed boundary proof");
    rejectCertificate({interior,interiorInfo,2},{4,4,nullptr});
}
int main() {
    encodings();
    prologues();
    oracle({0x90});
    oracle({0x48,0x89,0xc8},0,initial(1));
    oracle({0x48,0x31,0xc0},0,0);
    oracle({0x48,0x8d,0x04,0x11},0,initial(1) + initial(2));
    oracle({0x85,0xc9}); oracle({0x4d,0x85,0xc9}); oracle({0x48,0x85,0xe4});
    oracle({0x39,0xd1}); oracle({0x4d,0x3b,0xd1}); oracle({0x48,0x39,0xec});
    oracle({0xa9,0x81,0,0,0x80}); oracle({0x48,0xa9,0x81,0,0,0x80});
    oracle({0x49,0xf7,0xc1,0x81,0,0,0x80});
    oracle({0x3d,0x81,0,0,0x80}); oracle({0x48,0x3d,0x81,0,0,0x80});
    oracle({0x49,0x81,0xfa,0x81,0,0,0x80}); oracle({0x48,0x83,0xfc,0x81});
    oracle({0xb8,0x81,0,0,0x80},0,0x80000081ull);
    oracle({0x41,0xb9,0x81,0,0,0x80},9,0x80000081ull);
    oracle({0x49,0xba,0x81,0,0,0x80,0x55,0x66,0x77,0x88},10,0x8877665580000081ull);
    oracle({0xc7,0xc2,0x81,0,0,0x80},2,0x80000081ull);
    oracle({0x49,0xc7,0xc3,0x81,0,0,0x80},11,0xffffffff80000081ull);
    std::printf("SOFTWARE_ENTRY_INSTRUCTIONS_PASS checks=%u executions=%u unwindContexts=%u certifications=%u\n",
        checks,executed,unwindContexts,certifications);
}
