/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ASPROF_NATIVE_PREP_TEST_BRIDGE
#error This witness belongs only to the private native preparation test artifact.
#endif
#include "platform.h"
#include "vmStructs.h"
#include "vmEntry.h"
#include "native_handler_checkpoint.h"
#include "native_compiled_unwind_oracle.h"
#include "windowsInstructionDecoder.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <psapi.h>

extern "C" __declspec(dllexport) void JNICALL Java_CompiledHandlerSnapshotSmoke_checkpoint(JNIEnv*,jclass);

namespace {
using namespace HandlerCheckpoint;
namespace Compiled = WindowsProfiler::JavaUnwind::Compiled;
namespace Decoder = WindowsProfiler::InstructionDecoder;
struct PeRow {
    DWORD64 image;
    RUNTIME_FUNCTION function;
};
bool peRecordLocation(DWORD size,DWORD directory,DWORD bytes,DWORD64 record) {
    return directory && !(directory & 3) && directory <= size && bytes && bytes <= size - directory
        && !(bytes % sizeof(RUNTIME_FUNCTION)) && record >= directory && record - directory < bytes
        && !((record - directory) % sizeof(RUNTIME_FUNCTION));
}
bool peRecord(DWORD size,DWORD directory,DWORD bytes,DWORD64 record,DWORD64 pc,const RUNTIME_FUNCTION& function) {
    return peRecordLocation(size,directory,bytes,record)
        && function.BeginAddress < function.EndAddress && function.EndAddress <= size
        && pc >= function.BeginAddress && pc < function.EndAddress
        && function.UnwindData && !(function.UnwindData & 3) && function.UnwindData <= size
        && size - function.UnwindData >= 4;
}
struct Baseline {
    DWORD64 pc,sp,fp;
    PeRow helper;
};
struct Implicit;
struct State {
    Input input;
    jvmtiEnv* ti;
    std::array<jmethodID,4> ids;
    const Baseline* baseline = nullptr;
    Implicit* implicit = nullptr;
    DWORD owner = GetCurrentThreadId();
    unsigned hits = 0, peFrames = 0, oracleFrames = 0;
    std::string error, report, failureEvidence;
    const char* stage = "unarmed";
    DWORD64 observedPc = 0,observedSp = 0,observedFp = 0,codeAddress = 0;
    std::vector<unsigned char> stageCode;
};
thread_local State* active = nullptr;
thread_local unsigned unarmed = 0;
void require(bool ok,const char* message) {
    if (!ok) throw std::runtime_error(message);
}
void stage(State& state,const char* name,const CONTEXT& context) {
    state.stage = name;
    state.observedPc = context.Rip; state.observedSp = context.Rsp; state.observedFp = context.Rbp;
    state.codeAddress = 0;
    state.stageCode.clear();
}
std::string hexBytes(std::span<const unsigned char> bytes) {
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto byte : bytes) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
void recordFailure(State& state,const char* message) {
    state.error = message;
    std::fprintf(stderr,"HANDLER_WITNESS_FAILURE stage=%s pc=%llx sp=%llx fp=%llx reason=%s\n",
        state.stage,static_cast<unsigned long long>(state.observedPc),
        static_cast<unsigned long long>(state.observedSp),static_cast<unsigned long long>(state.observedFp),message);
    if (!state.failureEvidence.empty()) std::fprintf(stderr,"%s",state.failureEvidence.c_str());
    else if (!state.stageCode.empty())
        std::fprintf(stderr,"HANDLER_STAGE_CODE stage=%s address=%llx bytes=%s\n",
            state.stage,static_cast<unsigned long long>(state.codeAddress),hexBytes(state.stageCode).c_str());
    else if (state.observedPc) {
        unsigned char bytes[16];
        SIZE_T read = 0;
        auto copied = ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(state.observedPc),bytes,sizeof(bytes),&read);
        std::fprintf(stderr,"HANDLER_STAGE_PC_CODE stage=%s address=%llx readable=%d size=%zu bytes=%s\n",
            state.stage,static_cast<unsigned long long>(state.observedPc),copied,static_cast<std::size_t>(read),
            hexBytes(std::span{bytes}.first(read)).c_str());
    }
    if (state.baseline)
        std::fprintf(stderr,"HANDLER_EXPECTED_PARENT pc=%llx sp=%llx fp=%llx image=%llx begin=%lu end=%lu unwind=%lu\n",
            static_cast<unsigned long long>(state.baseline->pc),static_cast<unsigned long long>(state.baseline->sp),
            static_cast<unsigned long long>(state.baseline->fp),static_cast<unsigned long long>(state.baseline->helper.image),
            state.baseline->helper.function.BeginAddress,state.baseline->helper.function.EndAddress,state.baseline->helper.function.UnwindData);
    if (!state.report.empty()) std::fprintf(stderr,"HANDLER_PARTIAL_REPORT_BEGIN\n%sHANDLER_PARTIAL_REPORT_END\n",state.report.c_str());
}
struct Bounds {
    ULONG_PTR low = 0,high = 0;
    Bounds() { GetCurrentThreadStackLimits(&low,&high); }
    bool has(DWORD64 address,std::size_t bytes) const {
        return address >= low && address <= high && bytes <= high - address;
    }
};
std::vector<unsigned char> copy(std::uintptr_t address,std::size_t size) {
    require(address && size && size <= 1024 * 1024,"Invalid bounded code extent");
    std::vector<unsigned char> bytes(size);
    SIZE_T read = 0;
    require(ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(address),bytes.data(),size,&read)
        && read == size,"Cannot copy active code");
    return bytes;
}
std::int32_t signed32(const unsigned char* bytes) {
    std::int32_t result;
    std::memcpy(&result,bytes,sizeof(result));
    return result;
}
struct Instruction {
    unsigned op = 0, rex = 0, prefix = 0, reg = 16,rm = 16,group = 0;
    unsigned base = 16,index = 16,mode = 3,vectorWidth = 0;
    std::int64_t displacement = 0;
    std::size_t length = 0,operand = 0;
};
Instruction instruction(std::span<const unsigned char> bytes) {
    Instruction i;
    i.length = Decoder::length(bytes.data(),bytes.size());
    require(i.length && i.length <= bytes.size(),"Unrecognized instruction in anchor certificate");
    std::size_t p = 0;
    if (bytes[0] == 0xc5 && !(i.length == 3 && bytes[1] == 0xf8 && bytes[2] == 0x77)) {
        require(i.length >= 4 && (bytes[1] & 0x7f) == 0x7a && bytes[2] == 0x7f
            && (bytes[3] & 0xc0) != 0xc0,"Unsupported VEX anchor instruction");
        i.op = 0x17f; i.prefix = 0xf3;
        i.rex = (bytes[1] & 0x80) ? 0 : 4;
        p = 3;
    } else {
        if (bytes[p] == 0xf2 || bytes[p] == 0xf3 || bytes[p] == 0x66) i.prefix = bytes[p++];
        if (p < i.length && (bytes[p] & 0xf0) == 0x40) i.rex = bytes[p++];
        require(p < i.length,"Incomplete anchor opcode");
        i.op = bytes[p++];
        if (i.op == 0x0f) { require(p < i.length,"Incomplete two-byte anchor opcode"); i.op = 0x100 | bytes[p++]; }
    }
    if ((i.op == 0x16f || i.op == 0x17f) && (i.prefix == 0xf3 || i.prefix == 0x66)) i.vectorWidth = 16;
    i.operand = p;
    bool modrm = i.op == 0x88 || i.op == 0x89 || i.op == 0x8a || i.op == 0x8b || i.op == 0x8d
        || i.op == 0x63 || i.op == 0x80 || i.op == 0x81 || i.op == 0x83 || i.op == 0x85
        || i.op == 0x39 || i.op == 0x3b || i.op == 0xc6 || i.op == 0xc7 || i.op == 0xff
        || i.op == 0xf6 || i.op == 0xf7 || i.op == 0x01 || i.op == 0x03 || i.op == 0x09
        || i.op == 0x0b || i.op == 0x21 || i.op == 0x23 || i.op == 0x29 || i.op == 0x2b
        || i.op == 0x31 || i.op == 0x33 || i.op == 0x11f || i.op == 0x16f || i.op == 0x17f
        || i.op == 0x1ae || i.op == 0x1b6 || i.op == 0x1b7 || i.op == 0x1be || i.op == 0x1bf;
    if (!modrm) return i;
    require(p < i.length,"Incomplete anchor ModRM");
    auto m = bytes[p++];
    i.mode = m >> 6; i.group = (m >> 3) & 7;
    i.reg = i.group | ((i.rex & 4) ? 8 : 0);
    i.rm = (m & 7) | ((i.rex & 1) ? 8 : 0);
    if (i.mode == 3) return i;
    if ((m & 7) == 4) {
        require(p < i.length,"Incomplete anchor SIB");
        auto sib = bytes[p++];
        if (((sib >> 3) & 7) != 4 || (i.rex & 2)) i.index = ((sib >> 3) & 7) | ((i.rex & 2) ? 8 : 0);
        if (i.mode != 0 || (sib & 7) != 5) i.base = (sib & 7) | ((i.rex & 1) ? 8 : 0);
    } else if (i.mode != 0 || (m & 7) != 5) i.base = i.rm;
    if (i.mode == 1) { require(p < i.length,"Incomplete anchor disp8"); i.displacement = static_cast<signed char>(bytes[p]); }
    else if (i.mode == 2 || (i.mode == 0 && i.base == 16)) {
        require(i.length - p >= 4,"Incomplete anchor disp32"); i.displacement = signed32(bytes.data() + p);
    }
    return i;
}
bool call(const Instruction& i) { return i.op == 0xe8 || (i.op == 0xff && i.group == 2); }
bool jump(const Instruction& i) { return i.op == 0xe9 || i.op == 0xeb; }
bool branch(const Instruction& i) {
    return (i.op >= 0x70 && i.op <= 0x7f) || (i.op >= 0x180 && i.op <= 0x18f);
}
std::int64_t relative(std::span<const unsigned char> bytes,const Instruction& i) {
    return i.op == 0xeb || (i.op >= 0x70 && i.op <= 0x7f)
        ? static_cast<signed char>(bytes[i.length - 1]) : signed32(bytes.data() + i.length - 4);
}
struct Store { unsigned source; std::int64_t offset; bool xmm; };
constexpr Store stubRegisters[]{
    {3,-8,false},{12,-32,false},{13,-40,false},{14,-48,false},{15,-56,false},
    {6,-72,true},{7,-88,true},{8,-104,true},{9,-120,true},{10,-136,true},
    {11,-152,true},{12,-168,true},{13,-184,true},{14,-200,true},{15,-216,true},
    {6,-16,false},{7,-24,false}
};
std::size_t stubSavePrefix(std::span<const unsigned char> bytes) {
    constexpr unsigned char setup[]{0x55,0x48,0x8b,0xec,0x48,0x81,0xec,0xd8,0,0,0};
    require(bytes.size() >= sizeof(setup),"Truncated canonical call_stub setup");
    require(bytes[0] == 0x55 && bytes[1] == 0x48
        && ((bytes[2] == 0x8b && bytes[3] == 0xec) || (bytes[2] == 0x89 && bytes[3] == 0xe5))
        && !std::memcmp(bytes.data() + 4,setup + 4,sizeof(setup) - 4),
        "Noncanonical call_stub setup");
    std::size_t offset = sizeof(setup);
    auto store = [&](unsigned source,std::int64_t displacement,unsigned width,bool xmm) {
        auto i = instruction(bytes.subspan(offset));
        require(i.mode != 3 && i.base == 5 && i.index == 16 && i.reg == source
            && i.displacement == displacement && !(i.rex & 3),"Wrong call_stub save operand/order");
        if (xmm)
            require(i.op == 0x17f && i.prefix == 0xf3 && !(i.rex & 8) && i.vectorWidth == 16 && width == 16,
                "Wrong call_stub XMM save width/opcode");
        else require(i.op == 0x89 && !i.prefix && ((i.rex & 8) ? 8u : 4u) == width,
            "Wrong call_stub GPR/home save width/opcode");
        offset += i.length;
    };
    store(9,40,8,false);
    store(8,32,4,false);
    store(2,24,8,false);
    store(1,16,8,false);
    for (const auto& save : stubRegisters) store(save.source,save.offset,save.xmm ? 16 : 8,save.xmm);
    return offset;
}
struct Anchor {
    unsigned allocation = 0;
    std::vector<Store> saves;
};
// This private certificate deliberately rejects effects outside the fixed JNI
// wrapper/call_stub grammar. Decoder length alone conveys no frame proof.
Anchor anchorPrefix(std::span<const unsigned char> bytes,std::uintptr_t address,bool stub,
        std::uintptr_t barrier,std::uintptr_t nativeTarget,const CONTEXT* observed = nullptr,const Bounds* bounds = nullptr) {
    require(bytes.size() >= 8 && bytes.size() <= 16384,"Invalid anchor prefix extent");
    Anchor result;
    const auto saveEnd = stub ? stubSavePrefix(bytes) : 0;
    if (stub) result.saves.assign(std::begin(stubRegisters),std::end(stubRegisters));
    std::vector<std::size_t> starts, targets, indirectCalls;
    unsigned phase = 0, nativeCalls = 0;
    std::size_t previous = 0, anchorEnd = 0;
    Instruction last;
    for (std::size_t p = 0; p < bytes.size();) {
        auto b = bytes.subspan(p);
        auto i = instruction(b);
        starts.push_back(p);
        if (phase == 0 && i.op == 0x55 && i.length == 1) phase = 1;
        else if (phase == 1 && i.length == 3 && i.rex == 0x48 && i.mode == 3
                && ((i.op == 0x89 && i.rm == 5 && i.reg == 4)
                    || (i.op == 0x8b && i.reg == 5 && i.rm == 4))) phase = 2;
        else if (phase == 2 && i.rex == 0x48 && (i.op == 0x81 || i.op == 0x83)
                && i.mode == 3 && i.rm == 4 && i.group == 5) {
            auto amount = i.op == 0x83 ? static_cast<int>(static_cast<signed char>(b[i.length - 1]))
                : signed32(b.data() + i.length - 4);
            require(amount > 0 && !(amount & 7),"Invalid fixed anchor allocation");
            result.allocation = amount;
            anchorEnd = p + i.length;
            phase = 3;
        } else {
            require(phase == 0 || phase == 3,"Noncanonical anchor establishment");
            int destination = -1;
            bool writes = false, xmm = false, accepted = false;
            if (call(i)) {
                require(phase == 3,"Call before completed anchor");
                std::uintptr_t target = 0;
                if (stub) {
                    require(i.op == 0xff && i.mode == 3 && i.rm == 2 && p + i.length == bytes.size(),
                        "Unexpected call_stub call");
                    ++nativeCalls;
                } else if (i.op == 0xe8) target = address + p + i.length + relative(b,i);
                else {
                    require(i.mode == 3 && last.op >= 0xb8 && last.op <= 0xbf && (last.rex & 8)
                        && ((last.op & 7) | ((last.rex & 1) ? 8u : 0u)) == i.rm
                        && last.length == 10,"Uncertified indirect wrapper call");
                    std::memcpy(&target,bytes.data() + previous + last.length - 8,8);
                    indirectCalls.push_back(p);
                }
                if (!stub) {
                    if (p + i.length == bytes.size()) {
                        require(target == nativeTarget,"Wrapper return is not the exact checkpoint call");
                        ++nativeCalls;
                    } else require(barrier && target == barrier,"Uncertified pre-checkpoint wrapper call");
                }
                accepted = true;
            } else if (branch(i) || jump(i)) {
                require(phase == 3,"Branch before completed anchor");
                auto target = static_cast<std::int64_t>(p + i.length) + relative(b,i);
                require(target >= 0 && target < static_cast<std::int64_t>(bytes.size()),"Escaping anchor-prefix branch");
                targets.push_back(static_cast<std::size_t>(target));
                accepted = true;
            } else if (i.op == 0x90 || i.op == 0x11f || i.op == 0x85 || i.op == 0x39
                    || i.op == 0x3b || i.op == 0x3d || i.op == 0xa9
                    || ((i.op == 0x80 || i.op == 0x81 || i.op == 0x83) && i.group == 7)
                    || ((i.op == 0xf6 || i.op == 0xf7) && i.group == 0)) accepted = true;
            else if (i.op >= 0xb8 && i.op <= 0xbf) {
                destination = (i.op & 7) | ((i.rex & 1) ? 8 : 0); accepted = true;
            } else if (i.op == 0x88 || i.op == 0x89 || i.op == 0xc6 || i.op == 0xc7
                    || i.op == 0x01 || i.op == 0x09 || i.op == 0x21 || i.op == 0x29 || i.op == 0x31) {
                destination = i.mode == 3 ? static_cast<int>(i.rm) : -1;
                writes = i.mode != 3;
                accepted = (i.op != 0xc6 && i.op != 0xc7) || i.group == 0;
            } else if (i.op == 0x8a || i.op == 0x8b || i.op == 0x8d || i.op == 0x63
                    || i.op == 0x03 || i.op == 0x0b || i.op == 0x23 || i.op == 0x2b || i.op == 0x33
                    || i.op == 0x1b6 || i.op == 0x1b7 || i.op == 0x1be || i.op == 0x1bf) {
                destination = i.reg; accepted = true;
            } else if ((i.op == 0x81 || i.op == 0x83) || (i.op == 0xff && i.group <= 1)) {
                destination = i.mode == 3 ? static_cast<int>(i.rm) : -1;
                writes = i.mode != 3; accepted = true;
            } else if ((i.op == 0x16f || i.op == 0x17f) && (i.prefix == 0xf3 || i.prefix == 0x66)) {
                xmm = true; writes = i.op == 0x17f && i.mode != 3; accepted = true;
            } else if (i.op == 0x1ae && i.group == 2 && i.mode != 3) accepted = true;
            else if (i.length == 3 && b[0] == 0xc5 && b[1] == 0xf8 && b[2] == 0x77) accepted = true;
            else if (stub && phase == 3 && i.op == 0x50 && i.length == 1) accepted = true;
            require(accepted && destination != 4 && destination != 5 && (stub || destination != 15),
                "Unsupported or anchor/thread-clobbering wrapper/stub instruction");
            // Byte destinations AH/CH/DH/BH do not alias RSP/RBP; rejecting
            // additional low-byte destinations above is conservative.
            if (writes && !stub) {
                require(observed && bounds && i.index == 16,"Untracked wrapper memory writer");
                DWORD64 location = 0;
                if (i.base == 4) location = (phase == 0 ? observed->Rbp + 8 : observed->Rsp) + i.displacement;
                else if (i.base == 5) {
                    require(phase == 3,"RBP-relative writer before anchor establishment");
                    location = observed->Rbp + i.displacement;
                } else if (i.base == 15) {
                    require(observed->R15 == reinterpret_cast<DWORD64>(VMThread::current()),
                        "Wrapper thread register is not the current JavaThread");
                    location = observed->R15 + i.displacement;
                } else if (i.base == 16 && i.mode == 0 && (b[i.operand] & 7) == 5)
                    location = address + p + i.length + i.displacement;
                else require(false,"Untracked wrapper store base");
                auto width = xmm ? 16u : i.op == 0x88 || i.op == 0xc6 ? 1u : (i.rex & 8) ? 8u : 4u;
                require(location <= UINT64_MAX - width,"Wrapper store address overflows");
                auto linkage = observed->Rbp;
                require(location + width <= linkage || location >= linkage + 16,
                    "Wrapper writer overlaps saved RBP or return address");
                if (i.base == 15 || i.base == 16)
                    require(location + width <= bounds->low || location >= bounds->high,
                        "Wrapper nonstack writer aliases the actual stack");
                else if (phase == 3)
                    require(location >= observed->Rsp && location + width <= observed->Rbp,
                        "Wrapper stack writer escapes its allocated frame");
            }
            if (writes && stub)
                require(p < saveEnd,"Explicit memory writer after canonical call_stub saves");
        }
        previous = p; last = i; p += i.length;
    }
    require(phase == 3 && nativeCalls == 1,"Incomplete anchor or missing terminal call certificate");
    for (auto target : targets) {
        require(std::binary_search(starts.begin(),starts.end(),target),"Interior anchor branch target");
        require(target >= (stub ? saveEnd : anchorEnd),"Branch bypasses anchor establishment or reenters canonical saves");
        require(std::find(indirectCalls.begin(),indirectCalls.end(),target) == indirectCalls.end(),
            "Branch bypasses indirect call target materialization");
    }
    return result;
}
unsigned stubCertificateRegression() {
    std::vector<unsigned char> code{
        0x55,0x48,0x8b,0xec,0x48,0x81,0xec,0xd8,0,0,0,
        0x4c,0x89,0x4d,0x28, 0x44,0x89,0x45,0x20,
        0x48,0x89,0x55,0x18, 0x48,0x89,0x4d,0x10,
        0x48,0x89,0x5d,0xf8, 0x4c,0x89,0x65,0xe0,
        0x4c,0x89,0x6d,0xd8, 0x4c,0x89,0x75,0xd0,
        0x4c,0x89,0x7d,0xc8
    };
    constexpr std::size_t firstSave = 27,firstXmm = 47;
    for (unsigned reg = 6; reg <= 15; ++reg) {
        code.push_back(0xf3);
        if (reg >= 8) code.push_back(0x44);
        code.insert(code.end(),{0x0f,0x7f});
        int displacement = -72 - static_cast<int>(reg - 6) * 16;
        bool small = displacement >= -128;
        code.push_back(static_cast<unsigned char>((small ? 0x40 : 0x80) | ((reg & 7) << 3) | 5));
        if (small) code.push_back(static_cast<unsigned char>(displacement));
        else for (unsigned byte = 0; byte < 4; ++byte)
            code.push_back(static_cast<unsigned char>(static_cast<std::uint32_t>(displacement) >> (byte * 8)));
    }
    code.insert(code.end(),{0x48,0x89,0x75,0xf0,0x48,0x89,0x7d,0xe8});
    const auto saveEnd = code.size();
    code.insert(code.end(),{0x85,0xc9,0x74,0x05,0x50,0xff,0xc9,0x75,0xfb,0xff,0xd2});
    unsigned checks = 0;
    auto accepted = [&](const std::vector<unsigned char>& bytes) {
        try { anchorPrefix(bytes,0x10000000,true,0,0); return true; }
        catch (const std::runtime_error&) { return false; }
    };
    require(accepted(code),"Canonical call_stub certificate regression failed"); ++checks;
    auto reject = [&](std::vector<unsigned char> bytes) {
        require(!accepted(bytes),"Mutated call_stub certificate was accepted"); ++checks;
    };
    auto insert = [&](std::size_t offset,std::initializer_list<unsigned char> bytes) {
        auto result = code;
        result.insert(result.begin() + offset,bytes);
        return result;
    };
    reject(insert(firstSave,{0xeb,0x04}));                  // skipped save
    reject(insert(firstSave,{0x31,0xdb}));                  // clobbered incoming RBX
    reject(insert(firstXmm,{0x0f,0x57,0xf6}));              // clobbered incoming XMM6
    auto mutant = code; mutant[firstSave + 3] = 0xf9; reject(mutant);
    mutant = code;
    std::copy_n(code.begin() + firstSave,4,mutant.begin() + firstSave + 4);
    reject(mutant);                                       // duplicate save
    mutant = code; mutant[firstSave] = 0x40; reject(mutant);
    mutant = code; mutant[firstSave + 2] = 0x45; reject(mutant);
    mutant = code;
    std::swap_ranges(mutant.begin() + firstSave + 4,mutant.begin() + firstSave + 8,
        mutant.begin() + firstSave + 8);
    reject(mutant);                                       // wrong save order
    mutant = code; mutant[firstXmm + 4] = 0xb9; reject(mutant);
    reject(insert(saveEnd,{0x48,0x89,0x45,0xff}));          // partial linkage overlap
    reject(insert(saveEnd,{0x48,0x89,0x45,0xf9}));          // partial saved-register overlap
    reject(insert(saveEnd,{0x48,0x89,0x45,0x30}));          // later nonoverlapping store
    mutant = insert(saveEnd,{0xe9,0,0,0,0});
    auto displacement = static_cast<std::int32_t>(firstSave) - static_cast<std::int32_t>(saveEnd + 5);
    std::memcpy(mutant.data() + saveEnd + 1,&displacement,4);
    reject(mutant);                                       // branch back into saves
    reject(insert(code.size() - 2,{0xe8,0,0,0,1}));         // nonterminal direct call
    mutant.assign(code.begin(),code.begin() + saveEnd);
    mutant.push_back(0x90); reject(mutant);                // complete saves, no call
    mutant = code; mutant[code.size() - 2] = mutant.back() = 0x90;
    reject(mutant);                                       // removed terminal call
    mutant = code; mutant.resize(saveEnd - 1); reject(mutant);
    std::vector<unsigned char> vex;
    std::vector<std::size_t> vexStores;
    for (std::size_t offset = 0; offset < code.size();) {
        const auto i = instruction(std::span{code}.subspan(offset));
        if (i.op == 0x17f && i.prefix == 0xf3) {
            vexStores.push_back(vex.size());
            vex.insert(vex.end(),{0xc5,static_cast<unsigned char>(i.reg < 8 ? 0xfa : 0x7a),0x7f});
            vex.insert(vex.end(),code.begin() + offset + i.operand,code.begin() + offset + i.length);
        } else vex.insert(vex.end(),code.begin() + offset,code.begin() + offset + i.length);
        offset += i.length;
    }
    require(accepted(vex),"Canonical VEX call_stub certificate failed"); ++checks;
    for (unsigned reg = 0; reg < 16; ++reg) {
        const unsigned char bytes[]{0xc5,static_cast<unsigned char>(reg < 8 ? 0xfa : 0x7a),
            0x7f,static_cast<unsigned char>(0x45 | ((reg & 7) << 3)),0xf8};
        const auto i = instruction(bytes);
        require(i.op == 0x17f && i.prefix == 0xf3 && i.reg == reg && i.base == 5
            && i.index == 16 && i.displacement == -8 && i.vectorWidth == 16,
            "VEX XMM register/width/address normalization failed"); ++checks;
    }
    for (auto offset : {vexStores[0],vexStores[2]}) {
        for (unsigned bit = 0; bit < 7; ++bit) {
            mutant = vex; mutant[offset + 1] ^= 1u << bit; reject(mutant);
        }
        mutant = vex; mutant[offset + 1] ^= 0x80; reject(mutant); // Wrong saved source, valid inverted R.
    }
    for (auto opcode : {0x6f,0x7e,0xd6}) {
        mutant = vex; mutant[vexStores[0] + 2] = opcode; reject(mutant);
    }
    mutant = vex; mutant[vexStores[0] + 3] = 0xf6; reject(mutant); // Register destination.
    mutant = vex; mutant[vexStores[0] + 3] = 0x7d; reject(mutant); // Wrong source register.
    mutant = vex; mutant[vexStores[0] + 3] = 0x77; reject(mutant); // Wrong base.
    mutant = vex; mutant[vexStores[0] + 4] = 0xb9; reject(mutant); // Partial overlap.
    mutant = vex;
    std::swap_ranges(mutant.begin() + vexStores[0],mutant.begin() + vexStores[1],
        mutant.begin() + vexStores[1]);
    reject(mutant); // Save order.
    for (auto prefix : {0x66,0xf3,0x67}) {
        mutant = vex; mutant.insert(mutant.begin() + vexStores[0],prefix); reject(mutant);
    }
    auto insertVex = [&](std::size_t offset,std::initializer_list<unsigned char> bytes) {
        auto result = vex; result.insert(result.begin() + offset,bytes); return result;
    };
    reject(insertVex(vexStores[0],{0xeb,0x05}));
    reject(insertVex(vexStores[0],{0xc5,0xc8,0x57,0xf6})); // Early XMM6 clobber.
    mutant = vex;
    mutant.erase(mutant.begin() + vexStores[0],mutant.begin() + vexStores[0] + 5);
    mutant.insert(mutant.begin() + vexStores[0],{0xc4,0xe1,0x7a,0x7f,0x75,0xb8});
    reject(mutant); // VEX3 is outside the exact profile.
    mutant = vex;
    mutant[vexStores[0] + 3] = 0x74;
    mutant.insert(mutant.begin() + vexStores[0] + 4,0x05);
    reject(mutant); // RBP plus an index.
    reject(insertVex(stubSavePrefix(vex),{0xc5,0xfa,0x7f,0x75,0xb8})); // Later protected writer.
    return checks;
}
unsigned certificateRegression() {
    auto checks = stubCertificateRegression();
    Bounds bounds;
    CONTEXT observed{};
    observed.Rsp = bounds.high - 4096;
    observed.Rbp = observed.Rsp + 32;
    observed.R15 = reinterpret_cast<DWORD64>(VMThread::current());
    constexpr std::uintptr_t nativeTarget = 0x12345678;
    auto wrapper = [&](std::initializer_list<unsigned char> body) {
        std::vector<unsigned char> bytes{0x55,0x48,0x8b,0xec,0x48,0x83,0xec,0x20};
        bytes.insert(bytes.end(),body);
        bytes.insert(bytes.end(),{0x49,0xba});
        for (unsigned byte = 0; byte < 8; ++byte)
            bytes.push_back(static_cast<unsigned char>(nativeTarget >> (byte * 8)));
        bytes.insert(bytes.end(),{0x41,0xff,0xd2});
        try { anchorPrefix(bytes,0x10000000,false,0,nativeTarget,&observed,&bounds); return true; }
        catch (const std::runtime_error&) { return false; }
    };
    require(wrapper({0x49,0x89,0x07}),"Stable R15 wrapper certificate failed"); ++checks;
    require(!wrapper({0x4d,0x8b,0xd7,0x4c,0x8b,0xfd,0x49,0x89,0x07,0x4d,0x8b,0xfa}),
        "Restored R15 hid a prior linkage writer"); ++checks;
    const RUNTIME_FUNCTION valid{0x1000,0x1100,0x3000};
    auto record = [&](bool expected,DWORD directoryBytes,DWORD64 offset,DWORD64 pc,RUNTIME_FUNCTION row) {
        require(peRecord(0x5000,0x2000,directoryBytes,offset,pc,row) == expected,
            "Static PE row certificate regression failed"); ++checks;
    };
    record(true,24,0x2000,0x1004,valid);
    record(false,24,0x2100,0x1004,valid);                  // outside directory
    record(false,24,0x2004,0x1004,valid);                  // interior record pointer
    record(false,23,0x2000,0x1004,valid);                  // partial table record
    record(false,24,0x2000,0x1100,valid);                  // exclusive row end
    auto invalid = valid; invalid.BeginAddress = invalid.EndAddress;
    record(false,24,0x2000,0x1004,invalid);
    invalid = valid; invalid.UnwindData = 0;
    record(false,24,0x2000,0x1004,invalid);
    invalid = valid; invalid.UnwindData = 0x4ffc + 4;
    record(false,24,0x2000,0x1004,invalid);
    require(!peRecordLocation(0x5000,0x4ffc,24,0x4ffc),"Overflowing PE directory accepted"); ++checks;
    return checks;
}
void aliasUnwind(CONTEXT& context,std::span<const unsigned char> code,std::uintptr_t address,
        std::uint32_t begin,std::uint32_t end,std::span<const unsigned char> info) {
    auto offset = context.Rip - address;
    require(offset >= begin && offset < end && end <= code.size(),"Observed PC is outside the exact unwind row");
    auto infoOffset = (code.size() + 3) & ~std::size_t{3};
    auto page = static_cast<unsigned char*>(VirtualAlloc(nullptr,infoOffset + info.size(),
        MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    require(page,"Cannot allocate local metadata transport");
    std::memcpy(page,code.data(),code.size());
    std::memcpy(page + infoOffset,info.data(),info.size());
    RUNTIME_FUNCTION function{begin,end,static_cast<DWORD>(infoOffset)};
    auto sp = context.Rsp,fp = context.Rbp;
    context.Rip = reinterpret_cast<DWORD64>(page) + offset;
    require(context.Rsp == sp && context.Rbp == fp,"Metadata transport changed observed SP/FP");
    void* handler;
    DWORD64 establisher;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(page),context.Rip,&function,
        &context,&handler,&establisher,nullptr);
    VirtualFree(page,0,MEM_RELEASE);
}
template<class T> T imageRead(DWORD64 address) {
    T value;
    SIZE_T read = 0;
    require(ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(address),&value,sizeof(value),&read)
        && read == sizeof(value),"Cannot read bounded loaded-image metadata");
    return value;
}
PeRow peRow(DWORD64 pc) {
    MEMORY_BASIC_INFORMATION mapping{};
    require(VirtualQuery(reinterpret_cast<void*>(pc),&mapping,sizeof(mapping))
        && mapping.Type == MEM_IMAGE,"Native frame is not in a PE image");
    DWORD64 image = 0;
    auto function = RtlLookupFunctionEntry(pc,&image,nullptr);
    require(function && image == reinterpret_cast<DWORD64>(mapping.AllocationBase),
        "Native unwind row has no matching image identity");
    HMODULE module;
    require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,reinterpret_cast<LPCWSTR>(pc),&module),
        "Native PE image is not owned by the loader");
    struct ModulePin {
        HMODULE module;
        ~ModulePin() { FreeLibrary(module); }
    } pin{module};
    MODULEINFO mapped{};
    require(GetModuleInformation(GetCurrentProcess(),module,&mapped,sizeof(mapped))
        && reinterpret_cast<DWORD64>(mapped.lpBaseOfDll) == image && mapped.SizeOfImage >= sizeof(IMAGE_DOS_HEADER)
        && image <= UINT64_MAX - mapped.SizeOfImage,"Native loaded-image bounds disagree");
    const auto dos = imageRead<IMAGE_DOS_HEADER>(image);
    require(dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= sizeof(dos)
        && static_cast<DWORD>(dos.e_lfanew) <= mapped.SizeOfImage
        && sizeof(IMAGE_NT_HEADERS64) <= mapped.SizeOfImage - dos.e_lfanew,"Invalid bounded native PE header");
    const auto nt = imageRead<IMAGE_NT_HEADERS64>(image + dos.e_lfanew);
    require(nt.Signature == IMAGE_NT_SIGNATURE && nt.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64
        && nt.FileHeader.SizeOfOptionalHeader >= sizeof(IMAGE_OPTIONAL_HEADER64)
        && nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
        && nt.OptionalHeader.SizeOfImage == mapped.SizeOfImage
        && nt.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION,
        "Native image is not a supported loaded AMD64 PE");
    const auto directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    auto record = reinterpret_cast<DWORD64>(function);
    require(record >= image && peRecordLocation(mapped.SizeOfImage,directory.VirtualAddress,directory.Size,record - image),
        "Lookup row is not an aligned member of the loaded PE exception directory");
    const auto row = imageRead<RUNTIME_FUNCTION>(record);
    require(pc >= image && peRecord(mapped.SizeOfImage,directory.VirtualAddress,directory.Size,record - image,pc - image,row),
        "Native static PE row does not own the observed PC");
    return {image,row};
}
bool sameRow(const PeRow& a,const PeRow& b) {
    return a.image == b.image && a.function.BeginAddress == b.function.BeginAddress
        && a.function.EndAddress == b.function.EndAddress && a.function.UnwindData == b.function.UnwindData;
}
void nativeStep(CONTEXT& context,const Bounds& bounds) {
    require(bounds.has(context.Rsp,8),"Native context has no bounded return slot");
    auto row = peRow(context.Rip);
    auto old = context.Rsp;
    void* handler;
    DWORD64 establisher;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER,row.image,context.Rip,&row.function,&context,&handler,&establisher,nullptr);
    require(context.Rsp > old && bounds.has(context.Rsp,0),"Native unwind did not advance within the real stack");
}
__attribute__((noinline)) bool invokeWorkload(State& state,JNIEnv* env,jclass fixture,const jvalue* argument) {
    CONTEXT own;
    RtlCaptureContext(&own);
    stage(state,"baseline.capture",own);
    try {
        Bounds bounds;
        const auto row = peRow(own.Rip);
        require(sameRow(row,peRow(reinterpret_cast<DWORD64>(&invokeWorkload))),
            "Baseline capture is outside its own static helper row");
        auto parent = own;
        nativeStep(parent,bounds);
        const Baseline baseline{parent.Rip,parent.Rsp,parent.Rbp,row};
        state.baseline = &baseline;
        env->CallStaticVoidMethodA(fixture,state.ids[3],argument);
        state.baseline = nullptr;
        return !env->ExceptionCheck();
    } catch (const std::exception& failure) {
        recordFailure(state,failure.what());
        state.baseline = nullptr;
        return false;
    }
}
void wrapper(CONTEXT& context,State& state,const Bounds& bounds) {
    stage(state,"wrapper.identity",context);
    auto pc = reinterpret_cast<void*>(context.Rip);
    auto nm = CodeHeap::findNMethod(pc);
    require(nm && nm->isNMethod() && !std::strcmp(nm->name(),"native nmethod")
        && nm->method() && nm->method()->id() == state.ids[0],"Observed generated frame is not the exact native checkpoint wrapper");
    require(nm->isFrameCompleteAt(pc),"Native checkpoint wrapper is not frame-complete");
    auto entry = reinterpret_cast<std::uintptr_t>(nm->entry());
    require(entry >= reinterpret_cast<std::uintptr_t>(nm->code()) && entry < context.Rip
        && nm->contains(pc) && context.Rip - entry <= 16384,"Invalid native wrapper code extent");
    auto code = copy(entry,context.Rip - entry + 1);
    state.codeAddress = entry; state.stageCode = code;
    state.stage = "wrapper.certificate";
    auto frame = anchorPrefix(std::span{code}.first(code.size() - 1),entry,false,state.input.barrier,
        reinterpret_cast<std::uintptr_t>(&Java_CompiledHandlerSnapshotSmoke_checkpoint),&context,&bounds);
    require(nm->frameSize() * 8 == frame.allocation + 16,"Wrapper allocation disagrees with exported frame size");
    require(bounds.has(context.Rbp,16) && context.Rbp >= context.Rsp
        && context.Rbp - context.Rsp == frame.allocation,"Observed wrapper SP/FP disagree with canonical anchor");
    constexpr unsigned char info[]{2,0,2,5,0,3,0,0x50};
    state.stage = "wrapper.windows-unwind";
    aliasUnwind(context,code,entry,0,static_cast<std::uint32_t>(code.size()),info);
    ++state.oracleFrames;
}
const Compiled::Span& row(const std::vector<Compiled::Span>& rows,std::uint32_t pc) {
    for (const auto& r : rows) if (pc >= r.begin && pc < r.end) {
        require(r.proven,"Actual compiled context has no frame proof");
        return r;
    }
    throw std::runtime_error("Actual compiled context has no row");
}
std::uint32_t callStart(const Snapshot& snapshot,const std::vector<std::uint32_t>& reached,std::uint32_t pc) {
    for (auto start : reached) if (start < pc) {
        auto i = instruction(snapshot.code().subspan(start));
        if (start + i.length == pc && call(i)) return start;
    }
    throw std::runtime_error("Actual return PC has no reached forward-decoded call boundary");
}
void compiled(CONTEXT& context,State& state,const Bounds& bounds,unsigned index) {
    stage(state,"compiled.lookup",context);
    Snapshot snapshot;
    int level = 0;
    bool conventional = true,offsetKnown = false,startKnown = false,fullComputed = false,ordinaryComputed = false;
    std::uint32_t offset = 0,start = 0;
    std::vector<Compiled::Span> rows,ordinary;
    std::vector<std::uint32_t> reached,normalStarts;
    try {
        auto found = state.input.lookup(state.input.observer,context.Rip,state.ids[index],snapshot,level,conventional);
        if (!found)
            std::fprintf(stderr,"HANDLER_COMPILED_LOOKUP_FAILURE index=%u pc=%llx sp=%llx fp=%llx expectedId=%p\n",
                index,static_cast<unsigned long long>(context.Rip),static_cast<unsigned long long>(context.Rsp),
                static_cast<unsigned long long>(context.Rbp),reinterpret_cast<void*>(state.ids[index]));
        require(found,"Actual compiled frame has no equal retained callback certificate");
        state.stage = "compiled.route";
        require(level == 4,"Actual checkpoint chain is not level 4");
        if (index == 1) require(!conventional,"Actual handler frame uses the conventional route");
        offset = static_cast<std::uint32_t>(context.Rip - snapshot.address());
        offsetKnown = true;
        Compiled::Layout layout{snapshot.address(),state.input.barrier,snapshot.entry(),snapshot.allocation(),
            snapshot.edges().empty(),true};
        auto activeMethod = CodeHeap::findNMethod(reinterpret_cast<void*>(context.Rip));
        require(activeMethod && std::strcmp(activeMethod->name(),"nmethod") == 0,
            "Actual compiled frame is not an ordinary Java nmethod");
        state.stage = "compiled.full-analysis";
        fullComputed = Compiled::analyse(snapshot.code().data(),snapshot.code().size(),layout,rows,
            snapshot.edges(),snapshot.faults(),&reached);
        require(fullComputed,"Actual compiled snapshot failed CFG analysis");
        state.stage = "compiled.return-reached";
        require(std::binary_search(reached.begin(),reached.end(),offset),"Actual compiled PC is not a reached instruction start");
        state.stage = "compiled.call-boundary";
        start = callStart(snapshot,reached,offset);
        startKnown = true;
        state.stage = "compiled.row-call";
        const auto& before = row(rows,start);
        state.stage = "compiled.row-return";
        const auto& current = row(rows,offset);
        if (index == 1) {
            layout.handlersEmpty = true;
            state.stage = "compiled.ordinary-analysis";
            ordinaryComputed = Compiled::analyse(snapshot.code().data(),snapshot.code().size(),layout,ordinary,{},{},&normalStarts);
            require(ordinaryComputed,"Ordinary-root analysis failed");
            state.stage = "compiled.exceptional-only";
            require(!std::binary_search(normalStarts.begin(),normalStarts.end(),start)
                && !std::binary_search(normalStarts.begin(),normalStarts.end(),offset),
                "Observed checkpoint call/return is ordinary-root reachable");
            require(before.returnOffset == current.returnOffset && before.fpOffset == current.fpOffset,
                "Checkpoint call did not preserve the complete frame recipe");
            char detail[320];
            std::snprintf(detail,sizeof(detail),"HANDLER_OBSERVED code=%llx call=%u return=%u allocation=%u level=4 conventional=0 exceptionalOnly=1\n",
                static_cast<unsigned long long>(snapshot.address()),start,offset,snapshot.allocation());
            if (!state.implicit) state.report += detail;
        }
        state.stage = "compiled.stack-bounds";
        require(current.returnOffset <= 128 && bounds.has(context.Rsp,current.returnOffset + 8),
            "Compiled return slot is outside bounded oracle support");
        if (current.fpOffset >= 0) require(bounds.has(context.Rsp + current.fpOffset,8),"Compiled saved RBP is outside the stack");
        unsigned char info[16];
        unwindInfo(info,current);
        state.stage = "compiled.windows-unwind";
        aliasUnwind(context,snapshot.code(),snapshot.address(),current.begin,current.end,info);
        ++state.oracleFrames;
    } catch (...) {
        char detail[512];
        std::snprintf(detail,sizeof(detail),
            "HANDLER_COMPILED_FAILURE stage=%s index=%u pc=%llx sp=%llx fp=%llx base=%llx callKnown=%d call=%u returnKnown=%d return=%u level=%d conventional=%d expectedId=%p\n",
            state.stage,index,static_cast<unsigned long long>(state.observedPc),static_cast<unsigned long long>(state.observedSp),
            static_cast<unsigned long long>(state.observedFp),static_cast<unsigned long long>(snapshot.address()),
            startKnown,start,offsetKnown,offset,level,conventional,reinterpret_cast<void*>(state.ids[index]));
        std::string evidence = detail;
        std::snprintf(detail,sizeof(detail),
            "HANDLER_ACTIVE_CERTIFICATE index=%u address=%llx barrier=%llx entry=%zu allocation=%u bytes=",
            index,static_cast<unsigned long long>(snapshot.address()),static_cast<unsigned long long>(state.input.barrier),
            snapshot.entry(),snapshot.allocation());
        evidence += detail;
        evidence += hexBytes(snapshot.code());
        evidence += " handlers=";
        if (snapshot.edges().empty()) evidence += "-";
        for (const auto& edge : snapshot.edges())
            evidence += std::to_string(edge.source) + ":" + std::to_string(edge.target) + ":" + (edge.callReturn ? "1," : "0,");
        evidence += " faults=";
        if (snapshot.faults().empty()) evidence += "-";
        for (const auto& edge : snapshot.faults())
            evidence += std::to_string(edge.source) + ":" + std::to_string(edge.target) + ",";
        evidence += "\n";
        auto spans = [&](const char* name,bool computed,const std::vector<Compiled::Span>& values) {
            evidence += std::string("HANDLER_SPANS kind=") + name + " computed=" + (computed ? "1" : "0") + " values=";
            if (values.empty()) evidence += "-";
            for (const auto& value : values)
                evidence += std::to_string(value.begin) + ":" + std::to_string(value.end) + ":"
                    + std::to_string(value.returnOffset) + ":" + std::to_string(value.fpOffset) + ":" + (value.proven ? "1," : "0,");
            evidence += "\n";
        };
        auto starts = [&](const char* name,bool computed,const std::vector<std::uint32_t>& values) {
            evidence += std::string("HANDLER_REACHED kind=") + name + " computed=" + (computed ? "1" : "0") + " values=";
            if (values.empty()) evidence += "-";
            for (auto value : values) evidence += std::to_string(value) + ",";
            evidence += "\n";
        };
        spans("full",fullComputed,rows); starts("full",fullComputed,reached);
        spans("ordinary",ordinaryComputed,ordinary); starts("ordinary",ordinaryComputed,normalStarts);
        state.failureEvidence = std::move(evidence);
        throw;
    }
}
void stub(CONTEXT& context,State& state,const Bounds& bounds) {
    stage(state,"stub.identity",context);
    auto nm = CodeHeap::findNMethod(reinterpret_cast<void*>(context.Rip));
    require(nm && nm->isEntryFrame(reinterpret_cast<void*>(context.Rip)),"Compiled root did not return to exported call_stub return PC");
    auto address = state.input.stub;
    require(address && context.Rip > address && context.Rip - address < state.input.stubSize,
        "Exported return PC lacks an exact generated call_stub extent");
    auto code = copy(address,context.Rip - address + 1);
    state.codeAddress = address; state.stageCode = code;
    state.stage = "stub.certificate";
    auto frame = anchorPrefix(std::span{code}.first(code.size() - 1),address,true,0,0);
    require(frame.allocation == 216,"Unsupported Win64 call_stub allocation");
    require(frame.saves.size() == std::size(stubRegisters),"Call_stub lost its certified saved-register layout");
    require(context.Rbp >= 224 && bounds.has(context.Rbp - 224,240)
        && context.Rsp <= context.Rbp - 216,"Call_stub linkage or saved registers are outside the actual stack");
    std::vector<unsigned char> info{2,0,0,static_cast<unsigned char>(5 | (14 << 4)),0,3};
    auto word = [&](unsigned value) { info.push_back(value & 255); info.push_back((value >> 8) & 255); };
    for (const auto& e : frame.saves) {
        info.push_back(0); info.push_back(static_cast<unsigned char>((e.source << 4) | (e.xmm ? 9 : 4)));
        auto offset = static_cast<unsigned>(224 + e.offset);
        if (e.xmm) { word(offset); word(0); } else word(offset / 8);
    }
    info.push_back(0); info.push_back(1); word(224 / 8);
    info.push_back(0); info.push_back(0x50);
    info[2] = static_cast<unsigned char>((info.size() - 4) / 2);
    state.stage = "stub.windows-unwind";
    aliasUnwind(context,code,address,0,static_cast<std::uint32_t>(code.size()),info);
    ++state.oracleFrames;
}
struct LocalRow {
    std::vector<unsigned char> bytes;
    RUNTIME_FUNCTION function{};
    std::uintptr_t address = 0;
    std::uint32_t returnOffset = 0;
    std::int32_t fpOffset = -1;

    void prepare(const Snapshot& snapshot,const Compiled::Span& span) {
        require(span.proven && span.returnOffset <= 128 && !(span.returnOffset & 7)
            && (span.fpOffset == -1 || (span.fpOffset >= 0
                && static_cast<unsigned>(span.fpOffset) + 8 == span.returnOffset)),
            "Implicit observation requires a simple bounded Windows unwind row");
        auto infoOffset = (snapshot.code().size() + 3) & ~std::size_t{3};
        require(infoOffset <= 1024 * 1024,"Implicit alias code exceeds its cold bound");
        bytes.resize(infoOffset + 16);
        std::memcpy(bytes.data(),snapshot.code().data(),snapshot.code().size());
        unwindInfo(bytes.data() + infoOffset,span);
        function = {span.begin,span.end,static_cast<DWORD>(infoOffset)};
        address = snapshot.address();
        returnOffset = span.returnOffset;
        fpOffset = span.fpOffset;
    }

    bool step(CONTEXT& context,ULONG_PTR low,ULONG_PTR high) {
        auto has = [&](DWORD64 location,std::size_t size) {
            return location >= low && location <= high && size <= high - location;
        };
        if (context.Rip < address || context.Rip - address < function.BeginAddress
                || context.Rip - address >= function.EndAddress
                || !has(context.Rsp,returnOffset + 8)
                || (fpOffset >= 0 && !has(context.Rsp + fpOffset,8))) return false;
        auto offset = context.Rip - address;
        auto sp = context.Rsp;
        context.Rip = reinterpret_cast<DWORD64>(bytes.data()) + offset;
        void* handler;
        DWORD64 establisher;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER,reinterpret_cast<DWORD64>(bytes.data()),context.Rip,
            &function,&context,&handler,&establisher,nullptr);
        return context.Rsp > sp && has(context.Rsp,0);
    }
};
struct Implicit {
    Certificate source,carrier;
    LocalRow sourceRow,carrierRow;
    DWORD owner = GetCurrentThreadId();
    ULONG_PTR low = 0,high = 0;
    DWORD64 sourcePc = 0,carrierReturn = 0,commonPc = 0,commonSp = 0,commonFp = 0;
    std::atomic<unsigned> faults{0};
    std::atomic<bool> claimed{false};
    bool complete = false,contextUnchanged = false;
    unsigned failure = 0;
};
std::atomic<DWORD> implicitOwner{0};
std::atomic<Implicit*> implicitRecord{nullptr};
static_assert(std::atomic<DWORD>::is_always_lock_free && std::atomic<Implicit*>::is_always_lock_free
    && std::atomic<unsigned>::is_always_lock_free && std::atomic<bool>::is_always_lock_free);

std::uint64_t liveCell(const NMethodUnwindLayout::LiveCell& cell) {
    switch (cell.width) {
        case 1: return __atomic_load_n(reinterpret_cast<const std::uint8_t*>(cell.address),__ATOMIC_ACQUIRE);
        case 2: return __atomic_load_n(reinterpret_cast<const std::uint16_t*>(cell.address),__ATOMIC_ACQUIRE);
        case 4: return __atomic_load_n(reinterpret_cast<const std::uint32_t*>(cell.address),__ATOMIC_ACQUIRE);
        case 8: return __atomic_load_n(reinterpret_cast<const std::uint64_t*>(cell.address),__ATOMIC_ACQUIRE);
        default: __builtin_unreachable();
    }
}
bool liveEqual(const Certificate& certificate) {
    const auto& root = certificate.stamp.cells.back();
    if (liveCell(root) != root.expected) return false;
    for (const auto& cell : certificate.stamp.cells)
        if (liveCell(cell) != cell.expected) return false;
    for (const auto& range : certificate.stamp.bytes) {
        auto bytes = reinterpret_cast<const volatile unsigned char*>(range.address);
        for (std::size_t n = 0; n < range.bytes.size(); ++n)
            if (bytes[n] != range.bytes[n]) return false;
    }
    return liveCell(root) == root.expected;
}

LONG CALLBACK observeImplicit(EXCEPTION_POINTERS* exception) {
    // Other threads never load the pointer: its lifetime belongs to the one live
    // owner TID, whose VEH runs synchronously before that owner can retire it.
    if (implicitOwner.load(std::memory_order_acquire) != GetCurrentThreadId())
        return EXCEPTION_CONTINUE_SEARCH;
    auto& state = *implicitRecord.load(std::memory_order_acquire);
    const auto& record = *exception->ExceptionRecord;
    auto supplied = exception->ContextRecord;
    if (record.ExceptionCode != EXCEPTION_ACCESS_VIOLATION || record.NumberParameters != 2
            || record.ExceptionInformation[0] != 0 || record.ExceptionInformation[1] != 12
            || reinterpret_cast<DWORD64>(record.ExceptionAddress) != state.sourcePc
            || supplied->Rip != state.sourcePc || supplied->Rdx != 0) return EXCEPTION_CONTINUE_SEARCH;
    state.faults.fetch_add(1,std::memory_order_relaxed);
    if (state.claimed.exchange(true,std::memory_order_relaxed)) return EXCEPTION_CONTINUE_SEARCH;
    std::array<unsigned char,sizeof(CONTEXT)> original;
    std::memcpy(original.data(),supplied,sizeof(CONTEXT));
    CONTEXT context;
    std::memcpy(&context,original.data(),sizeof(context));
    if (!liveEqual(state.source)) state.failure = 1;
    else if (!state.sourceRow.step(context,state.low,state.high)) state.failure = 2;
    else if (context.Rip != state.carrierReturn) state.failure = 3;
    // Only this exact recovered return PC proves the carrier frame is active.
    else if (!liveEqual(state.carrier)) state.failure = 4;
    else if (!state.carrierRow.step(context,state.low,state.high)) state.failure = 5;
    else {
        state.commonPc = context.Rip; state.commonSp = context.Rsp; state.commonFp = context.Rbp;
        state.complete = true;
    }
    state.contextUnchanged = !std::memcmp(original.data(),supplied,sizeof(CONTEXT));
    return EXCEPTION_CONTINUE_SEARCH;
}

void prepareImplicit(Implicit& state,const Input& input,jmethodID source,jmethodID carrier) {
    require(input.coldLookup && input.coldLookup(input.observer,source,state.source)
        && input.coldLookup(input.observer,carrier,state.carrier),"Current implicit source/carrier certificates unavailable");
    for (const auto* certificate : {&state.source,&state.carrier}) {
        require(!certificate->stamp.cells.empty() && certificate->stamp.bytes.size() == 4,"Implicit live stamp is incomplete");
        require(certificate->stamp.cells.back().width == sizeof(std::uintptr_t),"Implicit method code root has the wrong width");
        for (const auto& cell : certificate->stamp.cells)
            require((cell.width == 1 || cell.width == 2 || cell.width == 4 || cell.width == 8)
                && cell.address && !(cell.address & (cell.width - 1))
                && cell.address <= UINTPTR_MAX - cell.width,"Implicit live cell cannot use an aligned exact-width load");
        for (const auto& range : certificate->stamp.bytes)
            require(range.bytes.size() <= 16 * 1024 * 1024 && range.address <= UINTPTR_MAX - range.bytes.size()
                && (range.bytes.empty() || range.address),"Implicit live byte range is not bounded");
    }
    require(state.source.level >= 1 && state.source.level <= 4,"Implicit source compilation level is unavailable");
    require(state.carrier.level == 4 && !state.carrier.conventional,"Implicit carrier must use the level-4 compiled route");
    auto analyse = [&](const Certificate& certificate,std::vector<Compiled::Span>& rows,
            std::vector<std::uint32_t>& starts,bool exceptional) {
        const auto& snapshot = certificate.snapshot;
        Compiled::Layout layout{snapshot.address(),input.barrier,snapshot.entry(),snapshot.allocation(),
            !exceptional || snapshot.edges().empty(),true};
        require(Compiled::analyse(snapshot.code().data(),snapshot.code().size(),layout,rows,
            exceptional ? snapshot.edges() : std::span<const Compiled::HandlerEdge>{},
            exceptional ? snapshot.faults() : std::span<const Compiled::FaultEdge>{},&starts),
            "Implicit certificate failed production frame analysis");
    };
    std::vector<Compiled::Span> sourceRows,carrierRows,ordinaryRows;
    std::vector<std::uint32_t> sourceStarts,carrierStarts,ordinaryStarts;
    analyse(state.source,sourceRows,sourceStarts,true);
    const auto& sourceSnapshot = state.source.snapshot;
    unsigned sources = 0;
    for (const auto& fault : sourceSnapshot.faults()) {
        auto i = instruction(sourceSnapshot.code().subspan(fault.source));
        constexpr unsigned char expected[]{0x8b,0x42,0x0c};
        if (i.length != sizeof(expected) || std::memcmp(sourceSnapshot.code().data() + fault.source,expected,sizeof(expected))) continue;
        require(std::binary_search(sourceStarts.begin(),sourceStarts.end(),fault.source)
            && std::binary_search(sourceStarts.begin(),sourceStarts.end(),fault.target),
            "Implicit source/continuation is not production-reached");
        const auto& sourceRow = row(sourceRows,fault.source);
        row(sourceRows,fault.target);
        state.sourceRow.prepare(sourceSnapshot,sourceRow);
        state.sourcePc = sourceSnapshot.address() + fault.source;
        ++sources;
    }
    require(sources == 1,"Expected exactly one certified mov eax,[rdx+12] implicit read");
    analyse(state.carrier,carrierRows,carrierStarts,true);
    analyse(state.carrier,ordinaryRows,ordinaryStarts,false);
    const auto& carrierSnapshot = state.carrier.snapshot;
    unsigned calls = 0;
    for (auto start : ordinaryStarts) {
        auto b = carrierSnapshot.code().subspan(start);
        auto i = instruction(b);
        if (i.op != 0xe8 || i.length != 5
                || carrierSnapshot.address() + start + i.length + relative(b,i)
                    != sourceSnapshot.address() + sourceSnapshot.entry()) continue;
        auto after = start + static_cast<std::uint32_t>(i.length);
        require(std::binary_search(carrierStarts.begin(),carrierStarts.end(),start)
            && std::binary_search(carrierStarts.begin(),carrierStarts.end(),after)
            && std::binary_search(ordinaryStarts.begin(),ordinaryStarts.end(),after),
            "Implicit carrier direct call/return is not reached");
        const auto& beforeRow = row(carrierRows,start);
        const auto& afterRow = row(carrierRows,after);
        const auto& ordinaryRow = row(ordinaryRows,after);
        require(beforeRow.returnOffset == afterRow.returnOffset
            && (beforeRow.fpOffset == -1 || beforeRow.fpOffset == afterRow.fpOffset)
            && afterRow.fpOffset >= 0
            && ordinaryRow.returnOffset == afterRow.returnOffset && ordinaryRow.fpOffset == afterRow.fpOffset,
            "Implicit carrier call/return has incompatible frame proofs");
        state.carrierRow.prepare(carrierSnapshot,afterRow);
        state.carrierReturn = carrierSnapshot.address() + after;
        ++calls;
    }
    require(calls == 1,"Expected one direct carrier E8 call to the current source compiled entry");
    GetCurrentThreadStackLimits(&state.low,&state.high);
}

void implicitCaller(const CONTEXT& context,State& state) {
    stage(state,"implicit.common-caller",context);
    auto& observation = *state.implicit;
    std::fprintf(stderr,"IMPLICIT_CALLER_COMPARE faultPc=%llx faultSp=%llx faultFp=%llx catchPc=%llx catchSp=%llx catchFp=%llx failure=%u\n",
        static_cast<unsigned long long>(observation.commonPc),static_cast<unsigned long long>(observation.commonSp),
        static_cast<unsigned long long>(observation.commonFp),static_cast<unsigned long long>(context.Rip),
        static_cast<unsigned long long>(context.Rsp),static_cast<unsigned long long>(context.Rbp),observation.failure);
    require(observation.owner == state.owner && observation.faults.load() == 1
        && observation.claimed.load() && observation.complete && !observation.failure
        && observation.contextUnchanged,"Implicit VEH observation is incomplete or changed the OS context");
    require(context.Rip == observation.commonPc && context.Rsp == observation.commonSp
        && context.Rbp == observation.commonFp,"Fault and catch do not recover the exact same outer caller PC/SP/FP");
}
void witness(CONTEXT context,State& state) {
    stage(state,"capture.ownership",context);
    Bounds bounds;
    require(state.owner == GetCurrentThreadId() && state.hits == 1,"Checkpoint ownership or once-only count changed");
    for (unsigned n = 0; !CodeHeap::contains(reinterpret_cast<void*>(context.Rip)); ++n) {
        stage(state,"native.before-wrapper",context);
        require(n < 32,"Native checkpoint wrapper was not reached");
        nativeStep(context,bounds); ++state.peFrames;
    }
    wrapper(context,state,bounds);
    compiled(context,state,bounds,1);
    if (state.implicit) implicitCaller(context,state);
    for (unsigned index = 2; index <= 3; ++index) compiled(context,state,bounds,index);
    stub(context,state,bounds);
    stage(state,"baseline.available",context);
    require(state.baseline,"Checkpoint has no immutable parent baseline");
    for (unsigned n = 0;; ++n) {
        stage(state,"native.after-stub",context);
        require(n < 64 && !CodeHeap::contains(reinterpret_cast<void*>(context.Rip)),"Unexpected generated frame below call_stub");
        const auto current = peRow(context.Rip);
        if (sameRow(current,state.baseline->helper)) {
            state.stage = "baseline.parent-unwind";
            nativeStep(context,bounds); ++state.peFrames;
            break;
        }
        nativeStep(context,bounds); ++state.peFrames;
    }
    stage(state,"baseline.compare",context);
    require(context.Rip == state.baseline->pc && context.Rsp == state.baseline->sp
        && context.Rbp == state.baseline->fp,
        "Actual outer PC/SP/FP differs from independently captured helper-parent baseline");
    // JNI/JVMTI is first used after the raw context and every native/compiled
    // frame has been recovered. Only method identity is compared here.
    state.stage = "identity.jvmti";
    jthread thread = nullptr;
    require(state.ti->GetCurrentThread(&thread) == JVMTI_ERROR_NONE,"Cannot identify checkpoint Java thread");
    jvmtiFrameInfo frames[8]{};
    jint count = 0;
    auto error = state.ti->GetStackTrace(thread,0,8,frames,&count);
    VM::jni()->DeleteLocalRef(thread);
    require(error == JVMTI_ERROR_NONE && count >= 4,"Independent JVMTI stack is incomplete");
    for (unsigned index = 0; index < state.ids.size(); ++index)
        require(frames[index].method == state.ids[index],"Independent JVMTI method chain differs from observed machine frames");
    char detail[256];
    std::snprintf(detail,sizeof(detail),"HANDLER_CONTEXT_WITNESS_OK checkpoints=1 normalCheckpoints=0 compiledCallers=2 oracleFrames=%u peFrames=%u exactBaseline=1 parentPeRow=1 pc=%llx sp=%llx fp=%llx\n",
        state.oracleFrames,state.peFrames,static_cast<unsigned long long>(context.Rip),
        static_cast<unsigned long long>(context.Rsp),static_cast<unsigned long long>(context.Rbp));
    if (!state.implicit) state.report += detail;
}
}

extern "C" __declspec(dllexport) int
asprof_test_handler_stub_certificate(const unsigned char* code,std::size_t size,std::uintptr_t originalAddress,
        char* error,std::size_t errorCapacity) {
    auto report = [&](const char* message) {
        if (error && errorCapacity) std::snprintf(error,errorCapacity,"%s",message);
    };
    if (!code || !size || size > 16384 || !originalAddress || originalAddress > UINTPTR_MAX - size
            || (!error && errorCapacity)) {
        report("Invalid bounded call_stub certificate input");
        return 0;
    }
    try {
        stubCertificateRegression();
        anchorPrefix(std::span{code,size},originalAddress,true,0,0);
        report("");
        return 1;
    } catch (const std::exception& failure) {
        report(failure.what());
        return 0;
    }
}

extern "C" __declspec(dllexport) void JNICALL
Java_CompiledHandlerSnapshotSmoke_checkpoint(JNIEnv*,jclass) {
    if (!active) { ++unarmed; return; }
    CONTEXT context;
    RtlCaptureContext(&context);
    auto& state = *active;
    ++state.hits;
    try { witness(context,state); }
    catch (const std::exception& failure) { recordFailure(state,failure.what()); }
}

namespace {
bool runImplicit(JNIEnv* env,jvmtiEnv* ti,jclass fixture,const Input& input,std::string& report,std::string& error) {
    Implicit observation;
    State state{input,ti,{}};
    state.implicit = &observation;
    state.ids = {env->GetStaticMethodID(fixture,"checkpoint","()V"),
        env->GetStaticMethodID(fixture,"implicitCarrier","(LCompiledHandlerSnapshotSmoke$Box;)V"),
        env->GetStaticMethodID(fixture,"implicitCaller","(LCompiledHandlerSnapshotSmoke$Box;)V"),
        env->GetStaticMethodID(fixture,"implicitRoot","(LCompiledHandlerSnapshotSmoke$Box;)V")};
    auto source = env->GetStaticMethodID(fixture,"faulting","(LCompiledHandlerSnapshotSmoke$Box;)I");
    auto boxId = env->GetStaticFieldID(fixture,"BOX","LCompiledHandlerSnapshotSmoke$Box;");
    if (env->ExceptionCheck()) { error = "Cannot resolve implicit checkpoint fixtures"; return false; }
    auto box = env->GetStaticObjectField(fixture,boxId);
    if (env->ExceptionCheck()) { error = "Cannot retain normal implicit fixture argument"; return false; }
    try { prepareImplicit(observation,input,source,state.ids[1]); }
    catch (const std::exception& failure) { error = failure.what(); env->DeleteLocalRef(box); return false; }
    HMODULE resident;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            reinterpret_cast<LPCWSTR>(&observeImplicit),&resident)) {
        error = "Cannot retain the private VEH artifact"; env->DeleteLocalRef(box); return false;
    }
    auto handler = AddVectoredExceptionHandler(1,observeImplicit);
    if (!handler) { error = "Cannot install passive implicit fault observer"; env->DeleteLocalRef(box); return false; }
    implicitRecord.store(&observation,std::memory_order_release);
    implicitOwner.store(observation.owner,std::memory_order_release);
    active = &state;
    jvalue argument{};
    argument.l = box;
    auto normal = invokeWorkload(state,env,fixture,&argument);
    env->DeleteLocalRef(box);
    if (normal && !state.hits && !observation.faults.load()) {
        argument.l = nullptr;
        invokeWorkload(state,env,fixture,&argument);
    } else if (state.error.empty()) state.error = "Normal implicit path faulted, threw or reached checkpoint";
    active = nullptr;
    implicitOwner.store(0,std::memory_order_release);
    implicitRecord.store(nullptr,std::memory_order_release);
    auto removed = RemoveVectoredExceptionHandler(handler);
    if (!removed || env->ExceptionCheck() || state.hits != 1 || observation.faults.load() != 1
            || !observation.complete || !observation.contextUnchanged || observation.failure || !state.error.empty()) {
        error = state.error.empty() ? "Implicit fault/catch observation did not complete exactly once (stage "
            + std::to_string(observation.failure) + ")" : state.error;
        return false;
    }
    report += "IMPLICIT_FAULT_CONTEXT_WITNESS_OK faults=1 checkpoints=1 normalFaults=0 normalCheckpoints=0"
        " contextUnchanged=1 commonCaller=1 exactBaseline=1 parentPeRow=1 targetCertified=1 targetObserved=0 sourceRoute=";
    report += observation.source.conventional ? "conventional" : "compiled";
    report += " sourceLevel=" + std::to_string(observation.source.level) + "\n";
    return true;
}
}
namespace HandlerCheckpoint {
bool run(JNIEnv* env,jvmtiEnv* ti,jclass fixture,const Input& input,std::string& report,std::string& error) {
    unsigned certificateChecks = 0;
    try { certificateChecks = certificateRegression(); }
    catch (const std::exception& failure) { error = failure.what(); return false; }
    State state{input,ti,{}};
    state.ids = {env->GetStaticMethodID(fixture,"checkpoint","()V"),
        env->GetStaticMethodID(fixture,"handlerTarget","(Z)V"),
        env->GetStaticMethodID(fixture,"handlerCaller","(Z)V"),
        env->GetStaticMethodID(fixture,"handlerRoot","(Z)V")};
    if (env->ExceptionCheck()) { error = "Cannot resolve exact checkpoint fixture IDs"; return false; }
    if (!unarmed || active || !input.barrier || !input.stub || !input.stubSize) {
        error = "Checkpoint warmup or generated entry/stub metadata missing"; return false;
    }
    active = &state;
    jvalue argument{};
    if (!invokeWorkload(state,env,fixture,&argument) || state.hits) {
        active = nullptr;
        error = state.error.empty() ? "Normal no-catch invocation reached checkpoint or threw" : state.error;
        return false;
    }
    argument.z = JNI_TRUE;
    invokeWorkload(state,env,fixture,&argument);
    active = nullptr;
    if (env->ExceptionCheck() || state.hits != 1 || !state.error.empty()) {
        error = state.error.empty() ? "Catch invocation did not complete exactly one checkpoint" : state.error;
        return false;
    }
    report = "HANDLER_CERTIFICATE_REGRESSION_OK checks=" + std::to_string(certificateChecks) + "\n" + state.report;
    return !input.implicit || runImplicit(env,ti,fixture,input,report,error);
}
}
