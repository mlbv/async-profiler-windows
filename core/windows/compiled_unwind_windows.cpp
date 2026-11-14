/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsCompiledUnwind.h"
#include "windowsInstructionDecoder.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <tuple>
#include <utility>

namespace WindowsProfiler::JavaUnwind::Compiled {
namespace {
enum class Flow { Next, Jump, Branch, Call, Return, Exit };
struct Op {
    std::size_t length = 0;
    Flow flow = Flow::Next;
    bool direct = false, rbpWrite = false, rbpIdentity = false, rbpPush = false;
    // stackBase: the address uses RSP as base; stackAddress: RSP plus an exact displacement.
    bool stackWrite = false, stackRead = false, stackBase = false, stackAddress = false;
    bool rbpSource = false, width64 = false, preciseFaultInput = false;
    unsigned width = 0;
    std::int64_t target = 0, adjust = 0, displacement = 0;
    // Frame-pointer provenance: memory-operand base/index GPRs (-1: none or
    // RIP), the GPR a store writes, and the GPRs defined from `inputs`. Copy,
    // Add and Lea keep an exact frame offset; other combinations do not.
    // subtrahend is the GPR a register-form SUB subtracts.
    enum class Def : std::uint8_t { Combine, Copy, Add, Lea } def = Def::Combine;
    int base = -1, index = -1, stored = -1, subtrahend = -1;
    std::uint16_t defines = 0, inputs = 0;
    bool load = false;
    std::int64_t addend = 0;
};
bool decode(const unsigned char* bytes,std::size_t readable,Op& op) {
    op.length = WindowsProfiler::InstructionDecoder::length(bytes,readable);
    if (!op.length || op.length > readable) return false;
    if (op.length == 3 && bytes[0] == 0xc5 && bytes[1] == 0xf8 && bytes[2] == 0x77) return true;
    if ((op.length == 1 && bytes[0] == 0x99) || (op.length == 2 && bytes[0] == 0x48 && bytes[1] == 0x99)) {
        op.defines = 1u << 2; op.inputs = 1u << 0;
        return true;
    }
    std::size_t cursor = 0;
    bool operand16 = false, locked = false;
    unsigned rex = 0;
    unsigned opcode;
    bool scalarVector = false;
    unsigned scalarPrefix = 0;
    std::int64_t displacementScale = 1;
    // Scalar XMM arithmetic and moves cannot write a general-purpose register.
    // Memory stores still invalidate an overlapping or untracked saved-RBP slot;
    // EVEX disp8 is a signed count of eight-byte scalar elements.
    if (bytes[0] == 0x62) {
        if (op.length < 6 || bytes[3] != 0x08) return false;
        cursor = 5;
        opcode = bytes[4];
        bool fma = (bytes[1] & 0x0f) == 2;
        if (fma) {
            if ((bytes[2] & 0x87) != 0x85 || (opcode != 0x99 && opcode != 0xa9 && opcode != 0xb9)) return false;
        } else {
            if ((bytes[1] & 0x0f) != 1 || (bytes[2] & 0x87) != 0x87) return false;
            if (opcode == 0x10 || opcode == 0x11) {
                if ((bytes[cursor] >> 6) == 3 || (bytes[2] & 0x78) != 0x78) return false;
            } else if (opcode != 0x58 && opcode != 0x59) return false;
        }
        rex = 0x40 | ((bytes[1] & 0x80) ? 0 : 4) | ((bytes[1] & 0x40) ? 0 : 2)
            | ((bytes[1] & 0x20) ? 0 : 1);
        opcode |= fma ? 0x400 : 0x300;
        scalarVector = true;
        scalarPrefix = 3;
        displacementScale = 8;
    } else if (bytes[0] == 0xc4 && op.length >= 5 && (bytes[1] & 0x1f) == 2 && bytes[3] == 0xf7 && !(bytes[2] & 4) && (bytes[2] & 3)) {
        // BMI2 SARX/SHLX/SHRX: VEX.LZ.{F3,66,F2}.0F38.W0/W1 F7 /r reads ModRM.rm
        // and VEX.vvvv, and writes only ModRM.reg.
        rex = 0x40 | ((bytes[1] & 0x80) ? 0 : 4) | ((bytes[1] & 0x40) ? 0 : 2)
            | ((bytes[1] & 0x20) ? 0 : 1) | ((bytes[2] & 0x80) ? 8 : 0);
        cursor = 4;
        opcode = 0x2f7;
    } else if (bytes[0] == 0xc4 && op.length >= 5 && (bytes[1] & 0x1f) == 2) {
        // VFMADD132SD/213SD/231SD read XMM/m64 and write only XMM state.
        // Mandatory 66 is encoded in pp; W1 selects scalar double precision.
        if ((bytes[2] & 0x87) != 0x81) return false;
        cursor = 4;
        opcode = bytes[3];
        if (opcode != 0x99 && opcode != 0xa9 && opcode != 0xb9) return false;
        rex = 0x40 | ((bytes[1] & 0x80) ? 0 : 4) | ((bytes[1] & 0x40) ? 0 : 2)
            | ((bytes[1] & 0x20) ? 0 : 1);
        opcode |= 0x400;
        scalarVector = true;
        scalarPrefix = 3;
    } else if (bytes[0] == 0xc5 || (bytes[0] == 0xc4 && op.length >= 5 && (bytes[1] & 0x1f) == 1)) {
        auto vex = bytes[bytes[0] == 0xc5 ? 1 : 2];
        cursor = bytes[0] == 0xc5 ? 2 : 3;
        if (op.length <= cursor + 1 || (vex & 4) || (bytes[0] == 0xc4 && (vex & 0x80))) return false;
        scalarPrefix = vex & 3;
        if (scalarPrefix != 2 && scalarPrefix != 3) return false;
        if (bytes[0] == 0xc5) rex = 0x40 | ((vex & 0x80) ? 0 : 4);
        else rex = 0x40 | ((bytes[1] & 0x80) ? 0 : 4) | ((bytes[1] & 0x40) ? 0 : 2)
            | ((bytes[1] & 0x20) ? 0 : 1);
        opcode = bytes[cursor++];
        switch (opcode) {
            case 0x10: case 0x11:
                if ((bytes[cursor] >> 6) != 3 && (vex & 0x78) != 0x78) return false;
                break;
            case 0x51: case 0x58: case 0x59: case 0x5c: case 0x5d: case 0x5e: case 0x5f:
                break;
            default: return false;
        }
        opcode |= 0x300;
        scalarVector = true;
    } else if (bytes[0] == 0xc4) {
        // Intel RORX: VEX.LZ.F2.0F3A.W0/W1 F0 /r ib. No SIMD or
        // arbitrary VEX instruction gains a proof from this special case.
        if (op.length < 6 || (bytes[1] & 0x1f) != 3 || (bytes[2] & 0x7f) != 0x7b || bytes[3] != 0xf0) return false;
        rex = 0x40 | ((bytes[1] & 0x80) ? 0 : 4) | ((bytes[1] & 0x40) ? 0 : 2)
            | ((bytes[1] & 0x20) ? 0 : 1) | ((bytes[2] & 0x80) ? 8 : 0);
        cursor = 4;
        opcode = 0x2f0;
    } else {
        while (cursor < op.length && (bytes[cursor] == 0x66 || bytes[cursor] == 0xf0)) {
            operand16 |= bytes[cursor] == 0x66; locked |= bytes[cursor] == 0xf0; ++cursor;
        }
        if (cursor < op.length && bytes[cursor] >= 0x40 && bytes[cursor] <= 0x4f) rex = bytes[cursor++];
        if (cursor == op.length) return false;
        opcode = bytes[cursor++];
    }
    if (opcode == 0x0f) {
        if (cursor == op.length) return false;
        opcode = 0x100 | bytes[cursor++];
    }
    op.width64 = (rex & 8) != 0;
    op.width = scalarVector ? (scalarPrefix == 3 ? 8 : 4) : op.width64 ? 8 : operand16 ? 2 : 4;
    auto displacement = [&](bool small) {
        if (small) return static_cast<std::int64_t>(static_cast<std::int8_t>(bytes[op.length - 1]));
        std::int32_t value;
        std::memcpy(&value,bytes + op.length - 4,sizeof(value));
        return static_cast<std::int64_t>(value);
    };
    if (opcode == 0x90 || opcode == 0x3d) return !locked;
    if (opcode == 0x11f) return !locked && cursor < op.length && ((bytes[cursor] >> 3) & 7) == 0;
    // PREFETCH hints and their reserved-NOP encodings change no state and never fault.
    if (opcode == 0x118 || opcode == 0x10d) return !locked;
    if (opcode == 0xc3) { op.flow = Flow::Return; return !locked && !operand16; }
    if (opcode == 0xf4 || opcode == 0xcc || opcode == 0x10b) { op.flow = Flow::Exit; return !locked; }
    if (opcode == 0xe8 || opcode == 0xe9 || opcode == 0xeb
            || (opcode >= 0x70 && opcode <= 0x7f) || (opcode >= 0x180 && opcode <= 0x18f)) {
        if (locked || rex || operand16) return false;
        op.direct = true;
        op.flow = opcode == 0xe8 ? Flow::Call : opcode == 0xe9 || opcode == 0xeb ? Flow::Jump : Flow::Branch;
        op.target = displacement(opcode == 0xeb || (opcode >= 0x70 && opcode <= 0x7f));
        return true;
    }
    if (opcode >= 0xb8 && opcode <= 0xbf) {
        auto destination = (opcode & 7) | ((rex & 1) << 3);
        op.rbpWrite = destination == 5;
        op.defines = static_cast<std::uint16_t>(1u << destination);
        return !locked && destination != 4;
    }
    if (opcode == 0x55 || opcode == 0x5d) {
        if (locked || operand16 || (rex & 1) || cursor != op.length) return false;
        op.width64 = op.stackBase = op.stackAddress = true;
        op.width = 8;
        op.rbpPush = opcode == 0x55;
        op.adjust = op.rbpPush ? 8 : -8;
        op.displacement = op.rbpPush ? -8 : 0;
        op.stackWrite = op.rbpSource = op.rbpPush;
        op.stackRead = op.rbpWrite = !op.rbpPush;
        op.base = 4;
        if (op.rbpPush) op.stored = 5;
        else { op.defines = 1u << 5; op.load = true; }
        return true;
    }
    if (cursor == op.length) return false;
    auto modrm = bytes[cursor++];
    auto mode = modrm >> 6, group = (modrm >> 3) & 7;
    auto reg = group | ((rex & 4) << 1), rm = (modrm & 7) | ((rex & 1) << 3);
    // Without REX, byte registers 4-7 are AH, CH, DH and BH.
    auto byteRegister = [&](unsigned r) { return !rex && r >= 4 && r < 8 ? r - 4 : r; };
    bool memory = mode != 3, stackBase = false, noIndex = true;
    if (memory) {
        if ((modrm & 7) == 4) {
            if (cursor == op.length) return false;
            auto sib = bytes[cursor++];
            stackBase = (sib & 7) == 4 && !(rex & 1);
            noIndex = ((sib >> 3) & 7) == 4 && !(rex & 2);
            if ((sib & 7) != 5 || mode) op.base = (sib & 7) | ((rex & 1) << 3);
            if (!noIndex) op.index = ((sib >> 3) & 7) | ((rex & 2) << 2);
        } else if ((modrm & 7) != 5 || mode) op.base = rm;
        if (mode == 1) {
            if (cursor == op.length) return false;
            op.displacement = static_cast<std::int8_t>(bytes[cursor]) * displacementScale;
        } else if (mode == 2) {
            if (op.length - cursor < 4) return false;
            std::int32_t value;
            std::memcpy(&value,bytes + cursor,sizeof(value));
            op.displacement = value;
        }
    }
    op.stackBase = stackBase;
    op.stackAddress = stackBase && noIndex;
    int destination = -1;
    bool writesMemory = false, readsMemory = false, valid = true, lockAllowed = false;
    auto bit = [](unsigned r) { return static_cast<std::uint16_t>(1u << r); };
    auto source = [&](unsigned r) { op.inputs |= bit(r); };
    switch (opcode) {
        case 0x310: case 0x351: case 0x358: case 0x359: case 0x35c: case 0x35d: case 0x35e: case 0x35f:
        case 0x499: case 0x4a9: case 0x4b9:
            break;
        case 0x311:
            writesMemory = memory;
            break;
        case 0x89:
            destination = memory ? -1 : rm;
            writesMemory = memory;
            op.rbpSource = reg == 5;
            op.rbpIdentity = !memory && reg == 5 && rm == 5 && op.width64;
            if (memory) op.stored = static_cast<int>(reg);
            else { source(reg); if (op.width64) op.def = Op::Def::Copy; }
            break;
        case 0x8b:
            destination = reg; readsMemory = memory;
            op.rbpIdentity = !memory && reg == 5 && rm == 5 && op.width64;
            if (!memory) { source(rm); if (op.width64) op.def = Op::Def::Copy; }
            break;
        case 0x8d:
            destination = reg;
            if (destination == 4 && op.width64 && op.stackAddress) { op.adjust = -op.displacement; destination = -1; }
            if (op.width64) op.def = Op::Def::Lea;
            else { if (op.base >= 0) source(static_cast<unsigned>(op.base)); if (op.index >= 0) source(static_cast<unsigned>(op.index)); }
            break;
        case 0x03: case 0x0b: case 0x23: case 0x2b: case 0x33: case 0x1af:
            if (opcode == 0x2b && !memory) op.subtrahend = static_cast<int>(rm);
            source(reg);
            [[fallthrough]];
        case 0x63: case 0x69: case 0x6b: case 0x2f0:
            destination = reg;
            if (!memory) source(rm);
            break;
        case 0x2f7:
            destination = reg;
            if (!memory) source(rm);
            source((~bytes[2] >> 3) & 15);
            break;
        case 0x01: case 0x09: case 0x21: case 0x29: case 0x31:
            if (opcode == 0x29 && !memory) op.subtrahend = static_cast<int>(reg);
            destination = memory ? -1 : rm; writesMemory = memory; lockAllowed = memory;
            if (memory) op.stored = static_cast<int>(reg);
            else { source(rm); source(reg); }
            break;
        case 0xc1: case 0xd1: case 0xd3:
            destination = memory ? -1 : rm; writesMemory = memory; valid = group != 6;
            if (!memory) source(rm);
            break;
        case 0xc7:
            valid = group == 0; destination = memory ? -1 : rm; writesMemory = memory; break;
        case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x84: case 0x85:
            break;
        case 0x1b6: case 0x1b7: case 0x1be: case 0x1bf:
            destination = reg; readsMemory = memory;
            if (!memory) source(rm);
            break;
        case 0x8a:
            destination = static_cast<int>(byteRegister(reg)); readsMemory = memory;
            source(static_cast<unsigned>(destination));
            if (!memory) source(byteRegister(rm));
            break;
        case 0xc6:
            valid = group == 0;
            if (memory) { writesMemory = true; op.width = 1; }
            else { destination = static_cast<int>(byteRegister(rm)); source(static_cast<unsigned>(destination)); }
            break;
        case 0x88:
            if (memory) { writesMemory = true; op.width = 1; op.stored = static_cast<int>(byteRegister(reg)); }
            else { destination = static_cast<int>(byteRegister(rm)); source(static_cast<unsigned>(destination)); source(byteRegister(reg)); }
            break;
        case 0xf6:
            valid = group == 0; break;
        case 0x1b0: case 0x1b1: {
            // RAX is the implicit comparand and failure destination: it keeps
            // its value or receives the destination operand, and only a
            // register destination can receive the source.
            auto value = opcode == 0x1b0 ? byteRegister(reg) : reg;
            if (memory) {
                writesMemory = lockAllowed = true; if (opcode == 0x1b0) op.width = 1;
                op.stored = static_cast<int>(value);
            } else {
                destination = static_cast<int>(opcode == 0x1b0 ? byteRegister(rm) : rm);
                source(static_cast<unsigned>(destination));
            }
            op.defines |= bit(0);
            source(0);
            if (!memory) source(value);
            break;
        }
        case 0x80:
            valid = group == 7; break;
        case 0x81: case 0x83:
            if (group == 7) break;
            destination = memory ? -1 : rm; writesMemory = memory;
            lockAllowed = memory;
            if (destination == 4 && op.width64 && (group == 0 || group == 5)) {
                auto amount = displacement(opcode == 0x83);
                op.adjust = group == 5 ? amount : -amount;
                destination = -1;
            }
            if (destination >= 0) {
                source(rm);
                if (op.width64 && (group == 0 || group == 5)) {
                    auto amount = displacement(opcode == 0x83);
                    op.def = Op::Def::Add; op.addend = group == 5 ? -amount : amount;
                }
            }
            break;
        case 0xf7:
            // TEST, NOT, NEG, MUL, IMUL, DIV, IDIV; the implicit RDX:RAX forms keep RSP/RBP.
            valid = group != 1;
            if (group == 2 || group == 3) {
                destination = memory ? -1 : rm; writesMemory = lockAllowed = memory;
                if (!memory) source(rm);
            } else if (group >= 4) {
                op.defines = bit(0) | bit(2);
                source(0); source(2);
                if (!memory) source(rm);
            }
            break;
        case 0xff:
            if (group <= 1) {
                destination = memory ? -1 : rm; writesMemory = memory; lockAllowed = memory;
                if (!memory) { source(rm); if (op.width64) { op.def = Op::Def::Add; op.addend = group ? -1 : 1; } }
            }
            else if (group == 2) op.flow = Flow::Call;
            else valid = false;
            break;
        default:
            if (opcode >= 0x190 && opcode <= 0x19f) {
                // SETcc writes one byte.
                if (memory) { writesMemory = true; op.width = 1; }
                else { destination = static_cast<int>(byteRegister(rm)); source(static_cast<unsigned>(destination)); }
            } else if (opcode >= 0x140 && opcode <= 0x14f) {
                // CMOV may leave the old destination unchanged. In particular,
                // a conditional load into RBP cannot establish restoration.
                destination = reg;
                source(reg);
                if (!memory) source(rm);
            } else valid = false;
    }
    if (!valid || destination == 4 || (locked && !lockAllowed)) return false;
    op.rbpWrite = destination == 5 && !op.rbpIdentity;
    if (destination >= 0) op.defines |= bit(static_cast<unsigned>(destination));
    // A register destination with a memory source receives loaded data; CMPXCHG
    // loads the memory operand into RAX on failure.
    op.load = memory && op.defines && op.def != Op::Def::Lea && (!writesMemory || opcode == 0x1b0 || opcode == 0x1b1);
    op.stackWrite = writesMemory;
    op.stackRead = readsMemory && op.rbpWrite && stackBase;
    // Fault edges describe synchronous faults before a precise read/divide has
    // committed. Memory writers may have partial effects; never reuse their
    // input frame, even when the normal transfer would preserve or save it.
    if (!locked && !writesMemory && op.flow == Flow::Next && !op.adjust) {
        switch (opcode) {
            case 0x8b: case 0x63: case 0x03: case 0x0b: case 0x23: case 0x2b: case 0x33:
            case 0x1af: case 0x69: case 0x6b: case 0x2f0: case 0x2f7:
            case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x84: case 0x85: case 0x310:
            case 0x1b6: case 0x1b7: case 0x1be: case 0x1bf: case 0x8a: case 0xf6:
                op.preciseFaultInput = memory;
                break;
            case 0x80: case 0x81: case 0x83:
                op.preciseFaultInput = memory && group == 7;
                break;
            case 0xf7:
                op.preciseFaultInput = group >= 6 || (memory && (group == 0 || group == 4 || group == 5));
                break;
            default:
                op.preciseFaultInput = memory && opcode >= 0x140 && opcode <= 0x14f;
                break;
        }
    }
    return true;
}
// A GPR either holds no pointer into the current frame, may point into an
// escaped frame object, holds exactly entry-SP plus `offset`, holds that exact
// address or a pointer into an escaped frame object, or may point anywhere in
// the frame.
enum class Pointer : std::uint8_t { None, Escaped, Exact, ExactOrEscaped, Frame };
bool exactKind(Pointer kind) { return kind == Pointer::Exact || kind == Pointer::ExactOrEscaped; }
bool escapedKind(Pointer kind) { return kind == Pointer::None || kind == Pointer::Escaped; }
struct State {
    // RBP may still hold its incoming value, or that value may be available
    // in the reserved slot at entry-SP minus eight. Joins retain only facts
    // shared by every incoming path.
    bool reached = false, sp = true, rbp = true, slot = false;
    std::int64_t delta = 0;
    // Values entering the frame (incoming registers, loads, call results)
    // point into it only after one of its addresses escaped to memory or a
    // callee. Escaped frame objects lie below the saved slot unless
    // slotEscaped (COMPATIBILITY.md).
    bool escaped = false, slotEscaped = false;
    std::array<Pointer,16> pointer{};
    std::array<std::int32_t,16> offset{};
    // Exact offsets of objects below the slot whose address escaped on every incoming
    // path, ascending; zero entries are unused. Further escapes stay unrecorded.
    std::array<std::int32_t,4> escapedObjects{};
    bool operator==(const State&) const = default;
};
// An exact address of a frame object that escaped is itself a pointer into
// an escaped frame object, as a load of that address would be.
bool escapedObject(const State& state,std::size_t r) {
    if (escapedKind(state.pointer[r])) return true;
    return exactKind(state.pointer[r]) && state.offset[r] <= -16
        && std::find(state.escapedObjects.begin(),state.escapedObjects.end(),state.offset[r]) != state.escapedObjects.end();
}
// Joins two incoming values of a GPR. An exact address meeting a non-frame or
// escaped-object value, or the same address, keeps that address alongside the
// escaped objects (an inflated-lock path where the lock slot never escaped).
std::pair<Pointer,std::int32_t> join(Pointer first,std::int32_t firstOffset,Pointer second,std::int32_t secondOffset) {
    if (first == second && (!exactKind(first) || firstOffset == secondOffset)) return {first,exactKind(first) ? firstOffset : 0};
    if (escapedKind(first) && escapedKind(second)) return {Pointer::Escaped,0};
    if (exactKind(first) && (escapedKind(second) || (exactKind(second) && firstOffset == secondOffset))) return {Pointer::ExactOrEscaped,firstOffset};
    if (exactKind(second) && escapedKind(first)) return {Pointer::ExactOrEscaped,secondOffset};
    return {Pointer::Frame,0};
}
State merge(State first,const State& second) {
    if (!first.reached) return second;
    first.sp &= second.sp && first.delta == second.delta;
    if (!first.sp) { first.delta = 0; first.slot = false; }
    first.rbp &= second.rbp;
    first.slot &= second.slot;
    first.escaped |= second.escaped;
    first.slotEscaped |= second.slotEscaped;
    for (std::size_t r = 0; r < 16; ++r) {
        bool same = first.pointer[r] == second.pointer[r] && (!exactKind(first.pointer[r]) || first.offset[r] == second.offset[r]);
        std::tie(first.pointer[r],first.offset[r]) = !same && escapedObject(first,r) && escapedObject(second,r)
            ? std::pair{Pointer::Escaped,std::int32_t{0}} : join(first.pointer[r],first.offset[r],second.pointer[r],second.offset[r]);
    }
    std::array<std::int32_t,4> common{};
    std::size_t kept = 0;
    for (auto value : first.escapedObjects)
        if (value && std::find(second.escapedObjects.begin(),second.escapedObjects.end(),value) != second.escapedObjects.end()) common[kept++] = value;
    first.escapedObjects = common;
    return first;
}
// Reads a GPR's provenance; RSP is exact while the stack delta is known.
std::pair<Pointer,std::int64_t> pointerOf(const State& state,int r) {
    if (r < 0) return {Pointer::None,0};
    if (r == 4) return state.sp ? std::pair{Pointer::Exact,-state.delta} : std::pair{Pointer::Frame,std::int64_t{0}};
    return {state.pointer[r],state.offset[r]};
}
// The saved slot occupies [entry-SP - 8, entry-SP).
bool atSlot(std::int64_t begin,std::int64_t end) { return begin < 0 && end > -8; }
void escape(State& state,int r) {
    auto [kind,offset] = pointerOf(state,r);
    if (exactKind(kind)) {
        state.escaped = true; state.slotEscaped |= offset >= -8 && offset < 0;
        auto& objects = state.escapedObjects;
        if (offset <= -16 && std::find(objects.begin(),objects.end(),offset) == objects.end() && !objects.back()) {
            auto slot = std::find(objects.begin(),objects.end(),0);
            *slot = static_cast<std::int32_t>(offset);
            std::sort(objects.begin(),slot + 1);
        }
    }
    else if (kind == Pointer::Frame) state.escaped = state.slotEscaped = true;
}
// Whether a store not based on RSP may write the saved slot.
bool reachesSlot(const State& state,const Op& op) {
    auto [base,baseOffset] = pointerOf(state,op.base);
    auto [index,indexOffset] = pointerOf(state,op.index);
    if (base == Pointer::Frame || index == Pointer::Frame || exactKind(index)) return true;
    if (exactKind(base)) {
        // An indexed access stays within a frame object below the slot.
        if (op.index >= 0 ? baseOffset >= -8 : atSlot(baseOffset + op.displacement,baseOffset + op.displacement + op.width)) return true;
        return base == Pointer::ExactOrEscaped && state.slotEscaped;
    }
    if (base == Pointer::Escaped || index == Pointer::Escaped) return state.slotEscaped;
    return false;
}
void define(State& state,const Op& op) {
    if (!op.defines) return;
    Pointer kind = Pointer::None;
    std::int64_t offset = 0;
    auto single = [&]() {
        for (int r = 0; r < 16; ++r) if (op.inputs & (1u << r)) return pointerOf(state,r);
        return std::pair{Pointer::None,std::int64_t{0}};
    };
    switch (op.def) {
        case Op::Def::Copy:
            std::tie(kind,offset) = single();
            break;
        case Op::Def::Add:
            std::tie(kind,offset) = single();
            offset += op.addend;
            break;
        case Op::Def::Lea: {
            auto [base,baseOffset] = pointerOf(state,op.base);
            auto [index,indexOffset] = pointerOf(state,op.index);
            if (exactKind(base) && op.index < 0) { kind = base; offset = baseOffset + op.displacement; }
            else if (exactKind(base) || base == Pointer::Frame || exactKind(index) || index == Pointer::Frame) kind = Pointer::Frame;
            else if (base == Pointer::Escaped || index == Pointer::Escaped) kind = Pointer::Escaped;
            break;
        }
        case Op::Def::Combine:
            // Subtracting a frame address leaves a frame-relative offset (the
            // stack-lock check `mark - rsp`); re-forming an address needs a
            // frame operand again, which is tracked.
            if (op.subtrahend >= 0) {
                auto subtrahend = pointerOf(state,op.subtrahend).first;
                if (subtrahend == Pointer::Exact || subtrahend == Pointer::Frame) break;
            }
            for (int r = 0; r < 16; ++r) if (op.inputs & (1u << r)) {
                auto input = pointerOf(state,r).first;
                if (exactKind(input) || input == Pointer::Frame) kind = Pointer::Frame;
                else if (input == Pointer::Escaped && kind == Pointer::None) kind = Pointer::Escaped;
            }
            break;
    }
    if (op.load && state.escaped && kind == Pointer::None) kind = Pointer::Escaped;
    if (exactKind(kind) && (offset < INT32_MIN || offset > INT32_MAX)) kind = Pointer::Frame;
    for (int r = 0; r < 16; ++r) if (op.defines & (1u << r)) {
        state.pointer[r] = kind;
        state.offset[r] = exactKind(kind) ? static_cast<std::int32_t>(offset) : 0;
    }
}
// A callee may receive any frame pointer held in a register, and leaves each
// register unchanged or holding a pointer into an escaped object: the merge
// of the two, as at a control-flow join.
void call(State& state) {
    for (int r = 0; r < 16; ++r) if (r != 4) escape(state,r);
    auto clobbered = state;
    clobbered.pointer.fill(state.escaped ? Pointer::Escaped : Pointer::None);
    clobbered.offset.fill(0);
    state = merge(state,clobbered);
}
}

bool analyse(const unsigned char* code,std::size_t size,const Layout& layout,std::vector<Span>& result,
             std::span<const HandlerEdge> handlerEdges,std::span<const FaultEdge> faultEdges,
             std::vector<std::uint32_t>* reachable) {
    if (layout.handlersEmpty != handlerEdges.empty() || !layout.singleEntry || layout.entry >= size || size > UINT32_MAX || (layout.allocation & 7)
            || (layout.unverifiedEntry && *layout.unverifiedEntry >= layout.entry)) return false;
    for (const auto& edge : handlerEdges) if (!edge.source || edge.source >= size || edge.target >= size) return false;
    std::vector<HandlerEdge> handlers(handlerEdges.begin(),handlerEdges.end());
    std::sort(handlers.begin(),handlers.end(),[](const HandlerEdge& first,const HandlerEdge& second) { return first.source < second.source; });
    for (const auto& edge : faultEdges)
        if (edge.source >= size || !edge.target || edge.target >= size || edge.source == edge.target) return false;
    std::vector<FaultEdge> faults(faultEdges.begin(),faultEdges.end());
    std::sort(faults.begin(),faults.end(),[](const FaultEdge& first,const FaultEdge& second) { return first.source < second.source; });
    for (std::size_t edge = 1; edge < faults.size(); ++edge)
        if (faults[edge - 1].source == faults[edge].source) return false;
    std::vector<bool> matched(handlers.size(),false), faultMatched(faults.size(),false);
    std::vector<State> states(size);
    std::vector<Op> instructions(size);
    std::vector<std::size_t> owners(size,static_cast<std::size_t>(-1));
    std::vector<std::size_t> pending;
    for (auto entry : {std::optional<std::size_t>(layout.entry), layout.unverifiedEntry}) if (entry) {
        states[*entry].reached = true;
        pending.push_back(*entry);
    }
    auto enqueue = [&](std::size_t target,const State& incoming) {
        auto joined = merge(states[target],incoming);
        if (joined != states[target]) { states[target] = joined; pending.push_back(target); }
    };
    bool unmatchedSeeded = false;
    while (!pending.empty() || !unmatchedSeeded) {
        if (pending.empty()) {
            // Unreachable metadata sources carry no proved frame state.
            unmatchedSeeded = true;
            for (std::size_t edge = 0; edge < handlers.size(); ++edge) if (!matched[edge]) {
                enqueue(handlers[edge].target,State{true,false,false,false,0});
            }
            for (std::size_t edge = 0; edge < faults.size(); ++edge) if (!faultMatched[edge]) {
                enqueue(faults[edge].target,State{true,false,false,false,0});
            }
            continue;
        }
        auto pc = pending.back(); pending.pop_back();
        if (owners[pc] != static_cast<std::size_t>(-1) && owners[pc] != pc) return false;
        auto& op = instructions[pc];
        if (!op.length) {
            if (!decode(code + pc,size - pc,op)) return false;
            for (auto byte = pc; byte < pc + op.length; ++byte) {
                if (owners[byte] != static_cast<std::size_t>(-1) && owners[byte] != pc) return false;
                owners[byte] = pc;
            }
        }
        auto state = states[pc];
        auto fault = std::lower_bound(faults.begin(),faults.end(),pc,
            [](const FaultEdge& edge,std::size_t source) { return edge.source < source; });
        if (fault != faults.end() && fault->source == pc) {
            faultMatched[static_cast<std::size_t>(fault - faults.begin())] = true;
            enqueue(fault->target,op.preciseFaultInput ? state : State{true,false,false,false,0});
        }
        auto slotOffset = state.delta - 8;
        if (op.stackWrite && op.stored >= 0) escape(state,op.stored);
        if (op.stackWrite && state.sp) {
            if (op.stackBase) {
                bool overlap = !op.stackAddress || (op.displacement < slotOffset + 8 && op.displacement + op.width > slotOffset);
                if (overlap) state.slot = op.stackAddress
                    && (op.rbpPush ? state.delta == 0 : state.delta >= 8 && state.delta == layout.allocation)
                    && op.displacement == slotOffset && op.width64 && op.rbpSource && state.rbp;
            } else if (reachesSlot(state,op)) state.slot = false;
        }
        if (op.rbpWrite) state.rbp = op.stackRead && op.stackAddress && op.width64 && state.sp && state.slot && op.displacement == slotOffset;
        define(state,op);
        if (op.adjust && state.sp) {
            state.delta += op.adjust;
            if (state.delta < 0 || state.delta > UINT32_MAX || (state.delta & 7)) { state.sp = false; state.delta = 0; }
            if (!state.sp || state.delta < 8) state.slot = false;
        }
        auto next = pc + op.length;
        auto target = static_cast<std::int64_t>(next) + op.target;
        bool returns = true;
        if (op.flow == Flow::Call) {
            auto absolute = static_cast<std::uintptr_t>(static_cast<std::intptr_t>(layout.address) + target);
            if (op.direct && target >= 0 && target < static_cast<std::int64_t>(size) && target != static_cast<std::int64_t>(layout.entry)
                    && (!layout.unverifiedEntry || target != static_cast<std::int64_t>(*layout.unverifiedEntry))) return false;
            // Win64 callees own the outgoing 32-byte home area. A saved
            // frame slot must remain above it at the declared allocation.
            state.slot = state.slot && state.sp && state.delta == layout.allocation && state.delta >= 40;
            if (!op.direct || !layout.barrier || absolute != layout.barrier) state.rbp = false;
            call(state);
            returns = !op.direct || !(layout.deoptimization.contains(absolute) || layout.uncommonTrap.contains(absolute));
            auto edge = std::lower_bound(handlers.begin(),handlers.end(),next,
                [](const HandlerEdge& edge,std::size_t source) { return edge.source < source; });
            for (; edge != handlers.end() && edge->source == next; ++edge) {
                matched[static_cast<std::size_t>(edge - handlers.begin())] = true;
                bool proven = edge->callReturn && state.sp && state.slot && state.delta == layout.allocation && state.delta >= 40;
                // Exceptional entry does not preserve the live RBP register.
                auto entry = state;
                entry.sp = entry.slot = proven; entry.rbp = false;
                if (!proven) entry.delta = 0;
                enqueue(edge->target,entry);
            }
        }
        if (op.flow == Flow::Jump || op.flow == Flow::Branch) {
            if (target >= 0 && target < static_cast<std::int64_t>(size)) enqueue(static_cast<std::size_t>(target),state);
        }
        if (op.flow == Flow::Next || op.flow == Flow::Branch || (op.flow == Flow::Call && returns)) {
            if (next >= size) return false;
            enqueue(next,state);
        }
    }
    for (const auto& edge : faults)
        if (owners[edge.source] != static_cast<std::size_t>(-1) && owners[edge.source] != edge.source) return false;
    std::vector<Span> spans;
    for (std::size_t pc = 0; pc < size;) {
        auto length = instructions[pc].length;
        const auto& state = states[pc];
        bool proven = length && state.reached && state.sp && (state.rbp || (state.slot && state.delta >= 8 && state.delta - 8 <= INT32_MAX));
        if (proven && instructions[pc].flow == Flow::Return && (state.delta != 0 || !state.rbp)) proven = false;
        auto end = pc + (length ? length : 1);
        auto delta = proven ? static_cast<std::uint32_t>(state.delta) : 0;
        auto fp = proven && !state.rbp ? static_cast<std::int32_t>(state.delta - 8) : -1;
        if (!spans.empty() && spans.back().end == pc && spans.back().returnOffset == delta && spans.back().fpOffset == fp && spans.back().proven == proven) spans.back().end = static_cast<std::uint32_t>(end);
        else spans.push_back({static_cast<std::uint32_t>(pc),static_cast<std::uint32_t>(end),delta,fp,proven});
        pc = end;
    }
    if (reachable) {
        std::vector<std::uint32_t> starts;
        for (std::size_t pc = 0; pc < size; ++pc)
            if (states[pc].reached && instructions[pc].length) starts.push_back(static_cast<std::uint32_t>(pc));
        *reachable = std::move(starts);
    }
    result = std::move(spans);
    return true;
}
}
