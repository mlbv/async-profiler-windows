/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsSoftwareFunction.h"
#include <algorithm>
#include <cstring>

namespace WindowsProfiler::SoftwareFunction {
namespace {
enum Kind : unsigned char { Plain, Return, Jump, Conditional, Call, IndirectJump, EpilogueJump, IndirectCall, Trap, Unsupported };
constexpr unsigned char noPop = 0xff;
struct Decoded {
    Kind kind = Plain;
    unsigned char pop = noPop;
    bool direct = false;
    std::int64_t target = 0;
};
template<class T> T read(const unsigned char* bytes) { T value; std::memcpy(&value, bytes, sizeof(value)); return value; }

Decoded decode(std::span<const unsigned char> bytes, std::uint32_t rva) {
    Decoded result;
    size_t cursor = 0;
    bool operand = false, legacy = false;
    for (; cursor < bytes.size(); ++cursor) {
        auto prefix = bytes[cursor];
        if (prefix == 0x66) operand = true;
        else if (prefix != 0xf0 && prefix != 0xf2 && prefix != 0xf3 && prefix != 0x2e && prefix != 0x36
                && prefix != 0x3e && prefix != 0x26 && prefix != 0x64 && prefix != 0x65 && prefix != 0x67) break;
        legacy = true;
    }
    unsigned rex = cursor < bytes.size() && (bytes[cursor] & 0xf0) == 0x40 ? bytes[cursor++] : 0;
    if (cursor >= bytes.size()) return {Unsupported};
    auto opcode = bytes[cursor];
    auto end = static_cast<std::int64_t>(rva) + static_cast<std::int64_t>(bytes.size());
    auto relative = [&](std::int64_t displacement, Kind kind) {
        result.kind = operand ? Unsupported : kind;
        result.direct = true;
        result.target = end + displacement;
        return result;
    };
    switch (opcode) {
        case 0xc3:
            // Windows epilogues recognize only RET and REP RET.
            return {bytes.size() == 1 || (bytes.size() == 2 && bytes[0] == 0xf3) ? Return : Unsupported};
        case 0xc2: return {bytes.size() == 3 ? Return : Unsupported};
        case 0xca: case 0xcb: case 0xcf: case 0x9a: case 0xea: return {Unsupported};
        case 0xe9: return relative(read<std::int32_t>(bytes.data() + bytes.size() - 4), Jump);
        case 0xeb: return relative(static_cast<std::int8_t>(bytes.back()), Jump);
        case 0xe8: return relative(read<std::int32_t>(bytes.data() + bytes.size() - 4), Call);
        case 0xe0: case 0xe1: case 0xe2: case 0xe3:
            return relative(static_cast<std::int8_t>(bytes.back()), Conditional);
        case 0xcc: case 0xcd: case 0xce: case 0xf1: case 0xf4: return {Trap};
        case 0xc7:
            // XBEGIN: the abort target is an intra-function branch.
            if (cursor + 1 < bytes.size() && bytes[cursor + 1] == 0xf8)
                return relative(read<std::int32_t>(bytes.data() + bytes.size() - 4), Conditional);
            return result;
        case 0xff: {
            if (cursor + 1 >= bytes.size()) return {Unsupported};
            auto operation = (bytes[cursor + 1] >> 3) & 7;
            if (operation == 3 || operation == 5) return {Unsupported};
            if (operation == 2) return {operand ? Unsupported : IndirectCall};
            if (operation != 4) return result;
            if (operand) return {Unsupported};
            // Exact byte forms matched by RtlVirtualUnwind's epilogue detection.
            bool epilogue = (bytes[0] == 0xff && bytes[1] == 0x25) || ((bytes[0] & 0xf8) == 0x48 && bytes[1] == 0xff);
            return {epilogue ? EpilogueJump : IndirectJump};
        }
        case 0x0f: {
            if (cursor + 1 >= bytes.size()) return {Unsupported};
            auto next = bytes[cursor + 1];
            if (next >= 0x80 && next <= 0x8f) return relative(read<std::int32_t>(bytes.data() + bytes.size() - 4), Conditional);
            if (next == 0x0b || next == 0xb9 || next == 0xff) return {Trap};
            if (next == 0x07 || next == 0x34 || next == 0x35) return {Unsupported};
            return result;
        }
        default:
            if (opcode >= 0x70 && opcode <= 0x7f) return relative(static_cast<std::int8_t>(bytes.back()), Conditional);
            if (opcode >= 0x58 && opcode <= 0x5f && !operand && !legacy)
                result.pop = static_cast<unsigned char>((opcode & 7) | ((rex & 1) << 3));
            return result;
    }
}
bool fallsThrough(unsigned char kind) {
    return kind == Plain || kind == Conditional || kind == Call || kind == IndirectCall;
}
struct Shape {
    SoftwareFunction::Teardown kind = SoftwareFunction::Teardown::None;
    unsigned base = 16;
    std::int64_t amount = 0;
};
// add rsp, imm and lea rsp, [base + disp] in RtlVirtualUnwind's recognized
// encodings, plus mov rsp, base, which it unwinds as an ordinary body instruction.
Shape teardown(std::span<const unsigned char> bytes) {
    Shape result;
    if (bytes.size() == 4 && bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xc4)
        return {SoftwareFunction::Teardown::Add, 16, static_cast<std::int8_t>(bytes[3])};
    if (bytes.size() == 7 && bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xc4)
        return {SoftwareFunction::Teardown::Add, 16, read<std::int32_t>(bytes.data() + 3)};
    if (bytes.size() >= 3 && (bytes[0] == 0x48 || bytes[0] == 0x49) && bytes[1] == 0x8d) {
        unsigned modrm = bytes[2], mode = modrm >> 6;
        if (((modrm >> 3) & 7) != 4 || (modrm & 7) == 4 || (mode != 1 && mode != 2)) return result;
        if (bytes.size() != (mode == 1 ? 4u : 7u)) return result;
        return {SoftwareFunction::Teardown::Lea, (modrm & 7) | ((bytes[0] & 1u) << 3),
            mode == 1 ? static_cast<std::int8_t>(bytes[3]) : read<std::int32_t>(bytes.data() + 3)};
    }
    if (bytes.size() == 3 && (bytes[2] >> 6) == 3) {
        auto modrm = bytes[2];
        if ((bytes[0] == 0x48 || bytes[0] == 0x4c) && bytes[1] == 0x89 && (modrm & 7) == 4)
            return {SoftwareFunction::Teardown::Move, ((modrm >> 3) & 7) | ((bytes[0] & 4u) << 1), 0};
        if ((bytes[0] == 0x48 || bytes[0] == 0x49) && bytes[1] == 0x8b && ((modrm >> 3) & 7) == 4)
            return {SoftwareFunction::Teardown::Move, (modrm & 7) | ((bytes[0] & 1u) << 3), 0};
    }
    return result;
}
}

const Analysis::Instruction* Analysis::find(std::uint32_t rva) const {
    auto found = std::lower_bound(_instructions.begin(), _instructions.end(), rva,
        [](const Instruction& instruction, std::uint32_t value) { return instruction.rva < value; });
    return found != _instructions.end() && found->rva == rva ? &*found : nullptr;
}

const char* Analysis::analyze(std::span<const Fragment> fragments, bool handler) {
    _instructions.clear(); _states.clear(); _epilogues.clear(); _exits.clear(); _begins.clear(); _ends.clear(); _code.clear();
    _unmatched.clear();
    if (fragments.empty()) return "function-coverage-empty";
    _primary = fragments[0].begin;
    auto& code = _code;
    for (const auto& fragment : fragments) {
        if (fragment.source.code.empty() || fragment.source.code.size() > UINT32_MAX - fragment.begin)
            return "function-coverage-range";
        NativeUnwind::BodyState state;
        if (auto error = NativeUnwind::bodyState(fragment.source, handler, state)) return error;
        if (!_states.empty() && (state.size != _states[0].size || state.pushes != _states[0].pushes
                || state.frameRegister != _states[0].frameRegister || state.frameSize != _states[0].frameSize))
            return "fragment-frame-differs-from-primary";
        _states.push_back(std::move(state));
        code.push_back(fragment.source.code);
        _begins.push_back(fragment.begin);
        _ends.push_back(fragment.begin + static_cast<std::uint32_t>(fragment.source.code.size()));
    }
    for (unsigned index = 0; index < fragments.size(); ++index) {
        auto bytes = code[index];
        for (size_t offset = 0; offset < bytes.size();) {
            auto length = InstructionDecoder::length(bytes.data() + offset, bytes.size() - offset);
            if (!length) return "function-instruction-unsupported";
            auto rva = static_cast<std::uint32_t>(_begins[index] + offset);
            auto decoded = decode(bytes.subspan(offset, length), rva);
            if (decoded.kind == Unsupported) return "function-transfer-unsupported";
            _instructions.push_back({rva, static_cast<unsigned char>(length), decoded.kind, decoded.pop, index,
                false, false, false, decoded.direct ? decoded.target : -1});
            offset += length;
        }
    }
    std::sort(_instructions.begin(), _instructions.end(), [](const Instruction& a, const Instruction& b) { return a.rva < b.rva; });
    for (size_t index = 1; index < _instructions.size(); ++index)
        if (_instructions[index - 1].rva + _instructions[index - 1].length > _instructions[index].rva)
            return "function-fragments-overlap";
    auto covered = [&](std::int64_t rva) {
        for (size_t index = 0; index < _begins.size(); ++index)
            if (rva >= _begins[index] && rva < _ends[index]) return true;
        return false;
    };
    _leaving.assign(_instructions.size(), false);
    for (size_t index = 0; index < _instructions.size(); ++index) {
        const auto& instruction = _instructions[index];
        _leaving[index] = instruction.kind == Jump && (!covered(instruction.target) || instruction.target == _primary);
    }
    auto leaves = [&](const Instruction& instruction) {
        return instruction.kind == Return || instruction.kind == EpilogueJump
            || _leaving[static_cast<size_t>(&instruction - _instructions.data())];
    };
    // Unproven bytes also guard epilogue interiors and call-return positions.
    for (size_t index = 0; index < _instructions.size(); ++index) {
        const auto& instruction = _instructions[index];
        if ((instruction.kind == Call || instruction.kind == IndirectCall) && index + 1 < _instructions.size()
                && _instructions[index + 1].rva == instruction.rva + instruction.length)
            _instructions[index + 1].callReturn = true;
        if (instruction.target < 0 || instruction.kind == Call || !covered(instruction.target)) continue;
        if (instruction.kind == Conditional && instruction.target == _primary) return "conditional-transfer-leaves-function";
        // Prolog-region positions have offset-limited states; entering one
        // from elsewhere would also hide a recursive call behind the entry.
        for (size_t fragment = 0; fragment < _begins.size(); ++fragment) {
            auto prolog = static_cast<std::int64_t>(_begins[fragment]) + _states[fragment].prolog;
            if (instruction.target > _begins[fragment] && instruction.target < prolog
                    && !(instruction.rva >= _begins[fragment] && instruction.rva < prolog)) return "branch-into-function-prolog";
        }
        if (auto target = find(static_cast<std::uint32_t>(instruction.target)))
            _instructions[static_cast<size_t>(target - _instructions.data())].branchTarget = true;
    }
    std::vector<size_t> pending;
    for (auto begin : _begins) {
        auto found = find(begin);
        pending.push_back(static_cast<size_t>(found - _instructions.data()));
    }
    while (!pending.empty()) {
        auto index = pending.back(); pending.pop_back();
        auto& instruction = _instructions[index];
        if (instruction.proven) continue;
        instruction.proven = true;
        if (instruction.kind == Conditional && !covered(instruction.target)) return "conditional-transfer-leaves-function";
        if (instruction.target >= 0 && instruction.kind != Call && covered(instruction.target) && instruction.target != _primary) {
            auto target = find(static_cast<std::uint32_t>(instruction.target));
            if (!target) return "branch-target-inside-instruction";
            pending.push_back(static_cast<size_t>(target - _instructions.data()));
        }
        if (fallsThrough(instruction.kind)) {
            if (index + 1 < _instructions.size() && _instructions[index + 1].rva == instruction.rva + instruction.length)
                pending.push_back(index + 1);
            // A final call may be noreturn; other code cannot fall out of the function.
            else if (instruction.kind != Call && instruction.kind != IndirectCall) return "fall-through-leaves-function";
        }
    }
    _handler = handler;
    _fragments.assign(fragments.begin(), fragments.end());
    for (size_t index = 0; index < _instructions.size(); ++index)
        if (leaves(_instructions[index]))
            if (auto error = match(index)) _unmatched.push_back({index, error});
    return nullptr;
}

const char* Analysis::match(size_t index) {
    auto contiguous = [&](size_t position) {
        return position && _instructions[position - 1].rva + _instructions[position - 1].length == _instructions[position].rva;
    };
    auto shapeOf = [&](const Instruction& instruction) {
        return teardown(_code[instruction.fragment].subspan(instruction.rva - _begins[instruction.fragment], instruction.length));
    };
    // The OS state at a prolog-region position applies only completed codes.
    auto stateAt = [&](const Instruction& instruction, unsigned& state) -> const char* {
        state = instruction.fragment;
        auto offset = instruction.rva - _begins[state];
        if (offset >= _states[state].prolog) return nullptr;
        NativeUnwind::BodyState partial;
        if (auto error = NativeUnwind::bodyState(_fragments[state].source, _handler, partial, offset)) return error;
        _states.push_back(std::move(partial));
        state = static_cast<unsigned>(_states.size() - 1);
        return nullptr;
    };
    {
        const auto& terminator = _instructions[index];
        if (!terminator.proven) return "return-site-in-unproven-code";
        unsigned stateIndex;
        if (auto error = stateAt(terminator, stateIndex)) return error;
        // The OS restores pops in reverse push order after the teardown.
        auto pops = _states[stateIndex].pushes.size();
        if (!_states[stateIndex].pushesFirst || pops > 16) return "epilogue-frame-unsupported";
        // Only a pushed frame register still holds the frame at the epilogue
        // start; a MOV-saved one may already be restored, breaking the body rule.
        if (auto frame = _states[stateIndex].frameRegister; frame && std::find(_states[stateIndex].pushes.begin(),
                _states[stateIndex].pushes.end(), frame) == _states[stateIndex].pushes.end())
            return "frame-register-not-pushed";
        auto start = index;
        for (size_t popped = 0; popped < pops; ++popped) {
            if (!contiguous(start) || _instructions[start - 1].pop != _states[stateIndex].pushes[popped]) return "epilogue-pops-mismatch";
            --start;
        }
        const auto& state = _states[stateIndex];
        Epilogue epilogue{};
        epilogue.teardown = SoftwareFunction::Teardown::None;
        auto osTeardown = [&](const Shape& shape) {
            return shape.kind == SoftwareFunction::Teardown::Add
                || (shape.kind == SoftwareFunction::Teardown::Lea && state.frameRegister && shape.base == state.frameRegister);
        };
        if (contiguous(start)) {
            auto shape = shapeOf(_instructions[start - 1]);
            auto remaining = static_cast<std::int64_t>(state.size) - static_cast<std::int64_t>(8 * pops);
            auto frame = static_cast<std::int64_t>(state.frameSize) - static_cast<std::int64_t>(8 * pops);
            // RtlVirtualUnwind treats MOV RSP and other LEA RSP forms as body
            // instructions, so their own position needs no amount proof.
            bool taken = shape.kind != SoftwareFunction::Teardown::None && (!osTeardown(shape)
                || (shape.kind == SoftwareFunction::Teardown::Add && remaining > 0 && shape.amount == remaining)
                || (shape.kind == SoftwareFunction::Teardown::Lea && shape.amount == frame));
            if (osTeardown(shape) && !taken) return "epilogue-teardown-mismatch";
            if (taken) {
                --start;
                epilogue.teardown = shape.kind;
                epilogue.frameRegister = static_cast<unsigned char>(shape.base);
                epilogue.amount = static_cast<std::int32_t>(shape.amount);
            }
        }
        if (epilogue.teardown == SoftwareFunction::Teardown::None) {
            if (state.size != 8 * pops && !state.frameRegister) return "epilogue-teardown-unrecognized";
            // An earlier pop would make the OS decode an epilogue through the INT3.
            if (contiguous(start) && _instructions[start - 1].pop != noPop) return "epilogue-preceded-by-pop";
        }
        // A direct branch into the epilogue is a further return when its
        // source has exactly the state left at its target: the pops still
        // ahead, no allocation and no frame. Shrink-wrapped early exits jump
        // from the prolog region straight to the final RET.
        std::vector<Exit> exits;
        for (auto position = start + 1; position <= index; ++position) {
            if (!_instructions[position].branchTarget) continue;
            auto remaining = index - position;
            for (const auto& branch : _instructions) {
                if (branch.target != _instructions[position].rva || (branch.kind != Conditional && branch.kind != Jump)) continue;
                auto condition = conditionOf(branch);
                if (!branch.proven || condition > 16) return "branch-into-epilogue-interior";
                unsigned sourceState;
                if (auto error = stateAt(branch, sourceState)) return error;
                const auto& entered = _states[sourceState];
                const auto& pushes = _states[stateIndex].pushes;
                if (entered.frameRegister || entered.size != 8 * remaining || entered.pushes.size() != remaining
                        || !std::equal(entered.pushes.begin(), entered.pushes.end(), pushes.begin()))
                    return "branch-into-epilogue-interior";
                exits.push_back({branch.rva, static_cast<unsigned>(_epilogues.size()), condition,
                    static_cast<unsigned char>(pops - remaining)});
            }
        }
        for (auto position = start; position <= index; ++position)
            if (!_instructions[position].proven) return "epilogue-in-unproven-code";
        const auto& first = _instructions[start];
        unsigned firstState;
        if (auto error = stateAt(first, firstState)) return error;
        // stateAt may have grown the state list.
        const auto& entry = _states[firstState];
        const auto& exit = _states[stateIndex];
        if (entry.size != exit.size || entry.pushes != exit.pushes || entry.frameRegister != exit.frameRegister
                || entry.frameSize != exit.frameSize) return "epilogue-crosses-prolog-operation";
        if (_handler && first.callReturn) return "handler-call-returns-to-epilogue";
        epilogue.start = first.rva;
        epilogue.terminator = terminator.rva;
        epilogue.end = terminator.rva + terminator.length;
        epilogue.fragment = first.fragment;
        epilogue.state = firstState;
        epilogue.popCount = static_cast<unsigned char>(pops);
        for (size_t popped = 0; popped < pops; ++popped) epilogue.pops[popped] = exit.pushes[pops - 1 - popped];
        epilogue.jump = terminator.kind != Return;
        const auto& bytes = _code[terminator.fragment];
        auto offset = terminator.rva - _begins[terminator.fragment];
        epilogue.immediate = bytes[offset] == 0xc2 ? read<std::uint16_t>(bytes.data() + offset + 1) : 0;
        _epilogues.push_back(epilogue);
        _exits.insert(_exits.end(), exits.begin(), exits.end());
    }
    return nullptr;
}
unsigned char Analysis::conditionOf(const Instruction& branch) const {
    auto bytes = _code[branch.fragment].subspan(branch.rva - _begins[branch.fragment], branch.length);
    size_t cursor = 0;
    while (cursor < bytes.size() && (bytes[cursor] == 0x2e || bytes[cursor] == 0x3e || bytes[cursor] == 0xf2)) ++cursor;
    if (bytes[cursor] >= 0x70 && bytes[cursor] <= 0x7f) return bytes[cursor] & 15;
    if (bytes[cursor] == 0x0f && bytes[cursor + 1] >= 0x80 && bytes[cursor + 1] <= 0x8f) return bytes[cursor + 1] & 15;
    if (bytes[cursor] == 0xeb || bytes[cursor] == 0xe9) return 16;
    // LOOP, JRCXZ and XBEGIN conditions are not EFLAGS predicates.
    return 255;
}
size_t Analysis::detected(size_t index) const {
    // RtlVirtualUnwind's code-stream rule: one optional ADD/LEA RSP, pops, then a terminator.
    auto contiguous = [&](size_t position) {
        return position + 1 < _instructions.size()
            && _instructions[position].rva + _instructions[position].length == _instructions[position + 1].rva;
    };
    const auto& first = _instructions[index];
    auto shape = teardown(_code[first.fragment].subspan(first.rva - _begins[first.fragment], first.length));
    auto frame = _states[first.fragment].frameRegister;
    if (shape.kind == SoftwareFunction::Teardown::Add || (shape.kind == SoftwareFunction::Teardown::Lea && frame && shape.base == frame)) {
        if (!contiguous(index)) return SIZE_MAX;
        ++index;
    }
    while (_instructions[index].pop != noPop) {
        if (!contiguous(index)) return SIZE_MAX;
        ++index;
    }
    const auto& terminator = _instructions[index];
    return terminator.kind == Return || terminator.kind == EpilogueJump || (terminator.kind == Jump && _leaving[index]) ? index : SIZE_MAX;
}

Position Analysis::classify(std::uint32_t rva, unsigned& fragment, const Epilogue*& epilogue) const {
    epilogue = nullptr;
    auto instruction = find(rva);
    if (!instruction || !instruction->proven) return Position::Unproven;
    fragment = instruction->fragment;
    for (const auto& candidate : _epilogues) {
        if (rva == candidate.start) { epilogue = &candidate; return Position::EpilogueStart; }
        if (rva > candidate.start && rva < candidate.end) { epilogue = &candidate; return Position::EpilogueInterior; }
    }
    auto index = static_cast<size_t>(instruction - _instructions.data());
    // The teardown run before an unmatched terminator keeps unknown states.
    for (auto [terminator, reason] : _unmatched) {
        auto start = terminator;
        while (start && start <= terminator && _instructions[start - 1].rva + _instructions[start - 1].length == _instructions[start].rva
                && (_instructions[start - 1].pop != noPop || teardown(_code[_instructions[start - 1].fragment].subspan(
                    _instructions[start - 1].rva - _begins[_instructions[start - 1].fragment], _instructions[start - 1].length)).kind
                    != SoftwareFunction::Teardown::None)) --start;
        if (index >= start && index <= terminator) return Position::EpilogueInterior;
    }
    // An unmatched OS epilogue at or through this position would see the INT3.
    for (size_t back = 0; back <= 17 && back <= index; ++back) {
        auto position = index - back;
        if (back && _instructions[position].rva + _instructions[position].length != _instructions[position + 1].rva) break;
        if (auto terminator = detected(position); terminator != SIZE_MAX && terminator >= index) return Position::EpilogueInterior;
    }
    return rva - _begins[fragment] < _states[fragment].prolog ? Position::Prolog : Position::Body;
}
bool Analysis::calls(const Instruction& instruction) { return instruction.kind == Call || instruction.kind == IndirectCall; }
bool Analysis::bodyEquivalent(std::uint32_t rva) const {
    auto instruction = find(rva);
    if (!instruction) return false;
    for (const auto& candidate : _epilogues) if (candidate.start == rva) return true;
    return detected(static_cast<size_t>(instruction - _instructions.data())) == SIZE_MAX;
}
}