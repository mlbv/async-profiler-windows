/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsNativeUnwind.h"
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace WindowsProfiler::SoftwareFunction {
// One exception-directory row of the analyzed function. Code covers
// [begin, begin + source.code.size()) image-relative; the primary row is first.
struct Fragment {
    std::uint32_t begin;
    NativeUnwind::Source source;
};
enum class Teardown : unsigned char { None, Add, Lea, Move };
struct Epilogue {
    // [start, end) image-relative; terminator is the final RET or leaving
    // jump. `state` indexes Analysis::state: the OS state at start, which is
    // offset-limited when start lies inside a prolog region.
    std::uint32_t start, terminator, end;
    unsigned fragment, state;
    Teardown teardown;
    unsigned char frameRegister;
    std::int32_t amount;
    std::array<unsigned char, 16> pops;
    unsigned char popCount;
    bool jump;
    std::uint16_t immediate;
};
// A direct branch whose source state equals an epilogue position it enters:
// when taken, the function returns through that epilogue's pops from
// firstPop and its terminator.
struct Exit {
    std::uint32_t branch;
    unsigned epilogue;
    // x86 condition code of a Jcc, or 16 for an unconditional jump.
    unsigned char condition;
    unsigned char firstPop;
};
enum class Position { Unproven, Prolog, Body, EpilogueStart, EpilogueInterior };

// Decodes the complete PE coverage of one function. Instruction boundaries
// come from a linear sweep that must tile every row; only code reached from
// row starts through fall-through and direct branches is proven. Indirect
// jumps follow the Windows x64 epilogue grammar: unprefixed JMP [RIP+disp32]
// and REX.W JMP r/m leave the function, every other form stays inside it.
// Each RET or leaving jump is matched to its epilogue or recorded as
// unmatched; return probes need every one matched.
class Analysis {
public:
    struct Instruction {
        std::uint32_t rva;
        unsigned char length, kind, pop;
        unsigned fragment;
        bool proven, branchTarget, callReturn;
        std::int64_t target;
    };
private:
    std::vector<Instruction> _instructions;
    std::vector<NativeUnwind::BodyState> _states;
    std::vector<Epilogue> _epilogues;
    std::vector<Exit> _exits;
    std::vector<std::uint32_t> _begins, _ends;
    std::vector<std::span<const unsigned char>> _code;
    std::vector<Fragment> _fragments;
    std::vector<bool> _leaving;
    std::vector<std::pair<size_t, const char*>> _unmatched;
    std::uint32_t _primary = 0;
    bool _handler = false;
    const Instruction* find(std::uint32_t rva) const;
    const char* match(size_t terminator);
    unsigned char conditionOf(const Instruction& branch) const;
    // Terminator index of the epilogue RtlVirtualUnwind detects at index, or SIZE_MAX.
    size_t detected(size_t index) const;
public:
    // Static diagnostic on failure; the analysis is then unusable.
    const char* analyze(std::span<const Fragment> fragments, bool handler);
    std::span<const Epilogue> epilogues() const { return _epilogues; }
    std::span<const Exit> exits() const { return _exits; }
    // First terminator without a matched epilogue; return sites need none.
    const char* returnError() const { return _unmatched.empty() ? nullptr : _unmatched.front().second; }
    const NativeUnwind::BodyState& state(unsigned index) const { return _states[index]; }
    std::span<const Instruction> instructions() const { return _instructions; }
    // Fragments must outlive classification. epilogue is set for a matched
    // EpilogueStart or EpilogueInterior; an unmatched OS epilogue at or
    // through rva is also an interior.
    Position classify(std::uint32_t rva, unsigned& fragment, const Epilogue*& epilogue) const;
    // At rva the OS applies the body rule or an epilogue equal to it.
    bool bodyEquivalent(std::uint32_t rva) const;
    static bool calls(const Instruction& instruction);
};
}
