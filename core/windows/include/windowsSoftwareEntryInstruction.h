/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstring>
#include <cstdint>
#include <span>

namespace WindowsProfiler::SoftwareSites {
inline bool nonstackEntryInstruction(std::span<const unsigned char> bytes) {
    if (bytes.empty()) return false;
    auto prefix = bytes[0] >= 0x40 && bytes[0] <= 0x4f ? size_t{1} : size_t{0};
    if (bytes.size() <= prefix) return false;
    auto rex = prefix ? bytes[0] : 0;
    auto opcode = bytes[prefix];
    auto length = bytes.size() - prefix;
    // Only 32/64-bit operands and one REX prefix; REX.X has no register operand.
    if (rex & 2) return false;
    if ((opcode == 0x85 || opcode == 0x39 || opcode == 0x3b)
            && length == 2 && (bytes[prefix + 1] & 0xc0) == 0xc0) return true;
    if ((opcode == 0xa9 || opcode == 0x3d) && length == 5 && !(rex & 7)) return true;
    if (opcode >= 0xb8 && opcode <= 0xbf && !(rex & 6)
            && length == ((rex & 8) ? 9u : 5u)) {
        auto destination = (opcode & 7) | ((rex & 1) ? 8 : 0);
        return destination <= 2 || (destination >= 8 && destination <= 11);
    }
    if (length < 2 || (rex & 4)) return false;
    auto modrm = bytes[prefix + 1];
    if ((modrm & 0xc0) != 0xc0) return false;
    auto operation = (modrm >> 3) & 7;
    if ((opcode == 0xf7 && operation == 0 && length == 6)
            || (operation == 7 && ((opcode == 0x81 && length == 6) || (opcode == 0x83 && length == 3)))) return true;
    if (opcode != 0xc7 || operation != 0 || length != 6) return false;
    auto destination = (modrm & 7) | ((rex & 1) ? 8 : 0);
    return destination <= 2 || (destination >= 8 && destination <= 11);
}
inline bool nonstackEntryInstruction(std::span<const unsigned char> bytes,
        std::span<const unsigned char> before, std::span<const unsigned char> after) {
    constexpr unsigned char empty[]{2,0,0,0};
    return before.size() == sizeof(empty) && after.size() == sizeof(empty)
        && !std::memcmp(before.data(),empty,sizeof(empty)) && !std::memcmp(after.data(),empty,sizeof(empty))
        && nonstackEntryInstruction(bytes);
}
enum class EntryEffectKind { Unsupported, Neutral, Move, Allocate, Push };
struct EntryEffect {
    EntryEffectKind kind = EntryEffectKind::Unsupported;
    unsigned destination = 16, source = 16;
    unsigned allocation = 0;
    bool width64 = false;
};
inline EntryEffect entryInstructionEffect(std::span<const unsigned char> bytes) {
    if ((bytes.size() == 1 && bytes[0] == 0x90) || nonstackEntryInstruction(bytes))
        return {EntryEffectKind::Neutral};
    // PUSH r64; a stack fault of the displaced copy is reported at the source.
    if ((bytes.size() == 1 && bytes[0] >= 0x50 && bytes[0] <= 0x57)
            || (bytes.size() == 2 && bytes[0] == 0x41 && bytes[1] >= 0x50 && bytes[1] <= 0x57))
        return {EntryEffectKind::Push, static_cast<unsigned>((bytes.back() & 7) | (bytes.size() == 2 ? 8 : 0)), 16, 0, true};
    if (bytes.size() == 4 && bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xec
            && bytes[3] && bytes[3] <= 0x7f && !(bytes[3] & 7))
        return {EntryEffectKind::Allocate,16,16,bytes[3],true};
    if (bytes.size() == 7 && bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xec) {
        std::int32_t amount;
        std::memcpy(&amount,bytes.data() + 3,sizeof(amount));
        if (amount > 0 && !(amount & 7))
            return {EntryEffectKind::Allocate,16,16,static_cast<unsigned>(amount),true};
    }
    auto prefix = !bytes.empty() && bytes[0] >= 0x40 && bytes[0] <= 0x4f ? size_t{1} : size_t{0};
    if (bytes.size() == prefix + 2 && (bytes[prefix] == 0x89 || bytes[prefix] == 0x8b
            || bytes[prefix] == 0x31 || bytes[prefix] == 0x33) && (bytes[prefix + 1] & 0xc0) == 0xc0) {
        auto rex = prefix ? bytes[0] : 0;
        auto modrm = bytes[prefix + 1];
        auto reg = static_cast<unsigned>(((modrm >> 3) & 7) | ((rex & 4) ? 8 : 0));
        auto rm = static_cast<unsigned>((modrm & 7) | ((rex & 1) ? 8 : 0));
        bool toRm = bytes[prefix] == 0x89 || bytes[prefix] == 0x31;
        auto destination = toRm ? rm : reg, source = toRm ? reg : rm;
        if (destination != 4) return {bytes[prefix] == 0x89 || bytes[prefix] == 0x8b
            ? EntryEffectKind::Move : EntryEffectKind::Neutral,destination,source,0,(rex & 8) != 0};
    }
    constexpr unsigned char leaSum[]{0x48,0x8d,0x04,0x11};
    if (bytes.size() == sizeof(leaSum) && !std::memcmp(bytes.data(),leaSum,sizeof(leaSum)))
        return {EntryEffectKind::Neutral,0};
    return {};
}
}
