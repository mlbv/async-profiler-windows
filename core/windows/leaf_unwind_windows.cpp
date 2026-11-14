/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsLeafUnwind.h"
#include "windowsInstructionDecoder.h"
#include <cstring>

namespace WindowsProfiler::JavaUnwind::Leaf {
namespace {
std::int32_t signed32(const unsigned char* bytes) {
    std::int32_t value;
    std::memcpy(&value,bytes,sizeof(value));
    return value;
}
// Instructions that change neither RSP nor RBP: NOP forms and a stack-bang
// store below RSP.
bool neutral(const unsigned char* bytes,std::size_t length) {
    std::size_t prefix = 0;
    while (prefix < length && bytes[prefix] == 0x66) ++prefix;
    if (length - prefix == 1 && bytes[prefix] == 0x90) return true;
    if (length - prefix >= 3 && bytes[prefix] == 0x0f && bytes[prefix + 1] == 0x1f && ((bytes[prefix + 2] >> 3) & 7) == 0) return true;
    return length == 7 && bytes[0] == 0x89 && bytes[1] == 0x84 && bytes[2] == 0x24 && signed32(bytes + 3) < 0;
}
// sub rsp, imm8/imm32
bool subtractsRsp(const unsigned char* bytes,std::size_t length,std::uint32_t& amount) {
    if (bytes[0] != 0x48 || !((length == 4 && bytes[1] == 0x83) || (length == 7 && bytes[1] == 0x81)) || bytes[2] != 0xec) return false;
    auto value = length == 4 ? static_cast<std::int8_t>(bytes[3]) : signed32(bytes + 3);
    if (value <= 0) return false;
    amount = static_cast<std::uint32_t>(value);
    return true;
}
// mov [rsp + disp8/disp32], rbp
bool storesRbp(const unsigned char* bytes,std::size_t length,std::uint32_t& displacement) {
    std::int32_t value;
    if (length == 5 && bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0x6c && bytes[3] == 0x24) value = static_cast<std::int8_t>(bytes[4]);
    else if (length == 8 && bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xac && bytes[3] == 0x24) value = signed32(bytes + 4);
    else return false;
    if (value < 0) return false;
    displacement = static_cast<std::uint32_t>(value);
    return true;
}
}

std::size_t prologueEnd(const unsigned char* code,std::size_t size,std::size_t entry,std::uint32_t allocation) {
    if (entry >= size || allocation < 8 || (allocation & 7)) return 0;
    bool pushed = false;
    std::uint32_t reserved = 0, value;
    for (auto offset = entry; offset < size;) {
        auto length = InstructionDecoder::length(code + offset,size - offset);
        if (!length || length > size - offset) return 0;
        auto bytes = code + offset;
        offset += length;
        if (neutral(bytes,length)) continue;
        if (!pushed && !reserved && length == 1 && bytes[0] == 0x55) {
            pushed = true;
            if (allocation == 8) return offset;
        } else if (pushed && length == 3 && bytes[0] == 0x48
                && ((bytes[1] == 0x8b && bytes[2] == 0xec) || (bytes[1] == 0x89 && bytes[2] == 0xe5))) {
            // mov rbp,rsp leaves the pushed slot below the return address.
        } else if (!reserved && subtractsRsp(bytes,length,value)) {
            if (pushed) return value == allocation - 8 ? offset : 0;
            if (value != allocation) return 0;
            reserved = value;
        } else if (reserved && storesRbp(bytes,length,value)) {
            return value == allocation - 8 ? offset : 0;
        } else return 0;
    }
    return 0;
}

bool savedRbpSlot(const unsigned char* code,std::size_t size,std::size_t entry,std::size_t complete,std::uint32_t allocation) {
    if (complete > size) return false;
    auto end = prologueEnd(code,complete,entry,allocation);
    if (!end) return false;
    for (auto offset = end; offset < complete;) {
        auto length = InstructionDecoder::length(code + offset,complete - offset);
        if (!length || length > complete - offset) return false;
        auto bytes = code + offset;
        offset += length;
        if (neutral(bytes,length)
                // mov rbp,rsp changes neither RSP nor the saved slot.
                || (length == 3 && bytes[0] == 0x48 && ((bytes[1] == 0x8b && bytes[2] == 0xec) || (bytes[1] == 0x89 && bytes[2] == 0xe5)))
                // Entry-barrier compare against the thread's disarmed value.
                || (length == 8 && bytes[0] == 0x41 && bytes[1] == 0x81 && bytes[2] == 0x7f)
                || (length == 11 && bytes[0] == 0x41 && bytes[1] == 0x81 && bytes[2] == 0xbf)
                // Conditional guards do not change the frame. A call's return PC
                // observes the same stack allocation and the reserved RBP slot.
                || (length == 2 && bytes[0] >= 0x70 && bytes[0] <= 0x7f)
                || (length == 6 && bytes[0] == 0x0f && bytes[1] >= 0x80 && bytes[1] <= 0x8f)
                || (length == 5 && bytes[0] == 0xe8)) continue;
        return false;
    }
    return true;
}

bool preservedRbp(const unsigned char* code, std::size_t size, std::uint32_t allocation, std::vector<Span>& result) {
    std::vector<Span> spans;
    std::vector<std::int64_t> exits;
    std::uint32_t delta = 0;
    bool allocated = false;
    if (!allocation || (allocation & 7) || size > UINT32_MAX) return false;
    for (std::size_t offset = 0; offset < size;) {
        auto length = InstructionDecoder::length(code + offset,size - offset);
        if (!length || length > size - offset) return false;
        auto bytes = code + offset;
        std::size_t cursor = 0;
        unsigned rex = 0;
        bool operand16 = false;
        while (cursor < length && bytes[cursor] == 0x66) { operand16 = true; ++cursor; }
        if (cursor < length && bytes[cursor] >= 0x40 && bytes[cursor] <= 0x4f) rex = bytes[cursor++];
        if (cursor == length) return false;
        unsigned opcode = bytes[cursor++];
        if (opcode == 0x0f) {
            if (cursor == length) return false;
            opcode = 0x100 | bytes[cursor++];
        }
        auto nextDelta = delta;
        bool valid = false, finished = false;
        if (opcode == 0x90 || opcode == 0x11f) valid = true;
        else if (opcode == 0xc3 && length == 1) {
            if (!allocated || delta) return false;
            for (auto target : exits) if (target < static_cast<std::int64_t>(offset + length) || target >= static_cast<std::int64_t>(size)) return false;
            valid = finished = true;
        } else if ((opcode >= 0x180 && opcode <= 0x18f) || (opcode >= 0x70 && opcode <= 0x7f)) {
            if (rex || operand16) return false;
            std::int64_t displacement;
            if (opcode < 0x100) displacement = static_cast<std::int8_t>(bytes[length - 1]);
            else {
                std::int32_t value;
                std::memcpy(&value,bytes + length - 4,sizeof(value));
                displacement = value;
            }
            exits.push_back(static_cast<std::int64_t>(offset + length) + displacement);
            valid = true;
        } else if (opcode >= 0xb8 && opcode <= 0xbf) {
            auto destination = (opcode & 7) | ((rex & 1) << 3);
            valid = destination != 4 && destination != 5;
        } else {
            if (cursor == length) return false;
            auto modrm = bytes[cursor];
            auto mode = modrm >> 6, group = (modrm >> 3) & 7;
            auto reg = group | ((rex & 4) << 1), rm = (modrm & 7) | ((rex & 1) << 3);
            int destination = -1;
            switch (opcode) {
                case 0x89: case 0x01: case 0x09: case 0x21: case 0x29: case 0x31:
                case 0xc1:
                    destination = mode == 3 ? rm : -1; valid = true; break;
                case 0xc7:
                    destination = mode == 3 ? rm : -1; valid = group == 0; break;
                case 0x8b: case 0x8d: case 0x03: case 0x0b: case 0x23: case 0x2b: case 0x33: case 0x1af:
                    destination = reg; valid = true; break;
                case 0x39: case 0x3b: case 0x85:
                    valid = true; break;
                case 0x80:
                    valid = group == 7; break;
                case 0x81: case 0x83:
                    valid = true;
                    if (group == 7) break;
                    destination = mode == 3 ? rm : -1;
                    if (destination == 4 && rex == 0x48 && !operand16 && (group == 0 || group == 5)) {
                        std::int64_t immediate;
                        if (opcode == 0x83) immediate = static_cast<std::int8_t>(bytes[length - 1]);
                        else {
                            std::int32_t value;
                            std::memcpy(&value,bytes + length - 4,sizeof(value));
                            immediate = value;
                        }
                        if (immediate != allocation) return false;
                        if (group == 5 && !allocated && delta == 0) { nextDelta = allocation; allocated = true; }
                        else if (group == 0 && allocated && delta == allocation) nextDelta = 0;
                        else return false;
                        destination = -1;
                    }
                    break;
            }
            if (destination == 4 || destination == 5) return false;
        }
        if (!valid) return false;
        if (!spans.empty() && spans.back().returnOffset == delta) spans.back().end = static_cast<std::uint32_t>(offset + length);
        else spans.push_back({static_cast<std::uint32_t>(offset),static_cast<std::uint32_t>(offset + length),delta});
        if (finished) { result = std::move(spans); return true; }
        offset += length;
        delta = nextDelta;
    }
    return false;
}
}
