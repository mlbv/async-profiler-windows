/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsInstructionDecoder.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include "../../third_party/detours/disasm.cpp"

namespace WindowsProfiler::InstructionDecoder {
namespace {
INIT_ONCE initialized = INIT_ONCE_STATIC_INIT;
BOOL CALLBACK initializeDecoder(PINIT_ONCE, void*, void**) {
    return CDetourDis::SetCodeModule(nullptr, nullptr, TRUE);
}
struct LastError {
    DWORD value = GetLastError();
    ~LastError() { SetLastError(value); }
};
struct Prefixes {
    size_t opcode = 0;
    bool forbidsVex = false;
};
Prefixes prefixes(const unsigned char* bytes, size_t size) {
    Prefixes result;
    while (result.opcode < size) {
        auto prefix = bytes[result.opcode];
        if ((prefix >= 0x40 && prefix <= 0x4f) || prefix == 0x66
                || prefix == 0xf0 || prefix == 0xf2 || prefix == 0xf3) result.forbidsVex = true;
        else if (prefix != 0x26 && prefix != 0x2e && prefix != 0x36 && prefix != 0x3e
                && prefix != 0x64 && prefix != 0x65 && prefix != 0x67) break;
        ++result.opcode;
    }
    return result;
}
}

void initialize() noexcept {
    LastError saved;
    if (!InitOnceExecuteOnce(&initialized, initializeDecoder, nullptr, nullptr)) RaiseFailFastException(nullptr, nullptr, 0);
}

size_t length(const void* source, size_t readable) noexcept {
    LastError saved;
    initialize();
    std::array<unsigned char, 32> snapshot, temporary;
    snapshot.fill(0xcc);
    auto available = std::min(MAX_INSTRUCTION_BYTES, readable);
    std::memcpy(snapshot.data(), source, available);
    auto prefix = prefixes(snapshot.data(), available);
    if (prefix.opcode == available) return 0;
    auto opcode = snapshot[prefix.opcode];
    // Intel SDM Vol. 2A, 2.3.2–2.3.4: LOCK, 66, F2, F3 and REX before VEX #UD.
    if ((opcode == 0xc4 || opcode == 0xc5) && prefix.forbidsVex) return 0;
    // The supported EVEX subset uses its native 64-bit address form only.
    if (opcode == 0x62 && prefix.opcode) return 0;
    CDetourDis decode(nullptr, nullptr);
    auto end = decode.CopyInstruction(temporary.data(), snapshot.data());
    if (!end) return 0;
    auto size = static_cast<size_t>(end - snapshot.data());
    // Relocation overflow and unexpandable LOOP branches do not invalidate
    // instruction boundaries; the scratch destination is irrelevant to length.
    return size && size <= available && size <= MAX_INSTRUCTION_BYTES ? size : 0;
}

bool relocate(void* destination, size_t capacity, const void* source, size_t readable, Relocation& result) noexcept {
    LastError saved;
    if (capacity < MAX_RELOCATED_BYTES || destination == source) return false;
    auto size = length(source, readable);
    if (!size) return false;
    auto bytes = static_cast<const unsigned char*>(source);
    auto output = static_cast<unsigned char*>(destination);
    auto opcode = prefixes(bytes, size).opcode;
    bool operand = std::find(bytes, bytes + opcode, 0x66) != bytes + opcode;
    auto next = reinterpret_cast<std::intptr_t>(bytes) + static_cast<std::intptr_t>(size);
    auto rebase = [](std::intptr_t target, std::intptr_t end, std::int32_t& relative) {
        auto delta = target - end;
        relative = static_cast<std::int32_t>(delta);
        return delta >= INT32_MIN && delta <= INT32_MAX;
    };
    std::int32_t relative;
    // E0-E3 are an opcode and rel8 after any prefixes.
    if (bytes[opcode] >= 0xe0 && bytes[opcode] <= 0xe3) {
        auto target = next + static_cast<std::int8_t>(bytes[size - 1]);
        if (operand || !rebase(target, reinterpret_cast<std::intptr_t>(output) + size + 7, relative)) return false;
        std::memcpy(output, bytes, size - 1);
        const unsigned char tail[]{2, 0xeb, 5, 0xe9};
        std::memcpy(output + size - 1, tail, sizeof(tail));
        std::memcpy(output + size + 3, &relative, sizeof(relative));
        result = {size, size + 7, reinterpret_cast<const void*>(target), size, size + 2};
        return true;
    }
    // This Detours pin decodes XBEGIN as C7/MOV and copies its rel32 as an immediate.
    if (size - opcode >= 2 && bytes[opcode] == 0xc7 && bytes[opcode + 1] == 0xf8) {
        std::int32_t displacement;
        std::memcpy(&displacement, bytes + size - sizeof(displacement), sizeof(displacement));
        auto target = next + displacement;
        if (operand || !rebase(target, reinterpret_cast<std::intptr_t>(output) + size, relative)) return false;
        std::memcpy(output, bytes, size - sizeof(relative));
        std::memcpy(output + size - sizeof(relative), &relative, sizeof(relative));
        result = {size, size, reinterpret_cast<const void*>(target), size, 0};
        return true;
    }
    LONG extra = 0;
    PBYTE target = nullptr;
    CDetourDis decode(&target, &extra);
    auto end = decode.CopyInstruction(static_cast<PBYTE>(destination), static_cast<PBYTE>(const_cast<void*>(source)));
    // This pin emits a single instruction, including when widening rel8 branches.
    if (!end || end - static_cast<const unsigned char*>(source) != size || extra < 0
            || static_cast<size_t>(extra) > MAX_INSTRUCTION_BYTES - size) return false;
    result = {size, size + static_cast<size_t>(extra), target, size + static_cast<size_t>(extra), 0};
    return true;
}
}
