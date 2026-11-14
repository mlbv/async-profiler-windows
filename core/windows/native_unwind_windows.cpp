/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsNativeUnwind.h"
#include "windowsSoftwareEntryInstruction.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <utility>

namespace WindowsProfiler::NativeUnwind {
namespace {
bool nonvolatile(unsigned reg) { return reg == 3 || (reg >= 5 && reg <= 7) || reg >= 12; }

bool controlTransfer(std::span<const unsigned char> instruction) {
    // InstructionDecoder already establishes the complete instruction length.
    // Its target also identifies direct/indirect branches, but near RET and
    // system/exception transfers have no target in the pinned Detours table.
    size_t cursor = 0;
    while (cursor < instruction.size()) {
        auto prefix = instruction[cursor];
        if (!(prefix >= 0x40 && prefix <= 0x4f) && prefix != 0x26 && prefix != 0x2e
                && prefix != 0x36 && prefix != 0x3e && prefix != 0x64 && prefix != 0x65
                && prefix != 0x66 && prefix != 0x67 && prefix != 0xf0 && prefix != 0xf2 && prefix != 0xf3) break;
        ++cursor;
    }
    if (cursor == instruction.size()) return true;
    auto opcode = instruction[cursor++];
    if ((opcode >= 0x70 && opcode <= 0x7f) || (opcode >= 0xe0 && opcode <= 0xe3) || (opcode >= 0xe8 && opcode <= 0xeb)
            || opcode == 0x9a || opcode == 0xc2 || opcode == 0xc3 || opcode == 0xca || opcode == 0xcb
            || opcode == 0xcc || opcode == 0xcd || opcode == 0xce || opcode == 0xcf || opcode == 0xf1 || opcode == 0xf4) return true;
    if (cursor == instruction.size()) return false;
    auto next = instruction[cursor];
    if (opcode == 0xff) return ((next >> 3) & 7) >= 2 && ((next >> 3) & 7) <= 5;
    if (opcode == 0xc7 && next == 0xf8) return true;
    return opcode == 0x0f && ((next >= 0x80 && next <= 0x8f)
        || next == 0x05 || next == 0x07 || next == 0x0b || next == 0x34 || next == 0x35);
}

std::uint32_t littleEndian(const unsigned char* bytes, unsigned count) {
    std::uint32_t value = 0;
    for (unsigned byte = 0; byte < count; ++byte)
        value |= static_cast<std::uint32_t>(bytes[byte]) << (byte * 8);
    return value;
}
struct Group { unsigned offset, index, slots, operation; };
struct Parsed {
    std::span<const unsigned char> code, unwind;
    std::array<bool, 256> boundaries{};
    std::array<Group, 255> groups{};
    size_t count = 0, padded = 0;
    unsigned version = 0, flags = 0, frame = 0;
};
// Body states also accept handlers and saved volatile registers, whose
// restoration does not affect any caller-visible register.
const char* parse(std::span<const unsigned char> code, std::span<const unsigned char> info, size_t zeroPrologLength, Parsed& result,
        bool body = false) {
    if (info.size() < 4) return "truncated-unwind-header";
    Parsed parsed;
    parsed.code = code; parsed.unwind = info;
    parsed.version = info[0] & 7; parsed.flags = info[0] >> 3; parsed.frame = info[3];
    if (parsed.version != 1 && parsed.version != 2) return "unsupported-unwind-version";
    if ((parsed.flags & ~7u) || ((parsed.flags & 4) && (parsed.flags & 3))) return "invalid-unwind-flags";
    auto slots = info[2];
    parsed.padded = 4 + ((static_cast<size_t>(slots) + 1) & ~size_t(1)) * 2;
    if (info.size() < parsed.padded) return "truncated-unwind-codes";
    if (parsed.flags & 3) {
        if (info.size() - parsed.padded < 4) return "truncated-unwind-handler";
        if (!body) return "language-handler-needs-forwarding";
    }
    if ((parsed.flags & 4) && info.size() - parsed.padded < 12) return "truncated-unwind-chain";
    if (code.size() > UINT32_MAX) return "function-range";
    if (info[1] > code.size()) return "prolog-outside-function";
    auto frameRegister = parsed.frame & 15;
    if ((!frameRegister && parsed.frame) || (frameRegister && !nonvolatile(frameRegister))) return "invalid-frame-register";

    parsed.boundaries[0] = true;
    for (size_t cursor = 0, limit = info[1] ? info[1] : zeroPrologLength; cursor < limit;) {
        auto length = InstructionDecoder::length(code.data() + cursor, limit - cursor);
        if (!length) return "invalid-prolog-instruction";
        cursor += length;
        parsed.boundaries[cursor] = true;
    }
    unsigned previous = 256, frameOperations = 0;
    for (unsigned index = 0; index < slots;) {
        auto bytes = info.data() + 4 + index * 2;
        unsigned offset = bytes[0], operation = bytes[1] & 15, detail = bytes[1] >> 4, width = 1;
        switch (operation) {
            case 0:
                if (!nonvolatile(detail)) return "invalid-push-register";
                break;
            case 1:
                if (detail > 1) return "invalid-alloc-large";
                width = detail ? 3 : 2;
                break;
            case 2:
                break;
            case 3:
                // SET_FPREG uses the header register/offset. MASM also emits
                // that register in the unused OpInfo nibble (0x53 for RBP).
                if (!frameRegister || ++frameOperations != 1) return "invalid-frame-operation";
                break;
            case 4: case 5:
                if (!body && !nonvolatile(detail)) return "invalid-save-register";
                width = operation == 5 ? 3 : 2;
                break;
            case 8: case 9:
                if (detail < 6) return "invalid-xmm-register";
                width = operation == 9 ? 3 : 2;
                break;
            default:
                return "unsupported-unwind-operation";
        }
        if (width > static_cast<unsigned>(slots) - index) return "truncated-unwind-operation";
        // Chained rows describe saves made before their first instruction
        // with CodeOffset 0.
        if ((!offset && !(parsed.flags & 4)) || offset > previous || offset > info[1] || !parsed.boundaries[offset])
            return "malformed-unwind-codes";
        // Secondary grouped-save prologs enter with the primary fixed frame
        // already established; pushes, allocations and new frame anchors are
        // outside that PE contract and require a separate state proof.
        if ((parsed.flags & 4) && operation <= 3) return "chained-prolog-state-needs-proof";
        // Three-slot PE values are unsigned and unscaled; two-slot values are
        // scaled. Preserve their bytes instead of adding them to a live RSP.
        // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
        if (operation == 1) {
            auto amount = littleEndian(bytes + 2, (width - 1) * 2);
            if (!amount) return "invalid-alloc-large";
            if (width == 3 && (amount & 7)) return "unaligned-stack-allocation";
        } else if ((operation == 5 && (littleEndian(bytes + 2, 4) & 7))
                || (operation == 9 && (littleEndian(bytes + 2, 4) & 15))) return "unaligned-save-offset";
        previous = offset;
        parsed.groups[parsed.count++] = {offset, index, width, operation};
        index += width;
    }
    if (frameRegister && !frameOperations && !(parsed.flags & 4)) return "missing-frame-operation";
    result = std::move(parsed);
    return nullptr;
}
bool append(const Parsed& parsed, size_t completed, std::vector<unsigned char>& bytes) {
    for (size_t index = 0; index < parsed.count; ++index) {
        const auto& group = parsed.groups[index];
        if (group.offset > completed) continue;
        if (group.slots > 255u - bytes[2]) return false;
        auto code = parsed.unwind.subspan(4 + group.index * 2, group.slots * 2);
        auto start = bytes.size();
        bytes.insert(bytes.end(), code.begin(), code.end());
        bytes[start] = 0;
        bytes[2] += static_cast<unsigned char>(group.slots);
        if (group.operation == 3) bytes[3] = static_cast<unsigned char>(parsed.frame);
    }
    return true;
}
}

const char* derive(const Source& source, const InstructionDecoder::Relocation& relocation, Recipe& result) {
    // Check instruction arithmetic before adding the two source offsets.
    if (source.code.size() > UINT32_MAX || source.probeOffset >= source.code.size()
            || !relocation.sourceBytes || relocation.sourceBytes > InstructionDecoder::MAX_INSTRUCTION_BYTES
            || relocation.sourceBytes > source.code.size() - source.probeOffset
            || !relocation.destinationBytes || relocation.destinationBytes > InstructionDecoder::MAX_RELOCATED_BYTES)
        return "instruction-range";
    auto end = source.probeOffset + relocation.sourceBytes;
    Parsed parsed;
    if (auto error = parse(source.code, source.unwind, source.probeOffset == 0 ? end : 0, parsed)) return error;
    if (source.unwind[1] ? end > source.unwind[1] : source.probeOffset != 0) return "body-state-needs-proof";
    // A zero-prolog chained segment can begin in an outlined epilog. Its first
    // instruction may restore RSP without an unwind operation at this site.
    if ((parsed.flags & 4) && !source.unwind[1]) return "chained-body-state-needs-proof";
    if (!parsed.boundaries[source.probeOffset] || !parsed.boundaries[end]) return "probe-inside-instruction";
    if (InstructionDecoder::length(source.code.data() + source.probeOffset, source.code.size() - source.probeOffset) != relocation.sourceBytes)
        return "relocation-length-mismatch";
    if (relocation.branchTarget || controlTransfer(source.code.subspan(source.probeOffset, relocation.sourceBytes)))
        return "control-transfer-needs-proof";
    if (!(parsed.flags & 4) && !source.chain.empty()) return "unexpected-unwind-chain";

    std::vector<std::uint32_t> identities;
    identities.reserve(source.chain.size());
    for (const auto& entry : source.chain) {
        if (entry.unwind.data() == source.unwind.data()) return "cyclic-unwind-chain";
        identities.push_back(entry.unwindRva);
    }
    std::sort(identities.begin(), identities.end());
    if (std::adjacent_find(identities.begin(), identities.end()) != identities.end()) return "cyclic-unwind-chain";

    Recipe prepared{{2,0,0,0},{2,0,0,0},parsed.version};
    auto frame = parsed.frame;
    if (!append(parsed, source.probeOffset, prepared.before) || !append(parsed, end, prepared.after)) return "flattened-unwind-too-large";
    size_t consumed = 0;
    while (parsed.flags & 4) {
        if (consumed == source.chain.size()) return "unresolved-unwind-chain";
        const auto& entry = source.chain[consumed++];
        auto trailer = parsed.unwind.data() + parsed.padded;
        if (entry.begin != littleEndian(trailer,4) || entry.end != littleEndian(trailer + 4,4)
                || entry.unwindRva != littleEndian(trailer + 8,4)) return "chained-entry-mismatch";
        if (entry.begin >= entry.end || entry.code.size() != static_cast<size_t>(entry.end - entry.begin)
                || (entry.unwindRva & 3)) return "chained-function-range";
        if (auto error = parse(entry.code, entry.unwind, 0, parsed)) return error;
        if (parsed.frame != frame) return "chained-frame-layout-mismatch";
        // Native unwinding applies the selected child's operations first,
        // followed by every parent record in immediate-parent-first order.
        if (!append(parsed,255,prepared.before) || !append(parsed,255,prepared.after)) return "flattened-unwind-too-large";
    }
    if (consumed != source.chain.size()) return "unexpected-unwind-chain";
    for (auto bytes : {&prepared.before,&prepared.after}) while (bytes->size() % 4) bytes->push_back(0);
    result = std::move(prepared);
    return nullptr;
}
const char* validateBoundary(const Source& source, size_t requestedOffset) {
    Parsed parsed;
    if (auto error = parse(source.code,source.unwind,0,parsed)) return error;
    if (requestedOffset >= source.code.size()
            || (source.unwind[1] ? requestedOffset >= source.unwind[1] : requestedOffset != 0))
        return "body-state-needs-proof";
    return parsed.boundaries[requestedOffset] ? nullptr : "probe-inside-instruction";
}
const char* certifyInstruction(const Source& source, const InstructionDecoder::Relocation& relocation, Recipe& result) {
    Recipe prepared;
    if (auto error = derive(source,relocation,prepared)) return error;
    if (!source.chain.empty() || (source.unwind[0] >> 3)) return "execution-needs-unchained-unwind";
    if (relocation.destinationBytes != relocation.sourceBytes) return "execution-relocation-needs-proof";
    auto end = source.probeOffset + relocation.sourceBytes;
    Parsed parsed;
    if (auto error = parse(source.code,source.unwind,source.probeOffset == 0 ? end : 0,parsed)) return error;
    auto effect = SoftwareSites::entryInstructionEffect(source.code.subspan(source.probeOffset,relocation.sourceBytes));
    const Group* added = nullptr;
    unsigned additions = 0;
    for (size_t index = 0; index < parsed.count; ++index) {
        const auto& group = parsed.groups[index];
        if (group.offset > source.probeOffset && group.offset <= end) { added = &group; ++additions; }
    }
    auto anchor = prepared.before[3] & 15;
    if (effect.kind == SoftwareSites::EntryEffectKind::Push) {
        if (additions != 1 || added->operation != 0
                || (parsed.unwind[4 + added->index * 2 + 1] >> 4) != effect.destination) return "instruction-push-mismatch";
    } else if (effect.kind == SoftwareSites::EntryEffectKind::Allocate) {
        if (additions != 1 || (added->operation != 1 && added->operation != 2))
            return "instruction-allocation-mismatch";
        auto bytes = parsed.unwind.data() + 4 + added->index * 2;
        auto amount = added->operation == 2 ? static_cast<unsigned>((bytes[1] >> 4) * 8 + 8)
            : littleEndian(bytes + 2,(added->slots - 1) * 2) * (added->slots == 2 ? 8 : 1);
        if (amount != effect.allocation) return "instruction-allocation-mismatch";
    } else if (effect.kind == SoftwareSites::EntryEffectKind::Move && additions == 1 && added->operation == 3) {
        if (!effect.width64 || effect.source != 4 || effect.destination != (parsed.frame & 15)
                || (parsed.frame >> 4) || anchor) return "instruction-frame-mismatch";
    } else {
        if (effect.kind != SoftwareSites::EntryEffectKind::Neutral && effect.kind != SoftwareSites::EntryEffectKind::Move)
            return "instruction-execution-needs-proof";
        if (prepared.before != prepared.after) return "instruction-unwind-mismatch";
        if (anchor && effect.destination == anchor) return "instruction-clobbers-frame-register";
    }
    result = std::move(prepared);
    return nullptr;
}
const char* bodyState(const Source& source, bool handlers, BodyState& result, size_t offset) {
    if (source.code.size() > UINT32_MAX) return "function-range";
    Parsed parsed;
    if (auto error = parse(source.code, source.unwind, 0, parsed, true)) return error;
    if (!handlers && (parsed.flags & 3)) return "language-handler-needs-forwarding";
    if (!(parsed.flags & 4) && !source.chain.empty()) return "unexpected-unwind-chain";
    BodyState prepared;
    prepared.prolog = source.unwind[1];
    prepared.recipe = {static_cast<unsigned char>(parsed.version), 0, 0, 0};
    auto frame = parsed.frame;
    struct Operation { unsigned operation, detail; std::uint32_t amount; };
    std::vector<Operation> operations;
    auto completed = offset;
    auto collect = [&](const Parsed& current) {
        for (size_t index = 0; index < current.count; ++index) {
            const auto& group = current.groups[index];
            if (group.offset > completed) continue;
            auto bytes = current.unwind.data() + 4 + group.index * 2;
            std::uint32_t amount = 0;
            if (group.operation == 2) amount = (bytes[1] >> 4) * 8u + 8;
            else if (group.operation == 1)
                amount = littleEndian(bytes + 2, (group.slots - 1) * 2) * (group.slots == 2 ? 8 : 1);
            operations.push_back({group.operation, static_cast<unsigned>(bytes[1] >> 4), amount});
        }
        return append(current, completed, prepared.recipe);
    };
    if (!collect(parsed)) return "flattened-unwind-too-large";
    // Parent rows always apply completely.
    completed = 255;
    size_t consumed = 0;
    while (parsed.flags & 4) {
        if (consumed == source.chain.size()) return "unresolved-unwind-chain";
        const auto& entry = source.chain[consumed++];
        auto trailer = parsed.unwind.data() + parsed.padded;
        if (entry.begin != littleEndian(trailer,4) || entry.end != littleEndian(trailer + 4,4)
                || entry.unwindRva != littleEndian(trailer + 8,4)) return "chained-entry-mismatch";
        if (entry.begin >= entry.end || entry.code.size() != static_cast<size_t>(entry.end - entry.begin)
                || (entry.unwindRva & 3)) return "chained-function-range";
        if (auto error = parse(entry.code, entry.unwind, 0, parsed, true)) return error;
        if (!handlers && (parsed.flags & 3)) return "language-handler-needs-forwarding";
        if (parsed.frame != frame) return "chained-frame-layout-mismatch";
        if (!collect(parsed)) return "flattened-unwind-too-large";
    }
    if (consumed != source.chain.size()) return "unexpected-unwind-chain";
    while (prepared.recipe.size() % 4) prepared.recipe.push_back(0);
    // Unwind order lists the newest operation first; replay the prolog.
    bool allocated = false;
    for (auto operation = operations.rbegin(); operation != operations.rend(); ++operation) {
        if (operation->operation == 0) {
            if (allocated) prepared.pushesFirst = false;
            prepared.size += 8;
            prepared.pushes.push_back(static_cast<unsigned char>(operation->detail));
        } else if (operation->operation == 1 || operation->operation == 2) {
            prepared.size += operation->amount;
            allocated = true;
        } else if (operation->operation == 3) {
            prepared.frameRegister = frame & 15;
            prepared.frameSize = prepared.size - 16 * static_cast<std::uint64_t>(frame >> 4);
            if (16 * static_cast<std::uint64_t>(frame >> 4) > prepared.size) return "frame-offset-exceeds-frame";
        }
    }
    result = std::move(prepared);
    return nullptr;
}
}
