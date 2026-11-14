/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsInstructionDecoder.h"
#include <cstdint>
#include <span>
#include <vector>

namespace WindowsProfiler::NativeUnwind {
struct ChainEntry {
    // Identity must match the child's embedded RUNTIME_FUNCTION exactly.
    // Code covers [begin,end); unwind starts at the supplied image-relative RVA.
    std::uint32_t begin, end, unwindRva;
    std::span<const unsigned char> code, unwind;
};
struct Source {
    // These are stable, readable snapshots of one native function and its
    // original PE UNWIND_INFO. The caller validates the containing PE mapping.
    std::span<const unsigned char> code, unwind;
    size_t probeOffset = 0;
    // Resolved parents in immediate-parent-first order. The caller validates
    // their PE mapping/bounds and keeps these snapshots stable with the source.
    std::span<const ChainEntry> chain{};
};
struct Recipe {
    // Each record describes a body range with SizeOfProlog zero. The first
    // covers the copied instruction and the second its following continuation.
    std::vector<unsigned char> before, after;
    unsigned sourceVersion = 0;
};
// Cold preparation only: no executable bytes or function tables are changed.
// Relocation must describe this exact source instruction. Original handlers,
// unresolved chains, epilog records and unproved operations/control transfers
// are rejected. Chained source prologs may add register saves to a complete
// parent state; stack/frame mutations and zero-prolog chained entries need a
// separate state proof. Flattened metadata must fit PE's 255-code-slot limit.
// Only original prolog instructions and zero-prolog entry instructions are
// supported; arbitrary body/epilog sites need a separate state proof.
// On failure the output is unchanged and the returned diagnostic is static.
const char* derive(const Source& source, const InstructionDecoder::Relocation& relocation, Recipe& result);
// Validate the requested boundary before any ENDBR normalization. Nonzero
// offsets require an original prologue; its end is already a body boundary.
const char* validateBoundary(const Source& source, size_t requestedOffset);
// Execution certification is separate from cold preparation. Selected neutral
// instructions preserve the entire recipe; stack/frame changes must match the
// exact newly completed unwind operation. On failure result is unchanged.
const char* certifyInstruction(const Source& source, const InstructionDecoder::Relocation& relocation, Recipe& result);
struct BodyState {
    // Every operation of the source and its parents with zero code offsets,
    // under the source's own UNWIND_INFO version and frame byte.
    std::vector<unsigned char> recipe;
    // Pushed registers in prolog order and entry-relative RSP/frame depths.
    std::vector<unsigned char> pushes;
    std::uint64_t size = 0, frameSize = 0;
    unsigned frameRegister = 0, prolog = 0;
    // An epilogue can only restore pushes made before every allocation.
    bool pushesFirst = true;
};
// State at a code offset of the source: its own operations whose CodeOffset
// does not exceed offset, then every parent operation. Language handlers are
// accepted only when requested; their routines are not represented.
const char* bodyState(const Source& source, bool handlers, BodyState& result, size_t offset = 255);
}
