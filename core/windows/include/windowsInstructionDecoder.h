/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstddef>

namespace WindowsProfiler::InstructionDecoder {
constexpr size_t MAX_INSTRUCTION_BYTES = 15;
constexpr size_t MAX_RELOCATED_BYTES = 32;
void initialize() noexcept;
// Source must remain readable and stable for the supplied bound. Unsupported
// instructions, truncation and overlong prefix sequences return zero. Length
// is independent of whether a relative target can reach a new destination.
size_t length(const void* source, size_t readable) noexcept;

struct Relocation {
    size_t sourceBytes = 0, destinationBytes = 0;
    const void* branchTarget = nullptr;
    // Destination offsets where the source instruction has completed: on its
    // fall-through path, and at the jump that ends its taken path (zero when
    // the relocated branch reaches its target itself).
    size_t completed = 0, taken = 0;
};
// Destination is a separate writable staging buffer; executable source is
// never changed. Failure must be handled before installing any code patch.
// Unrepresentable displacements and widening beyond 15 bytes are rejected.
// The relocated code falls through at destinationBytes. LOOPcc and JRCXZ have
// only rel8 forms: the unchanged instruction branches over a short jump to the
// end onto a rel32 jump to its target. XBEGIN keeps its form with a rebased
// abort target. Operand-size prefixed forms of both reject, since they can
// truncate the target to 16 bits.
bool relocate(void* destination, size_t capacity, const void* source, size_t readable, Relocation& result) noexcept;
}
