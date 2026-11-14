/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsCompiledUnwind.h"
#include <optional>
#include <span>

namespace WindowsProfiler::JavaUnwind::Compiled::Handlers {
struct PcDescFields {
    size_t size = 0, pc = 0, flags = 0;
};
enum class ImplicitExceptionProof { Unproved, EmptyByExtent, EmptyByZeroProbe };
// bytes starts at the typed implicit-table offset and ends at a validated
// upper bound, or at the exact endpoint when exactEnd is true. A zero probe
// rules out positive entries without claiming that an empty table has a header.
ImplicitExceptionProof proveNoImplicitExceptions(std::span<const unsigned char> bytes,bool exactEnd);
struct Source {
    unsigned version = 0;
    std::uintptr_t address = 0;
    size_t entry = 0;
    std::uint32_t allocation = 0;
    bool singleEntry = false;
    PcDescFields pcDesc;
    std::span<const unsigned char> code, table, descriptors;
    ImplicitExceptionProof implicitExceptionProof = ImplicitExceptionProof::Unproved;
    // A nonempty span is a typed exact table extent, including its alignment padding.
    std::span<const unsigned char> exactImplicitExceptions = {};
    // Inline-cache entry preceding the verified entry, with the same frame state.
    std::optional<size_t> unverifiedEntry = {};
};
class Snapshot {
    std::uintptr_t _address = 0;
    size_t _entry = 0;
    std::optional<size_t> _unverifiedEntry;
    std::uint32_t _allocation = 0;
    std::vector<unsigned char> _code;
    std::vector<HandlerEdge> _edges;
    std::vector<FaultEdge> _faults;
    friend const char* parse(const Source&, Snapshot&);
public:
    std::uintptr_t address() const { return _address; }
    size_t entry() const { return _entry; }
    std::optional<size_t> unverifiedEntry() const { return _unverifiedEntry; }
    std::uint32_t allocation() const { return _allocation; }
    std::span<const unsigned char> code() const { return _code; }
    std::span<const HandlerEdge> edges() const { return _edges; }
    std::span<const FaultEdge> faults() const { return _faults; }
};
// Cold-only parser. Source spans are stable snapshots already bounded against
// one supported nmethod layout. The result owns all code and edges, and can
// outlive source metadata. Failure leaves result unchanged.
// callReturn certifies an exact non-method-handle PcDesc at the source offset;
// the control-flow analyser must still match that offset to an actual call's
// return PC and prove its frame state. Missing PcDescs retain unknown edges.
// Fault offsets identify instruction starts. Metadata alone does not certify
// instruction effects; the analyser must prove each source's fault semantics.
// Secondary entries other than the inline-cache entry, method-handle returns
// and implicit deoptimization markers remain unsupported.
const char* parse(const Source& source, Snapshot& result);
}
