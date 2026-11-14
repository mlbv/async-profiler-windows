/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsCompiledHandlers.h"
#include <algorithm>
#include <climits>
#include <cstring>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace WindowsProfiler::JavaUnwind::Compiled::Handlers {
namespace {
std::int32_t integer(std::span<const unsigned char> bytes, size_t offset) {
    std::int32_t value;
    std::memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}
}
ImplicitExceptionProof proveNoImplicitExceptions(std::span<const unsigned char> bytes,bool exactEnd) {
    if (bytes.empty()) return ImplicitExceptionProof::EmptyByExtent;
    if (exactEnd || bytes.size() < sizeof(std::uint32_t)) return ImplicitExceptionProof::Unproved;
    std::uint32_t count;
    std::memcpy(&count,bytes.data(),sizeof(count));
    // HotSpot's reader sets length to zero for a zero-sized table, otherwise
    // it reads this word. Both cases therefore have no entries when it is zero.
    return count == 0 ? ImplicitExceptionProof::EmptyByZeroProbe : ImplicitExceptionProof::Unproved;
}
const char* parse(const Source& source, Snapshot& result) {
    if (source.version != 8 && source.version != 11 && source.version != 17 && source.version != 21
            && source.version != 25 && source.version != 26 && source.version != 27)
        return "unsupported-handler-metadata-version";
    if (!source.singleEntry) return "secondary-unwind-entry-unsupported";
    if (!source.address || source.code.empty() || source.code.size() > INT_MAX
            || source.code.size() > UINTPTR_MAX - source.address || source.entry >= source.code.size()
            || (source.unverifiedEntry && *source.unverifiedEntry >= source.entry)
            || (source.allocation & 7)) return "handler-code-bounds";
    std::vector<FaultEdge> faults;
    auto implicit = source.exactImplicitExceptions;
    if (implicit.empty()) {
        if (source.implicitExceptionProof != ImplicitExceptionProof::EmptyByExtent
                && source.implicitExceptionProof != ImplicitExceptionProof::EmptyByZeroProbe)
            return "implicit-exception-edges-unsupported";
    } else {
        if (source.implicitExceptionProof != ImplicitExceptionProof::Unproved)
            return "contradictory-implicit-exception-proof";
        if (implicit.size() < sizeof(std::uint32_t)) return "invalid-implicit-table-size";
        auto count = static_cast<std::uint32_t>(integer(implicit,0));
        if (!count || count > (implicit.size() - 4) / 8) return "invalid-implicit-table-size";
        auto payload = size_t{4} + size_t{8} * count;
        if (implicit.size() != ((payload + 7) & ~size_t{7})) return "invalid-implicit-table-size";
        std::set<std::uint32_t> faultSources;
        for (std::uint32_t index = 0; index < count; ++index) {
            auto offset = size_t{4} + size_t{8} * index;
            auto pc = static_cast<std::uint32_t>(integer(implicit,offset));
            auto target = static_cast<std::uint32_t>(integer(implicit,offset + 4));
            if (pc >= source.code.size() || !target || target >= source.code.size())
                return "invalid-implicit-table-entry";
            if (pc == target) return "implicit-deoptimization-unsupported";
            if (!faultSources.insert(pc).second) return "duplicate-implicit-fault-source";
            faults.push_back({pc,target});
        }
    }
    const auto& layout = source.pcDesc;
    if (layout.size < 8 || layout.size > 256 || layout.pc > layout.size - 4 || layout.flags > layout.size - 4
            || (layout.pc < layout.flags + 4 && layout.flags < layout.pc + 4)
            || source.descriptors.size() % layout.size) return "invalid-pcdesc-layout";
    std::map<std::uint32_t, std::uint32_t> flags;
    std::int32_t previous = -1, upper = -1;
    auto count = source.descriptors.size() / layout.size;
    if (count < 2) return "missing-pcdesc-sentinels";
    // JDK26 removed is_method_handle_invoke (bit 1) and renumbered later flags.
    auto supportedFlags = source.version <= 11 ? 0x0f : source.version <= 25 ? 0x3f : 0x1f;
    auto methodHandleFlag = source.version <= 25 ? 2 : 0;
    for (size_t index = 0; index < count; ++index) {
        auto offset = index * layout.size;
        auto pc = integer(source.descriptors, offset + layout.pc);
        auto bits = integer(source.descriptors, offset + layout.flags);
        // JVMCI8 and JDK11 include rethrow_exception; optimized native
        // returns and unknown flag meanings remain outside this proof.
        if (bits < 0 || (bits & ~supportedFlags)) return "unsupported-pcdesc-flags";
        if (bits & methodHandleFlag) return "method-handle-return-unsupported";
        if (index == 0) {
            if (pc != -1) return "missing-pcdesc-sentinels";
        } else if (pc > static_cast<std::int32_t>(source.code.size())) {
            if (upper != -1 && pc != upper) return "invalid-pcdesc-sentinel";
            upper = pc;
        } else {
            if (upper != -1 || pc <= previous || pc < 0) return "unordered-pcdesc-offsets";
            flags.emplace(static_cast<std::uint32_t>(pc), static_cast<std::uint32_t>(bits));
        }
        previous = pc;
    }
    if (upper == -1) return "missing-pcdesc-sentinels";
    if (source.table.size() % 8) return "misaligned-handler-table";
    std::vector<HandlerEdge> edges;
    std::set<std::uint32_t> sources;
    size_t cursor = 0;
    while (source.table.size() - cursor >= 12) {
        auto length = integer(source.table, cursor);
        auto pc = integer(source.table, cursor + 4);
        auto scope = integer(source.table, cursor + 8);
        cursor += 12;
        if (length <= 0 || static_cast<size_t>(length) > (source.table.size() - cursor) / 12
                || pc <= 0 || static_cast<size_t>(pc) >= source.code.size() || scope != 0)
            return "invalid-handler-subtable";
        if (!sources.insert(static_cast<std::uint32_t>(pc)).second) return "duplicate-handler-subtable";
        std::set<std::pair<std::int32_t,std::int32_t>> handlers;
        for (std::int32_t index = 0; index < length; ++index, cursor += 12) {
            auto bci = integer(source.table, cursor);
            auto target = integer(source.table, cursor + 4);
            auto depth = integer(source.table, cursor + 8);
            if (bci < -1 || target < 0 || static_cast<size_t>(target) >= source.code.size() || depth < 0)
                return "invalid-handler-entry";
            if (!handlers.emplace(bci, depth).second) return "duplicate-handler-entry";
            edges.push_back({static_cast<std::uint32_t>(pc), static_cast<std::uint32_t>(target),
                flags.contains(static_cast<std::uint32_t>(pc))});
        }
    }
    // ExceptionHandlerTable rounds its 12-byte records up to oop alignment;
    // the final four padding bytes are not an additional record.
    if (source.table.size() - cursor != (cursor % 8 ? 4u : 0u)) return "truncated-handler-table";
    Snapshot prepared;
    prepared._address = source.address; prepared._entry = source.entry; prepared._allocation = source.allocation;
    prepared._unverifiedEntry = source.unverifiedEntry;
    prepared._code.assign(source.code.begin(), source.code.end()); prepared._edges = std::move(edges);
    prepared._faults = std::move(faults);
    result = std::move(prepared);
    return nullptr;
}
}
