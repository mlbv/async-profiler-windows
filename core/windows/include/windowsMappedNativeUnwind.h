/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsNativeUnwind.h"
#include <windows.h>

namespace WindowsProfiler::NativeUnwind {
inline constexpr size_t MAX_MAPPED_CHAIN = 64;
inline constexpr size_t MAX_MAPPED_SNAPSHOT_BYTES = 4 * 1024 * 1024;

class SourceSnapshot {
    struct Function {
        RUNTIME_FUNCTION identity;
        std::vector<unsigned char> code, unwind;
    };
    std::vector<Function> _functions;
    std::vector<ChainEntry> _chain;
    size_t _probe = 0;
    friend const char* snapshotMapped(HMODULE, ULONG, const RUNTIME_FUNCTION&, DWORD64, size_t, SourceSnapshot&);
public:
    SourceSnapshot() = default;
    SourceSnapshot(const SourceSnapshot&) = delete;
    SourceSnapshot& operator=(const SourceSnapshot&) = delete;
    SourceSnapshot(SourceSnapshot&&) = default;
    SourceSnapshot& operator=(SourceSnapshot&&) = default;
    Source source() const { return {_functions.front().code, _functions.front().unwind, _probe, _chain}; }
};
// Caller retains the selected loaded-module lease throughout this call and
// checks its mapping epoch before/after preparation. All code and metadata are
// copied from that MEM_IMAGE allocation; no loader pathname is reopened.
// The selected row must match the mapped PE exception directory. Parents are
// resolved from embedded image-relative rows in immediate-parent-first order.
// Bounds/permissions, unsupported headers/handlers, cycles and explicit depth/
// byte limits reject before publication. derive still decides prolog eligibility.
// On failure result is unchanged. source() requires a successful snapshot.
const char* snapshotMapped(HMODULE module, ULONG imageSize, const RUNTIME_FUNCTION& function,
    DWORD64 pc, size_t instructionLength, SourceSnapshot& result);

class CoverageSnapshot {
    struct Function {
        RUNTIME_FUNCTION identity;
        std::vector<unsigned char> code, unwind;
    };
    std::vector<Function> _functions;
    std::vector<std::vector<ChainEntry>> _chains;
    std::vector<size_t> _fragments;
    bool _handler = false;
    friend const char* snapshotCoverage(HMODULE, ULONG, const RUNTIME_FUNCTION&, CoverageSnapshot&);
public:
    CoverageSnapshot() = default;
    CoverageSnapshot(const CoverageSnapshot&) = delete;
    CoverageSnapshot& operator=(const CoverageSnapshot&) = delete;
    CoverageSnapshot(CoverageSnapshot&&) = default;
    CoverageSnapshot& operator=(CoverageSnapshot&&) = default;
    // The primary row first, then every row chained to it by address.
    size_t fragments() const { return _fragments.size(); }
    const RUNTIME_FUNCTION& identity(size_t index) const { return _functions[_fragments[index]].identity; }
    Source source(size_t index) const {
        const auto& function = _functions[_fragments[index]];
        return {function.code, function.unwind, 0, _chains[index]};
    }
    bool handler() const { return _handler; }
};
// Same lease, mapping and bounds contract as snapshotMapped. Every directory
// row is resolved to its chain root; a primary language handler is retained
// as a flag, while its routine and data are not copied.
const char* snapshotCoverage(HMODULE module, ULONG imageSize, const RUNTIME_FUNCTION& primary, CoverageSnapshot& result);
}
