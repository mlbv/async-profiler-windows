/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>
#include <span>
namespace WindowsProfiler::JavaUnwind::Compiled {
struct CodeRange {
    std::uintptr_t begin = 0, end = 0;
    bool contains(std::uintptr_t address) const { return address >= begin && address < end; }
};
struct Layout {
    // The barrier must be the exact VM-generated method-entry stub. Its
    // normal return preserves RBP; arbitrary calls receive no such promise.
    std::uintptr_t address, barrier;
    std::size_t entry;
    std::uint32_t allocation;
    bool handlersEmpty, singleEntry;
    // Exact VM DeoptimizationBlob and UncommonTrapBlob code. A call into them
    // deoptimizes its caller and never returns to the call site.
    CodeRange deoptimization{}, uncommonTrap{};
    // Inline-cache entry before the verified entry; it is entered with the
    // same frame state and either leaves the method or reaches the verified entry.
    std::optional<std::size_t> unverifiedEntry{};
};
// Sources are exact return-PC offsets; callReturn excludes method-handle
// adapters and entries without a corresponding exported PcDesc.
struct HandlerEdge { std::uint32_t source,target; bool callReturn; };
// Sources are faulting instruction starts, distinct from handler call returns.
// Only certified precise reads/divides preserve their input frame on this edge.
struct FaultEdge { std::uint32_t source,target; };
struct Span { std::uint32_t begin,end,returnOffset; std::int32_t fpOffset; bool proven; };
// Handler/entry prerequisites come from exported VM metadata. Unknown
// instructions and overlapping instruction targets do not produce a proof.
// Optional reachable output lists sorted instruction starts, including reached
// states without frame proof. Omitting exceptional edges gives ordinary-entry
// reachability. Both outputs remain unchanged on failure.
bool analyse(const unsigned char* code,std::size_t size,const Layout& layout,std::vector<Span>& result,
             std::span<const HandlerEdge> handlers = {}, std::span<const FaultEdge> faults = {},
             std::vector<std::uint32_t>* reachable = nullptr);
}
