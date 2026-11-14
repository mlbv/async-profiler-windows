/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace WindowsProfiler::JavaUnwind::Leaf {
struct Span { std::uint32_t begin, end, returnOffset; };
// Recognize a straight-line leaf path with unchanged caller RBP. Branches may
// only leave that path for slow code beyond its return instruction.
bool preservedRbp(const unsigned char* code, std::size_t size, std::uint32_t allocation, std::vector<Span>& result);
// Return the offset just past the instruction that completes a conventional
// frame from entry: the caller RBP saved directly below the return address and
// allocation bytes reserved, by push rbp/sub rsp or sub rsp/mov [rsp+n],rbp.
// Returns 0 for any other sequence.
std::size_t prologueEnd(const unsigned char* code,std::size_t size,std::size_t entry,std::uint32_t allocation);
// Prove that a conventional prologue saved the caller RBP and allocated the
// stack space described by the VM before its frame-complete marker.
bool savedRbpSlot(const unsigned char* code,std::size_t size,std::size_t entry,std::size_t complete,std::uint32_t allocation);
}
