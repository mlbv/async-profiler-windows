/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstddef>
#include <cstdint>

namespace WindowsProfiler::JavaUnwind::VmStorage {
void initialize();
void reset();
bool acquire(std::uintptr_t base, std::uintptr_t limit, unsigned char*& bytes, size_t& size);
size_t capacity();
// WhiteBoxAPI is enabled but this JVM's WhiteBox has no code-blob allocator.
bool allocatorMissing();
}
