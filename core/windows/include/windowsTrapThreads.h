/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <cstddef>
#include <cstdint>

namespace WindowsProfiler::TrapThreads {
struct Identity {
    std::uint32_t slot = 0, tid = 0;
    std::uint64_t creation = 0, epoch = 0;
    bool operator==(const Identity&) const = default;
};

// One recording-event counter per thread, shared by all of its sites. The
// recording owner changes eventEpoch; profiling-window changes do not reset it.
struct State {
    std::uint64_t eventEpoch = 0;
    std::uint64_t remainder = 0;
};

class Lease;
Lease current() noexcept;
Lease pin(const Identity& identity) noexcept;

class Lease {
    friend Lease current() noexcept;
    friend Lease pin(const Identity&) noexcept;
    void* _slot = nullptr;
    bool _entered = false;
    explicit Lease(void* slot) noexcept : _slot(slot) {}
public:
    Lease() noexcept = default;
    Lease(const Lease&) = delete;
    Lease& operator=(const Lease&) = delete;
    Lease(Lease&& other) noexcept;
    Lease& operator=(Lease&& other) noexcept;
    ~Lease();
    explicit operator bool() const noexcept { return _slot != nullptr; }
    Identity identity() const noexcept;
    bool internal() const noexcept;
    // Callers mutate event state only while owning a successful tryEnter guard.
    State& state() const noexcept;
    // Reentrant users retain their pin, but do not own the mutation guard.
    // Internal-thread classification is separate so rescue can still enter.
    bool tryEnter() noexcept;
    void reset() noexcept;
};

// Cold enrollment only. The handle must identify a thread in this process.
// It is borrowed; successful preparation retains its own sampling-safe handle.
// Repeated enrollment preserves the live birth's state and identity.
const char* prepare(HANDLE thread, Identity* identity = nullptr) noexcept;
// Cold cleanup only: exited, unpinned records become tombstones. Live or pinned
// state survives stop/reset for rescue; recording eligibility belongs to owner.
std::size_t reapExited();
}
