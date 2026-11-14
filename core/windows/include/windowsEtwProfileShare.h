/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsEtwSession.h"
#include <cstdint>
#include <vector>

namespace WindowsProfiler::Etw {
// Each source's sampled-profile interval and the PMC overflow-source selection
// are machine-wide. Timer captures share source 0's interval; PMC captures share
// the selected source and its interval. Concurrent captures of one source may
// request different intervals: the source runs at the finest requested one and
// each capture decimates to its own. The first owner saves the previous interval;
// the last owner leaving, or the watcher of a terminated one, restores it.
//
// The registry lives in a private namespace whose boundary requires the
// Administrators SID and High integrity, so ordinary processes can neither create
// nor open it. An owner record is removed by others only when its process ID and
// creation time prove the process gone.
enum class ShareConflictKind : ULONG { None, Source, ExternalTimer, ExternalPmc };
struct ShareConflict {
    ShareConflictKind kind = ShareConflictKind::None;
    ULONG pid = 0, source = 0, interval = 0, raw = 0, reserved = 0;
    std::uint64_t rawConfig = 0;
};
static_assert(sizeof(ShareConflict) == 32);
// The source runs at interval from QPC time qpc onwards.
struct IntervalChange { std::uint64_t qpc; ULONG interval, reserved; };
static_assert(sizeof(IntervalChange) == 16);
// Private broker record carrying an IntervalChange to an unprivileged target.
constexpr GUID intervalChangeProvider = {0x5d0bd3a1, 0x7f86, 0x4e3c, {0x9a, 0x51, 0x2e, 0xc4, 0x8b, 0x6d, 0x13, 0x97}};
struct ShareRequest {
    ULONG source = 0;  // Raw sources are assigned at registration.
    ULONG interval = 0;  // Source units: 100 ns for the timer, events otherwise.
    ULONG targetPid = 0;
    bool explicitInterval = false;
    bool raw = false;
    RawPmuConfig rawConfig{};
};
struct ShareGrant {
    // interval is the source's at joining; requested is this capture's own.
    ULONG source = 0, interval = 0, requested = 0, minimum = 0, maximum = 0;
    // Changes from this position onwards are returned by sync.
    std::uint64_t position = 0;
    ShareConflict conflict{};
};
class ProfileShare {
    struct Registry;
    HANDLE _namespace = nullptr, _lock = nullptr, _section = nullptr;
    Registry* _registry = nullptr;
public:
    ProfileShare() = default;
    ProfileShare(const ProfileShare&) = delete;
    ProfileShare& operator=(const ProfileShare&) = delete;
    ~ProfileShare() { close(); }
    ULONG open();
    // The watcher's inherited handles. Every participant holds the namespace,
    // which exists only while one of them does.
    ULONG attach(HANDLE space, HANDLE lock, HANDLE section);
    void close();
    HANDLE space() const { return _namespace; }
    HANDLE lock() const { return _lock; }
    HANDLE section() const { return _section; }
    // ERROR_BUSY with grant.conflict for an incompatible configuration.
    ULONG join(WatchState& state, const ShareRequest& request, ShareGrant& grant);
    // Called after the owner's session has stopped; repeated calls are harmless.
    ULONG release(WatchState& state);
    // Appends the slot's changes after position. Changes made later take effect
    // after horizon, a QPC time read once these were complete.
    ULONG sync(ULONG slot, std::uint64_t& position, std::vector<IntervalChange>& changes, std::uint64_t& horizon) const;
};
}
