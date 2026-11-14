/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsEtwBroker.h"
#include <map>
#include <set>

namespace WindowsProfiler::Etw::Broker {
class ProfileRouter {
public:
    // Replay first, then second.
    struct Output { std::vector<unsigned char> first, second; };
    void configure(ULONG pid, bool stacks, size_t limit = 65536) { _pid = pid; _stacks = stacks; _limit = limit; }
    // Use a fresh router per capture. stacks controls forwarding only; switch
    // ownership is proven from stacks even when forwarding is disabled.
    void configureSoftware(ULONG pid, bool stacks, SoftwareKind kind, size_t limit = 65536) {
        configure(pid, stacks, limit); _software = kind;
    }
    ULONG route(ProfileView& value, bool targetHint, Output& output);
    void finish(Result& result);
    RouterDiagnostics softwareDiagnostics() const { return _softwareDiagnostics; }
private:
    struct Key {
        std::uint64_t time; ULONG tid;
        bool operator<(const Key& other) const { return time < other.time || (time == other.time && tid < other.tid); }
    };
    struct Pending { std::vector<unsigned char> bytes; bool hint; };
    ULONG _pid = 0;
    bool _stacks = true;
    size_t _limit = 65536;
    std::map<Key, ULONG> _proof;
    std::map<Key, Pending> _pending;
    std::uint64_t _foreign = 0, _unattributed = 0, _potential = 0;
    void discard(const Pending& value) { if (value.hint) ++_potential; else ++_unattributed; }
    void normalize(std::vector<unsigned char>& bytes);

    // A switched-out thread does not run until its next switch-in, whose
    // StackWalk is therefore its stack at the switch-out and names its process.
    struct Switch { std::uint64_t out = 0, in = 0; USHORT cpu = 0; bool switchedIn = false; };
    SoftwareKind _software = SoftwareKind::None;
    std::map<ULONG, Switch> _switches;
    // Target threads that logged their end; their later events are not counted.
    // The terminated switch-out or a new start of the TID ends the entry.
    std::set<ULONG> _exiting;
    // Same-tick CSwitch events from different processors have no reliable
    // order, but a thread's switch-out precedes its switch-in.
    std::uint64_t _switchTime = 0;
    std::vector<std::pair<ULONG, std::uint64_t>> _switchIns;
    RouterDiagnostics _softwareDiagnostics;
    ULONG softwareFailure(RouterFailure failure, ULONG error) {
        if (_softwareDiagnostics.reason == RouterFailure::None) _softwareDiagnostics.reason = failure;
        return error;
    }
    ULONG routeSoftware(ProfileView& value, Output& output);
    ULONG routeSwitch(const ProfileView& value);
    ULONG routeLifecycle(const ProfileView& value);
    void applySwitchIns();
};
}
