/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwProfileRouter.h"
#include <algorithm>
#include <cstring>

namespace WindowsProfiler::Etw::Broker {
void ProfileRouter::normalize(std::vector<unsigned char>& bytes) {
    Event value; std::memcpy(&value, bytes.data(), sizeof(value));
    value.header.ProcessId = _pid;
    std::memcpy(bytes.data(), &value, sizeof(value));
}
ULONG ProfileRouter::route(ProfileView& value, bool targetHint, Output& output) try {
    output = {};
    if (_software != SoftwareKind::None) return routeSoftware(value, output);
    Key key{value.time, value.tid};
    switch (value.kind) {
        case ProfileKind::Ignore: return ERROR_SUCCESS;
        case ProfileKind::ForeignSample: ++_foreign; return ERROR_SUCCESS;
        case ProfileKind::UnattributedSample: ++_unattributed; return ERROR_SUCCESS;
        case ProfileKind::UnknownSample: {
            auto proof = _proof.find(key);
            if (proof != _proof.end()) {
                if (proof->second != 1) { if (proof->second == 2) ++_foreign; else if (targetHint) ++_potential; else ++_unattributed; return ERROR_SUCCESS; }
                value.event.EventHeader.ProcessId = _pid;
                return encodeEvent(value.event, output.first);
            }
            Pending pending; pending.hint = targetHint;
            auto error = encodeEvent(value.event, pending.bytes);
            if (error) return error;
            auto existing = _pending.find(key);
            if (existing != _pending.end()) {
                discard(existing->second); discard(pending); _pending.erase(existing);
                _proof[key] = 0;
                while (_proof.size() > _limit) _proof.erase(_proof.begin());
            } else _pending.emplace(key, std::move(pending));
            while (_pending.size() > _limit) { auto old = _pending.begin(); discard(old->second); _pending.erase(old); }
            return ERROR_SUCCESS;
        }
        case ProfileKind::Stack: {
            if (value.pid == ULONG(-1)) return ERROR_SUCCESS;
            ULONG owner = value.pid == _pid ? 1 : 2;
            auto [proof, inserted] = _proof.emplace(key, owner);
            if (!inserted && proof->second != owner) proof->second = 0;
            auto pending = _pending.find(key);
            if (pending != _pending.end()) {
                if (proof->second == 1) { output.second = std::move(pending->second.bytes); normalize(output.second); }
                else if (proof->second == 2) ++_foreign;
                else discard(pending->second);
                _pending.erase(pending);
            }
            while (_proof.size() > _limit) _proof.erase(_proof.begin());
            if (value.pid == _pid && _stacks) return encodeEvent(value.event, output.first);
            return ERROR_SUCCESS;
        }
        case ProfileKind::Thread:
            return value.pid == _pid ? encodeEvent(value.event, output.first) : ERROR_SUCCESS;
        case ProfileKind::Sample:
        case ProfileKind::KernelImage:
            return encodeEvent(value.event, output.first);
        case ProfileKind::Switch: break;
    }
    return ERROR_INVALID_DATA;
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
void ProfileRouter::applySwitchIns() {
    for (auto [tid, time] : _switchIns) {
        auto found = _switches.find(tid);
        if (found == _switches.end()) continue;
        // The previous switch-in of this thread never received its StackWalk.
        if (found->second.switchedIn) { ++_softwareDiagnostics.sequenceBreaks; _switches.erase(found); continue; }
        found->second.in = time; found->second.switchedIn = true;
        ++_softwareDiagnostics.switchIns;
    }
    _switchIns.clear();
}
ULONG ProfileRouter::routeSwitch(const ProfileView& value) {
    if (value.time < _switchTime) return softwareFailure(RouterFailure::SwitchTimeReversal, ERROR_INVALID_DATA);
    if (value.time != _switchTime) { applySwitchIns(); _switchTime = value.time; }
    auto& diagnostics = _softwareDiagnostics;
    if (value.tid && value.terminated) {
        ++diagnostics.terminatedSwitches;
        _exiting.erase(value.tid);
    } else if (value.tid && _exiting.contains(value.tid)) {
        ++diagnostics.exitingEvents;
    } else if (value.tid) {
        auto [found, added] = _switches.try_emplace(value.tid);
        // Two switch-outs without a switch-in: the stream lost an event.
        if (!added) ++diagnostics.sequenceBreaks;
        found->second = {value.time, 0, value.cpu, false};
        ++diagnostics.switchOuts;
        diagnostics.switchHighWater = std::max<std::uint64_t>(diagnostics.switchHighWater, _switches.size());
        if (_switches.size() > _limit) return softwareFailure(RouterFailure::SwitchCapacity, ERROR_BUFFER_OVERFLOW);
    }
    if (value.incomingTid) _switchIns.emplace_back(value.incomingTid, value.time);
    return ERROR_SUCCESS;
}
ULONG ProfileRouter::routeLifecycle(const ProfileView& value) {
    auto opcode = value.event.EventHeader.EventDescriptor.Opcode;
    if (opcode == 1) {
        _exiting.erase(value.tid);
        // A new lifetime reuses a TID whose previous owner is gone.
        if (_switches.erase(value.tid)) ++_softwareDiagnostics.sequenceBreaks;
    } else if (opcode == 2 && value.pid == _pid) {
        // The thread logged its end while running, after its last switch-in proof.
        if (_switches.erase(value.tid)) ++_softwareDiagnostics.sequenceBreaks;
        _exiting.insert(value.tid);
        _softwareDiagnostics.exitingHighWater = std::max<std::uint64_t>(_softwareDiagnostics.exitingHighWater, _exiting.size());
        if (_exiting.size() > _limit) return softwareFailure(RouterFailure::ExitCapacity, ERROR_BUFFER_OVERFLOW);
    }
    return ERROR_SUCCESS;
}
ULONG ProfileRouter::routeSoftware(ProfileView& value, Output& output) {
    auto& diagnostics = _softwareDiagnostics;
    if (value.kind == ProfileKind::Switch) return routeSwitch(value);
    applySwitchIns();
    switch (value.kind) {
        case ProfileKind::Ignore: return ERROR_SUCCESS;
        case ProfileKind::ForeignSample: ++_foreign; return ERROR_SUCCESS;
        case ProfileKind::Sample:
            if (_exiting.contains(value.tid)) { ++diagnostics.exitingEvents; return ERROR_SUCCESS; }
            ++diagnostics.samples;
            return encodeEvent(value.event, output.first);
        case ProfileKind::Stack: {
            ++diagnostics.stacks;
            bool target = value.pid == _pid;
            auto found = _software == SoftwareKind::ContextSwitches ? _switches.find(value.tid) : _switches.end();
            if (found != _switches.end() && found->second.switchedIn && found->second.in == value.time) {
                if (target) {
                    ProvenSwitch payload{found->second.in, value.tid, 0};
                    EVENT_RECORD proven{};
                    proven.EventHeader.Size = sizeof(EVENT_HEADER) + sizeof(payload);
                    proven.EventHeader.ProviderId = provenSwitchProvider;
                    proven.EventHeader.TimeStamp.QuadPart = static_cast<LONGLONG>(found->second.out);
                    proven.EventHeader.ProcessId = _pid;
                    proven.BufferContext.ProcessorIndex = found->second.cpu;
                    proven.UserData = &payload; proven.UserDataLength = sizeof(payload);
                    auto error = encodeEvent(proven, output.first);
                    if (error) return error;
                    ++diagnostics.provenTarget;
                } else { ++diagnostics.provenForeign; ++_foreign; }
                _switches.erase(found);
            }
            if (!target) return ERROR_SUCCESS;
            ++diagnostics.targetStacks;
            return _stacks ? encodeEvent(value.event, output.second) : ERROR_SUCCESS;
        }
        case ProfileKind::Thread: {
            auto error = routeLifecycle(value);
            if (error || value.pid != _pid) return error;
            return encodeEvent(value.event, output.first);
        }
        case ProfileKind::KernelImage: return encodeEvent(value.event, output.first);
        default: return ERROR_INVALID_DATA;
    }
}
void ProfileRouter::finish(Result& result) {
    if (_software != SoftwareKind::None) {
        applySwitchIns();
        // Threads still switched out cannot be proven, like undelivered perf signals.
        _softwareDiagnostics.unresolved = _switches.size();
        _switches.clear(); _exiting.clear();
    }
    for (const auto& [key, value] : _pending) discard(value);
    _pending.clear(); _proof.clear();
    result.foreignProfiles = _foreign; result.unattributedProfiles = _unattributed; result.potentialTargetLoss = _potential;
    result.router = _softwareDiagnostics;
}
}
