/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwProfileShare.h"
#include <sddl.h>
#include <algorithm>
#include <cstring>
#include <cwchar>

namespace WindowsProfiler::Etw {
namespace {
// The suffix versions the layout. Other layouts see these sessions as external profilers.
constexpr WCHAR NAMESPACE[] = L"async-profiler-etw-profile.2";
constexpr WCHAR SECTION_NAME[] = L"async-profiler-etw-profile.2\\registry";
constexpr WCHAR LOCK_NAME[] = L"async-profiler-etw-profile.2\\lock";
constexpr size_t MAX_OWNERS = 64, MAX_CHANGES = 64;
constexpr ULONG TIMER = 0, PMC = 1;

std::uint64_t qpc() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }

struct Owner {
    volatile LONG used;
    ULONG pid, targetPid, requested;
    FILETIME created;
    GUID session;
    WCHAR name[128];
};
struct Slot {
    // requested produced the current interval; external marks an interval owned by another profiler.
    ULONG source, requested, interval, minimum, maximum, raw, external;
    RawPmuConfig rawConfig;
    TRACE_PROFILE_INTERVAL previous;
    volatile LONG intervalOwned;
    RawPmuLease lease;
    // Odd while an interval change is in progress.
    volatile LONG sequence;
    volatile LONG64 changes;
    IntervalChange log[MAX_CHANGES];
    Owner owners[MAX_OWNERS];
};

// Only a missing or exited process, or a reused ID, proves an owner gone.
bool alive(const Owner& owner) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, owner.pid);
    if (!process) return GetLastError() != ERROR_INVALID_PARAMETER;
    FILETIME created, exited, kernel, user;
    bool result = WaitForSingleObject(process, 0) == WAIT_TIMEOUT
        && (!GetProcessTimes(process, &created, &exited, &kernel, &user) || CompareFileTime(&created, &owner.created) == 0);
    CloseHandle(process);
    return result;
}

bool idle(const Slot& slot) {
    return std::none_of(std::begin(slot.owners), std::end(slot.owners), [](const Owner& owner) { return owner.used != 0; });
}

ULONG query(TRACE_PROFILE_INTERVAL& value) {
    ULONG length;
    return TraceQueryInformation(0, TraceSampledProfileIntervalInfo, &value, sizeof(value), &length);
}

// The registry lock serializes all registry and machine-wide configuration
// changes. Abandonment leaves records consistent: each OS mutation is preceded
// by the record that undoes it.
class Locked {
    HANDLE _lock;
public:
    ULONG error;
    explicit Locked(HANDLE lock) : _lock(lock) {
        auto result = WaitForSingleObject(lock, 30000);
        error = result == WAIT_OBJECT_0 || result == WAIT_ABANDONED ? ERROR_SUCCESS : result == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
    }
    ~Locked() { if (!error) ReleaseMutex(_lock); }
};
}

struct ProfileShare::Registry { Slot slots[2]; };

namespace {
// A dead owner whose watcher did not release it: stop its session so it is not
// mistaken for an external profiler. A session that cannot be stopped keeps its record.
void prune(Slot (&slots)[2]) {
    for (auto& slot : slots) {
        for (auto& owner : slot.owners) {
            if (!owner.used || alive(owner)) continue;
            Properties stopped;
            auto error = stopSession(owner.name, owner.session, stopped);
            if (!error || error == ERROR_INVALID_DATA) InterlockedExchange(&owner.used, 0);
        }
    }
}

ULONG external(const Slot (&slots)[2], bool pmc, bool& busy) {
    std::vector<GUID> ours;
    for (const auto& slot : slots) {
        for (const auto& owner : slot.owners) if (owner.used) ours.push_back(owner.session);
    }
    return otherProfilers(pmc, busy, ours);
}

// Undoes an idle slot's configuration. An external profiler using the interval
// prevents restoration; the record remains for a later owner to retry.
ULONG restore(Slot (&slots)[2], bool pmc) {
    auto& slot = slots[pmc];
    if (slot.intervalOwned) {
        bool busy;
        auto error = external(slots, pmc, busy);
        if (!error && busy) error = ERROR_BUSY;
        if (!error) error = TraceSetInformation(0, TraceSampledProfileIntervalInfo, &slot.previous, sizeof(slot.previous));
        if (error) return error;
        InterlockedExchange(&slot.intervalOwned, 0);
    }
    slot.external = 0;
    return removeRawPmu(slot.lease);
}

// Logged changes let every owner weight each sample by the interval in force at its timestamp.
ULONG change(Slot& slot, ULONG requested) {
    InterlockedIncrement(&slot.sequence);
    TRACE_PROFILE_INTERVAL value{slot.source, requested};
    auto time = qpc();
    auto error = TraceSetInformation(0, TraceSampledProfileIntervalInfo, &value, sizeof(value));
    if (!error) error = query(value);
    if (!error) {
        slot.log[slot.changes % MAX_CHANGES] = {time, value.Interval, 0};
        InterlockedIncrement64(&slot.changes);
        slot.requested = requested; slot.interval = value.Interval;
    }
    InterlockedIncrement(&slot.sequence);
    return error;
}

// The source runs at its owners' finest request. An external profiler that took
// the interval after the first owner vetoes a finer interval and keeps a finer one.
ULONG retune(Slot (&slots)[2], bool pmc, ShareConflict& conflict) {
    auto& slot = slots[pmc];
    if (slot.external || idle(slot)) return ERROR_SUCCESS;
    ULONG finest = ULONG(-1);
    for (const auto& owner : slot.owners) if (owner.used) finest = std::min(finest, owner.requested);
    if (finest == slot.requested) return ERROR_SUCCESS;
    bool busy;
    auto error = external(slots, pmc, busy);
    if (error) return error;
    if (busy) {
        if (finest > slot.requested) return ERROR_SUCCESS;
        conflict = {pmc ? ShareConflictKind::ExternalPmc : ShareConflictKind::ExternalTimer, 0, slot.source, slot.interval};
        return ERROR_BUSY;
    }
    return change(slot, finest);
}

ULONG configure(Slot (&slots)[2], bool pmc, const ShareRequest& request, ULONG& requested, ShareConflict& conflict) {
    auto& slot = slots[pmc];
    bool busy;
    auto error = external(slots, pmc, busy);
    if (error) return error;
    if (pmc && busy) { conflict.kind = ShareConflictKind::ExternalPmc; return ERROR_BUSY; }
    if (!busy && (error = restore(slots, pmc))) return error;
    TRACE_PROFILE_INTERVAL value{request.source, request.interval};
    if (request.raw) {
        if ((error = prepareRawPmu(request.rawConfig, request.interval, slot.lease)) || (error = addRawPmu(slot.lease))
                || (error = selectRawPmuInterval(slot.lease, request.explicitInterval))) return error;
        value = {slot.lease.source, slot.lease.interval};
    }
    slot.minimum = request.raw ? slot.lease.minimum : 0; slot.maximum = request.raw ? slot.lease.maximum : 0;
    slot.external = busy;
    if (busy) {
        // An external timer profiler owns the interval, as before any capture of ours.
        value.Interval = 0;
        if ((error = query(value))) return error;
        if (request.explicitInterval && request.interval != value.Interval) {
            conflict = {ShareConflictKind::ExternalTimer, 0, 0, value.Interval};
            return ERROR_BUSY;
        }
    } else {
        if (!slot.intervalOwned) {
            slot.previous = {value.Source, 0};
            if ((error = query(slot.previous))) return error;
            InterlockedExchange(&slot.intervalOwned, 1);
        }
        if ((error = TraceSetInformation(0, TraceSampledProfileIntervalInfo, &value, sizeof(value))) || (error = query(value))) return error;
    }
    if (pmc && (error = TraceSetInformation(0, TraceProfileSourceConfigInfo, &value.Source, sizeof(value.Source)))) return error;
    requested = busy ? value.Interval : request.raw ? slot.lease.interval : request.interval;
    slot.source = value.Source; slot.requested = requested; slot.interval = value.Interval;
    slot.raw = request.raw; slot.rawConfig = request.rawConfig;
    return ERROR_SUCCESS;
}
}

ULONG ProfileShare::open() {
    PSECURITY_DESCRIPTOR descriptor;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NWNR;;;HI)",
            SDDL_REVISION_1, &descriptor, nullptr)) return GetLastError();
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    BYTE administrators[SECURITY_MAX_SID_SIZE], high[SECURITY_MAX_SID_SIZE];
    DWORD administratorsSize = sizeof(administrators), highSize = sizeof(high);
    auto boundary = CreateBoundaryDescriptorW(NAMESPACE, 0);
    ULONG error = boundary && CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators, &administratorsSize)
        && CreateWellKnownSid(WinHighLabelSid, nullptr, high, &highSize) && AddSIDToBoundaryDescriptor(&boundary, administrators)
        && AddIntegrityLabelToBoundaryDescriptor(&boundary, high) ? ERROR_SUCCESS : GetLastError();
    // Opening races with the last holder closing it.
    while (!error && !_namespace) {
        _namespace = CreatePrivateNamespaceW(&security, boundary, NAMESPACE);
        if (_namespace || (error = GetLastError()) != ERROR_ALREADY_EXISTS) break;
        _namespace = OpenPrivateNamespaceW(boundary, NAMESPACE);
        error = _namespace || GetLastError() == ERROR_PATH_NOT_FOUND ? ERROR_SUCCESS : GetLastError();
    }
    if (boundary) DeleteBoundaryDescriptor(boundary);
    if (!error) {
        _lock = CreateMutexW(&security, FALSE, LOCK_NAME);
        _section = _lock ? CreateFileMappingW(INVALID_HANDLE_VALUE, &security, PAGE_READWRITE, 0, sizeof(Registry), SECTION_NAME) : nullptr;
        if (!_section) error = GetLastError();
    }
    LocalFree(descriptor);
    // A new section is zero-filled, which is the empty registry.
    if (!error) error = attach(_namespace, _lock, _section);
    if (error) close();
    return error;
}

ULONG ProfileShare::attach(HANDLE space, HANDLE lock, HANDLE section) {
    _namespace = space; _lock = lock; _section = section;
    _registry = static_cast<Registry*>(MapViewOfFile(section, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(Registry)));
    return _registry ? ERROR_SUCCESS : GetLastError();
}

void ProfileShare::close() {
    if (_registry) { UnmapViewOfFile(_registry); _registry = nullptr; }
    if (_section) { CloseHandle(_section); _section = nullptr; }
    if (_lock) { CloseHandle(_lock); _lock = nullptr; }
    if (_namespace) { ClosePrivateNamespace(_namespace, 0); _namespace = nullptr; }
}

ULONG ProfileShare::join(WatchState& state, const ShareRequest& request, ShareGrant& grant) {
    grant = {};
    Locked locked(_lock);
    if (locked.error) return locked.error;
    bool pmc = request.raw || request.source != 0;
    state.shareSlot = pmc ? PMC : TIMER;
    InterlockedExchange(&state.shareOwned, 1);
    auto& slots = _registry->slots;
    prune(slots);
    auto& slot = slots[state.shareSlot];
    auto active = std::find_if(std::begin(slot.owners), std::end(slot.owners), [](const Owner& owner) { return owner.used != 0; });
    ULONG requested = request.interval;
    if (active != std::end(slot.owners)) {
        bool sameSource = !pmc || (request.raw ? slot.raw && std::memcmp(&request.rawConfig, &slot.rawConfig, sizeof(RawPmuConfig)) == 0
            : !slot.raw && request.source == slot.source);
        if (!sameSource) {
            grant.conflict = {ShareConflictKind::Source, active->targetPid, slot.source, slot.interval, slot.raw, 0, slot.rawConfig.config};
            return ERROR_BUSY;
        }
        if (slot.external) {
            if (request.explicitInterval && request.interval != slot.interval) {
                grant.conflict = {ShareConflictKind::ExternalTimer, 0, slot.source, slot.interval};
                return ERROR_BUSY;
            }
            requested = slot.interval;
        } else if (request.raw && !request.explicitInterval) {
            requested = std::clamp(request.interval, slot.minimum, slot.maximum);
        } else if (request.raw && (request.interval < slot.minimum || request.interval > slot.maximum)) {
            return ERROR_INVALID_PARAMETER;
        }
    } else {
        auto error = configure(slots, pmc, request, requested, grant.conflict);
        if (error) return error;
    }
    auto free = std::find_if(std::begin(slot.owners), std::end(slot.owners), [](const Owner& owner) { return owner.used == 0; });
    if (free == std::end(slot.owners)) return ERROR_NO_SYSTEM_RESOURCES;
    FILETIME exited, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &free->created, &exited, &kernel, &user)) return GetLastError();
    free->pid = GetCurrentProcessId(); free->targetPid = request.targetPid; free->requested = requested; free->session = state.guid;
    std::wmemcpy(free->name, state.name, std::size(free->name));
    InterlockedExchange(&free->used, 1);
    auto error = retune(slots, pmc, grant.conflict);
    if (error) return error;
    grant.source = slot.source; grant.interval = slot.interval; grant.requested = requested;
    grant.minimum = slot.minimum; grant.maximum = slot.maximum; grant.position = slot.changes;
    return ERROR_SUCCESS;
}

ULONG ProfileShare::release(WatchState& state) {
    if (!InterlockedCompareExchange(&state.shareOwned, 0, 0)) return ERROR_SUCCESS;
    Locked locked(_lock);
    if (locked.error) return locked.error;
    auto& slots = _registry->slots;
    bool pmc = state.shareSlot == PMC;
    for (auto& owner : slots[pmc].owners) {
        if (owner.used && IsEqualGUID(owner.session, state.guid)) InterlockedExchange(&owner.used, 0);
    }
    prune(slots);
    ShareConflict ignored;
    auto error = idle(slots[pmc]) ? restore(slots, pmc) : retune(slots, pmc, ignored);
    InterlockedExchange(&state.shareOwned, 0);
    return error;
}

ULONG ProfileShare::sync(ULONG index, std::uint64_t& position, std::vector<IntervalChange>& changes, std::uint64_t& horizon) const {
    auto& slot = _registry->slots[index];
    for (;;) {
        auto sequence = InterlockedCompareExchange(&slot.sequence, 0, 0);
        if (sequence & 1) { SwitchToThread(); continue; }
        std::uint64_t count = InterlockedCompareExchange64(&slot.changes, 0, 0);
        if (count - position > MAX_CHANGES) return ERROR_BUFFER_OVERFLOW;
        auto size = changes.size();
        for (auto next = position; next < count; ++next) changes.push_back(slot.log[next % MAX_CHANGES]);
        auto now = qpc();
        if (InterlockedCompareExchange(&slot.sequence, 0, 0) == sequence) {
            position = count; horizon = now;
            return ERROR_SUCCESS;
        }
        changes.resize(size);
    }
}
}
