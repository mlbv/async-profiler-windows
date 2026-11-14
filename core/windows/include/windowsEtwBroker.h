/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <cstdint>
#include <array>
#include <vector>
#include "windowsEtwProfileShare.h"
#include "windowsSoftwareEvents.h"

namespace WindowsProfiler { struct KernelModule; }
namespace WindowsProfiler::Etw::Broker {
constexpr ULONG PROTOCOL = 8;
constexpr ULONG MAX_PACKET = 2 * 1024 * 1024;
constexpr ULONG MAX_EVENT_PACKET = 256 * 1024;
constexpr ULONG MAX_EXTENDED_BYTES = 128 * 1024;
constexpr USHORT MAX_SOURCE_EXTENSIONS = 64;
constexpr ULONG MAX_RETAINED_EXTENSIONS = 4;
enum class Type : ULONG { Hello = 1, Start, Ready, Event, Modules, Stop, Finished, Activate, StartProvider, Acknowledge };
struct Header { ULONG protocol = PROTOCOL, type = 0, size = 0, sequence = 0; };
struct Acknowledgement { ULONG reply = 0; };
static_assert(sizeof(Header) == 16 && sizeof(Acknowledgement) == 4);
struct Hello { ULONG pid = 0; FILETIME created{}; };
struct Request {
    ULONG source = 0, interval = 0;
    ULONG stacks = 0, images = 0, explicitInterval = 0;
    ULONG raw = 0;
    RawPmuConfig rawConfig{};
    ULONG software = 0;
};
static_assert(sizeof(Request) == 56);
// Software capture forwards every physical event, carries no PMU fields, and
// echoes interval without applying it. Targets send 1 and retain logical periods
// and sample weights locally; those periods need not fit the wire field.
ULONG validateRequest(const Request& request);
enum ProviderFlags : ULONG { Named = 1, Stacks = 2, Images = 4 };
struct ProviderRequest {
    GUID provider{};
    ULONG eventId = 0;
    LONG version = -1;
    ULONG flags = 0, reserved = 0;
};
static_assert(sizeof(ProviderRequest) == 32);
// interval is the capture's own; IntervalChange records give the shared source's.
struct Reply {
    ULONG error = 0, source = 0, interval = 0, pid = 0;
    // An incompatible shared profile configuration, with error ERROR_BUSY.
    ShareConflict conflict{};
};
static_assert(sizeof(Reply) == 48);
enum class RouterFailure : ULONG { None, SwitchTimeReversal, SwitchCapacity, ExitCapacity };
// Software routing counts. Context switches are proven by the switched-out thread's
// next switch-in stack; unresolved switches are still switched out at finish.
struct RouterDiagnostics {
    RouterFailure reason = RouterFailure::None;
    ULONG reserved = 0;
    std::uint64_t samples = 0, stacks = 0, targetStacks = 0;
    std::uint64_t switchOuts = 0, switchIns = 0, provenTarget = 0, provenForeign = 0;
    std::uint64_t terminatedSwitches = 0, exitingEvents = 0, sequenceBreaks = 0;
    std::uint64_t unresolved = 0, switchHighWater = 0, exitingHighWater = 0;
};
static_assert(sizeof(RouterDiagnostics) == 112);
struct Result {
    ULONG error = 0, eventsLost = 0, buffersLost = 0, realtimeBuffersLost = 0;
    ULONG cleanupError = 0, unsupportedFormat = 0;
    std::uint64_t foreignProfiles = 0, unattributedProfiles = 0, potentialTargetLoss = 0;
    RouterDiagnostics router{};
};
static_assert(sizeof(Result) == 160);
struct Event {
    EVENT_HEADER header{};
    ETW_BUFFER_CONTEXT context{};
    ULONG length = 0, extendedCount = 0, extendedBytes = 0;
};
struct Extension { USHORT type = 0, linkage = 0; ULONG size = 0; };
static_assert(sizeof(Event) == 96 && sizeof(Extension) == 8);
struct DecodedEvent {
    EVENT_RECORD event{};
    std::vector<EVENT_HEADER_EXTENDED_DATA_ITEM> extensions;
    std::vector<std::uint64_t> storage;
};
ULONG encodeEvent(const EVENT_RECORD& event, std::vector<unsigned char>& bytes);
ULONG decodeEvent(std::vector<unsigned char>& bytes, void* context, DecodedEvent& decoded);
ULONG providerEvent(const ProviderRequest& request, ULONG targetPid, const EVENT_RECORD& event,
                    EVENT_RECORD& filtered, bool& accepted,
                    std::array<EVENT_HEADER_EXTENDED_DATA_ITEM, 2>* continuation = nullptr);
enum class ProfileKind { Ignore, ForeignSample, UnattributedSample, Sample, UnknownSample, Stack, Thread, KernelImage, Switch };
struct ProfileView {
    EVENT_RECORD event{};
    std::array<unsigned char, 32> metadata{};
    ProfileKind kind = ProfileKind::Ignore;
    std::uint64_t time = 0;
    ULONG tid = 0, pid = 0;
    // Switch only: tid switches out unless terminated; incomingTid switches in.
    // Neither identity is part of a sanitized EVENT_RECORD.
    ULONG incomingTid = 0;
    USHORT cpu = 0;
    bool terminated = false;
    ULONG unsupportedFormat = 0;
};
ULONG profileEvent(ULONG targetPid, bool images, const EVENT_RECORD& event, ProfileView& filtered,
                   SoftwareKind software = SoftwareKind::None);
struct Module { std::uint64_t base = 0; ULONG size = 0, checksum = 0, timestamp = 0, pathLength = 0; };
bool connect(const char* path);
bool connected();
void close();
ULONG start(const Request& request, Reply& reply);
ULONG startProvider(const ProviderRequest& request, Reply& reply);
ULONG activate();
// Runs on the existing consumer thread. EVENT_RECORD storage is callback-local.
ULONG consume(void* context, void (WINAPI* callback)(EVENT_RECORD*), Result& result);
ULONG stop();
bool kernelModules(std::vector<KernelModule>& modules);
// once: serve only the first client, which must connect within 30 seconds,
// matching the lifetime of upstream asprof's fdtransfer server.
int server(DWORD targetPid, const WCHAR* pipeName, bool once);
}
