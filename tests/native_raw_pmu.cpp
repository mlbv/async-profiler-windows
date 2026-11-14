/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsRawPmu.h"
#include "windowsEtwWatcher.h"
#include "windowsEtwProfileShare.h"
#include "windowsPrivilege.h"
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <limits>
#include <stdexcept>

using namespace WindowsProfiler::Etw;
namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
struct Probe {
    ProfileShare share;
    SessionWatcher watcher;
    ~Probe() {
        if (watcher.state()) {
            auto error = finish();
            if (error) std::fprintf(stderr, "Raw PMU rollback failed: %lu\n", error);
        }
    }
    ULONG finish() {
        auto error = watcher.cleanup();
        auto result = watcher.finish();
        return error ? error : result.error;
    }
};
void registerProbe(const char* descriptor) {
    RawPmuConfig config;
    auto error = parseRawPmu(descriptor, config);
    if (error) throw std::runtime_error(error);
    WindowsProfiler::Privilege privilege(L"SeSystemProfilePrivilege");
    require(privilege.enable() == ERROR_SUCCESS, "Transient probe requires SeSystemProfilePrivilege");
    Probe probe;
    require(probe.share.open() == ERROR_SUCCESS, "Shared profile registry");
    Properties properties{};
    LARGE_INTEGER now; QueryPerformanceCounter(&now);
    std::swprintf(properties.name, std::size(properties.name), L"async-profiler-%lu-%llu", GetCurrentProcessId(),
        static_cast<unsigned long long>(now.QuadPart));
    require(BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&properties.p.Wnode.Guid), sizeof(GUID),
        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "Probe GUID generation");
    auto result = probe.watcher.start(properties, &probe.share);
    require(result == ERROR_SUCCESS, "Start cleanup watcher before source registration");
    ShareGrant grant;
    result = probe.share.join(*probe.watcher.state(), {0, 1000000, GetCurrentProcessId(), false, true, config}, grant);
    if (result) {
        std::fprintf(stderr, "Raw PMU registration failed: %lu\n", result);
        require(probe.finish() == ERROR_SUCCESS, "Failed registration rollback");
        throw std::runtime_error("Transient raw PMU registration was rejected");
    }
    require(grant.source && grant.minimum <= grant.interval && grant.interval <= grant.maximum,
        "Exact-name source enumeration after registration");
    std::printf("RAW_PMU_REGISTERED source=%lu interval=%lu range=%lu..%lu watcher=%lu\n", grant.source,
        grant.interval, grant.minimum, grant.maximum, probe.watcher.pid());
    std::fflush(stdout);
    require(probe.finish() == ERROR_SUCCESS, "Watchdog cleanup and source absence verification");
    std::puts("RAW_PMU_REMOVED sourceAbsent=1 sessionStarted=0");
}
}
int main(int argc, char** argv) try {
    if (argc == 3 && std::strcmp(argv[1], "--register") == 0) { registerProbe(argv[2]); return 0; }
    require(argc == 1, "Usage: raw-pmu-test [--register rc0]");
    RawPmuConfig raw, fields, uppercase;
    require(isRawPmu("rc0") && isRawPmu("rC0") && isRawPmu("cpu/event=0xc0/"), "raw source recognition");
    require(!isRawPmu("cycles") && !isRawPmu("wall") && !isRawPmu("restart") && !isRawPmu("realloc")
        && !isRawPmu("recv") && !isRawPmu("read") && !isRawPmu("rc0_suffix"), "ordinary event and native probe precedence");
    require(isRawPmu("cpu/read/"), "Explicit CPU descriptor disambiguates hexadecimal config from read probe");
    require(!parseRawPmu("rc0", raw) && !parseRawPmu("cpu/event=0xc0:umask=0/", fields)
        && !parseRawPmu("cpu/rC0/", uppercase), "equivalent raw encodings");
    require(raw.config == 0xc0 && std::memcmp(&raw, &fields, sizeof(raw)) == 0
        && std::memcmp(&raw, &uppercase, sizeof(raw)) == 0, "raw event retains exact selector and CPU scope");
    require(!parseRawPmu("cpu/event=192,umask=3/", fields) && fields.config == 0x3c0, "descriptor separator encoding");
    require(!parseRawPmu("cpu/event=0xc0:umask=1:edge:inv:cmask=2/", fields)
        && fields.config == 0x028401c0, "extended programming bit layout");
    require(parseRawPmu("r10000", fields), "privilege mode bits cannot be smuggled into raw config");
    require(parseRawPmu("r400000", fields), "enable bit is controlled by Windows");
    require(parseRawPmu("cpu/config=0xc0:event=0xc0/", fields), "overlapping fields rejected");
    require(parseRawPmu("cpu/event=0xc0:umask=256/", fields), "unit mask range");
    require(parseRawPmu("cpu/event=0xc0:edge=2/", fields), "flag range");
    require(parseRawPmu("cpu/event=0xc0:config1=1/", fields), "unsupported MSR config fails explicitly");
    require(parseRawPmu("cpu/event=0xc0:/", fields) && parseRawPmu("cpu//", fields)
        && parseRawPmu("cpu/event=0xc0", fields) && parseRawPmu("rnothex", fields), "malformed descriptors");
    if (raw.vendor == 2) {
        require(!parseRawPmu("cpu/event=0xabc:umask=0x12:host:guest/", fields)
            && fields.config == 0x30a000012bcull, "AMD extended event and host/guest encoding");
        require(parseRawPmu("cpu/event=0xc0:any/", fields), "Intel-only field on AMD");
    } else {
        require(!parseRawPmu("cpu/event=0xc0:any/", fields) && fields.config == 0x2000c0, "Intel any-thread field");
        require(parseRawPmu("cpu/event=0x100/", fields) && parseRawPmu("cpu/event=0xc0:host/", fields), "AMD-only fields on Intel");
    }
    RawPmuLease lease;
    require(prepareRawPmu(raw, 0, lease) == ERROR_INVALID_PARAMETER, "zero interval rejected before mutation");
    auto mismatched = raw; ++mismatched.model;
    require(prepareRawPmu(mismatched, 1000, lease) == ERROR_INVALID_PARAMETER, "helper revalidates CPU identity");
    require(prepareRawPmu(raw, 1000, lease) == ERROR_SUCCESS && !lease.pending && !lease.source
        && lease.interval == 1000 && std::wcsncmp(lease.name, L"asprof-raw-", 11) == 0, "nonmutating lease preparation");
    require(removeRawPmu(lease) == ERROR_SUCCESS, "unregistered lease cleanup does not mutate sources");
    lease.minimum = 4096; lease.maximum = 2147483647; lease.interval = 1000;
    require(selectRawPmuInterval(lease, true) == ERROR_INVALID_PARAMETER && lease.interval == 1000,
        "explicit intervals below the host minimum remain errors");
    require(selectRawPmuInterval(lease, false) == ERROR_SUCCESS && lease.interval == 4096,
        "implicit defaults adapt to the registered minimum");
    lease.interval = 3000000000u;
    require(selectRawPmuInterval(lease, true) == ERROR_INVALID_PARAMETER && lease.interval == 3000000000u,
        "explicit intervals above the host maximum remain errors");
    require(selectRawPmuInterval(lease, false) == ERROR_SUCCESS && lease.interval == lease.maximum,
        "implicit defaults adapt to the registered maximum");
    lease.pending = 1;
    require(prepareRawPmu(raw, 1000, lease) == ERROR_ALREADY_INITIALIZED && lease.pending == 1,
        "preparation cannot erase outstanding source ownership");
    lease.pending = 0;
    std::printf("RAW_PMU_PARSE_OK vendor=%lu family=%lu model=%lu stepping=%lu selector=%llx\n", raw.vendor,
        raw.family, raw.model, raw.stepping, static_cast<unsigned long long>(raw.config));
    return 0;
} catch (const std::exception& error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
