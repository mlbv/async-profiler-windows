/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsRawPmu.h"
#include <bcrypt.h>
#include <cpuid.h>
#include <evntrace.h>
#include <winternl.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string_view>
#include <vector>

namespace WindowsProfiler::Etw {
namespace {
// The transient custom-source interface used by Windows Performance Recorder.
// https://learn.microsoft.com/windows-hardware/test/wpt/recording-pmu-events
// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntexapi.h
struct AddInformation {
    ULONG infoClass;
    UCHAR version;
    UCHAR reserved[3];
    union Programming {
        struct { UCHAR event, unit, cmask, invert, anyThread, edge; } intel;
        struct { USHORT event; UCHAR unit, cmask, invert, edge, hostGuest, pmu; } amd;
        ULONG alignment[2];
    } programming;
    ULONG cpu[3];
    ULONG interval;
    BOOLEAN persist;
    WCHAR name[96];
};
struct RemoveInformation { ULONG infoClass, source, cpu[3]; };
static_assert(offsetof(AddInformation, programming) == 8 && offsetof(AddInformation, cpu) == 16
    && offsetof(AddInformation, interval) == 28 && offsetof(AddInformation, persist) == 32
    && offsetof(AddInformation, name) == 34 && sizeof(RemoveInformation) == 20);

using SetSystemInformation = NTSTATUS (NTAPI*)(ULONG, void*, ULONG);
ULONG change(void* data, ULONG size) {
    auto set = reinterpret_cast<SetSystemInformation>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetSystemInformation"));
    if (!set) return ERROR_PROC_NOT_FOUND;
    auto status = set(31, data, size);
    return status < 0 ? RtlNtStatusToDosError(status) : ERROR_SUCCESS;
}

bool processor(RawPmuConfig& config) {
    unsigned int a, b, c, d;
    __cpuid(0, a, b, c, d);
    char vendor[13]{};
    std::memcpy(vendor, &b, 4); std::memcpy(vendor + 4, &d, 4); std::memcpy(vendor + 8, &c, 4);
    if (std::strcmp(vendor, "GenuineIntel") == 0) config.vendor = 1;
    else if (std::strcmp(vendor, "AuthenticAMD") == 0) config.vendor = 2;
    else return false;
    __cpuid(1, a, b, c, d);
    auto family = (a >> 8) & 15;
    config.family = family + (family == 15 ? (a >> 20) & 255 : 0);
    config.model = ((a >> 4) & 15) | ((family == 6 || family == 15) ? (a >> 12) & 240 : 0);
    config.stepping = a & 15;
    return true;
}

const char* validate(const RawPmuConfig& config) {
    RawPmuConfig host;
    if (!processor(host)) return "Raw PMU events require an Intel or AMD x86 processor";
    if (host.vendor != config.vendor || host.family != config.family || host.model != config.model || host.stepping != config.stepping)
        return "Raw PMU processor identity does not match this host";
    constexpr std::uint64_t common = 0xffff | (1ull << 18) | (1ull << 23) | (255ull << 24);
    auto allowed = common | (config.vendor == 1 ? 1ull << 21 : (15ull << 32) | (3ull << 40));
    if (config.config & ~allowed) return "Raw PMU config contains unsupported or reserved programming bits";
    return nullptr;
}

bool number(std::string_view value, int base, std::uint64_t& result) {
    if (value.empty()) return false;
    if (base == 0) {
        base = 10;
        if (value.size() > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X')) { base = 16; value.remove_prefix(2); }
        else if (value.size() > 1 && value[0] == '0') base = 8;
    }
    auto end = value.data() + value.size();
    auto parsed = std::from_chars(value.data(), end, result, base);
    return !value.empty() && parsed.ec == std::errc() && parsed.ptr == end;
}

ULONG find(const RawPmuLease& lease, ULONG& source, ULONG& minimum, ULONG& maximum) try {
    ULONG size = 0;
    auto result = TraceQueryInformation(0, TraceProfileSourceListInfo, nullptr, 0, &size);
    if (result != ERROR_BAD_LENGTH && result != ERROR_INSUFFICIENT_BUFFER && result != ERROR_SUCCESS) return result;
    if (!size || size > 1024 * 1024) return ERROR_INVALID_DATA;
    std::vector<unsigned char> bytes(size);
    result = TraceQueryInformation(0, TraceProfileSourceListInfo, bytes.data(), size, &size);
    if (result) return result;
    if (size > bytes.size()) return ERROR_INVALID_DATA;
    for (size_t offset = 0; offset < size;) {
        constexpr auto header = offsetof(PROFILE_SOURCE_INFO, Description);
        if (size - offset < header + sizeof(WCHAR)) return ERROR_INVALID_DATA;
        auto info = reinterpret_cast<const PROFILE_SOURCE_INFO*>(bytes.data() + offset);
        auto count = info->NextEntryOffset ? info->NextEntryOffset : size - offset;
        if (count > size - offset || count < header + sizeof(WCHAR) || count % sizeof(WCHAR)) return ERROR_INVALID_DATA;
        auto chars = (count - header) / sizeof(WCHAR);
        auto end = static_cast<const WCHAR*>(std::wmemchr(info->Description, 0, chars));
        if (!end) return ERROR_INVALID_DATA;
        if (std::wcscmp(info->Description, lease.name) == 0) {
            source = info->Source; minimum = info->MinInterval; maximum = info->MaxInterval;
            return source && minimum <= maximum ? ERROR_SUCCESS : ERROR_INVALID_DATA;
        }
        if (!info->NextEntryOffset) break;
        offset += count;
    }
    return ERROR_NOT_FOUND;
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
}

bool isRawPmu(const char* name) {
    if (std::strncmp(name, "cpu/", 4) == 0) return true;
    // Upstream resolves its predefined read probe before trying rHEX, even
    // though all three letters after its initial r are hexadecimal digits.
    if (std::strcmp(name, "read") == 0 || name[0] != 'r') return false;
    std::uint64_t config;
    return number(std::string_view(name + 1), 16, config);
}

const char* parseRawPmu(const char* name, RawPmuConfig& config) {
    config = {};
    if (!processor(config)) return "Raw PMU events require an Intel or AMD x86 processor";
    std::string_view descriptor(name);
    if (descriptor.starts_with("cpu/")) {
        if (descriptor.size() < 6 || descriptor.back() != '/') return "Raw PMU descriptor must end with '/'";
        descriptor.remove_prefix(4); descriptor.remove_suffix(1);
    }
    if (descriptor.starts_with('r')) {
        descriptor.remove_prefix(1);
        if (!number(descriptor, 16, config.config)) return "Invalid raw PMU hexadecimal config";
    } else {
        std::uint64_t supplied = 0;
        while (!descriptor.empty()) {
            auto next = descriptor.find_first_of(",:");
            auto token = descriptor.substr(0, next);
            auto equals = token.find('=');
            auto key = token.substr(0, equals);
            std::uint64_t value = 1, mask = 0, encoded = 0;
            if (equals != std::string_view::npos && !number(token.substr(equals + 1), 0, value)) return "Invalid raw PMU field value";
            if (key == "config") { mask = ~0ull; encoded = value; }
            else if (key == "event") {
                auto maximum = config.vendor == 1 ? 255u : 4095u;
                if (value > maximum) return "Raw PMU event selector is out of range";
                mask = 255 | (config.vendor == 2 ? 15ull << 32 : 0);
                encoded = (value & 255) | ((value >> 8) << 32);
            } else if (key == "umask" || key == "cmask") {
                if (value > 255) return "Raw PMU byte field is out of range";
                auto shift = key == "umask" ? 8 : 24;
                mask = 255ull << shift; encoded = value << shift;
            } else if (key == "edge" || key == "inv" || key == "any" || key == "host" || key == "guest") {
                if (value > 1) return "Raw PMU flag must be zero or one";
                if ((key == "any" && config.vendor != 1) || ((key == "host" || key == "guest") && config.vendor != 2))
                    return "Raw PMU field is unavailable on this CPU vendor";
                auto shift = key == "edge" ? 18 : key == "inv" ? 23 : key == "any" ? 21 : key == "guest" ? 40 : 41;
                mask = 1ull << shift; encoded = value << shift;
            } else return "Unknown raw PMU field (Windows supports event, umask, edge, inv, any, cmask, host, guest, config)";
            if (supplied & mask) return "Duplicate or overlapping raw PMU fields";
            supplied |= mask; config.config |= encoded;
            if (next == std::string_view::npos) break;
            descriptor.remove_prefix(next + 1);
            if (descriptor.empty()) return "Empty raw PMU field";
        }
        if (!supplied) return "Empty raw PMU descriptor";
    }
    return validate(config);
}

ULONG prepareRawPmu(const RawPmuConfig& config, ULONG interval, RawPmuLease& lease) {
    if (InterlockedCompareExchange(&lease.pending, 0, 0)) return ERROR_ALREADY_INITIALIZED;
    if (!interval || validate(config)) return ERROR_INVALID_PARAMETER;
    std::array<unsigned char, 16> random;
    auto status = BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) return RtlNtStatusToDosError(status);
    lease = {};
    lease.config = config; lease.interval = interval;
    auto length = std::swprintf(lease.name, std::size(lease.name), L"asprof-raw-%lu-", GetCurrentProcessId());
    if (length < 0) return ERROR_INVALID_DATA;
    for (auto byte : random) {
        std::swprintf(lease.name + length, std::size(lease.name) - length, L"%02x", byte);
        length += 2;
    }
    return ERROR_SUCCESS;
}

ULONG addRawPmu(RawPmuLease& lease) {
    if (validate(lease.config) || !lease.interval || std::wcsncmp(lease.name, L"asprof-raw-", 11) != 0
            || !std::wmemchr(lease.name, 0, std::size(lease.name))) return ERROR_INVALID_PARAMETER;
    if (InterlockedCompareExchange(&lease.pending, 0, 0)) return ERROR_ALREADY_INITIALIZED;
    ULONG source, minimum, maximum;
    auto result = find(lease, source, minimum, maximum);
    if (result != ERROR_NOT_FOUND) return result ? result : ERROR_ALREADY_EXISTS;
    AddInformation info{};
    info.infoClass = 21; info.version = 2;
    auto config = lease.config.config;
    if (lease.config.vendor == 1) {
        info.programming.intel = {static_cast<UCHAR>(config), static_cast<UCHAR>(config >> 8), static_cast<UCHAR>(config >> 24),
            static_cast<UCHAR>((config >> 23) & 1), static_cast<UCHAR>((config >> 21) & 1), static_cast<UCHAR>((config >> 18) & 1)};
    } else if (config & ~0xffffull) {
        info.version = 3;
        info.programming.amd = {static_cast<USHORT>((config & 255) | (((config >> 32) & 15) << 8)),
            static_cast<UCHAR>(config >> 8), static_cast<UCHAR>(config >> 24), static_cast<UCHAR>((config >> 23) & 1),
            static_cast<UCHAR>((config >> 18) & 1), static_cast<UCHAR>((config >> 40) & 3), 0};
    } else {
        // V2 uses the same byte positions as the Intel Event/Unit pair.
        info.programming.intel.event = static_cast<UCHAR>(config);
        info.programming.intel.unit = static_cast<UCHAR>(config >> 8);
    }
    info.cpu[0] = lease.config.family; info.cpu[1] = lease.config.model; info.cpu[2] = lease.config.stepping;
    info.interval = lease.interval;
    std::wmemcpy(info.name, lease.name, std::size(lease.name));
    InterlockedExchange(&lease.pending, 1);
    result = change(&info, sizeof(info));
    if (result) return result;
    result = find(lease, source, minimum, maximum);
    if (result) return result;
    lease.source = source; lease.minimum = minimum; lease.maximum = maximum;
    return ERROR_SUCCESS;
}

ULONG selectRawPmuInterval(RawPmuLease& lease, bool explicitInterval) {
    if (!lease.interval || lease.minimum > lease.maximum || !lease.maximum) return ERROR_INVALID_DATA;
    if (!explicitInterval) lease.interval = std::clamp(lease.interval, lease.minimum, lease.maximum);
    return lease.interval >= lease.minimum && lease.interval <= lease.maximum ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
}

ULONG removeRawPmu(RawPmuLease& lease) {
    if (!InterlockedCompareExchange(&lease.pending, 0, 0)) return ERROR_SUCCESS;
    ULONG source, minimum, maximum;
    auto result = find(lease, source, minimum, maximum);
    if (result == ERROR_NOT_FOUND) { InterlockedExchange(&lease.pending, 0); return ERROR_SUCCESS; }
    if (result) return result;
    if (lease.source && source != lease.source) return ERROR_INVALID_DATA;
    RemoveInformation info{22, source, {lease.config.family, lease.config.model, lease.config.stepping}};
    result = change(&info, sizeof(info));
    if (result) return result;
    result = find(lease, source, minimum, maximum);
    if (result != ERROR_NOT_FOUND) return result ? result : ERROR_BUSY;
    InterlockedExchange(&lease.pending, 0);
    return ERROR_SUCCESS;
}
}
