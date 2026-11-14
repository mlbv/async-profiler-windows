/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

class CodeCache;

namespace WindowsProfiler::NativeProbe {
struct HardwareSpec {
    std::string target;
    unsigned access = 0, length = 1, counterArg = 0;
};
enum class Mode { Entry, Return };
enum class TargetKind { FileOffset, Symbol };
struct SoftwareSpec {
    std::string target;
    std::int64_t offset = 0;
    Mode mode = Mode::Entry;
    TargetKind kind = TargetKind::FileOffset;
};
const char* parseHardware(std::string_view event, bool memory, HardwareSpec& result);
const char* parseSoftware(std::string_view event, SoftwareSpec& result);

class LoadedTarget {
    HMODULE _module = nullptr;
public:
    const unsigned char* address = nullptr;
    std::uintptr_t imageBase = 0;
    ULONG imageSize = 0, rva = 0;
    CodeCache* cache = nullptr;
    std::uint64_t mappingEpoch = 0;
    size_t readable = 0;
    std::wstring path;
    LoadedTarget() = default;
    LoadedTarget(const LoadedTarget&) = delete;
    LoadedTarget& operator=(const LoadedTarget&) = delete;
    LoadedTarget(LoadedTarget&& other) noexcept;
    LoadedTarget& operator=(LoadedTarget&& other) noexcept;
    ~LoadedTarget();
    HMODULE module() const { return _module; }
    HMODULE releaseModule();
    void adoptModule(HMODULE module);
    bool currentMapping() const;
};
const char* resolveSoftware(const SoftwareSpec& spec, LoadedTarget& result);
}
