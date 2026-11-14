/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "platform.h"
#include "engine.h"
#include <evntrace.h>
#include <evntcons.h>
#include <array>
#include <span>
#include <string>
#include <vector>

class Writer;
namespace WindowsProfiler::Etw {
struct Source {
    ULONG id, minimum, maximum;
    std::string name;
};
ULONG parseSources(const void* data, size_t size, std::vector<Source>& sources);
ULONG querySources(std::vector<Source>& sources);
bool cpuTimerAlias(const char* name);
struct HardwareAlias {
    const char* name;
    std::array<const char*, 2> sources;
};
// Known names stay reserved even when this host has no equivalent HAL source.
std::span<const HardwareAlias> hardwareAliases();
bool hardwareAlias(const char* name);
const Source* findSource(const std::vector<Source>& sources, const char* name);
Error validateTargetCpu(int cpu);

enum class Kind { Ignore, Profile, Stack, UnsupportedStack, ThreadStart, ThreadEnd, ImageLoad, ImageUnload, ImageRundown, Malformed };
constexpr size_t MAX_STACK_FRAMES = 256;
struct Record {
    Kind kind = Kind::Ignore;
    std::uint64_t time = 0, ip = 0;
    ULONG pid = 0, tid = 0, source = 0, count = 1;
    USHORT cpu = 0;
    std::uint64_t imageBase = 0;
    ULONG imageSize = 0, imageChecksum = 0;
    size_t depth = 0;
    std::array<std::uint64_t, MAX_STACK_FRAMES> stack{};
};
// Decodes the documented classic PerfInfo/StackWalk/Thread payloads. No TDH or
// live target-thread context is needed on the consumer thread.
Record decode(const EVENT_RECORD& record);
}

class WindowsEtwEngine : public Engine {
    struct State;
    State* _state = nullptr;
public:
    Error prepare(Arguments& args) override;
    Error start(Arguments& args) override;
    void stop() override;
    Error stopError();
    void enableEvents(bool enabled) override;
    const char* type() override;
    const char* title() override;
    const char* units() override;
    int64_t interval() override;
    static bool accepts(const char* name);
    static Error list(Writer& out);
    void writeMetrics(Writer& out);
};
