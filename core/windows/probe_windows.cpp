/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProbe.h"
#include "windowsNativeProbeTarget.h"
#include "windowsBreakpoints.h"
#include "importHooks.h"
#include "profiler.h"
#include "stackFrame.h"
#include "writer.h"
#include "tsc.h"
#include <atomic>
#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>

namespace {
std::atomic<std::uint64_t> probe_calls{0}, probe_samples{0}, probe_dropped{0};

}
int64_t WindowsProbe::_interval;
unsigned WindowsProbe::_counterArg;
void WindowsProbe::initialize() { WindowsProfiler::Breakpoints::initialize(); }
Error WindowsProbe::start(Arguments& args) {
    (void)args;
    probe_calls.store(0); probe_samples.store(0); probe_dropped.store(0);
    return WindowsProfiler::Breakpoints::start(WindowsProfiler::Breakpoints::NATIVE_PROBE, _address,
            [](CONTEXT& context, void*) { record(context); }, nullptr,
            static_cast<WindowsProfiler::Breakpoints::Access>(_access), _length);
}
void WindowsProbe::stop() { WindowsProfiler::Breakpoints::stop(WindowsProfiler::Breakpoints::NATIVE_PROBE); }

Error WindowsProbe::prepareProbe(Arguments& args, bool memory) {
    if (args._interval < 0) return Error("Interval must be positive");
    WindowsProfiler::NativeProbe::HardwareSpec spec;
    if (auto error = WindowsProfiler::NativeProbe::parseHardware(args._event, memory, spec)) return Error(error);
    auto address = Profiler::instance()->resolveSymbol(spec.target.c_str());
    if (!address) return Error("Native probe symbol was not found or is ambiguous; qualify it with module.dll!symbol");
    _interval = std::max<int64_t>(1, args._interval);
    _counterArg = spec.counterArg;
    _address = address;
    _access = spec.access;
    _length = spec.length;
    return Error::OK;
}

void WindowsProbe::record(CONTEXT& context) {
    auto generation = sampleGeneration();
    // perf allocates a counter per TID. Recording gates do not stop or reset it.
    auto selected = _interval <= 1 || WindowsProfiler::Breakpoints::samplePeriod(
        WindowsProfiler::Breakpoints::NATIVE_PROBE, static_cast<std::uint64_t>(_interval));
    if (!canSample(generation)) return;
    auto filter = Profiler::instance()->threadFilter();
    if (filter->enabled() && !filter->contains(GetCurrentThreadId())) return;
    auto timestamp = TSC::ticks();
    if (!canSample(generation)) return;
    probe_calls.fetch_add(1, std::memory_order_relaxed);
    if (!selected) return;
    auto frame = StackFrame(&context);
    auto weight = _counterArg == 1 ? frame.arg0() : _counterArg == 2 ? frame.arg1()
        : _counterArg == 3 ? frame.arg2() : _counterArg == 4 ? frame.arg3() : static_cast<uintptr_t>(_interval);
    ExecutionEvent event(timestamp);
    auto copy = context;
    if (Profiler::instance()->recordSample(&copy, weight, EXECUTION_SAMPLE, &event)) probe_samples.fetch_add(1);
    else probe_dropped.fetch_add(1);
}


void WindowsProbe::writeMetrics(Writer& out) {
    out << "windows_probe_calls " << u64(probe_calls.load()) << '\n';
    out << "windows_probe_samples " << u64(probe_samples.load()) << '\n';
    out << "windows_probe_dropped " << u64(probe_dropped.load()) << '\n';
    out << "windows_probe_failed " << int(WindowsProfiler::Breakpoints::failed()) << '\n';
    out << "windows_breakpoint_targets " << int(WindowsProfiler::Breakpoints::activeTargets()) << '\n';
    out << "windows_import_failed " << int(WindowsProfiler::Imports::import_failed.load()) << '\n';
    WindowsProfiler::Imports::writeImportFailure(out);
    WindowsProfiler::writeSnapshotMetrics(out);
    WindowsProfiler::writeSymbolMetrics(out);
}
