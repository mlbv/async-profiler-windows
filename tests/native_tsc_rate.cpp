/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Checks the calibrated TSC rate against the exact source within its reported bound.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "windowsTscRate.h"
using WindowsProfiler::TscRate;

static void require(bool condition, const char* message) {
    if (!condition) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
static const char* name(TscRate::Source source) {
    return source == TscRate::Source::ReferencePage ? "reference TSC page" : source == TscRate::Source::Cpuid15 ? "CPUID 0x15" : "calibrated";
}

int main() {
    TscRate exact;
    require(!WindowsProfiler::measureTscRate(exact), "invariant TSC required");
    // About an hour of CPU time at 4 GHz keeps conversion truncation negligible.
    constexpr std::uint64_t cycles = std::uint64_t(1) << 44;
    std::printf("%s: %.0f Hz\n", name(exact.source), 1e9 * cycles / exact.nanos(cycles));
    for (int round = 0; round < 5; ++round) {
        TscRate calibrated;
        require(!WindowsProfiler::measureTscRate(calibrated, false), "calibration failed");
        require(calibrated.source == TscRate::Source::Calibrated, "exact sources were not excluded");
        require(calibrated.bound > 0 && calibrated.bound <= WindowsProfiler::CALIBRATION_BOUND, "calibration bound out of range");
        double error = static_cast<double>(calibrated.nanos(cycles)) / static_cast<double>(exact.nanos(cycles)) - 1;
        std::printf("calibrated: %.0f Hz, error %+.2f ppm, bound %.2f ppm\n", 1e9 * cycles / calibrated.nanos(cycles), error * 1e6, calibrated.bound * 1e6);
        // Both calibrations bound their error against QPC; an exact source has none.
        require(std::fabs(error) <= calibrated.bound + exact.bound + 1e-12, "calibrated rate exceeds its bound");
    }
    std::printf("tsc rate checks passed\n");
}
