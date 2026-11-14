/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <cstdint>

namespace WindowsProfiler {
// Invariant-TSC cycles to nanoseconds: ns = cycles * numerator / denominator.
struct TscRate {
    enum class Source { ReferencePage, Cpuid15, Calibrated };
    Source source;
    unsigned __int128 numerator, denominator;
    // Relative error bound against QPC; zero for exact sources.
    double bound;
    std::uint64_t nanos(std::uint64_t cycles) const { return static_cast<std::uint64_t>(cycles * numerator / denominator); }
};
constexpr double CALIBRATION_BOUND = 20e-6;
// Exact sources first: the Hyper-V reference TSC page from which Windows derives
// QPC (verified against QPC), then CPUID leaf 0x15. Otherwise the rate is
// calibrated against QPC within CALIBRATION_BOUND, which takes at least 20 ms.
// Fails only without an invariant TSC. exactSources=false forces calibration.
const char* measureTscRate(TscRate& rate, bool exactSources = true);
}
