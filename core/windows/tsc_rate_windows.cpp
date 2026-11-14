/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsTscRate.h"
#include "tsc.h"
#include <windows.h>
#include <winternl.h>
#include <x86intrin.h>
#include <cstring>

namespace WindowsProfiler {
namespace {
// Hyper-V reference TSC page: reference time in 100 ns units is
// ((tsc * scale) >> 64) + offset, and Windows derives QPC from it.
struct ReferenceTscPage { volatile ULONG sequence, reserved; volatile ULONG64 scale; volatile LONG64 offset; };
constexpr ULONG systemHypervisorSharedPageInformation = 197;
// KUSER_SHARED_DATA.QpcBias, the user-mode QPC offset added to reference time.
const volatile ULONG64& qpcBias = *reinterpret_cast<const volatile ULONG64*>(0x7FFE03B8);

std::uint64_t qpc() { LARGE_INTEGER value; QueryPerformanceCounter(&value); return value.QuadPart; }

bool referencePage(TscRate& rate) {
    unsigned eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    if (!(ecx >> 31)) return false;
    __cpuid(0x40000000, eax, ebx, ecx, edx);
    unsigned vendor[3] = {ebx, ecx, edx};
    if (eax < 0x40000003 || std::memcmp(vendor, "Microsoft Hv", sizeof(vendor)) != 0) return false;
    __cpuid(0x40000003, eax, ebx, ecx, edx);
    if (!(eax & (1 << 9))) return false;
    ReferenceTscPage* page = nullptr;
    if (NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(systemHypervisorSharedPageInformation), &page, sizeof(page), nullptr) < 0
            || !page) return false;
    for (;;) {
        ULONG sequence = page->sequence;
        if (!sequence) return false;
        ULONG64 scale = page->scale;
        LONG64 offset = page->offset;
        unsigned processor;
        auto before = qpc();
        auto tsc = __rdtscp(&processor);
        auto after = qpc();
        if (page->sequence != sequence) continue;
        // QPC must be exactly this conversion of the same TSC.
        auto reference = static_cast<ULONG64>((static_cast<unsigned __int128>(tsc) * scale) >> 64) + offset + qpcBias;
        if (reference < before || reference > after) return false;
        rate = {TscRate::Source::ReferencePage, static_cast<unsigned __int128>(scale) * 100, static_cast<unsigned __int128>(1) << 64, 0};
        return true;
    }
}

bool cpuid15(TscRate& rate) {
    unsigned eax, ebx, ecx, edx;
    __cpuid(0, eax, ebx, ecx, edx);
    if (eax < 0x15) return false;
    __cpuid(0x15, eax, ebx, ecx, edx);
    // TSC Hz = crystal Hz * ebx / eax.
    if (!eax || !ebx || !ecx) return false;
    rate = {TscRate::Source::Cpuid15, static_cast<unsigned __int128>(NANOTIME_FREQ) * eax, static_cast<unsigned __int128>(ecx) * ebx, 0};
    return true;
}

// A TSC read between two QPC reads happened at a QPC time within
// [before, after + 1); the narrowest of several brackets resists preemption.
struct Bracket { std::uint64_t tsc, twiceMiddle, width; };
Bracket bracket() {
    Bracket best{0, 0, UINT64_MAX};
    for (int attempt = 0; attempt < 64; ++attempt) {
        unsigned processor;
        auto before = qpc();
        auto tsc = __rdtscp(&processor);
        auto after = qpc();
        if (after + 1 - before < best.width) best = {tsc, before + after + 1, after + 1 - before};
    }
    return best;
}

// TSC::calibrate's method, with each endpoint bracketed by QPC reads: elapsed QPC
// time T is estimated from the bracket midpoints within half the summed widths W,
// so the rate's relative error against QPC is at most W / (2T - W). The second
// endpoint moves out until that bound is within CALIBRATION_BOUND.
void calibrate(TscRate& rate) {
    LARGE_INTEGER frequency;
    QueryPerformanceFrequency(&frequency);
    auto start = bracket();
    Sleep(20);
    for (;;) {
        auto end = bracket();
        auto twiceElapsed = end.twiceMiddle - start.twiceMiddle, widths = start.width + end.width;
        double bound = static_cast<double>(widths) / static_cast<double>(twiceElapsed - widths);
        if (bound <= CALIBRATION_BOUND) {
            rate = {TscRate::Source::Calibrated, static_cast<unsigned __int128>(NANOTIME_FREQ) * twiceElapsed,
                static_cast<unsigned __int128>(end.tsc - start.tsc) * frequency.QuadPart * 2, bound};
            return;
        }
        Sleep(5);
    }
}
}

const char* measureTscRate(TscRate& rate, bool exactSources) {
    if (!cpuHasGoodTimestampCounter()) return "Windows CPU time requires an invariant TSC";
    if (!exactSources || (!referencePage(rate) && !cpuid15(rate))) calibrate(rate);
    return nullptr;
}
}
