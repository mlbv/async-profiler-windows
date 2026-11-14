/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "windowsSamplingTimer.h"
#include "windowsTscRate.h"
#include "itimer.h"
#include "os.h"
#include "profiler.h"
#include "log.h"
#include <bcrypt.h>
#include <map>
#include <algorithm>
#include <cstring>
#include <random>

namespace {
volatile bool running;
pthread_t sampler;
// Sleep follows the default system timer resolution, too coarse for 1 ms polls.
WindowsProfiler::SamplingTimer pollTimer;
u64 cpuInterval;
u64 pollInterval;
std::uint64_t pollSeed;
bool cycleCounter;
bool userOnlyCpu;
int cpuSignal;

// QueryThreadCycleTime counts invariant-TSC cycles.
WindowsProfiler::TscRate tscRate;

struct CpuTime { std::uint64_t creation = 0; u64 previous = 0; u64 pending = 0; u64 seen = 0; };
void* sampleCPU(void*) {
    WindowsProfiler::markInternalThread();
    std::map<int, CpuTime> cpu;
    // A per-poll system-wide process snapshot costs milliseconds; list this process only.
    ThreadList* threads = WindowsProfiler::listSamplingThreads();
    auto filter = Profiler::instance()->threadFilter();
    u64 nextRefresh = 0;
    u64 iteration = 0;
    // User-only CPU time is GetThreadTimes' user split; cycle counts include both modes.
    bool cycles = cycleCounter || !userOnlyCpu;
    // Each poll lands at a uniformly random point of its own pollInterval slot. The slots
    // keep the average period at the request although each timer wait ends on a system
    // timer tick, and the random phase keeps periodic workloads from staying between
    // polls: a sleeping thread is not sampled, and its pending time waits for a poll
    // that finds it running.
    std::mt19937_64 random(pollSeed);
    std::uniform_int_distribution<u64> phase(0, pollInterval - 1);
    u64 slot = OS::nanotime();
    while (running) {
        if (u32 error = WindowsProfiler::samplingThreadError()) {
            Log::error("Windows CPU thread snapshot failed: NTSTATUS 0x%08x", error);
            break;
        }
        ++iteration;
        u64 now = OS::nanotime();
        if (now >= nextRefresh) {
            WindowsProfiler::refreshModulesIfChanged();
            nextRefresh = now + 1000000000;
        }
        // A poll more than a slot late resumes the slots from now instead of catching up.
        slot = std::max(slot + pollInterval, now - pollInterval);
        u64 deadline = slot + phase(random);
        // A thread is sampled at the poll nearest its interval boundary, were it to keep
        // running: waiting for a full interval would take one poll more on average.
        u64 threshold = cycleCounter ? cpuInterval
            : cpuInterval - std::min(cpuInterval - 1, (deadline > now ? deadline - now : 0) / 2);
        while (running && threads->hasNext()) {
            int tid = threads->next();
            if (tid == OS::threadId() || (filter->enabled() && !filter->contains(tid))) continue;
            std::uint64_t count, creation;
            if (!WindowsProfiler::readThreadCounter(tid, cycles, count, creation, userOnlyCpu)) continue;
            if (cycles && !cycleCounter) count = tscRate.nanos(count);
            auto& state = cpu[tid];
            if (state.creation != creation || count < state.previous) state = {creation, count, 0, iteration};
            state.seen = iteration;
            state.pending += count - state.previous;
            state.previous = count;
            if (state.pending < threshold || OS::threadState(tid) == THREAD_SLEEPING) continue;
            WindowsProfiler::setSampleWeight(state.pending);
            if (WindowsProfiler::sampleThread(tid, cpuSignal, state.creation)) state.pending = 0;
        }
        for (auto it = cpu.begin(); it != cpu.end();) {
            if (it->second.seen != iteration) it = cpu.erase(it);
            else ++it;
        }
        if (!running) break;
        if (!pollTimer.waitUntil(deadline)) {
            if (running) Log::error("Windows CPU sampling timer failed: %u", pollTimer.error());
            break;
        }
        threads->update();
    }
    delete threads;
    return NULL;
}
}

Error ITimer::start(Arguments& args) {
    return startCounter(args, false);
}
Error ITimer::startCounter(Arguments& args, bool cycles) {
    if (args._interval < 0) return Error("interval must be positive");
    if (cycles && args._alluser) return Error("User-only cycle sampling requires an ETW source");
    if (!cycles && !args._alluser) {
        Error error(WindowsProfiler::measureTscRate(tscRate));
        if (error) return error;
    }
    cycleCounter = cycles;
    userOnlyCpu = args._alluser;
    _type = strcmp(args._event, EVENT_ITIMER) == 0 ? EVENT_ITIMER : strcmp(args._event, EVENT_CTIMER) == 0 ? EVENT_CTIMER : EVENT_CPU;
    cpuInterval = args._interval ? args._interval : cycles ? 1000000 : DEFAULT_INTERVAL;
    // Any interval is accepted; sampling cadence floors at the 1 ms poll and each
    // sample's weight is the thread's exact accumulated CPU time. CPU time is polled
    // on average every half interval, or an even fraction of it no longer than 50 ms:
    // with a poll per interval, two polls up to two slots apart would merge samples.
    // A cycle interval is a count threshold polled every 1 ms on average.
    pollInterval = cycles ? 1000000 : std::max<u64>(1000000, cpuInterval / (2 * ((cpuInterval + 99999999) / 100000000)));
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&pollSeed), sizeof(pollSeed), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return Error("Cannot seed the Windows CPU poll schedule");
    }
    cpuSignal = args._signal == 0 ? OS::getProfilingSignal(0) : args._signal & 0xff;
    if (!WindowsProfiler::validProfilingSignal(cpuSignal)) return Error("Windows profiling signal must be in the range 1..255");
    if (args._wall >= 0 && cpuSignal == (args._signal == 0 ? OS::getProfilingSignal(1)
            : (args._signal >> 8) > 0 ? args._signal >> 8 : args._signal)) {
        return Error("Simultaneous CPU and wall profiling requires distinct signals: signal=CPU/WALL");
    }
    _interval = cpuInterval; _cstack = args._cstack; _signal = cpuSignal; _count_overrun = false;
    auto error = WindowsProfiler::prepareSamplingThreads();
    if (!error) error = pollTimer.open();
    if (error) return error;
    OS::installSignalHandler(cpuSignal, signalHandler);
    running = true;
    if (pthread_create(&sampler, NULL, sampleCPU, NULL) != 0) {
        running = false; pollTimer.close();
        return Error("Cannot create Windows CPU sampler");
    }
    return Error::OK;
}
void ITimer::stop() {
    if (!running) return;
    running = false;
    pollTimer.cancel();
    pthread_join(sampler, NULL);
    pollTimer.close();
}
