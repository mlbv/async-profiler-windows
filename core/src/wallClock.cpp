/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include <map>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "wallClock.h"
#include "mutex.h"
#include "profiler.h"
#include "stackFrame.h"
#include "tsc.h"


// Maximum number of threads sampled in one iteration. This limit serves as a throttle
// when generating profiling signals. Otherwise applications with too many threads may
// suffer from a big profiling overhead. Also, keeping this limit low enough helps
// to avoid contention on a spin lock inside Profiler::recordSample().
const int THREADS_PER_TICK = 8;

// Set the hard limit for thread walking interval to 100 microseconds.
// Smaller intervals are practically unusable due to large overhead.
const long long MIN_INTERVAL = 100000;

// A thread that ran for less than IDLE_THRESHOLD_NS since last iteration is considered idle.
const u64 IDLE_THRESHOLD_NS = 10000;

#ifndef _WIN32
// Maximum amount of CPU time a thread may spend to be eligible for wall clock event batching.
const u64 BATCH_CPU_THRESHOLD_NS = 500000;
#endif

// How many skipped idle samples can be recorded in a single WallClock event.
const u32 MAX_IDLE_BATCH = 1000;


struct ThreadSleepState {
    u64 generation;
    u64 start_time;
    u64 last_time;
    u64 last_cpu_time;
    u64 fingerprint;
    u32 call_trace_id;
    u32 counter;
};

typedef std::map<int, ThreadSleepState> ThreadSleepMap;

struct ThreadCpuTime {
    u64 generation;
    u64 cpu_time;
    u64 fingerprint;
    u64 trace;
};

// MPSC ring buffer
class ThreadCpuTimeBuffer {
  private:
    enum {
        RINGBUF_SIZE = 256,
        PAD_SIZE = 128
    };

    char _pad0[PAD_SIZE];  // protection against false sharing
    volatile u32 _write_ptr;
    char _pad1[PAD_SIZE - sizeof(u32)];
    u32 _read_ptr;
    char _pad2[PAD_SIZE - sizeof(u32)];
    ThreadCpuTime _ringbuf[RINGBUF_SIZE];

  public:
    ThreadCpuTimeBuffer() : _ringbuf(), _write_ptr(0), _read_ptr(0) {
    }

    void reset() {
        memset(_ringbuf, 0, sizeof(_ringbuf));
        _read_ptr = 0;
        storeRelease(_write_ptr, 0);
    }

    void add(u64 fingerprint, u64 trace, u64 generation, u64 cpu_time) {
        ThreadCpuTime& t = _ringbuf[atomicInc(_write_ptr) & (RINGBUF_SIZE - 1)];
        t.fingerprint = fingerprint;
        t.trace = trace;
        t.generation = generation;
        storeRelease(t.cpu_time, cpu_time);
    }

    void drain(ThreadSleepMap& thread_sleep_state, u64 generation) {
        u64 read_limit = _read_ptr + RINGBUF_SIZE;
        do {
            ThreadCpuTime& t = _ringbuf[_read_ptr & (RINGBUF_SIZE - 1)];
            u64 cpu_time = loadAcquire(t.cpu_time);
            if (cpu_time == 0) {
                break;
            }

            u64 fingerprint = t.fingerprint;
            u64 trace = t.trace;
            u64 packet_generation = t.generation;
            if (__sync_bool_compare_and_swap(&t.cpu_time, cpu_time, 0)) {
                if (packet_generation == generation) {
                    int thread_id = trace >> 32;
                    ThreadSleepState& tss = thread_sleep_state[thread_id];
                    tss.generation = generation;
                    tss.last_cpu_time = cpu_time;
                    tss.fingerprint = fingerprint;
                    tss.call_trace_id = (u32)trace;
                    tss.counter = 0;
                }
                _read_ptr++;
            }
        } while (_read_ptr < read_limit);
    }
};

static ThreadCpuTimeBuffer _thread_cpu_time_buf;
static ThreadSleepMap _thread_sleep_state;
static Mutex _thread_sleep_state_lock;


int64_t WallClock::_interval;
int WallClock::_signal;
WallClock::Mode WallClock::_mode;

// Gets fingerprint (as in OS::threadFingerprint) from the signal context of the current thread.
// Fingerprint is zero for running threads and non-zero for threads blocked on a syscall.
u64 WallClock::getThreadFingerprint(void* ucontext) {
#ifdef _WIN32
    return WindowsProfiler::sampledThreadFingerprint();
#endif
    StackFrame frame(ucontext);
    uintptr_t pc = frame.pc();

    // Consider a thread sleeping, if it has been interrupted in the middle of syscall execution,
    // either when PC points to the syscall instruction, or if syscall has just returned with EINTR
    if (StackFrame::isSyscall((instruction_t*)pc)) {
        return ((u64)frame.sp() << 32) ^ (pc + SYSCALL_SIZE);
    }

    // Make sure the previous instruction address is readable
    uintptr_t prev_pc = pc - SYSCALL_SIZE;
    if ((pc & 0xfff) >= SYSCALL_SIZE || Profiler::instance()->findLibraryByAddress((instruction_t*)prev_pc) != NULL) {
        if (StackFrame::isSyscall((instruction_t*)prev_pc) && frame.checkInterruptedSyscall()) {
            return ((u64)frame.sp() << 32) ^ pc;
        }
    }

    return 0;
}

void WallClock::signalHandler(int signo, siginfo_t* siginfo, void* ucontext) {
    auto generation = sampleGeneration();
    if (!canSample(generation)) return;
    u64 start_time = TSC::ticks();
    if (_mode == WALL_BATCH) {
        u64 fingerprint = getThreadFingerprint(ucontext);
#ifdef _WIN32
        // recordSample resumes the target before storing the trace and event.
        u64 cpu_time = fingerprint != 0 ? OS::threadCpuTime(0) : 0;
#endif
        WallClockEvent event;
        event._start_time = start_time;
        event._time_span = 0;
        event._thread_state = fingerprint == 0 ? THREAD_RUNNING : THREAD_SLEEPING;
        event._samples = 1;
        if (!canSample(generation)) return;
        u64 trace = Profiler::instance()->recordSample(ucontext, _interval, WALL_CLOCK_SAMPLE, &event);
        if (fingerprint != 0 && trace != 0) {
#ifndef _WIN32
            u64 cpu_time = OS::threadCpuTime(0);
#endif
            _thread_cpu_time_buf.add(fingerprint, trace, generation, cpu_time);
        }
    } else {
        ExecutionEvent event(start_time);
        if (_mode != CPU_ONLY) {
            event._thread_state = getThreadFingerprint(ucontext) == 0 ? THREAD_RUNNING : THREAD_SLEEPING;
        }
        if (!canSample(generation)) return;
        Profiler::instance()->recordSample(ucontext, _interval, EXECUTION_SAMPLE, &event);
    }
}

void WallClock::recordWallClock(const ThreadSleepState& tss, ThreadState state, int tid) {
    WallClockEvent event;
    event._start_time = tss.start_time;
    event._time_span = tss.last_time - tss.start_time;
    event._thread_state = state;
    event._samples = tss.counter;
    Profiler::instance()->recordExternalSamples(tss.counter, tss.counter * _interval, tid, tss.call_trace_id, WALL_CLOCK_SAMPLE, &event);
}

Error WallClock::start(Arguments& args) {
    if (args._wall >= 0 || strcmp(args._event, EVENT_WALL) == 0) {
        _mode = args._nobatch ? WALL_LEGACY : WALL_BATCH;
    } else {
        _mode = CPU_ONLY;
    }

    _interval = args._wall >= 0 ? args._wall : args._interval;
    if (_interval == 0) {
        // Increase default interval for wall clock mode due to larger number of sampled threads
        _interval = _mode == CPU_ONLY ? DEFAULT_INTERVAL : DEFAULT_INTERVAL * 5;
    }

    _signal = args._signal == 0 ? OS::getProfilingSignal(1)
                                : ((args._signal >> 8) > 0 ? args._signal >> 8 : args._signal);
#ifdef _WIN32
    if (!WindowsProfiler::validProfilingSignal(_signal)) return Error("Windows profiling signal must be in the range 1..255");
#endif
    OS::installSignalHandler(_signal, signalHandler);

#ifdef _WIN32
    Error clock_error = WindowsProfiler::prepareThreadCpuClock();
    if (clock_error) return clock_error;
    Error snapshot_error = WindowsProfiler::prepareSamplingThreads();
    if (snapshot_error) return snapshot_error;
    Error timer_error = _timer.open();
    if (timer_error) return timer_error;
#endif
    _running = true;

    if (pthread_create(&_thread, NULL, threadEntry, this) != 0) {
        _running = false;
#ifdef _WIN32
        _timer.close();
#endif
        return Error("Unable to create timer thread");
    }

    return Error::OK;
}

void WallClock::stop() {
    _running = false;
#ifdef _WIN32
    _timer.cancel();
#else
    pthread_kill(_thread, WAKEUP_SIGNAL);
#endif
    pthread_join(_thread, NULL);
#ifdef _WIN32
    _timer.close();
#endif
}

bool WallClock::waitForTimer(u64 nanos) {
#ifdef _WIN32
    if (_timer.wait(nanos)) return true;
    if (_running) {
        _running = false;
        Log::error("Windows wall-clock sampling timer failed: %u", _timer.error());
    }
    return false;
#else
    OS::uninterruptibleSleep(nanos, &_running);
    return _running;
#endif
}

void WallClock::flush() {
    if (_mode != WALL_BATCH) return;

    MutexLocker ml(_thread_sleep_state_lock);
    for (ThreadSleepMap::iterator it = _thread_sleep_state.begin(); it != _thread_sleep_state.end(); ++it) {
        if (it->second.counter != 0) {
            recordWallClock(it->second, THREAD_SLEEPING, it->first);
            it->second.counter = 0;
        }
    }
}

void WallClock::timerLoop() {
#ifdef _WIN32
    WindowsProfiler::markInternalThread();
#endif
    int self = OS::threadId();
    ThreadFilter* thread_filter = Profiler::instance()->threadFilter();
    bool thread_filter_enabled = thread_filter->enabled();
    Mode mode = _mode;

#ifdef _WIN32
    ThreadList* thread_list = WindowsProfiler::listSamplingThreads();
#else
    ThreadList* thread_list = OS::listThreads();
#endif
    _thread_cpu_time_buf.reset();
#ifdef _WIN32
    // A Windows timer wait can end up to one timer period after its deadline, so a
    // slot of the cycle needs two periods. Larger groups keep every thread sampled
    // once per interval when interval / slot is below upstream's group count.
    u64 timer_period = _timer.measurePeriod();
    if (timer_period == 0) {
        if (_running) Log::error("Windows wall-clock sampling timer failed: %u", _timer.error());
        _running = false;
    }
    u64 slots = timer_period ? std::max<u64>(1, (u64)_interval / (2 * timer_period)) : 1;
#endif
    u64 cycle_start_time = OS::nanotime();

    while (_running) {
#ifdef _WIN32
        if (u32 error = WindowsProfiler::samplingThreadError()) {
            Log::error("Windows wall-clock thread snapshot failed: NTSTATUS 0x%08x", error);
            _running = false;
            break;
        }
        WindowsProfiler::refreshModulesIfChanged();
#endif
        u64 generation = sampleGeneration();
        bool enabled = canSample(generation);

#ifdef _WIN32
        int threads_per_tick = std::max<int>(THREADS_PER_TICK, (thread_list->count() + slots - 1) / slots);
#else
        const int threads_per_tick = THREADS_PER_TICK;
#endif
        for (int signaled_threads = 0; signaled_threads < threads_per_tick && thread_list->hasNext(); ) {
            int thread_id = thread_list->next();
            if (thread_id == self || thread_id <= 0) {
                // On macOS, task_threads() may sporadically return 0 or -1 among thread IDs
                continue;
            }
            if (thread_filter_enabled && !thread_filter->contains(thread_id)) {
                continue;
            }

            if (mode == CPU_ONLY) {
                if (!enabled || OS::threadState(thread_id) == THREAD_SLEEPING) {
                    continue;
                }
            } else if (mode == WALL_BATCH) {
                MutexLocker ml(_thread_sleep_state_lock);
                ThreadSleepState& tss = _thread_sleep_state[thread_id];
                if (tss.generation != generation) {
                    if (tss.counter != 0) recordWallClock(tss, THREAD_SLEEPING, thread_id);
                    tss = {};
                    tss.generation = generation;
                }
                enabled = enabled && canSample(generation);
                if (enabled && tss.last_cpu_time != 0) {
                    u64 cpu_time_delta = OS::threadCpuTime(thread_id) - tss.last_cpu_time;
                    // Fast check: thread has not spent enough CPU time since last sampling
                    bool idle = cpu_time_delta <= IDLE_THRESHOLD_NS;
#ifndef _WIN32
                    // 2nd level check: thread spent some CPU time, but is now blocked on the same syscall
                    if (!idle && cpu_time_delta <= BATCH_CPU_THRESHOLD_NS &&
                            tss.fingerprint != 0 && OS::threadFingerprint(thread_id) == tss.fingerprint) {
                        tss.last_cpu_time += cpu_time_delta;
                        idle = true;
                    }
#else
                    // Windows has no EINTR wakeup, and its syscall number/argument fingerprint
                    // cannot distinguish successive waits reached through different Java frames.
#endif
                    // Fingerprint check is one-shot protection from EINTR wakeup.
                    // We still need to detect genuine wakeups.
                    tss.fingerprint = 0;

                    if (idle) {
                        u64 timestamp = TSC::ticks();
                        if (canSample(generation)) {
                            tss.last_time = timestamp;
                            if (++tss.counter < MAX_IDLE_BATCH) {
                                if (tss.counter == 1) {
                                    tss.start_time = tss.last_time;
                                }
                                continue;
                            }
                        }
                    } else {
                        tss.last_cpu_time = 0;
                    }
                }
                if (tss.counter != 0) {
                    recordWallClock(tss, THREAD_SLEEPING, thread_id);
                    tss.counter = 0;
                }
            }

            if (enabled && canSample(generation) && OS::sendSignalToThread(thread_id, _signal)) {
                signaled_threads++;
            }
        }

        u64 current_time = OS::nanotime();
        if (thread_list->hasNext()) {
            // Try to keep interval stable regardless of the number of profiled threads
            long long sleep_time = cycle_start_time + (u64)_interval * thread_list->index() / thread_list->count() - current_time;
            if (!waitForTimer(sleep_time < MIN_INTERVAL ? MIN_INTERVAL : sleep_time)) break;
        } else {
            // Cycle has ended: prepare for the next cycle
            cycle_start_time += (u64)_interval;
            long long sleep_time = cycle_start_time - current_time;
            if (sleep_time < MIN_INTERVAL) {
                cycle_start_time = current_time + MIN_INTERVAL;
                sleep_time = MIN_INTERVAL;
            }
            if (!waitForTimer(sleep_time)) break;
            thread_list->update();
        }

        // Sync thread CPU times updated since the previous iteration
        MutexLocker ml(_thread_sleep_state_lock);
        _thread_cpu_time_buf.drain(_thread_sleep_state, sampleGeneration());
    }

    delete thread_list;

    flush();
    _thread_sleep_state.clear();
}
