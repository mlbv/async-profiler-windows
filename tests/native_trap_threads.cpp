/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsTrapThreads.h"
#include "windowsProfiler.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

namespace TT = WindowsProfiler::TrapThreads;
namespace {
void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "TRAP_THREAD_FAILURE %s Windows=%lu\n", message, GetLastError()); std::exit(1); }
}
struct Job {
    bool retain = false, internal = false;
    TT::Identity expected{}, actual{};
    TT::Lease lease;
    bool passed = false;
};
DWORD WINAPI worker(void* argument) {
    auto& job = *static_cast<Job*>(argument);
    if (job.internal) WindowsProfiler::markInternalThread();
    auto lease = TT::current();
    require(lease && lease.identity() == job.expected, "Pre-enrolled birth was not found without TLS enrollment");
    require(lease.internal() == job.internal && lease.tryEnter(), "Birth internal/entry guard state leaked");
    require(lease.state().eventEpoch == 0 && lease.state().remainder == 0, "A new birth inherited old event state");
    lease.state().eventEpoch = 777; lease.state().remainder = 19;
    job.actual = lease.identity();
    job.passed = true;
    if (job.retain) job.lease = std::move(lease);
    return 0;
}
HANDLE launch(Job& job) {
    auto handle = CreateThread(nullptr, 0, worker, &job, CREATE_SUSPENDED, nullptr);
    require(handle != nullptr, "Cannot create private worker");
    require(TT::prepare(handle, &job.expected) == nullptr, "Cold birth enrollment failed");
    require(ResumeThread(handle) != DWORD(-1), "Cannot resume private worker");
    require(WaitForSingleObject(handle, 10000) == WAIT_OBJECT_0 && job.passed, "Worker did not finish its API checks");
    return handle;
}
DWORD WINAPI unknown(void*) {
    require(!TT::current(), "Unenrolled thread unexpectedly acquired state");
    return 0;
}
}

int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    TT::Identity identity;
    require(TT::prepare(GetCurrentThread(), &identity) == nullptr && identity.tid == GetCurrentThreadId()
            && identity.creation && identity.epoch, "Current thread cold enrollment/identity failed");
    {
        auto lease = TT::current();
        require(lease && lease.identity() == identity && !lease.internal() && lease.tryEnter(), "Current lease invalid");
        lease.state().eventEpoch = 91; lease.state().remainder = 3;
        auto nested = TT::current();
        require(nested && !nested.tryEnter(), "Nested callback acquired an owned guard");
        TT::Identity repeated;
        require(TT::prepare(GetCurrentThread(), &repeated) == nullptr && repeated == identity, "Repeated preparation changed live identity");
        require(lease.state().eventEpoch == 91 && lease.state().remainder == 3, "Repeated preparation reset event state");
    }
    {
        auto lease = TT::current();
        require(lease && lease.tryEnter() && lease.state().eventEpoch == 91 && lease.state().remainder == 3,
                "Guard release or retained stop state failed");
        require(TT::reapExited() == 0, "Live thread was reaped");
    }
    TT::Identity invalid{17,123,456,789};
    require(TT::prepare(nullptr, &invalid) != nullptr && invalid == TT::Identity{}, "Failed enrollment left a token");
    require(!TT::pin(TT::Identity{65536,1,1,1}), "Out-of-range token acquired state");
    auto wrongEpoch = identity; wrongEpoch.epoch++;
    auto wrongBirth = identity; wrongBirth.creation++;
    require(!TT::pin(wrongEpoch) && !TT::pin(wrongBirth), "A mismatched epoch/birth token acquired state");
    auto fresh = CreateThread(nullptr, 0, unknown, nullptr, 0, nullptr);
    require(fresh && WaitForSingleObject(fresh, 10000) == WAIT_OBJECT_0, "Unknown-thread API check failed");
    CloseHandle(fresh);

    Job retained; retained.retain = true;
    auto handle = launch(retained);
    CloseHandle(handle);
    // Only the real registry's retained handle now keeps the exited birth's ID
    // occupied. Reopening it must still identify that exact creation time.
    auto reopened = OpenThread(THREAD_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, retained.actual.tid);
    FILETIME born, ended, kernel, user;
    require(reopened && WaitForSingleObject(reopened, 0) == WAIT_OBJECT_0
            && GetThreadTimes(reopened, &born, &ended, &kernel, &user)
            && ((std::uint64_t(born.dwHighDateTime) << 32) | born.dwLowDateTime) == retained.actual.creation,
            "Registry did not retain the exited thread object's identity");
    CloseHandle(reopened);
    require(TT::reapExited() == 0 && retained.lease.state().remainder == 19, "Pinned dead birth was reclaimed");
    {
        auto second = TT::pin(retained.actual);
        require(second && !second.tryEnter(), "Moved retained guard lost exclusive ownership");
    }
    retained.lease.reset();
    require(TT::reapExited() == 1 && !TT::pin(retained.actual), "Released dead birth or stale token survived reap");

    Job raced;
    handle = launch(raced);
    std::atomic<bool> running{true}, bad{false};
    std::atomic<unsigned> pins{0}, stale{0};
    std::vector<std::thread> readers;
    for (unsigned i = 0; i < 4; ++i) readers.emplace_back([&] {
        unsigned iteration = 0;
        while (running.load(std::memory_order_acquire)) {
            {
                auto lease = TT::pin(raced.actual);
                if (lease) {
                    if (lease.identity() != raced.actual || lease.state().eventEpoch != 777 || lease.state().remainder != 19) bad = true;
                    pins.fetch_add(1, std::memory_order_relaxed);
                } else stale.fetch_add(1, std::memory_order_relaxed);
            }
            if (!(++iteration & 15)) std::this_thread::yield();
        }
    });
    auto deadline = GetTickCount64() + 3000;
    while (pins < 1000 && GetTickCount64() < deadline) Sleep(1);
    require(pins >= 1000, "Concurrent read pins were not exercised");
    size_t reaped = 0;
    for (unsigned i = 0; i < 64 && !reaped; ++i) reaped += TT::reapExited();
    while (stale == 0 && GetTickCount64() < deadline) Sleep(1);
    running.store(false, std::memory_order_release);
    for (auto& reader : readers) reader.join();
    require(reaped == 1 && pins >= 1000 && stale > 0 && !bad && !TT::pin(raced.actual),
            "Writer reservation/read-pin publication raced stale state");
    CloseHandle(handle);

    unsigned reusedSlots = 0;
    TT::Identity previous{};
    for (unsigned i = 0; i < 256; ++i) {
        Job job; job.internal = (i % 16) == 0;
        handle = launch(job);
        if (previous.epoch) {
            require(previous != job.actual && !TT::pin(previous), "A new birth accepted a stale identity");
            reusedSlots += previous.slot == job.actual.slot;
        }
        require(TT::reapExited() == 1, "Unpinned worker birth was not reclaimed");
        CloseHandle(handle); previous = job.actual;
    }
    require(TT::current() && TT::current().identity() == identity, "Churn invalidated live current state");
    std::printf("TRAP_THREADS_PASS pins=%u stale=%u concurrentReaped=%zu births=256 reusedSlots=%u nestedGuard=exclusive retainedStopState=1\n",
        pins.load(), stale.load(), reaped, reusedSlots);
}
