/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Reuse the existing argument target and profiling-window boundary functions.
#include "native_probe_arguments.cpp"
#include "native_memory_fixture.cpp"

namespace {
void periodRequire(bool value) { if (!value) std::abort(); }

std::uint64_t periodCalls(unsigned count, std::uint64_t first) {
    std::uint64_t result = 0;
    for (unsigned i = 0; i < count; ++i) result += ProbeArgumentsWork(first + i, 11, 13, 17);
    return result;
}

struct PeriodJob {
    unsigned count;
    std::uint64_t first, result;
    HANDLE start, done, release;
};

DWORD WINAPI periodWorker(void* argument) {
    auto& job = *static_cast<PeriodJob*>(argument);
    periodRequire(WaitForSingleObject(job.start, 10000) == WAIT_OBJECT_0);
    job.result = periodCalls(job.count, job.first);
    periodRequire(SetEvent(job.done) != FALSE);
    periodRequire(WaitForSingleObject(job.release, 10000) == WAIT_OBJECT_0);
    return 0;
}
}

extern "C" JNIEXPORT jlong JNICALL Java_NativeProbePeriod_calls(JNIEnv*, jclass, jint count, jlong first) {
    return static_cast<jlong>(periodCalls(static_cast<unsigned>(count), static_cast<std::uint64_t>(first)));
}

extern "C" JNIEXPORT jlong JNICALL Java_NativeProbePeriod_uneven(JNIEnv*, jclass) {
    auto release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    PeriodJob jobs[2]{{3,101,0,CreateEventW(nullptr,TRUE,FALSE,nullptr),CreateEventW(nullptr,TRUE,FALSE,nullptr),release},
                      {7,201,0,CreateEventW(nullptr,TRUE,FALSE,nullptr),CreateEventW(nullptr,TRUE,FALSE,nullptr),release}};
    HANDLE threads[2]{};
    periodRequire(release != nullptr);
    for (unsigned i = 0; i < 2; ++i) {
        periodRequire(jobs[i].start && jobs[i].done);
        threads[i] = CreateThread(nullptr, 0, periodWorker, &jobs[i], 0, nullptr);
        periodRequire(threads[i] != nullptr);
    }
    // Both workers remain alive. The first finishes its three hits before the
    // second performs seven, so global-modulo arguments would be 202 and 207.
    for (auto& job : jobs) {
        periodRequire(SetEvent(job.start) != FALSE);
        periodRequire(WaitForSingleObject(job.done, 10000) == WAIT_OBJECT_0);
    }
    periodRequire(SetEvent(release) != FALSE);
    periodRequire(WaitForMultipleObjects(2, threads, TRUE, 10000) == WAIT_OBJECT_0);
    for (unsigned i = 0; i < 2; ++i) { CloseHandle(threads[i]); CloseHandle(jobs[i].start); CloseHandle(jobs[i].done); }
    CloseHandle(release);
    return static_cast<jlong>(jobs[0].result + jobs[1].result);
}

extern "C" JNIEXPORT jlong JNICALL Java_NativeProbePeriod_windows(JNIEnv*, jclass) {
    std::uint64_t result = periodCalls(2,101);
    for (unsigned window = 0; window < 2; ++window) {
        periodRequire(WindowBegin(1) == 18);
        result += periodCalls(3,201 + window * 200);
        periodRequire(WindowEnd(1) == 20);
        if (window == 0) result += periodCalls(2,301);
    }
    return static_cast<jlong>(result);
}
