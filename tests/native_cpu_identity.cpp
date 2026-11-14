/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsProfiler.h"
#include "windowsTrapThreads.h"
#include "os.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>

namespace TT = WindowsProfiler::TrapThreads;
namespace {
std::atomic<unsigned> checks;
unsigned deliveries;
DWORD expectedTid;
int expectedSignal;
std::uint64_t expectedWeight;
CONTEXT observed{};
void require(bool condition,const char* message) {
    ++checks;
    if (!condition) {
        std::fprintf(stderr,"CPU_IDENTITY_FAILURE %s Windows=%lu\n",message,GetLastError());
        std::exit(1);
    }
}
void await(HANDLE event) {
    require(WaitForSingleObject(event,10000) == WAIT_OBJECT_0,"Owned worker did not complete its event handshake");
}
DWORD handles() {
    DWORD count;
    require(GetProcessHandleCount(GetCurrentProcess(),&count) != FALSE,"Cannot query owned test handle count");
    return count;
}
void idle() {
    require(!WindowsProfiler::capturingThread() && WindowsProfiler::sampledThreadId() == 0
        && WindowsProfiler::sampledVMThread() == nullptr,"Capture state escaped its lifetime");
}
struct Worker {
    HANDLE ready, inspect, inspected, stop;
    TT::Identity identity{};
};
DWORD WINAPI worker(void* argument) {
    auto& state = *static_cast<Worker*>(argument);
    require(!TT::current(),"Rejected birth was enrolled before identity validation");
    require(SetEvent(state.ready) != FALSE,"Cannot acknowledge unenrolled worker");
    await(state.inspect);
    {
        auto lease = TT::current();
        require(lease && !lease.internal() && lease.tryEnter(),"Matched capture did not enroll the owned birth");
        state.identity = lease.identity();
        lease.state().remainder = 73;
    }
    require(SetEvent(state.inspected) != FALSE,"Cannot acknowledge matched enrollment");
    await(state.stop);
    return 0;
}
}
namespace WindowsProfiler {
void deliverSample(int signal,siginfo_t* info,CONTEXT* context) {
    require(capturingThread() && sampledThreadId() == static_cast<int>(expectedTid)
        && sampledThreadState() == THREAD_RUNNING,"Sample delivered outside the exact owned capture");
    require(signal == expectedSignal && info && info->si_signo == expectedSignal
        && sampleWeight() == expectedWeight,"Sample signal or pending weight changed");
    require(context && (context->ContextFlags & CONTEXT_FULL) == CONTEXT_FULL
        && context->Rip && context->Rsp,"Real thread context was not delivered");
    require(sampledVMThread() == nullptr && sampledJNI() == nullptr,"Owned native worker acquired a JVM identity");
    observed = *context;
    ++deliveries;
}
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    auto initialHandles = handles();
    Worker state{CreateEventW(nullptr,TRUE,FALSE,nullptr),CreateEventW(nullptr,TRUE,FALSE,nullptr),
        CreateEventW(nullptr,TRUE,FALSE,nullptr),CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    require(state.ready && state.inspect && state.inspected && state.stop,"Cannot create owned worker handshake");
    auto thread = CreateThread(nullptr,0,worker,&state,CREATE_SUSPENDED,&expectedTid);
    require(thread && expectedTid,"Cannot create suspended owned target");
    FILETIME birth, ended, kernel, user;
    require(GetThreadTimes(thread,&birth,&ended,&kernel,&user) != FALSE,"Cannot query exact owned birth");
    auto creation = (std::uint64_t(birth.dwHighDateTime) << 32) | birth.dwLowDateTime;
    require(creation && creation != UINT64_MAX,"Owned target has no usable creation identity");
    auto ownedHandles = handles();
    expectedSignal = SIGPROF;
    expectedWeight = 7919;
    WindowsProfiler::setSampleWeight(expectedWeight);
    require(!WindowsProfiler::sampleThread(expectedTid,expectedSignal,creation + 1),"Mismatched CPU birth was captured");
    require(!WindowsProfiler::sampleThread(expectedTid,expectedSignal,std::uint64_t{0}),"Zero expected birth became unconstrained");
    require(deliveries == 0 && WindowsProfiler::sampleWeight() == expectedWeight,"Rejected capture delivered or consumed pending weight");
    require(handles() == ownedHandles,"Rejected capture leaked a thread handle");
    idle();
    require(ResumeThread(thread) == 1,"Rejected capture changed the owned suspension count");
    await(state.ready);
    require(WindowsProfiler::sampleThread(expectedTid,expectedSignal,creation),"Matching CPU birth was not captured");
    require(deliveries == 1 && observed.Rip && observed.Rsp,"Matching capture lost its native context");
    idle();
    require(SetEvent(state.inspect) != FALSE,"Cannot inspect retained birth");
    await(state.inspected);
    require(state.identity.tid == expectedTid && state.identity.creation == creation && state.identity.epoch,
        "Registry duplicate retained another birth");
    {
        auto lease = TT::pin(state.identity);
        require(lease && lease.state().remainder == 73,"Capture enrollment did not preserve registry identity");
    }
    auto retainedHandles = handles();
    require(retainedHandles == ownedHandles + 1,"Matched capture did not retain exactly one registry handle");
    expectedWeight = 104729;
    WindowsProfiler::setSampleWeight(expectedWeight);
    require(!WindowsProfiler::sampleThread(expectedTid,expectedSignal,creation + 1)
        && !WindowsProfiler::sampleThread(expectedTid,expectedSignal,std::uint64_t{0}),
        "Retained slot bypassed expected-birth validation");
    require(deliveries == 1 && WindowsProfiler::sampleWeight() == expectedWeight,"Retained mismatch delivered or consumed pending weight");
    require(WindowsProfiler::sampleThread(expectedTid,expectedSignal,creation),"Mismatch poisoned the next matched CPU capture");
    require(deliveries == 2,"Subsequent matching CPU sample did not deliver once");
    idle();
    expectedSignal = SIGVTALRM;
    expectedWeight = 1;
    WindowsProfiler::setSampleWeight(expectedWeight);
    require(WindowsProfiler::sampleThread(expectedTid,expectedSignal),"Legacy two-argument wall capture regressed");
    require(deliveries == 3 && handles() == retainedHandles,"Wall capture changed deliveries or retained handles");
    idle();
    require(SetEvent(state.stop) != FALSE,"Cannot finish owned worker");
    await(thread);
    require(!WindowsProfiler::sampleThread(expectedTid,SIGPROF,creation)
        && !WindowsProfiler::sampleThread(expectedTid,SIGVTALRM),"Terminated target was captured");
    require(deliveries == 3 && handles() == retainedHandles,"Terminated capture delivered or leaked a handle");
    idle();
    require(TT::reapExited() == 1 && !TT::pin(state.identity),"Failed capture retained a dead registry reader");
    require(handles() == ownedHandles,"Dead registry handle was not released");
    require(CloseHandle(thread) && CloseHandle(state.ready) && CloseHandle(state.inspect)
        && CloseHandle(state.inspected) && CloseHandle(state.stop),"Cannot close owned test handles");
    require(handles() == initialHandles,"Owned identity test leaked a handle");
    std::printf("CPU_IDENTITY_PASS checks=%u deliveries=%u mismatchRejected=1 zeroRejected=1 matchedRecovery=1 wallCompatible=1 terminatedClean=1\n",
        checks.load(),deliveries);
}
