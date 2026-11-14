/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "platform.h"
#include <jvmti.h>
#include "asprof.h"
#include <string>
#include <string_view>
#include <vector>

class VMThread;
class Writer;
class Dictionary;
namespace WindowsProfiler {
inline std::uint64_t queryPerformanceCounter() {
    LARGE_INTEGER value;
    QueryPerformanceCounter(&value);
    return static_cast<std::uint64_t>(value.QuadPart);
}
// Windows routes profiler callbacks internally instead of raising POSIX signals.
constexpr int MAX_PROFILING_SIGNAL = 255;
inline bool validProfilingSignal(int signal) { return signal > 0 && signal <= MAX_PROFILING_SIGNAL; }
std::wstring wide(std::string_view value);
std::string utf8(std::wstring_view value);
std::string modifiedUtf8(std::string_view value);
unsigned lookupJavaClass(Dictionary* classes, std::string_view value, bool descriptor = false);
HMODULE selfModule();
void ioError(DWORD error);
bool capturingThread();
int sampledThreadId();
int sampledThreadState();
// OS::threadFingerprint of the thread being sampled.
std::uint64_t sampledThreadFingerprint();
std::uint64_t threadFingerprint(HANDLE thread);
VMThread* sampledVMThread();
JNIEnv* sampledJNI();
void resumeSamplingTarget();
bool sampleThread(int tid, int signal);
// The opened thread must have this exact nonzero creation time.
bool sampleThread(int tid, int signal, std::uint64_t expectedCreation);
void registerJavaThread(JNIEnv* env, jthread thread);
void unregisterJavaThread(JNIEnv* env, jthread thread);
void registerExistingJavaThreads(JNIEnv* env);
asprof_thread_local_data* threadData(bool create);
void markSample(int tid, std::uint64_t timestamp);
void markExternalSample(int tid, std::uint64_t timestamp, std::uint64_t captureQpc);
bool isInternalThread(int tid);
void deliverSample(int signal, siginfo_t* info, CONTEXT* context);
void markInternalThread();
void setSampleWeight(std::uint64_t value);
std::uint64_t sampleWeight();
bool readThreadCounter(int tid, bool cycles, std::uint64_t& value, std::uint64_t& creation, bool userOnly = false);
void captureContext(CONTEXT& context);
// The committed stack [StackLimit, StackBase) of the thread being walked: the sampled
// thread during a capture from another thread, otherwise the current thread.
void stackLimits(std::uintptr_t& low, std::uintptr_t& high);
bool installLibraryHooks();
const char* importFailure();
void enableLibraryTracking(bool enabled);
const void* resolveSymbol(const char* name);
// Uses already loaded exports/PDB symbols without activating DLL forwarders.
const void* resolveLoadedSymbol(const char* name);
bool modulesChanged();
bool moduleTrackingAvailable();
void allocatorModuleUnloaded(void* base);
void refreshModulesIfChanged();
void writeSymbolMetrics(Writer& out);
HANDLE toolhelpSnapshot(DWORD flags, DWORD pid);
void writeSnapshotMetrics(Writer& out);
void kernelImageChanged(std::uint64_t base, ULONG size, ULONG checksum, bool unloaded, bool rundown);
void requestKernelSymbols(bool needed);
PRUNTIME_FUNCTION lookupFunctionEntry(DWORD64 pc, DWORD64* imageBase);
// For a JVM whose threads are unnamed: whether jvm.dll's version proves JNI_GetCreatedJavaVMs returned a created VM.
bool createdJvmAttachable(const void* getCreatedJavaVMs);

class SymbolResolutionScope {
    SymbolResolutionScope* _previous;
    std::vector<HMODULE> _retained;
public:
    SymbolResolutionScope();
    ~SymbolResolutionScope();
    void retain(HMODULE module);
};
}
