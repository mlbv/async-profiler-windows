/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Standalone registry tests link the real threads_windows.cpp. Unrelated JVM,
// stack-walking and recorder paths must never be reached in this executable.
#include "platform.h"
#include "profiler.h"
#include "vmStructs.h"
#include "stackWalker.h"
#include "windowsBreakpoints.h"
#include <cstdlib>

JavaVM* VM::_vm = nullptr;
jvmtiEnv* VM::_jvmti = nullptr;
AsyncGetCallTrace VM::_asyncGetCallTrace = nullptr;
Profiler* const Profiler::_instance = nullptr;
const Error Error::OK(nullptr);
bool VMStructs::_has_native_thread_id = false;
jfieldID VMStructs::_eetop = nullptr;
intptr_t VMStructs::_env_offset = -1;
int VMStructs::_comp_env_offset = -1;
int VMStructs::_comp_task_offset = -1;
int VMStructs::_comp_method_offset = -1;

JNIEnv* VMThread::jni() { std::abort(); }
VMThread* VMThread::current() { std::abort(); }
int VMThread::osThreadId() { std::abort(); }
jmethodID VMMethod::validatedId() { std::abort(); }
const char* Profiler::findNativeMethod(const void*) { std::abort(); }
int StackWalker::walkDwarf(void*, const void**, int) { std::abort(); }
int StackWalker::walkFP(void*, const void**, int) { std::abort(); }
#if defined(ASPROF_CPU_IDENTITY_TEST)
ThreadState OS::threadState(int) { return THREAD_RUNNING; }
#else
ThreadState OS::threadState(int) { std::abort(); }
#endif
Writer& Writer::operator<<(const char*) { std::abort(); }
Writer& Writer::operator<<(char) { std::abort(); }
Writer& Writer::operator<<(u64) { std::abort(); }
namespace WindowsProfiler {
#if defined(ASPROF_CPU_IDENTITY_TEST)
namespace Breakpoints { bool handling(DWORD) { return false; } }
#else
void deliverSample(int, siginfo_t*, CONTEXT*) { std::abort(); }
namespace Breakpoints { bool handling(DWORD) { std::abort(); } }
#endif
}
