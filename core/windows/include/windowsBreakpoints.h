/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "platform.h"
#include "arguments.h"

namespace WindowsProfiler::Breakpoints {
constexpr unsigned NATIVE_PROBE = 4;
using Callback = void (*)(CONTEXT&, void*);
// Cold observer callbacks remain callable for process lifetime; a CreateThread
// already in progress may have retained one after observation is disabled.
using ThreadObserver = bool (*)(HANDLE, DWORD);
Error observeThreads(ThreadObserver observer);
void stopObservingThreads();
enum class Access : unsigned { Execute = 0, Write = 1, ReadWrite = 3 };
void initialize();
Error start(unsigned role, const void* address, Callback callback, void* parameter, Access access = Access::Execute, unsigned length = 1);
void stop(unsigned role);
bool failed();
unsigned activeTargets();
bool handling(DWORD tid);
// Consume every hit, including hits outside recording windows or output filters.
// The registry's per-thread Point lifetime supplies the counter's event epoch.
bool samplePeriod(unsigned role, std::uint64_t period);
}
