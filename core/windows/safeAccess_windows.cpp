/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "safeAccess.h"
#include "threadLocalData.h"
#include "windowsSeh.h"

void* SafeAccess::load(void** address, void* fallback) {
    __try { return WindowsProfiler::guarded([&] { return *address; }); }
    __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION || GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR
            ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return fallback; }
}
int32_t SafeAccess::load32(int32_t* address, int32_t fallback) {
    __try { return WindowsProfiler::guarded([&] { return *address; }); }
    __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION || GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR
            ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) { return fallback; }
}
bool SafeAccess::checkFault(StackFrame&) { return false; }
asprof_thread_local_data* ThreadLocalData::getIfPresent() { return WindowsProfiler::threadData(false); }
asprof_thread_local_data* ThreadLocalData::get() { return WindowsProfiler::threadData(true); }
