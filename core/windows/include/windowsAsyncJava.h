/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "vmEntry.h"
#include "arguments.h"

class Writer;
namespace WindowsProfiler {
struct AsyncNativeStack {
    const void** frames;
    int capacity;
    CStack mode;
    int count = 0;
    uintptr_t pc = 0;
    jmethodID compilerMethod = NULL;
};
Error prepareAsyncJavaTrace();
Error prepareCompilerTrace();
int captureJavaAsync(ASGCT_CallTrace* trace, int maximum, AsyncNativeStack& native, bool verifyJNI);
int captureCompilerAsync(AsyncNativeStack& native);
void writeAsyncJavaMetrics(Writer& out);
}
