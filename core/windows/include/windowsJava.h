/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "platform.h"
#include "vmEntry.h"
#include <string>
#include <vector>

class Writer;
class Error;
namespace WindowsProfiler::Java {
struct Method {
    std::string klass, name, signature;
    jint modifiers = 0;
    std::vector<jvmtiLineNumberEntry> lines;
};
const Method* metadata(jmethodID id);
void reset();
Error start();
void stop();
void loaded(jvmtiEnv* ti, jmethodID method, jint size, const void* code,
            jint count, const jvmtiAddrLocationMap* locations, const void* info);
void unloaded(jmethodID method, const void* code);
void prepared(jvmtiEnv* ti, JNIEnv* env, jclass klass);
void beginClassChange() noexcept;
void endClassChange() noexcept;
void generated(const void* code, int size, const char* name);
int decode(std::uint64_t pc, std::uint64_t timestamp, ASGCT_CallFrame* frames, int capacity, bool& truncated,
    bool generated = true, bool* bytecode = nullptr);
void writeMetrics(Writer& out);
}
