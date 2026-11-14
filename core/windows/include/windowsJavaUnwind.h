/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "platform.h"
#include "windowsCfiHistory.h"
class Error;
class NMethod;
class Writer;
namespace WindowsProfiler::JavaUnwind {
Error start();
void stop();
void compiled(const void* code, int size, NMethod* method, bool publish);
void unloaded(const void* code, bool publish, std::uint64_t timestamp);
struct Metadata { size_t methodLife; size_t bytecodeLife; };
Metadata metadata(const void* method, const void* bytecode, int size, bool publish);
bool metadataAlive(size_t lifetime, std::uint64_t time);
void generated(const void* code, int size, const char* name, bool publish);
bool publish();
bool incomplete(std::uint64_t pc);
Certainty certainty(std::uint64_t pc,std::uint64_t timestamp,bool knownManaged,bool metadataDecoded);
const char* firstError();
void writeMetrics(Writer& out);
}
