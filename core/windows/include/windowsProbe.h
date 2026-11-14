/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "engine.h"

class Writer;
class WindowsProbe : public Engine {
  protected:
    Error prepareProbe(Arguments& args, bool memory);
    static unsigned _counterArg;
  private:
    static int64_t _interval;
    const void* _address = nullptr;
    unsigned _access = 0, _length = 1;
public:
    const char* type() override { return "windows_probe"; }
    const char* title() override { return "Native function calls"; }
    const char* units() override { return _counterArg ? "total" : "calls"; }
    int64_t interval() override { return _interval; }
    Error prepare(Arguments& args) override { return prepareProbe(args, false); }
    Error start(Arguments& args) override;
    void stop() override;
    static void initialize();
    static void record(CONTEXT& context);
    static void writeMetrics(Writer& out);
};

class WindowsWatchpoint : public WindowsProbe {
public:
    const char* type() override { return "memory_access"; }
    const char* title() override { return "Memory access profile"; }
    const char* units() override { return _counterArg ? "total" : "events"; }
    Error prepare(Arguments& args) override { return prepareProbe(args, true); }
};
