/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "platform.h"
#include "engine.h"

class Writer;
class WindowsSoftwareProbe : public Engine {
    struct State;
    State* _state = nullptr;
    static LONG CALLBACK exception(EXCEPTION_POINTERS* pointers);
    static LONG CALLBACK resume(EXCEPTION_POINTERS* pointers);
    static bool enroll(HANDLE thread,DWORD tid);
    static const char* prepareThreads();
public:
    static bool accepts(const char* name);
    static bool failed();
    Error prepare(Arguments& args) override;
    Error start(Arguments& args) override;
    void stop() override;
    Error stopError();
    const char* type() override;
    const char* title() override { return "Native software probe hits"; }
    const char* units() override { return "events"; }
    int64_t interval() override;
    static void writeMetrics(Writer& out);
};
