/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "engine.h"

class Writer;
class WindowsTracepointEngine : public Engine {
    struct State;
    State* _state = nullptr;
public:
    static bool accepts(const char* event);
    Error prepare(Arguments& args) override;
    Error start(Arguments& args) override;
    void stop() override;
    Error stopError();
    void enableEvents(bool enabled) override;
    const char* type() override { return "windows_tracepoint"; }
    const char* title() override { return "Windows tracepoint profile"; }
    const char* units() override { return "events"; }
    int64_t interval() override;
    void writeMetrics(Writer& out);
};
