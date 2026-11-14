/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include "engine.h"


std::atomic<bool> Engine::_enabled{false};
std::atomic<uint64_t> Engine::_event_generation{0};

Error Engine::start(Arguments& args) {
    return Error::OK;
}

void Engine::stop() {
}
