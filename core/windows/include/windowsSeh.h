/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

namespace WindowsProfiler {
// Clang implements only synchronous SEH for x86_64-w64-windows-gnu: a __try block covers faults raised in
// the calls it makes, not in its own loads. Code that may fault therefore runs through this non-inlined call.
template<class Body> __attribute__((noinline)) auto guarded(Body&& body) { return body(); }
}
