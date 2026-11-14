/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "platform.h"

namespace WindowsProfiler {
// An eagerly initialized OS lock; acquisition never initializes a CRT mutex.
class WindowsMutex {
    SRWLOCK _lock = SRWLOCK_INIT;
public:
    void lock() { AcquireSRWLockExclusive(&_lock); }
    void unlock() { ReleaseSRWLockExclusive(&_lock); }
};
}
