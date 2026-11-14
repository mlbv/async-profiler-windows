/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>

namespace WindowsProfiler {
class Privilege {
    const WCHAR* _name;
    HANDLE _token = nullptr;
    TOKEN_PRIVILEGES _previous{};
    bool _changed = false;
public:
    explicit Privilege(const WCHAR* name) : _name(name) {}
    Privilege(const Privilege&) = delete;
    Privilege& operator=(const Privilege&) = delete;
    ~Privilege() { restore(); }
    DWORD enable();
    void restore();
};
}
