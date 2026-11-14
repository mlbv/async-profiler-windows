/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <cstdint>

namespace WindowsProfiler {
// Cold setup validates the loaded ntdll status getter before exception callbacks
// or thread observers can use the saved-state object. No hot-path API binding.
const char* prepareNativeErrorState() noexcept;
class SavedNativeErrorState {
    DWORD _error;
    DWORD _status;
    unsigned char* _teb;
    std::uint32_t _offset;
public:
    SavedNativeErrorState() noexcept;
    ~SavedNativeErrorState();
    SavedNativeErrorState(const SavedNativeErrorState&) = delete;
    SavedNativeErrorState& operator=(const SavedNativeErrorState&) = delete;
};
}
