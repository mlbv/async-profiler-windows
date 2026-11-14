/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include "userEvents.h"
#include "flightRecorder.h"
#ifdef _WIN32
#include "windowsProfiler.h"
#endif
#include <cstring>

Dictionary UserEvents::_dict;

// No (extra) lock is needed here since Dictionary is thread-safe.

int UserEvents::registerEvent(const char* event) {
    if (event == NULL) return -1;
    size_t length = strlen(event);
    if (length > FlightRecorder::MAX_STRING_BYTES) return -1;
#ifdef _WIN32
    if (length != 0 && WindowsProfiler::wide(std::string_view(event, length)).empty()) return -1;
#endif
    return _dict.lookup(event);
}

void UserEvents::collect(std::map<unsigned int, const char*>& map) {
    _dict.collect(map);
}
