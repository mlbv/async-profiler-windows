/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include <string.h>
#include "event.h"
#include "profiler.h"
#ifdef _WIN32
#include "windowsProfiler.h"
#endif

void EventWithClass::setClassName(const char* class_name, u32 len) {
    _class_name = class_name;
    _class_name_len = len;
}

void EventWithClass::setClassSignature(const char* class_sig) {
    if (class_sig != nullptr) {
        if (class_sig[0] == 'L') {
            setClassName(class_sig + 1, strlen(class_sig) - 2);
        } else {
            setClassName(class_sig, strlen(class_sig));
        }
    }
}

u32 EventWithClass::classId() const {
    if (_class_name == nullptr) {
        return 0;
    }
#ifdef _WIN32
    return WindowsProfiler::lookupJavaClass(Profiler::instance()->classMap(), std::string_view(_class_name, _class_name_len));
#else
    return Profiler::instance()->classMap()->lookup(_class_name, _class_name_len);
#endif
}
