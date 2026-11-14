/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "windowsJvmVersion.h"
#include "log.h"

bool WindowsProfiler::createdJvmAttachable(const void* getCreatedJavaVMs) {
    using namespace JvmVersion;
    HMODULE jvm;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        static_cast<LPCWSTR>(getCreatedJavaVMs), &jvm);
    Version version;
    if (!fileVersion(jvm, version)) {
        Log::warn("Not attaching to the running JVM: jvm.dll has no file version");
        return false;
    }
    switch (creation(version)) {
        case Creation::Published:
            return true;
        case Creation::Unpublished:
            Log::warn("Not attaching to the running JVM: jvm.dll %u.%u.%u.%u predates the JDK-8308341 fix and names no threads",
                version[0], version[1], version[2], version[3]);
            return false;
        case Creation::Unknown:
            Log::warn("Not attaching to the running JVM: unrecognized jvm.dll version %u.%u.%u.%u",
                version[0], version[1], version[2], version[3]);
            return false;
    }
    __builtin_unreachable();
}
