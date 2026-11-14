/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsCompiledHandlers.h"
#include "nmethodUnwind.h"
#include <jni.h>
#include <jvmti.h>
#include <string>

namespace HandlerCheckpoint {
using Snapshot = WindowsProfiler::JavaUnwind::Compiled::Handlers::Snapshot;
using CaptureStamp = NMethodUnwindLayout::CaptureStamp;
struct Certificate {
    Snapshot snapshot;
    CaptureStamp stamp;
    int level = 0;
    bool conventional = false;
};
using Lookup = bool (*)(void*,std::uintptr_t,jmethodID,Snapshot&,int&,bool&);
using ColdLookup = bool (*)(void*,jmethodID,Certificate&);
struct Input {
    void* observer;
    Lookup lookup;
    std::uintptr_t barrier, stub;
    std::size_t stubSize;
    ColdLookup coldLookup = nullptr;
    bool implicit = false;
};
bool run(JNIEnv*,jvmtiEnv*,jclass,const Input&,std::string& report,std::string& error);
}
