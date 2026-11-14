/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _JAVAAPI_H
#define _JAVAAPI_H

#include <jvmti.h>
#include <string>
#include <string_view>
#include <vector>
#include "mutex.h"


class JavaAPI {
  public:
    static void registerNatives(jvmtiEnv* jvmti, JNIEnv* jni);
    static bool getUtf8(JNIEnv* env, jstring value, std::string& result);
#ifdef _WIN32
    static jstring newString(JNIEnv* env, std::string_view value);
#endif
};

class RecordingAPI {
  private:
    struct Binding {
        jweak klass;
        jfieldID state;
        jmethodID update_clock;
        bool jvm_clock;
        jlong frequency;
    };
    static std::vector<Binding> _bindings;
    static Mutex _lock;
    static bool _running;
    static void updateClock(JNIEnv* env, jclass klass, Binding& binding);
    static void updateState(bool running);

  public:
    // Should match constants in Recording.java
    enum State {
        UNAVAILABLE,
        STOPPED,
        RUNNING
    };

    static State registerNatives(JNIEnv* env, jclass recording_class);
    static bool isRecordingClass(jvmtiEnv* jvmti, JNIEnv* env, jclass candidate);
    static void bind(jvmtiEnv* jvmti, JNIEnv* env);
    static void classPrepared(jvmtiEnv* jvmti, JNIEnv* env, jclass klass);
    static void start();
    static void stop();
};

#endif // _JAVAAPI_H
