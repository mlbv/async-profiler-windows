/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// A JVMTI agent that does nothing, loaded dynamically to observe the JVM's dynamic-agent warning.
#include <jni.h>

extern "C" JNIEXPORT jint JNICALL Agent_OnAttach(JavaVM*, char*, void*) {
    return JNI_OK;
}
