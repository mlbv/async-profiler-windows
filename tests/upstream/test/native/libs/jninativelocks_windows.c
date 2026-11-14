/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Derived from upstream test/native/libs/jninativelocks.c; modified for Windows x86-64.
 */

// Windows variant of jninativelocks.c: the native mutex and reader/writer lock are a critical
// section and an SRW lock, the primitives the profiler's nativelock engine traces on Windows.

#include <jni.h>
#include <unistd.h>
#include <windows.h>

static CRITICAL_SECTION global_mutex;
static SRWLOCK global_rwlock = SRWLOCK_INIT;

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&global_mutex);
    }
    return TRUE;
}

JNIEXPORT void JNICALL Java_test_nativelock_NativeLock_mutexContentionThread(JNIEnv *env, jclass cls) {
    for (int i = 0; i < 50; i++) {
        EnterCriticalSection(&global_mutex);
        usleep(3000);
        LeaveCriticalSection(&global_mutex);
        usleep(1000);
    }
}

JNIEXPORT void JNICALL Java_test_nativelock_NativeLock_rdlockContentionThread(JNIEnv *env, jclass cls) {
    for (int i = 0; i < 50; i++) {
        AcquireSRWLockShared(&global_rwlock);
        usleep(3000);
        ReleaseSRWLockShared(&global_rwlock);
        usleep(1000);
    }
}

JNIEXPORT void JNICALL Java_test_nativelock_NativeLock_wrlockContentionThread(JNIEnv *env, jclass cls) {
    for (int i = 0; i < 50; i++) {
        AcquireSRWLockExclusive(&global_rwlock);
        usleep(5000);
        ReleaseSRWLockExclusive(&global_rwlock);
        usleep(2000);
    }
}
