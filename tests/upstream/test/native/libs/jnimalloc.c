/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

// For aligned_alloc
#ifndef _ISOC11_SOURCE
#define _ISOC11_SOURCE
#endif

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef _WIN32
// The UCRT has neither; the Windows build links them from windows/alignedalloc.c
int posix_memalign(void** memptr, size_t alignment, size_t size);
void* aligned_alloc(size_t alignment, size_t size);
#endif

JNIEXPORT jlong JNICALL Java_test_nativemem_Native_malloc(JNIEnv* env, jclass clazz, jlong size) {
    void* ptr = malloc((size_t)size);
    return (jlong)(intptr_t)ptr;
}

JNIEXPORT jlong JNICALL Java_test_nativemem_Native_calloc(JNIEnv* env, jclass clazz, jlong num, jlong size) {
    void* ptr = calloc((size_t)num, (size_t)size);
    return (jlong)(intptr_t)ptr;
}

JNIEXPORT jlong JNICALL Java_test_nativemem_Native_realloc(JNIEnv* env, jclass clazz, jlong addr, jlong size) {
    void* ptr = realloc((void*)(intptr_t)addr, (size_t)size);
    return (jlong)(intptr_t)ptr;
}

JNIEXPORT void JNICALL Java_test_nativemem_Native_free(JNIEnv* env, jclass clazz, jlong addr) {
    free((void*)(intptr_t)addr);
}

JNIEXPORT jlong JNICALL Java_test_nativemem_Native_posixMemalign(JNIEnv* env, jclass clazz, jlong alignment, jlong size) {
    void* ptr;
    int ret = posix_memalign(&ptr, (size_t)alignment, (size_t)size);
    return ret != 0 ? 0 : (jlong)(intptr_t)ptr;
}

JNIEXPORT jlong JNICALL Java_test_nativemem_Native_alignedAlloc(JNIEnv* env, jclass clazz, jlong alignment, jlong size) {
    return (jlong)(intptr_t)aligned_alloc((size_t)alignment, (size_t)size);
}
