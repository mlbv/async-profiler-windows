/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <jni.h>
#include <cstdint>

extern "C" {
__declspec(dllexport) volatile std::uint64_t ProbeArgumentsWatched[2]{};
__declspec(dllexport) __declspec(noinline) std::uint64_t ProbeArgumentsWork(
        std::uint64_t first, std::uint64_t second, std::uint64_t third, std::uint64_t fourth) {
    return first + 10 * second + 100 * third + 1000 * fourth;
}

JNIEXPORT jlong JNICALL Java_NativeProbeArguments_address(JNIEnv* env, jclass type, jboolean function) {
    (void)env;
    (void)type;
    return function ? reinterpret_cast<jlong>(ProbeArgumentsWork) : reinterpret_cast<jlong>(&ProbeArgumentsWatched[1]);
}
JNIEXPORT jlong JNICALL Java_NativeProbeArguments_run(JNIEnv* env, jclass type, jboolean memory) {
    (void)env;
    (void)type;
    std::uint64_t result = 0;
    for (std::uint64_t i = 0; i < 10; ++i) {
        if (memory) {
            ProbeArgumentsWatched[1] = i;
            result += ProbeArgumentsWatched[1];
        } else result += ProbeArgumentsWork(i, 11, 13, 17);
    }
    return static_cast<jlong>(result);
}
}
