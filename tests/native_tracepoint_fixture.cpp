/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <evntprov.h>
#include <TraceLoggingProvider.h>
#include <jni.h>

namespace {
constexpr GUID providerId = {0xe50fb813,0x9e08,0x40dc,{0xa8,0xaf,0x33,0x90,0xdb,0x1d,0xbb,0xf4}};
REGHANDLE provider = 0;
TRACELOGGING_DEFINE_PROVIDER(namedProvider, "Asprof.Tracepoint.Fixture",
    (0x2a94e71b,0x655a,0x4f69,0x8c,0x64,0x30,0x2d,0x17,0x03,0x2a,0xe9));
void check(JNIEnv* env, ULONG error) {
    if (error) env->ThrowNew(env->FindClass("java/lang/IllegalStateException"), "ETW tracepoint fixture API failed");
}
}
extern "C" JNIEXPORT void JNICALL Java_TracepointSmoke_initialize(JNIEnv* env, jclass) {
    auto error = EventRegister(&providerId, nullptr, nullptr, &provider);
    if (!error) error = TraceLoggingRegister(namedProvider);
    check(env, error);
}
extern "C" JNIEXPORT void JNICALL Java_TracepointSmoke_release(JNIEnv* env, jclass) {
    check(env, EventUnregister(provider));
    provider = 0;
    TraceLoggingUnregister(namedProvider);
}
extern "C" JNIEXPORT void JNICALL Java_TracepointSmoke_emit(JNIEnv* env, jclass, jint count, jint id, jint version, jboolean named) {
    EVENT_DESCRIPTOR event{};
    event.Id = static_cast<USHORT>(id); event.Version = static_cast<UCHAR>(version); event.Level = 4;
    ULONG error = 0;
    for (jint index = 0; index < count && !error; ++index) {
        if (named) {
            if (id == 1) TraceLoggingWrite(namedProvider, "燃烧𠮷", TraceLoggingInt32(index, "Index"));
            else TraceLoggingWrite(namedProvider, "OtherEvent", TraceLoggingInt32(index, "Index"));
        } else {
            EVENT_DATA_DESCRIPTOR data{};
            EventDataDescCreate(&data, &index, sizeof(index));
            error = EventWrite(provider, &event, 1, &data);
        }
    }
    check(env, error);
}
