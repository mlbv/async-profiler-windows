/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include <errno.h>
#include <string.h>
#include "asprof.h"
#include "httpClient.h"
#include "javaApi.h"
#include "os.h"
#include "profiler.h"
#include "threadLocalData.h"
#include "tsc.h"
#include "vmStructs.h"


static void throwNew(JNIEnv* env, const char* exception_class, const char* message) {
    jclass cls = env->FindClass(exception_class);
    if (cls != NULL) {
        env->ThrowNew(cls, message);
    }
}

bool JavaAPI::getUtf8(JNIEnv* env, jstring value, std::string& result) {
    jsize length = env->GetStringLength(value);
    const jchar* chars = env->GetStringChars(value, NULL);
    if (chars == NULL) return false;
    result.clear();
    bool valid = true;
    for (jsize i = 0; i < length; ++i) {
        unsigned cp = chars[i];
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (i + 1 == length || chars[i + 1] < 0xdc00 || chars[i + 1] > 0xdfff) { valid = false; break; }
            cp = 0x10000 + ((cp - 0xd800) << 10) + (chars[++i] - 0xdc00);
        } else if (cp >= 0xdc00 && cp <= 0xdfff) { valid = false; break; }
        if (cp < 0x80) result.push_back(cp);
        else if (cp < 0x800) {
            result.push_back(0xc0 | (cp >> 6)); result.push_back(0x80 | (cp & 0x3f));
        } else if (cp < 0x10000) {
            result.push_back(0xe0 | (cp >> 12)); result.push_back(0x80 | ((cp >> 6) & 0x3f)); result.push_back(0x80 | (cp & 0x3f));
        } else {
            result.push_back(0xf0 | (cp >> 18)); result.push_back(0x80 | ((cp >> 12) & 0x3f));
            result.push_back(0x80 | ((cp >> 6) & 0x3f)); result.push_back(0x80 | (cp & 0x3f));
        }
    }
    env->ReleaseStringChars(value, chars);
    if (!valid) throwNew(env, "java/lang/IllegalArgumentException", "String contains an unpaired UTF-16 surrogate");
    return valid;
}

#ifdef _WIN32
jstring JavaAPI::newString(JNIEnv* env, std::string_view value) {
    auto result = WindowsProfiler::wide(value);
    if (!value.empty() && result.empty()) {
        throwNew(env, "java/lang/IllegalArgumentException", "Input is not valid UTF-8");
        return NULL;
    }
    return env->NewString(reinterpret_cast<const jchar*>(result.data()), static_cast<jsize>(result.size()));
}
#endif


extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_start0(JNIEnv* env, jobject unused, jstring event, jlong interval, jboolean reset) {
    Arguments args;
    std::string event_str;
    if (!JavaAPI::getUtf8(env, event, event_str)) return;
    if (event_str == EVENT_ALLOC) {
        args._alloc = interval > 0 ? interval : 0;
    } else if (event_str == EVENT_LOCK) {
        args._lock = interval >= 0 ? interval : DEFAULT_LOCK_INTERVAL;
    } else {
        args._event = event_str.c_str();
        args._interval = interval;
    }

    Error error = Profiler::instance()->start(args, reset);

    if (error) {
        throwNew(env, "java/lang/IllegalStateException", error.message());
    }
}

extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_stop0(JNIEnv* env, jobject unused) {
    Error error = Profiler::instance()->stop();

    if (error) {
        throwNew(env, "java/lang/IllegalStateException", error.message());
    }
}

extern "C" DLLEXPORT jstring JNICALL
Java_one_profiler_AsyncProfiler_execute0(JNIEnv* env, jobject unused, jstring command) {
    Arguments args;
    std::string command_str;
    if (!JavaAPI::getUtf8(env, command, command_str)) return NULL;
    Error error = args.parse(command_str.c_str());

    if (error) {
        throwNew(env, "java/lang/IllegalArgumentException", error.message());
        return NULL;
    }

    Log::open(args);
    TemporaryLog log(args);

    const char* file = args.hasOutputFile() ? args.file() : NULL;
    if (file == NULL) {
        BufferWriter out;
        error = Profiler::instance()->runInternal(args, out);
        if (!error) {
            out << '\0';
            if (out.size() >= 0x3fffffff) {
                throwNew(env, "java/lang/IllegalStateException", "Output exceeds string size limit");
                return NULL;
            }
#ifdef _WIN32
            return JavaAPI::newString(env, std::string_view(out.buf(), out.size() - 1));
#else
            return env->NewStringUTF(out.buf());
#endif
        }
    } else if (Arguments::isUrl(file)) {
        BufferWriter out;
        error = Profiler::instance()->runInternal(args, out);
        if (!error && (error = HttpClient::send(file, out.buf(), out.size(), args._output))) {
            throwNew(env, "java/io/IOException", error.message());
            return NULL;
        }
    } else {
#ifdef _WIN32
        FileWriter out(args);
#else
        FileWriter out(file);
#endif
        if (!out.is_open()) {
            const char* message = strerror(errno);
#ifdef _WIN32
            Error file_error = args.fileError();
            if (file_error) message = file_error.message();
            args.reportOutputError(message);
#endif
            throwNew(env, "java/io/IOException", message);
            return NULL;
        }
        error = Profiler::instance()->runInternal(args, out);
        bool written = out.finish();
        if (!error && !written) {
#ifdef _WIN32
            args.reportOutputError("Could not write output file");
#endif
            throwNew(env, "java/io/IOException", "Could not write output file");
            return NULL;
        }
#ifdef _WIN32
        if (error) args.reportOutputError(error.message());
#endif
    }

    if (error) {
        throwNew(env, "java/lang/IllegalStateException", error.message());
        return NULL;
    }
    return env->NewStringUTF("OK");
}

extern "C" DLLEXPORT jbyteArray JNICALL
Java_one_profiler_AsyncProfiler_execute1(JNIEnv* env, jobject unused, jstring command) {
    Arguments args;
    std::string command_str;
    if (!JavaAPI::getUtf8(env, command, command_str)) return NULL;
    Error error = args.parse(command_str.c_str());

    if (error) {
        throwNew(env, "java/lang/IllegalArgumentException", error.message());
        return NULL;
    }
    if (args.hasOutputFile()) {
        throwNew(env, "java/lang/IllegalArgumentException", "execute1 calls should not specify an output file argument");
        return NULL;
    }

    Log::open(args);
    TemporaryLog log(args);

    BufferWriter out;
    error = Profiler::instance()->runInternal(args, out);
    if (error) {
        throwNew(env, "java/lang/IllegalStateException", error.message());
        return NULL;
    }

    jbyteArray output = env->NewByteArray(out.size());
    env->SetByteArrayRegion(output, 0, out.size(), (const jbyte*) out.buf());
    return output;
}

extern "C" DLLEXPORT jlong JNICALL
Java_one_profiler_AsyncProfiler_getSamples(JNIEnv* env, jobject unused) {
    return (jlong)Profiler::instance()->total_samples();
}

extern "C" DLLEXPORT void JNICALL
Java_one_profiler_AsyncProfiler_filterThread0(JNIEnv* env, jobject unused, jthread thread, jboolean enable) {
    int thread_id;
    if (thread == NULL) {
        thread_id = OS::threadId();
    } else if ((thread_id = VMThread::nativeThreadId(env, thread)) < 0) {
        return;
    }

    ThreadFilter* thread_filter = Profiler::instance()->threadFilter();
    if (enable) {
        thread_filter->add(thread_id);
    } else {
        thread_filter->remove(thread_id);
    }
}

extern "C" DLLEXPORT jint JNICALL
Java_one_profiler_Recording_registerNatives(JNIEnv* env, jclass cls) {
    return RecordingAPI::registerNatives(env, cls);
}

extern "C" DLLEXPORT jobject JNICALL
Java_one_profiler_Recording_getThreadLocalBuffer(JNIEnv* env, jclass cls) {
    asprof_thread_local_data* tld = ThreadLocalData::get();
    return tld == nullptr ? nullptr : env->NewDirectByteBuffer(tld, sizeof(*tld));
}

extern "C" DLLEXPORT void JNICALL
Java_one_profiler_Recording_emitSpan(JNIEnv* env, jclass cls, jlong startTime, jlong endTime, jstring tag) {
    if ((u64)startTime > (u64)endTime) return;

    SpanEvent event;
    event._start_time = startTime;
    event._end_time = endTime;
    std::string label;
    event._tag = nullptr;
    event._tag_length = 0;
    if (tag != nullptr) {
        if (!JavaAPI::getUtf8(env, tag, label)) return;
        if (label.size() > FlightRecorder::MAX_STRING_BYTES) {
            throwNew(env, "java/lang/IllegalArgumentException", "Span tag exceeds 8191 UTF-8 bytes");
            return;
        }
        event._tag = label.data();
        event._tag_length = label.size();
    }
    Profiler::instance()->recordEventOnly(SPAN, &event);
}


#define F(cls, name, sig)  {(char*)#name, (char*)sig, (void*)Java_one_profiler_##cls##_##name}

static const JNINativeMethod profiler_natives[] = {
    F(AsyncProfiler, start0,        "(Ljava/lang/String;JZ)V"),
    F(AsyncProfiler, stop0,         "()V"),
    F(AsyncProfiler, execute0,      "(Ljava/lang/String;)Ljava/lang/String;"),
    F(AsyncProfiler, execute1,      "(Ljava/lang/String;)[B"),
    F(AsyncProfiler, getSamples,    "()J"),
    F(AsyncProfiler, filterThread0, "(Ljava/lang/Thread;Z)V"),
};

static const JNINativeMethod recording_natives[] = {
    F(Recording, registerNatives,     "()I"),
    F(Recording, getThreadLocalBuffer, "()Ljava/nio/ByteBuffer;"),
    F(Recording, emitSpan,             "(JJLjava/lang/String;)V"),
};

#undef F


// Since AsyncProfiler class can be renamed or moved to another package (shaded),
// we look for the actual class in the stack trace.
void JavaAPI::registerNatives(jvmtiEnv* jvmti, JNIEnv* jni) {
    jvmtiFrameInfo frame[10];
    jint frame_count;
    if (jvmti->GetStackTrace(NULL, 0, sizeof(frame) / sizeof(frame[0]), frame, &frame_count) != 0) {
        return;
    }

    jclass System = jni->FindClass("java/lang/System");
    jmethodID load = jni->GetStaticMethodID(System, "load", "(Ljava/lang/String;)V");
    jmethodID loadLibrary = jni->GetStaticMethodID(System, "loadLibrary", "(Ljava/lang/String;)V");

    // Look for System.load() or System.loadLibrary() method in the stack trace.
    // The next frame will belong to AsyncProfiler class.
    for (int i = 0; i < frame_count - 1; i++) {
        if (frame[i].method == load || frame[i].method == loadLibrary) {
            jclass profiler_class;
            if (jvmti->GetMethodDeclaringClass(frame[i + 1].method, &profiler_class) == 0) {
                for (int j = 0; j < sizeof(profiler_natives) / sizeof(JNINativeMethod); j++) {
                    jni->RegisterNatives(profiler_class, &profiler_natives[j], 1);
                }
            }
            break;
        }
    }

    jni->ExceptionClear();
}


std::vector<RecordingAPI::Binding> RecordingAPI::_bindings;
Mutex RecordingAPI::_lock;
bool RecordingAPI::_running = false;

void RecordingAPI::updateClock(JNIEnv* env, jclass klass, Binding& binding) {
    bool enabled = TSC::usesJvmClock();
    jlong frequency = TSC::frequency();
    if (binding.frequency == frequency && binding.jvm_clock == enabled) return;

    jobject lookup = nullptr;
    if (enabled) {
        jclass lookup_class = env->FindClass("java/lang/invoke/MethodHandles$Lookup");
        jfieldID impl_field = lookup_class == nullptr ? nullptr : env->GetStaticFieldID(lookup_class, "IMPL_LOOKUP", "Ljava/lang/invoke/MethodHandles$Lookup;");
        if (impl_field != nullptr) lookup = env->GetStaticObjectField(lookup_class, impl_field);
        if (lookup_class != nullptr) env->DeleteLocalRef(lookup_class);
        if (lookup == nullptr) {
            env->ExceptionClear();
            Log::error("Cannot bind the recording SDK to the profiler clock");
            return;
        }
    }
    env->CallStaticVoidMethod(klass, binding.update_clock, lookup, frequency);
    if (lookup != nullptr) env->DeleteLocalRef(lookup);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return;
    }
    binding.jvm_clock = enabled;
    binding.frequency = frequency;
}

RecordingAPI::State RecordingAPI::registerNatives(JNIEnv* env, jclass klass) {
    if (env->RegisterNatives(klass, recording_natives, sizeof(recording_natives) / sizeof(recording_natives[0])) != 0) return UNAVAILABLE;
    jfieldID state = env->GetStaticFieldID(klass, "state", "I");
    jmethodID update = env->GetStaticMethodID(klass, "updateClock", "(Ljava/lang/invoke/MethodHandles$Lookup;J)V");
    if (state == nullptr || update == nullptr) return UNAVAILABLE;

    MutexLocker lock(_lock);
    for (auto it = _bindings.begin(); it != _bindings.end();) {
        if (env->IsSameObject(it->klass, nullptr)) {
            env->DeleteWeakGlobalRef(it->klass);
            it = _bindings.erase(it);
        } else {
            if (env->IsSameObject(it->klass, klass)) {
                updateClock(env, klass, *it);
                env->SetStaticIntField(klass, state, _running ? RUNNING : STOPPED);
                return _running ? RUNNING : STOPPED;
            }
            ++it;
        }
    }
    jweak retained = env->NewWeakGlobalRef(klass);
    if (retained == nullptr) return UNAVAILABLE;
    _bindings.push_back({retained, state, update, false, 0});
    updateClock(env, klass, _bindings.back());
    env->SetStaticIntField(klass, state, _running ? RUNNING : STOPPED);
    return _running ? RUNNING : STOPPED;
}

bool RecordingAPI::isRecordingClass(jvmtiEnv* jvmti, JNIEnv* env, jclass candidate) {
    // Fast path: compare class name in place if possible
    if (VMStructs::hasKlassField() && VMStructs::hasClassNames()) {
        VMSymbol* name = VMKlass::fromJavaClass(env, candidate)->name();
        return name != nullptr && name->length() == 22 && startsWith(name->body(), "one/profiler/Recording");
    }

    char* name;
    if (jvmti->GetClassSignature(candidate, &name, nullptr) == 0) {
        bool result = streq(name, "Lone/profiler/Recording;");
        jvmti->Deallocate((unsigned char*)name);
        return result;
    }
    return false;
}

void RecordingAPI::classPrepared(jvmtiEnv* jvmti, JNIEnv* env, jclass klass) {
    if (!isRecordingClass(jvmti, env, klass)) return;
    // Binding methods must not initialize a class from its ClassPrepare event.
    env->RegisterNatives(klass, recording_natives, sizeof(recording_natives) / sizeof(recording_natives[0]));
    jint status;
    if (!env->ExceptionCheck() && jvmti->GetClassStatus(klass, &status) == JVMTI_ERROR_NONE
            && (status & JVMTI_CLASS_STATUS_INITIALIZED)) registerNatives(env, klass);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

void RecordingAPI::bind(jvmtiEnv* jvmti, JNIEnv* env) {
    jint count;
    jclass* classes;
    if (jvmti->GetLoadedClasses(&count, &classes) != JVMTI_ERROR_NONE) return;
    for (jint i = 0; i < count; ++i) {
        classPrepared(jvmti, env, classes[i]);
        env->DeleteLocalRef(classes[i]);
    }
    jvmti->Deallocate(reinterpret_cast<unsigned char*>(classes));
}

void RecordingAPI::updateState(bool running) {
    MutexLocker lock(_lock);
    _running = running;
    JNIEnv* env = VM::jni();
    for (auto it = _bindings.begin(); it != _bindings.end();) {
        jclass klass = static_cast<jclass>(env->NewLocalRef(it->klass));
        if (klass == nullptr) {
            env->DeleteWeakGlobalRef(it->klass);
            it = _bindings.erase(it);
            continue;
        }
        if (running) updateClock(env, klass, *it);
        env->SetStaticIntField(klass, it->state, running ? RUNNING : STOPPED);
        env->DeleteLocalRef(klass);
        ++it;
    }
}

void RecordingAPI::start() { updateState(true); }
void RecordingAPI::stop() { updateState(false); }
