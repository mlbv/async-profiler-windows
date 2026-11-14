/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Windows port of upstream's test/test/nonjava/non_java_app.cpp: a native application that loads the
// profiler through the C API and creates a JVM before, after or between recordings, or on another thread.
// Usage: nativeNonjavaApplication FLOW PROFILER_DLL JAVA_HOME CLASS_PATH OUTPUT [SECOND_OUTPUT]
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <jni.h>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <string>
#include "../core/src/asprof.h"

static asprof_execute_t execute;
static asprof_error_str_t errorText;
static HMODULE jvmLibrary;
static JavaVM* jvm;
static JNIEnv* env;
static wchar_t** arguments;

static void fail(const char* message) {
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
}
static std::string utf8(const wchar_t* value) {
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) fail("Invalid UTF-16 argument");
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, result.data(), size, nullptr, nullptr);
    return result;
}
static void output(const char* buffer, size_t size) { std::fwrite(buffer, 1, size, stderr); }

extern "C" __declspec(dllexport) __declspec(noinline) double nativeBurnCpu() {
    double result = 0;
    for (int i = 1; i <= 100000000; ++i) {
        result += std::sqrt(i);
        result += std::pow(i, std::sqrt(i));
    }
    return result;
}

static void loadProfiler() {
    auto library = LoadLibraryW(arguments[2]);
    if (!library) fail("Cannot load the profiler");
    auto init = reinterpret_cast<asprof_init_t>(GetProcAddress(library, "asprof_init"));
    execute = reinterpret_cast<asprof_execute_t>(GetProcAddress(library, "asprof_execute"));
    errorText = reinterpret_cast<asprof_error_str_t>(GetProcAddress(library, "asprof_error_str"));
    if (!init || !execute || !errorText) fail("Missing C API exports");
    init();
}
static void run(const std::string& command) {
    if (auto error = execute(command.c_str(), output)) fail(errorText(error));
}
static void startProfiler() { run("start,event=cpu,interval=1ms,cstack=vmx"); }
static void stopProfiler(const wchar_t* file) { run("stop,file=" + utf8(file)); }

static void loadJvmLibrary() {
    // JDK 8 places the JVM under jre.
    std::wstring home = arguments[3];
    for (auto path : {home + L"\\bin\\server\\jvm.dll", home + L"\\jre\\bin\\server\\jvm.dll"}) {
        if ((jvmLibrary = LoadLibraryW(path.c_str())) != nullptr) return;
    }
    fail("Unable to find jvm.dll");
}
static void startJvm() {
    auto classPath = "-Djava.class.path=" + utf8(arguments[4]);
    JavaVMOption options[1]{{const_cast<char*>(classPath.c_str()), nullptr}};
    JavaVMInitArgs initArguments{JNI_VERSION_1_6, 1, options, JNI_TRUE};
    auto create = reinterpret_cast<jint (JNICALL*)(JavaVM**, void**, void*)>(GetProcAddress(jvmLibrary, "JNI_CreateJavaVM"));
    if (!create) fail("Unable to find JNI_CreateJavaVM");
    if (create(&jvm, reinterpret_cast<void**>(&env), &initArguments) != JNI_OK) fail("Failed to create JVM");
}
static void executeJvmTask() {
    auto type = env->FindClass("NonjavaTask");
    if (!type) fail("Cannot find NonjavaTask");
    auto task = env->GetStaticMethodID(type, "cpuHeavyTask", "()D");
    if (!task) fail("Cannot find cpuHeavyTask");
    for (int i = 0; i < 300; ++i) {
        env->CallStaticDoubleMethod(type, task);
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            fail("Exception in cpuHeavyTask");
        }
    }
    env->DeleteLocalRef(type);
}
static void stopJvm() {
    if (jvm->DestroyJavaVM() != JNI_OK) fail("Failed to destroy JVM");
}

int wmain(int argc, wchar_t** argv) {
    arguments = argv;
    if (argc < 6) fail("Usage: nativeNonjavaApplication FLOW PROFILER_DLL JAVA_HOME CLASS_PATH OUTPUT [SECOND_OUTPUT]");
    switch (argv[1][0]) {
        case '1':  // jvmFirst
            loadProfiler(); loadJvmLibrary(); startJvm(); startProfiler(); executeJvmTask(); stopProfiler(argv[5]); stopJvm();
            break;
        case '2':  // profilerFirst
            loadProfiler(); loadJvmLibrary(); startProfiler(); startJvm(); executeJvmTask(); stopProfiler(argv[5]); stopJvm();
            break;
        case '3':  // jvmInBetween
            if (argc < 7) fail("jvmInBetween needs two outputs");
            loadProfiler(); loadJvmLibrary(); startProfiler(); startJvm(); nativeBurnCpu(); executeJvmTask(); stopProfiler(argv[5]);
            startProfiler(); nativeBurnCpu(); executeJvmTask(); stopProfiler(argv[6]); stopJvm();
            break;
        case '4': {  // differentThread
            loadProfiler();
            auto thread = CreateThread(nullptr, 0, [](void*) -> DWORD {
                loadJvmLibrary(); startJvm();
                for (;;) executeJvmTask();
            }, nullptr, 0, nullptr);
            if (!thread) fail("Cannot create the JVM thread");
            Sleep(2000); startProfiler(); Sleep(2000); stopProfiler(argv[5]);
            break;
        }
        default:
            fail("Unknown flow");
    }
    return 0;
}
