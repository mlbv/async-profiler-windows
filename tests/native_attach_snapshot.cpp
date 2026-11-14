/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "importHooks.h"
#include "asprof.h"
#include <dbghelp.h>
#include <jni.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

namespace {
decltype(&CreateToolhelp32Snapshot) original;
std::uintptr_t dlsymBegin, dlsymEnd;
unsigned injected;
std::string output;
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
void collect(const char* data, size_t length) { output.append(data, length); }
HANDLE WINAPI snapshot(DWORD flags, DWORD pid) {
    if (injected < 2) {
        void* stack[16];
        auto count = CaptureStackBackTrace(0, 16, stack, nullptr);
        for (unsigned i = 0; i < count; ++i) {
            auto pc = reinterpret_cast<std::uintptr_t>(stack[i]);
            if (pc >= dlsymBegin && pc < dlsymEnd) {
                ++injected;
                SetLastError(ERROR_BAD_LENGTH);
                return INVALID_HANDLE_VALUE;
            }
        }
    }
    return original(flags, pid);
}
}

int wmain(int argc, WCHAR** argv) try {
    require(argc == 4, "Usage: attach-snapshot profiler.dll JDK upstream-test-classes");
    auto profiler = LoadLibraryW(argv[1]);
    require(profiler != nullptr, "Cannot load profiler");
    auto init = reinterpret_cast<asprof_init_t>(GetProcAddress(profiler, "asprof_init"));
    auto execute = reinterpret_cast<asprof_execute_t>(GetProcAddress(profiler, "asprof_execute"));
    require(init && execute, "Missing C API");
    init();

    // Resolve the injection boundary before JVM threads or profiling can use DbgHelp.
    auto process = GetCurrentProcess();
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_EXACT_SYMBOLS | SYMOPT_NO_PROMPTS);
    std::wstring path(argv[1]);
    auto directory = path.substr(0, path.find_last_of(L"/\\"));
    require(SymInitializeW(process, directory.c_str(), FALSE), "Cannot initialize test symbol session");
    auto base = SymLoadModuleExW(process, nullptr, argv[1], L"testedprofiler",
        reinterpret_cast<DWORD64>(profiler), 0, nullptr, 0);
    require(base != 0, "Cannot load profiler PDB");
    alignas(SYMBOL_INFO) char symbolBytes[sizeof(SYMBOL_INFO) + MAX_SYM_NAME]{};
    auto symbol = reinterpret_cast<SYMBOL_INFO*>(symbolBytes);
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;
    require(SymFromName(process, "testedprofiler!dlsym", symbol), "Cannot locate internal dlsym");
    DWORD64 image;
    auto function = RtlLookupFunctionEntry(symbol->Address, &image, nullptr);
    require(function != nullptr, "dlsym has no unwind function");
    dlsymBegin = image + function->BeginAddress;
    dlsymEnd = image + function->EndAddress;
    SymUnloadModule64(process, base);
    SymCleanup(process);

    auto jdkBin = std::wstring(argv[2]) + L"/bin";
    require(SetDllDirectoryW(jdkBin.c_str()), "Cannot set JVM dependency path");
    auto jvmLibrary = LoadLibraryExW((jdkBin + L"/server/jvm.dll").c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    require(jvmLibrary != nullptr, "Cannot load JVM");
    auto create = reinterpret_cast<jint (JNICALL*)(JavaVM**, void**, void*)>(GetProcAddress(jvmLibrary, "JNI_CreateJavaVM"));
    require(create != nullptr, "Missing JNI_CreateJavaVM");
    auto classpath = "-Djava.class.path=" + WindowsProfiler::utf8(argv[3]);
    JavaVMOption option{classpath.data(), nullptr};
    JavaVMInitArgs args{JNI_VERSION_1_6, 1, &option, JNI_TRUE};
    JavaVM* vm;
    JNIEnv* env;
    require(create(&vm, reinterpret_cast<void**>(&env), &args) == JNI_OK, "Cannot create JVM");
    auto changed = WindowsProfiler::Imports::patch_module(profiler,
        [](std::string_view, std::string_view name, void* target) -> void* {
            if (name != "CreateToolhelp32Snapshot") return nullptr;
            original = reinterpret_cast<decltype(original)>(target);
            return reinterpret_cast<void*>(snapshot);
        });
    require(changed == 1 && original, "Snapshot import was not intercepted");
    auto error = execute("start,event=cpu,interval=1ms,cstack=vmx", collect);
    WindowsProfiler::Imports::patch_module(profiler,
        [](std::string_view, std::string_view name, void*) -> void* {
            return name == "CreateToolhelp32Snapshot" ? reinterpret_cast<void*>(original) : nullptr;
        });
    std::printf("ATTACH_SNAPSHOT injected=%u error=%s\n", injected, error ? error : "none");
    require(error == nullptr && injected == 0, "Known JVM exports depend on global snapshots");

    auto klass = env->FindClass("test/nonjava/JavaClass");
    require(klass != nullptr, "Cannot find JavaClass");
    auto task = env->GetStaticMethodID(klass, "cpuHeavyTask", "()D");
    require(task != nullptr, "Cannot find CPU task");
    for (unsigned i = 0; i < 300; ++i) env->CallStaticDoubleMethod(klass, task);
    require(!env->ExceptionCheck(), "Java CPU task failed");
    output.clear();
    require(execute("stop,collapsed", collect) == nullptr, "Cannot stop capture");
    require(output.find("cpuHeavyTask") != std::string::npos, "JVM task missing from capture");
    require(vm->DestroyJavaVM() == JNI_OK, "Cannot destroy JVM");
    std::puts("ATTACH_SNAPSHOT_OK");
    return 0;
} catch (const std::exception& error) {
    std::fprintf(stderr, "%s\n%s\n", error.what(), output.c_str());
    return 1;
}
