/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <jni.h>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <limits>
#include <atomic>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <string>
#include <malloc.h>
#include <crtdbg.h>
#include "../core/src/asprof.h"

static HMODULE reloadModule;
static volatile std::uint64_t* watchedValue;
extern "C" JNIEXPORT jlong JNICALL Java_NativeWatchFixture_address(JNIEnv*, jclass) {
    if (!watchedValue) watchedValue = static_cast<std::uint64_t*>(std::calloc(1, sizeof(std::uint64_t)));
    if (!watchedValue) std::abort();
    return reinterpret_cast<jlong>(watchedValue);
}
static DWORD WINAPI watchWork(void* parameter) {
    auto count = static_cast<DWORD>(reinterpret_cast<std::uintptr_t>(parameter));
    DWORD sum = 0;
    for (DWORD i = 0; i < count; ++i) {
        *watchedValue = i;
        sum += static_cast<DWORD>(*watchedValue);
    }
    return sum;
}
extern "C" JNIEXPORT jlong JNICALL Java_NativeWatchFixture_function(JNIEnv*, jclass) { return reinterpret_cast<jlong>(watchWork); }
extern "C" JNIEXPORT jlong JNICALL Java_NativeWatchFixture_run(JNIEnv*, jclass) {
    DWORD sum = watchWork(reinterpret_cast<void*>(100));
    auto worker = CreateThread(nullptr, 0, watchWork, reinterpret_cast<void*>(40), 0, nullptr);
    if (!worker || WaitForSingleObject(worker, 10000) != WAIT_OBJECT_0) std::abort();
    DWORD other;
    if (!GetExitCodeThread(worker, &other)) std::abort();
    CloseHandle(worker);
    return sum + other;
}
static std::uint64_t (*reloadWork)(DWORD);
extern "C" JNIEXPORT jlongArray JNICALL Java_NativeReloadFixture_load(JNIEnv* env, jclass, jstring path) {
    auto name = env->GetStringChars(path, nullptr);
    if (!name) return nullptr;
    std::wstring filename(reinterpret_cast<const wchar_t*>(name), env->GetStringLength(path));
    env->ReleaseStringChars(path, name);
    auto module = LoadLibraryW(filename.c_str());
    if (!module) { env->ThrowNew(env->FindClass("java/lang/UnsatisfiedLinkError"), "Cannot load reload target"); return nullptr; }
    reloadModule = module;
    reloadWork = reinterpret_cast<std::uint64_t (*)(DWORD)>(GetProcAddress(module, "RunReloadWork"));
    auto address = reinterpret_cast<std::uintptr_t (*)()>(GetProcAddress(module, "ReloadTargetAddress"));
    if (!reloadWork || !address) std::abort();
    jlong values[]{reinterpret_cast<jlong>(module), static_cast<jlong>(address())};
    auto result = env->NewLongArray(2);
    env->SetLongArrayRegion(result, 0, 2, values);
    return result;
}
extern "C" JNIEXPORT jboolean JNICALL Java_NativeReloadFixture_present(JNIEnv*, jclass) {
    return GetModuleHandleW(L"reloadTarget.dll") != nullptr;
}
extern "C" JNIEXPORT jboolean JNICALL Java_NativeReloadFixture_unload(JNIEnv*, jclass) {
    if (!reloadModule || !FreeLibrary(reloadModule)) std::abort();
    reloadModule = nullptr;
    reloadWork = nullptr;
    return GetModuleHandleW(L"reloadTarget.dll") != nullptr;
}
extern "C" JNIEXPORT jlong JNICALL Java_NativeReloadFixture_run(JNIEnv*, jclass, jint count) { return reloadWork(count); }
extern "C" JNIEXPORT jlong JNICALL Java_NativeReloadFixture_timed(JNIEnv*, jclass, jint milliseconds) {
    auto timed = reinterpret_cast<std::uint64_t (*)(DWORD)>(GetProcAddress(reloadModule, "RunReloadTimedWork"));
    if (!timed) std::abort();
    return timed(milliseconds);
}
static DWORD WINAPI reloadEmptyThread(void*) { return 0; }
extern "C" JNIEXPORT void JNICALL Java_NativeReloadFixture_threadAttach(JNIEnv*, jclass) {
    auto configure = reinterpret_cast<void (*)(DWORD)>(GetProcAddress(reloadModule, "ConfigureThreadAttach"));
    if (!configure) std::abort();
    configure(300);
    for (int i = 0; i < 4; ++i) {
        auto thread = CreateThread(nullptr, 0, reloadEmptyThread, nullptr, 0, nullptr);
        if (!thread || WaitForSingleObject(thread, 10000) != WAIT_OBJECT_0) std::abort();
        CloseHandle(thread);
    }
    configure(0);
}

static std::vector<char> api_output;
static void collect_api_output(const char* data, size_t size) { api_output.insert(api_output.end(), data, data + size); }
static void api_require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
extern "C" JNIEXPORT jstring JNICALL Java_LogCleanupSmoke_capi(JNIEnv* env, jclass, jbyteArray command) {
    try {
        auto module = GetModuleHandleW(L"asyncProfiler.dll");
        auto init = reinterpret_cast<decltype(&asprof_init)>(GetProcAddress(module, "asprof_init"));
        auto execute = reinterpret_cast<decltype(&asprof_execute)>(GetProcAddress(module, "asprof_execute"));
        api_require(init && execute, "Missing profiler C API exports");
        init();
        std::string text(static_cast<std::size_t>(env->GetArrayLength(command)), '\0');
        env->GetByteArrayRegion(command, 0, static_cast<jsize>(text.size()), reinterpret_cast<jbyte*>(text.data()));
        api_output.clear();
        auto error = execute(text.c_str(), collect_api_output);
        if (error) return env->NewStringUTF(error);
        api_require(!api_output.empty(), "C API command returned no callback output");
        return nullptr;
    } catch (const std::exception& error) {
        env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what());
        return nullptr;
    }
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_NativeApiFixture_output(JNIEnv* env, jclass) {
    auto result = env->NewByteArray(static_cast<jsize>(api_output.size()));
    env->SetByteArrayRegion(result, 0, static_cast<jsize>(api_output.size()), reinterpret_cast<const jbyte*>(api_output.data()));
    return result;
}

extern "C" JNIEXPORT jstring JNICALL Java_NativeApiFixture_run(JNIEnv* env, jclass) {
    try {
    auto module = GetModuleHandleW(L"asyncProfiler.dll");
    auto init = reinterpret_cast<decltype(&asprof_init)>(GetProcAddress(module, "asprof_init"));
    auto execute = reinterpret_cast<decltype(&asprof_execute)>(GetProcAddress(module, "asprof_execute"));
    auto register_event = reinterpret_cast<decltype(&asprof_register_jfr_event)>(GetProcAddress(module, "asprof_register_jfr_event"));
    auto emit = reinterpret_cast<decltype(&asprof_emit_jfr_event)>(GetProcAddress(module, "asprof_emit_jfr_event"));
    auto thread_data = reinterpret_cast<decltype(&asprof_get_thread_local_data)>(GetProcAddress(module, "asprof_get_thread_local_data"));
    api_require(init && execute && register_event && emit && thread_data, "Missing API exports");
    init();
    auto local_data = thread_data();
    api_require(local_data != nullptr, "Thread-local counter was not allocated");
    api_output.clear();
    api_require(!execute("status", collect_api_output) && !api_output.empty(), "Status command failed");
    api_require(execute("start,event=wall", nullptr) != nullptr, "Second start should fail");
    api_require(!execute("version", nullptr), "JNI exception was not cleared");
    auto key = register_event("fixture.\xe4\xba\x8b\xe4\xbb\xb6");
    api_require(key > 0 && register_event("fixture.\xe4\xba\x8b\xe4\xbb\xb6") == key && register_event("\xff") == -1, "User-event registration failed");
    std::uint8_t data[2048];
    for (unsigned i = 0; i < sizeof(data); ++i) data[i] = static_cast<std::uint8_t>(i);
    api_require(!emit(key, nullptr, 0) && !emit(key, data, 256) && !emit(key, data, 2048), "User-event emission failed");
    api_require(emit(key, data, 2049) && emit(key, nullptr, 1) && emit(-1, data, 1), "Invalid user-event payload should fail");
    using Samples = jlong (JNICALL*)(JNIEnv*, jobject);
    auto samples = reinterpret_cast<Samples>(GetProcAddress(module, "Java_one_profiler_AsyncProfiler_getSamples"));
    api_require(samples != nullptr, "Missing native sample counter");
    for (unsigned attempt = 0; attempt < 100 && local_data->sample_counter == 0; ++attempt) Sleep(50);
    api_require(samples(env, nullptr) > 0 && local_data->sample_counter > 0 && thread_data() == local_data,
            "Thread-local counter did not update with a real profiling sample");
    api_output.clear();
    auto dump = execute("dump,otlp", collect_api_output);
    if (dump) return env->NewStringUTF(dump);
    api_require(!api_output.empty(), "Binary dump is empty");
    return env->NewStringUTF("API_OK");
    } catch (const std::exception& error) {
        env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what());
        return nullptr;
    }
}

extern "C" __declspec(dllexport) __declspec(noinline) DWORD ProbeWork(DWORD value) {
    return value * 3 + 7;
}

extern "C" __declspec(dllexport) __declspec(noinline) DWORD ProbeOther(DWORD value) { return value + 11; }

extern "C" __declspec(dllexport) __declspec(noinline) DWORD WindowBegin(DWORD value) { return value + 17; }
extern "C" __declspec(dllexport) __declspec(noinline) DWORD WindowEnd(DWORD value) { return value + 19; }

namespace ProfilerFixture {
struct PrivateBoundary {
    static __declspec(noinline) DWORD begin(DWORD value) { return value + 17; }
    static __declspec(noinline) DWORD end(DWORD value) { return value + 19; }
};
}

static void burnCpu(DWORD milliseconds) {
    LARGE_INTEGER frequency, start, now;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    volatile std::uint64_t value = 1;
    do {
        for (int i = 0; i < 10000; ++i) value = (value ^ (value >> 13)) * 0x100000001b3ULL;
        QueryPerformanceCounter(&now);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart * milliseconds / 1000);
}

struct CpuAccounting {
    HANDLE ready = nullptr, go = nullptr, done = nullptr, finish = nullptr, worker = nullptr;
    DWORD tid = 0, duration = 0, error = 0;
    bool kernel = false;
    std::uint64_t user = 0, system = 0;
};
static CpuAccounting accounting;
static std::uint64_t cpuTimeNs(const FILETIME& value) {
    return ((std::uint64_t(value.dwHighDateTime) << 32) | value.dwLowDateTime) * 100;
}
static DWORD WINAPI accountingWorker(void*) {
    try {
        DWORD handles;
        if (!GetProcessHandleCount(GetCurrentProcess(), &handles)) accounting.error = GetLastError();
        burnCpu(100);
        SetEvent(accounting.ready);
        HANDLE commands[]{accounting.go, accounting.finish};
        while (WaitForMultipleObjects(2, commands, FALSE, INFINITE) == WAIT_OBJECT_0) {
            FILETIME created, exited, kernelBefore, userBefore, kernelAfter, userAfter;
            if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernelBefore, &userBefore)) {
                accounting.error = GetLastError(); SetEvent(accounting.done); continue;
            }
            if (accounting.kernel) {
                LARGE_INTEGER frequency, started, now;
                QueryPerformanceFrequency(&frequency);
                QueryPerformanceCounter(&started);
                do {
                    if (!GetProcessHandleCount(GetCurrentProcess(), &handles)) { accounting.error = GetLastError(); break; }
                    QueryPerformanceCounter(&now);
                } while (now.QuadPart - started.QuadPart < frequency.QuadPart * accounting.duration / 1000);
            } else burnCpu(accounting.duration);
            if (!GetThreadTimes(GetCurrentThread(), &created, &exited, &kernelAfter, &userAfter)) {
                accounting.error = GetLastError(); SetEvent(accounting.done); continue;
            }
            accounting.user = cpuTimeNs(userAfter) - cpuTimeNs(userBefore);
            accounting.system = cpuTimeNs(kernelAfter) - cpuTimeNs(kernelBefore);
            SetEvent(accounting.done);
        }
    } catch (...) {
        accounting.error = ERROR_OUTOFMEMORY;
        SetEvent(accounting.ready);
        SetEvent(accounting.done);
    }
    return 0;
}
extern "C" JNIEXPORT jint JNICALL Java_NativeMemoryFixture_cpuCreate(JNIEnv* env, jclass) {
    try {
        api_require(!accounting.worker, "CPU workload already exists");
        accounting.ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        accounting.go = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        accounting.done = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        accounting.finish = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        api_require(accounting.ready && accounting.go && accounting.done && accounting.finish, "Cannot create CPU workload events");
        accounting.worker = CreateThread(nullptr, 0, accountingWorker, nullptr, 0, &accounting.tid);
        api_require(accounting.worker && WaitForSingleObject(accounting.ready, 10000) == WAIT_OBJECT_0 && !accounting.error,
                "Cannot initialize CPU accounting workload");
        api_require(SUCCEEDED(SetThreadDescription(accounting.worker, L"cpu-accounting-worker")),
                "Cannot name CPU accounting worker");
        return static_cast<jint>(accounting.tid);
    } catch (const std::exception& error) { env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what()); return 0; }
}
extern "C" JNIEXPORT jlongArray JNICALL Java_NativeMemoryFixture_cpuRun(JNIEnv* env, jclass, jboolean kernel, jint duration) {
    try {
        accounting.kernel = kernel != 0; accounting.duration = static_cast<DWORD>(duration);
        api_require(SetEvent(accounting.go) && WaitForSingleObject(accounting.done, 15000) == WAIT_OBJECT_0,
                "CPU accounting workload did not finish");
        jlong counters[]{static_cast<jlong>(accounting.user), static_cast<jlong>(accounting.system), accounting.error};
        auto result = env->NewLongArray(3);
        env->SetLongArrayRegion(result, 0, 3, counters);
        return result;
    } catch (const std::exception& error) { env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what()); return nullptr; }
}
extern "C" JNIEXPORT void JNICALL Java_NativeMemoryFixture_cpuClose(JNIEnv* env, jclass) {
    try {
        api_require(SetEvent(accounting.finish) && WaitForSingleObject(accounting.worker, 10000) == WAIT_OBJECT_0,
                "CPU accounting worker did not stop");
        for (auto handle : {accounting.worker, accounting.ready, accounting.go, accounting.done, accounting.finish}) CloseHandle(handle);
        accounting = {};
    } catch (const std::exception& error) { env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what()); }
}
extern "C" __declspec(dllexport) __declspec(noinline) void WindowInsideBusy() { burnCpu(80); }
extern "C" __declspec(dllexport) __declspec(noinline) void WindowOutsideBusy() { burnCpu(30); }

struct WindowWork { int cycles; int mode; };
static DWORD WINAPI windowWork(void* parameter) {
    auto work = *static_cast<WindowWork*>(parameter);
    DWORD sum = 0;
    for (int cycle = 0; cycle < work.cycles; ++cycle) {
        if (work.mode == 1) WindowOutsideBusy();
        for (DWORD i = 0; i < 10; ++i) sum += ProbeWork(i);
        auto beginResult = work.mode == 2 ? ProfilerFixture::PrivateBoundary::begin(1) : WindowBegin(1);
        if (beginResult != 18) std::abort();
        if (work.mode == 1) WindowInsideBusy();
        for (DWORD i = 0; i < 20; ++i) sum += ProbeWork(i);
        auto endResult = work.mode == 2 ? ProfilerFixture::PrivateBoundary::end(1) : WindowEnd(1);
        if (endResult != 20) std::abort();
        for (DWORD i = 0; i < 10; ++i) sum += ProbeWork(i);
        if (work.mode == 1) WindowOutsideBusy();
    }
    return sum;
}
extern "C" JNIEXPORT jlong JNICALL Java_NativeWindowFixture_run(JNIEnv*, jclass, jint mode) {
    if (mode == 3) {
        WindowWork parallel{10, 0};
        HANDLE workers[8];
        for (auto& worker : workers) {
            worker = CreateThread(nullptr, 0, windowWork, &parallel, 0, nullptr);
            if (!worker) std::abort();
        }
        if (WaitForMultipleObjects(8, workers, TRUE, 10000) != WAIT_OBJECT_0) std::abort();
        jlong total = 0;
        for (auto worker : workers) {
            DWORD value;
            if (!GetExitCodeThread(worker, &value)) std::abort();
            total += value;
            CloseHandle(worker);
        }
        return total;
    }
    WindowWork mainWork{3, mode}, workerWork{2, mode};
    DWORD sum = windowWork(&mainWork);
    auto worker = CreateThread(nullptr, 0, windowWork, &workerWork, 0, nullptr);
    if (!worker || WaitForSingleObject(worker, 10000) != WAIT_OBJECT_0) std::abort();
    DWORD other;
    if (!GetExitCodeThread(worker, &other)) std::abort();
    CloseHandle(worker);
    return sum + other;
}

static std::atomic<bool> probe_background_running{false};
static HANDLE probe_background_thread;
static DWORD WINAPI probe_background(void*) {
    while (probe_background_running.load()) {
        if (ProbeWork(10) != 37 || ProbeOther(10) != 21) std::abort();
        Sleep(1);
    }
    return 0;
}

extern "C" JNIEXPORT void JNICALL Java_NativeProbeFixture_background(JNIEnv*, jclass, jboolean start) {
    probe_background_running.store(start != 0);
    if (start) {
        probe_background_thread = CreateThread(nullptr, 0, probe_background, nullptr, 0, nullptr);
        if (!probe_background_thread) std::abort();
    } else {
        if (WaitForSingleObject(probe_background_thread, 10000) != WAIT_OBJECT_0) std::abort();
        CloseHandle(probe_background_thread);
    }
}

static DWORD WINAPI probe_worker(void*);
extern "C" JNIEXPORT void JNICALL Java_NativeProbeFixture_churn(JNIEnv*, jclass) {
    for (int i = 0; i < 4200; ++i) {
        auto thread = CreateThread(nullptr, 0, probe_worker, nullptr, 0, nullptr);
        if (!thread || WaitForSingleObject(thread, 10000) != WAIT_OBJECT_0) std::abort();
        CloseHandle(thread);
    }
}

static DWORD WINAPI probe_worker(void*) {
    DWORD result = 0;
    for (DWORD i = 0; i < 40; ++i) result += ProbeWork(i);
    return result;
}

extern "C" JNIEXPORT jlong JNICALL Java_NativeStartupFixture_run(JNIEnv*, jclass) {
    jlong result = 0;
    for (unsigned i = 0; i < 100; ++i) result += GetProcessId(GetCurrentProcess());
    return result;
}

extern "C" JNIEXPORT jlong JNICALL Java_NativeProbeFixture_run(JNIEnv*, jclass) {
    DWORD result = 0;
    for (DWORD i = 0; i < 100; ++i) result += ProbeWork(i);
    auto worker = CreateThread(nullptr, 0, probe_worker, nullptr, 0, nullptr);
    if (!worker || WaitForSingleObject(worker, 10000) != WAIT_OBJECT_0) std::abort();
    DWORD other;
    if (!GetExitCodeThread(worker, &other)) std::abort();
    CloseHandle(worker);
    return result + other;
}

struct HeldLock { int kind; CRITICAL_SECTION* critical; SRWLOCK* srw; HANDLE ready; };
static DWORD WINAPI hold_lock(void* argument) {
    auto& state = *static_cast<HeldLock*>(argument);
    if (state.kind == 0) EnterCriticalSection(state.critical);
    else AcquireSRWLockExclusive(state.srw);
    SetEvent(state.ready);
    Sleep(15);
    if (state.kind == 0) LeaveCriticalSection(state.critical);
    else ReleaseSRWLockExclusive(state.srw);
    return 0;
}

extern "C" JNIEXPORT jlongArray JNICALL Java_NativeOsLockFixture_run(JNIEnv* env, jclass) {
    CRITICAL_SECTION critical;
    InitializeCriticalSection(&critical);
    SRWLOCK exclusive = SRWLOCK_INIT, shared = SRWLOCK_INIT;
    for (int kind = 0; kind < 3; ++kind) {
        for (int iteration = 0; iteration < 20; ++iteration) {
            auto ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            HeldLock state{kind, &critical, kind == 1 ? &exclusive : &shared, ready};
            auto holder = CreateThread(nullptr, 0, hold_lock, &state, 0, nullptr);
            if (!holder || WaitForSingleObject(ready, 5000) != WAIT_OBJECT_0) std::abort();
            if (kind == 0) { EnterCriticalSection(&critical); LeaveCriticalSection(&critical); }
            else if (kind == 1) { AcquireSRWLockExclusive(&exclusive); ReleaseSRWLockExclusive(&exclusive); }
            else { AcquireSRWLockShared(&shared); ReleaseSRWLockShared(&shared); }
            if (WaitForSingleObject(holder, 5000) != WAIT_OBJECT_0) std::abort();
            CloseHandle(holder);
            CloseHandle(ready);
        }
    }
    jlong addresses[]{reinterpret_cast<jlong>(&critical), reinterpret_cast<jlong>(&exclusive), reinterpret_cast<jlong>(&shared)};
    DeleteCriticalSection(&critical);
    auto result = env->NewLongArray(3);
    env->SetLongArrayRegion(result, 0, 3, addresses);
    return result;
}

extern "C" JNIEXPORT jint JNICALL Java_NativeMemoryFixture_stress(JNIEnv*, jclass, jint count) {
    jint completed = 0;
    for (; completed < count; ++completed) {
        auto address = std::malloc(104729);
        if (!address) break;
        std::free(address);
    }
    return completed;
}

extern "C" JNIEXPORT jlongArray JNICALL Java_NativeMemoryFixture_expand(JNIEnv* env, jclass) {
    try {
        auto resize = [](void* address, std::size_t size) {
#ifdef _DEBUG
            return _expand_dbg(address, size, _NORMAL_BLOCK, __FILE__, __LINE__);
#else
            return _expand(address, size);
#endif
        };
        auto original = std::malloc(262147);
        api_require(original != nullptr, "Expand input allocation failed");
        std::memset(original, 0x5a, 64);
        auto resized = resize(original, 131081);
        api_require(resized == original && static_cast<unsigned char*>(resized)[0] == 0x5a, "In-place shrink failed");
        auto failed = resize(resized, (std::numeric_limits<std::size_t>::max)() - 4095);
        api_require(!failed && static_cast<unsigned char*>(resized)[0] == 0x5a, "Failed expand changed original allocation");
        api_require(resize(resized, 0) == resized, "Zero expand must retain the allocation");
        jlong addresses[]{reinterpret_cast<jlong>(original), reinterpret_cast<jlong>(resized)};
        std::free(resized);
        auto result = env->NewLongArray(2);
        env->SetLongArrayRegion(result, 0, 2, addresses);
        return result;
    } catch (const std::exception& error) {
        env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jlongArray JNICALL Java_NativeMemoryFixture_base(JNIEnv* env, jclass) {
    try {
        auto runtime = GetModuleHandleW(L"ucrtbase.dll");
        auto allocate = reinterpret_cast<void* (*)(std::size_t)>(GetProcAddress(runtime, "_malloc_base"));
        auto zero = reinterpret_cast<void* (*)(std::size_t, std::size_t)>(GetProcAddress(runtime, "_calloc_base"));
        auto resize = reinterpret_cast<void* (*)(void*, std::size_t)>(GetProcAddress(runtime, "_realloc_base"));
        auto release = reinterpret_cast<void (*)(void*)>(GetProcAddress(runtime, "_free_base"));
        jlong pointers[5];
        unsigned index = 0;
        auto remember = [&](void* address) { api_require(address != nullptr, "Base CRT allocation failed"); pointers[index++] = reinterpret_cast<jlong>(address); };
        auto a = allocate(65537); remember(a);
        a = resize(a, 131071); remember(a);
        auto b = zero(7, 1009); remember(b);
        auto c = allocate(98317); remember(c);
        std::memset(c, 0x5a, 64);
        api_require(!resize(c, (std::numeric_limits<std::size_t>::max)() - 4095) && static_cast<unsigned char*>(c)[0] == 0x5a,
                "Failed base realloc changed original allocation");
        auto d = allocate(49157); remember(d);
        api_require(resize(d, 0) == nullptr, "Zero base realloc did not free");
        release(a); release(b); release(c);
        auto result = env->NewLongArray(index);
        env->SetLongArrayRegion(result, 0, index, pointers);
        return result;
    } catch (const std::exception& error) {
        env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jlongArray JNICALL Java_NativeMemoryFixture_provider(JNIEnv* env, jclass, jstring path, jint phase) {
    try {
        static std::uintptr_t previousGetterAddress;
        auto chars = env->GetStringChars(path, nullptr);
        if (!chars) return nullptr;
        std::wstring filename(reinterpret_cast<const wchar_t*>(chars), env->GetStringLength(path));
        env->ReleaseStringChars(path, chars);
        auto module = LoadLibraryW(filename.c_str());
        api_require(module != nullptr, "Cannot load allocator provider fixture");
        auto allocate = reinterpret_cast<void* (*)(std::size_t)>(GetProcAddress(module, "malloc"));
        auto zero = reinterpret_cast<void* (*)(std::size_t, std::size_t)>(GetProcAddress(module, "calloc"));
        auto resize = reinterpret_cast<void* (*)(void*, std::size_t)>(GetProcAddress(module, "realloc"));
        auto release = reinterpret_cast<void (*)(void*)>(GetProcAddress(module, "free"));
        auto aligned = reinterpret_cast<void* (*)(std::size_t, std::size_t)>(GetProcAddress(module, "aligned_alloc"));
        auto posix = reinterpret_cast<int (*)(void**, std::size_t, std::size_t)>(GetProcAddress(module, "posix_memalign"));
        auto error = reinterpret_cast<int (*)(int)>(GetProcAddress(module, "ProviderError"));
        auto getterCalls = reinterpret_cast<unsigned (*)()>(GetProcAddress(module, "ProviderGetterCalls"));
        auto getterAddress = reinterpret_cast<std::uintptr_t (*)()>(GetProcAddress(module, "ProviderGetterAddress"));
        auto publicErrno = GetProcAddress(module, "_errno");
        HMODULE origin;
        api_require(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(allocate), &origin) != 0, "Cannot identify allocator implementation origin");
        api_require(origin == GetModuleHandleW(L"asyncProfiler.dll") || (error && origin == module) || (!error && origin != module),
                "Allocator provider origin did not match its implementation");
        if (error) api_require(reinterpret_cast<std::uintptr_t>(module) == 0x500000000000ULL, "Provider reload did not use the fixed base");
        if (getterAddress) {
            auto address = getterAddress();
            if (phase && previousGetterAddress) api_require(address == previousGetterAddress, "Provider getter address changed across the reload fixture");
            previousGetterAddress = address;
        }
        if (error) error(EDOM);
        errno = ERANGE;
        SetLastError(0x55667788);
        auto a = allocate(65537 + phase * 4096);
        auto windowsError = GetLastError();
        api_require(a != nullptr && errno == ERANGE && (!error || error(-1) == EDOM)
                && windowsError == (error ? 0x13579bdfUL : 0x55667788UL), "Allocator provider error state changed on success");
        jlong pointers[]{reinterpret_cast<jlong>(a), 0, 0, 0, 0};
        unsigned pointerCount = 3;
        a = resize(a, 131071 + phase * 4096); pointers[1] = reinterpret_cast<jlong>(a);
        auto b = zero(7, 1009 + phase); pointers[2] = reinterpret_cast<jlong>(b);
        api_require(a && b, "Allocator provider request failed");
        auto failed = resize(a, (std::numeric_limits<std::size_t>::max)());
        api_require(!failed && (!error || error(-1) == ENOMEM), "Allocator provider failure errno changed");
        api_require(errno == (error ? ERANGE : ENOMEM), "Allocator failure changed the caller's CRT errno");
        if (aligned && posix) {
            auto c = aligned(64, 65024 + phase * 64); pointers[pointerCount++] = reinterpret_cast<jlong>(c);
            api_require(c && reinterpret_cast<std::uintptr_t>(c) % 64 == 0, "C11 allocator alignment changed");
            api_require(!aligned(64, 65025) && error(-1) == EINVAL, "C11 allocator validation or errno changed");
            error(EDOM);
            auto output = reinterpret_cast<void*>(std::uintptr_t(0x2468));
            api_require(posix(&output, 3, 77737) == EINVAL && output == reinterpret_cast<void*>(std::uintptr_t(0x2468))
                    && error(-1) == EDOM, "Failed POSIX allocation changed output or errno");
            api_require(posix(reinterpret_cast<void**>(std::uintptr_t(1)), 3, 77737) == EINVAL,
                    "Failed POSIX allocation read an invalid output pointer");
            api_require(posix(&output, 64, 70001 + phase * 17) == 0 && reinterpret_cast<std::uintptr_t>(output) % 64 == 0
                    && error(-1) == EDOM, "POSIX allocation changed output, alignment or errno");
            pointers[pointerCount++] = reinterpret_cast<jlong>(output);
            release(c); release(output);
        }
        release(a); release(b);
        auto freeWindowsError = GetLastError();
        api_require(errno == (error ? ERANGE : ENOMEM) && (!error || freeWindowsError == 0x11223344UL),
                "Allocator free changed caller error state");
        if (getterCalls && !publicErrno) api_require(getterCalls() == 0, "A private getter from a prior provider generation was called");
        auto result = env->NewLongArray(pointerCount);
        env->SetLongArrayRegion(result, 0, pointerCount, pointers);
        FreeLibrary(module);
        api_require(GetModuleHandleW(filename.c_str()) == nullptr, "Allocator provider was pinned instead of unloading");
        return result;
    } catch (const std::exception& error) {
        env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jlongArray JNICALL Java_NativeMemoryFixture_debug(JNIEnv* env, jclass) {
#ifdef _DEBUG
    try {
        _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
        _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
        _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
        jlong pointers[17];
        unsigned index = 0;
        auto remember = [&](void* address) { api_require(address != nullptr, "Debug CRT allocation failed"); pointers[index++] = reinterpret_cast<jlong>(address); };
        auto a = _malloc_dbg(65111, _NORMAL_BLOCK, __FILE__, __LINE__); remember(a);
        std::memset(a, 0x5a, 64);
        auto failed = _realloc_dbg(a, (std::numeric_limits<std::size_t>::max)() - 4095, _NORMAL_BLOCK, __FILE__, __LINE__);
        api_require(!failed && static_cast<unsigned char*>(a)[0] == 0x5a, "Failed debug realloc changed the original allocation");
        a = _realloc_dbg(a, 130223, _NORMAL_BLOCK, __FILE__, __LINE__); remember(a);
        _free_dbg(a, _NORMAL_BLOCK);
        auto b = _calloc_dbg(7, 1009, _NORMAL_BLOCK, __FILE__, __LINE__); remember(b);
        b = _recalloc_dbg(b, 11, 1009, _NORMAL_BLOCK, __FILE__, __LINE__); remember(b);
        _free_dbg(b, _NORMAL_BLOCK);
        auto c = _aligned_malloc_dbg(65543, 64, __FILE__, __LINE__); remember(c);
        c = _aligned_realloc_dbg(c, 131101, 64, __FILE__, __LINE__); remember(c);
        c = _aligned_recalloc_dbg(c, 3, 65539, 64, __FILE__, __LINE__); remember(c);
        _aligned_free_dbg(c);
        auto d = _aligned_offset_malloc_dbg(49169, 128, 3, __FILE__, __LINE__); remember(d);
        d = _aligned_offset_realloc_dbg(d, 98327, 128, 3, __FILE__, __LINE__); remember(d);
        d = _aligned_offset_recalloc_dbg(d, 5, 32779, 128, 3, __FILE__, __LINE__); remember(d);
        _aligned_free_dbg(d);
        auto e = _malloc_dbg(90023, _NORMAL_BLOCK, __FILE__, __LINE__); remember(e);
        api_require(_realloc_dbg(e, 0, _NORMAL_BLOCK, __FILE__, __LINE__) == nullptr, "Zero debug realloc did not free");
        auto f = _calloc_dbg(3, 10007, _NORMAL_BLOCK, __FILE__, __LINE__); remember(f);
        api_require(_recalloc_dbg(f, 0, 10007, _NORMAL_BLOCK, __FILE__, __LINE__) == nullptr, "Zero debug recalloc did not free");
        auto g = _aligned_malloc_dbg(81931, 64, __FILE__, __LINE__); remember(g);
        api_require(_aligned_realloc_dbg(g, 0, 64, __FILE__, __LINE__) == nullptr, "Zero debug aligned realloc did not free");
        auto h = _aligned_offset_malloc_dbg(73753, 128, 3, __FILE__, __LINE__); remember(h);
        api_require(_aligned_offset_recalloc_dbg(h, 0, 10007, 128, 3, __FILE__, __LINE__) == nullptr, "Zero debug offset recalloc did not free");
        auto i = _aligned_malloc_dbg(61463, 64, __FILE__, __LINE__); remember(i);
        api_require(_aligned_recalloc_dbg(i, 0, 10007, 64, __FILE__, __LINE__) == nullptr, "Zero debug aligned recalloc did not free");
        auto j = _aligned_offset_malloc_dbg(114689, 128, 3, __FILE__, __LINE__); remember(j);
        api_require(_aligned_offset_realloc_dbg(j, 0, 128, 3, __FILE__, __LINE__) == nullptr, "Zero debug offset realloc did not free");
        auto dynamicMalloc = reinterpret_cast<decltype(&_malloc_dbg)>(GetProcAddress(GetModuleHandleW(L"ucrtbased.dll"), "_malloc_dbg"));
        auto dynamicFree = reinterpret_cast<decltype(&_free_dbg)>(GetProcAddress(GetModuleHandleW(L"ucrtbased.dll"), "_free_dbg"));
        auto k = dynamicMalloc(12289, _NORMAL_BLOCK, __FILE__, __LINE__); remember(k);
        dynamicFree(k, _NORMAL_BLOCK);
        auto result = env->NewLongArray(index);
        env->SetLongArrayRegion(result, 0, index, pointers);
        return result;
    } catch (const std::exception& error) {
        env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what());
        return nullptr;
    }
#else
    env->ThrowNew(env->FindClass("java/lang/AssertionError"), "Debug CRT fixture build is required");
    return nullptr;
#endif
}

extern "C" JNIEXPORT jlongArray JNICALL Java_NativeMemoryFixture_aligned(JNIEnv* env, jclass) {
    try {
        jlong pointers[11];
        unsigned index = 0;
        auto remember = [&](void* address) { api_require(address != nullptr, "Aligned CRT allocation failed"); pointers[index++] = reinterpret_cast<jlong>(address); };
        errno = EDOM;
        SetLastError(0x34567890);
        auto a = _aligned_malloc(65543, 64);
        api_require(a && errno == EDOM && GetLastError() == 0x34567890 && reinterpret_cast<std::uintptr_t>(a) % 64 == 0,
                "Aligned allocation forwarding changed error state or alignment");
        remember(a);
        std::memset(a, 0x5a, 64);
        auto failed = _aligned_realloc(a, (std::numeric_limits<std::size_t>::max)() - 4095, 64);
        api_require(!failed && errno == ENOMEM && static_cast<unsigned char*>(a)[0] == 0x5a, "Failed aligned realloc changed the original block");
        a = _aligned_realloc(a, 131101, 64); remember(a);
        a = _aligned_recalloc(a, 3, 65539, 64); remember(a);
        api_require(static_cast<unsigned char*>(a)[0] == 0x5a && static_cast<unsigned char*>(a)[196616] == 0, "Aligned recalloc did not preserve/zero memory");
        _aligned_free(a);
        auto b = _aligned_offset_malloc(49169, 128, 3); remember(b);
        api_require((reinterpret_cast<std::uintptr_t>(b) + 3) % 128 == 0, "Offset alignment changed");
        b = _aligned_offset_realloc(b, 98327, 128, 3); remember(b);
        b = _aligned_offset_recalloc(b, 5, 32779, 128, 3); remember(b);
        api_require((reinterpret_cast<std::uintptr_t>(b) + 3) % 128 == 0 && static_cast<unsigned char*>(b)[163894] == 0, "Offset recalloc semantics changed");
        _aligned_free(b);
        auto c = _recalloc(nullptr, 7, 10007); remember(c);
        std::memset(c, 0x3c, 64);
        failed = _recalloc(c, (std::numeric_limits<std::size_t>::max)() / 2, 3);
        api_require(!failed && errno == ENOMEM && static_cast<unsigned char*>(c)[0] == 0x3c, "Overflow recalloc changed the original block");
        c = _recalloc(c, 11, 10007); remember(c);
        api_require(static_cast<unsigned char*>(c)[0] == 0x3c && static_cast<unsigned char*>(c)[110076] == 0, "Recalloc did not preserve/zero memory");
        api_require(_recalloc(c, 0, 10007) == nullptr, "Zero recalloc did not free");
        auto d = _aligned_malloc(81931, 64); remember(d);
        api_require(_aligned_realloc(d, 0, 3) == nullptr, "Zero aligned realloc did not free before alignment validation");
        auto e = _aligned_offset_malloc(73753, 128, 3); remember(e);
        api_require(_aligned_offset_recalloc(e, 0, (std::numeric_limits<std::size_t>::max)(), 128, 3) == nullptr, "Zero offset recalloc did not free");
        auto f = _aligned_malloc(61463, 64); remember(f);
        api_require(_aligned_recalloc(f, 0, 10007, 64) == nullptr, "Zero aligned recalloc did not free");
        auto result = env->NewLongArray(index);
        env->SetLongArrayRegion(result, 0, index, pointers);
        return result;
    } catch (const std::exception& error) {
        env->ThrowNew(env->FindClass("java/lang/AssertionError"), error.what());
        return nullptr;
    }
}

extern "C" JNIEXPORT jlongArray JNICALL Java_NativeMemoryFixture_run(JNIEnv* env, jclass) {
    auto a = std::malloc(65537);
    auto b = std::calloc(7, 1009);
    auto c = std::malloc(32771);
    auto old_c = reinterpret_cast<std::uintptr_t>(c);
    auto new_c = std::realloc(c, 131071);
    auto d = std::malloc(49157);
    auto old_d = reinterpret_cast<std::uintptr_t>(d);
    auto new_d = std::realloc(d, 0);
    auto e = std::malloc(98317);
    errno = EDOM;
    auto failed = std::realloc(e, (std::numeric_limits<std::size_t>::max)() - 4095);
    auto failure_errno = errno;
    auto overflow = std::calloc((std::numeric_limits<std::size_t>::max)() / 2, 3);
    auto overflow_errno = errno;
    auto dynamic_malloc = reinterpret_cast<void* (*)(std::size_t)>(GetProcAddress(GetModuleHandleW(L"ucrtbase.dll"), "malloc"));
    auto f = dynamic_malloc(81929);
    auto legacy = LoadLibraryW(L"msvcrt.dll");
    auto legacy_malloc = reinterpret_cast<void* (*)(std::size_t)>(GetProcAddress(legacy, "malloc"));
    auto legacy_free = reinterpret_cast<void (*)(void*)>(GetProcAddress(legacy, "free"));
    auto legacy_errno = reinterpret_cast<int* (*)()>(GetProcAddress(legacy, "_errno"));
    *legacy_errno() = EDOM;
    SetLastError(0x23456789);
    auto h = legacy_malloc(12289);
    auto legacy_valid = h && *legacy_errno() == EDOM && GetLastError() == 0x23456789;
    auto z = std::malloc(0);
    auto cz = std::calloc(0, 100);
    auto valid = a && b && new_c && e && f && !new_d && !failed && !overflow
            && failure_errno == ENOMEM && overflow_errno == ENOMEM && legacy_valid;
    // Check forwarding preserves successful calls' errno and Windows last-error.
    errno = EDOM;
    SetLastError(0x12345678);
    auto g = std::malloc(73739);
    valid &= g && errno == EDOM && GetLastError() == 0x12345678;
    jlong values[]{reinterpret_cast<jlong>(a), reinterpret_cast<jlong>(b), static_cast<jlong>(old_c),
        reinterpret_cast<jlong>(new_c), static_cast<jlong>(old_d), reinterpret_cast<jlong>(e),
        reinterpret_cast<jlong>(f), reinterpret_cast<jlong>(g), reinterpret_cast<jlong>(h)};
    std::free(a); std::free(b); std::free(new_c); std::free(e); std::free(f); std::free(g);
    std::free(z); std::free(cz); std::free(nullptr);
    legacy_free(h);
    FreeLibrary(legacy);
    if (!valid) {
        env->ThrowNew(env->FindClass("java/lang/AssertionError"), "CRT allocation forwarding changed semantics");
        return nullptr;
    }
    auto result = env->NewLongArray(static_cast<jsize>(sizeof(values) / sizeof(values[0])));
    env->SetLongArrayRegion(result, 0, static_cast<jsize>(sizeof(values) / sizeof(values[0])), values);
    return result;
}
