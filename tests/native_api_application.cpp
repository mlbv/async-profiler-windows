/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <malloc.h>
#include "../core/src/asprof.h"
#include "native_dynamic_code.h"
#pragma comment(lib, "advapi32.lib")

static std::string output;
static void collect(const char* data, size_t size) { output.append(data, size); }
static void require(bool value, const char* message) { if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(2); } }
static std::string utf8(const std::wstring& value) {
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    require(size > 0, "Invalid UTF-16 path");
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}
extern "C" __declspec(dllexport) __declspec(noinline) void NativeCpuWork() {
    LARGE_INTEGER start, now, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    volatile std::uint64_t value = 1;
    do {
        for (int i = 0; i < 10000; ++i) value = (value ^ (value >> 13)) * 0x100000001b3ULL;
        QueryPerformanceCounter(&now);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart);
}
extern "C" __declspec(dllexport) __declspec(noinline) void NativeKernelWork() {
    using Query = LONG (NTAPI*)(ULONG, void*, ULONG, ULONG*);
    auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    require(query != nullptr, "Cannot find kernel workload entry");
    std::vector<unsigned char> buffer(4 * 1024 * 1024);
    LARGE_INTEGER start, now, frequency;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    do {
        ULONG length = 0;
        require(query(5, buffer.data(), static_cast<ULONG>(buffer.size()), &length) >= 0, "Kernel workload query failed");
        QueryPerformanceCounter(&now);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart / 2);
}
static volatile unsigned dynamicStackBytes = 256;
extern "C" __declspec(dllexport) __declspec(noinline) void NativeDynamicWork(const DynamicCode& code) {
    auto stack = static_cast<volatile unsigned char*>(_alloca(dynamicStackBytes));
    stack[0] = 1;
    LARGE_INTEGER start, now, frequency;
    QueryPerformanceFrequency(&frequency); QueryPerformanceCounter(&start);
    volatile std::uint64_t value = 0;
    do {
        value = value ^ code.run();
        QueryPerformanceCounter(&now);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart);
    require(stack[0] == 1, "Dynamic caller stack was corrupted");
}
struct HeldCritical { CRITICAL_SECTION* lock; HANDLE ready; };
static DWORD WINAPI holdCritical(void* argument) {
    auto& held = *static_cast<HeldCritical*>(argument);
    EnterCriticalSection(held.lock);
    SetEvent(held.ready);
    Sleep(50);
    LeaveCriticalSection(held.lock);
    return 0;
}
int wmain(int argc, wchar_t** argv) {
    require(argc >= 3 && argc <= 6, "Usage: nativeApiApplication DLL OUTPUT_DIRECTORY [ETW_SOURCE [MODE [INTERVAL]]]");
    auto library = LoadLibraryW(argv[1]);
    require(library != nullptr, "Cannot load profiler");
    auto init = reinterpret_cast<asprof_init_t>(GetProcAddress(library, "asprof_init"));
    auto execute = reinterpret_cast<asprof_execute_t>(GetProcAddress(library, "asprof_execute"));
    auto threadData = reinterpret_cast<asprof_get_thread_local_data_t>(GetProcAddress(library, "asprof_get_thread_local_data"));
    auto registerEvent = reinterpret_cast<asprof_register_jfr_event_t>(GetProcAddress(library, "asprof_register_jfr_event"));
    auto emit = reinterpret_cast<asprof_emit_jfr_event_t>(GetProcAddress(library, "asprof_emit_jfr_event"));
    require(init && execute && threadData && registerEvent && emit, "Missing C API exports");
    init();
    require(GetModuleHandleW(L"jvm.dll") == nullptr, "A JVM was loaded into the native fixture");
    auto command = [&](const std::string& text) {
        auto error = execute(text.c_str(), collect);
        if (error) { std::fprintf(stderr, "%s: %s\n", text.c_str(), error); std::exit(3); }
    };
    auto directory = utf8(argv[2]) + "/";
    auto counter = threadData();
    require(counter != nullptr, "Missing thread-local data");
    output.clear();
    command("version");
    require(output.find("4.5-windows") != std::string::npos, "Wrong profiler version");
    if (argc >= 4) {
        auto source = utf8(argv[3]);
        auto mode = argc >= 5 ? utf8(argv[4]) : "record";
        bool dynamic = mode == "jit" || mode == "jit-metadata" || mode == "jit-growable" || mode == "jit-metadata-growable"
            || mode == "jit-metadata-growable-shadow" || mode == "jit-metadata-growable-replace"
            || mode == "jit-growable-gpr-save" || mode == "jit-growable-gpr-push" || mode == "jit-growable-split"
            || mode == "jit-metadata-growable-poison";
        dynamic = dynamic || mode == "jit-growable-outside";
        dynamic = dynamic || mode == "jit-metadata-growable-three" || mode == "jit-metadata-growable-deep";
        dynamic = dynamic || mode == "jit-metadata-growable-restart" || mode == "jit-metadata-growable-shadow-restart";
        dynamic = dynamic || mode == "jit-metadata-growable-lower";
        bool recording = dynamic || mode == "record" || mode == "restart" || mode == "restart-thread" || mode == "kernel" || mode == "kernel-denied";
        require(recording || mode == "exit" || mode == "kill" || mode == "job-kill" || mode == "job-blocked" || mode == "helper-kill", "Unknown ETW fixture mode");
        if (mode == "kernel-denied") {
            HANDLE token;
            require(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) != FALSE, "Cannot open fixture token");
            TOKEN_PRIVILEGES privilege{};
            privilege.PrivilegeCount = 1;
            require(LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &privilege.Privileges[0].Luid) != FALSE, "Cannot find debug privilege");
            privilege.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
            require(AdjustTokenPrivileges(token, FALSE, &privilege, 0, nullptr, nullptr) != FALSE, "Cannot remove the fixture's debug privilege");
            CloseHandle(token);
        }
        HANDLE job = nullptr;
        if (mode == "job-kill" || mode == "job-blocked") {
            job = CreateJobObjectW(nullptr, nullptr);
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags = mode == "job-kill" ? JOB_OBJECT_LIMIT_BREAKAWAY_OK : JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            require(job && SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))
                && AssignProcessToJobObject(job, GetCurrentProcess()), "Cannot configure the fixture's job");
        }
        auto interval = argc == 6 ? utf8(argv[5]) : source == "etw:Timer" ? std::string("1000000") : std::string("10000000");
        auto start = "start,event=" + source + ",interval=" + interval + ",jfr,file=" + directory + "etw.jfr";
        auto error = execute(start.c_str(), collect);
        if (error) { std::fprintf(stderr, "%s\n", error); return 77; }
        NativeCpuWork();
        if (dynamic) {
            auto registration = mode.ends_with("lower") ? DynamicCode::Registration::LowerBase
                : mode.ends_with("deep") ? DynamicCode::Registration::DeepFrames
                : mode.ends_with("three") ? DynamicCode::Registration::ThreeFrames
                : mode.ends_with("outside") ? DynamicCode::Registration::OutsideInfo
                : mode.ends_with("poison") ? DynamicCode::Registration::PoisonFrame
                : mode.ends_with("split") ? DynamicCode::Registration::SplitBytes
                : mode.ends_with("gpr-save") ? DynamicCode::Registration::GprSave
                : mode.ends_with("gpr-push") ? DynamicCode::Registration::GprPush
                : mode.find("-shadow") != std::string::npos ? DynamicCode::Registration::ShadowClassic
                : mode.ends_with("replace") ? DynamicCode::Registration::Overlap
                : mode.find("growable") != std::string::npos ? DynamicCode::Registration::Growable : DynamicCode::Registration::Fixed;
            auto runDynamic = [&] {
                DynamicCode code(mode.starts_with("jit-metadata"), registration);
                NativeDynamicWork(code);
            };
            runDynamic();
            if (mode.ends_with("restart")) {
                command("stop");
                command("collapsed,total,file=" + directory + "first.collapsed");
                command(start);
                runDynamic();
            }
        }
        if (mode == "kernel" || mode == "kernel-denied") NativeKernelWork();
        if (mode == "restart" || mode == "restart-thread") {
            command("stop");
            command(start);
            NativeCpuWork();
            if (mode == "restart-thread") {
                auto worker = CreateThread(nullptr,0,[](LPVOID) -> DWORD { NativeCpuWork(); return 0; },nullptr,0,nullptr);
                require(worker && WaitForSingleObject(worker,10000) == WAIT_OBJECT_0,"Restart worker failed");
                CloseHandle(worker);
            }
        }
        if (!recording) {
            output.clear(); command("metrics");
            std::printf("%sETW_READY %lu\n", output.c_str(), GetCurrentProcessId());
            std::fflush(stdout);
            if (mode == "helper-kill") {
                std::getchar();
                // Companion loss stops the private trace; stop still finalizes the
                // recording and reports the loss.
                auto stopped = execute("stop", collect);
                require(stopped && std::strstr(stopped, "(Windows error 109)"), "Companion death did not fail stop");
                output.clear(); command("metrics");
                require(output.find("windows_etw_failure 109\n") != std::string::npos, "Missing companion death was not reported");
                auto previousCounter = counter->sample_counter;
                auto restart = start;
                restart.replace(restart.rfind("etw.jfr"), 7, "restart.jfr");
                command(restart);
                NativeCpuWork();
                command("stop");
                command("collapsed,total,file=" + directory + "etw.collapsed");
                output.clear(); command("metrics");
                require(output.find("windows_etw_failure 0\n") != std::string::npos, "ETW restart after companion death failed");
                require(counter->sample_counter > previousCounter, "ETW restart did not record new samples");
                std::puts("ETW_RECOVERY_OK");
                return 0;
            }
            if (mode == "kill") Sleep(INFINITE);
            else {
                std::getchar();
                if (mode == "job-kill") TerminateJobObject(job, 99);
                return 0;
            }
        }
        command("stop");
        command("collapsed,total,file=" + directory + "etw.collapsed");
        command("otlp,total,file=" + directory + "native.otlp");
        output.clear(); command("metrics");
        std::printf("%s", output.c_str());
        require(output.find("windows_etw_failure 0\n") != std::string::npos, "ETW capture/cleanup failed");
        require(output.find("windows_etw_events_lost 0\n") != std::string::npos, "ETW lost events");
        require(output.find("windows_etw_malformed_events 0\n") != std::string::npos, "Unrecognized ETW payload");
        require(counter->sample_counter > 0, "Native ETW samples did not update the thread counter");
        require(GetModuleHandleW(L"jvm.dll") == nullptr, "ETW capture unexpectedly loaded a JVM");
        std::puts("NATIVE_ETW_OK");
        return 0;
    }
    auto key = registerEvent("native.fixture");
    require(key > 0, "Cannot register native event");
    command("start,event=cycles,interval=1000000,jfr,file=" + directory + "cycles.jfr");
    NativeCpuWork();
    std::uint8_t payload[256];
    for (unsigned i = 0; i < sizeof(payload); ++i) payload[i] = static_cast<std::uint8_t>(i);
    require(!emit(key, payload, sizeof(payload)), "Cannot emit native event");
    command("stop");
    require(counter->sample_counter > 0, "Native thread sample counter did not update");
    command("collapsed,total,file=" + directory + "cycles.collapsed");
    command("start,event=nativemem,nativemem=1,jfr,file=" + directory + "memory.jfr");
    auto marker = std::malloc(131071);
    require(marker != nullptr, "Allocation failed");
    std::memset(marker, 1, 131071);
    std::printf("ALLOCATION %llu\n", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(marker)));
    std::free(marker);
    command("stop");
    CRITICAL_SECTION critical;
    InitializeCriticalSection(&critical);
    HeldCritical held{&critical, CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    require(held.ready != nullptr, "Cannot create lock fixture event");
    command("start,nativelock=1ms,jfr,file=" + directory + "locks.jfr");
    auto worker = CreateThread(nullptr, 0, holdCritical, &held, 0, nullptr);
    require(worker && WaitForSingleObject(held.ready, 10000) == WAIT_OBJECT_0, "Lock fixture failed");
    EnterCriticalSection(&critical);
    LeaveCriticalSection(&critical);
    require(WaitForSingleObject(worker, 10000) == WAIT_OBJECT_0, "Lock worker failed");
    command("stop");
    CloseHandle(worker);
    CloseHandle(held.ready);
    DeleteCriticalSection(&critical);
    require(GetModuleHandleW(L"jvm.dll") == nullptr, "The profiler unexpectedly loaded a JVM");
    std::puts("NATIVE_API_OK");
    return 0;
}
