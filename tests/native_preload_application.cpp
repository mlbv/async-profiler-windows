/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Native application for asprof-helper --preload. It never loads a JVM. The malloc, interposed,
// dlopen and locks modes follow upstream's malloc_plt_dyn, preload_malloc, profile_with_dlopen
// and native_lock_contention fixtures; api follows native_api.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include "../core/src/asprof.h"
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")

constexpr size_t MALLOC_SIZE = 1999993;
constexpr size_t MALLOC_DYN_SIZE = 2000003;
// Captured by a dynamic initializer before main, after a preloaded profiler has patched the import.
static void* (*malloc_dynamic)(size_t) = malloc;

static void require(bool value, const char* message) {
    if (!value) {
        std::fprintf(stderr, "%s\n", message);
        std::exit(2);
    }
}
static std::string utf8(const wchar_t* value) {
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, nullptr, 0, nullptr, nullptr);
    require(size > 0, "Invalid UTF-16 argument");
    std::string result(size - 1, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, result.data(), size, nullptr, nullptr);
    return result;
}
static void output(const char* data, size_t size) { std::fwrite(data, 1, size, stdout); }
static void printPid() {
    std::printf("PID %lu\n", GetCurrentProcessId());
    std::fflush(stdout);
}

// Child processes run this executable again; their identifiers are printed for the test.
static std::wstring self() {
    wchar_t path[MAX_PATH];
    require(GetModuleFileNameW(nullptr, path, MAX_PATH) < MAX_PATH, "Executable path too long");
    return path;
}
static std::wstring childCommand(const std::wstring& arguments) { return L"\"" + self() + L"\" " + arguments; }
static int finish(PROCESS_INFORMATION& child) {
    std::printf("CHILD %lu\n", child.dwProcessId);
    std::fflush(stdout);
    DWORD code = 0;
    require(WaitForSingleObject(child.hProcess, INFINITE) == WAIT_OBJECT_0 && GetExitCodeProcess(child.hProcess, &code), "Child wait failed");
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    return static_cast<int>(code);
}
static int spawn(const std::wstring& arguments, DWORD flags = 0, void* environment = nullptr) {
    auto command = childCommand(arguments);
    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION child;
    require(CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, flags, environment, nullptr, &startup, &child) != FALSE,
        "CreateProcessW failed");
    return finish(child);
}

struct Profiler {
    asprof_execute_t execute;
    asprof_error_str_t error;
    explicit Profiler(const wchar_t* path) {
        auto library = LoadLibraryW(path);
        require(library != nullptr, "Cannot load the profiler");
        auto init = reinterpret_cast<asprof_init_t>(GetProcAddress(library, "asprof_init"));
        execute = reinterpret_cast<asprof_execute_t>(GetProcAddress(library, "asprof_execute"));
        error = reinterpret_cast<asprof_error_str_t>(GetProcAddress(library, "asprof_error_str"));
        require(init && execute && error, "Missing C API exports");
        init();
    }
    void run(const std::string& command) const {
        if (auto failure = execute(command.c_str(), output)) {
            std::fprintf(stderr, "%s: %s\n", command.c_str(), error(failure));
            std::exit(3);
        }
    }
};

extern "C" __declspec(noinline) void PreloadCpuWork() {
    LARGE_INTEGER start, now, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    volatile std::uint64_t value = 1;
    do {
        for (int i = 0; i < 10000; ++i) value = (value ^ (value >> 13)) * 0x100000001b3ULL;
        QueryPerformanceCounter(&now);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart * 3 / 2);
}

static void preloadOrderTest() {
    auto memory = static_cast<unsigned char*>(malloc(MALLOC_SIZE));
    require(memory != nullptr, "malloc failed");
    for (size_t i = 0; i < MALLOC_SIZE; ++i) {
        if (memory[i] != 0xff) {
            std::fprintf(stderr, "malloc error, expected 0xff but found 0x%x\n", memory[i]);
            std::exit(1);
        }
    }
    free(memory);
}

static CRITICAL_SECTION mutex;
static SRWLOCK rwlock = SRWLOCK_INIT;
static DWORD WINAPI mutexContentionThread(void*) {
    for (int i = 0; i < 50; ++i) {
        EnterCriticalSection(&mutex);
        Sleep(5);
        LeaveCriticalSection(&mutex);
        Sleep(1);
    }
    return 0;
}
static DWORD WINAPI rwlockReaderThread(void*) {
    for (int i = 0; i < 30; ++i) {
        AcquireSRWLockShared(&rwlock);
        Sleep(3);
        ReleaseSRWLockShared(&rwlock);
        Sleep(1);
    }
    return 0;
}
static DWORD WINAPI rwlockWriterThread(void*) {
    for (int i = 0; i < 15; ++i) {
        AcquireSRWLockExclusive(&rwlock);
        Sleep(5);
        ReleaseSRWLockExclusive(&rwlock);
        Sleep(2);
    }
    return 0;
}
static void runThreads(LPTHREAD_START_ROUTINE first, int firstCount, LPTHREAD_START_ROUTINE second, int secondCount) {
    HANDLE threads[8];
    int count = 0;
    for (int i = 0; i < firstCount; ++i) threads[count++] = CreateThread(nullptr, 0, first, nullptr, 0, nullptr);
    for (int i = 0; i < secondCount; ++i) threads[count++] = CreateThread(nullptr, 0, second, nullptr, 0, nullptr);
    for (int i = 0; i < count; ++i) require(threads[i] != nullptr, "CreateThread failed");
    require(WaitForMultipleObjects(count, threads, TRUE, INFINITE) == WAIT_OBJECT_0, "Thread wait failed");
    for (int i = 0; i < count; ++i) CloseHandle(threads[i]);
}

int wmain(int argc, wchar_t** argv) {
    require(argc >= 2, "Usage: nativePreloadApplication MODE [ARGS...]");
    std::wstring mode = argv[1];
    if (mode == L"exit" && argc == 3) return static_cast<int>(std::wcstoul(argv[2], nullptr, 0));
    if (mode == L"args" && argc >= 3) {
        // Arguments after the output path, as UTF-16LE terminated by NUL characters.
        FILE* file;
        require(_wfopen_s(&file, argv[2], L"wb") == 0, "Cannot create the argument file");
        for (int i = 3; i < argc; ++i) std::fwrite(argv[i], sizeof(wchar_t), std::wcslen(argv[i]) + 1, file);
        require(std::fclose(file) == 0, "Cannot write the argument file");
        return 0;
    }
    if (mode == L"marker" && argc == 3) {
        FILE* file;
        require(_wfopen_s(&file, argv[2], L"wb") == 0 && std::fclose(file) == 0, "Cannot create the marker");
        return 0;
    }
    if (mode == L"wait" && argc == 3) {
        // Records the process ID as one complete line, then runs until terminated.
        FILE* file;
        require(_wfopen_s(&file, argv[2], L"wb") == 0, "Cannot create the process ID file");
        std::fprintf(file, "%lu\n", GetCurrentProcessId());
        require(std::fclose(file) == 0, "Cannot write the process ID file");
        Sleep(INFINITE);
    }
    if (mode == L"tree" && argc == 3) {
        // Every process of the tree burns CPU, then the next level starts.
        printPid();
        PreloadCpuWork();
        int depth = _wtoi(argv[2]);
        return depth > 0 ? spawn(L"tree " + std::to_wstring(depth - 1)) : 0;
    }
    if (mode == L"cpu-marker" && argc == 3) {
        FILE* file;
        require(_wfopen_s(&file, argv[2], L"wb") == 0 && std::fclose(file) == 0, "Cannot create the marker");
        PreloadCpuWork();
        return 0;
    }
    if (mode == L"spawn-suspended" && argc == 3) {
        auto command = childCommand(L"cpu-marker \"" + std::wstring(argv[2]) + L"\"");
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION child;
        require(CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &startup, &child) != FALSE,
            "CreateProcessW failed");
        require(SuspendThread(child.hThread) == 1 && ResumeThread(child.hThread) == 2, "The child is not suspended exactly once");
        Sleep(300);
        require(GetFileAttributesW(argv[2]) == INVALID_FILE_ATTRIBUTES, "The suspended child ran");
        require(ResumeThread(child.hThread) == 1, "Cannot resume the child");
        int code = finish(child);
        require(GetFileAttributesW(argv[2]) != INVALID_FILE_ATTRIBUTES, "The resumed child did not run");
        return code;
    }
    if (mode == L"shell" && argc == 2) {
        require(SUCCEEDED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)), "CoInitializeEx failed");
        auto file = self();
        SHELLEXECUTEINFOW info{sizeof(info)};
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        info.lpFile = file.c_str();
        info.lpParameters = L"cpu";
        info.nShow = SW_HIDE;
        require(ShellExecuteExW(&info) && info.hProcess, "ShellExecuteExW failed");
        PROCESS_INFORMATION child{info.hProcess, nullptr, GetProcessId(info.hProcess), 0};
        std::printf("CHILD %lu\n", child.dwProcessId);
        std::fflush(stdout);
        DWORD code = 0;
        require(WaitForSingleObject(info.hProcess, INFINITE) == WAIT_OBJECT_0 && GetExitCodeProcess(info.hProcess, &code), "Child wait failed");
        CloseHandle(info.hProcess);
        return static_cast<int>(code);
    }
    if (mode == L"spawn-ansi" && argc == 2) {
        char path[MAX_PATH];
        require(GetModuleFileNameA(nullptr, path, MAX_PATH) < MAX_PATH, "Executable path too long");
        std::string command = std::string("\"") + path + "\" cpu";
        STARTUPINFOA startup{sizeof(startup)};
        PROCESS_INFORMATION child;
        require(CreateProcessA(nullptr, command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &child) != FALSE, "CreateProcessA failed");
        return finish(child);
    }
    if (mode == L"spawn-user" && argc == 2) {
        HANDLE token, primary;
        require(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &token) != FALSE, "OpenProcessToken failed");
        require(DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &primary) != FALSE, "DuplicateTokenEx failed");
        auto command = childCommand(L"cpu");
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION child;
        require(CreateProcessAsUserW(primary, nullptr, command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &child) != FALSE,
            "CreateProcessAsUserW failed");
        CloseHandle(primary);
        CloseHandle(token);
        return finish(child);
    }
    if (mode == L"spawn32" && argc == 2) {
        wchar_t windows[MAX_PATH];
        require(GetSystemWindowsDirectoryW(windows, MAX_PATH) != 0, "Cannot find the Windows directory");
        std::wstring command = L"\"" + std::wstring(windows) + L"\\SysWOW64\\cmd.exe\" /c exit 7";
        STARTUPINFOW startup{sizeof(startup)};
        PROCESS_INFORMATION child;
        require(CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startup, &child) != FALSE,
            "CreateProcessW failed");
        return finish(child);
    }
    if (mode == L"spawn-noenv" && argc == 2) {
        // The child's environment omits ASPROF_COMMAND.
        auto strings = GetEnvironmentStringsW();
        std::wstring environment;
        for (auto entry = strings; *entry; entry += std::wcslen(entry) + 1) {
            if (_wcsnicmp(entry, L"ASPROF_COMMAND=", 15) != 0) environment.append(entry, std::wcslen(entry) + 1);
        }
        environment.push_back(L'\0');
        FreeEnvironmentStringsW(strings);
        return spawn(L"cpu", CREATE_UNICODE_ENVIRONMENT, environment.data());
    }
    if (mode == L"cpu" && argc == 2) {
        printPid();
        PreloadCpuWork();
        return 0;
    }
    if (mode == L"malloc" && argc == 2) {
        void* p = malloc(MALLOC_SIZE);
        void* q = malloc_dynamic(MALLOC_DYN_SIZE);
        free(p);
        free(q);
        return 0;
    }
    if (mode == L"interposed" && argc == 2) {
        preloadOrderTest();
        return 0;
    }
    if (mode == L"api-interposed" && argc == 4) {
        Profiler profiler(argv[2]);
        profiler.run("start,nativemem,file=" + utf8(argv[3]));
        preloadOrderTest();
        profiler.run("stop");
        return 0;
    }
    if ((mode == L"dlopen-first" || mode == L"profile-first") && argc == 5) {
        Profiler profiler(argv[2]);
        HMODULE library = mode == L"dlopen-first" ? LoadLibraryW(argv[3]) : nullptr;
        profiler.run("start,nativemem,cstack=dwarf,file=" + utf8(argv[4]));
        if (!library) library = LoadLibraryW(argv[3]);
        require(library != nullptr, "Cannot load the allocating library");
        auto callMalloc = reinterpret_cast<void* (*)(size_t)>(GetProcAddress(library, "call_malloc"));
        require(callMalloc != nullptr, "Missing call_malloc");
        free(callMalloc(MALLOC_SIZE));
        profiler.run("stop");
        return 0;
    }
    if (mode == L"locks" && argc == 2) {
        InitializeCriticalSection(&mutex);
        std::printf("Testing mutex contention...\n");
        runThreads(mutexContentionThread, 4, nullptr, 0);
        std::printf("Testing rwlock contention...\n");
        runThreads(rwlockReaderThread, 4, rwlockWriterThread, 2);
        DeleteCriticalSection(&mutex);
        return 0;
    }
    if (mode == L"api-exit" && argc == 4) {
        // Returns from main with the recording running; process exit finalizes it.
        Profiler profiler(argv[2]);
        profiler.run("start,event=cpu,interval=1ms,file=" + utf8(argv[3]));
        PreloadCpuWork();
        return 0;
    }
    if (mode == L"api-cstack" && argc == 5) {
        Profiler profiler(argv[2]);
        profiler.run("start,event=cpu,interval=1ms,cstack=" + utf8(argv[3]));
        PreloadCpuWork();
        profiler.run("stop,file=" + utf8(argv[4]));
        return 0;
    }
    if (mode == L"api" && argc == 4) {
        Profiler profiler(argv[2]);
        std::printf("Starting profiler\n");
        profiler.run("start,event=cpu,interval=1ms,wall=10ms,cstack=dwarf,loglevel=debug,file=" + utf8(argv[3]));
        Sleep(2000);
        std::printf("Stopping profiler\n");
        profiler.run("stop");
        return 0;
    }
    std::fprintf(stderr, "Unknown mode or argument count\n");
    return 2;
}
