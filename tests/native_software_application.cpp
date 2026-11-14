/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>
#include "../core/src/asprof.h"
#pragma comment(lib, "advapi32.lib")

static void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s (Windows error %lu)\n", message, GetLastError()); std::exit(2); }
}
static std::string output;
static void collect(const char* data, size_t size) { output.append(data, size); }
static std::string utf8(const std::wstring& value) {
    auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    require(size > 0, "Invalid UTF-16 argument");
    std::string result(size, '\0');
    require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr) == size,
            "Cannot encode argument");
    return result;
}
static void requireTokenLevel(bool elevated) {
    HANDLE token = nullptr;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) != FALSE, "Cannot query target token");
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    require(GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) != FALSE, "Cannot query target elevation");
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &size);
    std::vector<unsigned char> data(size);
    require(GetTokenInformation(token, TokenIntegrityLevel, data.data(), size, &size) != FALSE, "Cannot query target integrity");
    auto sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(data.data())->Label.Sid;
    auto integrity = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
    require(elevated ? elevation.TokenIsElevated && integrity == SECURITY_MANDATORY_HIGH_RID
                     : !elevation.TokenIsElevated && integrity == SECURITY_MANDATORY_MEDIUM_RID,
            elevated ? "Local target must run elevated" : "Broker target must run at medium integrity");
    require(CloseHandle(token) != FALSE, "Cannot close target token");
}
extern "C" __declspec(dllexport) __declspec(noinline) void NativePageFaultWork() {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    auto bytes = static_cast<size_t>(info.dwPageSize) * 256;
    for (unsigned batch = 0; batch < 8; ++batch) {
        auto pages = static_cast<volatile unsigned char*>(VirtualAlloc(nullptr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        require(pages != nullptr, "Cannot allocate fresh pages");
        for (size_t offset = 0; offset < bytes; offset += info.dwPageSize) pages[offset] = static_cast<unsigned char>(batch + 1);
        require(VirtualFree(const_cast<unsigned char*>(pages), 0, MEM_RELEASE) != FALSE, "Cannot release fresh pages");
    }
}
extern "C" __declspec(dllexport) __declspec(noinline) void NativeContextSwitchWork() {
    for (unsigned index = 0; index < 128; ++index) Sleep(1);
}
extern "C" __declspec(dllexport) __declspec(noinline) void NativeSoftwareWorkload(bool faults) {
    if (faults) NativePageFaultWork();
    else NativeContextSwitchWork();
    require(GetModuleHandleW(L"jvm.dll") == nullptr, "Workload loaded a JVM");
}
static DWORD WINAPI watchdog(void* argument) {
    auto result = WaitForSingleObject(static_cast<HANDLE>(argument), 240000);
    if (result != WAIT_OBJECT_0) {
        std::fputs("Native software fixture watchdog expired\n", stderr);
        TerminateProcess(GetCurrentProcess(), 124);
    }
    return 0;
}
static bool readCommand(const char* expected) {
    char command[64]{};
    require(std::fgets(command, sizeof(command), stdin) != nullptr, "Command pipe closed");
    command[std::strcspn(command, "\r\n")] = '\0';
    return std::strcmp(command, expected) == 0;
}
int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wcscmp(argv[1], L"--help") == 0) {
        std::puts("nativeSoftwareApplication --self-test | DLL OUTPUT_DIRECTORY [local]\n"
                  "Capture protocol: READY pid, one 'capture' per fixed case, then 'exit'.\n"
                  "local captures in this elevated process instead of through the broker.");
        return 0;
    }
    auto local = argc == 4 && std::wcscmp(argv[3], L"local") == 0;
    require(argc == 3 || local || (argc == 2 && std::wcscmp(argv[1], L"--self-test") == 0),
            "Usage: nativeSoftwareApplication --self-test | DLL OUTPUT_DIRECTORY [local]");
    setvbuf(stdout, nullptr, _IONBF, 0);
    requireTokenLevel(local);
    require(GetModuleHandleW(L"jvm.dll") == nullptr, "Native target already has a JVM");
    auto finished = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    require(finished != nullptr, "Cannot create watchdog completion event");
    auto guard = CreateThread(nullptr, 0, watchdog, finished, 0, nullptr);
    require(guard != nullptr, "Cannot start fixture watchdog");
    if (argc == 2) {
        NativeSoftwareWorkload(true);
        NativeSoftwareWorkload(false);
        std::puts("NATIVE_SOFTWARE_SELF_TEST_OK medium=1 jvm=0 freshPageTouches=2048 voluntarySleeps=128");
    } else {
        auto library = LoadLibraryW(argv[1]);
        require(library != nullptr, "Cannot load candidate profiler");
        auto init = reinterpret_cast<asprof_init_t>(GetProcAddress(library, "asprof_init"));
        auto execute = reinterpret_cast<asprof_execute_t>(GetProcAddress(library, "asprof_execute"));
        require(init && execute, "Missing native C API exports");
        init();
        auto command = [&](const std::string& text) {
            output.clear();
            auto error = execute(text.c_str(), collect);
            if (error) {
                std::fprintf(stderr, "%s: %s\n", text.c_str(), error);
                output.clear();
                auto metricsError = execute("metrics", collect);
                if (metricsError) std::fprintf(stderr, "Failure metrics: %s\n", metricsError);
                else std::fwrite(output.data(), 1, output.size(), stderr);
                std::exit(3);
            }
        };
        auto directory = utf8(argv[2]) + "/";
        require(directory.find(',') == std::string::npos, "Output directory cannot contain command delimiters");
        std::printf("READY %lu\n", GetCurrentProcessId());
        for (unsigned capture = 0; capture < 8; ++capture) {
            require(readCommand("capture"), "Expected capture command");
            auto item = capture % 4;
            auto faults = item < 2;
            auto event = faults ? "page-faults" : "context-switches";
            auto period = item == 1 ? 5 : item == 3 ? 3 : 1;
            auto base = directory + std::to_string(capture) + "-" + event + "-p" + std::to_string(period);
            // Supplying fdtransfer on every start exercises reconnect to the pinned target's default pipe.
            command("start,event=" + std::string(event) + ",interval=" + std::to_string(period)
                    + ",cstack=dwarf" + (local ? "" : ",fdtransfer") + ",jfr,file=" + base + ".jfr");
            NativeSoftwareWorkload(faults);
            command("stop");
            command("collapsed,total,file=" + base + ".jfr.collapsed");
            command("collapsed,samples,file=" + base + ".samples.collapsed");
            command("otlp,total,file=" + base + ".native.otlp");
            command("metrics");
            FILE* file = nullptr;
            require(_wfopen_s(&file, (std::wstring(argv[2]) + L"/" + std::to_wstring(capture) + L".metrics").c_str(), L"wb") == 0,
                    "Cannot create capture metrics");
            require(std::fwrite(output.data(), 1, output.size(), file) == output.size(), "Cannot write capture metrics");
            require(std::fclose(file) == 0, "Cannot close capture metrics");
            require(GetModuleHandleW(L"jvm.dll") == nullptr, "Capture loaded a JVM");
            std::printf("CAPTURE_DONE %u %s %d\n", capture, event, period);
        }
        require(readCommand("exit"), "Expected exit command");
        std::printf("NATIVE_SOFTWARE_CAPTURE_OK captures=8 %s jvm=0\n", local ? "local=1" : "reconnects=8 medium=1");
    }
    require(SetEvent(finished) != FALSE && WaitForSingleObject(guard, 10000) == WAIT_OBJECT_0, "Cannot finish watchdog");
    require(CloseHandle(guard) != FALSE && CloseHandle(finished) != FALSE, "Cannot close watchdog handles");
    return 0;
}
