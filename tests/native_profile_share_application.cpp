/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// Native target for concurrent ETW timer/PMC captures, driven one command per stdin line.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include "../core/src/asprof.h"

static void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s (Windows error %lu)\n", message, GetLastError()); std::exit(2); }
}
static std::string output;
static void collect(const char* data, size_t size) { output.append(data, size); }
static std::string utf8(const wchar_t* value) {
    auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, nullptr, 0, nullptr, nullptr);
    require(size > 0, "Invalid UTF-16 argument");
    std::string result(size, '\0');
    require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, result.data(), size, nullptr, nullptr) == size, "Cannot encode argument");
    result.pop_back();
    return result;
}
static void spin(unsigned milliseconds) {
    LARGE_INTEGER start, now, frequency;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);
    volatile std::uint64_t value = 1;
    do {
        for (int i = 0; i < 10000; ++i) value = (value ^ (value >> 13)) * 0x100000001b3ULL;
        QueryPerformanceCounter(&now);
    } while (now.QuadPart - start.QuadPart < frequency.QuadPart * milliseconds / 1000);
}
// Distinct phases attribute samples to the periods around another owner joining or leaving.
extern "C" __declspec(dllexport) __declspec(noinline) void ShareWorkBefore(unsigned milliseconds) { spin(milliseconds); }
extern "C" __declspec(dllexport) __declspec(noinline) void ShareWorkDuring(unsigned milliseconds) { spin(milliseconds); }
extern "C" __declspec(dllexport) __declspec(noinline) void ShareWorkAfter(unsigned milliseconds) { spin(milliseconds); }
// A fixed iteration count gives counter sources a ground truth: its retired instructions
// and branches per iteration are read from the binary.
extern "C" __declspec(dllexport) __declspec(noinline) std::uint64_t ShareCountWork(std::uint64_t iterations) {
    volatile std::uint64_t value = 1;
    for (std::uint64_t i = 0; i < iterations; ++i) value = (value ^ (value >> 13)) * 0x100000001b3ULL;
    return value;
}

int wmain(int argc, wchar_t** argv) {
    require(argc == 4 && (std::wcscmp(argv[3], L"local") == 0 || std::wcscmp(argv[3], L"broker") == 0),
            "Usage: nativeProfileShareApplication DLL OUTPUT_DIRECTORY local|broker");
    setvbuf(stdout, nullptr, _IONBF, 0);
    auto broker = std::wcscmp(argv[3], L"broker") == 0;
    auto library = LoadLibraryW(argv[1]);
    require(library != nullptr, "Cannot load candidate profiler");
    auto init = reinterpret_cast<asprof_init_t>(GetProcAddress(library, "asprof_init"));
    auto execute = reinterpret_cast<asprof_execute_t>(GetProcAddress(library, "asprof_execute"));
    require(init && execute, "Missing native C API exports");
    init();
    auto command = [&](const std::string& text) {
        output.clear();
        auto error = execute(text.c_str(), collect);
        if (error) { std::fprintf(stderr, "%s: %s\n", text.c_str(), error); std::exit(3); }
    };
    auto save = [&](const std::string& path) {
        FILE* file = nullptr;
        require(fopen_s(&file, path.c_str(), "wb") == 0, "Cannot create output");
        require(std::fwrite(output.data(), 1, output.size(), file) == output.size() && std::fclose(file) == 0, "Cannot write output");
    };
    auto directory = utf8(argv[2]) + "/";
    require(directory.find(',') == std::string::npos, "Output directory cannot contain command delimiters");
    std::printf("READY %lu\n", GetCurrentProcessId());
    char line[512];
    while (std::fgets(line, sizeof(line), stdin)) {
        line[std::strcspn(line, "\r\n")] = '\0';
        char name[64], event[128], interval[32], phase[16];
        unsigned milliseconds;
        unsigned long long iterations;
        if (sscanf_s(line, "start %63s %127s %31s", name, unsigned(sizeof(name)), event, unsigned(sizeof(event)), interval, unsigned(sizeof(interval))) == 3) {
            auto text = "start,event=" + std::string(event) + (std::strcmp(interval, "-") ? ",interval=" + std::string(interval) : "")
                + (broker ? ",fdtransfer" : "") + ",jfr,file=" + directory + name + ".jfr";
            output.clear();
            auto error = execute(text.c_str(), collect);
            if (error) std::printf("FAILED %s %s\n", name, error);
            else std::printf("STARTED %s\n", name);
        } else if (sscanf_s(line, "work %15s %u", phase, unsigned(sizeof(phase)), &milliseconds) == 2) {
            if (std::strcmp(phase, "before") == 0) ShareWorkBefore(milliseconds);
            else if (std::strcmp(phase, "during") == 0) ShareWorkDuring(milliseconds);
            else ShareWorkAfter(milliseconds);
            std::printf("WORKED %s\n", phase);
        } else if (sscanf_s(line, "count %llu", &iterations) == 1) {
            ULONG64 before, after;
            require(QueryThreadCycleTime(GetCurrentThread(), &before) != FALSE, "Cannot read thread cycles");
            ShareCountWork(iterations);
            require(QueryThreadCycleTime(GetCurrentThread(), &after) != FALSE, "Cannot read thread cycles");
            std::printf("COUNTED %llu cycles=%llu\n", iterations, static_cast<unsigned long long>(after - before));
        } else if (sscanf_s(line, "stop %63s", name, unsigned(sizeof(name))) == 1) {
            auto base = directory + name;
            command("stop");
            command("collapsed,total,file=" + base + ".collapsed");
            command("collapsed,samples,file=" + base + ".samples.collapsed");
            command("otlp,total,file=" + base + ".native.otlp");
            command("metrics");
            save(base + ".metrics");
            std::printf("STOPPED %s\n", name);
        } else if (std::strcmp(line, "exit") == 0) {
            std::puts("EXITED");
            return 0;
        } else {
            std::fprintf(stderr, "Unknown command: %s\n", line);
            return 4;
        }
    }
    return 5;
}
