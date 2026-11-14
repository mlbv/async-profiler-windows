/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include <windows.h>
#include "asprof.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace {
std::string output;
void receive(const char* data,size_t size) { output.append(data,size); }
void require(bool value,const char* message) {
    if (!value) { std::fprintf(stderr,"%s Windows=%lu\n",message,GetLastError()); std::exit(1); }
}
using Execute = decltype(&asprof_execute);
Execute execute;
void command(const std::string& value) {
    output.clear();
    auto error = execute(value.c_str(),receive);
    if (error) { std::fprintf(stderr,"Command %s: %s\n",value.c_str(),error); std::exit(1); }
}
unsigned long long metric(const char* name) {
    auto start = output.find(std::string(name) + " ");
    require(start != std::string::npos,"Missing software entry metric");
    return std::strtoull(output.c_str() + start + std::strlen(name) + 1,nullptr,10);
}
}
int main(int argc,char** argv) {
    require(argc == 5,"Pass profiler DLL, owned fixture DLL, output path, and default|period|offset|reject-push|reject-return mode");
    auto profiler = LoadLibraryA(argv[1]);
    require(profiler != nullptr,"Cannot load profiler");
    auto initialize = reinterpret_cast<decltype(&asprof_init)>(GetProcAddress(profiler,"asprof_init"));
    execute = reinterpret_cast<Execute>(GetProcAddress(profiler,"asprof_execute"));
    require(initialize && execute,"Profiler C API missing");
    initialize();
    auto fixture = LoadLibraryA(argv[2]);
    require(fixture != nullptr,"Cannot load owned fixture");
    using Work = unsigned long long (*)(unsigned long long,unsigned long long);
    auto work = reinterpret_cast<Work>(GetProcAddress(fixture,"SoftwareEntryWork"));
    auto pushed = GetProcAddress(fixture,"SoftwareEntryPush");
    require(work && pushed,"Owned fixture exports missing");
    const bool rejectPush = std::strcmp(argv[4],"reject-push") == 0;
    const bool rejectReturn = std::strcmp(argv[4],"reject-return") == 0;
    const bool periodMode = std::strcmp(argv[4],"period") == 0;
    const bool offsetMode = std::strcmp(argv[4],"offset") == 0;
    const auto period = periodMode ? 7u : 1u;
    auto source = rejectPush ? reinterpret_cast<const unsigned char*>(pushed) : reinterpret_cast<const unsigned char*>(work);
    auto original = source[0];
    std::string selector = std::string(rejectReturn ? "uretprobe:" : "uprobe:") + argv[2];
    if (offsetMode) {
        auto base = reinterpret_cast<const unsigned char*>(fixture);
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
        auto sections = IMAGE_FIRST_SECTION(nt);
        auto rva = source - base;
        std::uint64_t offset = 0;
        for (unsigned index = 0; index < nt->FileHeader.NumberOfSections; ++index) {
            const auto& section = sections[index];
            if (rva >= section.VirtualAddress && static_cast<size_t>(rva - section.VirtualAddress) < section.SizeOfRawData)
                offset = section.PointerToRawData + (rva - section.VirtualAddress);
        }
        require(offset != 0,"Owned fixture function has no executable file offset");
        selector += "+" + std::to_string(offset);
    } else selector += rejectPush ? "!SoftwareEntryPush" : "!SoftwareEntryWork";
    auto start = "start,event=" + selector + ",cstack=fp,collapsed,file=" + argv[3] + ",threads";
    if (periodMode) start += ",interval=7";
    if (rejectPush || rejectReturn) {
        auto error = execute(start.c_str(),receive);
        require(error != nullptr && source[0] == original,"Ineligible entry/return selector changed source");
        std::puts("SOFTWARE_PROBE_REJECT_OK sourceUnchanged=1");
        return 0;
    }
    command(start);
    require(source[0] == 0xcc,"Software entry did not arm INT3");
    constexpr unsigned threads = 4, calls = 703;
    std::atomic<bool> failed{false};
    auto run = [&](unsigned number) {
        for (unsigned index = 0; index < calls; ++index) {
            SetLastError(0x1234abcd);
            auto value = work(number,index);
            if (value != number + index || GetLastError() != 0x1234abcd) failed = true;
        }
    };
    run(5);
    std::vector<std::thread> workers;
    for (unsigned number = 0; number < threads; ++number) workers.emplace_back(run,number);
    for (auto& thread : workers) thread.join();
    require(!failed,"Displaced entry changed result or Win32 error state");
    command("stop");
    require(source[0] == original && work(11,22) == 33,"Stop did not restore owned source/behavior");
    command("metrics");
    auto expected = static_cast<unsigned long long>(threads + 1) * calls;
    require(metric("windows_software_probe_hits") == expected,"Software entry lost per-thread physical hits");
    require(metric("windows_software_probe_samples") == static_cast<unsigned long long>(threads + 1) * (calls / period),
        "Software entry per-TID period sample count mismatch");
    require(metric("windows_software_probe_failed") == 0 && metric("windows_software_probe_unprepared") == 0,
        "Software entry thread enrollment/capture failed");
    auto previousSamples = metric("windows_software_probe_samples");
    for (unsigned index = 0; index < 16; ++index) work(index,index);
    command("metrics");
    require(metric("windows_software_probe_samples") == previousSamples,"Stopped entry recorded more samples");
    auto error = execute(start.c_str(),receive);
    require(error && std::strstr(error,"same-mapping rearm") && source[0] == original,"Same mapping rearm was not rejected");
    std::printf("SOFTWARE_PROBE_CAPI_OK hits=%llu samples=%llu period=%u sourceRestored=1 rearmRejected=1\n",
        expected,previousSamples,period);
    FreeLibrary(fixture);
}
