/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "asprof.h"
#include <algorithm>
#include <cstring>

namespace Asprof::Jvms {
namespace {
// HotSpot's PerfDataPrologue and PerfDataEntry (runtime/perfMemory.hpp), version 2.0.
constexpr std::uint32_t MAGIC = 0xcafec0c0;
constexpr size_t PROLOGUE = 32, ENTRY = 20;

template<class T> T read(const std::string& data, size_t offset, bool little) {
    T value = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        auto byte = static_cast<T>(static_cast<unsigned char>(data[offset + (little ? i : sizeof(T) - 1 - i)]));
        value |= byte << (8 * i);
    }
    return value;
}

// The NUL-terminated byte-vector counters, or nothing while the JVM is still initializing.
std::optional<std::string> counter(const std::string& data, const char* wanted) {
    if (data.size() < PROLOGUE || read<std::uint32_t>(data, 0, false) != MAGIC) return {};
    bool little = data[4] == 1;
    if (data[5] != 2 || !data[7]) return {};
    auto offset = static_cast<size_t>(read<std::uint32_t>(data, 24, little));
    auto count = read<std::uint32_t>(data, 28, little);
    for (std::uint32_t i = 0; i < count && offset + ENTRY <= data.size(); ++i) {
        auto length = read<std::uint32_t>(data, offset, little);
        if (length == 0 || offset + length > data.size()) return {};
        auto name = offset + read<std::uint32_t>(data, offset + 4, little);
        auto vector = read<std::uint32_t>(data, offset + 8, little);
        auto value = offset + read<std::uint32_t>(data, offset + 16, little);
        if (name < data.size() && std::strncmp(data.data() + name, wanted, data.size() - name) == 0 && data[offset + 12] == 'B'
                && value + vector <= data.size()) {
            auto text = data.substr(value, vector);
            return text.substr(0, text.find('\0'));
        }
        offset += length;
    }
    return {};
}

std::optional<std::string> contents(const std::wstring& path) {
    // HotSpot holds the file with FILE_SHARE_READ | FILE_SHARE_DELETE and deletes it on close.
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    LARGE_INTEGER size;
    if (!file || !GetFileSizeEx(file.value, &size) || size.QuadPart > (16 << 20)) return {};
    std::string data(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(file.value, data.data(), static_cast<DWORD>(data.size()), &read, nullptr) || read != data.size()) return {};
    return data;
}

std::uint64_t started(DWORD pid) {
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    FILETIME created, exited, kernel, user;
    if (!process || !GetProcessTimes(process.value, &created, &exited, &kernel, &user)) return 0;
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}
}

// Attachable JVMs in this user's hsperfdata directories, as VirtualMachine.list() reports them.
std::vector<Jvm> list() {
    std::vector<Jvm> result;
    auto temporary = temporaryDirectory();
    WIN32_FIND_DATAW directory;
    HANDLE directories = FindFirstFileW((temporary + L"hsperfdata_*").c_str(), &directory);
    if (directories == INVALID_HANDLE_VALUE) return result;
    do {
        if (!(directory.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        auto root = temporary + directory.cFileName + L"\\";
        WIN32_FIND_DATAW entry;
        HANDLE files = FindFirstFileW((root + L"*").c_str(), &entry);
        if (files == INVALID_HANDLE_VALUE) continue;
        do {
            std::wstring name = entry.cFileName;
            if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || name.empty() || name.size() > 10
                    || !std::all_of(name.begin(), name.end(), [](wchar_t c) { return c >= L'0' && c <= L'9'; })) continue;
            auto pid = std::stoull(name);
            auto data = contents(root + name);
            if (pid > 0xffffffffULL || !data) continue;
            auto capabilities = counter(*data, "sun.rt.jvmCapabilities");
            auto command = counter(*data, "sun.rt.javaCommand");
            if (!capabilities || capabilities->empty() || (*capabilities)[0] != '1' || !command) continue;
            result.push_back({static_cast<DWORD>(pid), utf8(wide(*command, CP_ACP))});
        } while (FindNextFileW(files, &entry));
        FindClose(files);
    } while (FindNextFileW(directories, &directory));
    FindClose(directories);
    std::sort(result.begin(), result.end(), [](const Jvm& a, const Jvm& b) { return a.pid < b.pid; });
    return result;
}

// The most recently started JVM, matching upstream's `pgrep -n java`.
DWORD newest() {
    DWORD pid = 0;
    std::uint64_t latest = 0;
    for (const auto& jvm : list()) {
        auto time = started(jvm.pid);
        if (time > latest) { latest = time; pid = jvm.pid; }
    }
    if (!pid) fail("No Java process");
    return pid;
}

DWORD named(const std::string& name) {
    std::vector<DWORD> matches;
    for (const auto& jvm : list()) if (jpsName(jvm.command) == name) matches.push_back(jvm.pid);
    if (matches.size() > 1) fail("Multiple Java processes found");
    if (matches.empty()) fail("No Java process");
    return matches.front();
}

// jps's short main-class or JAR name (sun.tools.jps MonitoredVmUtil.mainClass without -l).
std::string jpsName(std::string command) {
    auto space = command.find(' ');
    if (space != std::string::npos && space > 0) command = command.substr(0, space);
    auto separator = command.find_last_of("/\\");
    if (separator != std::string::npos && separator > 0) command = command.substr(separator + 1);
    auto dot = command.rfind('.');
    if (dot != std::string::npos && dot > 0) {
        auto last = command.substr(dot + 1);
        return last == "jar" ? command : last;
    }
    return command;
}
}
