/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// asprof.exe: upstream asprof's command line (src/main/main.cpp) for the Windows port.
namespace Asprof {

// Ends the command with a message on stderr (none when empty) and the given exit code.
struct Failure {
    std::string message;
    int code = 1;
};

std::wstring wide(std::string_view text, UINT codePage = CP_UTF8);
std::string utf8(std::wstring_view text);
// Strings that HotSpot consumes with narrow Windows APIs use the system ANSI code page.
std::string ansi(std::string_view text);
std::string windowsError(DWORD error);
[[noreturn]] void fail(std::string message, int code = 1);

struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    explicit Handle(HANDLE handle) : value(handle) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(other.value) { other.value = nullptr; }
    Handle& operator=(Handle&& other) noexcept { std::swap(value, other.value); return *this; }
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
};

void writeOut(std::string_view text);
void writeErr(std::string_view text);

struct JvmLookup {
    std::function<DWORD()> newest;
    std::function<DWORD(const std::string&)> named;
};

struct Options {
    std::string action = "collect";
    bool jattach = false;
    bool help = false;
    bool version = false;
    int duration = 60;
    bool durationGiven = false;
    bool timeout = false;
    std::optional<std::string> file;
    std::string output;
    std::string format;
    std::string params;
    DWORD pid = 0;
    std::optional<std::string> libpath;
    std::optional<std::string> fdtransfer;
    std::optional<std::string> java;
    // jattach action arguments, or launch's program and arguments after "--".
    std::vector<std::string> arguments;

    static Options parse(const std::vector<std::string>& args, const JvmLookup& lookup);
    // Rejects input that would split or terminate a native agent argument.
    static const std::string& value(const std::string& value);
};
std::string brokerPipeName();
// Whether the agent selects JFR output, as Arguments::parse and detectOutputFormat do.
bool jfrOutput(const Options& o, const std::string& file);
bool isUrl(const std::string& file);

// Local HotSpot JVMs, as listed by jps from hsperfdata.
namespace Jvms {
struct Jvm { DWORD pid; std::string command; };
std::vector<Jvm> list();
DWORD newest();
DWORD named(const std::string& name);
std::string jpsName(std::string command);
}

// The profiler DLL and the helper beside it.
struct Library {
    std::wstring dll;
    std::wstring helper() const;
    static Library resolve(const std::optional<std::string>& libpath);
    std::string inspect() const;
};

// A HotSpot JVM reached through its Windows attach listener.
class Attach {
public:
    struct Reply {
        int status;
        std::string body;
    };
    explicit Attach(DWORD pid);
    Attach(const Attach&) = delete;
    Attach& operator=(const Attach&) = delete;
    // Runs one attach operation; arguments are byte strings in the encoding the operation consumes.
    Reply execute(const std::string& command, const std::vector<std::string>& arguments);
    HANDLE process() const { return _process.value; }
private:
    DWORD _pid;
    Handle _process;
    std::uintptr_t _enqueue = 0;
    std::uintptr_t _enqueueV2 = 0;
    int _version = 0;
    bool _streamingOption = false;
    Reply transact(int version, const std::string& command, const std::vector<std::string>& arguments);
};
// jattach's interpretation of a load reply: the Agent_OnAttach result, or -1 with a message.
int loadResult(const Attach::Reply& reply, std::string& message);
int jattach(DWORD pid, const std::string& action, const std::vector<std::string>& arguments);

// The concrete files the target opened, journaled through the agent's fileresult option.
class OutputFiles {
public:
    OutputFiles();
    ~OutputFiles();
    OutputFiles(const OutputFiles&) = delete;
    OutputFiles& operator=(const OutputFiles&) = delete;
    static std::string base();
    std::string options(bool local = true) const;
    std::vector<std::wstring> files() const;
    std::wstring single() const;
    void verify(bool jfr) const;
private:
    std::wstring _journal;
};
void validateJfr(const std::wstring& path);
std::wstring temporaryDirectory();
std::wstring absolutePath(const std::wstring& path);
void createParents(const std::wstring& path);

void startBroker(DWORD pid, const std::string& pipe, const Library& library);
std::wstring commandLine(const std::vector<std::wstring>& arguments);

}
