/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsPreload.h"
#include <cwchar>
#include <string>
#include <string_view>
#include <vector>

namespace WindowsProfiler::Preload {
namespace {
struct Handle {
    HANDLE value;
    ~Handle() { if (value) CloseHandle(value); }
};

void print(std::wstring message) {
    message += L'\n';
    auto output = GetStdHandle(STD_ERROR_HANDLE);
    DWORD mode, written;
    if (GetConsoleMode(output, &mode)) {
        WriteConsoleW(output, message.data(), static_cast<DWORD>(message.size()), &written, nullptr);
        return;
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), nullptr, 0, nullptr, nullptr);
    std::string bytes(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, message.data(), static_cast<int>(message.size()), bytes.data(), size, nullptr, nullptr);
    WriteFile(output, bytes.data(), static_cast<DWORD>(size), &written, nullptr);
}

DWORD report(DWORD error, const std::wstring& message) {
    print(L"asprof-helper: " + message + L": Windows error " + std::to_wstring(error));
    return error;
}

// Quotes for CommandLineToArgvW and the C runtime's argument parser.
void appendArgument(std::wstring& line, std::wstring_view argument) {
    if (!line.empty()) line += L' ';
    if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring_view::npos) {
        line += argument;
        return;
    }
    line += L'"';
    size_t backslashes = 0;
    for (auto c : argument) {
        if (c == L'\\') {
            ++backslashes;
            continue;
        }
        line.append(c == L'"' ? 2 * backslashes + 1 : backslashes, L'\\');
        line += c;
        backslashes = 0;
    }
    line.append(2 * backslashes, L'\\');
    line += L'"';
}

std::wstring fullPath(const WCHAR* path) {
    std::wstring result(GetFullPathNameW(path, 0, nullptr, nullptr), L'\0');
    if (!result.empty()) result.resize(GetFullPathNameW(path, static_cast<DWORD>(result.size()), result.data(), nullptr));
    return result;
}

}

int launch(int argc, WCHAR** argv) {
    std::vector<std::wstring> libraries;
    int index = 1;
    for (; index + 1 < argc && std::wcscmp(argv[index], L"--preload") == 0; index += 2) {
        auto path = fullPath(argv[index + 1]);
        if (path.empty()) return static_cast<int>(report(GetLastError(), L"Cannot resolve " + std::wstring(argv[index + 1])));
        libraries.push_back(std::move(path));
    }
    if (libraries.empty() || index + 1 >= argc || std::wcscmp(argv[index], L"--") != 0) {
        print(L"Usage: asprof-helper --preload DLL [--preload DLL ...] -- EXE [ARGS...]");
        return ERROR_INVALID_PARAMETER;
    }
    // As in a shell, a name with a directory is resolved against the current directory with an implied .exe;
    // CreateProcessW searches for a bare name, including PATH, and implies .exe itself.
    std::wstring application = argv[index + 1], commandLine;
    bool located = application.find_first_of(L"\\/:") != std::wstring::npos;
    if (located) {
        application = fullPath(argv[index + 1]);
        if (application.empty()) return static_cast<int>(report(GetLastError(), L"Cannot resolve " + std::wstring(argv[index + 1])));
        if (application.find(L'.', application.find_last_of(L'\\') + 1) == std::wstring::npos) application += L".exe";
    }
    for (int i = index + 1; i < argc; ++i) appendArgument(commandLine, argv[i]);

    // Console interrupts reach the child directly; the launcher stays to return its exit code.
    if (!SetConsoleCtrlHandler([](DWORD type) -> BOOL { return type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT; }, TRUE))
        return static_cast<int>(report(GetLastError(), L"Cannot install the console control handler"));
    // The application and the processes it leaves in this job end with the helper. ETW companions break away.
    Handle job{CreateJobObjectW(nullptr, nullptr)};
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    if (!job.value || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        return static_cast<int>(report(GetLastError(), L"Cannot create the application job"));

    STARTUPINFOW startup{sizeof(startup)};
    PROCESS_INFORMATION created;
    if (!CreateProcessW(located ? application.c_str() : nullptr, commandLine.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr,
            nullptr, &startup, &created))
        return static_cast<int>(report(GetLastError(), L"Cannot start " + application));
    Handle process{created.hProcess}, thread{created.hThread};
    auto fail = [&](DWORD error, const std::wstring& message) {
        TerminateProcess(process.value, error);
        return static_cast<int>(report(error, message));
    };
    if (!AssignProcessToJobObject(job.value, process.value)) return fail(GetLastError(), L"Cannot assign the application job");

    Injector injector(process.value, thread.value);
    std::wstring message;
    if (auto error = injector.load(libraries, message)) {
        DWORD code;
        if (WaitForSingleObject(process.value, 0) != WAIT_OBJECT_0) return fail(error, application + L": " + message);
        if (!GetExitCodeProcess(process.value, &code)) return static_cast<int>(report(GetLastError(), L"Cannot read the exit code"));
        WCHAR text[16];
        std::swprintf(text, 16, L"0x%08lX", code);
        print(L"asprof-helper: " + application + L": " + message + L" (exit code " + text + L")");
        return static_cast<int>(code);
    }
    injector.release(true, false);

    DWORD code;
    if (WaitForSingleObject(process.value, INFINITE) != WAIT_OBJECT_0 || !GetExitCodeProcess(process.value, &code))
        return static_cast<int>(report(GetLastError(), L"Cannot wait for " + application));
    return static_cast<int>(code);
}
}
