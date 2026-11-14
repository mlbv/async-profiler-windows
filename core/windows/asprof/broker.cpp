/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "asprof.h"

// The ETW broker that serves --fdtransfer, in place of upstream's fdtransfer server.
namespace Asprof {
namespace {
bool elevated() {
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) fail("Cannot query this process's token: " + windowsError(GetLastError()));
    DWORD length = 0;
    GetTokenInformation(token.value, TokenIntegrityLevel, nullptr, 0, &length);
    std::vector<unsigned char> label(length);
    if (!GetTokenInformation(token.value, TokenIntegrityLevel, label.data(), length, &length)) {
        fail("Cannot query this process's integrity level: " + windowsError(GetLastError()));
    }
    auto sid = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(label.data())->Label.Sid;
    return *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1) >= SECURITY_MANDATORY_HIGH_RID;
}
}

// Starts the helper's single-session broker and returns once its pipe accepts the target. Like
// upstream's server, it outlives this command until the target's profiling session disconnects,
// or exits if no session connects in 30 seconds.
void startBroker(DWORD pid, const std::string& pipe, const Library& library) {
    if (!elevated()) fail("--fdtransfer requires an elevated asprof: the ETW broker needs administrator privileges");
    SECURITY_ATTRIBUTES inheritable{sizeof(inheritable), nullptr, TRUE};
    Handle output, input, discard(CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &inheritable, OPEN_EXISTING, 0, nullptr));
    if (!CreatePipe(&output.value, &input.value, &inheritable, 0) || !SetHandleInformation(output.value, HANDLE_FLAG_INHERIT, 0) || !discard) {
        fail("Cannot create the broker's output pipe: " + windowsError(GetLastError()));
    }
    // Only the helper's standard handles are inherited, so it does not hold this command's output open.
    HANDLE handles[] = {input.value, discard.value};
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    std::vector<unsigned char> attributes(size);
    auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    if (!InitializeProcThreadAttributeList(list, 1, 0, &size)
            || !UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, sizeof(handles), nullptr, nullptr)) {
        fail("Cannot prepare the broker process: " + windowsError(GetLastError()));
    }
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = discard.value;
    startup.StartupInfo.hStdOutput = input.value;
    startup.StartupInfo.hStdError = discard.value;
    startup.lpAttributeList = list;
    auto helper = library.helper();
    auto command = commandLine({helper, L"--etw-broker", std::to_wstring(pid), wide(pipe), L"--once"});
    PROCESS_INFORMATION process{};
    auto started = CreateProcessW(helper.c_str(), command.data(), nullptr, nullptr, TRUE, EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                                  &startup.StartupInfo, &process);
    auto error = GetLastError();
    DeleteProcThreadAttributeList(list);
    if (!started) fail("Cannot start " + utf8(helper) + ": " + windowsError(error));
    Handle child(process.hProcess), thread(process.hThread);
    input = Handle();
    std::string text;
    char buffer[512];
    DWORD read = 0;
    while (ReadFile(output.value, buffer, sizeof(buffer), &read, nullptr) && read) {
        text.append(buffer, read);
        for (size_t end; (end = text.find('\n')) != std::string::npos; text.erase(0, end + 1)) {
            if (text.compare(0, 17, "ETW_BROKER_READY ") == 0) return;
        }
    }
    WaitForSingleObject(child.value, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(child.value, &code);
    fail("asprof-helper.exe could not start the ETW broker: " + windowsError(code));
}
}
