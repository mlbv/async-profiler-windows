/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "asprof.h"
#include "windowsPrivilege.h"
#include <psapi.h>
#include <sddl.h>
#include <cstring>

// HotSpot's Windows attach mechanism (os/windows/attachListener_windows.cpp): a thread created in
// the target calls jvm.dll's JVM_EnqueueOperation, and the attach listener answers over a named
// pipe that this client creates. Protocol v2 (JDK 24+) sends the request over the same pipe.
namespace Asprof {
namespace {
constexpr size_t V1_COMMAND = 16, V1_ARGUMENT = 1024;
// jattach's budget for the attach listener to accept a request; the operation itself is unbounded.
constexpr DWORD ACCEPT_TIMEOUT_MS = 6000;

// The remote thread's start routine (x64): calls data[1](data[2], data[3], data[4], data[5], data[6])
// and returns its result. JVM_EnqueueOperation_v2 takes only the first argument.
constexpr unsigned char STUB[] = {
    0x48, 0x83, 0xEC, 0x38,        // sub  rsp, 0x38
    0x48, 0x89, 0xC8,              // mov  rax, rcx
    0x4C, 0x8B, 0x50, 0x30,        // mov  r10, [rax+0x30]
    0x4C, 0x89, 0x54, 0x24, 0x20,  // mov  [rsp+0x20], r10
    0x4C, 0x8B, 0x48, 0x28,        // mov  r9, [rax+0x28]
    0x4C, 0x8B, 0x40, 0x20,        // mov  r8, [rax+0x20]
    0x48, 0x8B, 0x50, 0x18,        // mov  rdx, [rax+0x18]
    0x48, 0x8B, 0x48, 0x10,        // mov  rcx, [rax+0x10]
    0xFF, 0x50, 0x08,              // call qword ptr [rax+0x08]
    0x48, 0x83, 0xC4, 0x38,        // add  rsp, 0x38
    0xC3,                          // ret
};

const char* listenerError(DWORD code) {
    switch (code) {
        case 100: return "the target's attach listener is not initialized or is disabled (-XX:+DisableAttachMechanism)";
        case 101: return "the target's attach listener is busy";
        case 102: return "the target rejected the attach request arguments";
        case 103: return "the target's attach listener failed internally";
        default: return nullptr;
    }
}

struct Remote {
    HANDLE process;
    void* address = nullptr;
    Remote(HANDLE process, size_t size, DWORD protection) : process(process) {
        address = VirtualAllocEx(process, nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
        if (!address) fail("Cannot allocate memory in the target: " + windowsError(GetLastError()));
    }
    Remote(const Remote&) = delete;
    Remote& operator=(const Remote&) = delete;
    ~Remote() { if (address) VirtualFreeEx(process, address, 0, MEM_RELEASE); }
    // Leaves the memory to a remote thread that may still use it.
    void abandon() { address = nullptr; }
    std::uintptr_t at(size_t offset) const { return reinterpret_cast<std::uintptr_t>(address) + offset; }
};

void readRemote(HANDLE process, std::uintptr_t address, void* buffer, size_t size) {
    SIZE_T read = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<void*>(address), buffer, size, &read) || read != size) {
        fail("Cannot read jvm.dll in the target: " + windowsError(GetLastError()));
    }
}

// Finds the target's jvm.dll and resolves its enqueue exports from the loaded image.
void exports(HANDLE process, DWORD pid, std::uintptr_t& enqueue, std::uintptr_t& enqueueV2) {
    std::vector<HMODULE> modules(1024);
    DWORD needed = 0;
    if (!EnumProcessModules(process, modules.data(), static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &needed)) {
        fail("Cannot list the modules of process " + std::to_string(pid) + ": " + windowsError(GetLastError()));
    }
    modules.resize(std::min<size_t>(needed / sizeof(HMODULE), modules.size()));
    std::uintptr_t base = 0;
    for (auto module : modules) {
        WCHAR name[MAX_PATH];
        if (GetModuleBaseNameW(process, module, name, MAX_PATH) && _wcsicmp(name, L"jvm.dll") == 0) base = reinterpret_cast<std::uintptr_t>(module);
    }
    if (!base) fail("Process " + std::to_string(pid) + " is not a HotSpot JVM: jvm.dll is not loaded");
    IMAGE_DOS_HEADER dos;
    readRemote(process, base, &dos, sizeof(dos));
    IMAGE_NT_HEADERS64 nt;
    readRemote(process, base + dos.e_lfanew, &nt, sizeof(nt));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        fail("The target's jvm.dll is not an x64 image");
    }
    auto directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY table;
    readRemote(process, base + directory.VirtualAddress, &table, sizeof(table));
    std::vector<DWORD> names(table.NumberOfNames), functions(table.NumberOfFunctions);
    std::vector<WORD> ordinals(table.NumberOfNames);
    readRemote(process, base + table.AddressOfNames, names.data(), names.size() * sizeof(DWORD));
    readRemote(process, base + table.AddressOfNameOrdinals, ordinals.data(), ordinals.size() * sizeof(WORD));
    readRemote(process, base + table.AddressOfFunctions, functions.data(), functions.size() * sizeof(DWORD));
    for (size_t i = 0; i < names.size(); ++i) {
        char name[32]{};
        readRemote(process, base + names[i], name, sizeof(name) - 1);
        auto target = std::strcmp(name, "JVM_EnqueueOperation") == 0 ? &enqueue
                : std::strcmp(name, "JVM_EnqueueOperation_v2") == 0 ? &enqueueV2 : nullptr;
        if (!target || ordinals[i] >= functions.size()) continue;
        auto rva = functions[ordinals[i]];
        // A forwarder RVA points into the export directory instead of code.
        if (rva >= directory.VirtualAddress && rva < directory.VirtualAddress + directory.Size) continue;
        *target = base + rva;
    }
    if (!enqueue) fail("Process " + std::to_string(pid) + " does not support the HotSpot attach mechanism");
}

DWORD wait(HANDLE event, HANDLE process, DWORD timeout = INFINITE) {
    HANDLE handles[] = {event, process};
    auto result = WaitForMultipleObjects(2, handles, FALSE, timeout);
    if (result == WAIT_OBJECT_0 + 1) fail("The target process exited during the attach operation");
    return result;
}

struct Pipe {
    Handle handle;
    Handle event{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::wstring name;

    // Only the target's user may open the pipe; the connecting process is checked against the target.
    Pipe(HANDLE process, DWORD pid) {
        Handle token;
        if (!OpenProcessToken(process, TOKEN_QUERY, &token.value)) fail("Cannot query the target's user: " + windowsError(GetLastError()));
        DWORD length = 0;
        GetTokenInformation(token.value, TokenUser, nullptr, 0, &length);
        std::vector<unsigned char> user(length);
        LPWSTR sid = nullptr;
        if (!GetTokenInformation(token.value, TokenUser, user.data(), length, &length)
                || !ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid)) {
            fail("Cannot query the target's user: " + windowsError(GetLastError()));
        }
        auto sddl = L"D:P(A;;GRGW;;;" + std::wstring(sid) + L")(A;;GA;;;SY)";
        LocalFree(sid);
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
            fail("Cannot create the attach pipe's security descriptor: " + windowsError(GetLastError()));
        }
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        LARGE_INTEGER counter;
        QueryPerformanceCounter(&counter);
        name = L"\\\\.\\pipe\\asprof-attach-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(pid) + L"-"
                + std::to_wstring(counter.QuadPart);
        handle = Handle(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 8192, 8192, 0, &security));
        auto error = GetLastError();
        LocalFree(descriptor);
        if (!handle) fail("Cannot create the attach pipe: " + windowsError(error));
    }

    void connect(HANDLE process, DWORD pid) {
        OVERLAPPED operation{};
        operation.hEvent = event.value;
        if (!ConnectNamedPipe(handle.value, &operation)) {
            auto error = GetLastError();
            if (error == ERROR_IO_PENDING) {
                wait(event.value, process);
                DWORD ignored;
                if (!GetOverlappedResult(handle.value, &operation, &ignored, FALSE)) error = GetLastError();
                else error = ERROR_SUCCESS;
            } else if (error == ERROR_PIPE_CONNECTED) {
                error = ERROR_SUCCESS;
            }
            if (error) fail("The target did not connect to the attach pipe: " + windowsError(error));
        }
        ULONG client = 0;
        if (!GetNamedPipeClientProcessId(handle.value, &client) || client != pid) fail("The attach pipe was opened by another process");
    }

    void write(HANDLE process, const std::string& data) {
        OVERLAPPED operation{};
        operation.hEvent = event.value;
        DWORD written = 0;
        if (!WriteFile(handle.value, data.data(), static_cast<DWORD>(data.size()), nullptr, &operation)) {
            if (GetLastError() != ERROR_IO_PENDING) fail("Cannot send the attach request: " + windowsError(GetLastError()));
            wait(event.value, process);
        }
        if (!GetOverlappedResult(handle.value, &operation, &written, FALSE) || written != data.size()) {
            fail("Cannot send the attach request: " + windowsError(GetLastError()));
        }
    }

    std::string readAll(HANDLE process) {
        std::string result;
        char buffer[8192];
        for (;;) {
            OVERLAPPED operation{};
            operation.hEvent = event.value;
            DWORD read = 0;
            if (!ReadFile(handle.value, buffer, sizeof(buffer), nullptr, &operation)) {
                auto error = GetLastError();
                if (error == ERROR_BROKEN_PIPE) return result;
                if (error != ERROR_IO_PENDING) fail("Cannot read the attach reply: " + windowsError(error));
                wait(event.value, process);
            }
            if (!GetOverlappedResult(handle.value, &operation, &read, FALSE)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) return result;
                fail("Cannot read the attach reply: " + windowsError(GetLastError()));
            }
            if (read == 0) return result;
            result.append(buffer, read);
        }
    }
};
}

Attach::Attach(DWORD pid) : _pid(pid) {
    constexpr DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
            | PROCESS_VM_READ | SYNCHRONIZE;
    _process = Handle(OpenProcess(access, FALSE, pid));
    if (!_process && GetLastError() == ERROR_ACCESS_DENIED) {
        // As the JDK's attach client does, an administrator may attach to another user's JVM.
        WindowsProfiler::Privilege debug(L"SeDebugPrivilege");
        if (debug.enable() == ERROR_SUCCESS) _process = Handle(OpenProcess(access, FALSE, pid));
    }
    if (!_process) {
        auto error = GetLastError();
        if (error == ERROR_INVALID_PARAMETER) fail("Process " + std::to_string(pid) + " not found");
        fail("Cannot open process " + std::to_string(pid) + ": " + windowsError(error));
    }
    USHORT machine = 0, native = 0;
    if (!IsWow64Process2(_process.value, &machine, &native) || machine != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_AMD64) {
        fail("Process " + std::to_string(pid) + " is not an x64 process");
    }
    exports(_process.value, pid, _enqueue, _enqueueV2);
}

Attach::Reply Attach::execute(const std::string& command, const std::vector<std::string>& arguments) {
    if (!_version) {
        // As the JDK 25+ client negotiates: VMs without getversion answer -1 and speak v1 only.
        _version = 1;
        if (_enqueueV2) {
            auto reply = transact(1, "getversion", {"options"});
            if (reply.status == 0 && reply.body.compare(0, 1, "2") == 0 && (reply.body.size() == 1 || reply.body[1] == ' ')) {
                _version = 2;
                _streamingOption = reply.body.find("streaming") != std::string::npos;
            }
        }
    }
    return transact(_version, command, arguments);
}

Attach::Reply Attach::transact(int version, const std::string& command, const std::vector<std::string>& arguments) {
    std::string request;
    if (version == 1) {
        if (arguments.size() > 3) fail("Too many attach arguments");
        if (command.size() > V1_COMMAND) fail("The attach command is too long: " + command);
        for (const auto& argument : arguments) {
            if (argument.size() > V1_ARGUMENT) fail("An attach argument exceeds the 1024 bytes of this JVM's attach protocol");
        }
    } else {
        // "2" NUL size NUL command[ options] NUL (argument NUL)*; size counts every byte after its own NUL.
        auto body = command + (_streamingOption ? " streaming=0" : "") + '\0';
        for (const auto& argument : arguments) body += argument + '\0';
        request = "2" + std::string(1, '\0') + std::to_string(body.size()) + '\0' + body;
    }
    Pipe pipe(_process.value, _pid);
    auto pipeName = utf8(pipe.name);
    std::string slots[5] = {command, "", "", "", pipeName};
    for (size_t i = 0; version == 1 && i < arguments.size(); ++i) slots[i + 1] = arguments[i];
    if (version == 2) slots[0] = pipeName;
    // data: [0] unused, [8] function, [16..56) argument pointers, then the NUL-terminated strings.
    std::string data(56, '\0');
    std::uintptr_t pointers[7] = {0, version == 1 ? _enqueue : _enqueueV2};
    std::vector<size_t> offsets;
    for (const auto& slot : slots) {
        offsets.push_back(data.size());
        data += slot + '\0';
    }
    Remote code(_process.value, sizeof(STUB), PAGE_READWRITE);
    Remote block(_process.value, data.size(), PAGE_READWRITE);
    for (size_t i = 0; i < 5; ++i) pointers[i + 2] = block.at(offsets[i]);
    std::memcpy(data.data(), pointers, sizeof(pointers));
    DWORD previous;
    if (!WriteProcessMemory(_process.value, code.address, STUB, sizeof(STUB), nullptr)
            || !WriteProcessMemory(_process.value, block.address, data.data(), data.size(), nullptr)
            || !VirtualProtectEx(_process.value, code.address, sizeof(STUB), PAGE_EXECUTE_READ, &previous)
            || !FlushInstructionCache(_process.value, code.address, sizeof(STUB))) {
        fail("Cannot prepare the attach request in the target: " + windowsError(GetLastError()));
    }
    Handle thread(CreateRemoteThread(_process.value, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(code.address), block.address, 0, nullptr));
    if (!thread) {
        auto error = GetLastError();
        if (error == ERROR_NOT_ENOUGH_MEMORY) fail("Insufficient memory or insufficient privileges to attach");
        fail("Cannot start the attach thread in the target: " + windowsError(error));
    }
    if (wait(thread.value, _process.value, ACCEPT_TIMEOUT_MS) == WAIT_TIMEOUT) {
        // A suspended or hung target may still run the thread: its code and data stay allocated, and its call
        // target becomes the stub's final ret, so the request is not enqueued unless the call has already begun.
        auto ret = code.at(sizeof(STUB) - 1);
        WriteProcessMemory(_process.value, reinterpret_cast<void*>(block.at(sizeof(std::uintptr_t))), &ret, sizeof(ret), nullptr);
        code.abandon();
        block.abandon();
        fail("Cannot attach: the target did not run the attach request within " + std::to_string(ACCEPT_TIMEOUT_MS / 1000)
             + " seconds; it may be suspended or hung");
    }
    DWORD result;
    GetExitCodeThread(thread.value, &result);
    if (result) {
        auto reason = listenerError(result);
        fail(reason ? std::string("Cannot attach: ") + reason : "Cannot attach: the attach request failed with code " + std::to_string(result));
    }
    pipe.connect(_process.value, _pid);
    if (version == 2) pipe.write(_process.value, request);
    auto reply = pipe.readAll(_process.value);
    auto newline = reply.find('\n');
    auto status = reply.substr(0, newline);
    char* end = nullptr;
    auto value = std::strtol(status.c_str(), &end, 10);
    if (status.empty() || *end) fail("Malformed attach reply: " + reply.substr(0, 80));
    return {static_cast<int>(value), newline == std::string::npos ? std::string() : reply.substr(newline + 1)};
}

int loadResult(const Attach::Reply& reply, std::string& message) {
    message.clear();
    if (reply.status != 0) {
        message = reply.body;
        return reply.status;
    }
    auto line = reply.body.substr(0, reply.body.find('\n'));
    const char* prefix = "return code: ";
    // JDK 9+: "return code: N"; JDK 8: the bare result; JDK 21+: an error message on failure.
    auto number = line.compare(0, std::strlen(prefix), prefix) == 0 ? line.substr(std::strlen(prefix)) : line;
    char* end = nullptr;
    auto value = std::strtol(number.c_str(), &end, 10);
    if (!number.empty() && !*end) return static_cast<int>(value);
    message = reply.body;
    return -1;
}
}
