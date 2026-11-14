/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwBrokerPrivate.h"
#include "windowsKernel.h"
#include "windowsProfiler.h"
#include <atomic>
#include <climits>

namespace WindowsProfiler::Etw::Broker {
namespace {
HANDLE peer = INVALID_HANDLE_VALUE;
ULONG captureSequence = 0;
SRWLOCK writeLock = SRWLOCK_INIT;
SRWLOCK modulesLock = SRWLOCK_INIT;
std::vector<KernelModule> knownModules;
bool haveModules = false;
ULONG sendControl(Type type, const void* data = nullptr, ULONG size = 0) {
    // Stop and the consumer's final acknowledgment can be concurrent. Keep
    // each header and body together on the byte-mode pipe.
    AcquireSRWLockExclusive(&writeLock);
    auto error = send(peer, type, data, size, nullptr, nullptr, captureSequence);
    ReleaseSRWLockExclusive(&writeLock);
    return error;
}
ULONG acceptModules(const std::vector<unsigned char>& data) {
    std::vector<KernelModule> replacement;
    size_t offset = 0;
    while (offset < data.size()) {
        if (data.size() - offset < sizeof(Module)) return ERROR_INVALID_DATA;
        Module value; std::memcpy(&value, data.data() + offset, sizeof(value)); offset += sizeof(value);
        if (!(value.base >> 63) || !value.size || value.base + value.size < value.base || !value.pathLength
                || value.pathLength > 32767 || value.pathLength * sizeof(WCHAR) > data.size() - offset) return ERROR_INVALID_DATA;
        auto path = reinterpret_cast<const WCHAR*>(data.data() + offset);
        std::wstring name(path, value.pathLength);
        if (name.find(L'\0') != std::wstring::npos) return ERROR_INVALID_DATA;
        offset += value.pathLength * sizeof(WCHAR);
        replacement.push_back({value.base, value.size, value.checksum, value.timestamp, name, name.substr(name.find_last_of(L"\\/") + 1)});
    }
    auto current = replacement;
    AcquireSRWLockExclusive(&modulesLock);
    knownModules.swap(replacement); haveModules = true;
    ReleaseSRWLockExclusive(&modulesLock);
    auto sameImage = [](const KernelModule& left, const KernelModule& right) {
        return left.base == right.base && left.size == right.size && left.checksum == right.checksum
            && left.timestamp == right.timestamp && left.path == right.path;
    };
    for (const auto& old : replacement) {
        bool present = false;
        for (const auto& image : current) if (sameImage(old, image)) { present = true; break; }
        if (!present) WindowsProfiler::kernelImageChanged(old.base, old.size, old.checksum, true, false);
    }
    for (const auto& image : current) {
        bool present = false;
        for (const auto& old : replacement) if (sameImage(old, image)) { present = true; break; }
        if (!present) WindowsProfiler::kernelImageChanged(image.base, image.size, image.checksum, false, true);
    }
    return ERROR_SUCCESS;
}
}
bool connected() { return peer != INVALID_HANDLE_VALUE; }
void close() {
    if (connected()) { CancelIoEx(peer, nullptr); CloseHandle(peer); peer = INVALID_HANDLE_VALUE; }
    captureSequence = 0;
    AcquireSRWLockExclusive(&modulesLock); knownModules.clear(); haveModules = false; ReleaseSRWLockExclusive(&modulesLock);
}
bool connect(const char* path) try {
    close();
    auto defaultPath = std::string("\\\\.\\pipe\\async-profiler-") + std::to_string(GetCurrentProcessId());
    if (!path) path = defaultPath.c_str();
    auto length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, nullptr, 0);
    if (length <= 1) return false;
    std::wstring name(length, 0);
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, name.data(), length) || !pipePath(name.c_str())) return false;
    peer = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (!connected() && GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeW(name.c_str(), 10000)) {
        peer = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    }
    if (!connected()) return false;
    ULONG serverPid = 0;
    HANDLE server = nullptr, token = nullptr;
    bool valid = GetNamedPipeServerProcessId(peer, &serverPid) && serverPid != GetCurrentProcessId();
    if (valid) { server = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, serverPid); valid = server != nullptr; }
    std::vector<unsigned char> serverUser, clientUser;
    if (valid) valid = !tokenUser(server, serverUser) && !tokenUser(GetCurrentProcess(), clientUser) && sameUser(serverUser, clientUser);
    if (valid) valid = OpenProcessToken(server, TOKEN_QUERY, &token);
    TOKEN_ELEVATION elevation{}; DWORD bytes = 0;
    if (valid) valid = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &bytes) && elevation.TokenIsElevated;
    if (token) CloseHandle(token);
    if (server) CloseHandle(server);
    Hello hello; hello.pid = GetCurrentProcessId();
    if (valid) valid = !processCreated(GetCurrentProcess(), hello.created) && !sendControl(Type::Hello, &hello, sizeof(hello));
    Type type; std::vector<unsigned char> data; ULONG sequence = 0;
    if (valid) valid = !receive(peer, type, data, nullptr, 10000, nullptr, nullptr, &sequence)
        && !sequence && type == Type::Ready && data.size() == sizeof(Reply);
    if (valid) { Reply reply; std::memcpy(&reply, data.data(), sizeof(reply)); valid = !reply.error && reply.pid == serverPid; }
    if (!valid) close();
    return valid;
} catch (...) { close(); return false; }
static ULONG startCapture(Type operation, const void* request, ULONG size, Reply& reply) try {
    if (!connected()) return ERROR_PIPE_NOT_CONNECTED;
    if (captureSequence == ULONG(-1)) return ERROR_ARITHMETIC_OVERFLOW;
    ++captureSequence;
    auto error = sendControl(operation, request, size);
    if (error) return error;
    for (;;) {
        Type type; std::vector<unsigned char> data;
        ULONG sequence;
        error = receive(peer, type, data, nullptr, 10000, nullptr, nullptr, &sequence);
        if (error) return error;
        if (sequence != captureSequence) return ERROR_INVALID_DATA;
        if (type == Type::Modules) { if ((error = acceptModules(data))) return error; continue; }
        if (type != Type::Ready || data.size() != sizeof(Reply)) return ERROR_INVALID_DATA;
        std::memcpy(&reply, data.data(), sizeof(reply));
        if (reply.error) {
            Acknowledgement ack{static_cast<ULONG>(Type::Ready)};
            sendControl(Type::Acknowledge, &ack, sizeof(ack)); close();
        }
        return reply.error;
    }
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
ULONG start(const Request& request, Reply& reply) { return startCapture(Type::Start, &request, sizeof(request), reply); }
ULONG startProvider(const ProviderRequest& request, Reply& reply) { return startCapture(Type::StartProvider, &request, sizeof(request), reply); }
ULONG consume(void* context, void (WINAPI* callback)(EVENT_RECORD*), Result& result) try {
    for (;;) {
        Type type; std::vector<unsigned char> data;
        ULONG sequence;
        auto error = receive(peer, type, data, nullptr, INFINITE, nullptr, nullptr, &sequence);
        if (error) return error;
        if (sequence != captureSequence) return ERROR_INVALID_DATA;
        if (type == Type::Modules) { if ((error = acceptModules(data))) return error; continue; }
        if (type == Type::Finished) {
            if (data.size() != sizeof(result)) return ERROR_INVALID_DATA;
            std::memcpy(&result, data.data(), sizeof(result));
            Acknowledgement ack{static_cast<ULONG>(Type::Finished)};
            auto acknowledged = sendControl(Type::Acknowledge, &ack, sizeof(ack));
            return result.error ? result.error : acknowledged;
        }
        if (type != Type::Event) return ERROR_INVALID_DATA;
        DecodedEvent decoded;
        error = decodeEvent(data, context, decoded);
        if (error) return error;
        callback(&decoded.event);
    }
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
ULONG activate() try {
    auto error = sendControl(Type::Activate);
    if (error) return error;
    Type type; std::vector<unsigned char> data;
    ULONG sequence;
    error = receive(peer, type, data, nullptr, 10000, nullptr, nullptr, &sequence);
    if (error) return error;
    if (sequence != captureSequence) return ERROR_INVALID_DATA;
    if (type != Type::Ready || data.size() != sizeof(Reply)) return ERROR_INVALID_DATA;
    Reply reply; std::memcpy(&reply, data.data(), sizeof(reply)); return reply.error;
} catch (...) { return ERROR_NOT_ENOUGH_MEMORY; }
ULONG stop() { return connected() ? sendControl(Type::Stop) : ERROR_PIPE_NOT_CONNECTED; }
bool kernelModules(std::vector<KernelModule>& modules) {
    AcquireSRWLockShared(&modulesLock);
    bool available = haveModules;
    if (available) {
        try { modules = knownModules; } catch (...) { ReleaseSRWLockShared(&modulesLock); throw; }
    }
    ReleaseSRWLockShared(&modulesLock); return available;
}
}
