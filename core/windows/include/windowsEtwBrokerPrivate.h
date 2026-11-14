/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include "windowsEtwBroker.h"
#include <sddl.h>
#include <cstring>
#include <cwchar>
#include <iterator>
#include <string>
#include <vector>

namespace WindowsProfiler::Etw::Broker {
inline bool pipePath(const WCHAR* path) {
    constexpr WCHAR prefix[] = L"\\\\.\\pipe\\async-profiler-";
    return path && std::wcsncmp(path, prefix, std::size(prefix) - 1) == 0
        && std::wcslen(path) < 240 && !std::wcschr(path + std::size(prefix) - 1, L'\\');
}
inline ULONG transfer(HANDLE pipe, void* bytes, DWORD length, bool write, HANDLE owner = nullptr, DWORD timeout = 10000, HANDLE cancelled = nullptr, HANDLE lifetime = nullptr) {
    auto deadline = timeout == INFINITE ? 0 : GetTickCount64() + timeout;
    OVERLAPPED operation{};
    operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!operation.hEvent) return GetLastError();
    ULONG error = ERROR_SUCCESS;
    auto current = static_cast<unsigned char*>(bytes);
    while (length) {
        auto now = GetTickCount64();
        if (timeout != INFINITE && now >= deadline) { error = ERROR_TIMEOUT; break; }
        auto remaining = timeout == INFINITE ? INFINITE : static_cast<DWORD>(deadline - now);
        ResetEvent(operation.hEvent);
        DWORD done = 0;
        BOOL success = write ? WriteFile(pipe, current, length, &done, &operation)
                             : ReadFile(pipe, current, length, &done, &operation);
        if (!success) {
            error = GetLastError();
            if (error != ERROR_IO_PENDING) break;
            HANDLE events[4] = {operation.hEvent}; DWORD count = 1;
            DWORD ownerIndex = MAXDWORD, cancelledIndex = MAXDWORD, lifetimeIndex = MAXDWORD;
            if (owner) { ownerIndex = count; events[count++] = owner; }
            if (cancelled) { cancelledIndex = count; events[count++] = cancelled; }
            if (lifetime) { lifetimeIndex = count; events[count++] = lifetime; }
            auto waited = WaitForMultipleObjects(count, events, FALSE, remaining);
            if (waited != WAIT_OBJECT_0) {
                error = waited == WAIT_TIMEOUT ? ERROR_TIMEOUT : owner && waited == WAIT_OBJECT_0 + ownerIndex ? ERROR_PROCESS_ABORTED
                    : cancelled && waited == WAIT_OBJECT_0 + cancelledIndex ? ERROR_OPERATION_ABORTED
                    : lifetime && waited == WAIT_OBJECT_0 + lifetimeIndex ? ERROR_PROCESS_ABORTED : GetLastError();
                CancelIoEx(pipe, &operation);
                GetOverlappedResult(pipe, &operation, &done, TRUE);
                break;
            }
            if (!GetOverlappedResult(pipe, &operation, &done, FALSE)) { error = GetLastError(); break; }
        }
        error = done ? ERROR_SUCCESS : ERROR_BROKEN_PIPE;
        if (error) break;
        current += done; length -= done;
    }
    CloseHandle(operation.hEvent);
    return error;
}
inline ULONG send(HANDLE pipe, Type type, const void* data, ULONG size, HANDLE owner = nullptr, HANDLE lifetime = nullptr, ULONG sequence = 0) {
    if (size > MAX_PACKET) return ERROR_INVALID_PARAMETER;
    Header header{PROTOCOL, static_cast<ULONG>(type), size, sequence};
    auto deadline = GetTickCount64() + 10000;
    auto error = transfer(pipe, &header, sizeof(header), true, owner, 10000, nullptr, lifetime);
    if (error) return error;
    auto now = GetTickCount64();
    if (size && now >= deadline) return ERROR_TIMEOUT;
    return transfer(pipe, const_cast<void*>(data), size, true, owner, static_cast<DWORD>(deadline - now), nullptr, lifetime);
}
inline ULONG receive(HANDLE pipe, Type& type, std::vector<unsigned char>& data, HANDLE owner = nullptr, DWORD timeout = 10000, HANDLE cancelled = nullptr, HANDLE lifetime = nullptr, ULONG* sequence = nullptr) {
    Header header;
    auto deadline = timeout == INFINITE ? 0 : GetTickCount64() + timeout;
    auto error = transfer(pipe, &header, sizeof(header), false, owner, timeout, cancelled, lifetime);
    if (error) return error;
    if (header.protocol != PROTOCOL) return ERROR_REVISION_MISMATCH;
    if (header.size > MAX_PACKET || header.type < static_cast<ULONG>(Type::Hello)
            || header.type > static_cast<ULONG>(Type::Acknowledge)) return ERROR_INVALID_DATA;
    type = static_cast<Type>(header.type);
    if (sequence) *sequence = header.sequence;
    data.resize(header.size);
    auto now = GetTickCount64();
    if (header.size && timeout != INFINITE && now >= deadline) return ERROR_TIMEOUT;
    auto bodyTimeout = timeout == INFINITE ? 10000 : static_cast<DWORD>(deadline - now);
    return transfer(pipe, data.data(), header.size, false, owner, bodyTimeout, cancelled, lifetime);
}
inline ULONG tokenUser(HANDLE process, std::vector<unsigned char>& bytes) {
    HANDLE token;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return GetLastError();
    DWORD length = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &length);
    bytes.resize(length);
    auto error = GetTokenInformation(token, TokenUser, bytes.data(), length, &length) ? ERROR_SUCCESS : GetLastError();
    CloseHandle(token); return error;
}
inline bool sameUser(const std::vector<unsigned char>& left, const std::vector<unsigned char>& right) {
    return EqualSid(reinterpret_cast<const TOKEN_USER*>(left.data())->User.Sid,
                    reinterpret_cast<const TOKEN_USER*>(right.data())->User.Sid);
}
inline ULONG processCreated(HANDLE process, FILETIME& created) {
    FILETIME exited, kernel, user;
    return GetProcessTimes(process, &created, &exited, &kernel, &user) ? ERROR_SUCCESS : GetLastError();
}
}
