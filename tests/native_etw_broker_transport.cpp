/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsEtwBrokerPrivate.h"
#include "windowsEtwControllerSecurity.h"
#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <thread>

using namespace WindowsProfiler::Etw;
using namespace WindowsProfiler::Etw::Broker;
namespace {
void require(bool condition, const char* text) { if (!condition) throw std::runtime_error(text); }
struct Pipe {
    ControllerObject server, client, connected;
    Pipe() {
        static unsigned id;
        WCHAR name[160];
        std::swprintf(name, 160, L"\\\\.\\pipe\\async-profiler-transport-%lu-%u", GetCurrentProcessId(), ++id);
        server.value = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 4096, 4096, 0, nullptr);
        require(server.value != INVALID_HANDLE_VALUE, "CreateNamedPipe");
        connected.value = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        require(connected.value != nullptr, "CreateEvent");
        OVERLAPPED operation{}; operation.hEvent = connected.value;
        BOOL ready = ConnectNamedPipe(server.value, &operation);
        auto error = ready ? ERROR_SUCCESS : GetLastError();
        require(error == ERROR_IO_PENDING || error == ERROR_SUCCESS, "ConnectNamedPipe");
        client.value = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        require(client.value != INVALID_HANDLE_VALUE, "CreateFile");
        if (error == ERROR_IO_PENDING) {
            DWORD done;
            require(WaitForSingleObject(connected.value, 1000) == WAIT_OBJECT_0
                && GetOverlappedResult(server.value, &operation, &done, FALSE), "connect completion");
        }
    }
};
void dribbled(bool body) {
    Pipe pipe;
    Header header{PROTOCOL, static_cast<ULONG>(Type::Ready), body ? 16u : 0u, 7};
    ULONG writeError = ERROR_SUCCESS;
    std::thread writer([&] {
        if (body) {
            std::this_thread::sleep_for(std::chrono::milliseconds(70));
            writeError = transfer(pipe.server.value, &header, sizeof(header), true, nullptr, 1000);
        }
        auto bytes = reinterpret_cast<unsigned char*>(&header);
        for (size_t index = 0; !writeError && index < sizeof(header); ++index) {
            writeError = transfer(pipe.server.value, bytes + index, 1, true, nullptr, 1000);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
        }
    });
    Type type; std::vector<unsigned char> bytes; ULONG sequence = 0;
    auto started = GetTickCount64();
    auto error = receive(pipe.client.value, type, bytes, nullptr, 100, nullptr, nullptr, &sequence);
    auto elapsed = GetTickCount64() - started;
    writer.join();
    require(!writeError, "local writer failed");
    require(error == ERROR_TIMEOUT, body ? "dribbled body reset deadline" : "dribbled header reset deadline");
    require(elapsed < 400, "whole-packet timeout exceeded dribble duration");
    std::printf("BROKER_TRANSPORT_TIMEOUT phase=%s elapsed=%llu\n", body ? "body" : "header", static_cast<unsigned long long>(elapsed));
}
}
int main() try {
    Pipe pipe;
    Reply expected{0, 7, 1000, GetCurrentProcessId()};
    require(send(pipe.server.value, Type::Ready, &expected, sizeof(expected), nullptr, nullptr, 9) == 0, "normal send");
    Type type; std::vector<unsigned char> data; ULONG sequence;
    require(receive(pipe.client.value, type, data, nullptr, 1000, nullptr, nullptr, &sequence) == 0
        && type == Type::Ready && sequence == 9 && data.size() == sizeof(expected)
        && std::memcmp(data.data(), &expected, sizeof(expected)) == 0, "normal packet");
    dribbled(false); dribbled(true);
    std::puts("BROKER_TRANSPORT_OK normalPacket=1 absoluteHeaderDeadline=1 sharedBodyBudget=1");
    return 0;
} catch (const std::exception& error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
