/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsNativeErrorState.h"
#include "windowsInstructionDecoder.h"
#include "windowsMutex.h"
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>

namespace WindowsProfiler {
namespace {
std::atomic<std::uint32_t> statusOffset{0};
WindowsMutex setup;
}
const char* prepareNativeErrorState() noexcept {
    if (statusOffset.load(std::memory_order_acquire)) return nullptr;
    std::lock_guard lock(setup);
    if (statusOffset.load(std::memory_order_relaxed)) return nullptr;
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    auto getter = GetProcAddress(ntdll, "RtlGetLastNtStatus");
    MEMORY_BASIC_INFORMATION memory{};
    std::array<unsigned char, 9> bytes{};
    SIZE_T copied = 0;
    const unsigned char prefix[]{0x65,0x8b,0x04,0x25};
    auto address = reinterpret_cast<std::uintptr_t>(getter);
    if (!getter || !VirtualQuery(reinterpret_cast<const void*>(getter), &memory, sizeof(memory))
            || memory.AllocationBase != ntdll || memory.Type != MEM_IMAGE || memory.State != MEM_COMMIT
            || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) || memory.RegionSize < bytes.size()
            || address < reinterpret_cast<std::uintptr_t>(memory.BaseAddress)
            || address - reinterpret_cast<std::uintptr_t>(memory.BaseAddress) > memory.RegionSize - bytes.size()
            || !ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(getter), bytes.data(), bytes.size(), &copied)
            || copied != bytes.size() || std::memcmp(bytes.data(), prefix, sizeof(prefix)) || bytes[8] != 0xc3
            || InstructionDecoder::length(bytes.data(), bytes.size()) != 8)
        return "Cannot certify the loaded RtlGetLastNtStatus field accessor";
    std::uint32_t offset;
    std::memcpy(&offset, bytes.data() + 4, sizeof(offset));
    DWORD value;
    auto teb = reinterpret_cast<unsigned char*>(NtCurrentTeb());
    if (offset < 0x70 || offset > 0x2000 || (offset & 3)
            || !ReadProcessMemory(GetCurrentProcess(), teb + offset, &value, sizeof(value), &copied)
            || copied != sizeof(value))
        return "Cannot certify the current thread NT status field";
    statusOffset.store(offset, std::memory_order_release);
    return nullptr;
}
SavedNativeErrorState::SavedNativeErrorState() noexcept
    : _error(GetLastError()), _teb(reinterpret_cast<unsigned char*>(NtCurrentTeb())),
      _offset(statusOffset.load(std::memory_order_acquire)) {
    std::memcpy(&_status, _teb + _offset, sizeof(_status));
}
SavedNativeErrorState::~SavedNativeErrorState() {
    std::memcpy(_teb + _offset, &_status, sizeof(_status));
    SetLastError(_error);
}
}
