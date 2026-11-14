/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsKernel.h"
#include "windowsPrivilege.h"
#if !defined(ASPROF_HELPER) && !defined(ASPROF_KERNEL_TEST)
#include "windowsEtwBroker.h"
#endif
#include <winternl.h>
#include <psapi.h>
#include <algorithm>
#include <cstddef>
#include <cstring>

namespace WindowsProfiler {
namespace {
// Layout documented by phnt; validated before use rather than trusting a
// guessed module size or a synthetic address when Windows redacts the bases.
// https://github.com/winsiderss/phnt/blob/master/ntrtl.h
struct ModuleInfo {
    void* section; void* mapped; void* base;
    ULONG size, flags;
    USHORT loadOrder, initOrder, loadCount, nameOffset;
    char name[256];
};
struct ModuleInfoEx {
    USHORT next;
    ModuleInfo module;
    ULONG checksum, timestamp;
    void* preferred;
};
static_assert(sizeof(ModuleInfoEx) == 320 && offsetof(ModuleInfoEx, checksum) == 304);

std::wstring imagePath(const WCHAR* path, size_t length) {
    std::wstring value(path, length);
    WCHAR directory[32768];
    if (_wcsnicmp(value.c_str(), L"\\SystemRoot\\", 12) == 0) {
        auto count = GetWindowsDirectoryW(directory, 32768);
        return count && count < 32768 ? std::wstring(directory, count) + value.substr(11) : std::wstring();
    }
    if (value.starts_with(L"\\??\\")) return value.substr(4);
    if (value.size() >= 3 && value[1] == L':') return value;
    if (value.starts_with(L"\\Device\\")) {
        for (WCHAR drive = L'A'; drive <= L'Z'; ++drive) {
            WCHAR name[] = {drive, L':', 0};
            if (!QueryDosDeviceW(name, directory, 32768)) continue;
            size_t count = std::wcslen(directory);
            if (value.size() > count && value[count] == L'\\' && _wcsnicmp(value.c_str(), directory, count) == 0) {
                return std::wstring(name) + value.substr(count);
            }
        }
    }
    return {};
}
}

DWORD kernelModules(std::vector<KernelModule>& modules) {
#if !defined(ASPROF_HELPER) && !defined(ASPROF_KERNEL_TEST)
    if (Etw::Broker::kernelModules(modules)) return ERROR_SUCCESS;
#endif
    modules.clear();
    Privilege privilege(L"SeDebugPrivilege");
    auto privilegeError = privilege.enable();
    std::vector<unsigned char> bytes(64 * 1024);
    ULONG required = 0;
    auto status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(77), bytes.data(), static_cast<ULONG>(bytes.size()), &required);
    if (static_cast<ULONG>(status) == 0xc0000004 && required <= 16 * 1024 * 1024) {
        bytes.resize(required);
        status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(77), bytes.data(), static_cast<ULONG>(bytes.size()), &required);
    }
    if (status < 0) return privilegeError && (static_cast<ULONG>(status) == 0xc0000022 || static_cast<ULONG>(status) == 0xc0000061)
        ? privilegeError : RtlNtStatusToDosError(status);
    if (required > bytes.size()) return ERROR_INVALID_DATA;
    for (size_t offset = 0; offset + sizeof(USHORT) <= required;) {
        auto info = reinterpret_cast<const ModuleInfoEx*>(bytes.data() + offset);
        if (!info->next) return modules.empty() ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
        if (info->next < sizeof(*info) || info->next > required - offset) return ERROR_INVALID_DATA;
        auto base = reinterpret_cast<std::uintptr_t>(info->module.base);
        if (!(base >> 63) || !info->module.size || base + info->module.size < base) return privilegeError ? privilegeError : ERROR_ACCESS_DENIED;
        WCHAR name[32768];
        auto length = GetDeviceDriverFileNameW(info->module.base, name, 32768);
        if (length && length < 32768) {
            auto path = imagePath(name, length);
            if (!path.empty()) {
                auto separator = path.find_last_of(L"\\/");
                modules.push_back({base, info->module.size, info->checksum, info->timestamp, path, path.substr(separator + 1)});
            }
        }
        offset += info->next;
    }
    return ERROR_INVALID_DATA;
}

DWORD KernelImage::open(const KernelModule& module) {
    ImageIdentity identity{module.size, module.checksum, module.timestamp};
    auto result = MappedImage::open(module.path, identity, ImageIdentityPolicy::Kernel);
    if (!hasFile() && result == ERROR_FILE_NOT_FOUND
            && _wcsnicmp(module.name.c_str(), L"dump_", 5) == 0) {
        // Crash-dump stack copies use dump_ aliases. The candidate still has
        // to pass the loaded image's checksum/size checks below.
        auto candidate = module.path.substr(0, module.path.find_last_of(L"\\/") + 1) + module.name.substr(5);
        result = MappedImage::open(candidate, identity, ImageIdentityPolicy::Kernel);
    }
    return result;
}
}
