/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include "windowsMappedImage.h"

namespace WindowsProfiler {
struct KernelModule {
    std::uintptr_t base;
    ULONG size, checksum, timestamp;
    std::wstring path, name;
    std::uint64_t signature() const { return (std::uint64_t(checksum) << 32) | size; }
};
DWORD kernelModules(std::vector<KernelModule>& modules);
class KernelImage : public MappedImage {
public:
    KernelImage() = default;
    KernelImage(const KernelImage&) = delete;
    KernelImage& operator=(const KernelImage&) = delete;
    DWORD open(const KernelModule& module);
};
}
