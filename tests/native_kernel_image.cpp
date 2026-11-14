/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsKernel.h"
#include <cstdio>
#include <cwchar>
#include <stdexcept>

using namespace WindowsProfiler;
static void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int main(int argc, char** argv) try {
    std::vector<KernelModule> modules;
    auto error = kernelModules(modules);
    if (argc == 2) {
        require(error == ERROR_NOT_ALL_ASSIGNED || error == ERROR_ACCESS_DENIED, "Kernel address restriction was not reported");
        std::printf("KERNEL_IMAGE_DENIED_OK error=%lu\n", error);
        return 0;
    }
    if (error) { std::fprintf(stderr, "Kernel module enumeration: %lu\n", error); return 1; }
    require(!modules.empty(), "Empty kernel module list");
    auto module = modules.front();
    require(_wcsicmp(module.name.c_str(), L"ntoskrnl.exe") == 0, "Kernel image identity");
    KernelImage valid;
    require(valid.open(module) == ERROR_SUCCESS, "Cannot map the matching kernel image");
    auto wrong = module;
    wrong.checksum ^= 1;
    KernelImage checksum;
    require(checksum.open(wrong) == ERROR_REVISION_MISMATCH, "Mismatched checksum accepted");
    wrong = module; wrong.size ^= 0x1000;
    KernelImage size;
    require(size.open(wrong) == ERROR_REVISION_MISMATCH, "Mismatched image size accepted");
    wrong = module; wrong.timestamp = valid.headers()->FileHeader.TimeDateStamp ^ 1;
    KernelImage timestamp;
    require(timestamp.open(wrong) == ERROR_REVISION_MISMATCH, "Mismatched timestamp accepted");
    unsigned mapped = 0, aliases = 0, mismatched = 0;
    for (const auto& candidate : modules) {
        KernelImage image;
        auto opened = image.open(candidate);
        if (opened == ERROR_SUCCESS) {
            ++mapped;
            aliases += image.path() != candidate.path;
        }
        mismatched += opened == ERROR_REVISION_MISMATCH;
    }
    std::printf("KERNEL_IMAGE_OK modules=%zu mapped=%u mismatched=%u dumpAliases=%u size=%lu checksum=%lx timestampAvailable=%u\n",
                modules.size(), mapped, mismatched, aliases, module.size, module.checksum, module.timestamp != 0);
    return 0;
} catch (const std::exception& error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
