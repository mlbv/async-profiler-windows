/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <cstdint>
#include <span>
#include <string>

namespace WindowsProfiler {
enum class ImageIdentityPolicy { Kernel, User };
struct ImageIdentity { ULONG size, checksum, timestamp; };
namespace Pe {
const char* executableFileOffset(std::span<const IMAGE_SECTION_HEADER> sections, ULONG imageSize,
    std::uint64_t offset, ULONG& rva, size_t& available);
}
class MappedImage {
    HANDLE _file = INVALID_HANDLE_VALUE, _mapping = nullptr;
    const unsigned char* _base = nullptr;
    ULONG _size = 0;
    std::wstring _path;
protected:
    bool hasFile() const { return _file != INVALID_HANDLE_VALUE; }
public:
    MappedImage() = default;
    MappedImage(const MappedImage&) = delete;
    MappedImage& operator=(const MappedImage&) = delete;
    ~MappedImage();
    DWORD open(const std::wstring& path, const ImageIdentity& expected, ImageIdentityPolicy policy);
    const std::wstring& path() const { return _path; }
    const IMAGE_NT_HEADERS64* headers() const;
    std::span<const IMAGE_SECTION_HEADER> sections() const;
    const unsigned char* data(ULONG rva, size_t length) const;
    const char* executableFileOffset(std::uint64_t offset, ULONG& rva, size_t& available) const;
};
}
