/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsMappedImage.h"
#include <algorithm>
#include <cstddef>

namespace WindowsProfiler {
MappedImage::~MappedImage() {
    if (_base) UnmapViewOfFile(_base);
    if (_mapping) CloseHandle(_mapping);
    if (_file != INVALID_HANDLE_VALUE) CloseHandle(_file);
}
const IMAGE_NT_HEADERS64* MappedImage::headers() const {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(_base);
    return reinterpret_cast<const IMAGE_NT_HEADERS64*>(_base + dos->e_lfanew);
}
const unsigned char* MappedImage::data(ULONG rva, size_t length) const {
    return rva <= _size && length <= _size - rva ? _base + rva : nullptr;
}
std::span<const IMAGE_SECTION_HEADER> MappedImage::sections() const {
    auto pe = headers();
    return {IMAGE_FIRST_SECTION(pe), pe->FileHeader.NumberOfSections};
}
DWORD MappedImage::open(const std::wstring& path, const ImageIdentity& expected, ImageIdentityPolicy policy) {
    if (hasFile()) return ERROR_ALREADY_INITIALIZED;
    _path = path;
    _file = CreateFileW(_path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (_file == INVALID_HANDLE_VALUE) return GetLastError();
    _mapping = CreateFileMappingW(_file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr);
    if (!_mapping) return GetLastError();
    _base = static_cast<const unsigned char*>(MapViewOfFile(_mapping, FILE_MAP_READ, 0, 0, 0));
    if (!_base) return GetLastError();
    _size = expected.size;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0
            || !data(static_cast<ULONG>(dos->e_lfanew), sizeof(IMAGE_NT_HEADERS64))) return ERROR_BAD_EXE_FORMAT;
    auto pe = headers();
    if (pe->Signature != IMAGE_NT_SIGNATURE || pe->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
            || pe->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
            || pe->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) return ERROR_BAD_EXE_FORMAT;
    if ((policy == ImageIdentityPolicy::Kernel && !expected.checksum)
            || expected.size != pe->OptionalHeader.SizeOfImage || expected.checksum != pe->OptionalHeader.CheckSum
            || ((policy == ImageIdentityPolicy::User || expected.timestamp) && expected.timestamp != pe->FileHeader.TimeDateStamp))
        return ERROR_REVISION_MISMATCH;
    auto sectionOffset = static_cast<std::uint64_t>(dos->e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
        + pe->FileHeader.SizeOfOptionalHeader;
    auto sectionBytes = static_cast<size_t>(pe->FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (!pe->FileHeader.NumberOfSections || sectionOffset > _size || !data(static_cast<ULONG>(sectionOffset), sectionBytes)
            || pe->OptionalHeader.SizeOfHeaders > _size || sectionOffset + sectionBytes > pe->OptionalHeader.SizeOfHeaders)
        return ERROR_BAD_EXE_FORMAT;
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(_file, &fileSize)) return GetLastError();
    for (const auto& section : sections()) {
        auto virtualSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
        if (virtualSize > _size || section.VirtualAddress > _size - virtualSize
                || static_cast<std::uint64_t>(section.PointerToRawData) + section.SizeOfRawData > static_cast<std::uint64_t>(fileSize.QuadPart))
            return ERROR_BAD_EXE_FORMAT;
    }
    return ERROR_SUCCESS;
}

const char* MappedImage::executableFileOffset(std::uint64_t offset, ULONG& rva, size_t& available) const {
    return Pe::executableFileOffset(sections(), _size, offset, rva, available);
}

const char* Pe::executableFileOffset(std::span<const IMAGE_SECTION_HEADER> sections, ULONG imageSize,
        std::uint64_t offset, ULONG& rva, size_t& available) {
    bool found = false, backed = false;
    ULONG selected = 0;
    size_t remaining = 0;
    for (const auto& section : sections) {
        if (offset < section.PointerToRawData || offset - section.PointerToRawData >= section.SizeOfRawData) continue;
        backed = true;
        if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        auto delta = offset - section.PointerToRawData;
        auto virtualSize = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
        if (delta >= virtualSize) continue;
        auto mapped = static_cast<std::uint64_t>(section.VirtualAddress) + delta;
        if (mapped >= imageSize || virtualSize > imageSize || section.VirtualAddress > imageSize - virtualSize)
            return "Executable PE section lies outside the image";
        if (found) return "PE file offset maps to more than one executable section";
        selected = static_cast<ULONG>(mapped);
        remaining = static_cast<size_t>(std::min<std::uint64_t>(section.SizeOfRawData - delta, virtualSize - delta));
        found = true;
    }
    if (!found) return backed ? "PE file offset is not executable image data" : "PE file offset is outside mapped section data";
    rva = selected; available = remaining;
    return nullptr;
}
}
