/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsMappedImage.h"
#include <array>
#include <cstdio>
#include <cstdlib>

using namespace WindowsProfiler;
static void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s Windows=%lu\n", message, GetLastError()); std::exit(1); }
}
struct TemporaryImage {
    WCHAR path[MAX_PATH]{};
    explicit TemporaryImage(const WCHAR* original) {
        WCHAR temporary[MAX_PATH];
        require(GetTempPathW(MAX_PATH, temporary) && GetTempFileNameW(temporary, L"api", 0, path), "Cannot create image test file");
        require(CopyFileW(original, path, FALSE), "Cannot copy owned test image");
    }
    ~TemporaryImage() { DeleteFileW(path); }
    void setDword(std::uint64_t offset, DWORD value) {
        auto file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        require(file != INVALID_HANDLE_VALUE, "Cannot patch owned image fixture");
        LARGE_INTEGER position; position.QuadPart = offset;
        DWORD written = 0;
        require(SetFilePointerEx(file, position, nullptr, FILE_BEGIN) && WriteFile(file, &value, sizeof(value), &written, nullptr)
            && written == sizeof(value), "Cannot write owned image fixture");
        CloseHandle(file);
    }
};
int main() {
    auto module = GetModuleHandleW(nullptr);
    auto base = reinterpret_cast<const unsigned char*>(module);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    auto pe = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    WCHAR path[32768];
    auto length = GetModuleFileNameW(module, path, 32768);
    require(length && length < 32768, "Cannot find owned executable");
    ImageIdentity identity{pe->OptionalHeader.SizeOfImage, pe->OptionalHeader.CheckSum, pe->FileHeader.TimeDateStamp};
    MappedImage user;
    require(!user.open(path, identity, ImageIdentityPolicy::User), "Matching user identity rejected");
    auto wrong = identity; wrong.checksum ^= 1;
    MappedImage checksum;
    require(checksum.open(path, wrong, ImageIdentityPolicy::User) == ERROR_REVISION_MISMATCH, "User checksum mismatch accepted");
    wrong = identity; wrong.size ^= 0x1000;
    MappedImage size;
    require(size.open(path, wrong, ImageIdentityPolicy::User) == ERROR_REVISION_MISMATCH, "User size mismatch accepted");
    wrong = identity; wrong.timestamp ^= 1;
    MappedImage timestamp;
    require(timestamp.open(path, wrong, ImageIdentityPolicy::User) == ERROR_REVISION_MISMATCH, "User timestamp mismatch accepted");
    {
        TemporaryImage zero(path);
        zero.setDword(dos->e_lfanew + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum), 0);
        auto expected = identity; expected.checksum = 0;
        require(!GetModuleHandleW(zero.path), "Image fixture was unexpectedly loaded");
        MappedImage matchingZero;
        require(!matchingZero.open(zero.path, expected, ImageIdentityPolicy::User), "Matching zero user checksum rejected");
        require(!GetModuleHandleW(zero.path), "Read-only mapping loaded an executable image");
        MappedImage strictKernel;
        require(strictKernel.open(zero.path, expected, ImageIdentityPolicy::Kernel) == ERROR_REVISION_MISMATCH,
            "User zero-checksum policy weakened kernel validation");
    }
    std::array<IMAGE_SECTION_HEADER, 2> sections{};
    auto& text = sections[0];
    text.PointerToRawData = 0x400; text.SizeOfRawData = 0x400; text.VirtualAddress = 0x1000;
    text.Misc.VirtualSize = 0x300; text.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    auto& data = sections[1];
    data.PointerToRawData = 0x800; data.SizeOfRawData = 0x200; data.VirtualAddress = 0x2000; data.Misc.VirtualSize = 0x200;
    ULONG rva = 0; size_t available = 0;
    require(!Pe::executableFileOffset(sections, 0x3000, 0x430, rva, available) && rva == 0x1030 && available == 0x2d0,
        "Physical file offset was confused with an RVA");
    for (auto invalid : {0x100ULL, 0x700ULL, 0x810ULL, 0x100000000ULL}) {
        require(Pe::executableFileOffset(sections, 0x3000, invalid, rva, available), "Header/data/padding/overlay offset accepted");
        require(rva == 0x1030 && available == 0x2d0, "Failed file mapping modified output");
    }
    auto overlap = sections; overlap[1] = text;
    require(Pe::executableFileOffset(overlap, 0x3000, 0x430, rva, available), "Ambiguous raw section mapping accepted");
    text.VirtualAddress = 0xfffffff0;
    require(Pe::executableFileOffset(sections, 0x3000, 0x430, rva, available), "Overflowed executable section accepted");
    std::puts("Mapped image policies and executable file offsets: PASS");
}
