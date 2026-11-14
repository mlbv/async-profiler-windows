/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsMappedNativeUnwind.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <utility>

namespace WindowsProfiler::NativeUnwind {
namespace {
class Image {
    HMODULE _module;
    std::uintptr_t _base;
    ULONG _size;
    std::vector<IMAGE_SECTION_HEADER> _sections;
    std::vector<std::vector<unsigned char>> _copies;
public:
    Image(HMODULE module, ULONG size) : _module(module), _base(reinterpret_cast<std::uintptr_t>(module)), _size(size) {}
    bool bounds(ULONG rva, size_t size) const { return rva <= _size && size <= _size - rva; }
    bool accessible(ULONG rva, size_t size, bool code) const {
        if (!bounds(rva, size)) return false;
        auto cursor = _base + rva, end = cursor + size;
        while (cursor < end) {
            MEMORY_BASIC_INFORMATION page{};
            if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &page, sizeof(page))
                    || page.AllocationBase != _module || page.Type != MEM_IMAGE || page.State != MEM_COMMIT
                    || (page.Protect & (PAGE_GUARD | PAGE_NOACCESS))
                    || !(page.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY
                        | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                    || (code && !(page.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))))
                return false;
            cursor = std::min(end, reinterpret_cast<std::uintptr_t>(page.BaseAddress) + page.RegionSize);
        }
        return true;
    }
    bool read(ULONG rva, void* output, size_t size, bool code = false) const {
        if (!accessible(rva, size, code)) return false;
        SIZE_T copied = 0;
        return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(_base + rva), output, size, &copied)
            && copied == size;
    }
    bool section(ULONG rva, size_t size, bool code) const {
        if (!bounds(rva, size) || !size) return false;
        unsigned matches = 0;
        for (const auto& section : _sections) {
            auto length = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if (rva >= section.VirtualAddress && rva - section.VirtualAddress < length
                    && size <= length - (rva - section.VirtualAddress)) {
                if (!(section.Characteristics & IMAGE_SCN_MEM_READ)
                        || (code && !(section.Characteristics & IMAGE_SCN_MEM_EXECUTE))) return false;
                ++matches;
            } else if (static_cast<std::uint64_t>(rva) + size > section.VirtualAddress
                    && rva < static_cast<std::uint64_t>(section.VirtualAddress) + length) return false;
        }
        return matches == 1 && accessible(rva, size, code);
    }
    const char* headers(IMAGE_DATA_DIRECTORY& exception) {
        if (!_module || !_size || _base > std::numeric_limits<std::uintptr_t>::max() - _size)
            return "mapped-unwind-image-bounds";
        IMAGE_DOS_HEADER dos{};
        IMAGE_NT_HEADERS64 pe{};
        if (!read(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0
                || !read(static_cast<ULONG>(dos.e_lfanew), &pe, sizeof(pe))
                || pe.Signature != IMAGE_NT_SIGNATURE || pe.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                || pe.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
                || pe.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)
                || pe.OptionalHeader.SizeOfImage != _size || !pe.FileHeader.NumberOfSections
                || pe.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            return "mapped-unwind-image-headers";
        auto offset = static_cast<std::uint64_t>(dos.e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader)
            + pe.FileHeader.SizeOfOptionalHeader;
        auto bytes = static_cast<size_t>(pe.FileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
        if (offset > _size || bytes > _size - offset || pe.OptionalHeader.SizeOfHeaders > _size
                || offset + bytes > pe.OptionalHeader.SizeOfHeaders) return "mapped-unwind-section-table";
        _sections.resize(pe.FileHeader.NumberOfSections);
        if (!read(static_cast<ULONG>(offset), _sections.data(), bytes)) return "mapped-unwind-section-table";
        for (const auto& section : _sections) {
            auto length = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if (!bounds(section.VirtualAddress, length)) return "mapped-unwind-section-bounds";
        }
        exception = pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        return nullptr;
    }
    // Metadata reads through one snapshot of each containing readable section.
    bool readCopied(ULONG rva, void* output, size_t size) {
        if (!bounds(rva, size) || !size) return false;
        _copies.resize(_sections.size());
        for (size_t index = 0; index < _sections.size(); ++index) {
            const auto& section = _sections[index];
            auto length = section.Misc.VirtualSize ? section.Misc.VirtualSize : section.SizeOfRawData;
            if (rva < section.VirtualAddress || rva - section.VirtualAddress >= length) continue;
            if (size > length - (rva - section.VirtualAddress) || !(section.Characteristics & IMAGE_SCN_MEM_READ)) return false;
            auto& copy = _copies[index];
            if (copy.empty()) {
                std::vector<unsigned char> bytes(length);
                if (!read(section.VirtualAddress, bytes.data(), length)) return false;
                copy = std::move(bytes);
            }
            std::memcpy(output, copy.data() + (rva - section.VirtualAddress), size);
            return true;
        }
        return false;
    }
    const char* selected(const IMAGE_DATA_DIRECTORY& directory, ULONG pc, const RUNTIME_FUNCTION& function) const {
        if (!directory.Size || directory.Size % sizeof(RUNTIME_FUNCTION) || (directory.VirtualAddress & 3)
                || !section(directory.VirtualAddress, directory.Size, false)) return "mapped-unwind-exception-directory";
        size_t low = 0, high = directory.Size / sizeof(RUNTIME_FUNCTION);
        while (low < high) {
            auto middle = low + (high - low) / 2;
            RUNTIME_FUNCTION row{};
            if (!read(directory.VirtualAddress + static_cast<ULONG>(middle * sizeof(row)), &row, sizeof(row)))
                return "mapped-unwind-exception-directory";
            if (pc < row.BeginAddress) high = middle;
            else if (pc >= row.EndAddress) low = middle + 1;
            else return !std::memcmp(&row, &function, sizeof(row)) ? nullptr : "mapped-unwind-selected-row-mismatch";
        }
        return "mapped-unwind-selected-row-missing";
    }
};
}

const char* snapshotMapped(HMODULE module, ULONG imageSize, const RUNTIME_FUNCTION& function,
        DWORD64 pc, size_t instructionLength, SourceSnapshot& result) {
    Image image(module, imageSize);
    IMAGE_DATA_DIRECTORY directory{};
    if (auto error = image.headers(directory)) return error;
    auto base = reinterpret_cast<std::uintptr_t>(module);
    if (pc < base || pc - base >= imageSize || !instructionLength
            || instructionLength > InstructionDecoder::MAX_INSTRUCTION_BYTES)
        return "mapped-unwind-probe-bounds";
    auto rva = static_cast<ULONG>(pc - base);
    if (function.BeginAddress >= function.EndAddress || rva < function.BeginAddress || rva >= function.EndAddress
            || instructionLength > function.EndAddress - rva) return "mapped-unwind-probe-bounds";
    if (auto error = image.selected(directory, rva, function)) return error;

    SourceSnapshot prepared;
    prepared._probe = rva - function.BeginAddress;
    RUNTIME_FUNCTION current = function;
    size_t bytes = 0;
    for (;;) {
        if (current.BeginAddress >= current.EndAddress || (current.UnwindData & 3)
                || !image.section(current.BeginAddress, current.EndAddress - current.BeginAddress, true)
                || !image.section(current.UnwindData, 4, false)) return "mapped-unwind-function-bounds";
        for (const auto& prior : prepared._functions)
            if (prior.identity.UnwindData == current.UnwindData) return "cyclic-unwind-chain";
        std::array<unsigned char,4> header{};
        if (!image.read(current.UnwindData, header.data(), header.size())) return "mapped-unwind-header-read";
        auto version = header[0] & 7, flags = header[0] >> 3;
        if (version != 1 && version != 2) return "unsupported-unwind-version";
        if ((flags & ~7u) || ((flags & 4) && (flags & 3))) return "invalid-unwind-flags";
        if (flags & 3) return "language-handler-needs-forwarding";
        auto padded = 4 + ((static_cast<size_t>(header[2]) + 1) & ~size_t(1)) * 2;
        auto metadata = padded + (flags & 4 ? sizeof(RUNTIME_FUNCTION) : 0);
        auto code = static_cast<size_t>(current.EndAddress - current.BeginAddress);
        if (!image.section(current.UnwindData, metadata, false)) return "mapped-unwind-metadata-bounds";
        if (code > MAX_MAPPED_SNAPSHOT_BYTES - bytes
                || metadata > MAX_MAPPED_SNAPSHOT_BYTES - bytes - code) return "mapped-unwind-snapshot-limit";
        bytes += code + metadata;
        SourceSnapshot::Function copied{current, std::vector<unsigned char>(code), std::vector<unsigned char>(metadata)};
        if (!image.read(current.BeginAddress, copied.code.data(), code, true)
                || !image.read(current.UnwindData, copied.unwind.data(), metadata)) return "mapped-unwind-snapshot-read";
        if (std::memcmp(header.data(), copied.unwind.data(), header.size())) return "mapped-unwind-header-changed";
        prepared._functions.push_back(std::move(copied));
        if (!(flags & 4)) break;
        if (prepared._functions.size() > MAX_MAPPED_CHAIN) return "mapped-unwind-chain-limit";
        std::memcpy(&current, prepared._functions.back().unwind.data() + padded, sizeof(current));
    }
    for (size_t index = 1; index < prepared._functions.size(); ++index) {
        const auto& parent = prepared._functions[index];
        prepared._chain.push_back({parent.identity.BeginAddress, parent.identity.EndAddress, parent.identity.UnwindData,
            parent.code, parent.unwind});
    }
    result = std::move(prepared);
    return nullptr;
}

const char* snapshotCoverage(HMODULE module, ULONG imageSize, const RUNTIME_FUNCTION& primary, CoverageSnapshot& result) {
    Image image(module, imageSize);
    IMAGE_DATA_DIRECTORY directory{};
    if (auto error = image.headers(directory)) return error;
    if (auto error = image.selected(directory, primary.BeginAddress, primary)) return error;
    if (!directory.Size || directory.Size % sizeof(RUNTIME_FUNCTION)) return "mapped-unwind-exception-directory";
    std::vector<RUNTIME_FUNCTION> rows(directory.Size / sizeof(RUNTIME_FUNCTION));
    if (!image.readCopied(directory.VirtualAddress, rows.data(), directory.Size)) return "mapped-unwind-exception-directory";
    struct Header { unsigned flags; size_t metadata; RUNTIME_FUNCTION parent; };
    auto header = [&](const RUNTIME_FUNCTION& function, Header& parsed) -> const char* {
        if (function.UnwindData & 1) return "indirect-function-entry-unsupported";
        if (function.BeginAddress >= function.EndAddress || (function.UnwindData & 3)) return "mapped-unwind-function-bounds";
        std::array<unsigned char,4> bytes{};
        if (!image.readCopied(function.UnwindData, bytes.data(), bytes.size())) return "mapped-unwind-header-read";
        auto version = bytes[0] & 7;
        parsed.flags = bytes[0] >> 3;
        if (version != 1 && version != 2) return "unsupported-unwind-version";
        if ((parsed.flags & ~7u) || ((parsed.flags & 4) && (parsed.flags & 3))) return "invalid-unwind-flags";
        auto padded = 4 + ((static_cast<size_t>(bytes[2]) + 1) & ~size_t(1)) * 2;
        parsed.metadata = padded + (parsed.flags & 4 ? sizeof(RUNTIME_FUNCTION) : parsed.flags & 3 ? sizeof(ULONG) : 0);
        if ((parsed.flags & 4) && !image.readCopied(function.UnwindData + static_cast<ULONG>(padded),
                &parsed.parent, sizeof(parsed.parent))) return "mapped-unwind-chain-read";
        return nullptr;
    };
    auto same = [](const RUNTIME_FUNCTION& first, const RUNTIME_FUNCTION& second) { return !std::memcmp(&first, &second, sizeof(first)); };
    // Every row is classified: an unresolvable chain could hide a fragment.
    std::vector<RUNTIME_FUNCTION> fragments{primary};
    for (const auto& row : rows) {
        auto current = row;
        Header parsed{};
        for (size_t depth = 0;; ++depth) {
            if (depth > MAX_MAPPED_CHAIN) return "mapped-unwind-chain-limit";
            if (auto error = header(current, parsed)) return error;
            if (!(parsed.flags & 4)) break;
            current = parsed.parent;
        }
        if (same(current, primary) && !same(row, primary)) fragments.push_back(row);
    }
    std::sort(fragments.begin() + 1, fragments.end(),
        [](const RUNTIME_FUNCTION& first, const RUNTIME_FUNCTION& second) { return first.BeginAddress < second.BeginAddress; });
    CoverageSnapshot prepared;
    size_t bytes = 0;
    auto snapshot = [&](const RUNTIME_FUNCTION& function) -> const char* {
        for (const auto& existing : prepared._functions) if (same(existing.identity, function)) return nullptr;
        Header parsed{};
        if (auto error = header(function, parsed)) return error;
        auto code = static_cast<size_t>(function.EndAddress - function.BeginAddress);
        if (!image.section(function.BeginAddress, code, true) || !image.section(function.UnwindData, parsed.metadata, false))
            return "mapped-unwind-function-bounds";
        if (code > MAX_MAPPED_SNAPSHOT_BYTES - bytes || parsed.metadata > MAX_MAPPED_SNAPSHOT_BYTES - bytes - code)
            return "mapped-unwind-snapshot-limit";
        bytes += code + parsed.metadata;
        CoverageSnapshot::Function copied{function, std::vector<unsigned char>(code), std::vector<unsigned char>(parsed.metadata)};
        if (!image.read(function.BeginAddress, copied.code.data(), code, true)
                || !image.read(function.UnwindData, copied.unwind.data(), parsed.metadata)) return "mapped-unwind-snapshot-read";
        prepared._functions.push_back(std::move(copied));
        if (parsed.flags & 3) prepared._handler = true;
        return nullptr;
    };
    for (const auto& fragment : fragments) if (auto error = snapshot(fragment)) return error;
    // Chain parents need not be directory rows; their trailers name them exactly.
    std::vector<std::vector<RUNTIME_FUNCTION>> ancestry(fragments.size());
    for (size_t index = 0; index < fragments.size(); ++index) {
        Header parsed{};
        for (auto current = fragments[index];;) {
            if (auto error = header(current, parsed)) return error;
            if (!(parsed.flags & 4)) break;
            current = parsed.parent;
            ancestry[index].push_back(current);
            if (auto error = snapshot(current)) return error;
        }
    }
    auto find = [&](const RUNTIME_FUNCTION& function) -> const CoverageSnapshot::Function& {
        for (const auto& existing : prepared._functions) if (same(existing.identity, function)) return existing;
        __builtin_unreachable();
    };
    for (size_t index = 0; index < fragments.size(); ++index) {
        std::vector<ChainEntry> chain;
        for (const auto& parent : ancestry[index]) {
            const auto& function = find(parent);
            chain.push_back({parent.BeginAddress, parent.EndAddress, parent.UnwindData, function.code, function.unwind});
        }
        prepared._chains.push_back(std::move(chain));
        prepared._fragments.push_back(static_cast<size_t>(&find(fragments[index]) - prepared._functions.data()));
    }
    result = std::move(prepared);
    return nullptr;
}
}
