/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "asprof.h"

namespace Asprof {
namespace {
std::uint64_t bigEndian(const unsigned char* bytes, int size) {
    std::uint64_t value = 0;
    for (int i = 0; i < size; ++i) value = (value << 8) | bytes[i];
    return value;
}

std::string currentDirectory() {
    std::wstring path(GetCurrentDirectoryW(0, nullptr), L'\0');
    path.resize(GetCurrentDirectoryW(static_cast<DWORD>(path.size()), path.data()));
    return utf8(path);
}
}

// Every chunk of a finalized JFR file has a complete header and metadata inside the chunk.
void validateJfr(const std::wstring& path) {
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    LARGE_INTEGER size;
    if (!file || !GetFileSizeEx(file.value, &size)) fail("Cannot read " + utf8(path) + ": " + windowsError(GetLastError()));
    std::uint64_t position = 0, total = size.QuadPart;
    while (position < total) {
        unsigned char header[68];
        LARGE_INTEGER at;
        at.QuadPart = static_cast<LONGLONG>(position);
        DWORD read = 0;
        if (!SetFilePointerEx(file.value, at, nullptr, FILE_BEGIN) || !ReadFile(file.value, header, sizeof(header), &read, nullptr) || read != sizeof(header)) {
            fail("Incomplete JFR chunk header: " + utf8(path));
        }
        auto chunk = bigEndian(header + 8, 8), metadata = bigEndian(header + 24, 8);
        if (bigEndian(header, 4) != 0x464c5200) fail("Invalid JFR chunk magic: " + utf8(path));
        if (chunk < 68 || chunk > total - position || metadata < 68 || metadata >= chunk) {
            fail("Incomplete JFR recording; the target may have crashed or been killed: " + utf8(path));
        }
        position += chunk;
    }
    if (position == 0) fail("No finalized JFR chunks: " + utf8(path));
}

OutputFiles::OutputFiles() {
    WCHAR path[MAX_PATH];
    if (!GetTempFileNameW(temporaryDirectory().c_str(), L"apo", 0, path)) fail("Cannot create a temporary file: " + windowsError(GetLastError()));
    _journal = path;
}

OutputFiles::~OutputFiles() {
    DeleteFileW(_journal.c_str());
}

// Relative paths resolve against this command's directory after target-side expansion.
std::string OutputFiles::base() {
    return ",filebase=" + Options::value(currentDirectory());
}

std::string OutputFiles::options(bool local) const {
    return (local ? base() : "") + ",fileresult=" + Options::value(utf8(_journal));
}

std::vector<std::wstring> OutputFiles::files() const {
    Handle file(CreateFileW(_journal.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr));
    LARGE_INTEGER size;
    if (!file || !GetFileSizeEx(file.value, &size)) fail("Cannot read the output journal: " + windowsError(GetLastError()));
    std::string data(static_cast<size_t>(size.QuadPart), '\0');
    DWORD read = 0;
    if (!ReadFile(file.value, data.data(), static_cast<DWORD>(data.size()), &read, nullptr) || read != data.size()) {
        fail("Cannot read the output journal: " + windowsError(GetLastError()));
    }
    std::vector<std::wstring> files;
    for (size_t start = 0; start < data.size();) {
        auto end = data.find('\n', start);
        if (end == std::string::npos) end = data.size();
        auto line = data.substr(start, end - start);
        start = end + 1;
        if (line.compare(0, 7, "!ERROR\t") == 0) fail("Profiler output failed: " + line.substr(7));
        if (line.find_first_not_of(" \t\r") == std::string::npos) fail("Profiler reported an empty output filename");
        auto path = wide(line);
        if (path.size() < 3 || ((path[1] != L':' || path[2] != L'\\') && path.compare(0, 2, L"\\\\") != 0)) {
            fail("Profiler reported a relative output filename: " + line);
        }
        bool known = false;
        for (const auto& f : files) known |= _wcsicmp(f.c_str(), path.c_str()) == 0;
        if (!known) files.push_back(path);
    }
    return files;
}

std::wstring OutputFiles::single() const {
    auto list = files();
    if (list.size() != 1) fail("Profiler did not resolve exactly one output filename");
    return list.front();
}

void OutputFiles::verify(bool jfr) const {
    auto list = files();
    if (list.empty()) fail("Profiler reported no output");
    for (const auto& file : list) {
        WIN32_FILE_ATTRIBUTE_DATA attributes;
        if (!GetFileAttributesExW(file.c_str(), GetFileExInfoStandard, &attributes) || (attributes.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                || (attributes.nFileSizeHigh == 0 && attributes.nFileSizeLow == 0)) fail("Profiler produced no output: " + utf8(file));
        if (jfr) validateJfr(file);
    }
}
}
