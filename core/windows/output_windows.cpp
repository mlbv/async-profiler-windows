/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsProfiler.h"
#include "windowsOutput.h"
#include <algorithm>
#include <cerrno>
#include <io.h>
#include <winternl.h>

namespace WindowsProfiler {
static std::wstring fullPath(std::wstring path, const char* base) {
    if (path.empty()) return {};
    std::replace(path.begin(), path.end(), L'/', L'\\');
    bool drive = path.size() >= 3 && path[1] == L':' && path[2] == L'\\';
    bool unc = path.size() >= 2 && path[0] == L'\\' && path[1] == L'\\';
    if (!drive && !unc && base != nullptr) {
        auto directory = wide(base);
        std::replace(directory.begin(), directory.end(), L'/', L'\\');
        // Root-relative paths use the caller's drive, not the target JVM's.
        if (!path.empty() && path[0] == L'\\' && directory.size() >= 2 && directory[1] == L':') {
            path = directory.substr(0, 2) + path;
        } else {
            if (!directory.empty() && directory.back() != L'\\') directory += L'\\';
            path = directory + path;
        }
    }
    DWORD size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (size == 0) return {};
    std::wstring result(size, L'\0');
    DWORD count = GetFullPathNameW(path.c_str(), size, result.data(), nullptr);
    if (count == 0 || count >= size) return {};
    result.resize(count);
    return result;
}

std::wstring filePath(std::string_view path) {
    auto result = fullPath(wide(path), nullptr);
    if (result.rfind(L"\\\\?\\", 0) == 0 || result.rfind(L"\\\\.\\", 0) == 0) return result;
    if (result.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + result.substr(2);
    return result.empty() ? result : L"\\\\?\\" + result;
}

std::string outputPath(std::string_view path, const char* base) {
    return utf8(fullPath(wide(path), base));
}

EnvironmentResult environmentValue(std::string_view name, std::string& value) {
    value.clear();
    auto key = wide(name);
    if (key.empty()) { errno = EILSEQ; return EnvironmentResult::Error; }
    // A single read avoids the size-query/read race. Windows user-defined
    // environment values contain at most 32,767 UTF-16 characters.
    std::wstring result(32768, L'\0');
    SetLastError(ERROR_SUCCESS);
    DWORD count = GetEnvironmentVariableW(key.c_str(), result.data(), static_cast<DWORD>(result.size()));
    DWORD error = GetLastError();
    if (count == 0 && error == ERROR_ENVVAR_NOT_FOUND) return EnvironmentResult::Missing;
    if (count == 0 && error != ERROR_SUCCESS) { ioError(error); return EnvironmentResult::Error; }
    if (count >= result.size()) { errno = ERANGE; return EnvironmentResult::Error; }
    result.resize(count);
    value = utf8(result);
    if (count != 0 && value.empty()) { errno = EILSEQ; return EnvironmentResult::Error; }
    return EnvironmentResult::Value;
}

static bool createDirectoryTree(const std::wstring& path) {
    // GetFileAttributes does not describe a share itself. Its child creation
    // or final file open reports an unavailable share without creating it.
    size_t root;
    if (_wcsnicmp(path.c_str(), L"\\\\?\\UNC\\", 8) == 0) {
        auto server = path.find(L'\\', 8);
        root = server == std::wstring::npos ? server : path.find(L'\\', server + 1);
        if (root == std::wstring::npos) return true;
    } else {
        root = path.find(L'\\', 4);
        if (root == std::wstring::npos) { errno = EINVAL; return false; }
    }
    size_t end = root;
    while (end < path.size()) {
        end = path.find(L'\\', end + 1);
        if (end == std::wstring::npos) end = path.size();
        auto directory = path.substr(0, end);
        DWORD attributes = GetFileAttributesW(directory.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES) {
            if (attributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            errno = ENOTDIR;
            return false;
        }
        DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) { ioError(error); return false; }
        if (CreateDirectoryW(directory.c_str(), nullptr)) continue;
        error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS) {
            attributes = GetFileAttributesW(directory.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            errno = ENOTDIR;
            return false;
        }
        ioError(error);
        return false;
    }
    return true;
}

bool createOutputParents(const char* path) {
    auto filename = filePath(path);
    auto separator = filename.find_last_of(L'\\');
    if (separator == std::wstring::npos) { errno = EINVAL; return false; }
    // Keep the trailing slash for a drive root (\\?\C:\).
    return createDirectoryTree(filename.substr(0, separator == 6 ? separator + 1 : separator));
}

static bool fileIdentity(HANDLE handle, std::uint32_t& volume, std::uint64_t& index) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle, &info)) { ioError(GetLastError()); return false; }
    volume = info.dwVolumeSerialNumber;
    index = (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    return true;
}

// A device such as NUL has no file index; its kernel object name identifies it.
static bool deviceName(HANDLE handle, std::wstring& name) {
    alignas(UNICODE_STRING) unsigned char buffer[sizeof(UNICODE_STRING) + 1024];
    NTSTATUS status = NtQueryObject(handle, ObjectNameInformation, buffer, sizeof(buffer), nullptr);
    if (status < 0) { ioError(RtlNtStatusToDosError(status)); return false; }
    auto object = reinterpret_cast<UNICODE_STRING*>(buffer);
    name.assign(object->Buffer, object->Length / sizeof(wchar_t));
    return true;
}

int compareOutputFile(int fd, const char* path) {
    auto original = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (original == INVALID_HANDLE_VALUE) { errno = EBADF; return -1; }
    bool device = GetFileType(original) != FILE_TYPE_DISK;
    std::wstring original_device;
    std::uint32_t original_volume;
    std::uint64_t original_index;
    if (device ? !deviceName(original, original_device) : !fileIdentity(original, original_volume, original_index)) return -1;
    auto filename = filePath(path);
    if (filename.empty()) { errno = EILSEQ; return -1; }
    HANDLE handle = CreateFileW(filename.c_str(), FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) return 0;
        ioError(error);
        return -1;
    }
    bool inspected = true, same = false;
    if (device == (GetFileType(handle) != FILE_TYPE_DISK)) {
        std::wstring name;
        std::uint32_t volume;
        std::uint64_t index;
        inspected = device ? deviceName(handle, name) : fileIdentity(handle, volume, index);
        same = inspected && (device ? original_device == name : original_volume == volume && original_index == index);
    }
    CloseHandle(handle);
    return inspected ? same : -1;
}

void CachedOutputHandle::bind(int fd) noexcept {
    _handle = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
}

CachedOutputHandle::WriteResult CachedOutputHandle::write(const void* data, std::uint32_t size) const noexcept {
    DWORD written = 0;
    bool succeeded = WriteFile(_handle, data, size, &written, nullptr) != FALSE;
    return {written, succeeded};
}

bool OutputFiles::report(const char* journal, const char* path) {
    return appendJournal(journal, outputPath(path, nullptr) + '\n');
}

bool OutputFiles::reportError(const char* journal, const char* message) {
    return appendJournal(journal, std::string("!ERROR\t") + message + '\n');
}

bool OutputFiles::appendJournal(const char* journal, const std::string& line) {
    if (journal == nullptr || !_reporting) return true;
    auto filename = filePath(journal);
    HANDLE handle = CreateFileW(filename.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) { _reporting = false; return true; }
        ioError(error); return false;
    }
    DWORD written = 0;
    bool success = WriteFile(handle, line.data(), static_cast<DWORD>(line.size()), &written, nullptr)
            && written == line.size();
    DWORD error = success ? ERROR_SUCCESS : GetLastError();
    CloseHandle(handle);
    if (!success) ioError(error == ERROR_SUCCESS ? ERROR_WRITE_FAULT : error);
    return success;
}
}
