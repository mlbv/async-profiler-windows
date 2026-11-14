/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsProfiler.h"
#include "windowsOutput.h"
#include "dlfcn.h"
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdarg>
#include <cstdlib>
#include <tlhelp32.h>

namespace WindowsProfiler {
void ioError(DWORD error) {
    _set_doserrno(error);
    switch (error) {
        case ERROR_FILE_NOT_FOUND: case ERROR_PATH_NOT_FOUND: errno = ENOENT; break;
        case ERROR_ACCESS_DENIED: case ERROR_SHARING_VIOLATION: errno = EACCES; break;
        case ERROR_NOT_ENOUGH_MEMORY: case ERROR_OUTOFMEMORY: errno = ENOMEM; break;
        case ERROR_INVALID_HANDLE: errno = EBADF; break;
        case ERROR_DISK_FULL: case ERROR_HANDLE_DISK_FULL: errno = ENOSPC; break;
        case ERROR_BROKEN_PIPE: case ERROR_NO_DATA: errno = EPIPE; break;
        case ERROR_INVALID_PARAMETER: errno = EINVAL; break;
        case ERROR_OPERATION_ABORTED: errno = EINTR; break;
        default: errno = EIO; break;
    }
}
HMODULE selfModule() {
    HMODULE result;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(selfModule), &result);
    return result;
}
}

extern "C" int asprof_open(const char* name, int flags, int mode) {
    auto path = WindowsProfiler::filePath(name);
    if (path.empty()) { errno = EILSEQ; return -1; }
    return _wopen(path.c_str(), flags | _O_BINARY, mode & (_S_IREAD | _S_IWRITE));
}

static ssize_t positionedIO(int fd, void* data, size_t size, off_t offset, bool writing) {
    HANDLE original = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (original == INVALID_HANDLE_VALUE) return -1;
    HANDLE handle = ReOpenFile(original, writing ? GENERIC_WRITE : GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_OVERLAPPED);
    if (handle == INVALID_HANDLE_VALUE) { WindowsProfiler::ioError(GetLastError()); return -1; }
    OVERLAPPED request{};
    request.Offset = static_cast<DWORD>(offset);
    request.OffsetHigh = static_cast<DWORD>(static_cast<std::uint64_t>(offset) >> 32);
    request.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!request.hEvent) { auto error = GetLastError(); CloseHandle(handle); WindowsProfiler::ioError(error); return -1; }
    DWORD count = 0;
    BOOL success = writing ? WriteFile(handle, data, static_cast<DWORD>(size), &count, &request)
                           : ReadFile(handle, data, static_cast<DWORD>(size), &count, &request);
    DWORD error = success ? ERROR_SUCCESS : GetLastError();
    if (!success && error == ERROR_IO_PENDING) {
        success = GetOverlappedResult(handle, &request, &count, TRUE);
        error = success ? ERROR_SUCCESS : GetLastError();
    }
    CloseHandle(request.hEvent);
    CloseHandle(handle);
    if (!success && error != ERROR_HANDLE_EOF) { WindowsProfiler::ioError(error); return -1; }
    return count;
}
extern "C" ssize_t pwrite(int fd, const void* data, size_t size, off_t offset) {
    return positionedIO(fd, const_cast<void*>(data), size, offset, true);
}
extern "C" ssize_t asprof_pread(int fd, void* data, size_t size, off_t offset) {
    return positionedIO(fd, data, size, offset, false);
}

extern "C" void* dlopen(const char* name, int flags) {
    if (!name) return GetModuleHandleW(NULL);
    auto path = WindowsProfiler::wide(name);
    HMODULE module = NULL;
    if (flags & RTLD_NOLOAD) GetModuleHandleExW(0, path.c_str(), &module);
    else module = LoadLibraryW(path.c_str());
    if (module && (flags & RTLD_NODELETE)) {
        HMODULE pinned;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                reinterpret_cast<LPCWSTR>(module), &pinned);
    }
    return module;
}
extern "C" int dlclose(void* module) { return FreeLibrary(static_cast<HMODULE>(module)) ? 0 : -1; }
extern "C" void* dlsym(void* module, const char* name) {
    if (module && module != RTLD_NEXT) return reinterpret_cast<void*>(GetProcAddress(static_cast<HMODULE>(module), name));
    HANDLE snapshot = WindowsProfiler::toolhelpSnapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) return NULL;
    MODULEENTRY32W entry{sizeof(entry)};
    void* result = NULL;
    if (Module32FirstW(snapshot, &entry)) do {
        if ((result = reinterpret_cast<void*>(GetProcAddress(entry.hModule, name))) != NULL) break;
    } while (Module32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    return result;
}
extern "C" int dladdr(const void* address, Dl_info* info) {
    HMODULE module;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(address), &module)) return 0;
    wchar_t path[32768];
    DWORD length = GetModuleFileNameW(module, path, 32768);
    if (!length || length == 32768) return 0;
    static thread_local std::string filename;
    filename = WindowsProfiler::utf8(std::wstring_view(path, length));
    *info = {filename.c_str(), module, NULL, NULL};
    return 1;
}
extern "C" const char* dlerror() {
    static thread_local char message[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, message, sizeof(message), NULL);
    return message;
}

extern "C" int pipe(int* descriptors) { return _pipe(descriptors, 65536, _O_BINARY | _O_NOINHERIT); }
extern "C" int fcntl(int descriptor, int operation, ...) {
    if (operation != F_SETFL) { errno = ENOTSUP; return -1; }
    va_list args; va_start(args, operation); int flags = va_arg(args, int); va_end(args);
    if (flags != O_NONBLOCK) { errno = ENOTSUP; return -1; }
    DWORD mode = PIPE_NOWAIT;
    if (SetNamedPipeHandleState(reinterpret_cast<HANDLE>(_get_osfhandle(descriptor)), &mode, NULL, NULL)) return 0;
    WindowsProfiler::ioError(GetLastError()); return -1;
}
