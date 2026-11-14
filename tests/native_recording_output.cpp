/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "platform.h"
#include "windowsOutput.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <io.h>

namespace {
unsigned checks = 0, writes = 0;
void require(bool value,const char* message) {
    ++checks;
    if (!value) { std::fprintf(stderr,"RECORDING_OUTPUT_FAILURE %s Windows=%lu\n",message,GetLastError()); std::exit(1); }
}
using NativeWrite = decltype(&WriteFile);
NativeWrite nativeWrite;
enum class Mode { Real, Short, FailedPartial };
Mode mode = Mode::Real;
BOOL WINAPI writeOnce(HANDLE handle,LPCVOID data,DWORD size,LPDWORD count,LPOVERLAPPED request) {
    ++writes;
    auto amount = mode == Mode::Real ? size : size / 2;
    auto result = nativeWrite(handle,data,amount,count,request);
    if (result && mode == Mode::FailedPartial) { SetLastError(ERROR_WRITE_FAULT); return FALSE; }
    return result;
}
struct Errors {
    int crt = EDOM;
    unsigned long dos = 0x13572468;
    void set() const { _set_errno(crt); _set_doserrno(dos); }
    void unchanged() const {
        int actual;
        unsigned long actualDos;
        require(_get_errno(&actual) == 0 && _get_doserrno(&actualDos) == 0 && actual == crt && actualDos == dos,
                "Native output changed CRT errno or doserrno");
    }
};
struct File {
    wchar_t path[MAX_PATH]{};
    int fd;
    HANDLE locker;
    WindowsProfiler::CachedOutputHandle output;
    explicit File(bool temporary = false) {
        wchar_t directory[MAX_PATH];
        require(GetTempPathW(MAX_PATH,directory) && GetTempFileNameW(directory,L"rco",0,path),"Cannot create owned output path");
        auto handle = CreateFileW(path,GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,temporary ? FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE : FILE_ATTRIBUTE_NORMAL,nullptr);
        require(handle != INVALID_HANDLE_VALUE,"Cannot open owned native output");
        locker = CreateFileW(path,GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        require(locker != INVALID_HANDLE_VALUE,"Cannot open independent range-lock handle");
        fd = _open_osfhandle(reinterpret_cast<intptr_t>(handle),_O_BINARY | _O_RDWR);
        require(fd >= 0,"Cannot transfer native output to descriptor owner");
        output.bind(fd);
    }
    ~File() {
        require(_close(fd) == 0,"Descriptor owner did not close output");
        require(CloseHandle(locker),"Cannot close independent lock handle");
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) require(DeleteFileW(path),"Cannot remove owned output");
    }
};
}

// Unrelated output-path and reporting entry points must not run in this fixture.
namespace WindowsProfiler {
std::wstring wide(std::string_view) { std::abort(); }
std::string utf8(std::wstring_view) { std::abort(); }
void ioError(DWORD) { std::abort(); }
}
extern "C" int asprof_open(const char*,int,int) { std::abort(); }

extern "C" {
NativeWrite __wrap___imp_WriteFile = writeOnce;
}

int main() {
    nativeWrite = reinterpret_cast<NativeWrite>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"),"WriteFile"));
    require(nativeWrite != nullptr,"Cannot bind native write oracle");
    Errors errors;
    {
        File file;
        errors.set();
        auto result = file.output.write("header",6);
        errors.unchanged();
        require(result.succeeded && result.bytes == 6 && writes == 1,"Valid output was not one complete native write");
        require(_lseeki64(file.fd,0,SEEK_CUR) == 6,"Native write did not advance descriptor file position");
        require(_write(file.fd,":",1) == 1,"Cannot append fixture separator through descriptor");
        errors.set();
        result = file.output.write("body",4);
        errors.unchanged();
        require(result.succeeded && result.bytes == 4 && _lseeki64(file.fd,0,SEEK_CUR) == 11,
                "Native and descriptor writes did not share file position");
        require(_lseeki64(file.fd,0,SEEK_SET) == 0,"Cannot seek output to locked region");
        OVERLAPPED lock{};
        require(LockFileEx(file.locker,LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,0,64,0,&lock),
                "Cannot lock JFR-output byte range");
        errors.set();
        auto before = writes;
        result = file.output.write("blocked",7);
        auto nativeError = GetLastError();
        errors.unchanged();
        require(!result.succeeded && result.bytes == 0 && writes == before + 1 && nativeError == ERROR_LOCK_VIOLATION,
                "Range-lock failure was hidden or retried");
        require(_lseeki64(file.fd,0,SEEK_CUR) == 0,"Failed write advanced output file position");
        require(UnlockFileEx(file.locker,0,64,0,&lock),"Cannot release owned byte-range lock");
        errors.set();
        result = file.output.write("next",4);
        errors.unchanged();
        require(result.succeeded && result.bytes == 4,"Valid output did not recover after lock release");

        mode = Mode::Short;
        before = writes;
        errors.set();
        result = file.output.write("12345678",8);
        errors.unchanged();
        require(result.succeeded && result.bytes == 4 && writes == before + 1,
                "Successful partial byte count was changed or retried");
        mode = Mode::FailedPartial;
        before = writes;
        errors.set();
        result = file.output.write("ABCDEFGH",8);
        errors.unchanged();
        require(!result.succeeded && result.bytes == 4 && writes == before + 1,
                "Failed partial byte count was lost or retried");
        mode = Mode::Real;
        require(_lseeki64(file.fd,0,SEEK_CUR) == 12,"Partial native writes did not advance shared file position");

        require(_lseeki64(file.fd,0,SEEK_SET) == 0,"Cannot rewind completed fixture");
        char bytes[16]{};
        require(_read(file.fd,bytes,sizeof(bytes)) == 12 && std::memcmp(bytes,"next1234ABCD",12) == 0,
                "Native output content disagrees with returned byte counts");
    }
    {
        File memory(true);
        errors.set();
        auto result = memory.output.write("chunk-one",9);
        errors.unchanged();
        require(result.succeeded && result.bytes == 9,"In-memory output write failed");
        require(_chsize_s(memory.fd,0) == 0 && _lseeki64(memory.fd,0,SEEK_SET) == 0,"Cannot reset in-memory chunk fixture");
        errors.set();
        result = memory.output.write("two",3);
        errors.unchanged();
        require(result.succeeded && result.bytes == 3 && _lseeki64(memory.fd,0,SEEK_CUR) == 3,
                "Cached in-memory handle did not survive truncation and rewind");
    }
    std::printf("RECORDING_OUTPUT_OK checks=%u nativeWrites=%u errno=1 doserrno=1 lockedWrite=1 partialCounts=1 borrowedHandle=1 memoryReuse=1\n",
        checks,writes);
    return 0;
}
