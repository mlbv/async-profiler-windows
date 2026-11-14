/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "writer.h"
#include "arguments.h"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <io.h>

namespace {
int closes = 0, closeError = 0, writeError = 0;
void require(bool value, const char* message) {
    if (!value) { std::fprintf(stderr, "%s\n", message); std::exit(1); }
}
struct InspectWriter : FileWriter {
    using FileWriter::FileWriter;
    int error() const { return _err; }
};
}
void Log::writeRaw(LogLevel, const char*, size_t) { std::abort(); }
const char* Arguments::file() { std::abort(); }
int Arguments::openOutputFile(const char*, int) { std::abort(); }
extern "C" int asprof_open(const char* path, int flags, int mode) { return _open(path, flags, mode); }

extern "C" int __wrap_close(int fd) {
    ++closes;
    int result = _close(fd);
    if (closeError) { errno = closeError; return -1; }
    return result;
}
extern "C" ssize_t __wrap_write(int fd, const void* data, size_t size) {
    if (writeError) { errno = writeError; return -1; }
    return _write(fd, data, static_cast<unsigned int>(size));
}
int main(int argc, char** argv) {
    require(argc == 2, "Pass an owned scratch output path");
    auto openFile = [&] {
        int fd = _open(argv[1], _O_CREAT | _O_TRUNC | _O_WRONLY | _O_BINARY, 0600);
        require(fd > 2, "Owned descriptor");
        return fd;
    };
    {
        InspectWriter writer(openFile());
        writer << "final buffer";
        require(writer.finish() && !writer.is_open() && closes == 1, "Finish flushes and closes");
        require(writer.finish() && closes == 1, "Finish is idempotent");
    }
    require(closes == 1, "Destructor does not close twice");
    {
        FILE* file = std::fopen(argv[1], "rb");
        require(file != nullptr, "Open finalized output");
        char bytes[16]{};
        require(std::fread(bytes, 1, sizeof(bytes), file) == 12, "Final buffer reaches output");
        require(std::fclose(file) == 0 && std::strcmp(bytes, "final buffer") == 0, "Finalized output content");
    }
    closeError = EIO;
    {
        InspectWriter writer(openFile());
        writer << "close failure";
        require(!writer.finish() && writer.error() == EIO && !writer.is_open(), "Close error is reported");
    }
    require(closes == 2, "Failed close is not retried");
    writeError = ENOSPC;
    {
        InspectWriter writer(openFile());
        writer << "write failure";
        require(!writer.finish() && writer.error() == ENOSPC, "First write error survives close failure");
    }
    require(closes == 3, "Write failure still closes descriptor");
    closeError = writeError = 0;
    {
        InspectWriter writer(2);
        require(writer.finish() && writer.is_open() && closes == 3, "Borrowed standard descriptor remains open");
    }
    require(_unlink(argv[1]) == 0, "Remove owned fixture");
    std::puts("WRITER_FINISH_OK flush=1 checkedClose=1 firstError=1 singleClose=1 borrowedStandard=1");
}
