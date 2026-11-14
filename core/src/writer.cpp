/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "writer.h"
#ifdef _WIN32
#include "arguments.h"
#endif


Writer& Writer::operator<<(char c) {
    write(&c, 1);
    return *this;
}

Writer& Writer::operator<<(const char* s) {
    write(s, strlen(s));
    return *this;
}

Writer& Writer::operator<<(int n) {
    char buf[16];
    write(buf, snprintf(buf, sizeof(buf), "%d", n));
    return *this;
}

Writer& Writer::operator<<(long n) {
    char buf[24];
    write(buf, snprintf(buf, sizeof(buf), "%ld", n));
    return *this;
}

#ifdef _WIN32
Writer& Writer::operator<<(long long n) {
    char buf[24];
    write(buf, snprintf(buf, sizeof(buf), "%lld", n));
    return *this;
}
#endif

Writer& Writer::operator<<(u64 n) {
    char buf[24];
    write(buf, snprintf(buf, sizeof(buf), "%llu", n));
    return *this;
}

void Writer::move(char* data, size_t len) {
    write(data, len);
    free(data);
}

FileWriter::FileWriter(const char* file_name) : _size(0) {
#ifdef _WIN32
    _fd = asprof_open(file_name, O_WRONLY | O_TRUNC | O_CREAT, 0644);
#else
    _fd = open(file_name, O_WRONLY | O_TRUNC | O_CREAT, 0644);
#endif
    _buf = (char*)malloc(BUF_SIZE);
}

FileWriter::FileWriter(int fd) : _fd(fd), _size(0) {
    _buf = (char*)malloc(BUF_SIZE);
}

#ifdef _WIN32
FileWriter::FileWriter(Arguments& args) : FileWriter(args.openOutputFile(args.file(), O_WRONLY | O_TRUNC | O_CREAT)) {
}
#endif

FileWriter::~FileWriter() {
    finish();
    free(_buf);
}

bool FileWriter::finish() {
    flush(_buf, _size);
    _size = 0;
    if (_fd > STDERR_FILENO) {
        int fd = _fd;
        _fd = -1;
        if (close(fd) != 0 && _err == 0) _err = errno;
    }
    return good();
}

void FileWriter::flush(const char* data, size_t len) {
    if (_err != 0) return;
    while (len > 0) {
        ssize_t bytes = ::write(_fd, data, len);
        if (bytes <= 0) {
            _err = bytes < 0 ? errno : EIO;
            break;
        }
        data += bytes;
        len -= (size_t)bytes;
    }
}

void FileWriter::write(const char* data, size_t len) {
    if (_err != 0) return;
    if (_size + len > BUF_SIZE) {
        flush(_buf, _size);
        _size = 0;
        if (len > BUF_SIZE) {
            flush(data, len);
            return;
        }
    }
    memcpy(_buf + _size, data, len);
    _size += len;
}

BufferWriter::~BufferWriter() {
    free(_buf);
}

void BufferWriter::write(const char* data, size_t len) {
    size_t new_size = _size + len;
    if (new_size > _capacity) {
        _capacity = new_size >= _capacity * 2 ? new_size : _capacity * 2;
        _buf = (char*)realloc(_buf, _capacity);
    }
    memcpy(_buf + _size, data, len);
    _size = new_size;
}

void BufferWriter::move(char* data, size_t len) {
    if (_size == 0) {
        free(_buf);
        _buf = data;
        _size = len;
        _capacity = len;
    } else {
        Writer::move(data, len);
    }
}

void CallbackWriter::write(const char* data, size_t len) {
    if (_output_callback != nullptr) {
        _output_callback(data, len);
    }
}

void LogWriter::write(const char* data, size_t len) {
    Log::writeRaw(_logLevel, data, len);
}
