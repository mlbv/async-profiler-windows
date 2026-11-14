/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace WindowsProfiler {
std::wstring filePath(std::string_view path);
std::string outputPath(std::string_view path, const char* base);
enum class EnvironmentResult { Value, Missing, Error };
EnvironmentResult environmentValue(std::string_view name, std::string& value);
bool createOutputParents(const char* path);
// 1: same identity, 0: different or absent, -1: inspection failed (errno).
int compareOutputFile(int fd, const char* path);

// Borrows a synchronous binary descriptor's handle. Bind only on the cold path;
// the descriptor owns closure. Writes do not access CRT state or retry.
class CachedOutputHandle {
    void* _handle = nullptr;
public:
    struct WriteResult {
        std::uint32_t bytes;
        bool succeeded;
    };
    void bind(int fd) noexcept;
    WriteResult write(const void* data, std::uint32_t size) const noexcept;
};

// Shared by the command and its saved timer/shutdown arguments.
class OutputFiles {
    bool _reporting = true;
    bool appendJournal(const char* journal, const std::string& line);
public:
    bool report(const char* journal, const char* path);
    bool reportError(const char* journal, const char* message);
};
}
