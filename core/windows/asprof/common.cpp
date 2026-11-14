/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "asprof.h"
#include <shlobj.h>

namespace Asprof {
std::wstring wide(std::string_view text, UINT codePage) {
    if (text.empty()) return {};
    auto length = MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    std::wstring result(length, L'\0');
    MultiByteToWideChar(codePage, 0, text.data(), static_cast<int>(text.size()), result.data(), length);
    return result;
}

std::string utf8(std::wstring_view text) {
    if (text.empty()) return {};
    auto length = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    std::string result(length, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), length, nullptr, nullptr);
    return result;
}

std::string ansi(std::string_view text) {
    if (GetACP() == CP_UTF8) return std::string(text);
    auto unicode = wide(text);
    if (unicode.empty()) return {};
    BOOL lossy = FALSE;
    auto length = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, unicode.data(), static_cast<int>(unicode.size()), nullptr, 0, nullptr, &lossy);
    if (lossy) fail("The system code page cannot represent: " + std::string(text));
    std::string result(length, '\0');
    WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS, unicode.data(), static_cast<int>(unicode.size()), result.data(), length, nullptr, nullptr);
    return result;
}

std::string windowsError(DWORD error) {
    return "Windows error " + std::to_string(error);
}

void fail(std::string message, int code) {
    throw Failure{std::move(message), code};
}

namespace {
void write(DWORD stream, std::string_view text) {
    auto handle = GetStdHandle(stream);
    for (DWORD written = 0; !text.empty(); text.remove_prefix(written)) {
        if (!WriteFile(handle, text.data(), static_cast<DWORD>(text.size()), &written, nullptr)) return;
    }
}
}

void writeOut(std::string_view text) { write(STD_OUTPUT_HANDLE, text); }
void writeErr(std::string_view text) { write(STD_ERROR_HANDLE, text); }

std::wstring temporaryDirectory() {
    WCHAR path[MAX_PATH + 1];
    auto length = GetTempPathW(MAX_PATH + 1, path);
    return std::wstring(path, length);
}

std::wstring absolutePath(const std::wstring& path) {
    auto size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    std::wstring result(size, L'\0');
    result.resize(GetFullPathNameW(path.c_str(), size, result.data(), nullptr));
    return result;
}

void createParents(const std::wstring& path) {
    auto directory = path.substr(0, path.find_last_of(L"\\/"));
    auto error = SHCreateDirectoryExW(nullptr, directory.c_str(), nullptr);
    if (error != ERROR_SUCCESS && error != ERROR_ALREADY_EXISTS) fail("Cannot create " + utf8(directory) + ": " + windowsError(error));
}

// Quotes each argument so that CommandLineToArgvW and the C runtime recover it unchanged.
std::wstring commandLine(const std::vector<std::wstring>& arguments) {
    std::wstring result;
    for (const auto& argument : arguments) {
        if (!result.empty()) result += L' ';
        if (!argument.empty() && argument.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
            result += argument;
            continue;
        }
        result += L'"';
        size_t backslashes = 0;
        for (auto c : argument) {
            if (c == L'\\') {
                ++backslashes;
                continue;
            }
            result.append(c == L'"' ? backslashes * 2 + 1 : backslashes, L'\\');
            backslashes = 0;
            result += c;
        }
        result.append(backslashes * 2, L'\\');
        result += L'"';
    }
    return result;
}
}
