/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windowsProfiler.h"

namespace WindowsProfiler {
std::wstring wide(std::string_view value) {
    if (value.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), NULL, 0);
    if (size == 0) return {};
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}
std::string utf8(std::wstring_view value) {
    if (value.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), NULL, 0, NULL, NULL);
    if (size == 0) return {};
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), size, NULL, NULL);
    return result;
}
std::string modifiedUtf8(std::string_view value) {
    std::wstring wide;
    auto bytes = reinterpret_cast<const unsigned char*>(value.data());
    for (size_t i = 0; i < value.size();) {
        unsigned cp;
        if (bytes[i] < 0x80) cp = bytes[i++];
        else if ((bytes[i] & 0xe0) == 0xc0 && i + 1 < value.size() && (bytes[i + 1] & 0xc0) == 0x80) {
            cp = ((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f); i += 2;
            if (cp < 0x80 && cp != 0) return {};
        } else if ((bytes[i] & 0xf0) == 0xe0 && i + 2 < value.size()
                && (bytes[i + 1] & 0xc0) == 0x80 && (bytes[i + 2] & 0xc0) == 0x80) {
            cp = ((bytes[i] & 15) << 12) | ((bytes[i + 1] & 63) << 6) | (bytes[i + 2] & 63); i += 3;
            if (cp < 0x800) return {};
        } else return {};
        wide.push_back(static_cast<WCHAR>(cp));
    }
    return utf8(wide);
}
}
