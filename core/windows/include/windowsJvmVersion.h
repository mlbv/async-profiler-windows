/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>
#include <array>
#include <cstring>

namespace WindowsProfiler::JvmVersion {
using Version = std::array<unsigned, 4>;

// Reads VS_FIXEDFILEINFO's file version from a loaded module's version resource.
inline bool fileVersion(HMODULE module, Version& version) {
    // VS_VERSIONINFO: wLength, wValueLength, wType, L"VS_VERSION_INFO", 32-bit padding, VS_FIXEDFILEINFO.
    constexpr wchar_t key[] = L"VS_VERSION_INFO";
    constexpr size_t fixedOffset = (3 * sizeof(WORD) + sizeof(key) + 3) & ~size_t(3);
    auto resource = FindResourceW(module, MAKEINTRESOURCEW(VS_VERSION_INFO), reinterpret_cast<LPCWSTR>(RT_VERSION));
    auto loaded = resource ? LoadResource(module, resource) : nullptr;
    auto data = loaded ? static_cast<const unsigned char*>(LockResource(loaded)) : nullptr;
    if (!data || SizeofResource(module, resource) < fixedOffset + sizeof(VS_FIXEDFILEINFO)) return false;
    WORD valueLength;
    VS_FIXEDFILEINFO fixed;
    std::memcpy(&valueLength, data + sizeof(WORD), sizeof(valueLength));
    std::memcpy(&fixed, data + fixedOffset, sizeof(fixed));
    if (std::memcmp(data + 3 * sizeof(WORD), key, sizeof(key)) != 0 || valueLength != sizeof(fixed)
            || fixed.dwSignature != VS_FFI_SIGNATURE) return false;
    version = {HIWORD(fixed.dwFileVersionMS), LOWORD(fixed.dwFileVersionMS), HIWORD(fixed.dwFileVersionLS), LOWORD(fixed.dwFileVersionLS)};
    return true;
}

enum class Creation { Published, Unpublished, Unknown };

// Whether JNI_GetCreatedJavaVMs returns only completely created VMs: JDK-8308341 is fixed in
// 8u391, 11.0.21, 17.0.9 and 21. Unknown covers layouts that are not a JDK release number.
inline Creation creation(const Version& version) {
    auto [feature, interim, update, patch] = version;
    auto fixedFrom = [](unsigned value, unsigned first) { return value >= first ? Creation::Published : Creation::Unpublished; };
    // JDK 8 numbers jvm.dll 8.0.<update * 10 + n>.<build>; early updates used HotSpot's 25.<update>.<0>.<build>.
    if (feature == 8 && interim == 0) return fixedFrom(update / 10, 391);
    if (feature == 25 && interim != 0) return update == 0 ? fixedFrom(interim, 391) : Creation::Unknown;
    // Later releases use <feature>.0.<update>.<patch>; vendor product numbers have a nonzero second field.
    if (feature < 9 || interim != 0) return Creation::Unknown;
    if (feature == 11) return fixedFrom(update, 21);
    if (feature == 17) return fixedFrom(update, 9);
    return feature >= 21 ? Creation::Published : Creation::Unpublished;
}
}
