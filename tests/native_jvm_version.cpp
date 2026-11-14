/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// jvm-version-test [JVM_DLL=A.B.C.D ...]: classifies jvm.dll file versions and reads real version resources.
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include "windowsJvmVersion.h"

using namespace WindowsProfiler::JvmVersion;

static void require(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "%s\n", message);
        std::exit(1);
    }
}

int wmain(int argc, wchar_t** argv) {
    struct Case { Version version; Creation expected; };
    constexpr Case cases[] = {
        {{8, 0, 4710, 9}, Creation::Published},     // GraalVM EE 8u471
        {{8, 0, 5040, 1}, Creation::Published},     // Temurin 8u504
        {{8, 0, 3910, 13}, Creation::Published},    // 8u391, the first fixed update
        {{8, 0, 3820, 5}, Creation::Unpublished},   // 8u382
        {{8, 0, 2020, 8}, Creation::Unpublished},   // Oracle 8u202
        {{25, 51, 0, 3}, Creation::Unpublished},    // 8u51 with HotSpot 25.51 numbering
        {{25, 51, 1, 3}, Creation::Unknown},
        {{8, 1, 4710, 9}, Creation::Unknown},
        {{7, 0, 800, 15}, Creation::Unknown},
        {{9, 0, 4, 0}, Creation::Unpublished},
        {{11, 0, 20, 0}, Creation::Unpublished},
        {{11, 0, 21, 0}, Creation::Published},
        {{11, 0, 26, 0}, Creation::Published},      // Azul file version "11.0.26"
        {{11, 45, 27, 0}, Creation::Unknown},       // vendor product number
        {{13, 28, 0, 11}, Creation::Unknown},       // Azul Zulu "13.28+11"
        {{16, 0, 2, 0}, Creation::Unpublished},
        {{17, 0, 8, 0}, Creation::Unpublished},
        {{17, 0, 9, 0}, Creation::Published},
        {{17, 0, 3, 1}, Creation::Unpublished},
        {{20, 0, 2, 0}, Creation::Unpublished},
        {{21, 0, 1, 0}, Creation::Published},
        {{25, 0, 0, 0}, Creation::Published},
        {{26, 0, 2, 1}, Creation::Published},
        {{27, 0, 1, 0}, Creation::Published},
    };
    for (const auto& item : cases) {
        if (creation(item.version) != item.expected) {
            std::fprintf(stderr, "Wrong classification of %u.%u.%u.%u\n", item.version[0], item.version[1], item.version[2], item.version[3]);
            return 1;
        }
    }
    for (int i = 1; i < argc; ++i) {
        auto separator = std::wcsrchr(argv[i], L'=');
        require(separator != nullptr, "Arguments are JVM_DLL=A.B.C.D");
        *separator = 0;
        Version expected;
        require(std::swscanf(separator + 1, L"%u.%u.%u.%u", &expected[0], &expected[1], &expected[2], &expected[3]) == 4, "Malformed expected version");
        auto module = LoadLibraryExW(argv[i], nullptr, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
        require(module != nullptr, "Cannot map jvm.dll");
        Version actual;
        require(fileVersion(module, actual) && actual == expected, "Wrong jvm.dll file version");
        FreeLibrary(module);
    }
    Version none;
    require(!fileVersion(GetModuleHandleW(nullptr), none), "The test executable has no version resource");
    std::printf("JVM_VERSION_OK cases=%zu files=%d\n", sizeof(cases) / sizeof(cases[0]), argc - 1);
    return 0;
}
