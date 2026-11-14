/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _INCBIN_H
#define _INCBIN_H

#ifdef _WIN32
#  define INCBIN_SECTION ".section .rdata, \"dr\""
#  define INCBIN_SYMBOL
#  define INCBIN_RESTORE ".text"
#else
#  define INCBIN_RESTORE ".previous"
#ifdef __APPLE__
#  define INCBIN_SECTION ".const_data"
#  define INCBIN_SYMBOL  "_"
#else
#  define INCBIN_SECTION ".section \".rodata\", \"a\""
#  define INCBIN_SYMBOL
#endif
#endif

#define INCBIN(NAME, FILE) \
    extern "C" const char NAME[];\
    extern "C" const char NAME##_END[];\
    asm(INCBIN_SECTION "\n"\
        ".globl " INCBIN_SYMBOL #NAME "\n"\
        INCBIN_SYMBOL #NAME ":\n"\
        ".incbin \"" FILE "\"\n"\
        ".globl " INCBIN_SYMBOL #NAME "_END\n"\
        INCBIN_SYMBOL #NAME "_END:\n"\
        ".byte 0x00\n"\
        INCBIN_RESTORE "\n"\
    );

#define INCBIN_SIZEOF(NAME) (NAME##_END - NAME)

#ifdef _WIN32
#define INCLUDE_HELPER_CLASS(NAME_VAR, DATA_VAR, NAME) \
    static const char* const NAME_VAR = NAME;\
    INCBIN(DATA_VAR, ASPROF_HELPER_ROOT NAME ".class")
#else
#define INCLUDE_HELPER_CLASS(NAME_VAR, DATA_VAR, NAME) \
    static const char* const NAME_VAR = NAME;\
    INCBIN(DATA_VAR, "src/helper/" NAME ".class")
#endif

#endif // _INCBIN_H
