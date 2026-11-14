/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <stddef.h>
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 32
#define MAP_ANON MAP_ANONYMOUS
#define MAP_FAILED ((void*)-1)
extern "C" int mprotect(void*, size_t, int);
