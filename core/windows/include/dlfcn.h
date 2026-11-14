/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#define RTLD_DEFAULT ((void*)0)
#define RTLD_NEXT ((void*)-1)
#define RTLD_LAZY 1
#define RTLD_NOW 2
#define RTLD_NOLOAD 4
#define RTLD_NODELETE 8
#define RTLD_GLOBAL 16
#define RTLD_LOCAL 0
struct Dl_info { const char* dli_fname; void* dli_fbase; const char* dli_sname; void* dli_saddr; };
extern "C" void* dlopen(const char*, int);
extern "C" int dlclose(void*);
extern "C" void* dlsym(void*, const char*);
extern "C" int dladdr(const void*, Dl_info*);
extern "C" const char* dlerror();
