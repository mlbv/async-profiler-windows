/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
struct utsname { char sysname[256]; char nodename[256]; char release[256]; char version[256]; char machine[256]; };
extern "C" int uname(utsname*);
