/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
// JNI has the same 32-bit jint ABI on Windows; use C++ int for portable sources.
#pragma once
#define JNIEXPORT __declspec(dllexport)
#define JNIIMPORT __declspec(dllimport)
#define JNICALL
typedef int jint;
typedef long long jlong;
typedef signed char jbyte;
