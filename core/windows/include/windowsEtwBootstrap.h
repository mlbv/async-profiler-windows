/*
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once
#include <windows.h>

namespace WindowsProfiler::Etw::Broker {
int collector(DWORD targetPid, const WCHAR* pipeName, HANDLE bootstrap, HANDLE ready, bool once);
int worker(HANDLE mapping, HANDLE ready, HANDLE bootstrap);
}
