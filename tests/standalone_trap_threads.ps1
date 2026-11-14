# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
param([string]$OutputDirectory = "$PSScriptRoot\..\build\core\trap-thread-test",
      [string]$JdkHome = 'F:\jdks\graalvm-25.2.4+7.1')
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path
& 'F:\Utils\LLVM\bin\clang++.exe' --target=x86_64-w64-windows-gnu --sysroot=F:/Utils/mingw64-15.2.0 `
    -std=gnu++20 -O2 -g -static -pthread -fms-extensions -ffunction-sections -fdata-sections '-Wl,--gc-sections' '-Wl,--exclude-all-symbols' `
    -D_WIN32_WINNT=0x0A00 -D_LP64=1 -D_FILE_OFFSET_BITS=64 -DNOMINMAX -DWIN32_LEAN_AND_MEAN `
    "-I$repo/core/windows/include" "-I$repo/core/src" "-I$JdkHome/include" "-I$repo/build/core/native/generated" `
    (Join-Path $repo 'tests/native_trap_threads.cpp') (Join-Path $repo 'core/windows/threads_windows.cpp') `
    (Join-Path $repo 'tests/native_trap_thread_stubs.cpp') `
    -o (Join-Path $output 'trap-thread-test.exe')
if ($LASTEXITCODE) { throw "Trap-thread API test build failed: $LASTEXITCODE" }
& (Join-Path $output 'trap-thread-test.exe')
if ($LASTEXITCODE) { throw "Trap-thread API tests failed: $LASTEXITCODE" }
