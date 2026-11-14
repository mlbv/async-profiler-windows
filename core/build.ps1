# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
param(
    [string]$JdkHome = $env:JAVA_HOME,
    [Parameter(Mandatory = $true)][string]$ClangCxx,
    [Parameter(Mandatory = $true)][string]$MingwRoot,
    [switch]$ObjectsOnly
)
$ErrorActionPreference = 'Stop'
if (-not $JdkHome) { $JdkHome = Split-Path (Split-Path (Get-Command javac.exe).Source -Parent) -Parent }
$buildRoot = Join-Path (Split-Path $PSScriptRoot -Parent) 'build\core'
$helpers = Join-Path $buildRoot 'helpers'
$null = New-Item -ItemType Directory -Path $helpers -Force
$helperSources = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src\helper\one\profiler') -Filter '*.java' | Select-Object -ExpandProperty FullName)
& "$JdkHome\bin\javac.exe" -source 8 -target 8 -Xlint:-options -g:none -d $helpers $helperSources
if ($LASTEXITCODE -ne 0) { throw 'Profiler helper compilation failed' }
$native = Join-Path $buildRoot 'native'
& cmake -S $PSScriptRoot -B $native -G Ninja "-DCMAKE_CXX_COMPILER=$ClangCxx" '-DCMAKE_CXX_COMPILER_TARGET=x86_64-w64-windows-gnu' "-DCMAKE_SYSROOT=$MingwRoot" "-DJAVA_HOME=$JdkHome" "-DHELPER_DIR=$helpers"
if ($LASTEXITCODE -ne 0) { throw 'Windows profiler configuration failed' }
$target = if ($ObjectsOnly) { 'asyncProfiler_core' } else { 'asyncProfiler' }
& cmake --build $native --target $target --parallel
if ($LASTEXITCODE -ne 0) { throw 'Windows profiler compilation failed' }
