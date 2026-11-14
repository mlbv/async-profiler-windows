# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
param([Parameter(Mandatory = $true)][string]$JdkHome, [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [switch]$ProcessFixture, [switch]$StandaloneFixture, [switch]$SoftwareFixture, [switch]$ProfileShareFixture, [switch]$TracepointFixture, [switch]$SoftwareReturnFixture, [switch]$PreloadApplication, [switch]$NonjavaApplication, [switch]$AttachAgent,
    [ValidateSet('interposer', 'calls-malloc', 'dependent', 'fail')][string]$PreloadLibrary, [string]$LinkLibrary, [switch]$DebugSymbols, [switch]$DebugRuntime, [ValidateSet('x64', 'x86')][string]$Architecture = 'x64',
    [ValidateRange(0, 2)][int]$ReloadVersion = 0,
    [ValidateSet('forwarder', 'custom', 'custom-errno')][string]$AllocatorProvider,
    [ValidatePattern('^0x[0-9a-fA-F]{1,16}$')][string]$PreferredImageBase = '0x500000000000')
$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'MSVC x64 build tools are required for the CRT fixture.' }
$vcvarsName = if ($Architecture -eq 'x86') { 'vcvars32.bat' } else { 'vcvars64.bat' }
$vcvars = Join-Path $installation ('VC\Auxiliary\Build\' + $vcvarsName)
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$response = Join-Path $OutputDirectory 'fixture.rsp'
$source = if ($ProcessFixture) { 'process_fixture.cpp' } else { 'native_memory_fixture.cpp' }
$output = if ($ProcessFixture) { 'processFixture.exe' } else { 'nativeMemoryFixture.dll' }
if ($ReloadVersion) { $source = 'reload_target.cpp'; $output = 'reloadTarget.dll' }
if ($StandaloneFixture) { $source = 'native_api_application.cpp'; $output = 'nativeApiApplication.exe' }
if ($SoftwareFixture) { $source = 'native_software_application.cpp'; $output = 'nativeSoftwareApplication.exe' }
if ($ProfileShareFixture) { $source = 'native_profile_share_application.cpp'; $output = 'nativeProfileShareApplication.exe' }
if ($AllocatorProvider) { $source = 'allocator_provider.cpp'; $output = 'allocator-' + $AllocatorProvider + '.dll' }
if ($TracepointFixture) { $source = 'native_tracepoint_fixture.cpp'; $output = 'nativeTracepointFixture.dll' }
if ($PreloadApplication) { $source = 'native_preload_application.cpp'; $output = 'nativePreloadApplication.exe' }
if ($NonjavaApplication) { $source = 'native_nonjava_application.cpp'; $output = 'nativeNonjavaApplication.exe' }
if ($PreloadLibrary) { $source = 'native_preload_library.cpp'; $output = 'preload-' + $PreloadLibrary + '.dll' }
if ($SoftwareReturnFixture) { $source = 'native_software_return_msvc.cpp'; $output = 'softwareReturnMsvc.dll' }
if ($AttachAgent) { $source = 'native_attach_agent.cpp'; $output = 'attachAgent.dll' }
$optimization = if ($ProcessFixture -or $SoftwareReturnFixture) { '/O2' } else { '/Od' }
$runtime = if ($DebugRuntime) { '/MDd' } else { '/MD' }
if ($AllocatorProvider -like 'custom*') { $runtime = '/MT' }
$flags = @('/nologo', '/std:c++20', $optimization, $runtime, '/EHsc', '/W4', '/WX',
    ('/I"' + (Join-Path $JdkHome 'include') + '"'), ('/I"' + (Join-Path $JdkHome 'include\win32') + '"'),
    ('/Fo"' + (Join-Path $OutputDirectory 'fixture.obj') + '"'),
    ('/Fe"' + (Join-Path $OutputDirectory $output) + '"'),
    ('"' + (Join-Path $PSScriptRoot $source) + '"'))
if ($DebugSymbols) { $flags += '/Z7' }
if ($AllocatorProvider -eq 'forwarder') { $flags += '/DPROVIDER_FORWARDER' }
if ($AllocatorProvider -eq 'custom-errno') { $flags += '/DPROVIDER_EXPOSE_ERRNO' }
if ($TracepointFixture) { $flags += '/utf-8' }
if ($PreloadLibrary) { $flags += ('/DPRELOAD_' + $PreloadLibrary.ToUpperInvariant().Replace('-', '_')) }
# Exported extern "C" functions must remain able to propagate C++ exceptions.
if ($SoftwareReturnFixture) { $flags = @($flags | ForEach-Object { if ($_ -eq '/EHsc') { '/EHs' } else { $_ } }) + '/guard:ehcont' }
if ($ReloadVersion) { $flags += ('/DRELOAD_VERSION=' + $ReloadVersion) }
$executable = $ProcessFixture -or $StandaloneFixture -or $SoftwareFixture -or $ProfileShareFixture -or $PreloadApplication -or $NonjavaApplication
if (-not $executable) { $flags += '/LD' }
$flags += '/link'
if ($TracepointFixture) { $flags += 'advapi32.lib' }
if ($SoftwareReturnFixture) { $flags += @('/CETCOMPAT', '/guard:ehcont') }
if ($LinkLibrary) { $flags += ('"' + $LinkLibrary + '"') }
if (-not $executable) { $flags += ('/IMPLIB:"' + (Join-Path $OutputDirectory 'fixture.lib') + '"') }
if ($DebugSymbols) { $flags += @('/DEBUG', ('/PDB:"' + (Join-Path $OutputDirectory 'fixture.pdb') + '"')) }
if ($ReloadVersion) { $flags += @(('/BASE:' + $PreferredImageBase), '/DYNAMICBASE:NO', '/INCREMENTAL:NO') }
if ($AllocatorProvider -like 'custom*') { $flags += @('/BASE:0x500000000000', '/DYNAMICBASE:NO', '/INCREMENTAL:NO') }
[IO.File]::WriteAllText($response, ($flags -join ' '))
& $env:ComSpec /d /s /c ('call "' + $vcvars + '" >nul && cl.exe @"' + $response + '"')
if ($LASTEXITCODE -ne 0) { throw 'CRT fixture compilation failed.' }
