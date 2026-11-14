# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
Builds and runs the Windows adaptation of upstream's test suite, as upstream's `make test` does.

.DESCRIPTION
Requires the port's build output (build.ps1). Builds the API/converter and test JARs, downloads the
declared test dependency, builds the native test libraries/programs and the C++ unit tests through the
port's CMake tree, then runs the C++ unit tests (only without -Tests, as upstream) and
one.profiler.test.Runner on -JdkHome against build/asyncProfiler.dll.
#>
param(
    # JDK under test: runs the runner and every test JVM.
    [Parameter(Mandatory = $true)][string]$JdkHome,
    # JDK 17+ that compiles the JARs.
    [string]$BuildJdk = $JdkHome,
    # Runner filters (upstream TESTS): test directories, classes, methods or globs.
    [string[]]$Tests = @(),
    [string[]]$Skip = @(),
    [int]$Threads = 8,
    [int]$RetryCount = 0,
    [string]$LogDir = 'build/test/logs',
    [string]$LogLevel = '',
    # Directories with the JDK's PDBs (ASYNC_PROFILER_SYMBOL_PATH). Tests that name JVM-internal
    # functions need them, as upstream needs libjvm symbols.
    [string]$SymbolPath = '',
    [switch]$NoBuild
)
$ErrorActionPreference = 'Stop'
# Comma-separated lists as with upstream's TESTS/SKIP, also when invoked through pwsh -File
$Tests = @($Tests | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$Skip = @($Skip | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$protobufVersion = '4.31.1'

function Invoke-Checked([string]$what, [scriptblock]$command) {
    & $command
    if ($LASTEXITCODE -ne 0) { throw "$what failed with exit code $LASTEXITCODE" }
}

function Build-Jar([string]$jar, [string[]]$sourceDirs, [string[]]$jarArgs) {
    $classes = "build/classes-$([IO.Path]::GetFileNameWithoutExtension($jar))"
    if (Test-Path -LiteralPath $classes) { Remove-Item -LiteralPath $classes -Recurse -Force }
    $sources = @(Get-ChildItem -LiteralPath $sourceDirs -Filter '*.java' -Recurse | ForEach-Object FullName)
    Invoke-Checked "Compiling $jar" { & "$BuildJdk/bin/javac.exe" --release 8 -Xlint:-options -encoding UTF-8 -d $classes $sources }
    Invoke-Checked "Packaging $jar" { & "$BuildJdk/bin/jar.exe" @jarArgs -C $classes . }
    Remove-Item -LiteralPath $classes -Recurse -Force
}

Push-Location $PSScriptRoot
try {
    if (-not (Test-Path -LiteralPath "$root/build/asyncProfiler.dll")) { throw 'Build the port first (build.ps1).' }
    if (-not $NoBuild) {
        $null = New-Item -ItemType Directory -Force -Path build/jar, test/deps
        $protobuf = "test/deps/protobuf-java-$protobufVersion.jar"
        if (-not (Test-Path -LiteralPath $protobuf)) {
            Invoke-WebRequest -UseBasicParsing -OutFile $protobuf `
                -Uri "https://repo1.maven.org/maven2/com/google/protobuf/protobuf-java/$protobufVersion/protobuf-java-$protobufVersion.jar"
        }

        $core = "$root/core/src"
        Build-Jar 'build/jar/async-profiler.jar' @("$core/api") @('cfm', 'build/jar/async-profiler.jar', "$core/api/META-INF/MANIFEST.MF")
        Build-Jar 'build/jar/jfr-converter.jar' @("$core/converter") @('cfe', 'build/jar/jfr-converter.jar', 'one.convert.Main',
            '-C', "$core/res", '.', '-C', "$core/converter", 'META-INF')

        if (Test-Path -LiteralPath build/test/classes) { Remove-Item -LiteralPath build/test/classes -Recurse -Force }
        $testSources = @(Get-ChildItem -LiteralPath test -Filter '*.java' -Recurse |
            Where-Object { -not $_.FullName.StartsWith((Resolve-Path test/stubs).Path) } | ForEach-Object FullName)
        Invoke-Checked 'Compiling the test classes' {
            & "$BuildJdk/bin/javac.exe" -source 8 -target 8 -Xlint:-options '-XDignore.symbol.file' -implicit:none -encoding UTF-8 `
                -cp 'build/jar/*;test/deps/*;test/gen/*;test/stubs' -d build/test/classes $testSources
        }
        Invoke-Checked 'Packaging build/test.jar' { & "$BuildJdk/bin/jar.exe" cf build/test.jar -C build/test/classes . }

        $native = "$root/build/core/native"
        Invoke-Checked 'Configuring the native test targets' { cmake -S "$root/core" -B $native -DASPROF_UPSTREAM_TESTS=ON | Out-Null }
        Invoke-Checked 'Building the native test targets' { cmake --build $native --target upstream-tests }
    }

    # build/test/lib resolves the test libraries' own DLL dependencies (upstream: LD_LIBRARY_PATH)
    $gitUsrBin = (Get-Item (Get-Command git.exe).Source).Directory
    while ($gitUsrBin -and -not (Test-Path -LiteralPath "$($gitUsrBin.FullName)\usr\bin\sh.exe")) { $gitUsrBin = $gitUsrBin.Parent }
    if (-not $gitUsrBin) { throw 'Git for Windows sh.exe not found' }
    $gitUsrBin = "$($gitUsrBin.FullName)\usr\bin"
    $env:PATH = (Resolve-Path build/test/lib).Path + ';' + $env:PATH + ';' + $gitUsrBin
    if ($SymbolPath) { $env:ASYNC_PROFILER_SYMBOL_PATH = $SymbolPath }

    $failed = $false
    if ($Tests.Count -eq 0 -and (Test-Path -LiteralPath build/test/cpptests.exe)) {
        Write-Output 'Running cpp tests...'
        & build/test/cpptests.exe
        $failed = $LASTEXITCODE -ne 0
    }
    Write-Output "Running tests against $root\build\asyncProfiler.dll"
    # Test files, including those of test processes, stay in the build tree rather than the system temporary directory
    $tmpDir = (New-Item -ItemType Directory -Force -Path build/test/tmp).FullName
    $env:TEMP = $tmpDir
    $env:TMP = $tmpDir
    & "$JdkHome/bin/java.exe" "-Djava.io.tmpdir=$tmpDir" "-DlogDir=$LogDir" "-DlogLevel=$LogLevel" "-Dskip=$($Skip -join ' ')" "-DretryCount=$RetryCount" `
        "-DthreadCount=$Threads" -ea -cp 'build/test.jar;build/jar/*;test/deps/*;test/gen/*' one.profiler.test.Runner @Tests
    if ($failed -or $LASTEXITCODE -ne 0) { exit 1 }
} finally {
    Pop-Location
}
