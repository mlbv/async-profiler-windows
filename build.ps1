# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
param(
    [string]$JdkHome = $env:JAVA_HOME,
    [string]$ClangCxx,
    [string]$MingwRoot = $env:MINGW_ROOT,
    [switch]$JavaOnly,
    [switch]$Package,
    # Also build jfr-converter.exe, a native image of the converter (upstream's `make ni`); not packaged.
    [switch]$NativeImage
)
$ErrorActionPreference = 'Stop'
if (-not $JdkHome) {
    $JdkHome = Split-Path (Split-Path (Get-Command javac.exe -ErrorAction Stop).Source -Parent) -Parent
}
$buildDir = Join-Path $PSScriptRoot 'build'
$symbolFiles = @('asyncProfiler.pdb', 'asprof-helper.pdb', 'asprof.pdb')
$classesDir = Join-Path $buildDir ('classes-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $classesDir -Force
try {
    if (-not $JavaOnly) {
        if (-not $ClangCxx) { $ClangCxx = (Get-Command clang++.exe -ErrorAction Stop).Source }
        if (-not $MingwRoot) { $MingwRoot = Split-Path (Split-Path (Get-Command g++.exe -ErrorAction Stop).Source -Parent) -Parent }
        & (Join-Path $PSScriptRoot 'core/build.ps1') -JdkHome $JdkHome -ClangCxx $ClangCxx -MingwRoot $MingwRoot
        $nativeOutputs = @('asyncProfiler.dll', 'asprof-helper.exe', 'asprof.exe') + $symbolFiles
        Copy-Item -LiteralPath ($nativeOutputs | ForEach-Object { Join-Path $buildDir "core/native/$_" }) -Destination $buildDir -Force
    }
    $librarySources = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'core/src/api'), (Join-Path $PSScriptRoot 'core/src/converter') -Filter '*.java' -Recurse | Select-Object -ExpandProperty FullName)
    # jfrconv.cmd's entry point runs on the converters' Java 8 baseline.
    $librarySources += @('Version', 'Jfrconv') | ForEach-Object { Join-Path $PSScriptRoot "src/dev/profiler/windows/$_.java" }
    & "$JdkHome/bin/javac.exe" --release 8 -Xlint:-options -encoding UTF-8 -d $classesDir $librarySources
    if ($LASTEXITCODE -ne 0) { throw 'Java API/converter compilation failed.' }
    $version = [regex]::Match((Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'core/CMakeLists.txt')), 'set\(PROFILER_VERSION "([^"]+)"\)').Groups[1].Value
    if (-not $version) { throw 'PROFILER_VERSION is not defined in core/CMakeLists.txt.' }
    $buildDate = (Get-Date).ToString('MMM dd yyyy', [Globalization.CultureInfo]::InvariantCulture)
    [IO.File]::WriteAllText((Join-Path $classesDir 'dev/profiler/windows/version.properties'), "version=$version`ndate=$buildDate`n")
    $jarPath = Join-Path $buildDir 'asprof-windows.jar'
    & "$JdkHome/bin/jar.exe" --create --file $jarPath --manifest (Join-Path $PSScriptRoot 'manifest.mf') -C $classesDir . -C (Join-Path $PSScriptRoot 'core/src/res') . -C (Join-Path $PSScriptRoot 'core/src/converter') META-INF -C $PSScriptRoot third_party
    if ($LASTEXITCODE -ne 0) { throw 'JAR creation failed.' }
    Write-Output $jarPath
    if ($NativeImage) {
        $nativeImageTool = Join-Path $JdkHome 'bin/native-image.cmd'
        if (-not (Test-Path -LiteralPath $nativeImageTool)) { throw '-NativeImage needs GraalVM native-image: pass a GraalVM -JdkHome.' }
        $entryDir = Join-Path $classesDir 'native-image'
        & "$JdkHome/bin/javac.exe" -encoding UTF-8 -cp $jarPath -d $entryDir (Join-Path $PSScriptRoot 'src/jfrconv/dev/profiler/windows/NativeJfrconv.java')
        if ($LASTEXITCODE -ne 0) { throw 'Native converter entry compilation failed.' }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'src/jfrconv/META-INF') -Destination $entryDir -Recurse
        & $nativeImageTool -O3 --initialize-at-build-time -H:-ParseRuntimeOptions -cp "$jarPath;$entryDir" dev.profiler.windows.NativeJfrconv -o (Join-Path $buildDir 'jfr-converter')
        if ($LASTEXITCODE -ne 0) { throw 'jfr-converter.exe native image build failed.' }
    }
    if ($Package) {
        $dll = Join-Path $buildDir 'asyncProfiler.dll'
        if (-not (Test-Path -LiteralPath $dll) -or -not (Test-Path -LiteralPath (Join-Path $buildDir 'asprof-helper.exe'))) {
            throw 'Build the native profiler and its ETW helper before packaging.'
        }
        $inspectionJson = & (Join-Path $buildDir 'asprof.exe') inspect --libpath $dll
        if ($LASTEXITCODE -ne 0) { throw 'Profiler DLL inspection failed.' }
        $inspection = ($inspectionJson -join "`n") | ConvertFrom-Json
        if ($inspection.machine -ne 'amd64' -or $inspection.exports.Count -ne 20 -or
                @($inspection.exports | Where-Object { $_.name -eq 'asprof_preload_start' }).Count -ne 1 -or
                @($inspection.exports | Where-Object { $_.name -like 'asprof_test_*' -or $_.forwarder }).Count -ne 0) {
            throw 'Packaging requires the standard x86-64 profiler ABI with 20 direct exports, including the launcher entry; test builds cannot be packaged.'
        }
        if ($inspection.version -ne $version) { throw "The profiler DLL is version $($inspection.version), not $version." }
        $distDir = Join-Path $classesDir 'distribution'
        $null = New-Item -ItemType Directory -Path $distDir
        Copy-Item -LiteralPath $jarPath, $dll, (Join-Path $buildDir 'asprof-helper.exe'), (Join-Path $buildDir 'asprof.exe') -Destination $distDir
        foreach ($name in @('jfrconv.cmd', 'README.md', 'COMPATIBILITY.md', 'profiler.properties.example')) {
            Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $distDir
        }
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'LICENSE'), (Join-Path $PSScriptRoot 'core/UPSTREAM') -Destination $distDir
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'core/src/asprof.h') -Destination $distDir
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'third_party') -Destination $distDir -Recurse
        $zipPath = Join-Path $buildDir 'asprof-windows.zip'
        Compress-Archive -Path (Join-Path $distDir '*') -DestinationPath $zipPath -Force
        Write-Output $zipPath
        $debugZipPath = Join-Path $buildDir 'asprof-windows-debug.zip'
        Compress-Archive -LiteralPath ($symbolFiles | ForEach-Object { Join-Path $buildDir $_ }) -DestinationPath $debugZipPath -Force
        Write-Output $debugZipPath
    }
} finally {
    $resolvedClasses = [IO.Path]::GetFullPath($classesDir)
    $resolvedBuild = [IO.Path]::GetFullPath($buildDir) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedClasses.StartsWith($resolvedBuild, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove a directory outside the build directory: $resolvedClasses"
    }
    Remove-Item -LiteralPath $resolvedClasses -Recurse -Force
}
