@rem Copyright 2026 movblock
@rem SPDX-License-Identifier: Apache-2.0
@echo off
setlocal
set "APW_JAR=%~dp0asprof-windows.jar"
if not exist "%APW_JAR%" set "APW_JAR=%~dp0build\asprof-windows.jar"
if not exist "%APW_JAR%" (
    echo Build the converter JAR first: powershell -ExecutionPolicy Bypass -File "%~dp0build.ps1" -JavaOnly 1>&2
    exit /b 1
)
set "APW_JAVA="
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\java.exe" set "APW_JAVA=%JAVA_HOME%\bin\java.exe"
if not defined APW_JAVA for /f "delims=" %%j in ('where java.exe 2^>nul') do if not defined APW_JAVA set "APW_JAVA=%%j"
if not defined APW_JAVA (
    echo No JDK found. Set JAVA_HOME or ensure java executable is on the PATH 1>&2
    exit /b 1
)
"%APW_JAVA%" -Xss2M -Dsun.misc.URLClassPath.disableJarChecking -cp "%APW_JAR%" dev.profiler.windows.Jfrconv %*
exit /b %errorlevel%
