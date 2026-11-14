# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Start native applications through asprof-helper --preload, the Windows counterpart of upstream's LD_PRELOAD."""
import argparse
import ctypes
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--etw', action='store_true', help='Also capture etw:Timer in a preloaded process; requires elevation')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    native = root / 'build/core/native'
    helper, profiler = native / 'asprof-helper.exe', native / 'asyncProfiler.dll'
    work = Path(tempfile.mkdtemp(prefix='asprof-preload-'))
    print('Evidence:', work, flush=True)

    def build(name, *switches):
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(root / 'tests/build_native_fixture.ps1'),
                        '-JdkHome', str(args.java_home), '-OutputDirectory', str(work / name), *switches, '-DebugSymbols'], check=True)
    build('application', '-PreloadApplication')
    for variant in ('interposer', 'calls-malloc', 'fail'):
        build(variant, '-PreloadLibrary', variant)
    build('dependent', '-PreloadLibrary', 'dependent', '-LinkLibrary', str(work / 'calls-malloc/fixture.lib'))
    shutil.copyfile(work / 'calls-malloc/preload-calls-malloc.dll', work / 'dependent/preload-calls-malloc.dll')
    application = work / 'application/nativePreloadApplication.exe'
    interposer = work / 'interposer/preload-interposer.dll'
    calls_malloc = work / 'calls-malloc/preload-calls-malloc.dll'
    failing = work / 'fail/preload-fail.dll'
    classes = work / 'classes'
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes), str(root / 'tests/ReadPreload.java'),
                    str(root / 'tests/PreloadChildLauncher.java')], check=True)

    def run(name, command, asprof_command=None, expected=0, path=None):
        environment = {key: value for key, value in os.environ.items() if key.upper() not in ('ASPROF_COMMAND', 'PATH')}
        environment['PATH'] = os.pathsep.join(filter(None, [path and str(path), os.environ.get('PATH')]))
        if asprof_command is not None:
            environment['ASPROF_COMMAND'] = asprof_command
        result = subprocess.run([str(part) for part in command], capture_output=True, text=True, encoding='utf-8', errors='replace',
                                timeout=120, cwd=work, env=environment)
        (work / f'{name}.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        assert result.returncode == expected, f'{name}: exit code {result.returncode}, expected {expected}\n{result.stdout}{result.stderr}'
        print(f'{name}: exit code {result.returncode}', flush=True)
        return result

    def preload(*libraries):
        return [helper, *(part for library in libraries for part in ('--preload', library)), '--', application]

    def read(mode, recording, *extra):
        subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(classes), 'ReadPreload', mode, str(work / recording), *extra], check=True)

    # The launcher is transparent: full 32-bit exit codes and CommandLineToArgvW-compatible arguments.
    run('exit-small', preload(profiler) + ['exit', '37'], expected=37)
    run('exit-status', preload(profiler) + ['exit', '0xE0000001'], expected=0xE0000001)
    arguments = ['a b', 'q"x', 'tr\\', '', 'ü🙂', 'two  spaces\\"end', '\\\\server\\share\\', '\t']
    run('arguments', preload(profiler) + ['args', work / 'arguments.bin', *arguments])
    assert (work / 'arguments.bin').read_bytes().decode('utf-16-le').split('\0')[:-1] == arguments

    # A bare executable name is searched as CreateProcess does, including PATH, with an implied .exe.
    run('path-search', [helper, '--preload', profiler, '--', application.stem, 'exit', '5'], expected=5, path=application.parent)
    # A name with a directory resolves against the current directory, also with '/' and an implied .exe.
    run('relative-path', [helper, '--preload', profiler, '--', 'application/nativePreloadApplication', 'exit', '6'], expected=6)

    # The application runs in a kill-on-close job: terminating the helper terminates it.
    pid_file = work / 'wait.pid'
    launcher = subprocess.Popen([str(part) for part in preload(profiler) + ['wait', pid_file]], cwd=work,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 30
    while not (pid_file.exists() and pid_file.read_text(encoding='ascii').endswith('\n')):
        assert launcher.poll() is None and time.monotonic() < deadline, 'The waiting application did not start'
        time.sleep(.05)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    waiting = kernel.OpenProcess(0x00100000, False, int(pid_file.read_text(encoding='ascii')))
    assert waiting, f'Cannot open the waiting application: {ctypes.get_last_error()}'
    launcher.kill()
    launcher.wait(timeout=10)
    assert kernel.WaitForSingleObject(waiting, 10000) == 0, 'The application survived the helper'
    kernel.CloseHandle(waiting)
    print('kill-on-close: application ended with the helper', flush=True)

    # Preloaded DLLs resolve their own dependencies from their directory.
    run('dependent', preload(work / 'dependent/preload-dependent.dll') + ['exit', '0'])

    # ASPROF_COMMAND starts profiling before the entry point and finalizes the output at exit.
    run('cpu', preload(profiler) + ['cpu'], f'start,event=cpu,interval=1ms,file={work / "cpu.jfr"}')
    read('cpu', 'cpu.jfr')
    run('cpu-collapsed', preload(profiler) + ['cpu'], f'start,event=cpu,interval=1ms,file={work / "cpu.collapsed"}')
    assert 'PreloadCpuWork' in (work / 'cpu.collapsed').read_text(encoding='utf-8')

    # As with upstream's atexit hook, exit also finalizes a C API recording.
    run('api-exit', [application, 'api-exit', profiler, work / 'api-exit.jfr'])
    read('cpu', 'api-exit.jfr')

    # Without an attached JVM, VMStructs walkers record native frames, as in upstream's jvmInBetween flow.
    for cstack in ('vm', 'vmx'):
        run(f'api-{cstack}', [application, 'api-cstack', profiler, cstack, work / f'api-{cstack}.collapsed'])
        assert 'PreloadCpuWork' in (work / f'api-{cstack}.collapsed').read_text(encoding='utf-8')

    # malloc_plt_dyn: the pointer captured by a dynamic initializer is only hooked if profiling started first.
    run('malloc', preload(profiler) + ['malloc'], f'start,nativemem,file={work / "malloc.jfr"}')
    read('malloc', 'malloc.jfr', '1999993', '2000003')

    # preload_malloc: an interposer loaded before or after the profiler stays in the call chain.
    run('interposer-second', preload(profiler, interposer) + ['interposed'], f'start,nativemem,file={work / "interposer-second.jfr"}')
    read('malloc', 'interposer-second.jfr', '1999993')
    run('interposer-first', preload(interposer, profiler) + ['interposed'], f'start,nativemem,file={work / "interposer-first.jfr"}')
    read('malloc', 'interposer-first.jfr', '1999993')
    run('interposer-api', preload(interposer) + ['api-interposed', profiler, work / 'interposer-api.jfr'])
    read('malloc', 'interposer-api.jfr', '1999993')

    # profile_with_dlopen: a preloaded profiler without ASPROF_COMMAND waits for the C API.
    for mode in ('dlopen-first', 'profile-first'):
        run(mode, preload(profiler) + [mode, profiler, calls_malloc, work / f'{mode}.jfr'])
        read('malloc', f'{mode}.jfr', '1999993')

    # Children that inherit ASPROF_COMMAND are preloaded too, as upstream's inherited LD_PRELOAD does; %p separates outputs.
    def per_process(name):
        return f'start,event=cpu,interval=1ms,file={work / name}-%p.jfr'

    def child(result):
        return int(next(line.split()[1] for line in result.stdout.splitlines() if line.startswith('CHILD ')))

    result = run('tree', preload(profiler) + ['tree', '2'], per_process('tree'))
    pids = [int(line.split()[1]) for line in result.stdout.splitlines() if line.startswith('PID ')]
    assert len(set(pids)) == 3, result.stdout
    for pid in pids:
        read('cpu', f'tree-{pid}.jfr')
    result = run('suspended', preload(profiler) + ['spawn-suspended', work / 'suspended.marker'], per_process('suspended'))
    read('cpu', f'suspended-{child(result)}.jfr')
    for mode in ('shell', 'spawn-ansi', 'spawn-user'):
        result = run(mode, preload(profiler) + [mode], per_process(mode))
        read('cpu', f'{mode}-{child(result)}.jfr')
    result = run('spawn32', preload(profiler) + ['spawn32'], per_process('spawn32'), expected=7)
    assert f'Not preloading process {child(result)}: A 32-bit process cannot load x64 DLLs' in result.stdout, result.stdout
    result = run('spawn-noenv', preload(profiler) + ['spawn-noenv'], per_process('noenv'))
    assert not (work / f'noenv-{child(result)}.jfr').exists()
    result = run('java-child', [helper, '--preload', profiler, '--', args.java_home / 'bin/java.exe', '-cp', classes, 'PreloadChildLauncher',
                                application, 'cpu'], per_process('java-child'))
    read('cpu', f'java-child-{child(result)}.jfr')

    run('locks', preload(profiler) + ['locks'], f'start,nativelock,file={work / "locks.jfr"}')
    read('locks', 'locks.jfr')
    run('java', [helper, '--preload', profiler, '--', args.java_home / 'bin/java.exe', '-version'], f'start,nativemem,file={work / "java.jfr"}')
    read('java', 'java.jfr')
    if args.etw:
        # The ETW companion breaks away from the application's job.
        run('etw', preload(profiler) + ['cpu'], f'start,event=etw:Timer,interval=1ms,file={work / "etw.jfr"}')
        read('cpu', 'etw.jfr')

    # fake-preload: ASPROF_COMMAND has no effect when the application loads the DLL itself.
    result = run('fake-preload', [application, 'api', profiler, work / 'api.jfr'], f'start,cpu,file={work / "fake-preload.jfr"}')
    assert 'Starting profiler' in result.stdout and 'Stopping profiler' in result.stdout
    assert (work / 'api.jfr').stat().st_size > 0 and not (work / 'fake-preload.jfr').exists()

    # Preload failures terminate the process before its entry point and report the Windows error.
    copy = work / 'copy/asyncProfiler.dll'
    copy.parent.mkdir()
    shutil.copyfile(profiler, copy)
    failures = [('missing-dll', preload(profiler, work / 'missing.dll'), 126, 'missing.dll'),
                ('dll-init-failed', preload(failing), 1114, 'preload-fail.dll'),
                ('two-profilers', preload(profiler, copy), 87, 'asprof_preload_start')]
    for name, command, error, detail in failures:
        result = run(name, command + ['marker', work / f'{name}.marker'], 'start,event=cpu,file=failed.jfr', expected=error)
        assert detail in result.stderr and f'Windows error {error}' in result.stderr, result.stderr
        assert not (work / f'{name}.marker').exists() and not (work / 'failed.jfr').exists()
    wow64 = Path(os.environ['SystemRoot']) / 'SysWOW64/cmd.exe'
    result = run('wow64', [helper, '--preload', profiler, '--', wow64, '/c', 'exit 0'], expected=193)
    assert '32-bit process' in result.stderr
    run('usage', [helper, '--preload', profiler, application], expected=87)
    print('PRELOAD_OK', flush=True)


if __name__ == '__main__':
    main()
