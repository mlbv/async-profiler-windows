# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Validate ETW discovery/command errors, or capture real timer/PMU samples in a prepared native fixture."""
import argparse
import ctypes
from ctypes import wintypes
import os
import re
import shutil
from pathlib import Path
import subprocess
import tempfile
import time
from read_otlp import validate as validate_otlp


def validate_commands(library, expect_denied, window_fixture=None):
    dll = ctypes.CDLL(str(library))
    callback_type = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
    dll.asprof_init.argtypes = []
    dll.asprof_init.restype = None
    dll.asprof_execute.argtypes = [ctypes.c_char_p, callback_type]
    dll.asprof_execute.restype = ctypes.c_char_p
    dll.asprof_init()

    def execute(command):
        parts = []
        callback = callback_type(lambda address, size: parts.append(ctypes.string_at(address, size)))
        error = dll.asprof_execute(command.encode('utf-8'), callback)
        return error.decode('utf-8') if error else None, b''.join(parts).decode('utf-8')

    error, listing = execute('list')
    assert error is None and 'etw:Timer' in listing, (error, listing)
    print(listing, flush=True)
    for command, message in [
        ('start,event=etw:NotARealSource', 'unavailable'),
        ('start,event=etw:Timer,interval=1', 'multiples of 100ns'),
        ('start,event=etw:Timer,interval=100', 'outside'),
    ]:
        error, _ = execute(command)
        assert error and message in error, (command, error)
    if expect_denied:
        error, _ = execute('start,event=etw:Timer,interval=1000000')
        if error is None:
            execute('stop')
            raise AssertionError('Expected an unprivileged token; capture unexpectedly started')
        assert 'SeSystemProfilePrivilege' in error and '1300' in error, error
        error, status = execute('status')
        assert error is None and 'not active' in status, (error, status)
        print('ETW_PRIVILEGE_DENIAL_OK', flush=True)
    if window_fixture:
        fixture = ctypes.CDLL(str(window_fixture.resolve()))
        for boundary in [fixture.WindowBegin, fixture.WindowEnd]:
            boundary.argtypes = [wintypes.DWORD]
            boundary.restype = wintypes.DWORD
        error, _ = execute('start,event=etw:Timer,interval=1000000,alluser,begin=nativeMemoryFixture.dll!WindowBegin,end=nativeMemoryFixture.dll!WindowEnd')
        assert error is None, error
        try:
            for _ in range(32770):
                assert fixture.WindowBegin(1) == 18
                assert fixture.WindowEnd(1) == 20
        finally:
            error, _ = execute('stop')
            assert error is None, error
        error, metrics = execute('metrics')
        assert error is None, error
        assert 'windows_etw_failure 111\n' in metrics and 'windows_etw_window_overflow 1\n' in metrics, metrics
        assert 'windows_etw_window_boundaries 65536\n' in metrics and 'windows_breakpoint_targets 0\n' in metrics, metrics
        error, _ = execute('start,event=etw:Timer,interval=1000000,alluser')
        assert error is None, error
        error, _ = execute('stop')
        assert error is None, error
        error, metrics = execute('metrics')
        assert error is None, error
        assert 'windows_etw_failure 0\n' in metrics and 'windows_etw_window_overflow 0\n' in metrics, metrics
        assert 'windows_etw_window_boundaries 0\n' in metrics, metrics
        print('ETW_WINDOW_OVERFLOW_RECOVERY_OK boundaries=65536', flush=True)
    print('ETW_COMMANDS_OK', flush=True)
    return dict((name, int(identifier)) for name, identifier in re.findall(r'^\s+etw:(.*?)\s+source=(\d+)\s', listing, re.MULTILINE))


def query_interval(source):
    class Interval(ctypes.Structure):
        _fields_ = [('source', wintypes.ULONG), ('interval', wintypes.ULONG)]
    query = ctypes.WinDLL('advapi32', use_last_error=True).TraceQueryInformation
    query.argtypes = [ctypes.c_uint64, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
    query.restype = wintypes.ULONG
    value, length = Interval(source, 0), wintypes.ULONG()
    error = query(0, 5, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(length))
    assert error == 0, f'Query profile interval: {error}'
    return value.interval


def session_names():
    control = Path(__file__).resolve().parents[1] / 'build/core/native/etw-control.exe'
    result = subprocess.run([str(control), '--sessions'], capture_output=True, check=True, text=True)
    return result.stdout.splitlines()


def lifecycle(fixture, library, work, java_home, classes):
    sources = validate_commands(library, False)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetExitCodeProcess.restype = wintypes.BOOL
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    for source, mode in [('etw:Timer', 'exit'), ('etw:Timer', 'kill'),
                         ('etw:InstructionRetired', 'kill'), ('etw:InstructionRetired', 'job-kill'),
                         ('etw:InstructionRetired', 'job-blocked'), ('etw:InstructionRetired', 'helper-kill')]:
        output = work / (source.split(':')[1] + '-' + mode)
        output.mkdir(exist_ok=True)
        identifier = sources[source[4:]]
        previous = query_interval(identifier)
        (output / 'previous-interval.txt').write_text(str(previous), encoding='ascii')
        interval = '1000000' if identifier == 0 else '5000000' if previous == 10000000 else '10000000'
        helper_handle = None
        with (output / 'target.out').open('wb') as stdout, (output / 'target.err').open('wb') as stderr:
            target = subprocess.Popen([str(fixture), str(library), str(output), source, mode, interval],
                                      stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, cwd=work)
            prefix = f'async-profiler-{target.pid}-'
            try:
                if mode == 'job-blocked':
                    assert target.wait(timeout=15) == 77
                    error = (output / 'target.err').read_text(errors='replace')
                    assert 'permit job breakaway' in error and 'error 5)' in error, error
                else:
                    deadline = time.monotonic() + 15
                    while True:
                        text = (output / 'target.out').read_text(errors='replace')
                        if f'ETW_READY {target.pid}\n' in text: break
                        if target.poll() is not None or time.monotonic() > deadline:
                            raise AssertionError(f'Target failed: {text}\n{(output / "target.err").read_text(errors="replace")}')
                        time.sleep(.05)
                    helper = int(re.search(r'windows_etw_watchdog_pid (\d+)', text).group(1))
                    helper_handle = kernel.OpenProcess(0x101001 if mode == 'helper-kill' else 0x101000, False, helper)
                    assert helper_handle and kernel.WaitForSingleObject(helper_handle, 0) == 258, 'Watcher was not alive'
                    assert any(name.startswith(prefix) for name in session_names()), 'Private session missing while target is alive'
                    if identifier != 0:
                        assert query_interval(identifier) == int(interval) and int(interval) != previous
                    if mode == 'helper-kill':
                        assert kernel.TerminateProcess(helper_handle, 73), f'Cannot terminate test helper: {ctypes.get_last_error()}'
                        deadline = time.monotonic() + 10
                        while any(name.startswith(prefix) for name in session_names()):
                            assert target.poll() is None and time.monotonic() < deadline, 'Target failed to clean up after watcher death'
                            time.sleep(.05)
                        assert query_interval(identifier) == previous
                        target.stdin.write(b'\n')
                        target.stdin.flush()
                        assert target.wait(timeout=15) == 0, (output / 'target.err').read_text(errors='replace')
                        assert 'ETW_RECOVERY_OK' in (output / 'target.out').read_text(errors='replace')
                        # etw.jfr is the recording finalized after companion loss; restart.jfr follows recovery.
                        for reader, arguments in [('ReadCounters', [str(output / 'restart.jfr'), str(output / 'etw.collapsed'), 'instructions']),
                                                  ('ReadEtw', [str(output / 'restart.jfr')]), ('ReadEtw', [str(output / 'etw.jfr')])]:
                            subprocess.run([str(java_home / 'bin/java.exe'), '-cp', str(classes), reader, *arguments], check=True)
                    elif mode in ('exit', 'job-kill'):
                        target.stdin.write(b'\n')
                        target.stdin.flush()
                        assert target.wait(timeout=10) == (99 if mode == 'job-kill' else 0)
                    else:
                        target.kill()
                        target.wait(timeout=10)
                    assert kernel.WaitForSingleObject(helper_handle, 10000) == 0, 'Watcher survived target cleanup'
                    helper_exit = wintypes.DWORD()
                    assert kernel.GetExitCodeProcess(helper_handle, ctypes.byref(helper_exit)), f'Cannot query watcher exit status: {ctypes.get_last_error()}'
                    assert helper_exit.value == (73 if mode == 'helper-kill' else 0), f'Watcher cleanup failed: {helper_exit.value}'
                assert not any(name.startswith(prefix) for name in session_names()), 'Private session survived target exit'
                assert query_interval(identifier) == previous, 'Target exit failed to restore the sampling interval'
                print('ETW_LIFECYCLE_OK', source, mode, 'previousInterval=' + str(previous), flush=True)
            finally:
                if target.poll() is None:
                    target.kill()
                    target.wait(timeout=10)
                if helper_handle: kernel.CloseHandle(helper_handle)
                target.stdin.close()
                for name in session_names():
                    if name.startswith(prefix):
                        subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/logman.exe'), 'stop', name, '-ets'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--work-directory', type=Path)
    parser.add_argument('--live', action='store_true', help='Run the prepared native fixture; requires SeSystemProfilePrivilege')
    parser.add_argument('--expect-denied', action='store_true', help='Also verify clean failure with a token lacking SeSystemProfilePrivilege')
    parser.add_argument('--lifecycle', action='store_true', help='Test normal exit, forced termination, and Windows job termination')
    parser.add_argument('--restart', action='store_true', help='Verify full native caller stacks after stopping and restarting capture')
    parser.add_argument('--unicode-library', action='store_true', help='Load both native binaries from a path containing spaces and supplementary Unicode')
    parser.add_argument('--symbol-path', type=Path, help='Local directory containing matching native PDBs')
    parser.add_argument('--kernel', action='store_true', help='Require real named kernel frames from a kernel-heavy workload')
    parser.add_argument('--kernel-denied', action='store_true', help='Remove debug privilege in the disposable target and require correctly typed unresolved kernel frames')
    parser.add_argument('--window-fixture', type=Path, help='Verify window-history overflow and restart using the native memory fixture DLL')
    args = parser.parse_args()
    if args.symbol_path: os.environ['ASYNC_PROFILER_SYMBOL_PATH'] = str(args.symbol_path.resolve())
    root = Path(__file__).resolve().parents[1]
    work = args.work_directory or Path(tempfile.mkdtemp(prefix='asprof-etw-'))
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    print('Evidence:', work, flush=True)
    library = root / 'build/core/native/asyncProfiler.dll'
    if args.window_fixture:
        assert not args.expect_denied, 'The window-history test requires elevation'
        validate_commands(library, False, args.window_fixture)
        return
    if args.unicode_library:
        directory = work / '\u5e93 \u6587\u4ef6\U0001f642'
        directory.mkdir(exist_ok=True)
        for name in ['asyncProfiler.dll', 'asprof-helper.exe']:
            shutil.copy2(library.parent / name, directory / name)
        library = directory / library.name
    fixture = work / 'native/nativeApiApplication.exe'
    classes = work / 'classes'
    if not args.live:
        validate_commands(library, args.expect_denied)
        subprocess.run(['cmake', '--build', str(root / 'build/core/native'), '--target', 'etwControlTest', 'kernelImageTest'], check=True)
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                        str(root / 'tests/build_native_fixture.ps1'), '-JdkHome', str(args.java_home),
                        '-OutputDirectory', str(fixture.parent), '-StandaloneFixture', '-DebugSymbols'], check=True)
        classes.mkdir(exist_ok=True)
        subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes),
                        str(root / 'tests/ReadCounters.java'), str(root / 'tests/ReadEtw.java')], check=True)
        print('ETW_LIVE_FIXTURE_PREPARED', flush=True)
        return
    assert fixture.is_file() and (classes / 'ReadEtw.class').is_file(), 'Prepare the fixture without --live first'
    assert not args.expect_denied, '--live and --expect-denied are mutually exclusive'
    if args.lifecycle:
        lifecycle(fixture, library, work, args.java_home, classes)
        return
    for source, unit in [('etw:Timer', 'ns'), ('etw:InstructionRetired', 'instructions')]:
        output = work / source.split(':')[1]
        output.mkdir(exist_ok=True)
        mode = ['restart'] if args.restart else ['kernel-denied'] if args.kernel_denied else ['kernel'] if args.kernel else []
        result = subprocess.run([str(fixture), str(library), str(output), source, *mode], capture_output=True,
                                text=True, timeout=30, cwd=work)
        (output / 'native.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        print(result.stdout, result.stderr, flush=True)
        result.check_returncode()
        assert 'NATIVE_ETW_OK' in result.stdout
        if args.kernel_denied:
            assert 'windows_kernel_modules 0\n' in result.stdout and 'windows_kernel_symbol_error 1300\n' in result.stdout, result.stdout
        if args.kernel:
            assert re.search(r'windows_kernel_pdb_modules [1-9]\d*\n', result.stdout), result.stdout
            # Per-image failures, such as a driver file that no longer matches its loaded image,
            # leave the global kernel symbol status clear.
            assert 'windows_kernel_symbol_error 0\n' in result.stdout, result.stdout
            mismatches = int(re.search(r'windows_kernel_image_mismatches (\d+)\n', result.stdout).group(1))
            assert not mismatches or 'windows_kernel_first_image_error ' in result.stdout, result.stdout
            # Symbol refreshes count each mismatched image once, as an independent scan of the loaded images does.
            scan = subprocess.run([str(root / 'build/core/native/kernel-image-test.exe')], capture_output=True, text=True, check=True)
            assert mismatches == int(re.search(r'mismatched=(\d+)', scan.stdout).group(1)), (mismatches, scan.stdout)
        counts = subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(classes), 'ReadCounters',
                                 str(output / 'etw.jfr'), str(output / 'etw.collapsed'), unit],
                                check=True, capture_output=True, text=True)
        print(counts.stdout, end='', flush=True)
        samples, total = map(int, re.search(r'weightedSamples=(\d+) total=(\d+)', counts.stdout).groups())
        subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(classes), 'ReadEtw',
                        str(output / 'etw.jfr'), str(library), *(['kernel-raw'] if args.kernel_denied else ['kernel'] if args.kernel else [])], check=True)
        value_type = 'cpu' if unit == 'ns' else unit
        validate_otlp(output / 'native.otlp', 'NativeCpuWork', aggregated=True,
                      expected_values=total, expected_type=value_type, expected_unit=unit)
        subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(root / 'build/asprof-windows.jar'),
                        'one.convert.Main', '--total', str(output / 'etw.jfr'), str(output / 'converted.otlp')], check=True)
        validate_otlp(output / 'converted.otlp', 'NativeCpuWork', samples, expected_values=total,
                      expected_type=value_type, expected_unit='nanoseconds' if unit == 'ns' else unit)
    print('ETW_LIVE_OK', flush=True)


if __name__ == '__main__':
    main()
