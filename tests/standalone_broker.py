# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Exercise privileged ETW collection with an unelevated JVM and real Java stack decoding."""
import argparse
import ctypes
import json
from ctypes import wintypes
from pathlib import Path
import re
import subprocess
import tempfile
import time

from standalone_java_etw import validate_metadata_metrics, validate_recording, validate_totals
from standalone_etw import query_interval

import integrity


def wait_for(predicate, process, description, seconds=25):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        if process.poll() is not None:
            raise AssertionError(description + ': process exited ' + str(process.returncode))
        time.sleep(.05)
    raise AssertionError(description + ': timed out')


def granted_access(handle):
    query = ctypes.WinDLL('ntdll').NtQueryObject
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)]
    query.restype = wintypes.LONG
    basic, size = ctypes.create_string_buffer(56), wintypes.ULONG()
    status = query(handle, 0, basic, len(basic), ctypes.byref(size))
    assert status == 0, ('NtQueryObject', status)
    return int.from_bytes(basic.raw[4:8], 'little')


def verify_query_only(kernel, controller_pid):
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    query_process = kernel.OpenProcess(0x1000, False, controller_pid)
    assert query_process, ('Controller identity query', ctypes.get_last_error())
    security = ctypes.WinDLL('advapi32', use_last_error=True)
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    token = wintypes.HANDLE()
    try:
        maximum = kernel.OpenProcess(0x02000000, False, controller_pid)
        assert maximum
        try:
            assert granted_access(maximum) == 0x1000, 'Controller process access exceeds identity query'
        finally:
            kernel.CloseHandle(maximum)
        assert security.OpenProcessToken(query_process, 0x02000000, ctypes.byref(token))
        try:
            assert granted_access(token) == 8, 'Controller token access exceeds identity query'
            verify_private_defaults(kernel, security, token)
            elevated, size = wintypes.DWORD(), wintypes.DWORD()
            assert security.GetTokenInformation(token, 20, ctypes.byref(elevated), 4, ctypes.byref(size)) and elevated.value == 1
        finally:
            kernel.CloseHandle(token)
        for access in [0x1, 0x2, 0x8, 0x10, 0x20, 0x40, 0x80, 0x200, 0x400, 0x800, 0x2000, 0x20000, 0x40000, 0x80000]:
            forbidden = kernel.OpenProcess(access, False, controller_pid)
            if forbidden:
                kernel.CloseHandle(forbidden)
                raise AssertionError('Controller exposed process access ' + hex(access))
            assert ctypes.get_last_error() == 5
        for access in [0x1, 0x2, 0x3, 0x4, 0x10, 0x20, 0x40, 0x80, 0x100, 0x10000, 0x20000, 0x40000, 0x80000]:
            if security.OpenProcessToken(query_process, access, ctypes.byref(token)):
                kernel.CloseHandle(token)
                raise AssertionError('Controller exposed token control access ' + hex(access))
            assert ctypes.get_last_error() == 5
        print('CONTROLLER_QUERY_ONLY pid=' + str(controller_pid) + ' process=0x1000 token=0x8 controlDenials=27', flush=True)
    finally:
        kernel.CloseHandle(query_process)


def verify_private_defaults(kernel, security, token):
    security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    size = wintypes.DWORD()
    security.GetTokenInformation(token, 6, None, 0, ctypes.byref(size))
    data = ctypes.create_string_buffer(size.value)
    assert security.GetTokenInformation(token, 6, data, len(data), ctypes.byref(size))
    acl = ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0]
    assert acl
    count = int.from_bytes(ctypes.string_at(acl + 4, 2), 'little')
    security.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    values = {}
    for index in range(count):
        ace = ctypes.c_void_p()
        assert security.GetAce(acl, index, ctypes.byref(ace))
        header = ctypes.string_at(ace.value, 8)
        assert header[0] == 0, 'Unexpected controller default ACE type'
        text = wintypes.LPWSTR()
        assert security.ConvertSidToStringSidW(ace.value + 8, ctypes.byref(text))
        values[text.value] = int.from_bytes(header[4:8], 'little')
        kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    assert values == {'S-1-5-18': 0x10000000, 'S-1-5-32-544': 0x10000000, 'S-1-3-4': 0}, values


def verify_controller_threads(kernel, controller_pids):
    class Thread(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('usage', wintypes.DWORD), ('tid', wintypes.DWORD),
                    ('pid', wintypes.DWORD), ('base', wintypes.LONG), ('delta', wintypes.LONG), ('flags', wintypes.DWORD)]
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(Thread)]
    kernel.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(Thread)]
    kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenThread.restype = wintypes.HANDLE
    kernel.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
    kernel.GetProcessIdOfThread.restype = wintypes.DWORD
    snapshot = kernel.CreateToolhelp32Snapshot(4, 0)
    assert snapshot != ctypes.c_void_p(-1).value
    counts = dict.fromkeys(controller_pids, 0)
    entry = Thread()
    entry.size = ctypes.sizeof(entry)
    try:
        more = kernel.Thread32First(snapshot, ctypes.byref(entry))
        while more:
            if entry.pid in counts:
                handle = kernel.OpenThread(0x02000000, False, entry.tid)
                if handle:
                    access = granted_access(handle)
                    owner = kernel.GetProcessIdOfThread(handle)
                    kernel.CloseHandle(handle)
                    if not owner or owner == entry.pid:
                        raise AssertionError('Controller thread is accessible: pid=' + str(entry.pid) + ' tid=' + str(entry.tid) + ' owner=' + str(owner) + ' access=' + hex(access))
                else:
                    error = ctypes.get_last_error()
                    assert error in [5, 87], ('OpenThread', error)
                    if error == 5:
                        counts[entry.pid] += 1
            more = kernel.Thread32Next(snapshot, ctypes.byref(entry))
        assert ctypes.get_last_error() == 18
    finally:
        kernel.CloseHandle(snapshot)
    assert all(counts.values()), counts
    print('CONTROLLER_THREAD_DENIALS', counts, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--jar', type=Path)
    parser.add_argument('--default-pipe', action='store_true')
    parser.add_argument('--case', choices=['plain', 'raw', 'cpu-alias', 'interpreted', 'java-only', 'kernel', 'restart-plain', 'loop', 'target-death', 'broker-death', 'bootstrap-death'], default='plain')
    args = parser.parse_args()
    integrity.require_elevated()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-broker-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    jar = (args.jar or root / 'build/asprof-windows.jar').resolve()
    agent = (args.agent or root / 'build/core/native/asyncProfiler.dll').resolve()
    helper = agent.parent / 'asprof-helper.exe'
    previous_interval = query_interval(0)
    java = args.java_home / 'bin/java.exe'
    names = ['BrokerJavaSmoke.java', 'EtwJavaSmoke.java', 'EtwJavaPayload.java', 'ReadJavaEtw.java', 'ReadCounters.java']
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar),
                    '-d', str(classes), *[str(root / 'tests' / name) for name in names]], check=True)
    ready, release, recording = work / 'ready', work / 'release', work / 'java.jfr'
    pipe = r'\\.\pipe\async-profiler-broker-' + work.name
    # Code-cache layouts without reachable native unwind storage need the VM-owned buffer
    # that only an explicit WhiteBoxAPI permits.
    command = [str(java), '-XX:+UnlockDiagnosticVMOptions', '-XX:+WhiteBoxAPI', '-XX:CompileCommand=dontinline,EtwJavaSmoke.*',
               '-Dasprof.etw.broker=' + ('' if args.default_pipe else pipe)]
    if args.default_pipe:
        command += ['-Dasprof.etw.verify.empty=true']
    if args.case == 'raw':
        command += ['-Dasprof.etw.event=rc0', '-Dasprof.etw.interval=1000000']
    if args.case == 'cpu-alias':
        command += ['-Dasprof.etw.event=cpu-clock']
    if args.case.endswith('-death'):
        interval = 2_000_000 if previous_interval == 10_000 else 1_000_000
        command += ['-Dasprof.etw.interval=' + str(interval)]
    if args.case == 'interpreted':
        command += ['-Xint']
    fixture_case = 'java-only-cpu-id' if args.case == 'cpu-alias' else args.case
    command += ['-cp', str(classes) + ';' + str(jar), 'BrokerJavaSmoke', str(agent),
                str(recording), fixture_case, str(ready), str(release)]
    target, broker = None, None
    try:
        with (work / 'target.log').open('w', encoding='utf-8') as target_log, (work / 'broker.log').open('w', encoding='utf-8') as broker_log:
            target = integrity.deelevated_popen(command, stdout=target_log, stderr=subprocess.STDOUT, cwd=work)
            wait_for(ready.exists, target, 'JVM ready')
            assert int(ready.read_text()) == target.pid
            if args.default_pipe:
                pipe = r'\\.\pipe\async-profiler-' + str(target.pid)
            broker_command = [str(helper), '--etw-broker', str(target.pid)]
            if not args.default_pipe:
                broker_command += [pipe]
            broker = subprocess.Popen(broker_command, stdout=broker_log, stderr=subprocess.STDOUT, cwd=work)
            wait_for(lambda: 'ETW_BROKER_READY ' in (work / 'broker.log').read_text(errors='replace'), broker, 'Broker ready')
            # A different same-user process must not acquire the target's lease.
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                          wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
            kernel.CreateFileW.restype = wintypes.HANDLE
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            broker_pid = int(re.search(r'ETW_BROKER_READY pid=(\d+)', (work / 'broker.log').read_text()).group(1))
            with integrity.impersonating():
                verify_query_only(kernel, broker_pid)
                foreign = kernel.CreateFileW(pipe, 0xC0000000, 0, None, 3, 0, None)
                assert foreign != ctypes.c_void_p(-1).value, ('Foreign pipe open', ctypes.get_last_error())
            kernel.SetNamedPipeHandleState.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p]
            kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
            mode = wintypes.DWORD(1)
            assert kernel.SetNamedPipeHandleState(foreign, ctypes.byref(mode), None, None)
            deadline = time.monotonic() + 5
            rejected = False
            try:
                while time.monotonic() < deadline:
                    value, size = ctypes.c_ubyte(), wintypes.DWORD()
                    success = kernel.ReadFile(foreign, ctypes.byref(value), 1, ctypes.byref(size), None)
                    assert not success, 'Broker sent data to a foreign process'
                    error = ctypes.get_last_error()
                    if error in [109, 233]:
                        rejected = True
                        break
                    assert error == 232, ('Foreign read', error)
                    time.sleep(.02)
                assert rejected, 'Broker did not reject the foreign process'
            finally:
                kernel.CloseHandle(foreign)
            release.touch()
            if args.case.endswith('-death'):
                wait_for((work / 'active').exists, target, 'Capture active')
                assert query_interval(0) != previous_interval, 'Death test did not change the sampling interval'
                if args.case == 'target-death':
                    target.kill()
                    target.wait(timeout=10)
                else:
                    wait_for((work / 'sampled').exists, target, 'Delivered samples before broker death', seconds=12)
                    broker_pid = re.search(r'ETW_BROKER_READY pid=(\d+)', (work / 'broker.log').read_text()).group(1)
                    if args.case == 'bootstrap-death':
                        family = subprocess.run(['C:/Program Files/PowerShell/7/pwsh.exe', '-NoProfile',
                                                 '-ExecutionPolicy', 'Bypass', '-File', str(root / 'tests/broker_watchers.ps1'),
                                                 '-BrokerPid', broker_pid, '-IncludeBootstrap'], check=True, capture_output=True, text=True)
                        broker_pid = str(json.loads(family.stdout)['bootstrap'])
                    subprocess.run(['C:/Windows/System32/taskkill.exe', '/PID', broker_pid, '/F'], check=True)
                    wait_for(lambda: query_interval(0) == previous_interval, target, 'Watchdog interval restoration', seconds=15)
                    (work / 'finish').touch()
            target.wait(timeout=60)
            broker.wait(timeout=20)
        text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
        print(text, flush=True)
        print((work / 'broker.log').read_text(encoding='utf-8', errors='replace'), flush=True)
        assert query_interval(0) == previous_interval, 'Broker did not restore the previous sampling interval'
        if args.default_pipe:
            assert 'EMPTY_FDTRANSFER_REJECTED' in text
        if args.case == 'target-death':
            assert target.returncode != 0 and broker.returncode == 0
            print('PRIVILEGED_ETW_BROKER_TARGET_DEATH_OK intervalRestored=1', flush=True)
            return
        if args.case in ['broker-death', 'bootstrap-death']:
            assert target.returncode == 0 and broker.returncode != 0
            assert re.search(r'windows_etw_failure [1-9]\d*\n', text), 'Broker death was silently accepted'
            assert 'BROKER_FATAL_STOP ' in text
            validate_recording(java, classes, jar, recording, 'EtwJavaSmoke', 'plain')
            print('PRIVILEGED_ETW_BROKER_DEATH_OK case=' + args.case + ' intervalRestored=1 targetSurvived=1 fatalStop=1 retainedData=1', flush=True)
            return
        assert target.returncode == 0 and broker.returncode == 0
        validate_metadata_metrics(text)
        assert re.search(r'windows_etw_broker_pid [1-9]\d*\n', text)
        assert 'windows_etw_failure 0\n' in text and not re.search(r'windows_etw_failure [1-9]\d*\n', text)
        if args.case == 'raw':
            assert 'RAW_PMU_SOURCE_REMOVED' in text
            for metric in ['malformed_events', 'events_lost', 'buffers_lost', 'realtime_buffers_lost']:
                assert f'windows_etw_{metric} 0\n' in text
            subprocess.run([str(java), '-cp', str(classes), 'ReadJavaEtw', str(recording), 'EtwJavaSmoke', 'plain'], check=True)
            samples, total = validate_totals(java, classes, jar, recording, 'EtwJavaSmoke', counter_unit='events',
                                            expected_type='rc0', expected_unit='events')
            assert total == samples * 1000000, (samples, total)
            print('PRIVILEGED_ETW_RAW_BROKER_OK samples=' + str(samples) + ' events=' + str(total) + ' sourceRemoved=1', flush=True)
            return
        if args.case == 'kernel':
            assert re.search(r'windows_kernel_modules [1-9]\d*\n', text), 'Broker kernel identities were not installed'
            assert 'windows_kernel_symbol_error 0\n' in text
            # A driver whose file no longer matches its loaded image only loses that module's names.
            mismatches = int(re.search(r'windows_kernel_image_mismatches (\d+)\n', text).group(1))
            assert not mismatches or 'windows_kernel_first_image_error ' in text, text
        if args.case == 'loop':
            captures = sorted(work.glob('java.jfr-*.jfr'))
            assert len(captures) >= 2, ('Retained-peer loop recordings', captures)
            assert 'BROKER_LOOP_COMPLETED' in text
            # The first segment and the first retained-peer restart. The fixed timeout truncates the
            # final segment by the accumulated restart time, which can leave it without samples.
            for capture in captures[:2]:
                subprocess.run([str(java), '-cp', str(classes), 'ReadJavaEtw', str(capture), 'EtwJavaSmoke', 'plain'], check=True)
            print('PRIVILEGED_ETW_BROKER_LOOP_OK recordings=' + str(len(captures)), flush=True)
            return
        validate_recording(java, classes, jar, recording, 'EtwJavaSmoke', 'plain' if args.case == 'restart-plain' else fixture_case)
        if args.case == 'restart-plain':
            validate_recording(java, classes, jar, Path(str(recording) + '.restart.jfr'), 'EtwJavaSmoke', 'plain')
        print('PRIVILEGED_ETW_BROKER_OK', args.case, flush=True)
    finally:
        if target and target.poll() is None:
            target.kill()
            target.wait(timeout=10)
        if broker and broker.poll() is None:
            # The broker observes the target handle and restores the lease.
            broker.wait(timeout=20)


if __name__ == '__main__':
    main()
