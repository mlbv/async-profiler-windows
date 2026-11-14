# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Prove native page-fault/context-switch weights and stacks without a target JVM, through the broker or locally."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
import time

from read_otlp import validate as validate_otlp
from standalone_etw import query_interval
from standalone_tracepoint import token_properties

import integrity


CASES = [('page-faults', 1), ('page-faults', 5),
         ('context-switches', 1), ('context-switches', 3)] * 2
ZERO_METRICS = [
    'events_dropped_total', 'samples_skipped_total', 'calltracestorage_overflows_total',
    'windows_etw_failure', 'windows_etw_malformed_events', 'windows_etw_events_lost',
    'windows_etw_buffers_lost', 'windows_etw_realtime_buffers_lost',
    'windows_etw_pending_evictions', 'windows_etw_unsupported_stack_events',
    'windows_etw_broker_potential_target_loss', 'windows_etw_broker_cleanup_error',
    'windows_etw_software_unknown_threads', 'windows_etw_software_unproven_events',
    'windows_etw_module_lifetime_ambiguous_pcs', 'windows_etw_truncated_stacks',
    'windows_etw_software_router_sequence_breaks', 'windows_etw_software_router_reason',
]


class OutputPipe:
    """The queue reader follows the standalone native fixture's blocking pipe protocol."""

    def __init__(self, process, path):
        self.process = process
        self.path = path
        self.lines = queue.Queue()
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()

    def collect(self):
        try:
            with self.path.open('w', encoding='utf-8') as log:
                for line in self.process.stdout:
                    log.write(line)
                    log.flush()
                    self.lines.put(line.rstrip('\r\n'))
        finally:
            self.lines.put(None)

    def receive(self, description, seconds=40):
        try:
            line = self.lines.get(timeout=seconds)
        except queue.Empty:
            raise AssertionError(description + ': stdout deadline expired') from None
        assert line is not None, description + ': stdout closed'
        return line

    def until(self, prefix, seconds=40):
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, prefix + ': stdout deadline expired'
            line = self.receive(prefix, remaining)
            if line.startswith(prefix):
                return line

    def exchange(self, command, expected):
        self.process.stdin.write(command + '\n')
        self.process.stdin.flush()
        line = self.until("CAPTURE_DONE ")
        assert line == expected, (expected, line)


def user_sid(pid):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    security = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    process = kernel.OpenProcess(0x1000, False, pid)
    assert process, ('Open process identity', pid, ctypes.get_last_error())
    token = wintypes.HANDLE()
    try:
        assert security.OpenProcessToken(process, 8, ctypes.byref(token))
        try:
            size = wintypes.DWORD()
            security.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            data = ctypes.create_string_buffer(size.value)
            assert security.GetTokenInformation(token, 1, data, len(data), ctypes.byref(size))
            sid = ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0]
            text = wintypes.LPWSTR()
            assert security.ConvertSidToStringSidW(sid, ctypes.byref(text))
            try:
                return text.value
            finally:
                kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        finally:
            kernel.CloseHandle(token)
    finally:
        kernel.CloseHandle(process)


def run(command, work, name):
    result = subprocess.run(list(map(str, command)), check=True, capture_output=True,
                            text=True, timeout=40, cwd=work)
    (work / name).write_text(result.stdout + result.stderr, encoding='utf-8')
    return result.stdout


def collapsed(path, frame):
    rows = [line.rsplit(' ', 1) for line in path.read_text(encoding='utf-8').splitlines() if line]
    assert rows and all(int(value) > 0 for _, value in rows), path
    assert any(frame in stack and 'NativeSoftwareWorkload' in stack for stack, _ in rows), (path, frame)
    # Workload stacks must be complete; nested kernel faults elsewhere can lack ETW kernel parts.
    assert not any(frame in stack and '[etw_' in stack for stack, _ in rows), (path, 'partial workload stack')
    if frame == 'NativePageFaultWork':
        # As perf with the fault's user registers, user-mode faults carry no kernel frames.
        assert any(stack.endswith(';' + frame) for stack, _ in rows), (path, 'no user-mode fault leaf')
        assert not any(stack.split(f';{frame};', 1)[1].split(';')[0].endswith('_[k]')
                       for stack, _ in rows if f';{frame};' in stack), (path, 'kernel frames above a user-mode fault')
    return sum(int(value) for _, value in rows)


def validate_capture(index, event, period, work, java, classes, jar, broker_pid):
    base = work / f'{index}-{event}-p{period}'
    recording = Path(str(base) + '.jfr')
    frame = 'NativePageFaultWork' if event == 'page-faults' else 'NativeContextSwitchWork'
    native_total = collapsed(Path(str(recording) + '.collapsed'), frame)
    native_samples = collapsed(Path(str(base) + '.samples.collapsed'), frame)
    assert native_total == native_samples * period, (event, native_samples, native_total, period)

    counts = run([java, '-cp', classes, 'ReadCounters', recording,
                  str(recording) + '.collapsed', 'events', period, frame, 'NativeSoftwareWorkload'],
                 work, f'{index}.jfr-reader.log')
    samples, total = map(int, re.search(r'weightedSamples=(\d+) total=(\d+)', counts).groups())
    assert samples == native_samples and total == native_total == samples * period, (counts, native_samples, native_total)
    metrics_text = (work / f'{index}.metrics').read_text(encoding='utf-8')
    metrics = {}
    for line in metrics_text.splitlines():
        name, _, value = line.partition(' ')
        if re.fullmatch(r'-?\d+', value.strip()):
            metrics[name] = int(value)
    for name in ZERO_METRICS:
        assert metrics[name] == 0, (index, name, metrics[name])
    assert metrics['windows_etw_broker_pid'] == broker_pid, (index, metrics['windows_etw_broker_pid'], broker_pid)
    assert metrics['windows_etw_samples'] == metrics['samples_total'] == samples, (index, samples, metrics)
    assert metrics['windows_etw_software_matched_events'] >= total, (index, total, metrics)

    native_otlp = Path(str(base) + '.native.otlp')
    validate_otlp(native_otlp, frame, total, aggregated=True, expected_values=total,
                  expected_type=event, expected_unit='events')
    converted = Path(str(base) + '.converted.otlp')
    run([java, '-cp', jar, 'one.convert.Main', '--total', recording, converted], work, f'{index}.otlp-converter.log')
    validate_otlp(converted, frame, samples, expected_values=total,
                  expected_type=event, expected_unit='events')
    print(f'CAPTURE_VERIFIED index={index} event={event} period={period} samples={samples} total={total}', flush=True)
    return dict(index=index, event=event, period=period, samples=samples, total=total,
                softwareMatched=metrics['windows_etw_software_matched_events'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--self-test', action='store_true', help='Run bounded workloads only; no profiler, helper, or ETW')
    action.add_argument('--capture', action='store_true', help='Run eight serial broker captures from an elevated driver')
    parser.add_argument('--local', action='store_true', help='Capture in the elevated target instead of through the broker')
    parser.add_argument('--candidate', type=Path, help='Directory containing the matched DLL, helper, and CLI JAR')
    parser.add_argument('--java-home', type=Path, help='JDK used only for readers/converters')
    parser.add_argument('--output', type=Path, help='New evidence directory (must not exist)')
    args = parser.parse_args()
    fixture = args.fixture.resolve()
    assert fixture.is_file(), fixture
    integrity.require_elevated()
    work = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='asprof-native-software-'))
    if args.output:
        work.mkdir(parents=True)
    print('Evidence:', work, flush=True)
    if args.self_test:
        text = run([fixture, '--self-test'], work, 'self-test.log')
        assert 'NATIVE_SOFTWARE_SELF_TEST_OK medium=1 jvm=0' in text, text
        print(text, end='', flush=True)
        return
    if not args.candidate or not args.java_home:
        parser.error('--capture requires --candidate and --java-home')
    candidate = args.candidate.resolve()
    agent, helper, jar = [candidate / name for name in ['asyncProfiler.dll', 'asprof-helper.exe', 'asprof-windows.jar']]
    root = Path(__file__).resolve().parents[1]
    artifacts = [fixture, agent, helper, jar, Path(__file__).resolve(),
                 root / 'tests/native_software_application.cpp', root / 'tests/ReadCounters.java',
                 root / 'tests/read_otlp.py']
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts}
    manifest = json.loads((candidate / 'artifacts.json').read_text(encoding='utf-8'))
    for path in [agent, helper, jar]:
        assert before[str(path)].upper() == manifest[path.name].upper(), ('Candidate artifact mismatch', path)
    (work / 'inputs.json').write_text(json.dumps(before, indent=2), encoding='utf-8')
    classes = work / 'classes'
    classes.mkdir()
    java = args.java_home.resolve() / 'bin/java.exe'
    run([args.java_home.resolve() / 'bin/javac.exe', '--release', '17', '-d', classes,
         root / 'tests/ReadCounters.java'], work, 'reader-compile.log')
    previous_interval = query_interval(0)
    target = broker = None
    results = []
    streams = []
    try:
        with (work / 'target.err').open('w', encoding='utf-8') as errors, (work / 'broker.err').open('w', encoding='utf-8') as broker_errors:
            launch = [str(fixture), str(agent), str(work)]
            spawn = subprocess.Popen if args.local else integrity.deelevated_popen
            target = spawn([*launch, 'local'] if args.local else launch, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=errors, text=True, cwd=work)
            target_out = OutputPipe(target, work / 'target.log')
            streams.append(target_out)
            target_pid = int(target_out.receive('Native target ready', 15).removeprefix('READY '))
            broker_pid = 0
            if args.local:
                # The fixture verifies its own elevated token; its DACL denies this medium driver.
                print(f'ELEVATED_NATIVE_TARGET pid={target_pid}', flush=True)
            else:
                sid = user_sid(os.getpid())
                assert user_sid(target_pid) == sid, 'Target changed user'
                assert target_pid == target.pid and token_properties(target_pid) == (0, 0x2000), 'Target was not medium integrity'
                command = [str(helper), '--etw-broker', str(target_pid)]
                broker = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=broker_errors, text=True, cwd=work)
                broker_out = OutputPipe(broker, work / 'broker.log')
                streams.append(broker_out)
                ready = broker_out.until('ETW_BROKER_READY ', 20)
                broker_pid = int(re.search(r'pid=(\d+)', ready).group(1))
                assert f'target={target_pid} pipe=\\\\.\\pipe\\async-profiler-{target_pid}' in ready, ready
                assert token_properties(broker_pid) == (1, 0x3000), 'Helper was not high integrity'
                assert user_sid(broker_pid) == sid, 'Helper changed user'
                print(f'MEDIUM_NATIVE_TARGET pid={target_pid} elevatedSameUserHelper={broker_pid}', flush=True)
            for index, (event, period) in enumerate(CASES):
                target_out.exchange('capture', f'CAPTURE_DONE {index} {event} {period}')
                assert query_interval(0) == previous_interval, 'Software event capture changed timer interval'
                results.append(validate_capture(index, event, period, work, java, classes, jar, broker_pid))
                (work / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
            target.stdin.write('exit\n')
            target.stdin.flush()
            mode = 'local=1' if args.local else 'reconnects=8 medium=1'
            assert target_out.receive('Capture success') == f'NATIVE_SOFTWARE_CAPTURE_OK captures=8 {mode} jvm=0'
            assert target.wait(timeout=15) == 0
            if broker:
                assert broker.wait(timeout=20) == 0, 'Broker cleanup did not succeed'
    finally:
        if target and target.poll() is None:
            target.kill()
            target.wait(timeout=10)
        if broker and broker.poll() is None:
            # The helper owns a target-death watchdog and releases its capture lease.
            broker.wait(timeout=20)
        for stream in streams:
            stream.thread.join(timeout=5)
            assert not stream.thread.is_alive(), ('Output reader did not finish', stream.path)
        assert query_interval(0) == previous_interval, 'Timer interval was not preserved'
    after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts}
    assert before == after, 'A fixture/candidate artifact changed during the proof'
    (work / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(f'NATIVE_SOFTWARE_{"LOCAL" if args.local else "BROKER"}_OK captures=8 timerPreserved=1 inputsStable=1', flush=True)


if __name__ == '__main__':
    main()
