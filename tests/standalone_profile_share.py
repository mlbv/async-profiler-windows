# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Prove cross-process sharing of the machine-wide ETW timer/PMC configuration: concurrent local and brokered
captures, rejection of incompatible requests, owner termination, and restoration after the last owner."""
import argparse
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re
import subprocess
import time

from read_otlp import validate as validate_otlp
from standalone_etw import query_interval
from standalone_software_broker import OutputPipe

import integrity

ROOT = Path(__file__).resolve().parents[1]
ZERO_METRICS = ['windows_etw_failure', 'windows_etw_events_lost', 'windows_etw_buffers_lost',
                'windows_etw_realtime_buffers_lost', 'windows_etw_malformed_events', 'windows_etw_broker_cleanup_error']


class Context:
    def __init__(self, args):
        self.work = args.output.resolve()
        self.agent = args.agent.resolve()
        self.helper = self.agent.parent / 'asprof-helper.exe'
        self.jar = args.jar.resolve()
        self.fixture = args.fixture.resolve()
        self.java = args.java_home.resolve() / 'bin/java.exe'
        self.classes = self.work / 'classes'
        self.temporary = dict(TEMP=str(self.work), TMP=str(self.work))

    def elevated(self, *command):
        return subprocess.run(list(map(str, command)), capture_output=True, text=True,
                              timeout=60, stdin=subprocess.DEVNULL)

    def kill_elevated(self, pid):
        result = self.elevated('taskkill', '/F', '/PID', pid)
        assert result.returncode == 0, ('taskkill', pid, result.stdout, result.stderr)

    def sessions(self):
        result = self.elevated(ROOT / 'build/core/native/etw-control.exe', '--sessions')
        assert result.returncode == 0, result.stderr
        return result.stdout.splitlines()


def processes():
    class Entry(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('usage', wintypes.DWORD), ('pid', wintypes.DWORD),
                    ('heap', ctypes.c_size_t), ('module', wintypes.DWORD), ('threads', wintypes.DWORD),
                    ('parent', wintypes.DWORD), ('priority', ctypes.c_long), ('flags', wintypes.DWORD),
                    ('name', wintypes.WCHAR * 260)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    entry = Entry(size=ctypes.sizeof(Entry))
    result = []
    try:
        found = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            result.append((entry.pid, entry.parent, entry.name))
            found = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return result


def parent_pid(pid):
    return next(parent for child, parent, _ in processes() if child == pid)


def watchers(pid):
    return [child for child, parent, name in processes() if parent == pid and name.lower() == 'asprof-helper.exe']


def wait_exit(pids, seconds=30):
    """The owner's cleanup (normal, or its watcher's after termination) is complete once these processes exit."""
    deadline = time.monotonic() + seconds
    while any(pid in pids for pid, _, _ in processes()):
        assert time.monotonic() < deadline, ('Processes did not exit', pids)
        time.sleep(.05)


class Target:
    """A native or Java fixture capturing in its elevated process (local) or through its own broker."""

    def __init__(self, context, name, kind, mode):
        self.context, self.name, self.mode = context, name, mode
        if kind == 'native':
            command = [str(context.fixture), str(context.agent), str(context.work), mode]
        else:
            command = [str(context.java), '-XX:+UnlockDiagnosticVMOptions', '-XX:+WhiteBoxAPI',
                       '-Djava.io.tmpdir=' + str(context.work), '-cp', f'{context.classes};{context.jar}',
                       'ProfileShareJava', str(context.agent), str(context.work), mode]
        self.errors = (context.work / f'{name}.err').open('w', encoding='utf-8')
        streams = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors, text=True, cwd=context.work)
        if mode == 'local':
            self.process = subprocess.Popen(command, env=dict(os.environ, **context.temporary), **streams)
        else:
            self.process = integrity.deelevated_popen(command, env=context.temporary, **streams)
        self.out = OutputPipe(self.process, context.work / f'{name}.log')
        self.pid = int(self.out.until('READY ', 90).split()[1])
        self.broker = self.worker = None
        self.cleanup = []
        if mode == 'broker':
            self.broker_errors = (context.work / f'{name}.broker.err').open('w', encoding='utf-8')
            self.broker = subprocess.Popen([str(context.helper), '--etw-broker', str(self.pid)],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=self.broker_errors,
                                           text=True, cwd=context.work, env=dict(os.environ, **context.temporary))
            self.broker_out = OutputPipe(self.broker, context.work / f'{name}.broker.log')
            ready = self.broker_out.until('ETW_BROKER_READY ', 30)
            self.worker = int(re.search(r'pid=(\d+)', ready).group(1))

    def send(self, line):
        self.process.stdin.write(line + '\n')
        self.process.stdin.flush()

    def expect(self, *prefixes):
        deadline = time.monotonic() + 60
        while True:
            line = self.out.receive(self.name, deadline - time.monotonic())
            if line.startswith(prefixes):
                return line

    def start(self, capture, event, interval):
        self.send(f'start {capture} {event} {interval}')
        line = self.expect(f'STARTED {capture}', f'FAILED {capture} ')
        return line.removeprefix(f'FAILED {capture} ') if line.startswith('FAILED') else None

    def started(self, capture, event, interval):
        error = self.start(capture, event, interval)
        assert error is None, (self.name, capture, error)
        owner = self.worker or self.pid
        self.cleanup = watchers(owner) + ([self.worker] if self.worker else [])
        assert len(self.cleanup) == (2 if self.worker else 1), (self.name, self.cleanup)

    def stop(self, capture):
        self.send(f'stop {capture}')
        self.expect(f'STOPPED {capture}')

    def exit(self):
        self.send('exit')
        self.expect('EXITED')
        assert self.process.wait(timeout=30) == 0, (self.name, (self.context.work / f'{self.name}.err').read_text())
        if self.broker:
            assert self.broker.wait(timeout=30) == 0, (self.name, 'broker cleanup failed')
        self.close()

    def kill(self):
        """Terminates the capturing process: the elevated target, or a medium target whose worker then stops."""
        if self.mode == 'local':
            self.context.kill_elevated(self.pid)
        else:
            self.process.kill()
        self.process.wait(timeout=30)
        if self.broker:
            self.broker.wait(timeout=30)
        wait_exit(self.cleanup)
        self.close()

    def kill_worker(self):
        self.context.kill_elevated(self.worker)
        self.broker.wait(timeout=30)
        wait_exit(self.cleanup)

    def kill_launcher(self):
        self.context.kill_elevated(parent_pid(self.worker))
        self.broker.wait(timeout=30)
        wait_exit(self.cleanup)

    def close(self):
        for stream in [self.out] + ([self.broker_out] if self.broker else []):
            stream.thread.join(timeout=10)
        self.errors.close()
        if self.broker:
            self.broker_errors.close()


def gone(context, *targets):
    names = context.sessions()
    for target in targets:
        prefixes = [f'async-profiler-{target.pid}-'] + ([f'async-profiler-{target.worker}-'] if target.worker else [])
        assert not any(name.startswith(tuple(prefixes)) for name in names), (target.name, names)


def validate(context, capture, unit, kind, phases, period=None, value_type=None):
    """Matching JFR/collapsed/OTLP weights; returns per-phase collapsed totals and the capture's metrics."""
    base = context.work / capture
    rows = [line.rsplit(' ', 1) for line in (base.parent / f'{capture}.collapsed').read_text(encoding='utf-8').splitlines() if line]
    total = sum(int(value) for _, value in rows)
    prefix = 'shareWork' if kind == 'java' else 'ShareWork'
    reader = [str(context.java), '-cp', str(context.classes), 'ReadCounters', f'{base}.jfr', f'{base}.collapsed', unit]
    if period:
        reader.append(str(period))
    counts = subprocess.run(reader, check=True, capture_output=True, text=True).stdout
    samples, jfr_total = map(int, re.search(r'weightedSamples=(\d+) total=(\d+)', counts).groups())
    assert jfr_total == total, (capture, counts, total)
    metrics = {}
    for line in (base.parent / f'{capture}.metrics').read_text(encoding='utf-8').splitlines():
        name, _, value = line.partition(' ')
        if re.fullmatch(r'-?\d+', value.strip()):
            metrics[name] = int(value)
    for name in ZERO_METRICS:
        assert metrics[name] == 0, (capture, name, metrics[name])
    value_type = value_type or ('cpu' if unit == 'ns' else unit)
    frame = prefix + phases[0]
    validate_otlp(f'{base}.native.otlp', frame, aggregated=True, expected_values=total, expected_type=value_type, expected_unit=unit)
    subprocess.run([str(context.java), '-cp', str(context.jar), 'one.convert.Main', '--total', f'{base}.jfr', f'{base}.converted.otlp'],
                   check=True, capture_output=True)
    validate_otlp(f'{base}.converted.otlp', frame, samples, expected_values=total, expected_type=value_type,
                  expected_unit='nanoseconds' if unit == 'ns' else unit)
    totals = {phase: sum(int(value) for stack, value in rows if prefix + phase in stack) for phase in phases}
    print(f'CAPTURE_VERIFIED {capture} samples={samples} total={total} decimated={metrics["windows_etw_decimated_samples"]} '
          f'changes={metrics["windows_etw_interval_changes"]} ' + ' '.join(f'{k}={v}' for k, v in totals.items()), flush=True)
    return totals, metrics


def busy(result, *phases):
    # One busy thread for one second; a decimated capture moves up to one interval across each phase boundary.
    totals, _ = result
    for phase in phases:
        assert 700_000_000 <= totals[phase] <= 1_300_000_000, (phase, totals)
    return result


def decimated(result, changes):
    _, metrics = result
    assert metrics['windows_etw_decimated_samples'] > 0 and metrics['windows_etw_interval_changes'] == changes, metrics


def work(phase, *targets):
    for target in targets: target.send(f'work {phase} 1000')
    for target in targets: target.expect(f'WORKED {phase}')


def sources(agent):
    dll = ctypes.CDLL(str(agent))
    callback = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
    dll.asprof_init()
    dll.asprof_execute.argtypes = [ctypes.c_char_p, callback]
    dll.asprof_execute.restype = ctypes.c_char_p
    parts = []
    keep = callback(lambda address, size: parts.append(ctypes.string_at(address, size)))
    assert dll.asprof_execute(b'list', keep) is None
    listing = b''.join(parts).decode()
    return dict((name, int(identifier)) for name, identifier in re.findall(r'^\s+etw:(\S+)\s+source=(\d+)\s', listing, re.MULTILINE))


def local_pair(context, previous):
    a, b = Target(context, 'pair-a', 'native', 'local'), Target(context, 'pair-b', 'native', 'local')
    a.started('pair-a', 'etw:Timer', 2000000)
    assert query_interval(0) == 20000
    b.started('pair-b', 'etw:Timer', 2000000)
    work('before', a, b)
    a.stop('pair-a')
    a.exit()
    assert query_interval(0) == 20000, 'The remaining owner lost the shared interval'
    work('after', b)
    b.stop('pair-b')
    b.exit()
    assert query_interval(0) == previous, 'The last owner did not restore the interval'
    gone(context, a, b)
    busy(validate(context, 'pair-a', 'ns', 'native', ['Before'], 2000000), 'Before')
    busy(validate(context, 'pair-b', 'ns', 'native', ['Before', 'After'], 2000000), 'Before', 'After')
    print('SHARE_LOCAL_PAIR_OK', flush=True)


def timer_decimation(context, previous):
    """A 1 ms capture joins and leaves a running 100 ms capture, which decimates while the timer runs at 1 ms."""
    coarse, fine = Target(context, 'mixed-100ms', 'native', 'local'), Target(context, 'mixed-1ms', 'native', 'local')
    coarse.started('mixed-100ms', 'etw:Timer', 100000000)
    assert query_interval(0) == 1000000
    work('before', coarse)
    fine.started('mixed-1ms', 'etw:Timer', 1000000)
    assert query_interval(0) == 10000, 'The finer owner did not refine the shared interval'
    work('during', coarse, fine)
    fine.stop('mixed-1ms')
    fine.exit()
    assert query_interval(0) == 1000000, 'The finer owner leaving did not restore the coarser interval'
    work('after', coarse)
    coarse.stop('mixed-100ms')
    coarse.exit()
    assert query_interval(0) == previous
    gone(context, coarse, fine)
    busy(validate(context, 'mixed-1ms', 'ns', 'native', ['During'], 1000000), 'During')
    # About ten 100 ms timer samples per phase vary statistically; the 1 ms phase checks the decimated weight.
    result = busy(validate(context, 'mixed-100ms', 'ns', 'native', ['Before', 'During', 'After']), 'During')
    assert result[0]['Before'] > 0 and result[0]['After'] > 0, result
    decimated(result, 2)
    print('SHARE_TIMER_DECIMATION_OK intervals=1ms,100ms', flush=True)


def pmc_decimation(context, pmc, pmc_previous, other):
    coarse, fine = Target(context, 'pmc-10m', 'native', 'local'), Target(context, 'pmc-1m', 'native', 'local')
    rejected = Target(context, 'pmc-other', 'native', 'broker')
    coarse.started('pmc-10m', 'etw:InstructionRetired', 10000000)
    assert query_interval(pmc) == 10000000
    work('before', coarse)
    fine.started('pmc-1m', 'etw:InstructionRetired', 1000000)
    assert query_interval(pmc) == 1000000
    error = rejected.start('pmc-other', f'etw:{other}', '-')
    assert error == (f'Another async-profiler capture (pid {coarse.pid}) uses etw:InstructionRetired; '
                     'concurrent PMC captures must select the same overflow source'), error
    rejected.exit()
    work('during', coarse, fine)
    fine.stop('pmc-1m')
    fine.exit()
    assert query_interval(pmc) == 10000000
    work('after', coarse)
    coarse.stop('pmc-10m')
    coarse.exit()
    assert query_interval(pmc) == pmc_previous
    # The rejected broker capture had started its session before the share refused it.
    gone(context, coarse, fine, rejected)
    totals, _ = validate(context, 'pmc-1m', 'instructions', 'native', ['During'], 1000000)
    assert totals['During'] > 0
    result = validate(context, 'pmc-10m', 'instructions', 'native', ['Before', 'During', 'After'])
    assert all(value > 0 for value in result[0].values()), result
    decimated(result, 2)
    print('SHARE_PMC_DECIMATION_OK periods=1000000,10000000', flush=True)


def raw_pair(context):
    first, second = Target(context, 'raw-1', 'native', 'local'), Target(context, 'raw-2', 'native', 'local')
    third = Target(context, 'raw-3', 'native', 'local')
    first.started('raw-1', 'rc0', 1000000)
    # The second capture joins the first one's registered source rather than registering its own.
    second.started('raw-2', 'rc0', 4000000)
    registered = [name for name in sources(context.agent) if name.startswith('asprof-raw-')]
    assert len(registered) == 1, registered
    error = third.start('raw-3', 'rc2', '-')
    assert error == (f'Another async-profiler capture (pid {first.pid}) uses rc0; '
                     'concurrent PMC captures must select the same overflow source'), error
    third.exit()
    work('before', first, second)
    for target in (second, first):
        target.stop(target.name)
        target.exit()
    assert not any(name.startswith('asprof-raw-') for name in sources(context.agent)), 'The last owner did not remove the raw source'
    gone(context, first, second, third)
    assert validate(context, 'raw-1', 'events', 'native', ['Before'], 1000000, 'rc0')[0]['Before'] > 0
    # Without a transition, every decimated sample weighs exactly four shared periods.
    assert validate(context, 'raw-2', 'events', 'native', ['Before'], 4000000, 'rc0')[0]['Before'] > 0
    print('SHARE_RAW_PAIR_OK registeredSources=1', flush=True)


def local_broker_kill(context, previous):
    """Killing the finer local owner coarsens the interval under the brokered capture."""
    coarse, fine = Target(context, 'kill-broker', 'native', 'broker'), Target(context, 'kill-local', 'native', 'local')
    coarse.started('kill-broker', 'etw:Timer', 10000000)
    fine.started('kill-local', 'etw:Timer', 1000000)
    assert query_interval(0) == 10000
    work('before', coarse, fine)
    fine.kill()
    gone(context, fine)
    assert query_interval(0) == 100000, "The killed owner's watcher did not coarsen the interval"
    work('after', coarse)
    coarse.stop('kill-broker')
    coarse.exit()
    assert query_interval(0) == previous
    gone(context, coarse)
    decimated(busy(validate(context, 'kill-broker', 'ns', 'native', ['Before', 'After']), 'Before', 'After'), 2)
    print('SHARE_KILLED_OWNER_OK', flush=True)


def broker_jvms(context, previous):
    coarse, fine = Target(context, 'jvm-10ms', 'java', 'broker'), Target(context, 'jvm-1ms', 'java', 'broker')
    coarse.started('jvm-10ms', 'cpu', 10000000)
    work('before', coarse)
    fine.started('jvm-1ms', 'cpu', 1000000)
    assert query_interval(0) == 10000
    work('during', coarse, fine)
    fine.stop('jvm-1ms')
    fine.exit()
    assert query_interval(0) == 100000
    work('after', coarse)
    coarse.stop('jvm-10ms')
    coarse.exit()
    assert query_interval(0) == previous
    gone(context, coarse, fine)
    busy(validate(context, 'jvm-1ms', 'ns', 'java', ['During'], 1000000), 'During')
    decimated(busy(validate(context, 'jvm-10ms', 'ns', 'java', ['Before', 'During', 'After']), 'Before', 'During', 'After'), 2)
    print('SHARE_BROKER_JVMS_OK intervals=1ms,10ms', flush=True)


def last_owner_killed(context, previous):
    local = Target(context, 'last-local', 'native', 'local')
    targets = [Target(context, f'last-{name}', 'native', 'broker') for name in ['target', 'worker', 'launcher']]
    local.started('last-local', 'etw:Timer', 10000000)
    for index, target in enumerate(targets): target.started(target.name, 'etw:Timer', 1000000 * (index + 2))
    targets[0].kill()
    targets[1].kill_worker()
    targets[2].kill_launcher()
    for target in targets[1:]:
        target.process.kill()
        target.process.wait(timeout=30)
        target.close()
    gone(context, *targets)
    assert query_interval(0) == 100000, "Broker owner termination did not leave the local owner's interval"
    local.kill()
    assert query_interval(0) == previous, "The killed last owner's watcher did not restore the interval"
    gone(context, local)
    print('SHARE_LAST_OWNER_KILLED_OK targetKilled=1 workerKilled=1 launcherKilled=1', flush=True)


def set_interval(source, interval):
    class Luid(ctypes.Structure):
        _fields_ = [('low', wintypes.DWORD), ('high', wintypes.LONG)]

    class Privileges(ctypes.Structure):
        _fields_ = [('count', wintypes.DWORD), ('luid', Luid), ('attributes', wintypes.DWORD)]

    class Interval(ctypes.Structure):
        _fields_ = [('source', wintypes.ULONG), ('interval', wintypes.ULONG)]
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    advapi.TraceSetInformation.argtypes = [ctypes.c_uint64, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG]
    advapi.TraceSetInformation.restype = wintypes.ULONG
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    token, luid = wintypes.HANDLE(), Luid()
    assert advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x28, ctypes.byref(token))  # ADJUST_PRIVILEGES | QUERY
    assert advapi.LookupPrivilegeValueW(None, 'SeSystemProfilePrivilege', ctypes.byref(luid))
    privileges = Privileges(1, luid, 2)  # SE_PRIVILEGE_ENABLED
    assert advapi.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None) and ctypes.get_last_error() == 0
    kernel.CloseHandle(token)
    value = Interval(source, interval)
    assert advapi.TraceSetInformation(0, 5, ctypes.byref(value), ctypes.sizeof(value)) == 0  # TraceSampledProfileIntervalInfo


def everything_killed(context, previous):
    """A capture killed together with its watchdog takes the last registry handle, and the saved interval, with it.
    Its session keeps running and counts as an external profiler; once stopped, the next owner restores what it found."""
    killed = Target(context, 'all-killed', 'native', 'local')
    killed.started('all-killed', 'etw:Timer', 100000000)
    assert query_interval(0) == 1000000
    watchdog = killed.cleanup[0]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.restype = wintypes.HANDLE
    handle = kernel.OpenProcess(0x0800, False, watchdog)  # PROCESS_SUSPEND_RESUME
    assert handle and ctypes.WinDLL('ntdll').NtSuspendProcess(wintypes.HANDLE(handle)) == 0, ctypes.get_last_error()
    kernel.CloseHandle(wintypes.HANDLE(handle))
    killed.process.kill()
    killed.process.wait(timeout=30)
    context.kill_elevated(watchdog)
    wait_exit([watchdog])
    killed.close()
    names = [name for name in context.sessions() if name.startswith('async-profiler-')]
    assert len(names) == 1 and names[0].startswith(f'async-profiler-{killed.pid}-'), names
    try:
        assert query_interval(0) == 1000000, 'Nothing should have restored the interval'
        later = Target(context, 'all-later', 'native', 'local')
        error = later.start('all-later', 'etw:Timer', 2000000)
        assert error == 'Another ETW timer profiler uses 100000000ns; request that interval or leave interval unspecified', error
        later.exit()
        result = subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/logman.exe'), 'stop', names[0], '-ets'],
                                capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode == 0, result.stdout
        owner = Target(context, 'all-owner', 'native', 'local')
        owner.started('all-owner', 'etw:Timer', 2000000)
        assert query_interval(0) == 20000
        owner.stop('all-owner')
        owner.exit()
        assert query_interval(0) == 1000000, 'The next owner restores the interval it found'
    finally:
        set_interval(0, previous)
    gone(context, killed)
    print('SHARE_EVERYTHING_KILLED_OK sessionLeft=1 externalRefusal=1 leftoverRestored=1', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True, help='nativeProfileShareApplication.exe')
    parser.add_argument('--agent', type=Path, default=ROOT / 'build/core/native/asyncProfiler.dll')
    parser.add_argument('--jar', type=Path, default=ROOT / 'build/asprof-windows.jar')
    parser.add_argument('--output', type=Path, required=True, help='New evidence directory (must not exist)')
    args = parser.parse_args()
    integrity.require_elevated()
    context = Context(args)
    context.work.mkdir(parents=True)
    print('Evidence:', context.work, flush=True)
    context.classes.mkdir()
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-cp', str(context.jar), '-d', str(context.classes),
                    str(ROOT / 'tests/ProfileShareJava.java'), str(ROOT / 'tests/ReadCounters.java')], check=True)
    available = sources(context.agent)
    pmc = available['InstructionRetired']
    other = next(name for name, identifier in available.items() if identifier not in (0, pmc))
    previous, pmc_previous = query_interval(0), query_interval(pmc)
    print(f'BASELINE timer={previous} {pmc}={pmc_previous} other={other}', flush=True)
    local_pair(context, previous)
    timer_decimation(context, previous)
    pmc_decimation(context, pmc, pmc_previous, other)
    raw_pair(context)
    local_broker_kill(context, previous)
    broker_jvms(context, previous)
    last_owner_killed(context, previous)
    everything_killed(context, previous)
    print('PROFILE_SHARE_OK scenarios=8', flush=True)


if __name__ == '__main__':
    main()
