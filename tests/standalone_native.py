# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify Windows backends and reused upstream instrumentation."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import shutil
import threading
import time
from read_otlp import validate as validate_otlp

CPU_ACCOUNTING_THREAD = 'cpu-accounting-worker'


def main():
    memory_cases = {'memory', 'memory-debug', 'memory-expand', 'memory-base', 'memory-provider', 'memory-aligned'}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--reader-jdk', type=Path)
    parser.add_argument('--case', choices=['all', 'probe', *sorted(memory_cases), 'cpu-accounting', 'log-cleanup', 'oslocks', 'methods', 'latency', 'spans', 'api', 'startup', 'windows', 'etw-windows', 'reload', 'watches'], default='all')
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--cli-jar', type=Path, help='API JAR for the test programs and converters')
    parser.add_argument('--asprof', type=Path)
    parser.add_argument('--java-option', action='append', default=[])
    parser.add_argument('--runtime-directory', type=Path, action='append', default=[])
    parser.add_argument('--allocator-provider', type=Path, action='append', default=[])
    parser.add_argument('--provider-reloads', type=int, default=1)
    parser.add_argument('--cpu-invalid-targets', action='store_true')
    parser.add_argument('--cpu-rejections-only', action='store_true')
    parser.add_argument('--cpu-intervals', action='store_true')
    args = parser.parse_args()
    if args.cpu_intervals and (args.case != 'cpu-accounting' or args.cpu_invalid_targets or args.cpu_rejections_only):
        parser.error('--cpu-intervals requires --case cpu-accounting without rejection modes')
    if args.case == 'memory-provider' and not args.allocator_provider:
        parser.error('memory-provider requires --allocator-provider')
    if args.provider_reloads < 1:
        parser.error('--provider-reloads must be positive')
    args.allocator_provider *= args.provider_reloads
    root = Path(__file__).resolve().parents[1]
    agent = args.agent.resolve() if args.agent else root / 'build/core/native/asyncProfiler.dll'
    cli_jar = args.cli_jar.resolve() if args.cli_jar else root / 'build/asprof-windows.jar'
    asprof = args.asprof.resolve() if args.asprof else root / 'build/asprof.exe'
    work = Path(tempfile.mkdtemp(prefix='asprof-source-native-'))
    print('Evidence:', work, flush=True)
    java = args.java_home / 'bin/java.exe'
    reader_jdk = args.reader_jdk or args.java_home
    reader_java = reader_jdk / 'bin/java.exe'
    classes = work / 'classes'
    classes.mkdir()
    cli_temporary = work / 'cli-temporary'
    if args.cpu_rejections_only:
        cli_temporary.mkdir()
    names = ['NativeProbeFixture', 'ReadNativeProbe', 'NativeMemoryFixture', 'ReadNativeMemory',
             'NativeOsLockFixture', 'ReadNativeOsLocks', 'NativeMethodFixture', 'ReadNativeMethods',
             'NativeLatencyFixture', 'ReadNativeLatency', 'NativeSpanFixture', 'ReadNativeSpans', 'NativeApiFixture', 'ReadUserEvents',
             'NativeStartupFixture', 'ReadStartupProbe', 'NativeWindowFixture', 'ReadWindows', 'NativeReloadFixture', 'ReadReload', 'NativeWatchFixture', 'ReadWatches', 'ReadCpuAccounting', 'LogCleanupSmoke']
    if args.case in ['methods', 'latency']:
        name = 'NativeMethodFixture' if args.case == 'methods' else 'NativeLatencyFixture'
        reader = 'ReadNativeMethods' if args.case == 'methods' else 'ReadNativeLatency'
        subprocess.run([str(reader_jdk / 'bin/javac.exe'), '--release', '8', '-Xlint:-options', '-d', str(classes),
                        str(root / 'tests' / (name + '.java'))], check=True)
        subprocess.run([str(reader_jdk / 'bin/javac.exe'), '--release', '17', '-d', str(classes),
                        str(root / 'tests' / (reader + '.java'))], check=True)
    else:
        subprocess.run([str(reader_jdk / 'bin/javac.exe'), '--release', '17', '-cp', str(root / 'build/asprof-windows.jar'), '-d', str(classes),
                        *(str(root / 'tests' / (name + '.java')) for name in names)], check=True)
    fixture = args.fixture.resolve() if args.fixture else None
    if fixture is None and args.case in memory_cases | {'all', 'probe', 'cpu-accounting', 'log-cleanup', 'oslocks', 'api', 'startup', 'windows', 'etw-windows', 'reload', 'watches'}:
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                        str(root / 'tests/build_native_fixture.ps1'), '-JdkHome', str(args.java_home),
                        '-OutputDirectory', str(work / 'native'), '-DebugSymbols',
                        *(['-DebugRuntime'] if args.case == 'memory-debug' else [])], check=True)
        fixture = work / 'native/nativeMemoryFixture.dll'
    if args.case in ['all', 'reload']:
        for version in [1, 2]:
            subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                            str(root / 'tests/build_native_fixture.ps1'), '-JdkHome', str(args.java_home),
                            '-OutputDirectory', str(work / f'v{version}'), '-ReloadVersion', str(version), '-DebugSymbols'], check=True)

    def cli(*arguments, stdin=None, expected=0, agent_path=None):
        temporary = {'TMP': str(cli_temporary), 'TEMP': str(cli_temporary)} if args.cpu_rejections_only else {}
        result = subprocess.run([str(asprof), '--libpath', str(agent_path or agent), *map(str, arguments)],
                                input=stdin, capture_output=True, text=True, timeout=30, env=dict(os.environ, **temporary))
        with (work / 'commands.log').open('a', encoding='utf-8') as log:
            log.write(repr(arguments) + '\n' + result.stdout + result.stderr)
        assert result.returncode == expected, (arguments, result.stdout, result.stderr)
        return result.stderr if expected else result.stdout

    @contextmanager
    def target(name, *arguments):
        lines = queue.Queue()
        with (work / (name + '.err')).open('w') as errors:
            classpath = str(classes) + ';' + str(root / 'build/asprof-windows.jar')
            process = subprocess.Popen([str(java), *args.java_option, '-cp', classpath, name, *map(str, arguments)],
                                       cwd=work, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True,
                                       env=dict(os.environ, PATH=os.pathsep.join([*map(str, args.runtime_directory), os.environ.get('PATH', '')])))
            def collect():
                for line in process.stdout:
                    lines.put(line.strip())
                lines.put('EOF')
            threading.Thread(target=collect, daemon=True).start()
            def exchange(command):
                process.stdin.write(command + '\n')
                process.stdin.flush()
                return lines.get(timeout=25)
            try:
                assert lines.get(timeout=15).startswith('READY ')
                yield process, exchange
                assert process.poll() is None, 'Target JVM exited unexpectedly'
            finally:
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=10)

    def read(reader, output, *arguments):
        result = subprocess.run([str(reader_java), '-cp', str(classes), reader, str(output), *map(str, arguments)],
                                capture_output=True, text=True, timeout=20)
        (work / (output.stem + '-events.txt')).write_text(result.stdout + result.stderr, encoding='utf-8')
        assert result.returncode == 0, (reader, result.stdout, result.stderr)
        print(reader, result.stdout.splitlines()[-1], flush=True)
        return result.stdout

    if args.case in ['all', 'methods']:
        with target('NativeMethodFixture') as (process, exchange):
            output = work / 'methods.jfr'
            cli('start', process.pid, '--event', 'NativeMethodFixture.work', '--cstack', 'no', '-f', output)
            assert exchange('100') == 'DONE 100 3850'
            cli('stop', process.pid)
            read('ReadNativeMethods', output, 100)
            assert exchange('100') == 'DONE 100 3850'
            rejected = cli('start', process.pid, '--event', 'unrecognized-event', '-f', work / 'rejected.jfr', expected=200)
            assert '[ERROR] Native probe symbol was not found' in rejected, rejected
            assert exchange('100') == 'DONE 100 3850'
            # Keep a valid PE/export table but make Windows fail an actual DLL
            # dependency load. This must never be accepted as legacy success.
            broken = work / 'missing-dependency.dll'
            image = agent.read_bytes()
            assert b'KERNEL32.dll' in image
            broken.write_bytes(image.replace(b'KERNEL32.dll', b'BROKEN32.dll'))
            # As jattach, a library the JVM cannot load exits with -1 and the JVM's message (none on JDK 8).
            failed_load = cli('status', process.pid, agent_path=broken, expected=255)
            assert 'was not loaded' in failed_load or 'Target JVM failed to load' in failed_load, failed_load
            assert exchange('100') == 'DONE 100 3850'
    if args.case in ['all', 'startup']:
        for sync in ['none', 'profile']:
            output = work / f'startup-{sync}.jfr'
            synchronized = ['--jfrsync', sync] if sync == 'profile' else []
            text = cli('launch', '--event', 'NativeMethodFixture.work', '--cstack', 'no', *synchronized, '-f', output,
                       '--', '-cp', classes, 'NativeMethodFixture', stdin='100\nquit\n')
            assert 'DONE 100 3850' in text, text
            read('ReadNativeMethods', output, 100)
        output = work / 'startup-probe.jfr'
        text = cli('launch', '--probe', 'kernel32.dll!GetProcessId', '-f', output,
                   '--', '-cp', classes, 'NativeStartupFixture', fixture)
        assert 'STARTUP_OK' in text, text
        read('ReadStartupProbe', output)
    if args.case in ['all', 'spans']:
        with target('NativeSpanFixture', root / 'build/asprof-windows.jar') as (process, exchange):
            assert exchange('preload') == 'PRELOADED'
            for number, clock in enumerate(['monotonic', 'tsc']):
                output = work / f'spans-{number}.jfr'
                started = int(time.time() * 1000)
                cli('start', process.pid, '--event', 'NativeSpanFixture.work', '--cstack', 'no', '--clock', clock, '-f', output)
                assert exchange('run') == 'SPANS 135'
                assert exchange('loader') == 'LOADER_OK'
                cli('stop', process.pid)
                assert exchange('state') == 'STATE 1 0'
                read('ReadNativeSpans', output, started - 5000, int(time.time() * 1000) + 500)
                if number == 0:
                    converted = work / 'span-filter.otlp'
                    subprocess.run([str(java), '-cp', str(root / 'build/asprof-windows.jar'), 'one.convert.Main',
                                    '--tag', 'sampled.5', str(output), str(converted)], check=True, capture_output=True, text=True, timeout=20)
                    validate_otlp(converted, 'NativeSpanFixture.work', 1)
    if args.case in ['all', 'latency']:
        with target('NativeLatencyFixture') as (process, exchange):
            output = work / 'latency.jfr'
            cli('start', process.pid, '--trace', 'NativeLatencyFixture.work:5ms', '--cstack', 'no', '-f', output)
            assert exchange('10') == 'DONE 10 135'
            cli('stop', process.pid)
            read('ReadNativeLatency', output, 5, 5_000_000)
    if args.case in ['all', 'api']:
        otlp = work / 'api.otlp'
        with target('NativeApiFixture', fixture, otlp) as (process, exchange):
            output = work / 'user-events.jfr'
            cli('start', process.pid, '--event', 'wall', '--cstack', 'no', '-f', output)
            assert exchange('run') == 'API_OK'
            cli('stop', process.pid)
            read('ReadUserEvents', output)
            validate_otlp(otlp, 'NativeApiFixture.main', aggregated=True)
    if args.case == 'log-cleanup':
        result = subprocess.run([str(reader_java), '-cp', str(classes) + ';' + str(cli_jar), 'LogCleanupSmoke',
                                 str(agent), str(fixture), str(work)], cwd=work, capture_output=True, text=True, timeout=20)
        (work / 'log-cleanup.txt').write_text(result.stdout + result.stderr, encoding='utf-8')
        print(result.stdout, flush=True)
        assert result.returncode == 0, (result.stdout, result.stderr)
    if args.case == 'cpu-accounting' and args.cpu_intervals:
        reports = []
        with target('NativeMemoryFixture', fixture, 'early') as (process, exchange):
            for interval_ms in [1, 20, 80]:
                tid = int(exchange('cpu-create').removeprefix('CPU_TID '))
                interval = interval_ms * 1_000_000
                output = work / f'cpu-interval-{interval_ms}.jfr'
                collapsed = output.with_suffix('.collapsed')
                native_otlp = work / f'cpu-interval-{interval_ms}-native.otlp'
                converted_otlp = work / f'cpu-interval-{interval_ms}-converted.otlp'
                cli('start', process.pid, '--event', 'cpu', '--interval', f'{interval_ms}ms',
                    '--ithread', CPU_ACCOUNTING_THREAD, '--target-cpu', -1, '-f', output)
                counters = json.loads(exchange('cpu-run user 2500').removeprefix('CPU_TIMES '))
                assert counters[2] == 0, counters
                (work / f'cpu-interval-{interval_ms}-measured.json').write_text(
                    json.dumps(dict(tid=tid, interval_ns=interval, user_ns=counters[0], kernel_ns=counters[1])),
                    encoding='utf-8')
                cli('stop', process.pid)
                assert exchange('cpu-close') == 'CPU_CLOSED'
                cli('dump', process.pid, '-f', collapsed, '-o', 'collapsed', '--total')
                cli('dump', process.pid, '-f', native_otlp, '-o', 'otlp', '--total')
                summary = read('ReadCpuAccounting', output, tid, counters[0], counters[1], 'false', 'user', interval, collapsed)
                values = dict(item.split('=', 1) for item in summary.splitlines()[-1].split()[1:])
                samples, total = int(values['samples']), int(values['sampled'])
                validate_otlp(native_otlp, '', aggregated=True, expected_values=total,
                              expected_type='cpu', expected_unit='ns')
                converted = subprocess.run([str(reader_java), '-cp', str(cli_jar), 'one.convert.Main',
                                            '--total', str(output), str(converted_otlp)],
                                           capture_output=True, text=True, timeout=20)
                (work / f'cpu-interval-{interval_ms}-convert.txt').write_text(
                    converted.stdout + converted.stderr, encoding='utf-8')
                assert converted.returncode == 0, (converted.stdout, converted.stderr)
                validate_otlp(converted_otlp, '', samples, expected_values=total,
                              expected_type='cpu', expected_unit='nanoseconds')
                report = dict(interval_ns=interval, tid=tid, user_ns=counters[0], kernel_ns=counters[1],
                              measured_ns=counters[0] + counters[1], samples=samples, sampled_ns=total,
                              minimum_weight_ns=int(values['minimumWeight']), maximum_weight_ns=int(values['maximumWeight']))
                report['samples_per_cpu_second'] = samples * 1_000_000_000 / report['measured_ns']
                reports.append(report)
                (work / 'cpu-intervals.json').write_text(json.dumps(reports, indent=2), encoding='utf-8')
                print('CPU_INTERVAL', json.dumps(report, sort_keys=True), flush=True)
        first, last = reports[0], reports[-1]
        # The 80ms threshold polls at the engine's 50ms clamp. Compare observed
        # sample frequency per measured CPU time rather than duration/interval.
        assert last['samples'] * 2 <= first['samples'], reports
        assert last['samples_per_cpu_second'] * 2 <= first['samples_per_cpu_second'], reports
        print('CPU_INTERVALS_OK intervalsMs=1,20,80 materialReduction=1 totalsPreserved=1', flush=True)
    if args.case == 'cpu-accounting' and not args.cpu_intervals:
        with target('NativeMemoryFixture', fixture, 'early') as (process, exchange):
            tid = int(exchange('cpu-create').removeprefix('CPU_TID '))
            if args.cpu_invalid_targets or args.cpu_rejections_only:
                # Malformed indexes are argument errors; a well-formed absent CPU fails the start command.
                for index, (value, status) in enumerate([('garbage', 100), ('', 100), ('-2', 100), ('2147483648', 100),
                                                         ('2147483647', 200)]):
                    error = cli('start', process.pid, '--event', 'cpu', '--target-cpu', value,
                                '-f', work / f'invalid-cpu-{index}.jfr', expected=status)
                    assert 'target' in error.lower() and 'cpu' in error.lower(), error
                    print('CPU_REJECTION', repr(value), error.strip(), flush=True)
                    if args.cpu_rejections_only:
                        leftovers = list(cli_temporary.glob('asprof-log.*'))
                        assert not leftovers, ('Temporary agent logs remain after native rejection', leftovers)
                    assert 'not active' in cli('status', process.pid)
            if args.cpu_rejections_only:
                assert exchange('cpu-close') == 'CPU_CLOSED'
                print('CPU_REJECTIONS_OK', flush=True)
                return
            for number, (kind, user_only) in enumerate([('kernel', False), ('kernel', True), ('user', True)]):
                output = work / f'cpu-accounting-{number}.jfr'
                cli('start', process.pid, '--event', 'cpu', '--interval', '1ms', '--ithread', CPU_ACCOUNTING_THREAD, '--target-cpu', -1,
                    *(['--all-user'] if user_only else []), '-f', output)
                counters = json.loads(exchange(f'cpu-run {kind} 2500').removeprefix('CPU_TIMES '))
                assert counters[2] == 0, counters
                cli('stop', process.pid)
                read('ReadCpuAccounting', output, tid, counters[0], counters[1], str(user_only).lower(), kind)
            assert exchange('cpu-close') == 'CPU_CLOSED'
    if args.case in memory_cases | {'all'}:
        with target('NativeMemoryFixture', fixture, 'early') as (process, exchange):
            commands = {'memory-debug': ['debug', 'expand'], 'memory-expand': ['expand'], 'memory-base': ['base'],
                        'memory-provider': ['provider'], 'memory-aligned': ['aligned']}.get(args.case, ['run'])
            for command in commands:
                output = work / ('memory.jfr' if command == 'run' else f'memory-{command}.jfr')
                cli('start', process.pid, '--event', 'nativemem', '--nativemem', 1, '-f', output)
                if command == 'provider':
                    pointers = []
                    for phase, provider in enumerate(args.allocator_provider):
                        pointers.extend(json.loads(exchange(f'provider {phase} {provider.resolve()}').removeprefix('POINTERS ')))
                else:
                    pointers = json.loads(exchange(command).removeprefix('POINTERS '))
                cli('stop', process.pid)
                expected = []
                if command == 'debug':
                    expected = ['65111,130223,7063,11099,65543,131101,196617,49169,98327,163895,90023,30021,81931,73753,61463,114689,12289']
                elif command == 'expand':
                    expected = ['262147,131081', '1,2']
                elif command == 'base':
                    expected = ['65537,131071,7063,98317,49157']
                elif command == 'provider':
                    expected_sizes = []
                    for phase, provider in enumerate(args.allocator_provider):
                        expected_sizes.extend((65537 + phase * 4096, 131071 + phase * 4096, 7 * (1009 + phase)))
                        if provider.name != 'allocator-forwarder.dll':
                            expected_sizes.extend((65024 + phase * 64, 70001 + phase * 17))
                    expected = [','.join(map(str, expected_sizes))]
                elif command == 'aligned':
                    expected = ['65543,131101,196617,49169,98327,163895,70049,110077,81931,73753,61463']
                read('ReadNativeMemory', output, ','.join(map(str, pointers)), 'all', *expected)
    if args.case in ['all', 'oslocks']:
        with target('NativeOsLockFixture', fixture) as (process, exchange):
            output = work / 'oslocks.jfr'
            cli('start', process.pid, '--nativelock', '1ms', '-f', output)
            addresses = json.loads(exchange('run').removeprefix('LOCKS '))
            cli('stop', process.pid)
            read('ReadNativeOsLocks', output, ','.join(map(str, addresses)))
    if args.case in ['all', 'probe']:
        with target('NativeProbeFixture', fixture) as (process, exchange):
            for interval, count in [(1, 140), (5, 28)]:
                output = work / f'probe-{interval}.jfr'
                cli('start', process.pid, '--probe', 'nativeMemoryFixture.dll!ProbeWork', '--interval', interval, '-f', output)
                assert exchange('run') == 'RESULT 18170'
                cli('stop', process.pid)
                read('ReadNativeProbe', output, count)
                metrics = cli('metrics', process.pid)
                assert 'windows_probe_calls 140\n' in metrics, metrics
                assert 'windows_probe_failed 0\n' in metrics and 'windows_probe_dropped 0\n' in metrics, metrics
                assert exchange('run') == 'RESULT 18170'
            output = work / 'probe-churn.jfr'
            cli('start', process.pid, '--probe', 'nativeMemoryFixture.dll!ProbeWork', '--interval', 1000, '-f', output)
            assert exchange('churn') == 'CHURNED'
            cli('stop', process.pid)
            # perf_event_open binds each period counter to one TID. Each of the
            # 4,200 new workers makes only 40 calls, below this period of 1,000.
            read('ReadNativeProbe', output, 0, 'workers')
            metrics = cli('metrics', process.pid)
            assert 'windows_probe_calls 168000\n' in metrics and 'windows_probe_samples 0\n' in metrics, metrics
            assert 'windows_probe_failed 0\n' in metrics and 'windows_probe_dropped 0\n' in metrics, metrics
            assert 'windows_breakpoint_targets 0\n' in metrics, metrics
    if args.case in ['all', 'windows']:
        with target('NativeWindowFixture', fixture) as (process, exchange):
            begin = ['--begin', 'nativeMemoryFixture.dll!WindowBegin']
            end = ['--end', 'nativeMemoryFixture.dll!WindowEnd']
            for mode, flags, samples, windows, bounds, symbol in [
                    ('bounded', begin + end, 100, 5, 'bounded', 'ProbeWork'),
                    ('nostop', begin + end + ['--nostop'], 200, 5, 'unbounded', 'ProbeWork'),
                    ('begin', begin, 190, 0, 'unbounded', 'ProbeWork'),
                    ('end', end, 30, 1, 'bounded', 'ProbeWork'),
                    ('shared', begin + end, 5, 5, 'bounded', 'WindowBegin')]:
                output = work / f'window-{mode}.jfr'
                cli('start', process.pid, '--probe', 'nativeMemoryFixture.dll!' + symbol, '-f', output, *flags)
                assert exchange('run') == 'RESULT 5600'
                cli('stop', process.pid)
                read('ReadWindows', output, samples, windows, bounds)
                metrics = cli('metrics', process.pid)
                assert 'windows_breakpoint_targets 0\n' in metrics and 'windows_probe_failed 0\n' in metrics, metrics
                assert exchange('run') == 'RESULT 5600'
            for event in ['cpu', 'wall']:
                output = work / f'window-{event}.jfr'
                cli('start', process.pid, '--event', event, '--interval', '1ms', '-f', output, *begin, *end)
                assert exchange('cpu') == 'RESULT 5600'
                cli('stop', process.pid)
                read('ReadWindows', output, -1, 5, 'bounded')
            output = work / 'window-private.jfr'
            cli('start', process.pid, '--probe', 'nativeMemoryFixture.dll!ProbeWork', '-f', output,
                '--begin', 'nativeMemoryFixture.dll!ProfilerFixture::PrivateBoundary::begin',
                '--end', 'nativeMemoryFixture.dll!ProfilerFixture::PrivateBoundary::end')
            assert exchange('private') == 'RESULT 5600'
            cli('stop', process.pid)
            read('ReadWindows', output, 100, 5, 'bounded')
            output = work / 'window-parallel.jfr'
            cli('start', process.pid, '--probe', 'nativeMemoryFixture.dll!ProbeWork', '-f', output, *begin, *end)
            assert exchange('parallel') == 'RESULT 89600'
            cli('stop', process.pid)
            read('ReadWindows', output, -2, -1, 'bounded')
    if args.case == 'etw-windows':
        with target('NativeWindowFixture', fixture) as (process, exchange):
            begin = ['--begin', 'nativeMemoryFixture.dll!WindowBegin']
            end = ['--end', 'nativeMemoryFixture.dll!WindowEnd']
            for event, interval in [('etw:Timer', '1ms'), ('etw:InstructionRetired', '1000000')]:
                for mode, flags, samples, windows, bounds in [
                        ('bounded', begin + end, -1, 5, 'bounded'),
                        ('nostop', begin + end + ['--nostop'], -3, 5, 'unbounded'),
                        ('begin', begin, -3, 0, 'unbounded'),
                        ('end', end, -3, 1, 'bounded')]:
                    output = work / f'window-{event.split(":")[1]}-{mode}.jfr'
                    cli('start', process.pid, '--event', event, '--interval', interval, '-f', output, *flags)
                    assert exchange('cpu') == 'RESULT 5600'
                    cli('stop', process.pid)
                    metrics = cli('metrics', process.pid)
                    with (work / 'etw-window-metrics.log').open('a', encoding='utf-8') as log:
                        log.write(f'{event} {mode}\n{metrics}\n')
                    assert 'windows_etw_failure 0\n' in metrics and 'windows_etw_window_overflow 0\n' in metrics, metrics
                    assert 'windows_breakpoint_targets 0\n' in metrics, metrics
                    if mode in ['bounded', 'end']:
                        assert 'windows_etw_outside_windows 0\n' not in metrics, metrics
                    read('ReadWindows', output, samples, windows, bounds)
    if args.case in ['all', 'watches']:
        with target('NativeWatchFixture', fixture) as (process, exchange):
            address = exchange('address').removeprefix('ADDRESS ')
            function = exchange('function').removeprefix('ADDRESS ')
            for mode, length, interval, calls, count in [('w', 1, 1, 140, 140), ('w', 2, 1, 140, 140), ('w', 4, 1, 140, 140),
                                                         ('rw', 8, 1, 280, 280), ('w', 8, 5, 140, 28), ('x', 1, 1, 2, 2)]:
                watched = function if mode == 'x' else address
                output = work / f'watch-{mode}-{length}-{interval}.jfr'
                cli('start', process.pid, '--event', f'mem:0x{watched}:{length}:{mode}', '--interval', interval, '-f', output)
                assert exchange('run') == 'RESULT 5730'
                cli('stop', process.pid)
                read('ReadWatches', output, count, interval)
                metrics = cli('metrics', process.pid)
                assert f'windows_probe_calls {calls}\n' in metrics and 'windows_probe_failed 0\n' in metrics, metrics
                assert exchange('run') == 'RESULT 5730'
            error = cli('start', process.pid, '--event', f'mem:0x{address}:8:r', '-f', work / 'watch-invalid.jfr', expected=200)
            assert 'read-only mode is unavailable' in error, error
            error = cli('start', process.pid, '--event', f'mem:0x{int(address, 16) + 1:x}:8:w',
                        '-f', work / 'watch-unaligned.jfr', expected=200)
            assert 'must be aligned to its length' in error, error
    if args.case in ['all', 'reload']:
        active = work / 'active'
        active.mkdir()
        dll = active / 'reloadTarget.dll'
        with target('NativeReloadFixture', fixture) as (process, exchange):
            addresses = []
            for version, name, value, previous in [(1, 'VersionOne', 15050, 'VersionTwo'), (2, 'VersionTwo', 25150, 'VersionOne')]:
                shutil.copyfile(work / f'v{version}/reloadTarget.dll', dll)
                loaded = json.loads(exchange('load ' + str(dll)).removeprefix('LOADED '))
                addresses.append(loaded)
                if version == 2:
                    error = cli('start', process.pid, '--probe', 'reloadTarget.dll!ReloadFixture::VersionOne::work',
                                '-f', work / 'retired.jfr', expected=200)
                    assert 'Native probe symbol was not found' in error, error
                output = work / f'reload-{version}.jfr'
                cli('start', process.pid, '--probe', f'reloadTarget.dll!ReloadFixture::{name}::work', '-f', output)
                assert exchange('100') == f'RESULT {value}'
                assert exchange('unload') == 'PRESENT true', 'A target DLL was not retained while its breakpoint was active'
                cli('stop', process.pid)
                assert exchange('present') == 'PRESENT false', 'A stopped breakpoint retained the target DLL'
                read('ReadReload', output, name, previous, 100)
            assert addresses[0][0] == addresses[1][0] and addresses[0][1] != addresses[1][1], addresses
            shutil.copyfile(work / 'v1/reloadTarget.dll', dll)
            assert exchange('load ' + str(dll)).startswith('LOADED ')
            output = work / 'loader-lock.jfr'
            cli('start', process.pid, '--event', 'cpu', '--interval', '1ms', '-f', output)
            assert exchange('thread') == 'THREAD_OK'
            cli('stop', process.pid)
            read('ReadReload', output, 'ReloadThreadAttachBusy', '-', -1)
            assert exchange('unload') == 'PRESENT false'
            output = work / 'reload-live.jfr'
            cli('start', process.pid, '--event', 'cpu', '--interval', '1ms', '-f', output)
            for version in [1, 2, 1]:
                shutil.copyfile(work / f'v{version}/reloadTarget.dll', dll)
                assert exchange('load ' + str(dll)).startswith('LOADED ')
                assert exchange('timed 500').startswith('TIMED ')
                assert exchange('unload') == 'PRESENT false'
            before = dict(line.split(' ', 1) for line in cli('metrics', process.pid).splitlines())
            for _ in range(20):
                assert exchange('load ' + str(dll)).startswith('LOADED ')
                assert exchange('unload') == 'PRESENT false'
            after = dict(line.split(' ', 1) for line in cli('metrics', process.pid).splitlines())
            assert before['windows_native_versions'] == after['windows_native_versions'], (before, after)
            cli('stop', process.pid)
            read('ReadReload', output, 'VersionOne', '-', -1)
            read('ReadReload', output, 'VersionTwo', '-', -1)
    print('PASS source-built backends:', args.case, flush=True)


if __name__ == '__main__':
    main()
