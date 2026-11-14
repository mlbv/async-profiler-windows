# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Validate asprof.exe and jfrconv.cmd: parsing, attach, snapshots, launch, jattach actions and conversion."""
import argparse
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from read_otlp import validate as validate_otlp
from standalone_software_broker import OutputPipe

import integrity


def broker_pipes():
    return sorted(name for name in os.listdir('\\\\.\\pipe\\') if name.startswith('async-profiler-asprof-'))


@contextmanager
def frozen(pid):
    """Attaches as a debugger that handles no debug events: no thread of the process runs, new ones included."""
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    assert kernel32.DebugActiveProcess(pid), ctypes.get_last_error()
    try:
        assert kernel32.DebugSetProcessKillOnExit(False), ctypes.get_last_error()
        yield
    finally:
        assert kernel32.DebugActiveProcessStop(pid), ctypes.get_last_error()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--unicode-path', action='store_true')
    parser.add_argument('--agent', type=Path, help='Profiler DLL; asprof-helper.exe must be beside it')
    parser.add_argument('--asprof', type=Path, help='asprof.exe')
    parser.add_argument('--jar', type=Path, help='asprof-windows.jar for jfrconv.cmd')
    parser.add_argument('--jfr-converter', type=Path, help='Also check the optional native converter (build.ps1 -NativeImage)')
    parser.add_argument('--broker', action='store_true',
                        help='Also run elevated --fdtransfer captures (live ETW: use the exclusive lock)')
    args = parser.parse_args()
    integrity.require_elevated()
    root = Path(__file__).resolve().parents[1]
    asprof = (args.asprof or root / 'build/asprof.exe').resolve()
    jar = (args.jar or root / 'build/asprof-windows.jar').resolve()
    agent = (args.agent or root / 'build/asyncProfiler.dll').resolve()
    work = Path(tempfile.mkdtemp(prefix='asprof-standalone-cli-'))
    recordings = work / '同步 𠮷' if args.unicode_path else work
    recordings.mkdir(exist_ok=True)
    print('Evidence:', work, flush=True)
    java = args.java_home / 'bin/java.exe'
    # JVM launch uses JAVA_HOME; the DLL lookup checks are independent of the caller's environment.
    os.environ['JAVA_HOME'] = str(args.java_home)
    os.environ.pop('ASYNC_PROFILER_DLL', None)
    classes = work / 'classes'
    classes.mkdir()
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8', '-d', str(classes),
                    *(str(root / 'tests' / name) for name in ['Fixture.java', 'CliTemplateTarget.java', 'ReadRecording.java'])],
                   check=True)
    subprocess.run(['cmake', '--build', str(root / 'build/core/native'), '--target', 'asprofOptionsTest'], check=True)
    options = subprocess.run([str(root / 'build/core/native/asprof-options-test.exe')], capture_output=True, text=True, timeout=30)
    print(options.stdout, options.stderr, flush=True)
    assert options.returncode == 0 and 'ASPROF_OPTIONS_OK' in options.stdout, options

    # The CLI and its target run as an ordinary user would run them; only broker captures need an elevated asprof.
    ordinary = dict(JAVA_HOME=str(args.java_home), TEMP=str(work), TMP=str(work), ASYNC_PROFILER_DLL=None)

    def run(command, expected=0, elevated=False, env=None):
        streams = dict(cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                       encoding='utf-8', errors='replace')
        process = (subprocess.Popen(command, **streams) if elevated
                   else integrity.deelevated_popen(command, env={**ordinary, **(env or {})}, **streams))
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            raise
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        print(command, result.returncode, result.stdout[-3000:], result.stderr[-3000:], flush=True)
        assert result.returncode == expected, (command, expected, result.returncode)
        return result

    def cli(*arguments, expected=0, elevated=False):
        return run([str(asprof), '--libpath', str(agent), *map(str, arguments)], expected, elevated)

    def read(path, started=None):
        bounds = [] if started is None else [str(started - 5000), str(int(time.time() * 1000) + 500)]
        result = subprocess.run([str(java), '-cp', str(classes), 'ReadRecording', str(path), *bounds],
                                capture_output=True, text=True, timeout=15)
        print(path.name, result.stdout, result.stderr, flush=True)
        result.check_returncode()
        return dict(line.split('=', 1) for line in result.stdout.splitlines())

    usage = cli('-h')
    assert usage.stdout.startswith('Usage: asprof [action] [options] <pid>\n'), usage.stdout
    assert cli(expected=1).stdout == usage.stdout
    version = re.fullmatch(r'Async-profiler (\S+) built on \w{3} [ \d]\d \d{4}\n', cli('-v').stdout).group(1)
    inspection = json.loads(cli('inspect').stdout)
    assert inspection['version'] == version and inspection['machine'] == 'amd64', inspection
    assert cli('--bogus', '1', expected=1).stderr == 'Unrecognized option: --bogus\n'
    assert cli('-f', 'a,b.jfr', '1', expected=1).stderr == 'Option values cannot contain commas: a,b.jfr\n'

    package = work / 'package'
    package.mkdir()
    for source in [agent, agent.parent / 'asprof-helper.exe', asprof, jar, root / 'jfrconv.cmd']:
        shutil.copy2(source, package / {agent: 'asyncProfiler.dll', jar: 'asprof-windows.jar'}.get(source, source.name))
    configured = work / 'configured'
    configured.mkdir()
    shutil.copy2(asprof, configured / 'asprof.exe')
    converters = [package / 'jfrconv.cmd', *([args.jfr_converter.resolve()] if args.jfr_converter else [])]
    for converter in converters:
        assert re.fullmatch(rf'JFR converter {re.escape(version)} built on \w{{3}} \d{{2}} \d{{4}}\n', run([str(converter), '-v']).stdout), converter

    with (work / 'target.err').open('w') as errors:
        target = integrity.deelevated_popen([str(java), '-cp', str(classes), 'CliTemplateTarget', '120'], cwd=work, env=ordinary,
                                  stdout=subprocess.PIPE, stderr=errors, text=True)
        target_output = OutputPipe(target, work / 'target.out')
        try:
            assert target_output.receive('Java fixture ready', 10) == f'READY {target.pid}'
            pid = str(target.pid)
            assert cli('status', pid).stdout == 'Profiler is not active\n'
            # PID lookup by the application name as jps shows it, and DLL lookup without --libpath.
            assert run([str(package / 'asprof.exe'), 'status', 'CliTemplateTarget']).stdout == 'Profiler is not active\n'
            assert f'{pid}\tCliTemplateTarget 120\n' in run([str(asprof), 'ps']).stdout
            missing = run([str(configured / 'asprof.exe'), 'status', pid], expected=1)
            assert 'Profiler library not found' in missing.stderr, missing.stderr
            run([str(configured / 'asprof.exe'), 'status', pid], env=dict(ASYNC_PROFILER_DLL=str(agent)))
            (configured / 'profiler.properties').write_text('agent=' + agent.as_posix() + '\n', encoding='utf-8')
            run([str(configured / 'asprof.exe'), 'status', pid])

            rejected = cli('start', '--fdtransfer', '-e', 'etw:Timer', pid, expected=1)
            assert rejected.stderr == '--fdtransfer requires an elevated asprof: the ETW broker needs administrator privileges\n', rejected.stderr
            assert cli('status', pid).stdout == 'Profiler is not active\n'

            # Existing output files are replaced, as upstream does.
            for name in ['sync.jfr', 'snapshot.jfr', 'collect.html']:
                (recordings / name).write_bytes(b'existing output')
            started = int(time.time() * 1000)
            started_text = cli('start', '--jfrsync', 'profile', '-f', recordings / 'sync.jfr', pid).stderr
            assert started_text.endswith('Profiling started\n'), started_text
            time.sleep(1)  # Native and JVM events must accumulate before the live snapshot.
            snapshot = cli('dump', '-f', recordings / 'snapshot.jfr', pid)
            assert snapshot.stdout == '' and not list(recordings.glob('asprof-snapshot-*')), snapshot
            assert cli('status', pid).stdout.startswith('Profiling is running for ')
            assert '--- Execution profile ---' in cli('stop', pid).stdout
            metrics = cli('metrics', pid).stdout
            assert 'windows_import_failed 0\n' in metrics, metrics
            for name in ['sync.jfr', 'snapshot.jfr']:
                # Both native-first snapshots and JVM-first finalized recordings must share the same clock.
                counts = read(recordings / name, started)
                assert counts['fixtureStack'] == 'true' and int(counts.get('wrapper.Probe', 0)) > 0, counts
            assert 'Basic events:\n' in cli('list', pid).stdout

            cli('start', '-e', 'wall', '-i', '5ms', '-f', recordings / 'wall.collapsed', pid)
            time.sleep(1)  # The live workload must accumulate sleeping and runnable wall samples.
            for name, selector in [('included', '-I'), ('excluded', '-X')]:
                cli('dump', '-f', recordings / f'{name}-%p.collapsed', '--total', '-s', selector, 'Fixture.busy', pid)
                rows = (recordings / f'{name}-{pid}.collapsed').read_text(encoding='utf-8').splitlines()
                assert rows and all(int(line.rsplit(' ', 1)[1]) > 0 for line in rows), rows
                if name == 'included':
                    assert all('Fixture.busy' in line for line in rows), rows
                else:
                    assert all('Fixture.busy' not in line for line in rows), rows
                    assert any('Fixture.' in line for line in rows), rows
            flat = recordings / 'top.txt'
            cli('stop', '-f', flat, '-o', 'flat=1', '-I', 'Fixture.*', pid)
            flat_rows = [line for line in flat.read_text(encoding='utf-8').splitlines()
                         if re.match(r'^\s*\d+\s+\d+\.\d+%\s+\d+\s+', line)]
            assert len(flat_rows) == 1, flat.read_text(encoding='utf-8')

            collected = cli('-d', 1, '-e', 'cpu', '-i', '1ms', '--cstack', 'no', '-o', 'collapsed', pid)
            assert 'Profiling for 1 seconds\nDone\n' in collected.stderr, collected.stderr
            rows = collected.stdout.splitlines()
            assert rows and any('Fixture.busy' in row for row in rows) and all(int(row.rsplit(' ', 1)[1]) > 0 for row in rows), rows
            assert not list(work.glob(f'asprof*.*.{pid}')), 'Temporary output or log remained'
            # Ctrl+C ends collect early; asprof still stops the profiler and prints the profile.
            interrupted = work / 'interrupted'
            hidden = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=0)
            begun = time.monotonic()
            interrupter = integrity.deelevated_popen([sys.executable, str(root / 'tests/console_interrupt.py'), str(interrupted), '3',
                                                      str(asprof), '--libpath', str(agent), '-d', '30', '-o', 'collapsed', pid],
                                                     env=ordinary, creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=hidden)
            assert interrupter.wait(timeout=60) == 0
            assert time.monotonic() - begun < 20
            assert interrupted.with_suffix('.exit').read_text(encoding='ascii') == '0'
            assert 'Profiling for 30 seconds\nInterrupted\n' in interrupted.with_suffix('.stderr').read_text(encoding='utf-8')
            assert 'Fixture.busy' in interrupted.with_suffix('.stdout').read_text(encoding='utf-8')
            assert cli('status', pid).stdout == 'Profiler is not active\n'
            cli('-d', 1, '-f', recordings / 'collect.html', '--title', 'CLI, collect', pid)
            html = (recordings / 'collect.html').read_text(encoding='utf-8')
            assert '<canvas' in html and 'CLI&#44; collect' in html, html[:500]
            # As upstream, stopping an inactive profiler dumps its last profile.
            last = cli('stop', '-o', 'collapsed', '--total', pid).stdout
            assert any('Fixture.busy' in row for row in last.splitlines()), last

            for event in ['bus-cycles', 'L1-dcache-load-misses', 'LLC-load-misses', 'dTLB-load-misses']:
                unavailable = cli('start', '-e', event, '-f', recordings / 'unavailable.jfr', pid, expected=200)
                assert 'Windows ETW profile source is unavailable' in unavailable.stderr, unavailable.stderr
            # Software events need ETW: an unelevated target without a broker is rejected.
            switches = cli('start', '-e', 'context-switches', '-f', recordings / 'switch.jfr', pid, expected=200)
            assert 'ETW capture requires SeSystemProfilePrivilege' in switches.stderr, switches.stderr
            assert cli('status', pid).stdout == 'Profiler is not active\n'
            unrecognized = cli('start', '-e', 'unrecognized-event', '-f', work / 'bad.jfr', pid, expected=200)
            assert '[ERROR] Native probe symbol was not found' in unrecognized.stderr, unrecognized.stderr
            # Only a stop without dump options reports the inactive profiler.
            assert 'return code: 200' in cli('load', pid, agent, 'true', 'stop', expected=200).stdout

            version = cli('jcmd', pid, 'VM.version')
            assert version.stdout.startswith('Connected to remote JVM\nJVM response code = 0\n') and 'JDK' in version.stdout, version.stdout
            failed = cli('jcmd', pid, 'VM.bogus', expected=255).stdout
            assert failed.startswith('Connected to remote JVM\nJVM response code = -1\n') and 'Unknown diagnostic command' in failed, failed
            assert 'Full thread dump' in cli('threaddump', pid).stdout
            status = work / 'loaded-status.txt'
            loaded = cli('load', pid, agent, 'true', f'status,file={status}')
            assert loaded.stdout == 'Connected to remote JVM\nJVM response code = 0\nreturn code: 0\n\n', loaded.stdout
            assert status.read_text(encoding='utf-8') == 'Profiler is not active\n'
            assert 'return code: 200' in cli('load', pid, agent, 'true', 'start,event=unrecognized-event', expected=200).stdout
            # A request the target does not run fails after jattach's 6-second budget for the attach listener, and the
            # resumed target does not execute it late. Only protocol v1 (JDK 24 and earlier) passes the request to the
            # attach thread rather than through the closed pipe.
            begun = time.monotonic()
            with frozen(target.pid):
                late = cli('load', pid, agent, 'true', f'start,event=cpu,file={work / "late.jfr"}', expected=1)
            assert late.stderr == 'Cannot attach: the target did not run the attach request within 6 seconds; it may be suspended or hung\n', late.stderr
            assert 5.5 < time.monotonic() - begun < 20
            time.sleep(1)  # The resumed target runs the abandoned attach thread.
            assert cli('status', pid).stdout == 'Profiler is not active\n'

            if args.broker:
                assert not broker_pipes(), broker_pipes()
                cli('start', '--fdtransfer', '-e', 'etw:Timer', '-f', recordings / 'broker.jfr', pid, elevated=True)
                assert len(broker_pipes()) == 1, broker_pipes()
                time.sleep(1)  # Timer samples must accumulate through the broker.
                cli('stop', pid)
                time.sleep(1)  # The broker exits once the target's session disconnects.
                assert not broker_pipes(), broker_pipes()
                assert read(recordings / 'broker.jfr')['fixtureStack'] == 'true'
                cli('-d', 1, '--fdtransfer', '-e', 'etw:Timer', '-f', recordings / 'broker-collect.jfr', pid, elevated=True)
                time.sleep(1)
                assert not broker_pipes(), broker_pipes()
                assert read(recordings / 'broker-collect.jfr')['fixtureStack'] == 'true'
                switched = cli('-d', 1, '--fdtransfer', '-e', 'context-switches', '-o', 'collapsed', '--total', pid, elevated=True)
                assert switched.stdout.strip() and all(int(row.rsplit(' ', 1)[1]) > 0 for row in switched.stdout.splitlines()), switched.stdout
                time.sleep(1)
                assert not broker_pipes(), broker_pipes()
                cli('start', '-e', 'cpu', pid)
                cli('start', '--fdtransfer', '-e', 'etw:Timer', pid, expected=200, elevated=True)
                assert len(broker_pipes()) == 1, broker_pipes()
                time.sleep(32)  # Like upstream's fdtransfer server, an unused broker exits after 30 seconds.
                assert not broker_pipes(), broker_pipes()
                cli('stop', pid)
                # A start that fails after connecting releases the broker's session.
                cli('start', '--fdtransfer', '-e', 'unrecognized-event', pid, expected=200, elevated=True)
                time.sleep(1)
                assert not broker_pipes(), broker_pipes()
                print('CLI_BROKER_OK sessions=3 acceptTimeout=1 failedStart=1', flush=True)
            assert target.poll() is None, 'A CLI command terminated the JVM'
        finally:
            target.terminate()
            target.wait(timeout=10)
            target_output.thread.join(timeout=5)
            assert not target_output.thread.is_alive(), 'Fixture stdout reader did not finish'
    print((work / 'target.err').read_text(errors='replace'), flush=True)

    launched = cli('launch', '-d', 2, '-o', 'collapsed', '--cstack', 'no', '--', '-cp', classes, 'Fixture', '3')
    assert re.match(r'Launched PID \d+\n', launched.stderr), launched.stderr
    assert any('Fixture.busy' in row for row in launched.stdout.splitlines()), launched.stdout
    for index, converter in enumerate(converters):
        # cmd splits unquoted arguments at '=', so jfrconv.cmd's entry point reassembles the JVM options.
        converted = recordings / f'sync-{index}.otlp'
        run([str(converter), '-J-Xmx256m', '-Dunused=a=b', '--total', str(recordings / 'sync.jfr'), str(converted)])
        validate_otlp(converted, 'Fixture.busy')
        collapsed = recordings / f'sync-{index}.collapsed'
        run([str(converter), str(recordings / 'sync.jfr'), str(collapsed)])
        assert 'Fixture.busy' in collapsed.read_text(encoding='utf-8')
    print('CLI_OK', flush=True)


if __name__ == '__main__':
    main()
