# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Validate dedicated native timeout controls without status polling or elevation."""
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import re
import subprocess
import tempfile

from standalone_software_broker import OutputPipe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True, help='API JAR for the test program')
    parser.add_argument('--asprof', type=Path)
    parser.add_argument('--memory-only', action='store_true')
    args = parser.parse_args()
    java = args.java_home.resolve() / 'bin/java.exe'
    jar, agent = args.jar.resolve(), args.agent.resolve()
    asprof = (args.asprof or Path(__file__).resolve().parents[1] / 'build/asprof.exe').resolve()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-cli-timeout-'))
    classes = work / 'classes'
    classes.mkdir()
    print('Evidence:', work, flush=True)
    subprocess.run([str(args.java_home.resolve() / 'bin/javac.exe'), '--release', '17',
                    '-cp', str(jar), '-d', str(classes),
                    str(root / 'tests/CliTimeoutTarget.java'),
                    str(root / 'tests/ReadLifecycleBounds.java')], check=True)

    def cli(*arguments, success=True):
        result = subprocess.run([str(asprof), '--libpath', str(agent), *map(str, arguments)], cwd=work, capture_output=True,
                                text=True, timeout=15)
        print(arguments, result.returncode, result.stdout, result.stderr, flush=True)
        if success:
            result.check_returncode()
        return result

    def verify(path, maximum_span=None):
        if path.suffix == '.jfr':
            result = subprocess.run([str(java), '-cp', str(classes), 'ReadLifecycleBounds', str(path)],
                                    cwd=work, check=True, capture_output=True, text=True, timeout=15)
            print(result.stdout, end='', flush=True)
            if maximum_span is not None:
                span = int(re.search(r'spanMs=(\d+)', result.stdout).group(1))
                assert span <= maximum_span, (path, span, maximum_span)
        else:
            rows = path.read_text(encoding='utf-8').splitlines()
            assert rows and any('CliTimeoutTarget.burn' in row for row in rows), rows
            assert sum(int(row.rsplit(' ', 1)[1]) for row in rows) > 0, rows

    def memory_chunks(pid):
        memory_path = work / 'memory-chunks.jfr'
        cli('--timeout', '6s', '-i', '1ms', '--cstack', 'no', '--jfropts', 256, '--chunktime', 5, '-f', memory_path, pid)
        cpu(7000, False)
        verify(memory_path)
        memory = memory_path.read_bytes()
        offset = chunks = 0
        while offset < len(memory):
            assert memory[offset:offset + 4] == bytes((70, 76, 82, 0)), (offset, memory[offset:offset + 4])
            length = int.from_bytes(memory[offset + 8:offset + 16], 'big')
            assert 68 <= length <= len(memory) - offset, length
            chunk_path = work / f'memory-chunk-{chunks}.jfr'
            chunk_path.write_bytes(memory[offset:offset + length])
            verify(chunk_path)
            offset += length
            chunks += 1
        assert chunks == 2, chunks
        print('CLI_MEMORY_CHUNKS_OK chunks=2 cachedNativeOutput=1', flush=True)

    with (work / 'target.err').open('w') as errors:
        target = subprocess.Popen([str(java), '-cp', str(classes) + ';' + str(jar),
                                   'CliTimeoutTarget', str(agent)], cwd=work, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=errors, text=True)
        output = OutputPipe(target, work / 'target.log')

        def cpu(milliseconds, active):
            target.stdin.write(f'{milliseconds} {str(active).lower()}\n')
            target.stdin.flush()
            reply = output.until('WORK_DONE ', milliseconds / 1000 + 10)
            assert reply == f'WORK_DONE {milliseconds} active={str(active).lower()}', reply

        try:
            assert output.receive('Target ready', 10) == f'READY {target.pid}'
            if args.memory_only:
                memory_chunks(target.pid)
                target.stdin.write('quit\n')
                target.stdin.flush()
                assert target.wait(timeout=10) == 0
                assert '[ERROR]' not in (work / 'target.log').read_text(encoding='utf-8')
                return
            # --timeout turns the default collect into start: returning here proves no -d wait/stop.
            long_path = work / 'long.jfr'
            cli('--timeout', '40s', '-i', '1ms', '--cstack', 'no', '-f', long_path, target.pid)
            cpu(1000, True)
            cli('stop', target.pid)
            verify(long_path)

            for action, suffix in [('collect', '.jfr'), ('start', '.collapsed'), ('resume', '.jfr')]:
                path = work / (action + suffix)
                cli(action, '--timeout', '1s', '-i', '1ms', '--cstack', 'no', '-f', path, target.pid)
                cpu(2000, False)
                verify(path, maximum_span=1500)

            cli('--timeout', '3s', '--loop', '1', '-i', '1ms', '--cstack', 'no', '-f', work / 'ring-%n{2}.jfr', target.pid)
            cpu(4000, False)
            for index in range(2):
                verify(work / f'ring-{index}.jfr')

            cli('--loop', '1s', '-i', '1ms', '--cstack', 'no', '-f', work / 'unlimited-ring-%n{2}.jfr', target.pid)
            cpu(2200, True)
            cli('stop', target.pid)
            for index in range(2):
                verify(work / f'unlimited-ring-{index}.jfr')

            memory_chunks(target.pid)

            absolute = (datetime.now() + timedelta(seconds=4)).strftime('%H:%M:%S')
            absolute_path = work / 'absolute.jfr'
            cli('start', '--timeout', absolute, '-i', '1ms', '--cstack', 'no', '-f', absolute_path, target.pid)
            cpu(5000, False)
            verify(absolute_path)

            cli('start', '--timeout', '0', '-i', '1ms', '--cstack', 'no', '-f', work / 'unlimited.jfr', target.pid)
            cpu(1000, True)
            cli('stop', target.pid)
            verify(work / 'unlimited.jfr')

            bad_path = work / 'conflict.jfr'
            rejected = cli('launch', '--timeout', '1', '-d', 1, '-f', bad_path, '--java', java, '--', '-version', success=False)
            assert rejected.returncode == 1 and 'Use either -d or --timeout with launch' in rejected.stderr, rejected
            assert not bad_path.exists(), bad_path

            target.stdin.write('quit\n')
            target.stdin.flush()
            assert target.wait(timeout=10) == 0
        finally:
            if target.poll() is None:
                target.kill()
                target.wait(timeout=10)
            output.thread.join(timeout=5)
            assert not output.thread.is_alive()

    target_log = (work / 'target.log').read_text(encoding='utf-8')
    assert '[ERROR]' not in target_log, target_log

    launched = cli('launch', '--timeout', '1s', '-i', '1ms', '--cstack', 'no',
                   '-f', work / 'launch-%p.jfr', '--java', java, '--', '-cp',
                   str(classes) + ';' + str(jar), 'CliTimeoutTarget', agent, '2200')
    assert '[ERROR]' not in launched.stdout + launched.stderr, launched
    pid = re.search(r'Launched PID (\d+)', launched.stderr).group(1)
    verify(work / f'launch-{pid}.jfr', maximum_span=1500)
    loop_launch = cli('launch', '-d', 2, '--loop', '1s', '-i', '1ms', '--cstack', 'no',
                      '-f', work / 'launch-loop-%p-%n{2}.jfr', '--java', java, '--', '-cp',
                      str(classes) + ';' + str(jar), 'CliTimeoutTarget', agent, '3200')
    assert '[ERROR]' not in loop_launch.stdout + loop_launch.stderr, loop_launch
    loop_pid = re.search(r'Launched PID (\d+)', loop_launch.stderr).group(1)
    for index in range(2):
        verify(work / f'launch-loop-{loop_pid}-{index}.jfr', maximum_span=1500)
    print('CLI_TIMEOUT_OK nativeDeadline=1 asynchronousRecord=1 relative=1 absolute=1 resume=1 loop=1 zero=1 launch=1 noPolling=1', flush=True)


if __name__ == '__main__':
    main()
