# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Capture an ETW timer profile through the same-user broker from a low-integrity native target."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile

from read_otlp import validate as validate_otlp
from standalone_tracepoint import token_properties

import integrity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True, help='JDK for readers/converters')
    parser.add_argument('--fixture', type=Path, required=True, help='nativeProfileShareApplication.exe')
    parser.add_argument('--agent', type=Path, default=Path(__file__).resolve().parents[1] / 'build/asyncProfiler.dll')
    parser.add_argument('--work-directory', type=Path)
    args = parser.parse_args()
    integrity.require_elevated()
    root = Path(__file__).resolve().parents[1]
    work = (args.work_directory or Path(tempfile.mkdtemp(prefix='asprof-low-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    # A low-integrity process can write only below a low label, which LocalLow carries.
    output = Path(tempfile.mkdtemp(prefix='asprof-low-', dir=Path(os.environ['USERPROFILE']) / 'AppData/LocalLow'))
    target = integrity.deelevated_popen([str(args.fixture.resolve()), str(args.agent.resolve()), str(output), 'broker'],
                                        integrity=integrity.LOW_INTEGRITY, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=work)
    pid = target.pid
    broker = None
    try:
        ready = target.stdout.readline()
        assert ready.startswith('READY '), ready
        assert token_properties(pid) == (0, 0x1000), ('Target is not low integrity', token_properties(pid))
        broker = subprocess.Popen([str(args.agent.parent / 'asprof-helper.exe'), '--etw-broker', str(pid)],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=work)
        line = broker.stdout.readline()
        assert line.startswith('ETW_BROKER_READY '), line
        def exchange(command, prefix):
            target.stdin.write(command + '\n')
            target.stdin.flush()
            while True:
                reply = target.stdout.readline()
                assert reply, ('Target exited', command)
                if reply.startswith(prefix):
                    return reply
        reply = exchange('start low etw:Timer 1000000', 'STARTED low')
        assert reply.startswith('STARTED'), reply
        exchange('work before 1000', 'WORKED before')
        exchange('stop low', 'STOPPED low')
        exchange('exit', 'EXITED')
        target.wait(timeout=30)
        assert broker.wait(timeout=30) == 0, 'Broker cleanup failed'
    finally:
        if target.poll() is None:
            target.kill()
        if broker and broker.poll() is None:
            broker.wait(timeout=30)
    rows = [line.rsplit(' ', 1) for line in (output / 'low.collapsed').read_text(encoding='utf-8').splitlines() if line]
    total = sum(int(value) for _, value in rows)
    work_total = sum(int(value) for stack, value in rows if 'ShareWorkBefore' in stack)
    assert 700_000_000 <= work_total <= 1_300_000_000, (work_total, total)
    classes = work / 'classes'
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes), str(root / 'tests/ReadCounters.java')], check=True)
    counts = subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(classes), 'ReadCounters', str(output / 'low.jfr'),
                             str(output / 'low.collapsed'), 'ns', '1000000'], check=True, capture_output=True, text=True).stdout
    samples = int(re.search(r'weightedSamples=(\d+)', counts).group(1))
    validate_otlp(output / 'low.native.otlp', 'ShareWorkBefore', aggregated=True, expected_values=total, expected_type='cpu', expected_unit='ns')
    metrics = (output / 'low.metrics').read_text(encoding='utf-8')
    assert 'windows_etw_failure 0\n' in metrics and 'windows_etw_events_lost 0\n' in metrics, metrics
    print(f'LOW_INTEGRITY_BROKER_OK pid={pid} samples={samples} workNs={work_total}', flush=True)


if __name__ == '__main__':
    main()
