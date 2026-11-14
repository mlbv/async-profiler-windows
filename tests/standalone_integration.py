# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Run the source-built profiler in disposable Windows JVMs."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import re
from read_otlp import validate as validate_otlp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--case', choices=['cpu', 'wall', 'alloc', 'lock', 'cycles', 'unicode'], default='cpu')
    parser.add_argument('--symbols', type=Path, help='jvm.dll PDB directory, which JDK 8 allocation profiling requires')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    agent = (args.agent or root / 'build/core/native/asyncProfiler.dll').resolve()
    work = Path(tempfile.mkdtemp(prefix='asprof-standalone-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    sources = list((root / 'core/src/api/one/profiler').glob('*.java'))
    sources += [root / 'tests' / name for name in ['Fixture.java', 'ReadVmStacks.java', 'StandaloneSmoke.java', 'ReadCounters.java', 'UnicodeJvmSmoke.java']]
    # The target JDK's own compiler targets its release and API, including JDK 8's jdk.jfr backport.
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '-encoding', 'UTF-8', '-d', str(classes),
                    *map(str, sources)], check=True)
    cases = {
        'cpu': ('event=cpu,interval=10ms,cstack=vm', 'jdk.ExecutionSample'),
        'cycles': ('event=cycles,interval=1000000,cstack=vm', 'jdk.ExecutionSample'),
        'wall': ('event=wall,interval=10ms,cstack=vm', 'profiler.WallClockSample'),
        'alloc': ('event=alloc,alloc=64k,cstack=vm', 'jdk.ObjectAllocationInNewTLAB'),
        'lock': ('event=lock,lock=1us,cstack=vm', 'jdk.JavaMonitorEnter'),
    }
    main_class, extra = 'UnicodeJvmSmoke', []
    if args.case != 'unicode':
        main_class = 'StandaloneSmoke'
        extra = list(cases[args.case])
    with (work / 'run.log').open('w', encoding='utf-8') as log:
        result = subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(classes), main_class,
                                 str(agent), str(work / 'own.jfr'), *extra],
                                cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=45,
                                env=dict(os.environ, ASYNC_PROFILER_SYMBOL_PATH=str(args.symbols.resolve())) if args.symbols else None)
    print((work / 'run.log').read_text(encoding='utf-8', errors='replace'), end='')
    result.check_returncode()
    if args.case == 'cycles':
        result = subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(classes), 'ReadCounters',
                                 str(work / 'own.jfr'), str(work / 'own.jfr.collapsed'), 'cycles'], check=True, capture_output=True, text=True)
        print(result.stdout, end='')
        samples, total = map(int, re.search(r'weightedSamples=(\d+) total=(\d+)', result.stdout).groups())
        converted = work / 'cycles.otlp'
        subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(root / 'build/asprof-windows.jar'),
                        'one.convert.Main', '--total', str(work / 'own.jfr'), str(converted)], check=True)
        validate_otlp(converted, 'Fixture.busy', samples, expected_values=total, expected_type='cycles', expected_unit='cycles')


if __name__ == '__main__':
    main()
