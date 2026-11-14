# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify actual JVM safepoint windows using the upstream TTSP workload on Windows."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--case', choices=['bounded', 'nostop'], default='bounded')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-ttsp-'))
    print('Evidence:', work, flush=True)
    agent = work / 'asyncProfiler.dll'
    shutil.copy2(args.agent or root / 'build/core/native/asyncProfiler.dll', agent)
    classes = work / 'classes'
    classes.mkdir()
    sources = list((root / 'core/src/api/one/profiler').glob('*.java'))
    sources += [args.upstream / 'test/test/jfr/Ttsp.java', *(root / 'tests' / name for name in
                ['TtspSmoke.java', 'ReadWindows.java', 'ReadCounters.java'])]
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes), *map(str, sources)], check=True)
    output = work / 'ttsp.jfr'
    java = args.java_home / 'bin/java.exe'
    env = os.environ.copy()
    env['ASYNC_PROFILER_SYMBOL_PATH'] = str(args.symbols.resolve())
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        result = subprocess.run([str(java), '-cp', str(classes), 'TtspSmoke', str(agent), str(output), args.case],
                                cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=45)
    print((work / 'target.log').read_text(encoding='utf-8', errors='replace'), end='')
    result.check_returncode()
    subprocess.run([str(java), '-cp', str(classes), 'ReadWindows', str(output), '-2', '-1',
                    'bounded' if args.case == 'bounded' else 'outside', 'delaySafepoint', '3'], check=True)
    subprocess.run([str(java), '-cp', str(classes), 'ReadCounters', str(output), str(output) + '.collapsed', 'ns'], check=True)
    print('TTSP_' + args.case.upper() + '_OK', flush=True)


if __name__ == '__main__':
    main()
