# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify forced JVM AGCT routing and cancelled special-APC lifetime on Windows."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--java-option', action='append', default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-async-java-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    agent = work / 'asyncProfiler.dll'
    shutil.copy2(args.agent or root / 'build/core/native/asyncProfiler.dll', agent)
    sources = list((root / 'core/src/api/one/profiler').glob('*.java'))
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes),
                    *map(str, sources), *(str(root / 'tests' / name) for name in
                    ['AsyncJavaSmoke.java', 'ReadCounters.java', 'NativeWindowFixture.java'])], check=True)
    with (work / 'run.log').open('w', encoding='utf-8') as log:
        result = subprocess.run([str(args.java_home / 'bin/java.exe'), *args.java_option, '-cp', str(classes), 'AsyncJavaSmoke',
                                 str(agent), str(work), *([str(args.fixture)] if args.fixture else [])],
                                cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=60)
    print((work / 'run.log').read_text(encoding='utf-8', errors='replace'), end='')
    result.check_returncode()


if __name__ == '__main__':
    main()
