# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify retained resume data and absolute timeout/loop deadlines."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from standalone_java_etw import validate_totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--jfrsync', action='store_true')
    parser.add_argument('--case', choices=['normal', 'failure', 'external', 'exit'], default='normal')
    args = parser.parse_args()
    if args.case == 'external' and not args.jfrsync:
        parser.error('--case external requires --jfrsync')
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-lifecycle-limits-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    jar = root / 'build/asprof-windows.jar'
    java = args.java_home / 'bin/java.exe'
    sources = [root / 'tests' / name for name in ['LifecycleLimitSmoke.java', 'ReadLifecycleResume.java', 'ReadCounters.java', 'ReadLifecycleBounds.java']]
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar),
                    '-d', str(classes), *map(str, sources)], check=True)
    sync = 'sync' if args.jfrsync else 'plain'
    mode = sync + ('-' + args.case if args.case != 'normal' else '')
    private_library = work / 'asyncProfiler.dll'
    shutil.copy2(root / 'build/core/native/asyncProfiler.dll', private_library)
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        result = subprocess.run([str(java), '-XX:CompileCommand=dontinline,LifecycleLimitSmoke.*', '-cp', str(classes) + ';' + str(jar),
                                 'LifecycleLimitSmoke', str(private_library), str(work), mode],
                                cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=45)
    text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
    print(text, flush=True)
    result.check_returncode()
    if args.case == 'failure':
        assert 'STOP_FAILURE_CAUGHT' in text and 'RECORDER_FAILURE_OK' in text, text
        if args.jfrsync:
            recovery = work / 'resume.jfr.native-recovery'
            validate_totals(java, classes, jar, recovery, 'LifecycleLimitSmoke', 'LifecycleLimitSmoke.beforeResume')
            retained = re.search(r'^JVM recording data retained at (.+)$', text, re.MULTILINE)
            assert retained, text
            summary = subprocess.run([str(args.java_home / 'bin/jfr.exe'), 'summary', retained[1].strip()],
                                     check=True, capture_output=True, text=True)
            assert re.search(r'test.LifecyclePhase\s+1\s', summary.stdout), summary.stdout
        print('LIFECYCLE_FAILURE_ALL_OK', sync, flush=True)
        return
    if args.case in ['external', 'exit']:
        recording = work / 'resume.jfr'
        if args.jfrsync:
            summary = subprocess.run([str(args.java_home / 'bin/jfr.exe'), 'summary', str(recording)],
                                     check=True, capture_output=True, text=True)
            assert re.search(r'test.LifecyclePhase\s+1\s', summary.stdout), summary.stdout
        if args.case == 'exit':
            subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(recording) + '.collapsed'], check=True)
        validate_totals(java, classes, jar, recording, 'LifecycleLimitSmoke', 'LifecycleLimitSmoke.beforeResume')
        print('LIFECYCLE_' + args.case.upper() + '_ALL_OK', sync, flush=True)
        return
    recording = work / 'resume.jfr'
    subprocess.run([str(java), '-cp', str(classes), 'ReadLifecycleResume', str(recording), sync], check=True)
    subprocess.run([str(java), '-cp', str(classes), 'ReadLifecycleResume', str(work / 'resume-snapshot.jfr'), sync], check=True)
    validate_totals(java, classes, jar, recording, 'LifecycleLimitSmoke', 'LifecycleLimitSmoke.beforeResume')
    deadlines = {Path(path): deadline for deadline, path in re.findall(r'^CAPTURE_LIMIT (\d+) (.+)$', text, re.MULTILINE)}
    assert len(deadlines) == 3, deadlines
    for recording, deadline in deadlines.items():
        subprocess.run([str(java), '-cp', str(classes), 'ReadLifecycleBounds', str(recording), deadline], check=True)
        collapsed = Path(str(recording) + '.collapsed')
        if not collapsed.exists():
            subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(collapsed)], check=True)
        validate_totals(java, classes, jar, recording, 'LifecycleLimitSmoke', 'LifecycleLimitSmoke.beforeResume')
    print('LIFECYCLE_LIMITS_ALL_OK', sync, flush=True)


if __name__ == '__main__':
    main()
