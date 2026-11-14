# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify native automatic stop, rotation and target filename expansion."""
import argparse
import os
import re
from pathlib import Path
import subprocess
import struct
import tempfile
from standalone_java_etw import validate_totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--jfrsync', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-lifecycle-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    jar = root / 'build/asprof-windows.jar'
    java = args.java_home / 'bin/java.exe'
    sources = [root / 'tests' / name for name in ['LifecycleSmoke.java', 'ReadCounters.java', 'ReadRecordingChunks.java', 'ReadLifecycleBounds.java']]
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar),
                    '-d', str(classes), *map(str, sources)], check=True)
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        result = subprocess.run([str(java), '-cp', str(classes) + ';' + str(jar), 'LifecycleSmoke',
                                 str(root / 'build/core/native/asyncProfiler.dll'), str(work), *(['sync'] if args.jfrsync else [])], cwd=work,
                                stdout=log, stderr=subprocess.STDOUT,
                                env=dict(os.environ, ASPROF_FILENAME='记录𠮷', ASPROF_LONG_FILENAME='文' * 176), timeout=90)
    text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
    print(text, flush=True)
    result.check_returncode()
    recordings = list(work.glob('*.jfr'))
    assert len(recordings) == 5, recordings
    deadlines = {Path(path): deadline for deadline, path in re.findall(r'^CAPTURE_LIMIT (\d+) (.+)$', text, re.MULTILINE)}
    for recording in recordings:
        subprocess.run([str(java), '-cp', str(classes), 'ReadLifecycleBounds', str(recording), deadlines[recording]], check=True)
        collapsed = Path(str(recording) + '.collapsed')
        if not collapsed.exists():
            subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(collapsed)], check=True)
        samples, total = validate_totals(java, classes, jar, recording, 'LifecycleSmoke', 'LifecycleSmoke.burn')
        if recording.name.startswith('chunks-'):
            data = recording.read_bytes()
            offset = chunks = 0
            paths = []
            while offset < len(data):
                assert data[offset:offset+4] == b'FLR\0'
                size, = struct.unpack_from('>Q', data, offset + 8)
                assert 68 <= size <= len(data) - offset, size
                path = work / f'chunk-{chunks}.jfr'
                path.write_bytes(data[offset:offset+size])
                paths.append(path)
                offset += size
                chunks += 1
            assert chunks >= 3, chunks
            read = subprocess.run([str(java), '-cp', str(classes), 'ReadRecordingChunks', *map(str, paths)],
                                  check=True, capture_output=True, text=True)
            print(read.stdout, end='', flush=True)
            count = re.search(r'chunks=(\d+) samples=(\d+) total=(\d+)', read.stdout)
            assert (int(count[2]), int(count[3])) == (samples, total), read.stdout
            print('CHUNK_ROTATION_OK chunks=' + str(chunks), flush=True)
    for index in range(2):
        collapsed = work / f'folded-{index}.collapsed'
        text = collapsed.read_text(encoding='utf-8')
        assert 'LifecycleSmoke.burn' in text, text
        assert sum(int(line.rsplit(' ', 1)[1]) for line in text.splitlines()) >= 10
    print('COLLAPSED_RING_OK', flush=True)
    print('LIFECYCLE_ALL_OK', flush=True)


if __name__ == '__main__':
    main()
