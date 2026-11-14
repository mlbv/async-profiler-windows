# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Check batched and nobatch wall sampling across more than eight selected threads."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--threads', type=int, default=17)
    parser.add_argument('--interval-ns', type=int, default=20_000_000)
    parser.add_argument('--duration-ms', type=int, default=2000)
    args = parser.parse_args()
    if args.threads <= 8 or args.interval_ns <= 0 or args.duration_ms <= 0:
        parser.error('Use more than eight threads and positive interval/duration.')
    root = Path(__file__).resolve().parents[1]
    java = args.java_home.resolve() / 'bin/java.exe'
    javac = args.java_home.resolve() / 'bin/javac.exe'
    agent, jar = args.agent.resolve(), args.jar.resolve()
    work = Path(tempfile.mkdtemp(prefix='asprof-wall-population-'))
    classes = work / 'classes'
    classes.mkdir()
    print('Evidence:', work, flush=True)
    inputs = [agent, jar]
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    (work / 'inputs.json').write_text(json.dumps(hashes, indent=2), encoding='utf-8')
    for path, digest in hashes.items():
        print('WALL_INPUT_BEFORE', path, digest, flush=True)
    subprocess.run([str(javac), '--release', '17', '-cp', str(jar), '-d', str(classes),
                    str(root / 'tests/WallPopulation.java'), str(root / 'tests/ReadWallPopulation.java')], check=True)
    classpath = str(classes) + ';' + str(jar)
    for nobatch in [False, True]:
        mode = 'nobatch' if nobatch else 'batch'
        recording = work / (mode + '.jfr')
        with (work / (mode + '.log')).open('w', encoding='utf-8') as log:
            target = subprocess.run([str(java), '-cp', classpath, 'WallPopulation', str(agent), str(recording),
                                     str(nobatch).lower(), str(args.threads), str(args.interval_ns), str(args.duration_ms)],
                                    cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=30)
        text = (work / (mode + '.log')).read_text(encoding='utf-8')
        print(text, end='', flush=True)
        target.check_returncode()
        assert '[ERROR]' not in text, text
        elapsed = re.search(r'WALL_POPULATION_CAPTURE .*elapsedNs=(\d+)', text)
        assert elapsed, text
        subprocess.run([str(java), '-cp', classpath, 'ReadWallPopulation', str(recording),
                        str(nobatch).lower(), str(args.threads), str(args.interval_ns), elapsed.group(1)],
                       cwd=work, check=True, timeout=15)
    for path, digest in hashes.items():
        after = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        assert after == digest, (path, digest, after)
        print('WALL_INPUT_AFTER', path, after, flush=True)
    print('WALL_POPULATION_ALL_OK modes=2 beyondSingleBatch=1 perThreadCadence=1 weights=1 filter=1 inputHashesStable=1', flush=True)


if __name__ == '__main__':
    main()
