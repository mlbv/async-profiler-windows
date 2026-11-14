# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Exercise deep inline expansion and requested ETW stack-depth limits."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile
from standalone_java_etw import hotspot_compiler_options, validate_metadata_metrics, validate_totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--recording-directory', type=Path, help='Validate retained captures without launching another target')
    parser.add_argument('--physical', action='store_true', help='Require explicit truncation at the ETW physical capture ceiling')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = args.recording_directory or Path(tempfile.mkdtemp(prefix='asprof-stack-depth-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir(exist_ok=True)
    payload = work / 'DeepStackPayload.java'
    methods = [f'    static long m{i}(long value) {{ return ' +
               (f'm{i+1}(value) + {i}; }}' if i < 519 else 'StackDepthSmoke.burn(value); }') for i in range(520)]
    payload.write_text('public final class DeepStackPayload {\n' + '\n'.join(methods) + '\n}\n', encoding='utf-8')
    java, javac = [args.java_home / 'bin' / name for name in ['java.exe', 'javac.exe']]
    jar = root / 'build/asprof-windows.jar'
    sources = [root / 'tests' / name for name in ['StackDepthSmoke.java', 'ReadStackDepth.java', 'ReadCounters.java']]
    subprocess.run([str(javac), '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar), '-d', str(classes),
                    str(payload), *map(str, sources)], check=True)
    # Release HotSpot limits a single C2 inline tree to roughly 100 levels.
    # Six compiled islands keep physical capture shallow while expanding past 512.
    compile_options = []
    for entry in range(0, 520, 90):
        compile_options += [f'-XX:CompileCommand=compileonly,DeepStackPayload.m{entry}',
                            f'-XX:CompileCommand=dontinline,DeepStackPayload.m{entry}']
    if args.physical: compile_options = ['-XX:CompileCommand=dontinline,DeepStackPayload.*']
    command = [str(java), '-Xbatch', *hotspot_compiler_options(java), '-XX:-TieredCompilation', '-XX:CompileThreshold=20',
               '-XX:MaxInlineLevel=90', *compile_options, '-cp', str(classes) + ';' + str(jar),
               'StackDepthSmoke', str(root / 'build/core/native/asyncProfiler.dll'), str(work), *(['physical'] if args.physical else [])]
    if args.recording_directory is None:
        with (work / 'target.log').open('w', encoding='utf-8') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=90, cwd=work)
    text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
    print(text, flush=True)
    if args.recording_directory is None: result.check_returncode()
    validate_metadata_metrics(text)
    assert not re.search(r'windows_etw_(malformed_events|events_lost|failure) [1-9]\d*\n', text)
    recordings = [(1024, 1024)] if args.physical else [(1024, 1024), (64, 64), (64, 12), (64, 0)]
    for cstack in ['dwarf', 'no']:
        for limit, retained in recordings:
            depth = str(limit) if retained == limit else f'{limit}-{retained}'
            recording = work / f'{cstack}-{depth}.jfr'
            subprocess.run([str(java), '-cp', str(classes), 'ReadStackDepth', str(recording),
                            str(limit), str(retained), str(cstack == 'no').lower(), str(args.physical).lower()], check=True)
            validate_totals(java, classes, jar, recording, 'DeepStackPayload',
                            'DeepStackPayload.m519' if retained else 'truncated')
    print('STACK_DEPTH_ALL_OK', flush=True)


if __name__ == '__main__':
    main()
