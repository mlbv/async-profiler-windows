# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Check allocation, weak-reference liveness, Java locks and filtered wall stacks on older HotSpot JVMs."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from read_otlp import fields, validate as validate_otlp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--reader-jdk', type=Path, required=True)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--converter-jar', type=Path)
    parser.add_argument('--case', choices=['alloc', 'live', 'live-concurrent', 'live-mixed', 'lock', 'wall', 'wall-supplementary', 'wall-resume', 'wall-cancel', 'tlab'], required=True)
    parser.add_argument('--java-option', action='append', default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-collectors-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    jar = (args.converter_jar or root / 'build/asprof-windows.jar').resolve()
    reader = args.reader_jdk / 'bin/java.exe'
    javac = args.reader_jdk / 'bin/javac.exe'
    subprocess.run([str(javac), '--release', '8', '-Xlint:-options', '-encoding', 'UTF-8', '-cp', str(jar), '-d', str(classes), str(root / 'tests/CollectorSmoke.java')], check=True)
    subprocess.run([str(javac), '--release', '17', '-encoding', 'UTF-8', '-d', str(classes),
                    str(root / 'tests/ReadCollectors.java'), str(root / 'tests/ReadWallCadence.java')], check=True)
    library = work / 'asyncProfiler.dll'
    shutil.copy2(args.agent or root / 'build/core/native/asyncProfiler.dll', library)
    recording = work / 'collector.jfr'
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        # The tlab case's allocateCompiled must run as C2 code before profiling starts
        compiled = ['-XX:-TieredCompilation', '-Xbatch'] if args.case == 'tlab' else []
        result = subprocess.run([str(args.java_home / 'bin/java.exe'), '-Xms64m', '-Xmx128m', *compiled, *args.java_option,
                                 '-XX:CompileCommand=dontinline,CollectorSmoke.*', '-cp', str(classes) + ';' + str(jar),
                                 'CollectorSmoke', str(library), str(recording), args.case], cwd=work,
                                stdout=log, stderr=subprocess.STDOUT, timeout=45)
    text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
    print(text, flush=True)
    result.check_returncode()
    if args.case == 'wall-cancel':
        assert 'WALL_CANCEL_OK' in text
        subprocess.run([str(args.reader_jdk / 'bin/jfr.exe'), 'summary', str(recording)], check=True, capture_output=True)
        print('COLLECTORS_ALL_OK wall-cancel', flush=True)
        return
    paths = [recording] + ([Path(str(recording) + '.restart.jfr')] if args.case in ['live', 'live-concurrent'] else [])
    for recording in paths:
        result = subprocess.run([str(reader), '-cp', str(classes), 'ReadCollectors', str(recording), args.case],
                                capture_output=True, text=True)
        print(result.stdout, end='', flush=True)
        print(result.stderr, end='', flush=True)
        result.check_returncode()
        counts = re.search(r'events=(\d+) total=(\d+)', result.stdout)
        events, total = map(int, counts.groups())
        if args.case in ['wall', 'wall-supplementary']:
            subprocess.run([str(reader), '-cp', str(classes), 'ReadWallCadence', str(recording),
                            '7000000' if args.case == 'wall-supplementary' else '5000000', 'check'], check=True)
        converted = recording.with_suffix('.converted.collapsed')
        wall = args.case.startswith('wall')
        option = 'wall' if wall else 'live' if args.case.startswith('live') else 'alloc' if args.case == 'tlab' else args.case
        subprocess.run([str(reader), '-cp', str(jar), 'one.convert.Main', '--' + option, '--total', str(recording), str(converted)], check=True)
        converted_total = sum(int(line.rsplit(' ', 1)[1]) for line in converted.read_text(encoding='utf-8').splitlines())
        assert converted_total == total, (converted_total, total)
        if wall:
            count_file = recording.with_suffix('.samples.collapsed')
            subprocess.run([str(reader), '-cp', str(jar), 'one.convert.Main', '--wall', str(recording), str(count_file)], check=True)
            assert sum(int(line.rsplit(' ', 1)[1]) for line in count_file.read_text(encoding='utf-8').splitlines()) == events
            count_otlp = recording.with_suffix('.samples.otlp')
            subprocess.run([str(reader), '-cp', str(jar), 'one.convert.Main', '--wall', str(recording), str(count_otlp)], check=True)
            validate_otlp(count_otlp, 'CollectorSmoke.wallBusy', expected_values=events, expected_type='cpu', expected_unit='count')
        otlp = recording.with_suffix('.otlp')
        subprocess.run([str(reader), '-cp', str(jar), 'one.convert.Main', '--' + option, '--total', str(recording), str(otlp)], check=True)
        frame = 'wallBusy' if wall else 'contendMonitor' if args.case == 'lock' else 'allocateRetained'
        validate_otlp(otlp, 'CollectorSmoke.' + frame, None if wall else events, expected_values=total,
                      expected_type='cpu' if wall else 'locks' if args.case == 'lock' else 'allocations',
                      expected_unit='nanoseconds' if wall or args.case == 'lock' else 'bytes')
        if wall:
            root_fields = fields(otlp.read_bytes())
            periods = [fields(profile)[6][0] for resource in root_fields[1]
                       for scope in fields(resource)[2] for profile in fields(scope)[2]]
            expected_periods = [5_000_000, 7_000_000, 7_000_000] if args.case == 'wall-resume' else [7_000_000 if args.case == 'wall-supplementary' else 5_000_000]
            assert periods == expected_periods, periods
    print('COLLECTORS_ALL_OK', args.case, flush=True)


if __name__ == '__main__':
    main()
