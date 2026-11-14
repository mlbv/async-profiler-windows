# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Exercise the packaged Java 8 API, SDK and converters on an older Windows JVM."""
import argparse
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile
import shutil
from read_otlp import validate as validate_otlp


def validate_converters(java, jar, recording, samples, total, case):
    html = recording.with_suffix('.html')
    subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(html)], check=True)
    roundtrip = recording.with_suffix('.roundtrip.collapsed')
    subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', str(html), str(roundtrip)], check=True)
    rows = roundtrip.read_text(encoding='utf-8').splitlines()
    assert any('LegacyProfilerSmoke.燃烧𠮷' in row for row in rows), rows
    assert sum(int(row.rsplit(' ', 1)[1]) for row in rows) == total, rows
    otlp = recording.with_suffix('.otlp')
    subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(otlp)], check=True)
    validate_otlp(otlp, 'LegacyProfilerSmoke.燃烧𠮷', samples, expected_values=total,
                  expected_type='cycles' if case == 'cycles' else 'cpu',
                  expected_unit='cycles' if case == 'cycles' else 'nanoseconds')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--reader-jdk', type=Path, required=True)
    parser.add_argument('--case', choices=['cpu', 'cycles', 'etw:Timer'], default='cpu')
    parser.add_argument('--java-option', action='append', default=[])
    parser.add_argument('--javaagent', action='store_true')
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--features', default='')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    jar = root / 'build/asprof-windows.jar'
    with zipfile.ZipFile(jar) as archive:
        for name in archive.namelist():
            if name.endswith('.class') and name.startswith('one/'):
                assert struct.unpack('>H', archive.read(name)[6:8])[0] <= 52, name
        assert all(name in archive.namelist() for name in ['flame.html', 'tree.html', 'heatmap.html'])
        manifest = archive.read('META-INF/MANIFEST.MF').decode('utf-8')
        assert 'Agent-Class: one.profiler.Agent' in manifest and 'Premain-Class: one.profiler.Agent' in manifest
    work = Path(tempfile.mkdtemp(prefix='asprof-legacy-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    javac = args.reader_jdk / 'bin/javac.exe'
    java = args.java_home / 'bin/java.exe'
    reader = args.reader_jdk / 'bin/java.exe'
    subprocess.run([str(javac), '--release', '8', '-encoding', 'UTF-8', '-cp', str(jar), '-d', str(classes),
                    str(root / 'tests/LegacyProfilerSmoke.java')], check=True)
    subprocess.run([str(javac), '--release', '17', '-encoding', 'UTF-8', '-d', str(classes),
                    str(root / 'tests/ReadLegacyProfile.java'), str(root / 'tests/ReadCounters.java')], check=True)
    recording = work / 'legacy.jfr'
    agent = work / 'asyncProfiler.dll'
    source = args.agent or root / 'build/core/native/asyncProfiler.dll'
    shutil.copy2(source, agent)
    if args.case.startswith('etw:'):
        # ETW capture starts the helper beside the DLL.
        shutil.copy2(source.with_name('asprof-helper.exe'), work / 'asprof-helper.exe')
    vm_options = args.java_option.copy()
    if args.features:
        vm_options += ['-Dasprof.test.features=' + args.features]
    if args.javaagent:
        interval = '1000000' if args.case == 'cycles' else '1ms' if args.case.startswith('etw:') else '10ms'
        stack = 'no' if 'agct' in args.features else 'vm'
        features = ',features=' + args.features if args.features else ''
        vm_options += ['-Done.profiler.libraryPath=' + str(agent),
                       '-javaagent:' + str(jar) + '=start,event=' + args.case + ',interval=' + interval
                       + ',cstack=' + stack + features + ',jfr,file=' + str(recording)]
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        result = subprocess.run([str(java), '-Xms64m', '-Xmx256m', *vm_options, '-XX:CompileCommand=dontinline,LegacyProfilerSmoke.*',
                                 '-cp', str(classes) + ';' + str(jar), 'LegacyProfilerSmoke',
                                 str(agent), str(recording), args.case, *(['preloaded'] if args.javaagent else [])],
                                stdout=log, stderr=subprocess.STDOUT, timeout=40, cwd=work)
    text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
    print(text, flush=True)
    result.check_returncode()
    assert 'LEGACY_PROFILER_OK' in text
    if 'agct' in args.features:
        calls = int(re.search(r'^windows_agct_calls (\d+)$', text, re.MULTILINE).group(1))
        assert calls >= 10, text
        if 'jnienv' in args.features:
            checked = int(re.search(r'^windows_agct_jnienv_checks (\d+)$', text, re.MULTILINE).group(1))
            assert checked == calls, (checked, calls)
    if 'stats' in args.features:
        duration = int(re.search(r'^stackwalk_ns_total (\d+)$', text, re.MULTILINE).group(1))
        assert duration > 0, text
    subprocess.run([str(reader), '-cp', str(classes), 'ReadLegacyProfile', str(recording), args.case, args.features], check=True)
    counts = subprocess.run([str(reader), '-cp', str(classes), 'ReadCounters', str(recording), str(recording) + '.collapsed',
                             'cycles' if args.case == 'cycles' else 'ns'], check=True, capture_output=True, text=True)
    print(counts.stdout, end='', flush=True)
    samples, total = map(int, re.search(r'weightedSamples=(\d+) total=(\d+)', counts.stdout).groups())
    validate_converters(java, jar, recording, samples, total, args.case)
    print('LEGACY_API_SDK_CONVERTER_OK', flush=True)


if __name__ == '__main__':
    main()
