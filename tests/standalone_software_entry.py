# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Prove certified software-entry counts, native callers and exported weights through the C API."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from read_otlp import validate as validate_otlp


def prologue_capture(java_home, candidate, application, fixture, work, root, retained=False):
    library, jar = candidate / 'asyncProfiler.dll', candidate / 'asprof-windows.jar'
    if retained:
        text = (work / 'prologues.log').read_text(encoding='utf-8')
    else:
        result = subprocess.run([str(application), str(library), str(fixture), str(work), 'prologues'],
                                cwd=work, capture_output=True, text=True, timeout=45)
        text = result.stdout + result.stderr
        (work / 'prologues.log').write_text(text, encoding='utf-8')
        print(text, end='', flush=True)
        result.check_returncode()
    assert 'SOFTWARE_PROLOGUE_APPLICATION_OK' in text and '[ERROR]' not in text, text
    metrics = dict(re.findall(r'^(windows_software_probe_\w+|windows_import_failed|events_dropped_total|calltracestorage_overflows_total) (\d+)$',
                              text, re.MULTILINE))
    for name in ['windows_software_probe_failed', 'windows_software_probe_unprepared',
                 'windows_software_probe_dropped', 'windows_import_failed',
                 'events_dropped_total', 'calltracestorage_overflows_total']:
        assert int(metrics[name]) == 0, (name, metrics.get(name))
    classes = work / 'classes'
    classes.mkdir(exist_ok=retained)
    java = java_home / 'bin/java.exe'
    subprocess.run([str(java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes),
                    str(root / 'tests/ReadCounters.java')], check=True)
    captures = re.findall(r'^PROLOGUE_CAPTURE name=(\S+) frame=(\S+) period=(\d+) samples=(\d+) total=(\d+) selector=(\S+)$',
                          text, re.MULTILINE)
    assert len(captures) == 10, captures
    for name, frame, period, samples, total, selector in captures:
        recording = work / (name + '.jfr')
        collapsed = work / (name + '.total.collapsed')
        read = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters', str(recording),
                               str(collapsed), 'events', period, frame, 'NativeSoftwarePrologueCaller'],
                              capture_output=True, text=True, timeout=15, check=True)
        print(read.stdout, end='', flush=True)
        actual = re.search(r'weightedSamples=(\d+) total=(\d+)', read.stdout)
        assert actual and actual.groups() == (samples, total), read.stdout
        converted = work / (name + '.converted.otlp')
        subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(converted)],
                       cwd=work, timeout=15, check=True)
        validate_otlp(work / (name + '.native.otlp'), frame, int(total), aggregated=True,
                      expected_values=int(total), expected_type=selector, expected_unit='events')
        validate_otlp(converted, frame, int(samples), expected_values=int(total),
                      expected_type=selector, expected_unit='events')
    print('SOFTWARE_PROLOGUE_EXPORTS_OK captures=10 aliases=2 rearmed=2 push=1 body=1 exactWeights=1 nativeCallers=1', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--cet-launcher', type=Path)
    parser.add_argument('--prologue-only', action='store_true')
    parser.add_argument('--recording-directory', type=Path)
    args = parser.parse_args()
    if args.recording_directory and not args.prologue_only:
        parser.error('--recording-directory requires --prologue-only')
    root = Path(__file__).resolve().parents[1]
    candidate = args.candidate.resolve()
    library, jar, helper = [candidate / name for name in ['asyncProfiler.dll', 'asprof-windows.jar', 'asprof-helper.exe']]
    application, fixture = args.application.resolve(), args.fixture.resolve()
    paths = [library, jar, helper, application, fixture]
    if args.cet_launcher:
        paths.append(args.cet_launcher.resolve())
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    manifest = json.loads((candidate / 'artifacts.json').read_text(encoding='utf-8'))
    for path in [library, jar, helper]:
        assert before[str(path)].upper() == manifest[path.name].upper(), path
    work = args.recording_directory.resolve() if args.recording_directory else Path(tempfile.mkdtemp(prefix='asprof-software-entry-'))
    if args.recording_directory:
        assert json.loads((work / 'inputs.json').read_text(encoding='utf-8')) == before, 'Retained capture inputs differ'
    else:
        (work / 'inputs.json').write_text(json.dumps(before, indent=2), encoding='utf-8')
    print('Evidence:', work, flush=True)
    if args.prologue_only:
        prologue_capture(args.java_home.resolve(), candidate, application, fixture, work, root,
                         retained=bool(args.recording_directory))
        assert before == {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        return
    result = subprocess.run([str(application), str(library), str(fixture), str(work)],
                            cwd=work, capture_output=True, text=True, timeout=45)
    text = result.stdout + result.stderr
    (work / 'native.log').write_text(text, encoding='utf-8')
    print(text, end='', flush=True)
    result.check_returncode()
    assert 'SOFTWARE_ENTRY_APPLICATION_OK' in text and '[ERROR]' not in text, text
    metrics = {}
    for line in text.splitlines():
        name, _, value = line.partition(' ')
        if re.fullmatch(r'\d+', value):
            metrics[name] = int(value)
    for name in ['windows_software_probe_failed', 'windows_software_probe_unprepared',
                 'windows_software_probe_dropped', 'events_dropped_total',
                 'calltracestorage_overflows_total', 'windows_import_failed']:
        assert metrics[name] == 0, (name, metrics.get(name))
    classes = work / 'classes'
    classes.mkdir()
    java = args.java_home.resolve() / 'bin/java.exe'
    subprocess.run([str(args.java_home.resolve() / 'bin/javac.exe'), '--release', '17', '-cp', str(jar), '-d', str(classes),
                    str(root / 'tests/ReadCounters.java'), str(root / 'tests/ReadWindows.java'), str(root / 'tests/SoftwareEntryJavaSmoke.java')],
                   check=True)
    selectors = re.search(r'target=(\S+) alternate=(\S+)', text)
    assert selectors, text
    for name, period, samples, total, frame, caller, selector in [
            ('entry', 5, 6, 30, 'SoftwareEntryTarget', 'NativeSoftwareEntryCaller', selectors[1]),
            ('alternate', 3, 1, 3, 'SoftwareEntryAlternate', 'NativeSoftwareAlternateSelected', selectors[2])]:
        recording = work / (name + '.jfr')
        collapsed = work / (name + '.total.collapsed')
        read = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters', str(recording),
                               str(collapsed), 'events', str(period), frame, caller],
                              check=True, capture_output=True, text=True, timeout=15)
        print(read.stdout, end='', flush=True)
        counts = re.search(r'weightedSamples=(\d+) total=(\d+)', read.stdout)
        assert tuple(map(int, counts.groups())) == (samples, total), read.stdout
        converted = work / (name + '.otlp')
        subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(converted)],
                       check=True, cwd=work, timeout=15)
        validate_otlp(converted, frame, samples, expected_values=total,
                      expected_type=selector, expected_unit='events')
    java_work = work / 'java'
    java_work.mkdir()
    java_result = subprocess.run([str(java), '-cp', str(classes) + ';' + str(jar),
                                  'SoftwareEntryJavaSmoke', str(library), str(fixture), str(java_work)],
                                 cwd=work, capture_output=True, text=True, timeout=30)
    java_text = java_result.stdout + java_result.stderr
    (work / 'java.log').write_text(java_text, encoding='utf-8')
    print(java_text, end='', flush=True)
    java_result.check_returncode()
    assert 'SOFTWARE_ENTRY_JAVA_OK' in java_text, java_text
    for name, period, frame, caller in [('java', 3, 'call', 'selected'), ('java-rearm', 2, 'call', 'selected'),
                                        ('java-next', 1, 'other', 'alternate')]:
        read = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters',
                               str(java_work / (name + '.jfr')), str(java_work / (name + '.total.collapsed')),
                               'events', str(period), frame, caller],
                              check=True, capture_output=True, text=True, timeout=15)
        print(read.stdout, end='', flush=True)
        assert f'weightedSamples=1 total={period}' in read.stdout, read.stdout
    if args.cet_launcher:
        for mode in ['compatible', 'strict']:
            cet_work = work / mode
            cet_work.mkdir()
            run = subprocess.run([str(args.cet_launcher.resolve()), mode, str(application), str(library),
                                  str(fixture), str(cet_work)], cwd=work, capture_output=True, text=True, timeout=45)
            cet_text = run.stdout + run.stderr
            (work / (mode + '.log')).write_text(cet_text, encoding='utf-8')
            print(mode, run.returncode, cet_text, flush=True)
            run.check_returncode()
            assert 'SOFTWARE_ENTRY_APPLICATION_OK' in cet_text and 'SOFTWARE_ENTRY_CET_CHILD_EXIT=0' in cet_text, cet_text
            for name, period, total, caller in [('entry', 5, 30, 'NativeSoftwareEntryCaller'),
                                                ('alternate', 3, 3, 'NativeSoftwareAlternateSelected')]:
                read = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters',
                                       str(cet_work / (name + '.jfr')),
                                       str(cet_work / (name + '.total.collapsed')), 'events', str(period),
                                       'SoftwareEntry', caller], check=True, capture_output=True, text=True, timeout=15)
                assert f'total={total} ' in read.stdout, read.stdout
                print(read.stdout, end='', flush=True)
    floating = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters', str(work / 'floating.jfr'),
                               str(work / 'floating.total.collapsed'), 'events', '1',
                               'SoftwareEntryFloating', 'NativeSoftwareFloatingCaller'],
                              check=True, capture_output=True, text=True, timeout=15)
    assert 'weightedSamples=1 total=1 ' in floating.stdout, floating.stdout
    print(floating.stdout, end='', flush=True)
    for name, count, frame, caller in [('immediate', 1, 'SoftwareEntryImmediate', 'NativeSoftwareImmediateCaller'),
                                       ('comparison', 3, 'SoftwareEntryComparison', 'NativeSoftwareComparisonCaller')]:
        read = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters', str(work / (name + '.jfr')),
                               str(work / (name + '.total.collapsed')), 'events', '1', frame, caller],
                              check=True, capture_output=True, text=True, timeout=15)
        assert f'weightedSamples={count} total={count} ' in read.stdout, read.stdout
        print(read.stdout, end='', flush=True)
    io_work = work / 'io-failure'
    io_work.mkdir()
    failed_io = subprocess.run([str(application), str(library), str(fixture), str(io_work), 'io-failure'],
                               cwd=work, capture_output=True, text=True, timeout=45)
    io_text = failed_io.stdout + failed_io.stderr
    (work / 'io-failure.log').write_text(io_text, encoding='utf-8')
    print(io_text, end='', flush=True)
    failed_io.check_returncode()
    assert 'SOFTWARE_ENTRY_IO_TRANSPARENCY_OK' in io_text, io_text
    recovery = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters',
                               str(io_work / 'recovery.jfr'), str(io_work / 'recovery.total.collapsed'),
                               'events', '1', 'SoftwareEntryAlternate', 'NativeSoftwareAlternateSelected'],
                              check=True, capture_output=True, text=True, timeout=15)
    assert 'weightedSamples=1 total=1 ' in recovery.stdout, recovery.stdout
    print(recovery.stdout, end='', flush=True)
    subprocess.run([str(java), '-cp', str(classes), 'ReadWindows', str(work / 'window.jfr'),
                    '2', '2', 'bounded', 'NativeSoftwareWindowInside', '2'], check=True, timeout=15)
    assert before == {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    print('SOFTWARE_ENTRY_EXPORTS_OK captures=8 perThread=1 phaseReset=1 exactWeights=1 nativeCallers=1 inputsStable=1', flush=True)


if __name__ == '__main__':
    main()
