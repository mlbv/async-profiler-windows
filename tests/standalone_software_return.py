# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Prove software return-probe counts, caller stacks, unwinding and exported weights through the C API and Java."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from read_otlp import validate as validate_otlp


def read_counters(java, classes, recording, collapsed, period, frame, caller=None):
    command = [str(java), '-cp', str(classes), 'ReadCounters', str(recording), str(collapsed), 'events', str(period), frame]
    if caller:
        command.append(caller)
    read = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
    print(read.stdout, end='', flush=True)
    counts = re.search(r'weightedSamples=(\d+) total=(\d+)', read.stdout)
    assert counts, read.stdout
    return tuple(map(int, counts.groups()))


def application(path, arguments, work, log, launcher=None):
    command = ([str(launcher), log] if launcher else []) + [str(path)] + [str(value) for value in arguments]
    result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=120)
    text = result.stdout + result.stderr
    (work / (log + '.log')).write_text(text, encoding='utf-8')
    print(text, end='', flush=True)
    result.check_returncode()
    assert 'SOFTWARE_RETURN_APPLICATION_OK' in text and '[ERROR]' not in text, text
    for name in ['windows_software_probe_failed', 'windows_software_probe_unprepared', 'windows_software_probe_dropped',
                 'windows_import_failed', 'events_dropped_total', 'calltracestorage_overflows_total']:
        value = re.search(r'^' + name + r' (\d+)$', text, re.MULTILINE)
        assert value and int(value[1]) == 0, (name, value)
    for marker in ['RETURN_REJECTIONS_OK unproven=1 interior=1 nonEntry=1 noMetadata=1', 'RETURN_SHAPES_OK', 'RETURN_UNWIND_STEPPING_OK sehDispatch=1',
                   'RETURN_MSVC_OK', 'RETURN_UPROBE_PARITY_OK', 'RETURN_UPROBE_BRANCHES_OK', 'RETURN_REARM_GATE_OK']:
        assert marker in text, marker
    return text



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--application', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--msvc-fixture', type=Path, required=True)
    parser.add_argument('--cet-launcher', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    candidate = args.candidate.resolve()
    library, jar, helper = [candidate / name for name in ['asyncProfiler.dll', 'asprof-windows.jar', 'asprof-helper.exe']]
    application_path, fixture, msvc = args.application.resolve(), args.fixture.resolve(), args.msvc_fixture.resolve()
    paths = [library, jar, helper, application_path, fixture, msvc] + ([args.cet_launcher.resolve()] if args.cet_launcher else [])
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    manifest = json.loads((candidate / 'artifacts.json').read_text(encoding='utf-8'))
    for path in [library, jar, helper]:
        assert before[str(path)].upper() == manifest[path.name].upper(), path
    work = Path(tempfile.mkdtemp(prefix='asprof-software-return-'))
    (work / 'inputs.json').write_text(json.dumps(before, indent=2), encoding='utf-8')
    print('Evidence:', work, flush=True)
    fixtures = work / 'fixtures'
    fixtures.mkdir()
    shutil.copy2(fixture, fixtures / fixture.name)
    shutil.copy2(msvc, fixtures / 'softwareReturnMsvc.dll')
    owned = fixtures / fixture.name

    java = args.java_home.resolve() / 'bin/java.exe'
    classes = work / 'classes'
    classes.mkdir()
    subprocess.run([str(args.java_home.resolve() / 'bin/javac.exe'), '--release', '17', '-cp', str(jar), '-d', str(classes),
                    str(root / 'tests/ReadCounters.java'), str(root / 'tests/SoftwareReturnJava.java')], check=True)

    native = work / 'native'
    text = application(application_path, [library, owned, native], work, 'native')
    captures = re.findall(r'^RETURN_CAPTURE name=(\S+) leaf=(\S+) period=(\d+) samples=(\d+) total=(\d+) selector=(\S+)$',
                          text, re.MULTILINE)
    assert len(captures) == 42, captures
    for name, leaf, period, samples, total, selector in captures:
        recording = native / (name + '.jfr')
        frame = leaf.split('|')[0]
        assert read_counters(java, classes, recording, native / (name + '.total.collapsed'), period, frame) \
            == (int(samples), int(total)), name
        converted = native / (name + '.converted.otlp')
        subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(converted)],
                       cwd=work, timeout=30, check=True)
        validate_otlp(native / (name + '.native.otlp'), frame, int(total), aggregated=True,
                      expected_values=int(total), expected_type=selector, expected_unit='events')
        validate_otlp(converted, frame, int(samples), expected_values=int(total), expected_type=selector,
                      expected_unit='events')
    print(f'SOFTWARE_RETURN_EXPORTS_OK captures={len(captures)} exactWeights=1 callerLeaves=1', flush=True)

    if args.cet_launcher:
        for mode in ['compatible', 'strict']:
            directory = work / mode
            cet = application(application_path, [library, owned, directory], work, mode, args.cet_launcher.resolve())
            assert 'SOFTWARE_ENTRY_CET_CHILD_EXIT=0' in cet and 'SOFTWARE_RETURN_CET_POLICY' in cet, cet
            for name, leaf, period, samples, total, selector in re.findall(
                    r'^RETURN_CAPTURE name=(\S+) leaf=(\S+) period=(\d+) samples=(\d+) total=(\d+) selector=(\S+)$',
                    cet, re.MULTILINE):
                assert read_counters(java, classes, directory / (name + '.jfr'), directory / (name + '.total.collapsed'),
                                     period, leaf.split('|')[0]) == (int(samples), int(total)), (mode, name)
        print('SOFTWARE_RETURN_CET_OK compatible=1 strict=1', flush=True)

    java_work = work / 'java'
    java_work.mkdir()
    run = subprocess.run([str(java), '-cp', str(classes) + ';' + str(jar), 'SoftwareReturnJava', str(library), str(owned),
                          str(java_work)], cwd=work, capture_output=True, text=True, timeout=120)
    java_text = run.stdout + run.stderr
    (work / 'java.log').write_text(java_text, encoding='utf-8')
    print(java_text, end='', flush=True)
    run.check_returncode()
    assert 'SOFTWARE_RETURN_JAVA_OK' in java_text, java_text
    # Java stacks: the leaf after return is the JNI method's Java frame.
    for name, period, samples, frame, caller in [('java-framed', 2, 3, 'framed', 'chosen'),
                                                 ('java-framed-rearm', 3, 2, 'framed', 'chosen'),
                                                 ('java-jni', 1, 4, 'branched', 'main'),
                                                 ('java-sleep', 1, 7, 'napping', 'main'),
                                                 ('java-assert', 1, 5, 'asserting', 'main')]:
        assert read_counters(java, classes, java_work / (name + '.jfr'), java_work / (name + '.total.collapsed'), period,
                             frame, caller) == (samples, samples * period), name
    print('SOFTWARE_RETURN_JAVA_EXPORTS_OK captures=5 jniHost=1 chainedJvm=2', flush=True)
    assert before == {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    print('SOFTWARE_RETURN_OK inputsStable=1', flush=True)


if __name__ == '__main__':
    main()
