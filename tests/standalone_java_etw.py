# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify captured Java metadata without treating ETW's incomplete physical stacks as complete."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile
from read_otlp import validate as validate_otlp


def hotspot_compiler_options(java):
    """Disable a JVMCI compiler when present; JDK27 builds may have no JVMCI."""
    flags = subprocess.run([str(java), '-XX:+UnlockExperimentalVMOptions', '-XX:+PrintFlagsFinal', '-version'],
                           capture_output=True, text=True, check=True).stdout
    return ['-XX:+UnlockExperimentalVMOptions', '-XX:-UseJVMCICompiler'] if re.search(r'\bUseJVMCICompiler\s+= true\b', flags) else []


def validate_metadata_metrics(text):
    assert 'windows_java_metadata_failed 0\n' in text and not re.search(r'windows_java_metadata_failed [1-9]\d*\n', text)
    assert 'windows_java_unwind_failures 0\n' in text and not re.search(r'windows_java_unwind_failures [1-9]\d*\n', text)


def validate_recording(java, classes, jar, recording, target, mode, features=''):
    subprocess.run([str(java), '-cp', str(classes), 'ReadJavaEtw', str(recording), target, mode, features], check=True)
    method = {'adapters': 'adapterTarget', 'scalar': 'unprovenTarget', 'unproven': 'unprovenFmaTarget'}.get(mode)
    expected_frame = target + '.' + method if method else None
    validate_totals(java, classes, jar, recording, target, expected_frame)


def validate_totals(java, classes, jar, recording, target, expected_frame=None, *, counter_unit='ns',
                    expected_type='cpu', expected_unit='nanoseconds'):
    counts = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters', str(recording), str(recording) + '.collapsed', counter_unit],
                            check=True, capture_output=True, text=True)
    print(counts.stdout, end='', flush=True)
    samples, total = map(int, re.search(r'weightedSamples=(\d+) total=(\d+)', counts.stdout).groups())
    exported = recording.with_suffix('.otlp')
    subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(exported)], check=True)
    if expected_frame is None:
        expected_frame = target + ('.burn' if target == 'EtwJavaPayload' else '.燃烧𠮷')
    validate_otlp(exported, expected_frame, samples,
                  expected_values=total, expected_type=expected_type, expected_unit=expected_unit)
    return samples, total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--case', choices=['plain', 'unload', 'interpreted', 'java-only', 'java-only-interpreted', 'java-only-cpu-id', 'java-only-cpu', 'c1', 'restart', 'restart-plain', 'restart-reflect', 'cpu', 'exceptions', 'adapters', 'scalar', 'unproven', 'exit', 'reflect', 'reflect-cpu'], default='plain')
    parser.add_argument('--java-option', action='append', default=[])
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--jar', type=Path)
    parser.add_argument('--features', default='')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    agent = args.agent.resolve() if args.agent else root / 'build/core/native/asyncProfiler.dll'
    work = Path(tempfile.mkdtemp(prefix='asprof-java-etw-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    jar = args.jar.resolve() if args.jar else root / 'build/asprof-windows.jar'
    java = args.java_home / 'bin/java.exe'
    sources = [root / 'tests' / name for name in ['EtwJavaSmoke.java', 'EtwJavaPayload.java', 'ReadJavaEtw.java', 'ReadCounters.java']]
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar), '-d', str(classes), *map(str, sources)], check=True)
    recording = work / 'java.jfr'
    vm_options = {'interpreted': ['-Xint'], 'java-only-interpreted': ['-Xint'], 'c1': ['-XX:TieredStopAtLevel=1'],
                  'adapters': ['-XX:CompileCommand=exclude,EtwJavaSmoke.adapters']}.get(args.case, [])
    if args.features:
        vm_options += ['-Dasprof.etw.features=' + args.features, '-Dasprof.etw.verify.features=true']
    command = [str(java), '-XX:CompileCommand=dontinline,EtwJavaSmoke.*', '-Xlog:class+unload=info', *vm_options, *args.java_option,
               '-cp', str(classes) + ';' + str(jar), 'EtwJavaSmoke', str(agent), str(recording), args.case]
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=60, cwd=work)
    text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
    print(text, flush=True)
    result.check_returncode()
    if args.features:
        assert 'ETW_SAMPLED_STATE_FEATURES_REJECTED' in text, text
    if 'stats' in args.features:
        assert re.search(r'stackwalk_ns_total [1-9]\d*\n', text), text
        assert re.search(r'stackwalk_ns_avg [1-9]\d*\n', text), text
    if args.case == 'exit':
        subprocess.run([str(java), '-cp', str(classes), 'ReadJavaEtw', str(recording), 'EtwJavaSmoke', 'plain'], check=True)
        print('JAVA_ETW_VM_EXIT_OK', flush=True)
        return
    validate_metadata_metrics(text)
    if args.case == 'unproven':
        # The exact workload's default Graal 21/25 C2 code is checked by standalone_fma_snapshot.py.
        # Other compiler configurations need their own byte capture and rejection proof.
        assert re.search(r'windows_etw_unproven_cfi_stacks [1-9]\d*\n', text), text
    if args.case in ['interpreted', 'java-only-interpreted']:
        assert re.search(r'windows_java_unmapped_vm_pcs [1-9]\d*\n', text)
    elif args.case != 'cpu' and not args.case.endswith('-cpu'):
        assert re.search(r'windows_java_decoded [1-9]\d*\n', text)
    if args.case in ['unload', 'restart']:
        assert 'UNLOADED_LOADERS 8' in text and re.search(r'windows_java_unloads [1-9]\d*\n', text)
    target = 'EtwJavaPayload' if args.case in ['unload','reflect','reflect-cpu'] else 'EtwJavaSmoke'
    validate_recording(java, classes, jar, recording, target, 'cpu' if args.case == 'reflect-cpu' else args.case, args.features)
    if args.case.startswith('restart'):
        assert 'METADATA_RESET_OK' in text
        second = 'unload' if args.case == 'restart' else args.case.removeprefix('restart-')
        validate_recording(java, classes, jar, Path(str(recording) + '.restart.jfr'),
                           'EtwJavaSmoke' if second == 'plain' else 'EtwJavaPayload', second, args.features)
    print('JAVA_ETW_METADATA_OK', args.case, flush=True)


if __name__ == '__main__':
    main()
