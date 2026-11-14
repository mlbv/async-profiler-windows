# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify Java page-fault and context-switch captures, locally elevated or through the broker."""
import argparse
import ctypes
import os
from pathlib import Path
import re
import subprocess
import time

from read_otlp import validate as validate_otlp
from standalone_etw import query_interval

import integrity


ZERO_METRICS = [
    'events_dropped_total', 'samples_skipped_total', 'calltracestorage_overflows_total',
    'windows_etw_failure', 'windows_etw_malformed_events', 'windows_etw_events_lost',
    'windows_etw_buffers_lost', 'windows_etw_realtime_buffers_lost', 'windows_etw_pending_evictions',
    'windows_etw_unsupported_stack_events', 'windows_etw_broker_potential_target_loss',
    'windows_etw_broker_cleanup_error', 'windows_etw_software_unknown_threads',
    'windows_etw_software_unproven_events', 'windows_etw_software_router_sequence_breaks',
    'windows_etw_software_router_reason', 'windows_etw_module_lifetime_ambiguous_pcs',
]
WORKLOAD = {'page-faults': 'touch', 'context-switches': 'sleeper'}


def cases(cpu):
    return ['page-faults:1', 'page-faults:7', 'context-switches:1', 'context-switches:2',
            'page-faults:1:cstack=no', 'context-switches:1:cstack=no', 'context-switches:1:record-cpu',
            f'context-switches:1:record-cpu,target-cpu={cpu}', f'page-faults:1:record-cpu,target-cpu={cpu}',
            'page-faults:1:alluser', 'context-switches:1:alluser', 'context-switches:3']


def wait_for(predicate, process, description, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        if process.poll() is not None:
            raise AssertionError(description + ': process exited ' + str(process.returncode))
        time.sleep(.05)
    raise AssertionError(description + ': timed out')


def metrics(path):
    values = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        name, _, value = line.partition(' ')
        if re.fullmatch(r'-?\d+', value.strip()):
            values[name] = int(value)
    return values


def rows(path):
    result = [line.rsplit(' ', 1) for line in path.read_text(encoding='utf-8').splitlines() if line]
    return [(stack, int(value)) for stack, value in result]


def validate(index, spec, work, java, classes, jar, broker):
    event, period, *rest = spec.split(':', 2)
    period, options = int(period), (rest[0].split(',') if rest else [])
    base = work / f'{index}-{event}-p{period}'
    recording = Path(str(base) + '.jfr')
    values = metrics(Path(str(base) + '.metrics'))
    for name in ZERO_METRICS:
        assert values[name] == 0, (spec, name, values[name])
    assert (values['windows_etw_broker_pid'] != 0) == broker, (spec, values['windows_etw_broker_pid'])
    total_rows, sample_rows = rows(Path(str(recording) + '.collapsed')), rows(Path(str(base) + '.samples.collapsed'))
    total, samples = sum(value for _, value in total_rows), sum(value for _, value in sample_rows)
    assert total == samples * period, (spec, samples, total)
    if 'alluser' in options and event == 'context-switches':
        # Switches happen in kernel mode; upstream's exclude_kernel counts none.
        assert samples == 0 and values['windows_etw_software_matched_events'] == 0, (spec, samples, values)
        print(f'CAPTURE_VERIFIED index={index} spec={spec} samples=0 kernelOnlyEventsExcluded=1', flush=True)
        return dict(spec=spec, samples=0, total=0)
    assert values['windows_etw_samples'] == values['samples_total'] == samples, (spec, samples, values)
    assert values['windows_etw_software_matched_events'] >= total, (spec, total, values)
    workload = WORKLOAD[event]
    counts = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters', str(recording), str(recording) + '.collapsed',
                             'events', str(period), workload], check=True, capture_output=True, text=True).stdout
    named = int(re.search(r'namedStacks=(\d+)', counts).group(1))
    assert re.search(rf'weightedSamples={samples} total={total} ', counts), (spec, counts)
    churn = sum(value for stack, value in sample_rows if 'churnWork' in stack)
    assert churn > 0, (spec, 'no churn-thread samples')
    if 'cstack=no' in options:
        assert not any('_[k]' in stack or 'NtDelayExecution' in stack for stack, _ in total_rows), (spec, 'native frames retained')
    if 'alluser' in options:
        assert not any('_[k]' in stack for stack, _ in total_rows), (spec, 'kernel frames retained')
    if 'record-cpu' in options:
        target = next((option.split('=')[1] for option in options if option.startswith('target-cpu=')), None)
        marker = f'[CPU-{target}]' if target else '[CPU-'
        assert all(marker in stack for stack, _ in total_rows), (spec, 'sample without expected CPU frame')
    partial = {kind: values['windows_etw_' + kind + '_partial_stacks'] for kind in ['java', 'vm', 'native']}
    incomplete, cut = values['windows_etw_incomplete_stacks'], values['windows_etw_unproven_cfi_stacks']
    validate_otlp(Path(str(base) + '.native.otlp'), workload, total, aggregated=True, expected_values=total,
                  expected_type=event, expected_unit='events')
    converted = Path(str(base) + '.converted.otlp')
    subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(converted)],
                   check=True, capture_output=True, text=True)
    validate_otlp(converted, workload, samples, expected_values=total, expected_type=event, expected_unit='events')
    shared = values['windows_etw_software_shared_user_stacks']
    print(f'CAPTURE_VERIFIED index={index} spec={spec} samples={samples} total={total} named={named} churn={churn} '
          f'partial={partial} incomplete={incomplete} cfiCut={cut} sharedUser={shared}', flush=True)
    return dict(spec=spec, samples=samples, total=total, named=named, churn=churn, partial=partial,
                incomplete=incomplete, cut=cut, shared=shared)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--mode', choices=['local', 'broker'], required=True)
    parser.add_argument('--output', type=Path, required=True, help='New evidence directory (must not exist)')
    parser.add_argument('--recording-directory', type=Path, help='Validate retained captures without another recording')
    parser.add_argument('--target-cpu', type=int, default=2)
    args = parser.parse_args()
    if args.recording_directory:
        work = args.recording_directory.resolve()
        java = args.java_home.resolve() / 'bin/java.exe'
        results = [validate(index, spec, work, java, work / 'classes', args.jar.resolve(), args.mode == 'broker')
                   for index, spec in enumerate(cases(args.target_cpu))]
        print(f'SOFTWARE_JAVA_OK mode={args.mode} captures={len(results)} retained=1', flush=True)
        return
    integrity.require_elevated()
    root = Path(__file__).resolve().parents[1]
    work = args.output.resolve()
    work.mkdir(parents=True)
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    agent, jar = args.agent.resolve(), args.jar.resolve()
    java = args.java_home.resolve() / 'bin/java.exe'
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-cp', str(jar), '-d', str(classes),
                    str(root / 'tests/SoftwareJavaSmoke.java'), str(root / 'tests/ReadCounters.java')], check=True)
    previous_interval = query_interval(0)
    selected = cases(args.target_cpu)
    endpoint = '-' if args.mode == 'local' else ''
    command = [str(java), '-Djava.io.tmpdir=' + str(work), '-XX:+UnlockDiagnosticVMOptions', '-XX:+WhiteBoxAPI',
               '-cp', str(classes) + ';' + str(jar), 'SoftwareJavaSmoke', str(agent), str(work), endpoint, *selected]
    target = broker = None
    temporary = dict(TEMP=str(work), TMP=str(work))
    try:
        with (work / 'target.log').open('w', encoding='utf-8') as target_log, (work / 'broker.log').open('w', encoding='utf-8') as broker_log:
            if args.mode == 'local':
                target = subprocess.Popen(command, stdout=target_log, stderr=subprocess.STDOUT, cwd=work,
                                          env=dict(os.environ, **temporary))
            else:
                target = integrity.deelevated_popen(command, stdout=target_log, stderr=subprocess.STDOUT, cwd=work, env=temporary)
            ready = work / 'ready'
            wait_for(ready.exists, target, 'JVM ready')
            pid = int(ready.read_text())
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            if args.mode == 'broker':
                broker = subprocess.Popen([str(agent.parent / 'asprof-helper.exe'), '--etw-broker', str(pid)],
                                          stdout=broker_log, stderr=subprocess.STDOUT, cwd=work, env=dict(os.environ, **temporary))
                wait_for(lambda: 'ETW_BROKER_READY ' in (work / 'broker.log').read_text(errors='replace'), broker, 'Broker ready')
            # Two processors keep target-cpu captures populated while retaining cross-processor switches.
            mask = (1 << args.target_cpu) | (1 << (args.target_cpu + 1))
            kernel.OpenProcess.restype = ctypes.c_void_p
            handle = kernel.OpenProcess(0x0200 | 0x0400, False, pid)
            assert handle, ('OpenProcess', ctypes.get_last_error())
            assert kernel.SetProcessAffinityMask(ctypes.c_void_p(handle), ctypes.c_size_t(mask)), ('Affinity', ctypes.get_last_error())
            kernel.CloseHandle(ctypes.c_void_p(handle))
            (work / 'release').touch()
            assert target.wait(timeout=600) == 0, (work / 'target.log').read_text(errors='replace')
            if broker:
                assert broker.wait(timeout=30) == 0, 'Broker cleanup failed'
        text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
        assert f'SOFTWARE_JAVA_CAPTURES_OK captures={len(selected)}' in text, text
        assert query_interval(0) == previous_interval, 'Software capture changed the sampling interval'
        results = [validate(index, spec, work, java, classes, jar, args.mode == 'broker') for index, spec in enumerate(selected)]
        print(f'SOFTWARE_JAVA_OK mode={args.mode} captures={len(results)} restarts={len(results) - 1}', flush=True)
    finally:
        if target and target.poll() is None:
            target.kill()
            target.wait(timeout=10)
        if broker and broker.poll() is None:
            broker.wait(timeout=30)


if __name__ == '__main__':
    main()
