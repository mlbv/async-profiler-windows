# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Validate real custom-source overflow captures and native API descriptor grammar."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

from standalone_java_etw import validate_metadata_metrics, validate_totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--case', choices=['raw', 'descriptor', 'default', 'range', 'comma'], required=True)
    parser.add_argument('--work-directory', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = args.work_directory.resolve() if args.work_directory else Path(tempfile.mkdtemp(prefix='asprof-raw-pmu-'))
    work.mkdir(parents=True, exist_ok=True)
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir(exist_ok=True)
    java = args.java_home / 'bin/java.exe'
    jar = root / 'build/asprof-windows.jar'
    agent = args.agent.resolve()
    assert agent.is_file() and agent.with_name('asprof-helper.exe').is_file(), agent
    sources = ['EtwJavaSmoke.java', 'EtwJavaPayload.java', 'ReadJavaEtw.java', 'ReadCounters.java', 'RawPmuGrammar.java']
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar),
                    '-d', str(classes), *(str(root / 'tests' / source) for source in sources)], check=True)
    recording = work / 'raw.jfr'
    classpath = str(classes) + ';' + str(jar)
    if args.case in ['comma', 'range']:
        command = [str(java), '-cp', classpath, 'RawPmuGrammar', str(agent), args.case]
    else:
        event = 'cpu/event=0xc0:umask=0/' if args.case == 'descriptor' else 'rc0'
        options = ['-Dasprof.etw.interval=default'] if args.case == 'default' else []
        command = [str(java), '-XX:CompileCommand=dontinline,EtwJavaSmoke.*', '-Dasprof.etw.event=' + event, *options,
                   '-cp', classpath, 'EtwJavaSmoke', str(agent), str(recording), 'plain']
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=60, cwd=work)
    text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
    print(text, flush=True)
    result.check_returncode()
    if args.case in ['comma', 'range']:
        assert ('RAW_PMU_RANGE_REJECTED ' if args.case == 'range' else 'RAW_PMU_COMMA_REJECTED ') in text
        print('RAW_PMU_NATIVE_GRAMMAR_OK', args.case, flush=True)
        return
    assert 'RAW_PMU_SOURCE_REMOVED' in text
    assert 'windows_etw_failure 0\n' in text
    assert re.search(r'windows_etw_samples [1-9]\d*\n', text)
    for metric in ['malformed_events', 'events_lost', 'buffers_lost', 'realtime_buffers_lost']:
        assert f'windows_etw_{metric} 0\n' in text
    validate_metadata_metrics(text)
    subprocess.run([str(java), '-cp', str(classes), 'ReadJavaEtw', str(recording), 'EtwJavaSmoke', 'plain'], check=True)
    samples, total = validate_totals(java, classes, jar, recording, 'EtwJavaSmoke', counter_unit='events',
                                    expected_type=event, expected_unit='events')
    assert total == samples * 1000000, (samples, total)
    print('RAW_PMU_OVERFLOW_OK', args.case, 'samples=' + str(samples), 'events=' + str(total), flush=True)


if __name__ == '__main__':
    main()
