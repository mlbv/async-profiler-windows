# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Prepare Java ETW metadata and unwind tables at ordinary privilege, optionally with WhiteBox code storage and the JDK27 hot code heap."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--case', choices=['default', 'whitebox', 'whitebox-unsegmented', 'hot-code'], default='default')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-java-unwind-setup-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    agent = work / 'asyncProfiler.dll'
    shutil.copy2(args.agent or root / 'build/core/native/asyncProfiler.dll', agent)
    sources = list((root / 'core/src/api/one/profiler').glob('*.java'))
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes),
                    *map(str, sources), str(root / 'tests/JavaUnwindSetup.java')], check=True)
    release = (args.java_home / 'release').read_text(encoding='utf-8')
    feature = int(re.search(r'^JAVA_VERSION="(\d+)', release, re.M).group(1))
    options, warm, mode = [], '0', 'prepare'
    whitebox = args.case != 'default'
    if whitebox:
        options = ['-XX:+UnlockDiagnosticVMOptions', '-XX:+WhiteBoxAPI']
    if args.case == 'whitebox-unsegmented':
        options.append('-XX:-SegmentedCodeCache')
    elif args.case == 'hot-code':
        # Relocate sampled C2 nmethods into the MethodHot heap within seconds.
        options += ['-XX:+UnlockExperimentalVMOptions', '-XX:+HotCodeHeap', '-XX:+NMethodRelocation',
                   '-XX:HotCodeHeapSize=8m', '-XX:HotCodeStartupDelaySeconds=1', '-XX:HotCodeSampleSeconds=2',
                   '-XX:HotCodeIntervalSeconds=1', '-XX:HotCodeStablePercent=-1', '-XX:HotCodeSamplePercent=100',
                   '-XX:HotCodeCallLevel=2', '-Xlog:hotcode=debug']
        warm, mode = '8', 'cpu'
    with (work / 'run.log').open('w', encoding='utf-8') as log:
        result = subprocess.run([str(args.java_home / 'bin/java.exe'), *options, '--enable-native-access=ALL-UNNAMED',
                                 '-cp', str(classes), 'JavaUnwindSetup', str(agent), warm, mode, str(work / 'provider.jfr')],
                                cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    text = (work / 'run.log').read_text(encoding='utf-8', errors='replace')
    print(text, end='')
    result.check_returncode()
    metrics = {key: value for key, value in re.findall(r'^(windows_java\w+) (.*)$', text, re.M)}
    assert 'windows_java_unwind_first_error' not in metrics, metrics
    for key in ['windows_java_unwind_failures', 'windows_java_metadata_failed']:
        assert metrics[key] == '0', (key, metrics[key])
    for key in ['windows_java_unwind_publications', 'windows_java_unwind_methods', 'windows_java_unwind_codelets',
                'windows_java_unwind_runtime_stubs', 'windows_java_compilations', 'windows_java_prepared_classes']:
        assert int(metrics[key]) > 0, (key, metrics[key])
    if feature >= 21:
        assert metrics['windows_java_unwind_entry_barrier_known'] == '1', 'Method entry barrier stub not recognized'
    if whitebox:
        assert metrics['windows_java_unwind_code_cache_pages'] == '1' and int(metrics['windows_java_unwind_code_cache_bytes']) > 0
    if args.case == 'hot-code':
        relocated = sum(map(int, re.findall(r'Relocated (\d+) nmethods to the MethodHot heap', text)))
        assert relocated > 0, 'No nmethod reached the MethodHot heap'
        total, rooted = map(int, re.search(r'WORK_SAMPLES total=(\d+) rooted=(\d+)', text).groups())
        assert total > 0 and rooted == total, (total, rooted)
    print('JAVA_UNWIND_SETUP_OK', args.case, 'java=%d' % feature, flush=True)


if __name__ == '__main__':
    main()
