# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify Java metadata across successful and rejected class changes during ETW capture."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile
from standalone_java_etw import validate_totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--interpreted', action='store_true')
    parser.add_argument('--restart-during-change', action='store_true')
    parser.add_argument('--java-option', action='append', default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-java-change-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    java = args.java_home / 'bin/java.exe'
    javac = args.java_home / 'bin/javac.exe'
    jar = root / 'build/asprof-windows.jar'
    sources = ['EtwClassChange.java', 'EtwJavaPayload.java', 'ReadJavaChange.java', 'ReadCounters.java']
    subprocess.run([str(javac), '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar), '-d', str(classes),
                    *(str(root / 'tests' / name) for name in sources)], check=True)
    original = (root / 'tests/EtwJavaPayload.java').read_text(encoding='utf-8')
    versions = []
    for version in [1, 2]:
        directory = work / f'version{version}'
        directory.mkdir()
        source = directory / 'EtwJavaPayload.java'
        source.write_text('\n' * (100 * version) + original.replace('180_000_000L', '240_000_000L' if version == 1 else '300_000_000L'), encoding='utf-8')
        subprocess.run([str(javac), '--release', '17', '-g', '-d', str(directory), str(source)], check=True)
        versions.append(directory / 'EtwJavaPayload.class')
    manifest = work / 'agent.mf'
    manifest.write_text('Manifest-Version: 1.0\nPremain-Class: EtwClassChange\nCan-Redefine-Classes: true\nCan-Retransform-Classes: true\n\n', encoding='ascii')
    agent = work / 'change-agent.jar'
    with zipfile.ZipFile(agent, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('META-INF/MANIFEST.MF', manifest.read_bytes())
        for path in classes.rglob('*.class'):
            archive.write(path, path.relative_to(classes).as_posix())
    recording = work / 'java.jfr'
    command = [str(java), *args.java_option, '-javaagent:' + str(agent), *(['-Xint'] if args.interpreted else []),
               '-cp', str(agent) + ';' + str(jar), 'EtwClassChange', str(root / 'build/core/native/asyncProfiler.dll'),
               str(recording), *map(str, versions)]
    if args.restart_during_change: command.append('restart')
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=45, cwd=work)
    text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
    print(text, flush=True)
    result.check_returncode()
    assert 'JAVA_CLASS_CHANGE_OK' in text
    assert 'JAVA_CLASS_CHANGE_RESET_OK' in text
    for metric in ['windows_java_metadata_failed', 'windows_java_unwind_failures', 'windows_java_mapping_unsafe']:
        values = re.findall(r'^' + metric + r' (\d+)$', text, re.M)
        assert values and all(int(value) == 0 for value in values), text
    active = list(map(int, re.findall(r'^windows_java_active_class_changes (\d+)$', text, re.M)))
    changes = list(map(int, re.findall(r'^windows_java_class_changes (\d+)$', text, re.M)))
    assert active[-1] == 0 and (changes[0] >= 2 and changes[-1] >= 1 if args.restart_during_change else changes[-1] >= 4), text
    assert int(re.findall(r'^windows_java_transition_pcs (\d+)$', text, re.M)[-1]) > 0, text
    if args.restart_during_change:
        assert active[0] == 2 and 'JAVA_CLASS_CHANGE_RESTART_OK' in text
        validate_totals(java, classes, jar, recording, 'EtwJavaPayload')
        recording = Path(str(recording) + '.restart.jfr')
    subprocess.run([str(java), '-cp', str(classes), 'ReadJavaChange', str(recording),
                    'interpreted' if args.interpreted else 'compiled',
                    *(['restarted'] if args.restart_during_change else [])], check=True)
    validate_totals(java, classes, jar, recording, 'EtwJavaPayload')
    print('JAVA_CHANGE_METADATA_OK', flush=True)


if __name__ == '__main__':
    main()
