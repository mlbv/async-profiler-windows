# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Check per-thread native probe periods, window/filter phase and sampled argument weights."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--fixture', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-probe-period-'))
    print('Evidence:', work, flush=True)
    agent = work / 'asyncProfiler.dll'
    shutil.copy2(args.agent or root / 'build/core/native/asyncProfiler.dll', agent)
    classes = work / 'classes'
    classes.mkdir()
    sources = list((root / 'core/src/api/one/profiler').glob('*.java'))
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes), *map(str, sources),
                    *(str(root / 'tests' / name) for name in ['NativeProbePeriod.java', 'ReadProbeArguments.java', 'ReadWindows.java'])], check=True)
    fixture = args.fixture
    if fixture is None:
        native = work / 'native'
        native.mkdir()
        vswhere = Path('C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe')
        installation = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
            'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
        if not installation:
            raise RuntimeError('MSVC tools required for native probe period fixture')
        fixture = native / 'nativeProbePeriod.dll'
        response = native / 'fixture.rsp'
        response.write_text(' '.join(['/nologo', '/std:c++20', '/Od', '/MD', '/EHsc', '/W4', '/WX', '/Z7', '/LD',
            f'/I"{args.java_home / "include"}"', f'/I"{args.java_home / "include/win32"}"',
            f'/Fo"{native / "fixture.obj"}"', f'/Fe"{fixture}"', f'"{root / "tests/native_probe_period.cpp"}"',
            '/link', '/DEBUG', f'/IMPLIB:"{native / "fixture.lib"}"', f'/PDB:"{native / "fixture.pdb"}"']), encoding='utf-8')
        script = native / 'build.cmd'
        script.write_text(f'@echo off\ncall "{Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"}" >nul\n'
            f'if errorlevel 1 exit /b 1\ncl.exe @"{response}"\nexit /b %errorlevel%\n', encoding='utf-8')
        subprocess.run(['cmd.exe', '/d', '/c', str(script)], check=True)
    java = args.java_home / 'bin/java.exe'
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        result = subprocess.run([str(java), '-cp', str(classes), 'NativeProbePeriod', str(agent), str(fixture), str(work)],
                                cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=45)
    print((work / 'target.log').read_text(encoding='utf-8', errors='replace'), end='', flush=True)
    result.check_returncode()
    for name, weights, mode in [('uneven', [205], 'workers'), ('window-phase', [203,403], 'java'),
                                ('filter-phase', [203,403], 'java'), ('epoch-before', [], 'java'), ('epoch-after', [605], 'java')]:
        recording = work / (name + '.jfr')
        subprocess.run([str(java), '-cp', str(classes), 'ReadProbeArguments', str(recording),
            ','.join(map(str, weights)), 'total', mode, 'NativeProbePeriod'], check=True)
        rows = Path(str(recording) + '.collapsed').read_text(encoding='utf-8').splitlines()
        assert sum(int(row.rsplit(' ', 1)[1]) for row in rows if row.strip()) == sum(weights), (name, rows)
        if name == 'window-phase':
            subprocess.run([str(java), '-cp', str(classes), 'ReadWindows', str(recording), '2', '2', 'bounded'], check=True)
        print('PROBE_PERIOD_OK', name, weights, flush=True)


if __name__ == '__main__':
    main()
