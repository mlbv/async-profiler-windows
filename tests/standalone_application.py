# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Exercise the public C API in an executable that never loads a JVM."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-native-application-'))
    print('Evidence:', work, flush=True)
    subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                    str(root / 'tests/build_native_fixture.ps1'), '-JdkHome', str(args.java_home),
                    '-OutputDirectory', str(work / 'native'), '-StandaloneFixture', '-DebugSymbols'], check=True)
    output = work / '目录🙂'
    output.mkdir()
    result = subprocess.run([str(work / 'native/nativeApiApplication.exe'), str(root / 'build/core/native/asyncProfiler.dll'), str(output)],
                            capture_output=True, text=True, timeout=30, cwd=work)
    (work / 'native.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    print(result.stdout, result.stderr, flush=True)
    result.check_returncode()
    assert 'NATIVE_API_OK' in result.stdout
    pointer = next(line.split()[1] for line in result.stdout.splitlines() if line.startswith('ALLOCATION '))
    classes = work / 'classes'
    classes.mkdir()
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes),
                    str(root / 'tests/ReadCounters.java'), str(root / 'tests/ReadNativeApplication.java')], check=True)
    subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(classes), 'ReadNativeApplication', str(output), pointer], check=True)


if __name__ == '__main__':
    main()
