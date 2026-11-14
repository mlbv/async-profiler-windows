# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Upstream's non-Java flows: a native application creates a JVM before, after or between recordings, or on another thread."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True, help='JDK 8 or later whose JVM the application creates')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    native = root / 'build/core/native'
    work = Path(tempfile.mkdtemp(prefix='asprof-nonjava-'))
    print('Evidence:', work, flush=True)

    # jvm.dll version classification behind the readiness check for JVMs with unnamed threads.
    subprocess.run(['cmake', '--build', str(native), '--target', 'jvmVersionTest'], check=True)
    subprocess.run([str(native / 'jvm-version-test.exe')], check=True)

    subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(root / 'tests/build_native_fixture.ps1'),
                    '-JdkHome', str(args.java_home), '-OutputDirectory', str(work / 'application'), '-NonjavaApplication', '-DebugSymbols'], check=True)
    classes = work / 'classes'
    classes.mkdir()
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '-d', str(classes), str(root / 'tests/NonjavaTask.java')], check=True)

    def flow(name, number, *outputs):
        command = [str(work / 'application/nativeNonjavaApplication.exe'), number, str(native / 'asyncProfiler.dll'), str(args.java_home),
                   str(classes), *(str(work / output) for output in outputs)]
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=600, cwd=work)
        (work / f'{name}.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        assert result.returncode == 0, f'{name}: exit code {result.returncode}\n{result.stderr}'
        return [(work / output).read_text(encoding='utf-8') for output in outputs]

    jvm_first, = flow('jvmFirst', '1', 'jvm-first.collapsed')
    assert 'cpuHeavyTask' in jvm_first
    profiler_first, = flow('profilerFirst', '2', 'profiler-first.collapsed')
    assert 'cpuHeavyTask' not in profiler_first
    before, after = flow('jvmInBetween', '3', 'in-between-1.collapsed', 'in-between-2.collapsed')
    assert 'nativeBurnCpu' in before and 'cpuHeavyTask' not in before
    assert 'nativeBurnCpu' in after and 'cpuHeavyTask' in after
    different_thread, = flow('differentThread', '4', 'different-thread.collapsed')
    assert 'cpuHeavyTask' in different_thread
    print('NONJAVA_OK', flush=True)


if __name__ == '__main__':
    main()
