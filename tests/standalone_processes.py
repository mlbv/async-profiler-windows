# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Validate Windows process sampling against real x64 and WOW64 workloads."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-processes-'))
    print('Evidence:', work, flush=True)
    java = args.java_home / 'bin/java.exe'
    jar = root / 'build/asprof-windows.jar'
    classes = work / 'classes'
    classes.mkdir()
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8', '-cp', str(jar),
                    '-d', str(classes), str(root / 'tests/Fixture.java'), str(root / 'tests/ReadProcessSamples.java')], check=True)
    for arch in ['x64', 'x86']:
        output = work / arch
        subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                        str(root / 'tests/build_native_fixture.ps1'), '-JdkHome', str(args.java_home),
                        '-OutputDirectory', str(output), '-ProcessFixture', '-Architecture', arch], check=True)
        shutil.copyfile(output / 'processFixture.exe', output / '进程.exe')

    children = []
    logs = []

    def launch(name, command):
        path = work / (name + '.log')
        log = path.open('w')
        logs.append(log)
        process = subprocess.Popen(list(map(str, command)), cwd=work, stdout=log, stderr=subprocess.STDOUT)
        children.append(process)
        deadline = time.monotonic() + 15
        while True:
            text = path.read_text(encoding='utf-8', errors='replace')
            for line in text.splitlines():
                if line.startswith('READY '):
                    return process, line
            if process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError((name, process.poll(), text))
            time.sleep(.05)

    def cli(*arguments):
        result = subprocess.run([str(root / 'build/asprof.exe'), '--libpath', str(root / 'build/core/native/asyncProfiler.dll'),
                                 *map(str, arguments)], capture_output=True, text=True, timeout=30)
        with (work / 'commands.log').open('a', encoding='utf-8') as log:
            log.write(repr(arguments) + '\n' + result.stdout + result.stderr)
        result.check_returncode()

    try:
        pids = []
        for arch in ['x64', 'x86']:
            command = [work / arch / '进程.exe', work / arch / '进程🙂.bin']
            if arch == 'x86':
                command.append('尾' * 1000)
            worker, ready = launch(arch, command)
            assert int(ready.split()[2]) >= 32 * 1024 * 1024, 'The native workload has no private working set'
            pids.append(worker.pid)
        target, _ = launch('jvm', [java, '-cp', classes, 'Fixture', '90'])
        output = work / 'processes.jfr'
        cli('start', target.pid, '--proc', 1, '--cstack', 'no', '-f', output)
        time.sleep(5)
        cli('stop', target.pid)
        result = subprocess.run([str(java), '-cp', str(classes) + ';' + str(jar), 'ReadProcessSamples', str(output),
                                 str(os.getpid()), *map(str, pids)], capture_output=True, text=True, timeout=20)
        (work / 'events.txt').write_text(result.stdout + result.stderr, encoding='utf-8')
        print(result.stdout, result.stderr, flush=True)
        result.check_returncode()
        assert all(process.poll() is None for process in children)
    finally:
        for process in children:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
        for log in logs:
            log.close()
    print('PASS process sampling', flush=True)


if __name__ == '__main__':
    main()
