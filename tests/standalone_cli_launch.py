# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Profile native programs with asprof launch, which starts them through asprof-helper --preload."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path, help='Profiler DLL; asprof-helper.exe must be beside it')
    parser.add_argument('--asprof', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    asprof = (args.asprof or root / 'build/asprof.exe').resolve()
    agent = (args.agent or root / 'build/asyncProfiler.dll').resolve()
    java = args.java_home / 'bin/java.exe'
    work = Path(tempfile.mkdtemp(prefix='asprof-cli-launch-'))
    print('Evidence:', work, flush=True)
    subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(root / 'tests/build_native_fixture.ps1'),
                    '-JdkHome', str(args.java_home), '-OutputDirectory', str(work / 'application'), '-PreloadApplication', '-DebugSymbols'],
                   check=True)
    application = work / 'application/nativePreloadApplication.exe'
    classes = work / 'classes'
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes), str(root / 'tests/ReadPreload.java')], check=True)
    environment = {key: value for key, value in os.environ.items() if key.upper() != 'ASPROF_COMMAND'}

    def cli(*arguments, expected=0):
        command = [str(asprof), '--libpath', str(agent), *map(str, arguments)]
        result = subprocess.run(command, cwd=work, env=environment, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=120, stdin=subprocess.DEVNULL)
        print(arguments, result.returncode, result.stdout[-2000:], result.stderr[-2000:], flush=True)
        assert result.returncode == expected, (arguments, expected, result.returncode)
        return result

    def read(mode, recording):
        subprocess.run([str(java), '-cp', str(classes), 'ReadPreload', mode, str(recording)], check=True)

    # The program's full 32-bit exit code; its recording is finalized when it exits.
    for code in (37, 0xE0000001):
        result = cli('launch', '-f', f'exit-{code}.jfr', '--', application, 'exit', hex(code), expected=code)
        assert 'Launched PID' not in result.stderr and (work / f'exit-{code}.jfr').stat().st_size > 0, result.stderr

    # Without -f, the profile written at exit goes to stdout.
    result = cli('launch', '-e', 'cpu', '-i', '1ms', '-o', 'collapsed', '--', application, 'cpu')
    assert any('PreloadCpuWork' in row for row in result.stdout.splitlines()), result.stdout

    # Relative Unicode program and output paths resolve against the calling directory; %p is the program's PID.
    program = work / '程序 🙂/应用.exe'
    program.parent.mkdir()
    shutil.copyfile(application, program)
    cli('launch', '-e', 'cpu', '-i', '1ms', '-f', '输出 𠮷/cpu-%p.jfr', '--', program.relative_to(work), 'cpu')
    recordings = list((work / '输出 𠮷').iterdir())
    assert len(recordings) == 1 and re.fullmatch(r'cpu-\d+\.jfr', recordings[0].name), recordings
    read('cpu', recordings[0])

    # Ctrl+C reaches the program, whose exit finalizes the recording while asprof keeps waiting.
    interrupted = work / 'interrupted'
    hidden = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=0)
    subprocess.run([sys.executable, str(root / 'tests/console_interrupt.py'), str(interrupted), '3', str(asprof),
                    '--libpath', str(agent), 'launch', '-f', 'interrupted.jfr', '--', str(application), 'wait', str(work / 'wait.pid')],
                   cwd=work, env=environment, creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=hidden, check=True, timeout=60)
    print('interrupted', interrupted.with_suffix('.stderr').read_text(encoding='utf-8', errors='replace'), flush=True)
    # STATUS_CONTROL_C_EXIT; asprof exits with 1 instead if the recording was not finalized.
    assert int(interrupted.with_suffix('.exit').read_text(encoding='ascii')) == 0xC000013A
    assert (work / 'wait.pid').exists() and (work / 'interrupted.jfr').stat().st_size > 0

    # Preload failures exit with the helper's Windows error and its own message.
    wow64 = Path(os.environ['SystemRoot']) / 'SysWOW64/cmd.exe'
    result = cli('launch', '-f', 'wow64.jfr', '--', wow64, '/c', 'exit 0', expected=193)
    assert 'asprof-helper:' in result.stderr and 'A 32-bit process cannot load x64 DLLs' in result.stderr, result.stderr
    assert 'Profiler' not in result.stderr and not (work / 'wow64.jfr').exists(), result.stderr
    broken = work / 'broken/asyncProfiler.dll'
    broken.parent.mkdir()
    image = agent.read_bytes()
    assert b'KERNEL32.dll' in image
    broken.write_bytes(image.replace(b'KERNEL32.dll', b'BROKEN32.dll'))
    shutil.copyfile(agent.parent / 'asprof-helper.exe', broken.parent / 'asprof-helper.exe')
    marker = work / 'broken.marker'
    result = cli('--libpath', broken, 'launch', '-f', 'broken.jfr', '--', application, 'marker', marker, expected=126)
    assert 'asprof-helper:' in result.stderr and 'Windows error 126' in result.stderr, result.stderr
    assert not marker.exists() and not (work / 'broken.jfr').exists()

    assert 'only to JVM launches' in cli('launch', '--java', java, '--', application, 'exit', '0', expected=1).stderr
    print('CLI_LAUNCH_OK', flush=True)


if __name__ == '__main__':
    main()
