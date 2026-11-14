# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Check native probe grammar, Windows ABI argument weights, and data access modes."""
import argparse
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
from read_otlp import validate as validate_otlp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--cli-jar', type=Path)
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--case', choices=['all', 'valid', 'invalid'], default='all')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-probe-arguments-'))
    print('Evidence:', work, flush=True)
    java = args.java_home / 'bin/java.exe'
    jar = args.cli_jar.resolve() if args.cli_jar else root / 'build/asprof-windows.jar'
    agent = args.agent or root / 'build/core/native/asyncProfiler.dll'
    classes = work / 'classes'
    classes.mkdir()
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes),
                    str(root / 'tests/NativeProbeArguments.java'), str(root / 'tests/ReadProbeArguments.java')], check=True)
    fixture = args.fixture
    if fixture is None:
        build = work / 'native'
        build.mkdir()
        fixture = build / 'nativeProbeArguments.dll'
        # The shared fixture builder deliberately does not acquire another mode
        # for this independent four-argument ABI workload.
        vswhere = Path('C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe')
        install = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
                                           'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
        if not install:
            raise RuntimeError('MSVC x64 build tools are required for the argument fixture')
        response = build / 'fixture.rsp'
        flags = ['/nologo', '/std:c++20', '/Od', '/MD', '/EHsc', '/W4', '/WX', '/Z7', '/LD',
                 f'/I"{args.java_home / "include"}"', f'/I"{args.java_home / "include/win32"}"',
                 f'/Fo"{build / "fixture.obj"}"', f'/Fe"{fixture}"', f'"{root / "tests/native_probe_arguments.cpp"}"',
                 '/link', '/DEBUG', f'/IMPLIB:"{build / "fixture.lib"}"', f'/PDB:"{build / "fixture.pdb"}"']
        response.write_text(' '.join(flags), encoding='utf-8')
        vcvars = Path(install) / 'VC/Auxiliary/Build/vcvars64.bat'
        script = build / 'build.cmd'
        script.write_text(f'@echo off\ncall "{vcvars}" >nul\nif errorlevel 1 exit /b %errorlevel%\ncl.exe @"{response}"\nexit /b %errorlevel%\n', encoding='utf-8')
        subprocess.run(['cmd.exe', '/d', '/c', str(script)], check=True)

    def cli(*arguments, expected=0):
        result = subprocess.run([str(root / 'build/asprof.exe'), '--libpath', str(agent), *map(str, arguments)],
                                capture_output=True, text=True, timeout=30)
        with (work / 'commands.log').open('a', encoding='utf-8') as log:
            log.write(repr(arguments) + '\n' + result.stdout + result.stderr)
        assert result.returncode == expected, (arguments, result.stdout, result.stderr)
        return result.stdout + result.stderr

    lines = queue.Queue()
    with (work / 'target.err').open('w') as errors:
        process = subprocess.Popen([str(java), '-cp', str(classes), 'NativeProbeArguments', str(fixture)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, text=True, cwd=work)
        def collect():
            for line in process.stdout:
                lines.put(line.strip())
            lines.put('EOF')
        threading.Thread(target=collect, daemon=True).start()
        def exchange(command):
            process.stdin.write(command + '\n')
            process.stdin.flush()
            return lines.get(timeout=20)
        try:
            assert lines.get(timeout=15).startswith('READY ')
            address = int(exchange('address').removeprefix('ADDRESS '))
            function = int(exchange('function').removeprefix('ADDRESS '))
            symbol = 'nativeProbeArguments.dll!ProbeArgumentsWork'
            data = 'nativeProbeArguments.dll!ProbeArgumentsWatched+8'
            cases = [
                ('implicit-calls', symbol, 'probe', None, [1] * 10),
                ('calls', symbol, 'probe', 1, [1] * 10),
                ('first', symbol + '{1}', 'probe', 1, list(range(10))),
                ('second', symbol + '{2}', 'probe', 1, [11] * 10),
                ('third', symbol + '{3}', 'probe', 1, [13] * 10),
                ('fourth', symbol + '{4}', 'probe', 1, [17] * 10),
                ('sampled', symbol + '{1}', 'probe', 5, [4, 9]),
                ('execute', 'mem:' + symbol + ':x{3}', 'probe', 1, [13] * 10),
                ('execute-width', 'mem:' + symbol + '/8:x{4}', 'probe', 1, [17] * 10),
                ('execute-address', f'mem:0x{function:x}/8:x', 'probe', 1, [1] * 10),
                ('symbol-write', 'mem:' + data + '/8:w', 'watch', 1, [1] * 10),
                ('decimal-write', f'mem:{address}:8:w', 'watch', 1, [1] * 10),
                ('hex-readwrite', f'mem:0x{address:x}/8:wr', 'watch', 1, [1] * 20),
                ('default-readwrite', 'mem:' + data + '/8', 'watch', 1, [1] * 20),
            ]
            for name, event, command, interval, weights in cases if args.case != 'invalid' else []:
                recording = work / (name + '.jfr')
                cli('start', process.pid, '--event', event, *(['--interval', interval] if interval is not None else []),
                    '-f', recording)
                assert exchange(command) == ('RESULT 45' if command == 'watch' else 'RESULT 184145')
                cli('stop', process.pid)
                unit = 'total' if '{' in event else 'events' if event.startswith('mem:') else 'calls'
                read = subprocess.run([str(java), '-cp', str(classes), 'ReadProbeArguments', str(recording), ','.join(map(str, weights)), unit],
                                      capture_output=True, text=True, timeout=20)
                (work / (name + '-events.txt')).write_text(read.stdout + read.stderr, encoding='utf-8')
                assert read.returncode == 0, (name, read.stdout, read.stderr)
                otlp = work / (name + '.otlp')
                subprocess.run([str(java), '-cp', str(jar), 'one.convert.Main', '--total', str(recording), str(otlp)],
                               capture_output=True, text=True, check=True, timeout=20)
                validate_otlp(otlp, 'NativeProbeArguments', len(weights), expected_values=sum(weights))
                metrics = cli('metrics', process.pid)
                assert 'windows_probe_failed 0\n' in metrics and 'windows_probe_dropped 0\n' in metrics, metrics
                print(name, read.stdout.strip(), flush=True)
            invalid = [
                (symbol + '{0}', 'Only arguments 1-4'),
                (symbol + '{5}', 'Only arguments 1-4'),
                (symbol + '{1x}', 'Only arguments 1-4'),
                ('mem:' + data + '/8:r', 'read-only mode is unavailable'),
                ('mem:nativeProbeArguments.dll!ProbeArgumentsWatched+9/8:w', 'must be aligned'),
                ('mem:' + data + '/3:w', 'length must be 1, 2, 4, or 8'),
                ('mem:' + symbol + '/4:x', 'execution breakpoint length must be 1'),
            ]
            for index, (event, message) in enumerate(invalid if args.case != 'valid' else []):
                error = cli('start', process.pid, '--event', event, '-f', work / f'invalid-{index}.jfr', expected=200)
                assert message.lower() in error.lower(), (event, error)
                assert exchange('probe') == 'RESULT 184145'
                print('REJECTION_OK', event, flush=True)
            assert process.poll() is None
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)


if __name__ == '__main__':
    main()
