# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Attaching the profiler to JDK 21+ suppresses the dynamic-agent warning; a startup -agentpath does not."""
import argparse
from pathlib import Path
import subprocess
import tempfile

WARNING = 'A JVM TI agent has been loaded dynamically'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True, help='JDK 17+ for the CLI, jcmd and the agent fixture')
    parser.add_argument('--target-java', type=Path, action='append', required=True, help='Java home of a JDK 21+ target; repeatable')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    profiler, jar = root / 'build/core/native/asyncProfiler.dll', root / 'build/asprof-windows.jar'
    work = Path(tempfile.mkdtemp(prefix='asprof-attach-warning-'))
    print('Evidence:', work, flush=True)
    subprocess.run(['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(root / 'tests/build_native_fixture.ps1'),
                    '-JdkHome', str(args.java_home), '-OutputDirectory', str(work / 'agent'), '-AttachAgent'], check=True)
    other_agent = work / 'agent/attachAgent.dll'
    classes = work / 'classes'
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '8', '-Xlint:-options', '-d', str(classes),
                    str(root / 'tests/AttachWarningTarget.java')], check=True)

    def target_stderr(java, name, options, attach):
        # Loads attachAgent.dll through jcmd after attach(); its warning shows whether EnableDynamicAgentLoading is marked.
        with (work / f'{name}.err').open('w+', encoding='utf-8') as errors:
            target = subprocess.Popen([str(java), *options, '-cp', str(classes), 'AttachWarningTarget'], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=errors, text=True)
            try:
                while (line := target.stdout.readline()) and line.strip() != 'READY': pass
                assert line, 'The target exited before READY'
                attach(target.pid)
                subprocess.run([str(args.java_home / 'bin/jcmd.exe'), str(target.pid), 'JVMTI.agent_load', str(other_agent)],
                               capture_output=True, text=True, timeout=120, check=True)
            finally:
                target.stdin.close()
                target.wait(timeout=60)
            errors.seek(0)
            return errors.read()

    def cli_attach(pid):
        result = subprocess.run([str(root / 'build/asprof.exe'), '--libpath', str(profiler), 'status', str(pid)],
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stdout + result.stderr

    for index, home in enumerate(args.target_java):
        java = home / 'bin/java.exe'
        attached = target_stderr(java, f'{index}-attach', [], cli_attach)
        assert WARNING not in attached, attached
        startup = target_stderr(java, f'{index}-startup', [f'-agentpath:{profiler}=start,event=cpu,file={work / f"{index}.jfr"}'], lambda _: None)
        assert WARNING in startup and 'attachAgent.dll' in startup, startup
        print(f'{home}: attach suppresses the warning; startup -agentpath leaves it', flush=True)
    print('ATTACH_WARNING_OK', flush=True)


if __name__ == '__main__':
    main()
