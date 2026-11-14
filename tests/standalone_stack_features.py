# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Exercise upstream receiver/compilation-task workloads on the Windows stack walker."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from standalone_java_etw import hotspot_compiler_options


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--agent', type=Path)
    parser.add_argument('--symbols', type=Path)
    parser.add_argument('--case', choices=['vtable', 'itable', 'comptask'], required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-stack-features-'))
    print('Evidence:', work, flush=True)
    agent = work / 'asyncProfiler.dll'
    shutil.copy2(args.agent or root / 'build/core/native/asyncProfiler.dll', agent)
    classes = work / 'classes'
    classes.mkdir()
    sources = list((root / 'core/src/api/one/profiler').glob('*.java'))
    if args.case == 'comptask':
        sources += [args.upstream / 'test/test/comptask/Main.java', root / 'tests/CompilerTaskSmoke.java', root / 'tests/ReadCounters.java']
    else:
        sources += [root / 'tests/VtableSmoke.java', *(args.upstream / 'test/test/recovery' / name for name in
                    ['Numbers.java', 'Suppliers.java'])]
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes), *map(str, sources)], check=True)
    output = work / (args.case + '.collapsed')
    java = str(args.java_home / 'bin/java.exe')
    # These workloads need HotSpot's C1/C2 tasks.
    command = [java, *hotspot_compiler_options(java)]
    if args.case == 'comptask':
        recording = work / 'comptask.jfr'
        command += ['-Xcomp', '-agentpath:' + str(agent) + '=start,event=cpu,interval=1ms,features=comptask,jfr,file=' + str(recording),
                    '-cp', str(classes), 'CompilerTaskSmoke', str(agent), str(output)]
    else:
        command += ['-cp', str(classes), 'VtableSmoke', str(agent), str(output), args.case]
    env = os.environ.copy()
    if args.symbols:
        env['ASYNC_PROFILER_SYMBOL_PATH'] = str(args.symbols.resolve())
    with (work / 'target.log').open('w', encoding='utf-8') as log:
        result = subprocess.run(command, cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=90)
    print((work / 'target.log').read_text(encoding='utf-8', errors='replace'), end='')
    result.check_returncode()
    if args.case == 'comptask':
        subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(classes), 'ReadCounters', str(recording), str(output), 'ns'], check=True)
        stacks = output.read_text(encoding='utf-8')
        for compiler in ['Compiler', 'C2Compiler']:
            assert re.search(r';' + compiler + r'::compile_method;((?:java|sun|jdk)/[^;]+\.[^;]+);', stacks), compiler
        print('UPSTREAM_COMPILATION_TASKS_OK', flush=True)


if __name__ == '__main__':
    main()
