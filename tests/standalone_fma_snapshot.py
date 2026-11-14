# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Retain the exact ETW cutoff workload's compiled code and check CFI rejection without ETW."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', action='append', type=Path, required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--objcopy', type=Path, required=True)
    parser.add_argument('--objdump', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    library, jar, oracle = args.library.resolve(), args.jar.resolve(), args.oracle.resolve()
    objcopy, objdump = args.objcopy.resolve(), args.objdump.resolve()
    inputs = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in [library, jar, oracle, objcopy, objdump]}
    work = Path(tempfile.mkdtemp(prefix='asprof-fma-snapshot-'))
    classes = work / 'classes'
    classes.mkdir()
    (work / 'inputs.json').write_text(json.dumps(inputs, indent=2), encoding='utf-8')
    print('Evidence:', work, flush=True)
    subprocess.run([str(args.java_home[0].resolve() / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8',
                    '-cp', str(jar), '-d', str(classes),
                    *[str(root / 'tests' / name) for name in ['EtwJavaSmoke.java', 'CompiledHandlerSnapshotSmoke.java',
                                                            'FmaCompilerSnapshotSmoke.java']]], check=True)
    count = 0
    for index, home in enumerate(args.java_home):
        command = [str(home.resolve() / 'bin/java.exe'), '-Xbatch', '-XX:CompileThreshold=100',
                   '-XX:CompileCommand=dontinline,EtwJavaSmoke.*', '-cp', str(classes) + ';' + str(jar),
                   'FmaCompilerSnapshotSmoke', str(library)]
        result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=60)
        text = result.stdout + result.stderr
        (work / f'{index}.log').write_text(text, encoding='utf-8')
        print(home, result.returncode, text, flush=True)
        result.check_returncode()
        assert 'FMA_COMPILER_SNAPSHOT_OK' in text, text
        captures = re.findall(r'UNSUPPORTED_CODE address=([0-9a-f]+) barrier=([0-9a-f]+) entry=(\d+) allocation=(\d+) bytes=([0-9a-f]+)', text)
        assert captures, text
        for item, (address, barrier, entry, allocation, code) in enumerate(captures):
            path = work / f'{index}-fma-{item}.bin'
            path.write_bytes(bytes.fromhex(code))
            obj = path.with_suffix('.obj')
            subprocess.run([str(objcopy), '-I', 'binary', '-O', 'pe-x86-64', '-B', 'i386:x86-64',
                            '--rename-section', '.data=.text,alloc,load,readonly,code,contents', str(path), str(obj)],
                           check=True, timeout=15)
            disassembly = subprocess.check_output([str(objdump), '-d', '--no-show-raw-insn', str(obj)], text=True, timeout=15)
            path.with_suffix('.asm').write_text(disassembly, encoding='utf-8')
            instructions = re.findall(r'^\s*([0-9a-f]+):\s+vfmadd(?:132|213|231)sd\s', disassembly, re.MULTILINE)
            assert instructions, disassembly
            print('FMA_INSTRUCTION_PROVENANCE offsets=' + ','.join(instructions), flush=True)
            subprocess.run([str(oracle), '--unsupported', str(path), address, barrier, entry, allocation],
                           check=True, timeout=15)
            count += 1
    assert inputs == {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in inputs}
    print(f'FMA_SNAPSHOT_ALL_OK runtimes={len(args.java_home)} captures={count} exactWorkload=1 unchangedInputs=1 noEtw=1', flush=True)


if __name__ == '__main__':
    main()
