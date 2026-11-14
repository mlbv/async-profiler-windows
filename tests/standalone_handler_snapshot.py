# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Exercise typed nmethod snapshots through real JVMTI callbacks without ETW capture."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, action='append', required=True)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--scalar-oracle', type=Path)
    parser.add_argument('--fault-oracle', type=Path)
    parser.add_argument('--fault-method', default='faulting')
    parser.add_argument('--handler-oracle', type=Path)
    parser.add_argument('--handler-method', default='throwing')
    witnesses = parser.add_mutually_exclusive_group()
    witnesses.add_argument('--handler-witness', action='store_true',
                           help='Require an actual catch-path context and independent native caller baseline')
    witnesses.add_argument('--implicit-witness', action='store_true',
                           help='Correlate a passive OS fault context with its actual Java catch context')
    parser.add_argument('--vm-option', action='append', default=[])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    library, jar = args.library.resolve(), args.jar.resolve()
    work = Path(tempfile.mkdtemp(prefix='asprof-handler-snapshot-'))
    classes = work / 'classes'
    classes.mkdir()
    paths = [library, jar]
    if args.scalar_oracle:
        paths.append(args.scalar_oracle.resolve())
    if args.fault_oracle:
        paths.append(args.fault_oracle.resolve())
    if args.handler_oracle:
        paths.append(args.handler_oracle.resolve())
    inputs = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    (work / 'inputs.json').write_text(json.dumps(inputs, indent=2), encoding='utf-8')
    print('Evidence:', work, flush=True)
    subprocess.run([str(args.java_home[0].resolve() / 'bin/javac.exe'), '--release', '8',
                    '-d', str(classes), str(root / 'tests/CompiledHandlerSnapshotSmoke.java')], check=True)
    for index, home in enumerate(args.java_home):
        witness_options = []
        if args.handler_witness:
            witness_options.append('-Dasprof.test.handlerWitness=true')
        if args.implicit_witness:
            witness_options.append('-Dasprof.test.implicitWitness=true')
        command = [str(home.resolve() / 'bin/java.exe'), *args.vm_option, *witness_options, '-Xbatch',
                   '-XX:CompileThreshold=100',
                   '-XX:CompileCommand=dontinline,CompiledHandlerSnapshotSmoke.*',
                   '-cp', str(classes) + ';' + str(jar), 'CompiledHandlerSnapshotSmoke', str(library)]
        result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=60)
        text = result.stdout + result.stderr
        (work / f'{index}.log').write_text(text, encoding='utf-8')
        print(home, result.returncode, text, flush=True)
        result.check_returncode()
        assert 'COMPILED_HANDLER_SNAPSHOT_RUNTIME_OK' in text, text
        assert 'OBSERVER_WORKLOAD_EXCEPTION_OK' in text, text
        assert 'OBSERVER_LIFETIME_OK admittedDrained=1 lateIgnored=1' in text, text
        if args.handler_witness or args.implicit_witness:
            witnesses = [line for line in text.splitlines() if line.startswith('HANDLER_CONTEXT_WITNESS_OK ')]
            assert len(witnesses) == 1, text
            fields = dict(item.split('=', 1) for item in witnesses[0].split()[1:])
            expected = {'checkpoints': '1', 'normalCheckpoints': '0', 'compiledCallers': '2',
                        'exactBaseline': '1', 'parentPeRow': '1'}
            assert all(fields.get(key) == value for key, value in expected.items()), text
            certificates = [line for line in text.splitlines()
                            if line.startswith('HANDLER_CERTIFICATE_REGRESSION_OK checks=')]
            assert len(certificates) == 1 and int(certificates[0].rsplit('=', 1)[1]) >= 78, text
        if args.implicit_witness:
            implicit = [line for line in text.splitlines()
                        if line.startswith('IMPLICIT_FAULT_CONTEXT_WITNESS_OK ')]
            assert len(implicit) == 1, text
            fields = dict(item.split('=', 1) for item in implicit[0].split()[1:])
            expected = {'faults': '1', 'checkpoints': '1', 'normalFaults': '0',
                        'normalCheckpoints': '0', 'contextUnchanged': '1', 'commonCaller': '1',
                        'exactBaseline': '1', 'parentPeRow': '1', 'targetCertified': '1',
                        'targetObserved': '0'}
            assert all(fields.get(key) == value for key, value in expected.items()), text
            assert fields.get('sourceRoute') in ('conventional', 'compiled'), text
            assert int(fields['sourceLevel']) in (1, 2, 3, 4), text
        if args.scalar_oracle:
            captures = re.findall(r'SCALAR_CODE address=([0-9a-f]+) barrier=([0-9a-f]+) entry=(\d+) allocation=(\d+) bytes=([0-9a-f]+)', text)
            assert captures, text
            for item, (address, barrier, entry, allocation, code) in enumerate(captures):
                path = work / f'{index}-scalar-{item}.bin'
                path.write_bytes(bytes.fromhex(code))
                subprocess.run([str(args.scalar_oracle.resolve()), str(path), address, barrier, entry, allocation],
                               check=True, timeout=15)
        if args.fault_oracle:
            faults = re.findall(r'FAULT_CODE method=' + re.escape(args.fault_method)
                                + r'(?: level=\d+ conventional=[01])? address=([0-9a-f]+) barrier=([0-9a-f]+) entry=(\d+) allocation=(\d+) bytes=([0-9a-f]+) faults=([0-9:,]+) handlers=([0-9:,-]+)', text)
            assert faults, text
            for item, (address, barrier, entry, allocation, code, edges, handlers) in enumerate(faults):
                path = work / f'{index}-fault-{item}.bin'
                path.write_bytes(bytes.fromhex(code))
                subprocess.run([str(args.fault_oracle.resolve()), str(path), address, barrier, entry, allocation,
                                edges.rstrip(','), handlers.rstrip(',')], check=True, timeout=15)
        if args.handler_oracle:
            handlers = re.findall(r'HANDLER_CODE method=' + re.escape(args.handler_method)
                                  + r' level=4 conventional=0 address=([0-9a-f]+) barrier=([0-9a-f]+) entry=(\d+) allocation=(\d+) bytes=([0-9a-f]+) faults=- handlers=([0-9:,]+)', text)
            assert handlers, text
            for item, (address, barrier, entry, allocation, code, edges) in enumerate(handlers):
                path = work / f'{index}-handler-{item}.bin'
                path.write_bytes(bytes.fromhex(code))
                subprocess.run([str(args.handler_oracle.resolve()), str(path), address, barrier, entry, allocation,
                                '-', edges.rstrip(',')], check=True, timeout=15)
    assert inputs == {str(path): hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in inputs}
    print(f'HANDLER_SNAPSHOT_JVMS_OK runtimes={len(args.java_home)} callbackLifetime=1 noEtw=1 unchangedInputs=1', flush=True)


if __name__ == '__main__':
    main()
