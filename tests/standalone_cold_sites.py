# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify private cold-site preparation and continuation readiness under owned CET policies."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    library, driver, fixture = [path.resolve() for path in [args.library, args.driver, args.fixture]]
    paths = [library, driver, fixture, library.with_name('asprof-helper.exe')]
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    work = Path(tempfile.mkdtemp(prefix='asprof-cold-mitigations-'))
    (work / 'inputs.json').write_text(json.dumps(before, indent=2), encoding='utf-8')
    print('Evidence:', work, flush=True)
    for mode in ['ordinary', 'cet', 'strict-cet']:
        command = [str(driver)]
        if mode != 'ordinary':
            command.append('--' + mode)
        command += [str(library), str(fixture)]
        result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=45)
        text = result.stdout + result.stderr
        (work / (mode + '.log')).write_text(text, encoding='utf-8')
        print(mode, result.returncode, text, flush=True)
        result.check_returncode()
        assert 'NATIVE_COLD_SITES_PASS' in text and 'continuation=1' in text, text
        flags = re.search(r'COLD_SITE_MITIGATIONS policy=([0-9a-f]+) continuations=(\d+) range=(\d+) possible=(\d+)', text)
        assert flags, text
        policy = int(flags[1], 16)
        if mode != 'ordinary':
            required = 0x15 if mode == 'strict-cet' else 0x5
            assert policy & required == required and not policy & 0x20a, text
            assert bool(policy & 0x10) == (mode == 'strict-cet'), text
            assert tuple(map(int, flags.groups()[1:])) == (3, 1, 1), text
            assert 'COLD_SITE_CET_CHILD_EXIT=0' in text, text
    after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    assert before == after, 'A private artifact or source fixture changed during validation'
    print('COLD_SITE_MITIGATIONS_OK ordinary=1 compatible=1 strict=1 continuation=1 unchangedInputs=1 sourcePatch=0', flush=True)


if __name__ == '__main__':
    main()
