# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Run production handler metadata and OS-unwind oracles on retained compiled-code fixtures."""
import argparse
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    args = parser.parse_args()
    count = contexts = 0
    for folder, version in [('handlers21', 21), ('handlers25', 25)]:
        directory = args.fixtures.resolve() / folder
        text = (directory / 'cml-pcdesc.log').read_text(encoding='utf-8', errors='replace')
        barrier = int(re.search(r'VM_BARRIER.*address=([0-9a-f]+)', text).group(1), 16)
        for match in re.finditer(r'NATIVE_COMPILED method=throwing address=([0-9a-f]+) size=(\d+)\s+'
                                r'NATIVE_COMPILED_METADATA frameSize=(\d+) frameCompleteOffset=(\d+)', text):
            if int(match[4]) != 12:
                continue
            address, size, words = int(match[1], 16), int(match[2]), int(match[3])
            prefix = directory / f'throwing-{address:x}-{size}'
            result = subprocess.run([str(args.oracle.resolve()), str(prefix) + '.bin',
                                     str(prefix) + '-handlers.bin', str(prefix) + '-pcdesc.bin',
                                     str(barrier - address), str(words * 8 - 8), str(version)],
                                    capture_output=True, text=True, timeout=20)
            print(result.stdout, result.stderr, end='', flush=True)
            result.check_returncode()
            actual = re.search(r'COMPILED_HANDLER_CAPTURE .*contexts=(\d+)', result.stdout)
            assert actual, result.stdout
            contexts += int(actual[1])
            count += 1
    assert count == 4 and contexts == 4744, (count, contexts)
    print(f'COMPILED_HANDLERS_RETAINED_OK fixtures={count} contexts={contexts} owningSnapshot=1 osOracle=1', flush=True)


if __name__ == '__main__':
    main()
