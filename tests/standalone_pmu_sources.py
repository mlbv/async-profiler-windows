# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Capture every enumerated ETW overflow source on a deterministic loop and check counting sources against the
loop's retired instructions and branches read from the fixture binary, and raw AMD host/guest programming."""
import argparse
import ctypes
import json
from pathlib import Path
import re
import subprocess

from standalone_profile_share import Context, Target, sources

import integrity

ROOT = Path(__file__).resolve().parents[1]
ITERATIONS = 200_000_000
# Each overflow interrupt and its stack walk retire about 16,000 instructions on the sampled
# CPU, which the counter includes; at this period that adds 0.2% to the loop's counts.
PERIOD = 10_000_019


def loop_counts(fixture):
    """Retired instructions and branches per ShareCountWork iteration, from its disassembly."""
    objdump = Path('C:/Utils/LLVM/bin/llvm-objdump.exe')
    thunk = subprocess.run([str(objdump), '-d', '--no-show-raw-insn', '--disassemble-symbols=ShareCountWork', str(fixture)],
                           check=True, capture_output=True, text=True).stdout
    # Incremental linking exports a jump thunk.
    body = int(re.search(r'<ShareCountWork>:\s+\S+:\s+jmp\s+0x([0-9a-f]+)', thunk).group(1), 16)
    listing = subprocess.run([str(objdump), '-d', '--no-show-raw-insn', f'--start-address={body:#x}', f'--stop-address={body + 0x80:#x}',
                              str(fixture)], check=True, capture_output=True, text=True).stdout
    instructions = [(int(address, 16), text.split()[0], text) for address, text in re.findall(r'^\s*([0-9a-f]+):\s+(.+)$', listing, re.MULTILINE)]
    back = next((address, int(re.search(r'0x([0-9a-f]+)', text).group(1), 16)) for address, mnemonic, text in instructions
                if mnemonic == 'jmp' and int(re.search(r'0x([0-9a-f]+)', text).group(1), 16) < address)
    loop = [mnemonic for address, mnemonic, _ in instructions if back[1] <= address <= back[0]]
    return len(loop), sum(1 for mnemonic in loop if mnemonic.startswith('j'))


def capture(target, context, name, event, java, classes):
    target.started(name, event, PERIOD)
    target.send(f'count {ITERATIONS}')
    cycles = int(re.search(r'cycles=(\d+)', target.expect('COUNTED ')).group(1))
    target.stop(name)
    base = context.work / name
    rows = [line.rsplit(' ', 1) for line in base.with_suffix('.collapsed').read_text(encoding='utf-8').splitlines() if line]
    total = sum(int(value) for _, value in rows)
    loop = sum(int(value) for stack, value in rows if 'ShareCountWork' in stack)
    unit = 'instructions' if event in ('etw:InstructionRetired', 'instructions') else 'cycles' if event == 'etw:TotalCycles' else 'events'
    counts = subprocess.run([str(java), '-cp', str(classes), 'ReadCounters', f'{base}.jfr', f'{base}.collapsed', unit, str(PERIOD)],
                            capture_output=True, text=True)
    # A source that counts nothing in this loop records no samples, which the reader rejects.
    agreed = counts.returncode == 0 or (total == 0 and 'Counter mismatch: JFR=0 collapsed=0' in counts.stderr)
    assert agreed, (name, counts.stdout, counts.stderr)
    result = dict(event=event, samples=total // PERIOD, total=total, loop=loop, perIteration=loop / ITERATIONS, cycles=cycles)
    print('PMU_SOURCE', json.dumps(result), flush=True)
    return result


def near(value, expected, tolerance):
    # Two samples of quantization on top of the relative tolerance.
    return abs(value - expected) <= tolerance * expected + 2 * PERIOD / ITERATIONS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True, help='nativeProfileShareApplication.exe')
    parser.add_argument('--agent', type=Path, default=ROOT / 'build/core/native/asyncProfiler.dll')
    parser.add_argument('--jar', type=Path, default=ROOT / 'build/asprof-windows.jar')
    parser.add_argument('--output', type=Path, required=True, help='New evidence directory (must not exist)')
    args = parser.parse_args()
    integrity.require_elevated()
    context = Context(args)
    context.work.mkdir(parents=True)
    context.classes.mkdir()
    print('Evidence:', context.work, flush=True)
    java = args.java_home.resolve() / 'bin/java.exe'
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(context.classes),
                    str(ROOT / 'tests/ReadCounters.java')], check=True)
    instructions, branches = loop_counts(context.fixture)
    print(f'LOOP instructions={instructions} branches={branches} iterations={ITERATIONS}', flush=True)
    available = sources(context.agent)
    events = [f'etw:{name}' for name, identifier in available.items() if identifier] + [
        'instructions', 'branch-instructions', 'branch-misses', 'cache-misses', 'rc0', 'rc2',
        'cpu/event=0xc0:host/', 'cpu/event=0xc0:guest/']
    target = Target(context, 'pmu', 'native', 'local')
    results = {}
    for index, event in enumerate(events):
        results[event] = capture(target, context, f'pmu-{index}', event, java, context.classes)
    target.exit()
    (context.work / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    per = {event: result['perIteration'] for event, result in results.items()}
    for event in ['etw:InstructionRetired', 'etw:FRRetiredx86Instructions', 'instructions', 'rc0']:
        assert near(per[event], instructions, .02), (event, per[event], instructions)
    for event in ['etw:FRRetiredBranches', 'etw:BranchInstructions', 'branch-instructions', 'rc2']:
        assert near(per[event], branches, .02), (event, per[event], branches)
    for event in ['etw:BranchMispredictions', 'etw:FRRetiredBranchesMispredicted', 'branch-misses']:
        assert per[event] < .01 * branches, (event, per[event])
    # Extended AMD programming registers and counts. The Hyper-V root partition counts every
    # instruction in both host-only and guest-only modes, so only one mode's coverage is asserted.
    assert near(max(per['cpu/event=0xc0:host/'], per['cpu/event=0xc0:guest/']), per['rc0'], .02), per
    for event in ['etw:TotalIssues', 'etw:TotalCycles', 'etw:DCAccess', 'etw:DcacheAccesses']:
        assert results[event]['loop'] > 0, (event, results[event])
    cycles = results['etw:TotalCycles']
    print(f'PMU_SOURCES_OK captures={len(results)} instructionsPerIteration={per["etw:InstructionRetired"]:.4f}/{instructions} '
          f'branchesPerIteration={per["etw:FRRetiredBranches"]:.4f}/{branches} '
          f'host={per["cpu/event=0xc0:host/"]:.4f} guest={per["cpu/event=0xc0:guest/"]:.4f} '
          f'coreToTsc={cycles["loop"] / cycles["cycles"]:.3f}', flush=True)


if __name__ == '__main__':
    main()
