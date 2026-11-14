# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Replay retained HotSpot call-stub bytes through the private certificate without a JVM."""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--library', type=Path, required=True)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--objcopy', type=Path, required=True)
    parser.add_argument('--objdump', type=Path, required=True)
    args = parser.parse_args()
    library, log, objcopy, objdump = [path.resolve() for path in
                                    [args.library, args.log, args.objcopy, args.objdump]]
    inputs = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in [library, log, objcopy, objdump]}
    text = log.read_text(encoding='utf-8', errors='strict')
    observed = re.search(r'HANDLER_WITNESS_FAILURE stage=stub\.certificate pc=([0-9a-f]+)', text)
    capture = re.search(r'HANDLER_STAGE_CODE stage=stub\.certificate address=([0-9a-f]+) bytes=([0-9a-f]+)', text)
    assert observed and capture, 'No exact retained call-stub certificate failure'
    address = int(capture[1], 16)
    size = int(observed[1], 16) - address
    retained = bytes.fromhex(capture[2])
    assert 0 < size < len(retained) <= 16384
    code = retained[:size]
    assert code[-2:] == bytes.fromhex('ffd2'), 'Retained prefix does not end at CALL RDX'
    work = Path(tempfile.mkdtemp(prefix='asprof-handler-stub-offline-'))
    print('Evidence:', work, flush=True)
    path = work / 'call-stub.bin'
    path.write_bytes(code)
    obj = path.with_suffix('.obj')
    subprocess.run([str(objcopy), '-I', 'binary', '-O', 'pe-x86-64', '-B', 'i386:x86-64',
                    '--rename-section', '.data=.text,alloc,load,readonly,code,contents', str(path), str(obj)],
                   check=True, timeout=15)
    assembly = subprocess.check_output([str(objdump), '-d', '--no-show-raw-insn', str(obj)], text=True, timeout=15)
    path.with_suffix('.asm').write_text(assembly, encoding='utf-8')
    saves = [int(offset, 16) for offset in re.findall(r'^\s*([0-9a-f]+):\s+vmovdqu\s', assembly, re.MULTILINE)]
    assert len(saves) == 10, assembly
    assert all(code[offset] == 0xc5 and code[offset + 1] in (0xfa, 0x7a)
               and code[offset + 2] == 0x7f for offset in saves), assembly
    module = ctypes.CDLL(str(library))
    certify = module.asprof_test_handler_stub_certificate
    certify.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.c_size_t,
                        ctypes.POINTER(ctypes.c_char), ctypes.c_size_t]
    certify.restype = ctypes.c_int
    checks = 0

    def check(data, expected):
        nonlocal checks
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        error = ctypes.create_string_buffer(1024)
        result = certify(buffer, len(data), address, error, len(error))
        assert result in (0, 1)
        assert bool(result) == expected, (data.hex(), error.value.decode('utf-8', errors='replace'))
        if not expected:
            assert error.value, 'Rejected certificate omitted its reason'
        checks += 1

    check(code, True)
    assert {code[offset + 1] for offset in saves} == {0xfa, 0x7a}
    for offset in saves:
        for replacement in (code[offset + 1] | 4, code[offset + 1] ^ 1, code[offset + 1] ^ 8,
                            code[offset + 1] ^ 0x80):
            mutant = bytearray(code)
            mutant[offset + 1] = replacement
            check(mutant, False)
        mutant = bytearray(code)
        mutant[offset + 2] = 0x6f
        check(mutant, False)
        mutant = bytearray(code)
        mutant[offset + 3] = (mutant[offset + 3] & 0x3f) | 0xc0
        check(mutant, False)
    for prefix in (0x66, 0xf0, 0xf2, 0xf3, 0x48, 0x67, 0x65):
        check(code[:saves[0]] + bytes([prefix]) + code[saves[0]:], False)
    check(code[:-2], False)
    check(code[:-2] + b'\x90\x90', False)
    check(code[:-2] + b'\xe8\x00\x00\x00\x01' + code[-2:], False)
    assert inputs == {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in inputs}
    result = dict(checks=checks, bytes=len(code), originalAddress=hex(address),
                  vexSaves=len(saves), unchangedInputs=True, noJvm=True, codeExecuted=False)
    (work / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    (work / 'inputs.json').write_text(json.dumps(inputs, indent=2), encoding='utf-8')
    print(f'HANDLER_STUB_OFFLINE_PASS checks={checks} bytes={len(code)} vexSaves=10 noJvm=1 codeExecuted=0',
          flush=True)


if __name__ == '__main__':
    main()
