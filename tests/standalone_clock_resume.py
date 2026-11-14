# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Check timestamp continuity when native JFR resume changes its clock source."""
import argparse
import ctypes
from pathlib import Path
import struct
import subprocess
import tempfile
import time
from standalone_java_etw import validate_totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-clock-resume-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes),
                    str(root / 'tests/ReadLifecycleBounds.java'), str(root / 'tests/ReadCounters.java')], check=True)
    library = ctypes.CDLL(str(root / 'build/core/native/asyncProfiler.dll'))
    writer = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
    library.asprof_init.argtypes = []
    library.asprof_init.restype = None
    library.asprof_execute.argtypes = [ctypes.c_char_p, writer]
    library.asprof_execute.restype = ctypes.c_char_p
    library.asprof_init()

    def execute(command):
        output = []
        callback = writer(lambda address, size: output.append(ctypes.string_at(address, size)))
        error = library.asprof_execute(command.encode('utf-8'), callback)
        if error:
            raise RuntimeError(error.decode('utf-8'))
        return b''.join(output).decode('utf-8')

    def burn():
        end = time.monotonic() + 1
        value = 1
        while time.monotonic() < end:
            value = ((value ^ (value >> 13)) * 0x100000001b3) & 0xffffffffffffffff
        return value

    def rejected_unchanged(path, content):
        path.write_bytes(content)
        try:
            execute(f'resume,event=cpu,interval=1ms,cstack=dwarf,jfr,clock=monotonic,file={path}')
        except RuntimeError:
            pass
        else:
            raise AssertionError('Invalid recording was accepted')
        assert path.read_bytes() == content
        assert 'not active' in execute('status')

    rejected_unchanged(work / 'invalid.jfr', b'not a JFR recording')
    for first, second in [('monotonic', 'tsc'), ('tsc', 'monotonic')]:
        recording = work / f'{first}-{second}.jfr'
        for action, clock in [('start', first), ('resume', second)]:
            execute(f'{action},event=cpu,interval=1ms,cstack=dwarf,jfr,clock={clock},file={recording}')
            try:
                burn()
            finally:
                execute('stop')
        Path(str(recording) + '.collapsed').write_text(execute('collapsed,total'), encoding='utf-8')
        data = recording.read_bytes()
        offset = 0
        frequencies = []
        while offset < len(data):
            assert data[offset:offset+4] == b'FLR\0'
            size, = struct.unpack_from('>Q', data, offset + 8)
            assert 68 <= size <= len(data) - offset
            frequencies.append(struct.unpack_from('>Q', data, offset + 56)[0])
            offset += size
        print('CLOCK_RESUME', first, second, 'frequencies=', frequencies, flush=True)
        assert len(frequencies) == 2 and frequencies[0] == frequencies[1], frequencies
        subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(classes), 'ReadLifecycleBounds',
                        str(recording), str(int(time.time() * 1000))], check=True)
        validate_totals(args.java_home / 'bin/java.exe', classes, root / 'build/asprof-windows.jar', recording,
                        'native', 'python')
    invalid_clock = bytearray(recording.read_bytes())
    struct.pack_into('>Q', invalid_clock, 56, 0)
    rejected_unchanged(work / 'invalid-clock.jfr', invalid_clock)
    print('INVALID_RESUME_REJECTED_UNCHANGED', flush=True)
    print('CLOCK_RESUME_ALL_OK', flush=True)


if __name__ == '__main__':
    main()
