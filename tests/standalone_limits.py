# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Exercise size-triggered chunk rollover and bounded stack storage through the C API."""
import argparse
import ctypes
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import time
from standalone_java_etw import validate_totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--case', choices=['all', 'size', 'memory'], default='all')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-limits-'))
    print('Evidence:', work, flush=True)
    classes = work / 'classes'
    classes.mkdir()
    java = args.java_home / 'bin/java.exe'
    jar = root / 'build/asprof-windows.jar'
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-d', str(classes),
                    str(root / 'tests/ReadRecordingLimits.java'), str(root / 'tests/ReadCounters.java')], check=True)
    private_library = work / 'asyncProfiler.dll'
    shutil.copy2(root / 'build/core/native/asyncProfiler.dll', private_library)
    library = ctypes.CDLL(str(private_library))
    writer = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
    library.asprof_init.argtypes = []
    library.asprof_init.restype = None
    library.asprof_execute.argtypes = [ctypes.c_char_p, writer]
    library.asprof_execute.restype = ctypes.c_char_p
    library.asprof_register_jfr_event.argtypes = [ctypes.c_char_p]
    library.asprof_register_jfr_event.restype = ctypes.c_int
    library.asprof_emit_jfr_event.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
    library.asprof_emit_jfr_event.restype = ctypes.c_char_p
    library.asprof_init()

    def execute(command):
        output = []
        callback = writer(lambda address, size: output.append(ctypes.string_at(address, size)))
        error = library.asprof_execute(command.encode('utf-8'), callback)
        if error:
            raise RuntimeError(error.decode('utf-8'))
        return b''.join(output).decode('utf-8')

    def burn(seconds):
        end = time.monotonic() + seconds
        value = 1
        while time.monotonic() < end:
            value = ((value ^ (value >> 13)) * 0x100000001b3) & 0xffffffffffffffff
        return value

    def totals(recording, frame):
        Path(str(recording) + '.collapsed').write_text(execute('collapsed,total'), encoding='utf-8')
        return validate_totals(java, classes, jar, recording, 'native', frame)

    if args.case in ['all', 'size']:
        recording = work / 'size.jfr'
        execute(f'start,event=cpu,interval=1ms,cstack=dwarf,jfr,chunksize=256k,chunktime=0,file={recording}')
        key = library.asprof_register_jfr_event(b'rollover-sequence')
        assert key >= 0, key
        started = time.monotonic()
        try:
            for batch in range(2):
                for sequence in range(batch * 500, (batch + 1) * 500):
                    payload = f'{sequence:08x}'.encode('ascii') + b'A' * 2040
                    error = library.asprof_emit_jfr_event(key, payload, len(payload))
                    if error:
                        raise RuntimeError(error.decode('utf-8'))
                burn(1.3)
        finally:
            execute('stop')
        print('SIZE_CAPTURE_SECONDS', time.monotonic() - started, flush=True)
        data = recording.read_bytes()
        paths = []
        offset = 0
        while offset < len(data):
            assert data[offset:offset + 4] == b'FLR\0'
            size, = struct.unpack_from('>Q', data, offset + 8)
            assert 68 <= size <= len(data) - offset
            chunk = work / f'size-chunk-{len(paths)}.jfr'
            chunk.write_bytes(data[offset:offset + size])
            paths.append(chunk)
            offset += size
        subprocess.run([str(java), '-cp', str(classes), 'ReadRecordingLimits', '1000', *map(str, paths)], check=True)
        totals(recording, 'python')

    if args.case in ['all', 'memory']:
        recording = work / 'memory.jfr'
        execute(f'start,event=cpu,interval=1ms,cstack=dwarf,jfr,memlimit=1,file={recording}')
        try:
            burn(1.5)
        finally:
            execute('stop')
        metrics = execute('metrics')
        print(metrics, end='', flush=True)
        overflow = re.search(r'^calltracestorage_overflows_total (\d+)$', metrics, re.MULTILINE)
        assert overflow and int(overflow[1]) > 0, metrics
        assert 'storage_overflow' in execute('collapsed,total')
        totals(recording, 'storage_overflow')
        execute(f'start,event=cpu,interval=1ms,cstack=dwarf,jfr,file={work / "recovered.jfr"}')
        try:
            burn(0.5)
        finally:
            execute('stop')
        assert 'calltracestorage_overflows_total 0\n' in execute('metrics')
        assert 'storage_overflow' not in execute('collapsed,total')
        print('MEMLIMIT_RESET_OK', flush=True)
        execute('start,event=wall,interval=5ms,cstack=dwarf,memlimit=1')
        try:
            burn(0.5)
        finally:
            execute('stop')
        wall = execute('collapsed,total')
        assert 'storage_overflow' in wall, wall
        assert sum(int(line.rsplit(' ', 1)[1]) for line in wall.splitlines()) > 0, wall
        print('MEMLIMIT_WALL_OK', flush=True)
    print('RECORDING_LIMITS_OK', args.case, flush=True)


if __name__ == '__main__':
    main()
