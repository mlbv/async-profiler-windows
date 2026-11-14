# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Exercise real Windows provider events through the source-built tracepoint engine."""
import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import uuid

from standalone_broker import wait_for
from standalone_etw import query_interval
from standalone_java_etw import validate_metadata_metrics, validate_totals

import integrity


def token_properties(pid):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    security = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    security.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    security.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    security.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    security.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    process = kernel.OpenProcess(0x1000, False, pid)
    assert process, ('Process identity query', pid, ctypes.get_last_error())
    token = wintypes.HANDLE()
    try:
        assert security.OpenProcessToken(process, 8, ctypes.byref(token))
        try:
            elevated, size = wintypes.DWORD(), wintypes.DWORD()
            assert security.GetTokenInformation(token, 20, ctypes.byref(elevated), 4, ctypes.byref(size))
            security.GetTokenInformation(token, 25, None, 0, ctypes.byref(size))
            integrity = ctypes.create_string_buffer(size.value)
            assert security.GetTokenInformation(token, 25, integrity, len(integrity), ctypes.byref(size))
            sid = ctypes.cast(integrity, ctypes.POINTER(ctypes.c_void_p))[0]
            count = security.GetSidSubAuthorityCount(sid)[0]
            rid = security.GetSidSubAuthority(sid, count - 1)[0]
            return elevated.value, rid
        finally:
            kernel.CloseHandle(token)
    finally:
        kernel.CloseHandle(process)


def preferred_image_base(path):
    data = path.read_bytes()
    header = struct.unpack_from('<I', data, 0x3c)[0]
    assert struct.unpack_from('<H', data, header + 24)[0] == 0x20b, 'Fixture must be PE64'
    return struct.unpack_from('<Q', data, header + 24 + 24)[0]


def verify_resident_images(pid, images):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.K32EnumProcessModulesEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
                                              ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    kernel.K32GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    process = kernel.OpenProcess(0x410, False, pid)
    assert process, ('Resident module query', ctypes.get_last_error())
    try:
        modules = (wintypes.HMODULE * 1024)()
        needed = wintypes.DWORD()
        assert kernel.K32EnumProcessModulesEx(process, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3)
        assert needed.value <= ctypes.sizeof(modules), 'Resident module list exceeded fixture bound'
        expected = {str(image): preferred_image_base(image) for image in images}
        resident = {int(modules[index]) for index in range(needed.value // ctypes.sizeof(wintypes.HMODULE))}
        found = {}
        for image in images:
            base = expected[str(image)]
            assert base in resident, ('Preferred image base was not resident', image, hex(base))
            name = ctypes.create_unicode_buffer(32768)
            size = kernel.K32GetModuleFileNameExW(process, base, name, len(name))
            assert size and size < len(name)
            normalized = str(Path(name.value).resolve()).removeprefix('\\\\?\\').casefold()
            assert normalized == str(image.resolve()).removeprefix('\\\\?\\').casefold(), ('Wrong image at preferred base', image, name.value)
            found[str(image)] = base
        assert found == expected and len(set(found.values())) == 2, ('Preferred/resident image bases', found, expected)
        print('RESIDENT_PREFERRED_BASES', {name: hex(base) for name, base in found.items()}, flush=True)
    finally:
        kernel.CloseHandle(process)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--case', choices=['id', 'interval', 'java-only', 'named', 'restart', 'kernel-image', 'kernel-restart'], default='id')
    parser.add_argument('--image-library', type=Path)
    parser.add_argument('--second-image-library', type=Path)
    parser.add_argument('--work-directory', type=Path)
    parser.add_argument('--java-option', action='append', default=[])
    parser.add_argument('--broker', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = args.work_directory.resolve() if args.work_directory else Path(tempfile.mkdtemp(prefix='asprof-tracepoint-'))
    work.mkdir(parents=True, exist_ok=True)
    classes = work / 'classes'
    classes.mkdir(exist_ok=True)
    jar = root / 'build/asprof-windows.jar'
    java = args.java_home / 'bin/java.exe'
    previous_interval = query_interval(0) if args.broker else None
    if args.broker:
        integrity.require_elevated()
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8',
                    '-cp', str(jar), '-d', str(classes),
                    *[str(root / 'tests' / name) for name in ['TracepointSmoke.java', 'ReadTracepoint.java', 'ReadCounters.java']]], check=True)
    command = [str(java), '-XX:CompileCommand=dontinline,TracepointSmoke.*', *args.java_option, '-cp', str(classes) + ';' + str(jar),
               'TracepointSmoke', str(args.agent.resolve()), str(args.fixture.resolve()), str(work), args.case]
    resident_images = []
    if args.case.startswith('kernel-'):
        if args.image_library is None:
            parser.error('--case kernel-* requires --image-library')
        if args.case == 'kernel-restart':
            for index in range(2):
                image = work / ('provider-image-' + str(index) + '.dll')
                original = args.second_image_library if index == 1 and args.second_image_library else args.image_library
                shutil.copy2(original, image)
                command.append(str(image))
                resident_images.append(image)
            if args.second_image_library:
                assert args.broker, 'Resident control fixture currently uses broker mode'
                assert len({preferred_image_base(image) for image in resident_images}) == 2, 'Control fixtures must have distinct preferred bases'
                command[1:1] = ['-Dasprof.tracepoint.images=' + str(work)]
        else:
            command.append(str(args.image_library.resolve()))
    target, broker = None, None
    try:
        with (work / 'target.log').open('w', encoding='utf-8') as log, (work / 'broker.log').open('w', encoding='utf-8') as broker_log:
            if args.broker:
                ready, release = work / 'ready', work / 'release'
                assert not ready.exists() and not release.exists(), 'Broker evidence directory must be fresh'
                pipe = r'\\.\pipe\async-profiler-provider-' + uuid.uuid4().hex
                command[1:1] = ['-Dasprof.tracepoint.broker=' + pipe, '-Dasprof.tracepoint.ready=' + str(ready),
                                '-Dasprof.tracepoint.release=' + str(release)]
                target = integrity.deelevated_popen(command, stdout=log, stderr=subprocess.STDOUT, cwd=work)
                wait_for(ready.exists, target, 'Provider JVM ready')
                assert int(ready.read_text()) == target.pid
                assert token_properties(target.pid) == (0, 0x2000), 'Provider target was not medium integrity'
                helper = args.agent.resolve().parent / 'asprof-helper.exe'
                broker = subprocess.Popen([str(helper), '--etw-broker', str(target.pid), pipe],
                                          stdout=broker_log, stderr=subprocess.STDOUT, cwd=work)
                wait_for(lambda: 'ETW_BROKER_READY ' in (work / 'broker.log').read_text(errors='replace'), broker, 'Provider broker ready')
                helper_pid = int(re.search(r'ETW_BROKER_READY pid=(\d+)', (work / 'broker.log').read_text()).group(1))
                assert token_properties(helper_pid) == (1, 0x3000), 'Provider broker was not elevated'
                print('PROVIDER_MEDIUM_TARGET pid=' + str(target.pid) + ' broker=' + str(helper_pid), flush=True)
                release.touch()
                if args.case == 'kernel-restart' and args.second_image_library:
                    wait_for((work / 'images-loaded').exists, target, 'Both provider images loaded')
                    verify_resident_images(target.pid, resident_images)
                    (work / 'images-checked').touch()
                target.wait(timeout=90)
                broker.wait(timeout=20)
                assert broker.returncode == 0, ('Provider broker exit', broker.returncode)
                assert query_interval(0) == previous_interval, 'Provider collection changed the timer interval'
                result = target
            else:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=90, cwd=work)
    finally:
        if target and target.poll() is None:
            target.kill()
            target.wait(timeout=10)
        if broker and broker.poll() is None:
            broker.wait(timeout=20)
    text = (work / 'target.log').read_text(encoding='utf-8', errors='replace')
    print(text, flush=True)
    if isinstance(result, subprocess.Popen):
        assert result.returncode == 0, ('Provider target exit', result.returncode)
    else:
        result.check_returncode()
    validate_metadata_metrics(text)
    event = 'trace:{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}/5/0' if args.case.startswith('kernel-') else (
        'trace:{2a94e71b-655a-4f69-8c64-302d17032ae9}/@燃烧𠮷' if args.case == 'named' else 'trace:{e50fb813-9e08-40dc-a8af-3390db1dbbf4}/1/7')
    interval = 7 if args.case == 'interval' else 1
    for attempt in range(2 if args.case in ['restart', 'kernel-restart'] else 1):
        recording = work / ('tracepoint-' + str(attempt) + '.jfr')
        subprocess.run([str(java), '-cp', str(classes), 'ReadTracepoint', str(recording), args.case], check=True)
        samples, total = validate_totals(java, classes, jar, recording, 'TracepointSmoke', counter_unit='events',
                                        expected_type=event, expected_unit='events')
        assert samples == (1 if args.case.startswith('kernel-') else 1024 // interval) and total == samples * interval, (samples, total, interval)
    print('TRACEPOINT_OK', args.case, 'Evidence:', work, flush=True)


if __name__ == '__main__':
    main()
