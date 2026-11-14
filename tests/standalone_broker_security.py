# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Check both privileged controllers before sending any capture activation."""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time
import uuid

from standalone_broker import verify_query_only, verify_controller_threads, wait_for
from standalone_etw import query_interval

import integrity

# WindowsProfiler::Etw::Broker wire format: protocol, Reply (48 bytes) and Result (160 bytes).
PROTOCOL, REPLY_SIZE, RESULT_SIZE = 8, 48, 160


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--tamper-thread-query', action='store_true')
    parser.add_argument('--provider', action='store_true')
    parser.add_argument('--protocol-mismatch', action='store_true')
    parser.add_argument('--minimal', action='store_true')
    args = parser.parse_args()
    integrity.require_elevated()
    root = Path(__file__).resolve().parents[1]
    helper = args.agent.resolve().parent / 'asprof-helper.exe'
    work = Path(tempfile.mkdtemp(prefix='asprof-broker-security-'))
    print('Evidence:', work, flush=True)
    pipe = r'\\.\pipe\async-profiler-security-' + work.name
    previous = query_interval(0)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.WriteFile.argtypes = kernel.ReadFile.argtypes
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME), ctypes.POINTER(wintypes.FILETIME)]
    kernel.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    kernel.SetNamedPipeHandleState.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, ctypes.c_void_p]
    peer, broker, broker_pid = None, None, None
    started, stopped = False, False
    sequence = 0

    def transfer(data, write):
        offset = 0
        deadline = time.monotonic() + 10
        while offset < len(data):
            done = wintypes.DWORD()
            call = kernel.WriteFile if write else kernel.ReadFile
            if not call(peer, ctypes.byref(data, offset), len(data) - offset, ctypes.byref(done), None):
                error = ctypes.get_last_error()
                if error != 232:
                    raise ctypes.WinError(error)
            if not done.value:
                assert time.monotonic() < deadline, 'Broker protocol timed out'
                time.sleep(.01)
                continue
            offset += done.value

    def send(kind, payload=b'', version=PROTOCOL):
        raw = (struct.pack('<IIII', version, kind, len(payload), sequence) if version >= 3
               else struct.pack('<III', version, kind, len(payload))) + payload
        transfer(ctypes.create_string_buffer(raw, len(raw)), True)

    def connect_peer():
        handle = kernel.CreateFileW(pipe, 0xC0000000, 0, None, 3, 0x100000 | 0x10000, None)
        if handle == ctypes.c_void_p(-1).value and ctypes.get_last_error() == 231:
            assert kernel.WaitNamedPipeW(pipe, 10000)
            handle = kernel.CreateFileW(pipe, 0xC0000000, 0, None, 3, 0x100000 | 0x10000, None)
        assert handle != ctypes.c_void_p(-1).value, ctypes.get_last_error()
        mode = wintypes.DWORD(1)
        assert kernel.SetNamedPipeHandleState(handle, ctypes.byref(mode), None, None)
        return handle

    def reply(expected_error, expected_source, expected_interval):
        data = receive(3)
        assert len(data) == REPLY_SIZE and data[16:] == bytes(REPLY_SIZE - 16), data
        assert struct.unpack_from('<IIII', data) == (expected_error, expected_source, expected_interval, broker_pid), data[:16]

    def receive(expected):
        header = ctypes.create_string_buffer(16)
        transfer(header, False)
        version, kind, length, received = struct.unpack('<IIII', header.raw)
        assert version == PROTOCOL and received == sequence and kind == expected and length <= 2 * 1024 * 1024, (version, kind, length, received)
        data = ctypes.create_string_buffer(length)
        transfer(data, False)
        return data.raw

    try:
        with (work / 'broker.log').open('w', encoding='utf-8') as log:
            broker = subprocess.Popen([str(helper), '--etw-broker', str(os.getpid()), pipe],
                                      stdout=log, stderr=subprocess.STDOUT, cwd=work)
            wait_for(lambda: 'ETW_BROKER_READY ' in (work / 'broker.log').read_text(errors='replace'), broker, 'Broker ready')
            broker_pid = int(re.search(r'ETW_BROKER_READY pid=(\d+)', (work / 'broker.log').read_text()).group(1))
            with integrity.impersonating():
                if not args.minimal:
                    verify_query_only(kernel, broker_pid)
                peer = connect_peer()
            actual = wintypes.ULONG()
            assert kernel.GetNamedPipeServerProcessId(peer, ctypes.byref(actual)) and actual.value == broker_pid
            times = [wintypes.FILETIME() for _ in range(4)]
            assert kernel.GetProcessTimes(kernel.GetCurrentProcess(), *[ctypes.byref(value) for value in times])
            created = times[0].dwLowDateTime | times[0].dwHighDateTime << 32
            if args.protocol_mismatch:
                try:
                    send(1, struct.pack('<IQ', os.getpid(), created), version=PROTOCOL - 1)
                    receive(3)
                    raise AssertionError('Old wire was accepted')
                except OSError as failure:
                    assert failure.winerror in [109, 233], failure
                kernel.CloseHandle(peer)
                with integrity.impersonating():
                    peer = connect_peer()
                print(f'BROKER_OLD_WIRE_REJECTED version={PROTOCOL - 1}', flush=True)
            send(1, struct.pack('<IQ', os.getpid(), created))
            reply(0, 0, 0)
            sequence = 1
            if args.provider:
                guid = uuid.UUID('22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716').bytes_le
                send(9, guid + struct.pack('<IiII', 5, -1, 0, 0))
            else:
                send(2, struct.pack('<6IQ6I', 0, previous, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0))
            reply(0, 0, 1 if args.provider else previous)
            started = True
            children = subprocess.run(['C:/Program Files/PowerShell/7/pwsh.exe', '-NoProfile',
                                       '-ExecutionPolicy', 'Bypass', '-File', str(root / 'tests/broker_watchers.ps1'),
                                       '-BrokerPid', str(broker_pid), '-IncludeBootstrap'], check=True, capture_output=True, text=True)
            family = json.loads(children.stdout.strip())
            watchers = family['watchers']
            assert len(watchers) == 1, watchers
            with integrity.impersonating():
                bootstrap = kernel.OpenProcess(0x02000000, False, family['bootstrap'])
                if bootstrap:
                    kernel.CloseHandle(bootstrap)
                    raise AssertionError('Bootstrap exposed process access')
                assert ctypes.get_last_error() == 5
                if not args.minimal:
                    verify_query_only(kernel, watchers[0])
                    verify_controller_threads(kernel, [broker_pid, watchers[0]])
            if args.tamper_thread_query:
                subprocess.run(['C:/Program Files/PowerShell/7/pwsh.exe', '-NoProfile',
                                '-ExecutionPolicy', 'Bypass', '-File', str(root / 'tests/broker_thread_query.ps1'),
                                '-ControllerPid', str(watchers[0]), '-ExpectedExecutable', str(helper)], check=True)
                send(8)
                assert struct.unpack_from('<I', receive(3))[0] == 5, 'Product failed to reject changed thread ACL'
                send(6)
                finished = receive(7)
                assert len(finished) == RESULT_SIZE and struct.unpack_from('<I', finished)[0] == 5
                send(10, struct.pack('<I', 7))
            else:
                send(6)
                finished = receive(7)
                assert finished == bytes(RESULT_SIZE), finished
                send(10, struct.pack('<I', 7))
            stopped = True
            assert query_interval(0) == previous
            print('PRE_ACTIVATION_SECURITY_OK controllers=2 bootstrapQueryDenied=1 activated=0 intervalRestored=1 provider=' + str(int(args.provider)) + ' tamperRejected=' + str(int(args.tamper_thread_query)), flush=True)
    finally:
        if peer and peer != ctypes.c_void_p(-1).value:
            if started and not stopped:
                try:
                    send(6)
                    receive(7)
                    send(10, struct.pack('<I', 7))
                except (OSError, AssertionError):
                    pass
            kernel.CloseHandle(peer)
        if broker and broker.poll() is None:
            if broker_pid:
                subprocess.run(['C:/Windows/System32/taskkill.exe', '/PID', str(broker_pid), '/F'], check=True)
            else:
                broker.terminate()
            broker.wait(timeout=15)


if __name__ == '__main__':
    main()
