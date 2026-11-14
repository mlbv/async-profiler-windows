# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Force a final-buffer write failure using a Windows byte-range lock."""
import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import tempfile


class Overlapped(ctypes.Structure):
    _fields_ = [('internal', ctypes.c_size_t), ('internal_high', ctypes.c_size_t),
                ('offset', wintypes.DWORD), ('offset_high', wintypes.DWORD), ('event', wintypes.HANDLE)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--expect-unchecked', action='store_true')
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix='asprof-output-failure-'))
    output = work / 'locked.txt'
    journal = work / 'journal.txt'
    journal.touch()
    print('Evidence:', work, flush=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.LockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(Overlapped)]
    kernel.LockFileEx.restype = wintypes.BOOL
    kernel.UnlockFileEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.DWORD, ctypes.POINTER(Overlapped)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateFileW(str(output), 0xc0000000, 7, None, 2, 0x80, None)
    assert handle != wintypes.HANDLE(-1).value, ctypes.get_last_error()
    request = Overlapped()
    assert kernel.LockFileEx(handle, 3, 0, 0xffffffff, 0xffffffff, ctypes.byref(request)), ctypes.get_last_error()
    library = ctypes.CDLL(str(args.agent.resolve()))
    library.asprof_init.argtypes = []
    library.asprof_init.restype = None
    library.asprof_execute.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    library.asprof_execute.restype = ctypes.c_char_p
    library.asprof_init()
    command = f'version,file={output},fileresult={journal}'.encode('utf-8')
    try:
        error = library.asprof_execute(command, None)
        print('Locked write:', error, 'bytes:', output.stat().st_size, flush=True)
        assert output.stat().st_size == 0, 'The byte-range lock did not prevent the final-buffer write'
        if args.expect_unchecked:
            assert error is None, error
            print('UNCHECKED_FINAL_WRITE_REPRODUCED', flush=True)
            return
        assert error is not None and b'Could not write output file' in error, error
        assert '!ERROR\tCould not write output file' in journal.read_text(encoding='utf-8')
    finally:
        assert kernel.UnlockFileEx(handle, 0, 0xffffffff, 0xffffffff, ctypes.byref(request)), ctypes.get_last_error()
        assert kernel.CloseHandle(handle), ctypes.get_last_error()
    error = library.asprof_execute(command, None)
    assert error is None, error
    assert output.read_text(encoding='utf-8').startswith('4.5-windows')
    print('FINAL_WRITE_ERROR_AND_RECOVERY_OK', flush=True)


if __name__ == '__main__':
    main()
