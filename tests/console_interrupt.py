# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Run a command in this process's console and interrupt it with Ctrl+C after a delay.

Usage: console_interrupt.py RESULT DELAY_SECONDS COMMAND... (start it in a new console). The command's
stdout, stderr and exit code are written to RESULT.stdout, RESULT.stderr and RESULT.exit.
"""
import ctypes
from pathlib import Path
import subprocess
import sys
import time


def main():
    result, delay, command = Path(sys.argv[1]), float(sys.argv[2]), sys.argv[3:]
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    def ignore(enabled):
        if not kernel32.SetConsoleCtrlHandler(None, enabled):
            raise ctypes.WinError(ctypes.get_last_error())

    with result.with_suffix('.stdout').open('wb') as stdout, result.with_suffix('.stderr').open('wb') as stderr:
        # Children inherit whether Ctrl+C is ignored, which callers such as test runners may have set.
        ignore(False)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        time.sleep(delay)
        ignore(True)
        if not kernel32.GenerateConsoleCtrlEvent(0, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        code = process.wait(timeout=60)
    result.with_suffix('.exit').write_text(str(code), encoding='ascii')


if __name__ == '__main__':
    main()
