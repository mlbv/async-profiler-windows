# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Check empty/missing Unicode output variables and concurrent target-env reads."""
import argparse
import ctypes
from pathlib import Path
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--case', choices=['all', 'unstable'], default='all')
    parser.add_argument('--expect-unstable-fallback', action='store_true')
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix='asprof-output-environment-'))
    journal = work / 'journal.txt'
    journal.touch()
    print('Evidence:', work, flush=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.SetEnvironmentVariableW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    kernel.SetEnvironmentVariableW.restype = ctypes.c_int
    library = ctypes.CDLL(str(args.agent.resolve()))
    library.asprof_init.argtypes = []
    library.asprof_init.restype = None
    library.asprof_execute.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
    library.asprof_execute.restype = ctypes.c_char_p
    library.asprof_init()
    variable = 'ASPROF_NATIVE_OUTPUT_目录𠮷'

    def resolve(pattern):
        command = f'resolve,file={pattern},filebase={work},fileresult={journal}'
        return library.asprof_execute(command.encode('utf-8'), None)

    try:
        if args.case == 'all':
            assert kernel.SetEnvironmentVariableW(variable, None), ctypes.get_last_error()
            error = resolve(f'prefix-%{{{variable}}}-suffix.svg')
            assert error is not None and b'Output environment variable is not defined' in error, error
            assert journal.read_bytes() == b'', 'Missing variable reported a fallback output'
            assert kernel.SetEnvironmentVariableW(variable, ''), ctypes.get_last_error()
            assert resolve(f'prefix-%{{{variable}}}-suffix.svg') is None
            assert Path(journal.read_text(encoding='utf-8').strip()) == work / 'prefix--suffix.svg'
            journal.write_text('', encoding='utf-8')
            assert kernel.SetEnvironmentVariableW(variable, '目标𠮷'), ctypes.get_last_error()
            assert resolve(f'prefix-%{{{variable}}}.collapsed') is None
            assert Path(journal.read_text(encoding='utf-8').strip()) == work / 'prefix-目标𠮷.collapsed'
            journal.write_text('', encoding='utf-8')

        short = 'small'
        long = 'long' * 1024
        assert kernel.SetEnvironmentVariableW(variable, short), ctypes.get_last_error()
        stopped = threading.Event()
        failures = []

        def mutate():
            while not stopped.is_set():
                for value in (long, short):
                    if not kernel.SetEnvironmentVariableW(variable, value):
                        failures.append(ctypes.get_last_error())
                        stopped.set()

        thread = threading.Thread(target=mutate)
        thread.start()
        try:
            for _ in range(2000):
                assert resolve(f'prefix-%{{{variable}}}.collapsed') is None
        finally:
            stopped.set()
            thread.join(timeout=5)
        assert not thread.is_alive() and not failures, failures
        records = journal.read_text(encoding='utf-8').splitlines()
        expected = {str(work / f'prefix-{value}.collapsed') for value in (short, long)}
        unexpected = [line for line in records if line not in expected]
        print('Concurrent reads:', len(records), 'fallbacks:', len(unexpected), flush=True)
        if args.expect_unstable_fallback:
            assert unexpected, 'Size-query/read race did not reproduce'
            assert all(Path(line).name == 'prefix-.collapsed' for line in unexpected), unexpected[:2]
            print('UNSTABLE_ENV_FALLBACK_REPRODUCED', flush=True)
        else:
            assert len(records) == 2000 and not unexpected, unexpected[:2]
            print('OUTPUT_ENVIRONMENT_OK', flush=True)
    finally:
        kernel.SetEnvironmentVariableW(variable, None)


if __name__ == '__main__':
    main()
