# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Prove same-base reload and the private-getter canary independently of profiling."""
import argparse
import ctypes
import errno
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public', type=Path, required=True)
    parser.add_argument('--private', type=Path, required=True)
    args = parser.parse_args()
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.FreeLibrary.argtypes = [ctypes.c_void_p]
    kernel.FreeLibrary.restype = ctypes.c_int
    kernel.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel.GetModuleHandleW.restype = ctypes.c_void_p
    previous = None
    for path, public in [(args.public.resolve(), True), (args.private.resolve(), False)]:
        library = ctypes.CDLL(str(path))
        try:
            assert library._handle == 0x500000000000, hex(library._handle)
            library.ProviderGetterAddress.restype = ctypes.c_void_p
            address = library.ProviderGetterAddress()
            if previous is not None:
                assert address == previous, (hex(previous), hex(address))
            previous = address
            library.ProviderGetterCalls.restype = ctypes.c_uint
            assert library.ProviderGetterCalls() == 0
            if public:
                getter = library._errno
                getter.restype = ctypes.POINTER(ctypes.c_int)
                library.ProviderError(errno.EDOM)
                assert getter()[0] == errno.EDOM
            else:
                try:
                    library._errno
                    raise AssertionError('Private provider unexpectedly exported _errno')
                except AttributeError:
                    pass
                # This is a fresh pointer supplied by the currently loaded
                # provider, with the same RVA as the prior public accessor.
                getter = ctypes.CFUNCTYPE(ctypes.POINTER(ctypes.c_int))(address)
                assert getter()
            assert library.ProviderGetterCalls() == 1, 'The canary did not detect an accessor call'
            print('PROVIDER_CANARY_CONTROL_OK public=' + str(public) + ' base=' + hex(library._handle)
                  + ' getter=' + hex(address), flush=True)
        finally:
            if not kernel.FreeLibrary(library._handle):
                raise ctypes.WinError(ctypes.get_last_error())
        assert kernel.GetModuleHandleW(str(path)) is None, 'Provider remained pinned after FreeLibrary'
    print('PROVIDER_RELOAD_CONTROLS_OK', flush=True)


if __name__ == '__main__':
    main()
