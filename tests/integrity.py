# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Process integrity for tests, which run elevated.

Targets served by the ETW broker are ordinary processes. They run with this session's UAC-filtered
token, taken from the desktop shell: a standard-user process of the same user at medium integrity, or
lowered to low integrity. The linked token itself is unusable here, because Windows returns it to
callers without SeTcbPrivilege only at identification level.

Importing this module makes the driver's token own new objects as the user rather than through
Administrators, so ordinary processes can use what the driver and its elevated children create,
including tempfile.mkdtemp's owner-only directories.
"""
import contextlib
import ctypes
import subprocess
import threading
from ctypes import wintypes

kernel = ctypes.WinDLL('kernel32', use_last_error=True)
advapi = ctypes.WinDLL('advapi32', use_last_error=True)
user = ctypes.WinDLL('user32', use_last_error=True)
userenv = ctypes.WinDLL('userenv', use_last_error=True)

MEDIUM_INTEGRITY, LOW_INTEGRITY = 0x2000, 0x1000
TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_ADJUST_DEFAULT, TOKEN_ALL_ACCESS = 0x0002, 0x0008, 0x0080, 0xF01FF
TOKEN_USER, TOKEN_OWNER, TOKEN_INTEGRITY_LEVEL, TOKEN_ELEVATION = 1, 4, 25, 20
SECURITY_IMPERSONATION, TOKEN_PRIMARY, TOKEN_IMPERSONATION = 2, 1, 2
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SE_GROUP_INTEGRITY = 0x20
CREATE_UNICODE_ENVIRONMENT = 0x400
STARTF_USESHOWWINDOW, SW_HIDE = 0x1, 0


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [('cb', wintypes.DWORD), ('lpReserved', wintypes.LPWSTR), ('lpDesktop', wintypes.LPWSTR),
                ('lpTitle', wintypes.LPWSTR), ('dwX', wintypes.DWORD), ('dwY', wintypes.DWORD),
                ('dwXSize', wintypes.DWORD), ('dwYSize', wintypes.DWORD), ('dwXCountChars', wintypes.DWORD),
                ('dwYCountChars', wintypes.DWORD), ('dwFillAttribute', wintypes.DWORD), ('dwFlags', wintypes.DWORD),
                ('wShowWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD), ('lpReserved2', ctypes.c_void_p),
                ('hStdInput', wintypes.HANDLE), ('hStdOutput', wintypes.HANDLE), ('hStdError', wintypes.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE),
                ('dwProcessId', wintypes.DWORD), ('dwThreadId', wintypes.DWORD)]


class TOKEN_MANDATORY_LABEL(ctypes.Structure):
    _fields_ = [('Sid', ctypes.c_void_p), ('Attributes', wintypes.DWORD)]


kernel.GetCurrentProcess.restype = wintypes.HANDLE
kernel.CloseHandle.argtypes = [wintypes.HANDLE]
kernel.OpenProcess.restype = wintypes.HANDLE
kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel.LocalFree.argtypes = [ctypes.c_void_p]
user.GetShellWindow.restype = wintypes.HWND
user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
userenv.CreateEnvironmentBlock.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.HANDLE, wintypes.BOOL]
userenv.DestroyEnvironmentBlock.argtypes = [ctypes.c_void_p]
advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                       ctypes.POINTER(wintypes.DWORD)]
advapi.SetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
advapi.DuplicateTokenEx.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                    ctypes.POINTER(wintypes.HANDLE)]
advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
advapi.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
advapi.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
advapi.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
advapi.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
advapi.SetThreadToken.argtypes = [ctypes.c_void_p, wintypes.HANDLE]
advapi.CreateProcessWithTokenW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPWSTR,
                                           wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
                                           ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION)]


def check(result, call):
    if not result:
        raise ctypes.WinError(ctypes.get_last_error(), call)


def _token_information(token, information_class):
    size = wintypes.DWORD()
    advapi.GetTokenInformation(token, information_class, None, 0, ctypes.byref(size))
    buffer = ctypes.create_string_buffer(size.value)
    check(advapi.GetTokenInformation(token, information_class, buffer, size, ctypes.byref(size)), 'GetTokenInformation')
    return buffer


def _token_user(token):
    sid = ctypes.cast(_token_information(token, TOKEN_USER), ctypes.POINTER(ctypes.c_void_p))[0]
    text = wintypes.LPWSTR()
    check(advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)), 'ConvertSidToStringSid')
    try:
        return text.value
    finally:
        kernel.LocalFree(text)


def _token_integrity(token):
    sid = ctypes.cast(_token_information(token, TOKEN_INTEGRITY_LEVEL), ctypes.POINTER(ctypes.c_void_p))[0]
    return advapi.GetSidSubAuthority(sid, advapi.GetSidSubAuthorityCount(sid)[0] - 1)[0]


def _token_elevated(token):
    return ctypes.cast(_token_information(token, TOKEN_ELEVATION), ctypes.POINTER(wintypes.DWORD))[0] != 0


def _own_token():
    token = wintypes.HANDLE()
    check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)), 'OpenProcessToken')
    return token


def _own_objects_as_user():
    token = wintypes.HANDLE()
    check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, ctypes.byref(token)),
          'OpenProcessToken')
    try:
        user = _token_information(token, TOKEN_USER)
        owner = ctypes.c_void_p(ctypes.cast(user, ctypes.POINTER(ctypes.c_void_p))[0])
        check(advapi.SetTokenInformation(token, TOKEN_OWNER, ctypes.byref(owner), ctypes.sizeof(owner)),
              'SetTokenInformation(TokenOwner)')
    finally:
        kernel.CloseHandle(token)


_own_objects_as_user()


def require_elevated():
    token = _own_token()
    try:
        assert _token_elevated(token), 'Run the tests elevated; ordinary targets start de-elevated'
    finally:
        kernel.CloseHandle(token)


def _filtered_token(token_type, integrity):
    pid = wintypes.DWORD()
    shell = user.GetShellWindow()
    assert shell, 'No desktop shell supplies this session\'s filtered token'
    user.GetWindowThreadProcessId(shell, ctypes.byref(pid))
    process = kernel.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    check(process, 'OpenProcess(shell)')
    shell_token, result = wintypes.HANDLE(), wintypes.HANDLE()
    try:
        check(advapi.OpenProcessToken(process, TOKEN_DUPLICATE | TOKEN_QUERY, ctypes.byref(shell_token)),
              'OpenProcessToken(shell)')
    finally:
        kernel.CloseHandle(process)
    try:
        own = _own_token()
        try:
            assert _token_user(shell_token) == _token_user(own), 'The desktop shell runs as another user'
        finally:
            kernel.CloseHandle(own)
        assert not _token_elevated(shell_token), 'The desktop shell is elevated'
        assert _token_integrity(shell_token) == MEDIUM_INTEGRITY, 'The desktop shell is not medium integrity'
        check(advapi.DuplicateTokenEx(shell_token, TOKEN_ALL_ACCESS, None, SECURITY_IMPERSONATION, token_type,
                                      ctypes.byref(result)), 'DuplicateTokenEx')
    finally:
        kernel.CloseHandle(shell_token)
    if integrity != MEDIUM_INTEGRITY:
        sid = ctypes.c_void_p()
        check(advapi.ConvertStringSidToSidW(f'S-1-16-{integrity}', ctypes.byref(sid)), 'ConvertStringSidToSid')
        try:
            label = TOKEN_MANDATORY_LABEL(sid, SE_GROUP_INTEGRITY)
            check(advapi.SetTokenInformation(result, TOKEN_INTEGRITY_LEVEL, ctypes.byref(label),
                                             ctypes.sizeof(label) + advapi.GetLengthSid(sid)),
                  'SetTokenInformation(TokenIntegrityLevel)')
        finally:
            kernel.LocalFree(sid)
    return result


def _desktop_environment(token):
    block = ctypes.c_void_p()
    check(userenv.CreateEnvironmentBlock(ctypes.byref(block), token, False), 'CreateEnvironmentBlock')
    try:
        variables, offset = {}, 0
        while entry := ctypes.wstring_at(block.value + offset):
            offset += (len(entry) + 1) * ctypes.sizeof(ctypes.c_wchar)
            key, _, value = entry.partition('=')
            variables[key.upper()] = value
        return variables
    finally:
        userenv.DestroyEnvironmentBlock(block)


def _process_creator(integrity, overrides):
    def create(executable, args, _process_attributes, _thread_attributes, _inherit_handles, flags, _env, cwd, startupinfo):
        """Stands in for _winapi.CreateProcess as subprocess.Popen calls it."""
        # The secondary logon service can't attach the process to the caller's console, so a console
        # program gets a console of its own; keep it hidden unless the caller chose a window state.
        flags_set = startupinfo.dwFlags & STARTF_USESHOWWINDOW
        startup = STARTUPINFOW(cb=ctypes.sizeof(STARTUPINFOW), dwFlags=startupinfo.dwFlags | STARTF_USESHOWWINDOW,
                               wShowWindow=startupinfo.wShowWindow if flags_set else SW_HIDE,
                               hStdInput=startupinfo.hStdInput or None, hStdOutput=startupinfo.hStdOutput or None,
                               hStdError=startupinfo.hStdError or None)
        information = PROCESS_INFORMATION()
        token = _filtered_token(TOKEN_PRIMARY, integrity)
        try:
            variables = _desktop_environment(token)
            for key, value in (overrides or {}).items():
                if value is None:
                    variables.pop(key.upper(), None)
                else:
                    variables[key.upper()] = value
            block = ctypes.create_unicode_buffer(''.join(f'{key}={value}\0' for key, value in variables.items()) + '\0')
            check(advapi.CreateProcessWithTokenW(token, 0, executable, ctypes.create_unicode_buffer(args),
                                                 flags | CREATE_UNICODE_ENVIRONMENT, block, cwd, ctypes.byref(startup),
                                                 ctypes.byref(information)), 'CreateProcessWithTokenW')
        finally:
            kernel.CloseHandle(token)
        return information.hProcess, information.hThread, information.dwProcessId, information.dwThreadId
    return create


_creation = threading.Lock()


def deelevated_popen(args, integrity=MEDIUM_INTEGRITY, env=None, **kwargs):
    """subprocess.Popen whose process runs with the session's filtered token at the given integrity.

    The process gets the user's desktop environment, as an ordinary process of that user would, with the
    variables in env set (or removed where None). The elevated driver's environment can't be passed
    whole: the secondary logon service rejects blocks over 32,767 characters.
    """
    with _creation:
        original = subprocess._winapi.CreateProcess
        subprocess._winapi.CreateProcess = _process_creator(integrity, env)
        try:
            return subprocess.Popen(args, close_fds=False, **kwargs)
        finally:
            subprocess._winapi.CreateProcess = original


@contextlib.contextmanager
def impersonating(integrity=MEDIUM_INTEGRITY):
    """Evaluates the calling thread's access checks as an ordinary process of the session would."""
    token = _filtered_token(TOKEN_IMPERSONATION, integrity)
    try:
        check(advapi.SetThreadToken(None, token), 'SetThreadToken')
        try:
            yield
        finally:
            check(advapi.SetThreadToken(None, None), 'SetThreadToken(revert)')
    finally:
        kernel.CloseHandle(token)
