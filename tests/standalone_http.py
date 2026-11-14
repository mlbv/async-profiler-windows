# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Exercise native HTTP uploads, proxy routing, deadlines and bounded responses through the C API."""
import argparse
import base64
from contextlib import contextmanager
import ctypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
from queue import Queue
import threading
import time
from unittest.mock import patch


@contextmanager
def endpoint(status=200, response=b"", hold=False, credentials=None, proxy_auth=False):
    requests = Queue()
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if credentials is not None:
                header = "Proxy-Authorization" if proxy_auth else "Authorization"
                expected = "Basic " + base64.b64encode(credentials.encode("utf-8")).decode("ascii")
                if self.headers.get(header) != expected:
                    self.send_response(407 if proxy_auth else 401)
                    self.send_header("Proxy-Authenticate" if proxy_auth else "WWW-Authenticate", 'Basic realm="test"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
            requests.put((self.path, self.headers, body))
            if hold:
                release.wait(20)
            try:
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "/redirected")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", type=Path, default=Path(__file__).resolve().parents[1] / "build/asyncProfiler.dll")
    args = parser.parse_args()
    agent = ctypes.CDLL(str(args.agent.resolve()))
    agent.asprof_init.argtypes = []
    agent.asprof_init.restype = None
    callback_type = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)
    agent.asprof_execute.argtypes = [ctypes.c_char_p, callback_type]
    agent.asprof_execute.restype = ctypes.c_char_p
    agent.asprof_init()
    output = []
    callback = callback_type(lambda data, size: output.append(ctypes.string_at(data, size)))
    assert agent.asprof_execute(b"version", callback) is None
    version = b"".join(output)
    assert version.startswith(b"4.6-windows."), version

    def send(url, options=""):
        command = f"version,{options}file={url},filebase=C:/unused"
        return agent.asprof_execute(command.encode("utf-8"), callback)

    proxy_keys = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")
    clean = {key: "" for key in proxy_keys}
    with patch.dict(os.environ, clean):
        for options, content_type, path in (
                ("", "application/x-protobuf", "/v1development/profiles"),
                ("collapsed,", "text/plain", "/encoded%20profile?part=one"),
                ("flamegraph,", "text/html", "/profile"),
                ("tree,", "text/html", "/profile")):
            with endpoint(status=202) as (url, requests):
                suffix = "" if not options else path
                assert send(url + suffix, options) is None
                actual_path, headers, body = requests.get(timeout=5)
                assert actual_path == path, actual_path
                assert headers["Content-Type"] == content_type, headers
                assert headers.get("Expect") is None, headers
                assert body == version, body

        with endpoint(status=503, response=b"try later") as (url, _):
            assert send(url) == b"Remote endpoint rejected the profile"
        with endpoint(status=302) as (url, requests):
            assert send(url) == b"Remote endpoint rejected the profile"
            assert requests.qsize() == 1
        for length in (4 * 1024 * 1024, 4 * 1024 * 1024 + 1):
            with endpoint(response=b"x" * length) as (url, _):
                error = send(url)
                assert error == (None if length == 4 * 1024 * 1024 else b"HTTP response exceeds 4 MB"), error

        with endpoint() as (proxy, requests):
            with patch.dict(os.environ, {"http_proxy": proxy}):
                assert send("http://http-target.invalid/profile", "collapsed,") is None
            path, _, body = requests.get(timeout=5)
            assert path == "http://http-target.invalid/profile" and body == version, path
        with endpoint(credentials="user:p@ss:%/+") as (url, requests):
            assert send(url.replace("http://", "http://user:p%40ss%3A%25%2F%2B@")) is None
            requests.get(timeout=5)
        with endpoint(credentials="user:p@ss:%/+", proxy_auth=True) as (proxy, requests):
            authenticated_proxy = proxy.replace("http://", "http://user:p%40ss%3A%25%2F%2B@")
            with patch.dict(os.environ, {"http_proxy": authenticated_proxy}):
                assert send("http://http-target.invalid/profile", "collapsed,") is None
            requests.get(timeout=5)
        for bypass in ("127.0.0.1", "127.0.0.0/8", "*"):
            with endpoint() as (url, requests):
                with patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:9", "no_proxy": bypass}):
                    assert send(url) is None
                requests.get(timeout=5)

        with endpoint(hold=True) as (url, requests):
            start = time.monotonic()
            assert send(url) == b"HTTP request timed out"
            elapsed = time.monotonic() - start
            assert 9 <= elapsed < 13, elapsed
            requests.get(timeout=5)

    print("HTTP_OK content_types=4 status_errors redirects response_limit proxy authentication bypass deadline", flush=True)


if __name__ == "__main__":
    main()
