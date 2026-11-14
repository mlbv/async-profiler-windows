# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify asprof URL output through collect, dump, stop and launch without local output files."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading

from read_otlp import validate as validate_otlp
from standalone_software_broker import OutputPipe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--asprof", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    asprof = (args.asprof or root / "build/asprof.exe").resolve()
    agent = args.agent.resolve()
    java = args.java_home / "bin/java.exe"
    work = Path(tempfile.mkdtemp(prefix="asprof-cli-http-"))
    classes = work / "classes"
    classes.mkdir()
    print("Evidence:", work, flush=True)
    subprocess.run([str(args.java_home / "bin/javac.exe"), "--release", "17", "-d", str(classes),
                    str(root / "tests/Fixture.java"), str(root / "tests/CliTemplateTarget.java")], check=True)
    requests = queue.Queue()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.put((self.path, self.headers["Content-Type"], body))
            self.send_response(503 if self.path == "/reject" else 200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    endpoint = f"http://127.0.0.1:{server.server_port}"

    def cli(*arguments, expected=0):
        result = subprocess.run([str(asprof), "--libpath", str(agent), *map(str, arguments)],
                                cwd=work, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=45)
        print(arguments, result.returncode, result.stdout[-1000:], result.stderr[-2000:], flush=True)
        assert result.returncode == expected, result
        return result

    def receive(path, content_type, name):
        actual_path, actual_type, body = requests.get(timeout=5)
        assert actual_path == path, (path, actual_path)
        assert actual_type == content_type, actual_type
        assert body, path
        output = work / name
        output.write_bytes(body)
        if content_type == "application/x-protobuf":
            validate_otlp(output, "Fixture.busy", aggregated=True)
        else:
            assert b"Fixture.busy" in body, body[:1000]

    try:
        with (work / "target.err").open("w", encoding="utf-8") as errors:
            target = subprocess.Popen([str(java), "-cp", str(classes), "CliTemplateTarget", "120"],
                                      cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=errors, text=True)
            output = OutputPipe(target, work / "target.out")
            try:
                assert output.receive("Java fixture ready", 15) == f"READY {target.pid}"
                # The suffix must not select JFR; escapes survive expansion and %p names the target.
                path = "/v1/collect%20name%2F-%p.jfr"
                cli("-d", 1, "-e", "cpu", "-i", "1ms", "-f", endpoint + path, target.pid)
                receive(path.replace("%p", str(target.pid)), "application/x-protobuf", "collect.otlp")
                assert cli("status", target.pid).stdout == "Profiler is not active\n"

                cli("start", "-e", "cpu", "-i", "1ms", target.pid)
                cli("dump", "-f", endpoint + "/dump.jfr", target.pid)
                receive("/dump.jfr", "application/x-protobuf", "dump.otlp")
                assert cli("status", target.pid).stdout.startswith("Profiling is running for ")
                cli("stop", "-o", "collapsed", "-f", endpoint + "/stop", target.pid)
                receive("/stop", "text/plain", "stop.collapsed")

                failed = cli("-d", 1, "-o", "collapsed", "-f", endpoint + "/reject", target.pid, expected=200)
                assert "503" in failed.stderr, failed.stderr
                receive("/reject", "text/plain", "rejected.collapsed")
                assert cli("status", target.pid).stdout == "Profiler is not active\n"
                assert target.poll() is None, "A CLI command terminated the target"
            finally:
                target.terminate()
                target.wait(timeout=10)
                output.thread.join(timeout=5)
                assert not output.thread.is_alive(), "Fixture stdout reader did not finish"

        path = "/launch%20name%2F-%p.jfr"
        launched = cli("launch", "--java", java, "-i", "1ms", "-f", endpoint + path,
                       "--", "-cp", classes, "CliTemplateTarget", "2")
        pid = re.search(r"Launched PID (\d+)\n", launched.stderr).group(1)
        receive(path.replace("%p", pid), "application/x-protobuf", "launch.otlp")
        # Shutdown upload errors must still reach the CLI through its output journal.
        failed = cli("launch", "--java", java, "-i", "1ms", "-o", "collapsed", "-f", endpoint + "/reject",
                     "--", "-cp", classes, "CliTemplateTarget", "2", expected=1)
        assert "Profiler output failed: Remote endpoint rejected the profile" in failed.stderr, failed.stderr
        receive("/reject", "text/plain", "launch-rejected.collapsed")
        assert requests.empty(), "Unexpected duplicate profile submission"
        assert not (work / "http:").exists(), "A URL became a local output directory"
        assert not list(work.glob("asprof-snapshot-*")), "URL output used a local JFR snapshot"
        print("CLI_HTTP_OK collect=1 dump=1 stop=1 launch=1 rejected=2", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)
        assert not server_thread.is_alive(), "HTTP server did not stop"


if __name__ == "__main__":
    main()
