# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""CPU, monitor/park lock and span SDK events from virtual threads (JDK 21+)."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path, default=Path(__file__).resolve().parents[1] / 'build/asyncProfiler.dll')
    parser.add_argument('--work-directory', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    jar = root / 'build/asprof-windows.jar'
    work = (args.work_directory or Path(tempfile.mkdtemp(prefix='asprof-virtual-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    classes = work / 'classes'
    java_home = args.java_home
    subprocess.run([str(java_home / 'bin/javac.exe'), '-cp', str(jar), '-d', str(classes), str(root / 'tests/VirtualThreads.java')], check=True)
    recording = work / 'virtual.jfr'
    result = subprocess.run([str(java_home / 'bin/java.exe'), '-cp', f'{classes};{jar}', 'VirtualThreads', str(args.agent.resolve()),
                             str(recording)], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0 and 'VIRTUAL_THREADS_DONE spans=800' in result.stdout, (result.stdout, result.stderr)
    jfr = str(java_home / 'bin/jfr.exe')
    summary = subprocess.run([jfr, 'summary', str(recording)], check=True, capture_output=True, text=True).stdout
    counts = dict((name, int(count)) for name, count in re.findall(r'^\s*(\S+)\s+(\d+)\s+\d+\s*$', summary, re.MULTILINE))
    assert counts.get('profiler.Span') == 800, ('spans', counts)
    assert counts.get('jdk.ExecutionSample', 0) > 0 and counts.get('jdk.JavaMonitorEnter', 0) > 0, counts
    # An unpinned virtual thread parks by unmounting rather than through Unsafe.park, which
    # the lock profiler traces, so ReentrantLock contention records no park events, as upstream.
    def events(name):
        return subprocess.run([jfr, 'print', '--events', name, str(recording)], check=True, capture_output=True, text=True).stdout
    assert 'VirtualThreads.vtBurn' in events('jdk.ExecutionSample')
    assert 'VirtualThreads.vtMonitor' in events('jdk.JavaMonitorEnter')
    monitors = counts['jdk.JavaMonitorEnter']
    spans = events('profiler.Span')
    assert spans.count('tag = "vt-span"') == 800, spans[:2000]
    version = subprocess.run([str(java_home / 'bin/java.exe'), '-version'], capture_output=True, text=True).stderr.splitlines()[0]
    print(f'VIRTUAL_THREADS_OK cpu={counts["jdk.ExecutionSample"]} park={counts.get("jdk.ThreadPark", 0)} monitor={monitors} '
          f'spans={counts["profiler.Span"]} jvm="{version}"', flush=True)


if __name__ == '__main__':
    main()
