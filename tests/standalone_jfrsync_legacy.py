# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Synchronize profiler samples with the JVM's own JFR recording on JDK 8u262+/11, whose JFR APIs predate the
Java 17 readers of the lifecycle suite: one file holds the JVM's events and the profiler's samples."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

WORKLOAD = '''
public class SyncWorkload {
    static volatile Object keep;
    static volatile long sink;
    static void syncBurn() {
        long value = 1;
        for (int i = 0; i < 1000000; i++) value = value * 31 + i;
        sink = value;
    }
    public static void main(String[] args) {
        long end = System.nanoTime() + 3000000000L;
        while (System.nanoTime() < end) {
            syncBurn();
            for (int i = 0; i < 100; i++) keep = new byte[64 * 1024];
            if ((System.nanoTime() / 1000000) % 500 < 2) System.gc();
        }
    }
}
'''

# The target JDK's own reader: JDK 17+ readers reject a file mixing a JDK 11 chunk with the
# profiler's chunk, while each chunk alone parses.
READER = '''
import java.nio.file.Paths;
import java.util.Map;
import java.util.TreeMap;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedFrame;
import jdk.jfr.consumer.RecordingFile;

public class SyncReader {
    public static void main(String[] args) throws Exception {
        Map<String, Integer> counts = new TreeMap<String, Integer>();
        int workload = 0;
        for (RecordedEvent event : RecordingFile.readAllEvents(Paths.get(args[0]))) {
            String name = event.getEventType().getName();
            Integer count = counts.get(name);
            counts.put(name, count == null ? 1 : count + 1);
            if (name.equals("jdk.ExecutionSample") && event.getStackTrace() != null) {
                for (RecordedFrame frame : event.getStackTrace().getFrames()) {
                    if (frame.getMethod().getName().equals("syncBurn")) { workload++; break; }
                }
            }
        }
        System.out.println("COUNTS samples=" + counts.get("jdk.ExecutionSample") + " workload=" + workload
            + " gc=" + counts.get("jdk.GarbageCollection") + " cpuLoad=" + counts.get("jdk.CPULoad"));
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--reader-jdk', type=Path, required=True, help='JDK 17+ whose javac and jfr tools are used')
    parser.add_argument('--agent', type=Path, default=Path(__file__).resolve().parents[1] / 'build/asyncProfiler.dll')
    parser.add_argument('--work-directory', type=Path)
    args = parser.parse_args()
    work = (args.work_directory or Path(tempfile.mkdtemp(prefix='asprof-jfrsync-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    (work / 'SyncWorkload.java').write_text(WORKLOAD, encoding='utf-8')
    subprocess.run([str(args.reader_jdk / 'bin/javac.exe'), '--release', '8', '-nowarn', '-d', str(work), str(work / 'SyncWorkload.java')],
                   check=True, capture_output=True)
    recording = work / 'sync.jfr'
    result = subprocess.run([str(args.java_home / 'bin/java.exe'),
                             f'-agentpath:{args.agent.resolve()}=start,event=cpu,interval=10ms,jfrsync=profile,file={recording}',
                             '-cp', str(work), 'SyncWorkload'], capture_output=True, text=True, timeout=120, cwd=work)
    assert result.returncode == 0, (result.stdout, result.stderr)
    (work / 'SyncReader.java').write_text(READER, encoding='utf-8')
    subprocess.run([str(args.reader_jdk / 'bin/javac.exe'), '-source', '8', '-target', '8', '-nowarn', '-d', str(work), str(work / 'SyncReader.java')],
                   check=True, capture_output=True)
    read = subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', str(work), 'SyncReader', str(recording)],
                          check=True, capture_output=True, text=True).stdout
    samples, workload, gc, load = (int(value) if value != 'null' else 0 for value in
                                   re.search(r'samples=(\w+) workload=(\d+) gc=(\w+) cpuLoad=(\w+)', read).groups())
    # The JVM's profile settings contribute GC and CPU-load events; the profiler contributes its samples.
    assert samples > 0 and workload > 0 and gc > 0 and load > 0, read
    version = subprocess.run([str(args.java_home / 'bin/java.exe'), '-version'], capture_output=True, text=True).stderr.splitlines()[0]
    print(f'JFRSYNC_LEGACY_OK samples={samples} workload={workload} gc={gc} cpuLoad={load} jvm="{version}"', flush=True)


if __name__ == '__main__':
    main()
