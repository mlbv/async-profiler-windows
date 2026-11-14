# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Record every event family enabled by the `all` option at once on a JVM and check each one produced events."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

WORKLOAD = '''
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

public class AllEvents {
    static final Object MONITOR = new Object();
    static final ReentrantLock LOCK = new ReentrantLock();
    static final List<Object> retained = new ArrayList<Object>();
    static volatile Object keep;
    static volatile long sink;

    static void burn(long millis) {
        long end = System.nanoTime() + millis * 1000000L, value = 1;
        while (System.nanoTime() < end) value = value * 31 + 1;
        sink = value;
    }
    static void allocate() {
        for (int i = 0; i < 2000; i++) {
            byte[] block = new byte[64 * 1024];
            if (i % 100 == 0) retained.add(block);
            keep = block;
        }
    }
    static void nativeMemory() {
        for (int i = 0; i < 200; i++) keep = ByteBuffer.allocateDirect(1 << 20);
    }
    static void contend() throws InterruptedException {
        Thread[] threads = new Thread[4];
        for (int t = 0; t < threads.length; t++) {
            threads[t] = new Thread(new Runnable() {
                public void run() {
                    for (int i = 0; i < 20; i++) {
                        synchronized (MONITOR) { burn(2); }
                        LOCK.lock();
                        try { burn(2); } finally { LOCK.unlock(); }
                    }
                }
            });
            threads[t].start();
        }
        for (Thread thread : threads) thread.join();
    }
    public static void main(String[] args) throws Exception {
        Thread sleeper = new Thread(new Runnable() {
            public void run() {
                try { Thread.sleep(60000); } catch (InterruptedException e) { }
            }
        }, "all-sleeper");
        sleeper.setDaemon(true);
        sleeper.start();
        long end = System.nanoTime() + 4000000000L;
        while (System.nanoTime() < end) {
            allocate();
            nativeMemory();
            contend();
            burn(100);
        }
        System.out.println("ALL_EVENTS_DONE");
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
    work = (args.work_directory or Path(tempfile.mkdtemp(prefix='asprof-all-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    (work / 'AllEvents.java').write_text(WORKLOAD, encoding='utf-8')
    subprocess.run([str(args.reader_jdk / 'bin/javac.exe'), '--release', '8', '-nowarn', '-d', str(work), str(work / 'AllEvents.java')],
                   check=True, capture_output=True)
    recording = work / 'all.jfr'
    result = subprocess.run([str(args.java_home / 'bin/java.exe'), f'-agentpath:{args.agent.resolve()}=start,all,proc=1,file={recording}',
                             '-cp', str(work), 'AllEvents'], capture_output=True, text=True, timeout=180, cwd=work)
    assert result.returncode == 0 and 'ALL_EVENTS_DONE' in result.stdout, (result.stdout, result.stderr)
    summary = subprocess.run([str(args.reader_jdk / 'bin/jfr.exe'), 'summary', str(recording)], check=True, capture_output=True, text=True).stdout
    counts = dict((name, int(count)) for name, count in re.findall(r'^\s*(\S+)\s+(\d+)\s+\d+\s*$', summary, re.MULTILINE))
    allocation = sum(counts.get(name, 0) for name in ['jdk.ObjectAllocationInNewTLAB', 'jdk.ObjectAllocationOutsideTLAB', 'jdk.ObjectAllocationSample'])
    required = {'cpu': counts.get('jdk.ExecutionSample', 0), 'wall': counts.get('profiler.WallClockSample', 0), 'alloc': allocation,
                'live': counts.get('profiler.LiveObject', 0), 'monitor': counts.get('jdk.JavaMonitorEnter', 0),
                'park': counts.get('jdk.ThreadPark', 0), 'malloc': counts.get('profiler.Malloc', 0),
                'proc': counts.get('profiler.ProcessSample', 0)}
    version = subprocess.run([str(args.java_home / 'bin/java.exe'), '-version'], capture_output=True, text=True).stderr.splitlines()[0]
    # Live objects need sampled allocation (JDK 11+), as upstream; JDK 8 allocation uses TLAB breakpoints and its PDB.
    assert all(value for name, value in required.items() if name != 'live' or '"1.8.' not in version), (required, counts)
    print('ALL_OK ' + ' '.join(f'{name}={value}' for name, value in required.items())
          + f' free={counts.get("profiler.Free", 0)} nativelock={counts.get("profiler.NativeLock", 0)} jvm="{version}"', flush=True)


if __name__ == '__main__':
    main()
