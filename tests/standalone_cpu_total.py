# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Compare the CPU engine's total for a busy thread with that thread's own CPU time (ThreadMXBean) over a fixed
profiling duration, at a coarse and a sub-poll interval, as upstream's CpuTests.ctimerTotal/itimerTotal do."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

PROGRAM = '''
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import one.profiler.AsyncProfiler;

public class CpuTotal {
    static volatile long sink;
    static volatile boolean running = true;

    public static void main(String[] args) throws Exception {
        final ThreadMXBean threads = ManagementFactory.getThreadMXBean();
        Thread burner = new Thread(new Runnable() {
            public void run() {
                long value = 1;
                while (running) for (int i = 0; i < 100000; i++) value = value * 31 + i;
                sink = value;
            }
        }, "cpu-total-burner");
        burner.start();
        Thread.sleep(500);
        AsyncProfiler profiler = AsyncProfiler.getInstance(args[0]);
        for (int index = 1; index < args.length; index++) {
            long cpuBefore = threads.getThreadCpuTime(burner.getId());
            long wallBefore = System.nanoTime();
            profiler.execute("start,event=" + args[index]);
            Thread.sleep(2000);
            profiler.stop();
            long wall = System.nanoTime() - wallBefore;
            long cpu = threads.getThreadCpuTime(burner.getId()) - cpuBefore;
            long total = 0;
            for (String line : profiler.execute("collapsed,total").split("\\\\n")) {
                if (line.contains("CpuTotal")) total += Long.parseLong(line.substring(line.lastIndexOf(' ') + 1));
            }
            System.out.println("CPU_TOTAL event=" + args[index] + " profiler=" + total + " threadCpu=" + cpu + " wall=" + wall);
        }
        running = false;
        burner.join();
    }
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--compiler-jdk', type=Path, required=True, help='JDK whose javac builds the Java 8 program')
    parser.add_argument('--agent', type=Path, default=Path(__file__).resolve().parents[1] / 'build/asyncProfiler.dll')
    parser.add_argument('--work-directory', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    jar = root / 'build/asprof-windows.jar'
    work = (args.work_directory or Path(tempfile.mkdtemp(prefix='asprof-cpu-total-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    (work / 'CpuTotal.java').write_text(PROGRAM, encoding='utf-8')
    subprocess.run([str(args.compiler_jdk / 'bin/javac.exe'), '--release', '8', '-nowarn', '-cp', str(jar), '-d', str(work),
                    str(work / 'CpuTotal.java')], check=True, capture_output=True)
    events = ['ctimer,interval=100ms', 'ctimer,interval=1us', 'itimer,interval=100ms']
    result = subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', f'{work};{jar}', 'CpuTotal', str(args.agent.resolve()), *events],
                            capture_output=True, text=True, timeout=120, cwd=work)
    assert result.returncode == 0, (result.stdout, result.stderr)
    rows = re.findall(r'CPU_TOTAL event=(\S+) profiler=(\d+) threadCpu=(\d+) wall=(\d+)', result.stdout)
    assert len(rows) == len(events), result.stdout
    for event, profiler, cpu, wall in rows:
        profiler, cpu, wall = int(profiler), int(cpu), int(wall)
        # The thread's CPU time between start and stop, less up to one interval left pending at stop
        # and one poll period (at most 50 ms) at each end, is what the profiler can attribute.
        interval = 100_000_000 if '100ms' in event else 1_000_000
        assert cpu - interval - 2 * 50_000_000 <= profiler <= cpu + 50_000_000, (event, profiler, cpu)
        print(f'CPU_TOTAL_OK event={event} profiler={profiler / 1e9:.3f}s threadCpu={cpu / 1e9:.3f}s wall={wall / 1e9:.3f}s', flush=True)


if __name__ == '__main__':
    main()
