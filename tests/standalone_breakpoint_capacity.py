# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Combine hardware-breakpoint users (TLAB allocation, TTSP windows, a native probe) up to and beyond the four x64
debug-register slots on a JVM with matching PDBs: four slots record, a fifth fails start explicitly."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

PROGRAM = '''
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public class Capacity {
    static volatile Object keep;
    public static void main(String[] args) throws Exception {
        AsyncProfiler profiler = AsyncProfiler.getInstance(Path.of(args[0]).toAbsolutePath().toString());
        try {
            profiler.execute(args[1]);
        } catch (IllegalStateException e) {
            System.out.println("FAILED " + e.getMessage());
            return;
        }
        long end = System.nanoTime() + 2000000000L;
        while (System.nanoTime() < end) {
            for (int i = 0; i < 1000; i++) keep = new byte[256 * 1024];
            System.currentTimeMillis();
            System.gc();
        }
        profiler.stop();
        System.out.println("STOPPED " + profiler.execute("metrics").lines().filter(l -> l.startsWith("windows_breakpoint")).toList());
    }
}
'''


def run(java_home, classes, jar, agent, command, symbols, work):
    environment = dict(os.environ, ASYNC_PROFILER_SYMBOL_PATH=str(symbols))
    result = subprocess.run([str(java_home / 'bin/java.exe'), '-cp', f'{classes};{jar}', 'Capacity', str(agent), command],
                            capture_output=True, text=True, timeout=120, env=environment, cwd=work)
    assert result.returncode == 0, (command, result.stdout, result.stderr)
    # The agent logs to stdout.
    return result.stdout.strip().splitlines()[-1], result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True, help='JDK 17+ whose PDBs are in --symbols')
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--agent', type=Path, default=Path(__file__).resolve().parents[1] / 'build/asyncProfiler.dll')
    parser.add_argument('--work-directory', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    jar = root / 'build/asprof-windows.jar'
    work = (args.work_directory or Path(tempfile.mkdtemp(prefix='asprof-capacity-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    (work / 'Capacity.java').write_text(PROGRAM, encoding='utf-8')
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '-cp', str(jar), '-d', str(work), str(work / 'Capacity.java')], check=True)
    agent = args.agent.resolve()
    four, _ = run(args.java_home, work, jar, agent, f'start,event=cpu,alloc,tlab,ttsp,jfr,file={work / "four.jfr"}', args.symbols, work)
    assert four.startswith('STOPPED'), four
    # The first user that finds no free slot fails start; the log names the cause.
    five, log = run(args.java_home, work, jar, agent, f'start,event=jvm.dll!JVM_CurrentTimeMillis,alloc,tlab,ttsp,jfr,file={work / "five.jfr"}',
               args.symbols, work)
    assert five.startswith('FAILED') and 'x64 has four hardware slots shared with debuggers' in log, (five, log)
    print(f'BREAKPOINT_CAPACITY_OK four="{four}" five="{five}"', flush=True)


if __name__ == '__main__':
    main()
