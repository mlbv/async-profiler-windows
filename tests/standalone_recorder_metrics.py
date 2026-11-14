# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Check retained recorder metadata accounting and reset without collecting another full profile matrix."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-recorder-metrics-'))
    print('Evidence:', work, flush=True)
    jar = root / 'build/asprof-windows.jar'
    methods = '\n'.join(f'    static void m{i}() {{ m{i + 1}(); }}' for i in range(32))
    source = '''
import java.nio.file.Path;
import one.profiler.AsyncProfiler;

public final class MetricsSmoke {
    static volatile long result;
METHODS
    static void m32() {
        var value = result;
        for (var i = 0; i < 100_000; i++) value = Long.rotateLeft(value ^ i, 13) * 0x100000001b3L;
        result = value;
    }
    static void burn(long millis) {
        var until = System.nanoTime() + millis * 1_000_000L;
        while (System.nanoTime() < until) m0();
    }
    static long memory(AsyncProfiler profiler) throws Exception {
        for (var line : profiler.execute("metrics").split("\\n")) {
            if (line.startsWith("mem_flightrecorder_kb ")) return Long.parseLong(line.substring(line.indexOf(' ') + 1));
        }
        throw new AssertionError("Recorder metric missing");
    }
    public static void main(String[] args) throws Exception {
        var profiler = AsyncProfiler.getInstance(args[0]);
        var output = Path.of(args[1], "metrics.jfr");
        burn(250);
        profiler.execute("start,event=cpu,interval=1ms,cstack=no,jfr,file=" + output);
        var recorderOverhead = memory(profiler);
        burn(750);
        profiler.execute("stop");
        var idle = memory(profiler);
        if (idle < 2) throw new AssertionError("Retained metadata omitted from metrics: " + idle);
        profiler.execute("resume,event=cpu,interval=3600s,cstack=no,jfr,file=" + output);
        var active = memory(profiler);
        if (active != idle + recorderOverhead) throw new AssertionError("Dictionary transfer changed accounting: idle=" + idle + " overhead=" + recorderOverhead + " active=" + active);
        profiler.execute("stop");
        if (memory(profiler) != idle) throw new AssertionError("Stopped metadata accounting changed");
        profiler.execute("start,event=cpu,interval=3600s,cstack=no");
        var reset = memory(profiler);
        profiler.execute("stop");
        if (reset != 0) throw new AssertionError("Fresh non-JFR start retained old dictionary: " + reset);
        System.out.println("RECORDER_METRICS_OK idleKb=" + idle + " recorderOverheadKb=" + recorderOverhead + " activeKb=" + active + " resetKb=" + reset);
    }
}
'''.replace('METHODS', methods)
    fixture = work / 'MetricsSmoke.java'
    fixture.write_text(source, encoding='utf-8')
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-cp', str(jar), '-d', str(work), str(fixture)], check=True)
    library = work / 'asyncProfiler.dll'
    shutil.copy2(root / 'build/core/native/asyncProfiler.dll', library)
    subprocess.run([str(args.java_home / 'bin/java.exe'), '-XX:CompileCommand=dontinline,MetricsSmoke.*', '-cp', str(work) + ';' + str(jar),
                    'MetricsSmoke', str(library), str(work)], cwd=work, check=True, timeout=30)


if __name__ == '__main__':
    main()
