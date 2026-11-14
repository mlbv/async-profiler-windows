# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Run upstream method-instrumentation regressions and the JVM 8 anonymous-class crash check."""
import argparse
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--reader-jdk', type=Path, required=True)
    parser.add_argument('--agent', type=Path, required=True)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--case', choices=['all', 'anonymous', 'constructors', 'methods', 'stop', 'recovery', 'inflight'], default='all')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    work = Path(tempfile.mkdtemp(prefix='asprof-legacy-instrument-'))
    print('Evidence:', work, flush=True)
    jar = root / 'build/asprof-windows.jar'
    classes = work / 'classes'
    classes.mkdir()
    java = args.java_home.resolve() / 'bin/java.exe'
    agent = args.agent.resolve()
    sources = [args.upstream / 'test/test/instrument' / (name + '.java') for name in ['CpuBurner', 'MethodTracingStop']]
    sources.append(root / 'tests/LegacyAnonymousInstrumentation.java')
    sources.append(root / 'tests/LegacyInstrumentationLifecycle.java')
    subprocess.run([str(args.reader_jdk / 'bin/javac.exe'), '--release', '8', '-Xlint:-options', '-cp', str(jar),
                    '-d', str(classes), *map(str, sources)], check=True)
    classpath = str(classes) + ';' + str(jar)

    def run(name, arguments):
        with (work / (name + '.log')).open('w', encoding='utf-8') as log:
            result = subprocess.run([str(java), '-ea', '-Xms32m', '-Xmx64m', '-Xverify:all',
                                     '-XX:ErrorFile=' + str(work / 'hs_err_pid%p.log'), *arguments],
                                    cwd=work, stdout=log, stderr=subprocess.STDOUT, timeout=45)
        text = (work / (name + '.log')).read_text(encoding='utf-8', errors='replace')
        print(text, end='', flush=True)
        result.check_returncode()
        assert 'VerifyError' not in text and 'EXCEPTION_ACCESS_VIOLATION' not in text, text
        return text

    if args.case in ['all', 'stop']:
        run('stop', ['-Done.profiler.libraryPath=' + str(agent), '-cp', classpath, 'test.instrument.MethodTracingStop'])
        print('UPSTREAM_STOP_OK', flush=True)
    for name, event in [('constructors', '*.<init>'), ('methods', '*.*')]:
        if args.case not in ['all', name]:
            continue
        folded = work / (name + '.collapsed')
        run(name, ['-agentpath:' + str(agent) + '=start,event=' + event + ',collapsed,file=' + str(folded),
                   '-cp', str(classes), 'test.instrument.CpuBurner'])
        text = folded.read_text(encoding='utf-8')
        assert 'java/lang/String.<init>' in text and 'java/lang/Thread.<init>' in text
        assert ('java/lang/Thread.run ' in text) == (name == 'methods')
        assert sum(int(line.rsplit(' ', 1)[1]) for line in text.splitlines()) > 0
        print('UPSTREAM_INSTRUMENTATION_OK', name, flush=True)
    if args.case in ['all', 'anonymous']:
        with zipfile.ZipFile(work / 'fixture-agent.jar', 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nPremain-Class: LegacyAnonymousInstrumentation\nCan-Retransform-Classes: true\n\n')
            for path in classes.glob('LegacyAnonymousInstrumentation*.class'):
                archive.write(path, path.name)
        text = run('anonymous', ['-javaagent:' + str(work / 'fixture-agent.jar'), '-cp', classpath,
                                 'LegacyAnonymousInstrumentation', str(agent)])
        assert 'LEGACY_ANONYMOUS_INSTRUMENTATION_OK' in text, text
    if args.case in ['all', 'recovery', 'inflight']:
        with zipfile.ZipFile(work / 'lifecycle-agent.jar', 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\nPremain-Class: LegacyInstrumentationLifecycle\nCan-Retransform-Classes: true\n\n')
            for path in classes.glob('LegacyInstrumentationLifecycle*.class'):
                archive.write(path, path.name)
        for case in ['recovery', 'inflight'] if args.case == 'all' else [args.case]:
            text = run(case, ['-javaagent:' + str(work / 'lifecycle-agent.jar'), '-cp', classpath,
                              'LegacyInstrumentationLifecycle', str(agent), case])
            expected = 'INSTRUMENTATION_UNDO_RECOVERY_OK' if case == 'recovery' else 'INSTRUMENTATION_INFLIGHT_ISOLATION_OK'
            assert expected in text, text


if __name__ == '__main__':
    main()
