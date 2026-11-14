# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Verify target-side CLI filename templates, overwrites, rotation and snapshots."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True, help='API JAR for the test programs')
    parser.add_argument('--asprof', type=Path)
    parser.add_argument('--agent', type=Path, required=True)
    verification = parser.add_mutually_exclusive_group()
    verification.add_argument('--stop-copy', action='store_true', help='Also require exact stop-to-file JFR sample preservation')
    verification.add_argument('--environment-only', action='store_true', help='Only check missing/empty environment expansion and rejected live snapshots')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    asprof = (args.asprof or root / 'build/asprof.exe').resolve()
    work = Path(tempfile.mkdtemp(prefix='asprof-cli-templates-'))
    target_root = work / '目标 𠮷'
    target_cwd = work / 'target-cwd'
    target_cwd.mkdir()
    controller_root = work / 'wrong-controller-root'
    print('Evidence:', work, flush=True)
    java = args.java_home / 'bin/java.exe'
    classes = work / 'classes'
    classes.mkdir()
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-encoding', 'UTF-8',
                    '-cp', str(args.jar), '-d', str(classes), str(root / 'tests/Fixture.java'),
                    str(root / 'tests/CliTemplateTarget.java'),
                    str(root / 'tests/ReadRecording.java'), str(root / 'tests/ReadStoppedCopies.java'),
                    str(root / 'tests/StopCopySmoke.java')], check=True)

    def cli(*arguments, check=True):
        result = subprocess.run([str(asprof), '--libpath', str(args.agent), *map(str, arguments)],
                                cwd=work, env=dict(os.environ, ASPROF_CLI_OUTPUT=str(controller_root)),
                                capture_output=True, text=True, encoding='utf-8', timeout=45)
        print(arguments, result.returncode, result.stdout, result.stderr, flush=True)
        if check:
            result.check_returncode()
        return result

    def verify(path, started):
        assert path.is_file(), path
        result = subprocess.run([str(java), '-cp', str(classes), 'ReadRecording', str(path),
                                 str(started - 5000), str(int(time.time() * 1000) + 1000)],
                                capture_output=True, text=True, encoding='utf-8', timeout=20)
        print(path.name, result.stdout, result.stderr, flush=True)
        result.check_returncode()
        assert 'fixtureStack=true' in result.stdout, result.stdout
        assert 'wrapper.Probe=' in result.stdout, result.stdout

    def native_samples(path):
        result = subprocess.run([str(java), '-cp', str(classes), 'ReadStoppedCopies', str(path)],
                                capture_output=True, text=True, encoding='utf-8', timeout=20)
        result.check_returncode()
        return result.stdout

    def environment_recordings(pid, started):
        rejected = cli('-d', 1, '--jfrsync', 'profile', '-f', '%{ASPROF_CLI_MISSING}/missing-variable-%p.jfr', pid, check=False)
        assert rejected.returncode == 200, 'A missing environment variable silently changed the output path'
        assert 'ASPROF_CLI_MISSING' in rejected.stderr, rejected.stderr
        assert not (work / '{ASPROF_CLI_MISSING}').exists(), 'An unresolved environment placeholder became a directory'
        assert not (work / f'missing-variable-{pid}.jfr').exists(), 'A missing environment variable fell back to the working directory'
        assert 'not active' in cli('status', pid).stdout
        cli('-d', 2, '--jfrsync', 'profile', '-f', '%{ASPROF_CLI_OUTPUT}/empty-%{ASPROF_CLI_EMPTY}%p.jfr', pid)
        verify(target_root / f'empty-{pid}.jfr', started)

    def missing_snapshot(pid):
        rejected = cli('dump', '-f', '%{ASPROF_CLI_MISSING}/missing-snapshot.jfr', pid, check=False)
        assert rejected.returncode == 200
        assert 'ASPROF_CLI_MISSING' in rejected.stderr, rejected.stderr
        assert 'running' in cli('status', pid).stdout, 'Rejected filename resolution stopped profiling'

    with (work / 'target.out').open('w', encoding='utf-8') as output, (work / 'target.err').open('w', encoding='utf-8') as errors:
        target_environment = dict(os.environ, ASPROF_CLI_OUTPUT=str(target_root), ASPROF_CLI_REL='relative-env', ASPROF_CLI_EMPTY='')
        target_environment.pop('ASPROF_CLI_MISSING', None)
        # The fixture's main thread mostly waits on a monitor; one-second ring segments need a busy thread.
        target = subprocess.Popen([str(java), '-cp', str(classes), 'CliTemplateTarget', '120'], cwd=target_cwd,
                                  env=target_environment, stdout=output, stderr=errors)
        try:
            deadline = time.monotonic() + 10
            while 'READY' not in (work / 'target.out').read_text(encoding='utf-8'):
                if target.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Fixture did not become ready')
                time.sleep(.05)

            started = int(time.time() * 1000)
            if args.environment_only:
                environment_recordings(target.pid, started)
                cli('start', '--jfrsync', 'profile', '-f', '%{ASPROF_CLI_OUTPUT}/env-active-%p.jfr', target.pid)
                time.sleep(1)
                missing_snapshot(target.pid)
                cli('dump', '-f', '%{ASPROF_CLI_OUTPUT}/env-snapshot-%p.jfr', target.pid)
                verify(target_root / f'env-snapshot-{target.pid}.jfr', started)
                cli('stop', target.pid)
                verify(target_root / f'env-active-{target.pid}.jfr', started)
                print('CLI_ENVIRONMENTS_OK', flush=True)
                return
            pattern = '%{ASPROF_CLI_OUTPUT}/new/record-%p-%t-%n{2}.jfr'
            cli('-d', 2, '--jfrsync', 'profile', '-f', pattern, target.pid)
            matches = list((target_root / 'new').glob('record-*.jfr'))
            assert len(matches) == 1, matches
            assert re.fullmatch(r'record-' + str(target.pid) + r'-\d{8}-\d{6}-0\.jfr', matches[0].name), matches
            verify(matches[0], started)
            assert not controller_root.exists(), 'Filename expansion used the controller environment'

            cli('-d', 2, '--jfrsync', 'profile', '-f', '%{ASPROF_CLI_REL}/relative-%p.jfr', target.pid)
            verify(work / 'relative-env' / f'relative-{target.pid}.jfr', started)
            assert not (target_cwd / 'relative-env').exists(), 'Relative output used the target working directory'

            environment_recordings(target.pid, started)

            # Existing output files are replaced, as upstream does.
            collision = target_root / 'collision.jfr'
            collision.write_bytes(b'replace-existing-output\x00\xff')
            cli('-d', 2, '--jfrsync', 'profile', '-f', '%{ASPROF_CLI_OUTPUT}/collision.jfr', target.pid)
            verify(collision, started)

            cli('start', '--jfrsync', 'profile', '-f', '%{ASPROF_CLI_OUTPUT}/active-%p.jfr', target.pid)
            time.sleep(1)
            missing_snapshot(target.pid)
            snapshot = target_root / f'snapshot-{target.pid}.jfr'
            cli('dump', '-f', '%{ASPROF_CLI_OUTPUT}/snapshot-%p.jfr', target.pid)
            verify(snapshot, started)
            before = hashlib.sha256(snapshot.read_bytes()).digest()
            time.sleep(1)  # A later snapshot holds more finalized data.
            cli('dump', '-f', '%{ASPROF_CLI_OUTPUT}/snapshot-%p.jfr', target.pid)
            assert hashlib.sha256(snapshot.read_bytes()).digest() != before, 'A repeated snapshot did not replace its output'
            verify(snapshot, started)
            assert not list(target_root.glob('asprof-snapshot-*')), 'A temporary snapshot remained'
            assert 'running' in cli('status', target.pid).stdout
            cli('dump', '-f', '%{ASPROF_CLI_OUTPUT}/folded-%p.collapsed', target.pid)
            folded = (target_root / f'folded-{target.pid}.collapsed').read_text(encoding='utf-8')
            assert 'Fixture.busy' in folded, folded
            assert sum(int(line.rsplit(' ', 1)[1]) for line in folded.splitlines()) >= 10
            stopped = target_root / f'stopped-{target.pid}.jfr'
            if args.stop_copy:
                cli('stop', '-f', '%{ASPROF_CLI_OUTPUT}/stopped-%p.jfr', target.pid)
            else:
                cli('stop', target.pid)
            verify(target_root / f'active-{target.pid}.jfr', started)
            if args.stop_copy:
                verify(stopped, started)
                original = target_root / f'active-{target.pid}.jfr'
                assert native_samples(stopped) == native_samples(original), \
                    'The stopped copy omitted final native samples'
                assert stopped.read_bytes() == original.read_bytes(), 'The stopped copy omitted final JVM or native data'

            # --loop starts asynchronously; the target finishes the ring at its native timeout.
            cli('--loop', 1, '--timeout', 4, '--jfrsync', 'profile', '-f', '%{ASPROF_CLI_OUTPUT}/ring-%n{2}.jfr', target.pid)
            time.sleep(5)
            assert 'not active' in cli('status', target.pid).stdout
            for index in range(2):
                verify(target_root / f'ring-{index}.jfr', started)
            existing = target_root / 'existing-1.jfr'
            existing.write_bytes(b'replace-later-ring-slot\x00\xff')
            cli('--loop', 1, '--timeout', 3, '--jfrsync', 'profile', '-f', '%{ASPROF_CLI_OUTPUT}/existing-%n{2}.jfr', target.pid)
            time.sleep(4)
            assert 'not active' in cli('status', target.pid).stdout
            for index in range(2):
                verify(target_root / f'existing-{index}.jfr', started)
            assert not list(target_root.rglob('*%*')), 'A literal template path was created'
            assert target.poll() is None
            launched = cli('launch', '--java', java, '-d', 3, '--jfrsync', 'profile', '-f', 'launch-%p.jfr',
                           '--', '-cp', classes, 'Fixture', '5')
            child_pid = re.search(r'Launched PID (\d+)', launched.stderr)
            assert child_pid, launched.stderr
            verify(work / f'launch-{child_pid[1]}.jfr', started)
            print('CLI_TEMPLATES_OK', flush=True)
        finally:
            target.terminate()
            target.wait(timeout=10)
    print((work / 'target.err').read_text(encoding='utf-8', errors='replace'), flush=True)
    if args.stop_copy:
        subprocess.run([str(java), '-cp', str(classes) + ';' + str(args.jar), 'StopCopySmoke', str(args.agent), str(work)],
                       cwd=work, check=True, timeout=30)


if __name__ == '__main__':
    main()
