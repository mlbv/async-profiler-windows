# Copyright 2026 movblock
# SPDX-License-Identifier: Apache-2.0
"""Check frame-naming (simple, norm, sig, ann, lib, dot), filtering (include, exclude), grouping (threads, sched) and
HTML rendering (title, minwidth, reverse, inverted, tree) options on a real Windows CPU recording."""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile


def rows(path):
    result = [line.rsplit(' ', 1) for line in path.read_text(encoding='utf-8').splitlines() if line]
    assert result and all(int(value) > 0 for _, value in result), path
    return result


def frames(stacks):
    return {frame for stack, _ in stacks for frame in stack.split(';')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--agent', type=Path, default=Path(__file__).resolve().parents[1] / 'build/asyncProfiler.dll')
    parser.add_argument('--work-directory', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    jar = root / 'build/asprof-windows.jar'
    work = (args.work_directory or Path(tempfile.mkdtemp(prefix='asprof-output-options-'))).resolve()
    work.mkdir(parents=True, exist_ok=True)
    classes = work / 'classes'
    subprocess.run([str(args.java_home / 'bin/javac.exe'), '--release', '17', '-cp', str(jar), '-d', str(classes),
                    str(root / 'tests/OutputOptions.java')], check=True)
    result = subprocess.run([str(args.java_home / 'bin/java.exe'), '-cp', f'{classes};{jar}', 'opt.sample.OutputOptions',
                             str(args.agent.resolve()), str(work)], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0 and 'OUTPUT_OPTIONS_WRITTEN' in result.stdout, (result.stdout, result.stderr)

    plain = rows(work / 'plain.collapsed')
    names = frames(plain)
    assert 'opt/sample/OutputOptions.burn' in names, sorted(names)[:50]
    lambdas = [name for name in names if '$$Lambda' in name]
    # JDK 17 names hidden lambda classes $$Lambda$N/0x...; later JDKs omit the sequence number.
    hidden = re.compile(r'\$\$Lambda(\$\d+)?[./]0x')
    assert lambdas and any(hidden.search(name) for name in lambdas), lambdas
    simple = frames(rows(work / 'simple.collapsed'))
    assert 'OutputOptions.burn' in simple and not any(name.startswith('opt/sample/') for name in simple), sorted(simple)[:50]
    dotted = frames(rows(work / 'dot.collapsed'))
    assert 'opt.sample.OutputOptions.burn' in dotted and not any('opt/sample/' in name for name in dotted), sorted(dotted)[:50]
    normalized = frames(rows(work / 'norm.collapsed'))
    assert any(re.search(r'\$\$Lambda(\$\d+)?\.run$', name) for name in normalized), sorted(name for name in normalized if 'Lambda' in name)
    assert not any(hidden.search(name) for name in normalized), normalized
    signatures = frames(rows(work / 'sig.collapsed'))
    assert 'opt/sample/OutputOptions.burn(ILjava/lang/String|)J' in signatures, sorted(name for name in signatures if 'burn' in name)
    annotated = frames(rows(work / 'ann.collapsed'))
    assert 'opt/sample/OutputOptions.burn_[j]' in annotated, sorted(name for name in annotated if 'burn' in name)
    libraries = frames(rows(work / 'lib.collapsed'))
    native = sorted(name for name in libraries if '`' in name)
    assert any(name.startswith('zip.dll`') for name in native), native[:20]
    included, excluded = rows(work / 'include.collapsed'), (work / 'exclude.collapsed').read_text(encoding='utf-8')
    assert all('burn' in stack for stack, _ in included) and 'burn' not in excluded, excluded[:2000]
    threads = rows(work / 'threads.collapsed')
    assert any(re.match(r'\[options-worker tid=\d+\];', stack) for stack, _ in threads), [stack[:80] for stack, _ in threads][:10]
    sched = rows(work / 'sched.collapsed')
    assert all(stack.startswith('[NORMAL];') for stack, _ in sched if 'burn' in stack), [stack[:60] for stack, _ in sched][:10]

    default, titled = (work / 'default.html').read_text(encoding='utf-8'), (work / 'titled.html').read_text(encoding='utf-8')
    assert '<h1>Options Graph</h1>' in titled and '<h1>CPU profile</h1>' in default
    # minwidth=2 omits frames below 2% of the total.
    count = lambda html: len(re.findall(r'\n[fnu]\(', html))
    assert 0 < count(titled) < count(default), (count(titled), count(default))
    assert 'let inverted = false;' in default and 'let inverted = true;' in (work / 'inverted.html').read_text(encoding='utf-8')
    reverse = (work / 'reverse.html').read_text(encoding='utf-8')
    assert 'let inverted = true;' in reverse, 'Reversed stacks render as an icicle'
    tree = (work / 'tree.html').read_text(encoding='utf-8')
    assert 'Call tree' in tree and 'OutputOptions.burn' in tree
    traces, flat = (work / 'traces.txt').read_text(encoding='utf-8'), (work / 'flat.txt').read_text(encoding='utf-8')
    assert 'OutputOptions.burn' in traces and 'OutputOptions.burn' in flat, (traces[:1000], flat[:1000])
    version = subprocess.run([str(args.java_home / 'bin/java.exe'), '-version'], capture_output=True, text=True).stderr.splitlines()[0]
    print(f'OUTPUT_OPTIONS_OK frames={len(names)} lambdas={len(lambdas)} jvm="{version}"', flush=True)


if __name__ == '__main__':
    main()
