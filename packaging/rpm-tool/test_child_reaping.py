"""Linux native-generator child custody checks; no package installation."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def enable_subreaper():
    if sys.platform != 'linux':
        raise RuntimeError('child custody qualification requires Linux')
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
    actual = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(actual), 0, 0, 0) != 0 or actual.value != 1:
        raise RuntimeError('subreaper state not established')


def collect_owned_children(end):
    """Natural waits in an isolated worker; adoption always remains a failure."""
    adopted, waits = set(), []
    while True:
        children = [int(pid) for pid in Path(
            '/proc/self/task/{}/children'.format(os.getpid())).read_text().split()]
        adopted.update(children)
        if not children:
            return dict(adopted=sorted(adopted), waits=waits, emergency_cleanup=False)
        for pid in children:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                waits.append(dict(pid=waited, status=status))
        if time.monotonic() >= end:
            raise TimeoutError('owned children did not settle naturally')
        time.sleep(0.01)


def require_no_adoption(observation):
    if observation['adopted']:
        raise AssertionError('generator left adopted children: {}'.format(observation['adopted']))


def worker(tool, case, end):
    enable_subreaper()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16777216, 16777216))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    report = dict(case=case, passed=False, emergency_cleanup=False)
    with tempfile.TemporaryDirectory(prefix='rpm-child-custody-') as directory:
        root = Path(directory)
        for name in ('home', 'config', 'cache', 'tmp', 'bin'):
            (root / name).mkdir(mode=0o700)
        pidfile = root / 'ldd.pid'
        real_ldd = Path(shutil.which('ldd', path='/usr/bin:/bin') or '/missing').resolve(strict=True)
        python = Path(sys.executable).resolve(strict=True)
        script = ('#!' + str(python) + '\nimport os,sys\n'
                  + 'fd=os.open(' + repr(str(pidfile)) + ',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n'
                  + 'os.write(fd,str(os.getpid()).encode());os.close(fd)\n')
        if case == 'real-ldd':
            script += 'os.execv(' + repr(str(real_ldd)) + ',["ldd",*sys.argv[1:]])\n'
        elif case == 'invalid-utf8':
            script += 'os.write(1,b"\\xff");sys.exit(0)\n'
        elif case == 'nonzero-output':
            script += 'os.write(1,b"libfixture.so.1 => /fixture/libfixture.so.1 (0x0)\\n");sys.exit(7)\n'
        else:
            raise ValueError('fixed child case required')
        wrapper = root / 'bin/ldd'; wrapper.write_text(script); wrapper.chmod(0o700)
        if python.stat().st_size > 16777216:
            raise ValueError('native Python ELF fixture size bound')
        payload = python.read_bytes()
        if payload[:4] != b'\x7fELF':
            raise ValueError('native Python ELF fixture required')
        (root / 'payload').write_bytes(payload); (root / 'payload').chmod(0o700)
        (root / 'Cargo.toml').write_text(
            '[package]\nname="child-custody-test"\nversion="1.0.0"\nlicense="MIT"\n'
            'description="inert child custody fixture"\n[package.metadata.generate-rpm]\n'
            'assets=[{source="payload",dest="/usr/bin/child-custody-fixture",mode="755"}]\n')
        environment = dict(PATH=str(root / 'bin') + ':/usr/bin:/bin', LANG='C', LC_ALL='C',
                           HOME=str(root / 'home'), XDG_CONFIG_HOME=str(root / 'config'),
                           XDG_CACHE_HOME=str(root / 'cache'), TMPDIR=str(root / 'tmp'), HISTFILE='/dev/null')
        process = None
        try:
            with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                process = subprocess.Popen([tool, '--auto-req', 'builtin', '--output', str(root / 'test.rpm')],
                                           cwd=root, env=environment, stdin=subprocess.DEVNULL,
                                           stdout=out, stderr=err)
                status = process.wait(timeout=max(0.001, end - time.monotonic()))
                err.seek(0); stderr = err.read(4096)
                report.update(generator_exit=status, generator_stderr=stderr.decode('utf-8', 'replace'))
            if not pidfile.exists():
                raise AssertionError('ldd fixture was not invoked')
            report['ldd_pid'] = int(pidfile.read_text())
            report['observation'] = collect_owned_children(end)
            require_no_adoption(report['observation'])
            if case == 'invalid-utf8':
                if status == 0 or b'Failed to read output stream from command `ldd`' not in stderr:
                    raise AssertionError('invalid UTF-8 must retain ldd read-error category')
            elif status != 0 or not (root / 'test.rpm').is_file():
                raise AssertionError('valid output must preserve generator status policy')
            report['passed'] = True
        except BaseException as error:
            report['failure'] = type(error).__name__ + ': ' + str(error)
            if process is not None and process.poll() is None:
                report['emergency_cleanup'] = True
                process.terminate()
                try:
                    process.wait(timeout=max(0.001, end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
        finally:
            try:
                final = collect_owned_children(end)
                if 'observation' not in report:
                    report['observation'] = final
                elif final['adopted']:
                    report['observation']['adopted'] += final['adopted']
                    report['observation']['waits'] += final['waits']
                if final['adopted']:
                    report['passed'] = False
            except BaseException as error:
                report.update(passed=False, emergency_cleanup=True, settlement_failure=type(error).__name__)
        if time.monotonic() >= end:
            report.update(passed=False, deadline_exhausted=True)
    return report


def run_case(tool, case, end):
    """The separate worker owns observation and natural collection of defects."""
    argv = [sys.executable, '-B', str(Path(__file__).resolve()), '--worker', tool, case, str(end)]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=max(0.001, end - time.monotonic()))
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise TimeoutError('child custody worker deadline')
    if process.returncode != 0 or len(stdout) > 65536 or stderr:
        raise RuntimeError('child custody worker failed')
    return json.loads(stdout)


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--worker':
        # Internal fixed worker invocation; public CLI has only one tool operand.
        end = float(sys.argv[4])
        if not time.monotonic() < end <= time.monotonic() + 65:
            raise ValueError('worker original end')
        print(json.dumps(worker(sys.argv[2], sys.argv[3], end)))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', type=Path)
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('child custody qualification requires Linux')
    if not args.tool.is_absolute() or not args.tool.is_file() or not os.access(args.tool, os.X_OK):
        parser.error('tool must be an existing absolute executable')
    end = time.monotonic() + 60
    passed = True
    for case in ('real-ldd', 'invalid-utf8', 'nonzero-output'):
        report = run_case(str(args.tool), case, end)
        print(json.dumps(report, sort_keys=True))
        if not report['passed'] and report.get('generator_stderr'):
            print(report['generator_stderr'], file=sys.stderr)
        passed = report['passed'] and not report['emergency_cleanup'] and passed
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
