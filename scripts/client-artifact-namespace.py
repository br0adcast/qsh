#!/usr/bin/env python3
"""Exact CID ownership for the fixed Linux artifact acceptance entries.

Internal implementation; callers select controls, archive, or installed-client acceptance,
never an arbitrary container command. Creation precedes all runtime effects.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

LIMIT = 131072
INSTALLED_BOOTSTRAP = r"""
import importlib.util,sys
s=importlib.util.spec_from_file_location('installed_acceptance','/work/scripts/client-acceptance-inside.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
if sys.argv[1]=='archive':
 m.run_archive(*sys.argv[2:])
else:
 m.run(*sys.argv[2:])
"""
BOOTSTRAP = r"""
import importlib.util,os,sys,unittest
print('ARTIFACT_PYTHON '+sys.version.split()[0],flush=True)
spec=importlib.util.spec_from_file_location('contained_runtime','/work/scripts/tests/client_artifact_smoke_runtime.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if os.environ['QSH_SMOKE_CASE']=='held-unregistered':
 module.held_unregistered()
else:
 result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(module.ArtifactSmoke))
 sys.exit(0 if result.wasSuccessful() else 1)
"""


def docker(*args):
    result = subprocess.run(['docker'] + list(args), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30)
    if len(result.stdout) + len(result.stderr) > LIMIT:
        raise RuntimeError('Docker control output exceeded limit')
    if result.returncode:
        raise RuntimeError('Docker control failed: {} {}'.format(args[0], result.stderr[-2048:].decode('utf8', 'replace')))
    return result.stdout.decode('utf8').strip()


def _qualify(paths, image, case, interpreter, acceptance=None):
    if interpreter not in ('/usr/bin/python3', '/usr/libexec/platform-python'):
        raise ValueError('unsupported test interpreter')
    if acceptance is None and case not in ('normal', 'held-unregistered'):
        raise ValueError('unsupported owned runtime case')
    source = Path(__file__).resolve().parent
    paths = [Path(path).resolve() for path in paths]
    for path in paths:
        if not path.is_file():
            raise ValueError('explicit artifact must be a regular file')
    receipt = {'entry': acceptance['mode'] if acceptance is not None else 'controls',
               'image': image, 'artifacts': [hashlib.sha256(p.read_bytes()).hexdigest() for p in paths],
               'namespace_stopped': False, 'removed': False}
    cid = None
    attach = None
    failure = None
    captured = bytearray()
    with tempfile.TemporaryDirectory(prefix='qsh-artifact-namespace-') as tmp:
        root = Path(tmp)
        root.chmod(0o755)
        stage = root / 'scripts'
        (stage / 'tests').mkdir(parents=True)
        for name in ('client-artifact-smoke.py', 'check-release-output.py', 'check-release-version.py'):
            shutil.copyfile(str(source / name), str(stage / name))
        shutil.copyfile(str(source / 'tests' / 'client_artifact_smoke_runtime.py'),
                        str(stage / 'tests' / 'client_artifact_smoke_runtime.py'))
        command = [interpreter, '-c', BOOTSTRAP]
        mounts = ([str(paths[0]) + ':/artifacts/qsh:ro',
                   str(paths[1]) + ':/artifacts/qshd:ro'] if acceptance is None else [])
        user = '65534:65534'
        if acceptance is not None:
            shutil.copyfile(str(source.parent / 'packaging' / 'client-acceptance-inside.py'),
                            str(stage / 'client-acceptance-inside.py'))
            mounts = [str(path) + ':/artifacts/' + path.name + ':ro' for path in paths]
            user = '0:0'
            command = [interpreter, '-c', INSTALLED_BOOTSTRAP, acceptance['mode']]
            command += ['/artifacts/' + path.name for path in paths]
            command += [acceptance['version'], acceptance['target'], acceptance['floor']]
        cidfile = root / 'cid'
        try:
            # CID is captured before any fixed entry starts. Controls run
            # unprivileged; installed bootstrap verifies then permanently drops
            # to the pre-existing nobody account. No host account mutation.
            created = docker('create', '--cidfile', str(cidfile), '--init',
                             '--network', 'none', '--pids-limit', '128',
                             '--memory', '512m', '--user', user,
                             '--name', 'qsh-artifact-' + uuid.uuid4().hex,
                             '-v', str(stage) + ':/work/scripts:ro',
                             *[arg for mount in mounts for arg in ('-v', mount)],
                             '-e', 'PYTHONDONTWRITEBYTECODE=1',
                             '-e', 'QSH_SMOKE_CLIENT=/artifacts/qsh',
                             '-e', 'QSH_SMOKE_DAEMON=/artifacts/qshd',
                             '-e', 'USER=nobody', '-e', 'QSH_SMOKE_CASE=' + case, image,
                             *command)
            cid = cidfile.read_text().strip()
            if not re.fullmatch('[0-9a-f]{64}', cid) or cid != created:
                raise RuntimeError('Docker create identity mismatch')
            receipt['cid'] = cid
            attach = subprocess.Popen(['docker', 'start', '-a', cid],
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            os.set_blocking(attach.stdout.fileno(), False)
            deadline = time.monotonic() + 120
            while True:
                if time.monotonic() >= deadline:
                    raise RuntimeError('owned artifact namespace watchdog expired')
                ready, _, _ = select.select([attach.stdout], [], [], 0.05)
                if ready:
                    chunk = os.read(attach.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    if len(captured) + len(chunk) > LIMIT:
                        raise RuntimeError('owned artifact namespace output exceeded limit')
                    captured.extend(chunk)
                    if (case == 'held-unregistered'
                            and not receipt.get('positive_unregistered_hold')
                            and b'ARTIFACT_UNREGISTERED_LEAF_HELD\n' in captured):
                        receipt['positive_unregistered_hold'] = True
                        # Same watchdog loop, actual expiry after a real fence.
                        deadline = time.monotonic() + 0.2
            attach_status = attach.wait(timeout=max(0.1, deadline - time.monotonic()))
            receipt['attach_status'] = attach_status
            receipt['wait_status'] = int(docker('wait', cid))
            if attach_status != 0 or receipt['wait_status'] != 0:
                raise RuntimeError('artifact runtime controls failed inside owned namespace')
        except BaseException as error:
            failure = error
        finally:
            if cid is None and cidfile.exists():
                candidate = cidfile.read_text().strip()
                if re.fullmatch('[0-9a-f]{64}', candidate):
                    cid = candidate
                    receipt['cid'] = cid
            try:
                if cid is not None:
                    state = json.loads(docker('inspect', '--format', '{{json .State}}', cid))
                    if state['Running']:
                        docker('kill', cid)
                    receipt['final_wait_status'] = int(docker('wait', cid))
                    state = json.loads(docker('inspect', '--format', '{{json .State}}', cid))
                    if state['Running'] or state['Pid'] != 0:
                        raise RuntimeError('owned namespace did not actually stop')
                    receipt['namespace_stopped'] = True
                    docker('rm', cid)
                    receipt['removed'] = True
            except BaseException as error:
                # Preserve exact CID and failure; Docker failure cannot certify
                # containment or be hidden by temporary cidfile destruction.
                receipt['cleanup_error'] = str(error)
                failure = error
            finally:
                if attach is not None:
                    try:
                        attach.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        attach.kill()
                        attach.wait()
                        if failure is None:
                            failure = RuntimeError('Docker attach failed to finish')
                    attach.stdout.close()
    sys.stdout.write(captured.decode('utf8', 'replace'))
    print(json.dumps(receipt, sort_keys=True), flush=True)
    if failure is not None:
        raise failure
    return receipt



def run_controls(client, daemon, image, case='normal', interpreter='/usr/bin/python3'):
    return _qualify([client, daemon], image, case, interpreter)


def run_installed(package, archive, version, target, floor, image):
    return _qualify([package, archive], image, 'normal', '/usr/bin/python3',
                    {'mode': 'installed', 'version': version, 'target': target, 'floor': floor})


def run_archive(archive, version, target, floor, image):
    return _qualify([archive], image, 'normal', '/usr/bin/python3',
                    {'mode': 'archive', 'version': version, 'target': target, 'floor': floor})


if __name__ == '__main__':
    sys.exit('internal namespace owner; use the fixed controls or package entry')
