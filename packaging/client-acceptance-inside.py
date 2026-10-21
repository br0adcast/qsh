"""Internal installed-client bootstrap; only the namespace owner invokes run().

Import is not containment proof. The public outer entry establishes the exact
owned Docker namespace before installation or artifact execution can start.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import stat
import subprocess
import sys
import tarfile
import tempfile

MAX_BINARY = 67108864


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def checked(command):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=30, check=True)
    if len(result.stdout) + len(result.stderr) > 131072:
        raise ValueError('package tool output exceeded limit')
    return result.stdout.decode('utf8').strip()


def file_digest(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BINARY:
        raise ValueError('client payload must be a bounded regular file')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def equal_payloads(*paths):
    values = [file_digest(path) for path in paths]
    if len(set(values)) != 1:
        raise ValueError('package/archive/installed client payload differs')
    return values[0]


def archive_inputs(archive, directory, version, target, guard):
    # Do not extract arbitrary paths, links or archive ownership. The existing
    # canonical guard validates the complete archive before installation.
    root = 'qsh-' + version + '-' + target
    with tarfile.open(str(archive), 'r:gz') as source:
        for program in ('qsh', 'qshd'):
            member = source.getmember(root + '/' + program)
            if not member.isfile() or not 0 < member.size <= MAX_BINARY:
                raise ValueError('invalid archive program payload')
            with source.extractfile(member) as stream, (directory / program).open('wb') as output:
                remaining = member.size
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise ValueError('truncated archive program')
                    output.write(chunk)
                    remaining -= len(chunk)
            (directory / program).chmod(0o755)
    guard.check_archive(archive, directory, version, target)


def extract_package(package, fmt, directory):
    if fmt == 'deb':
        checked(['dpkg-deb', '-x', str(package), str(directory)])
        return
    producer = subprocess.Popen(['rpm2cpio', str(package)], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
    try:
        subprocess.run(['cpio', '-idm', '--quiet', '--no-absolute-filenames'],
                       cwd=str(directory), stdin=producer.stdout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                       timeout=30, check=True)
        if producer.wait(timeout=30) != 0:
            raise ValueError('RPM payload extraction failed')
    finally:
        producer.stdout.close()
        if producer.poll() is None:
            producer.kill()
        producer.wait()


def installed_identity(fmt, guard, package, version, arch):
    if fmt == 'deb':
        fields = checked(['dpkg-query', '-W', '-f=${Package}\\n${Version}\\n${Architecture}\\n', 'qsh']).splitlines()
        owner = checked(['dpkg-query', '-S', '/usr/bin/qsh'])
        if owner != 'qsh: /usr/bin/qsh':
            raise ValueError('installed client is not owned by qsh package')
    else:
        fields = checked(['rpm', '-qf', '/usr/bin/qsh', '--qf', '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n']).splitlines()
    guard.check_fields(fmt, fields, package.name, 'qsh', version, arch)


def drop_privileges(nobody):
    os.setgroups([])
    os.setgid(nobody.pw_gid)
    os.setuid(nobody.pw_uid)
    if os.geteuid() != nobody.pw_uid or os.getegid() != nobody.pw_gid or os.getgroups():
        raise ValueError('runtime privilege drop did not commit')


def run(package, archive, version, target, floor):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('installed bootstrap requires the owned Linux root namespace')
    targets = {'x86_64-unknown-linux-musl': ('x86_64', 'amd64'),
               'aarch64-unknown-linux-musl': ('aarch64', 'arm64')}
    machine, deb_arch = targets[target]
    if platform.machine() != machine:
        raise ValueError('installed runtime architecture differs from selected target')
    libc = checked(['getconf', 'GNU_LIBC_VERSION'])
    if libc != 'glibc ' + floor:
        raise ValueError('installed runtime does not match the declared glibc floor')
    package, archive = Path(package), Path(archive)
    fmt = package.suffix[1:]
    if fmt not in ('deb', 'rpm'):
        raise ValueError('unsupported client package format')
    guard = module('release_output', 'check-release-output.py')
    helper = module('artifact_smoke', 'client-artifact-smoke.py')
    arch = deb_arch if fmt == 'deb' else machine
    guard.check_package(package, fmt, 'qsh', version, arch)
    nobody = pwd.getpwnam('nobody')
    if nobody.pw_uid == 0 or nobody.pw_gid == 0:
        raise ValueError('existing runtime account must be unprivileged')
    # Root-owned validation storage remains until the exact namespace stops.
    # After permanent privilege drop it cannot be recursively unlinked here.
    root = Path(tempfile.mkdtemp(prefix='qsh-installed-acceptance-'))
    inputs, payload = root / 'archive', root / 'payload'
    inputs.mkdir()
    payload.mkdir()
    archive_inputs(archive, inputs, version, target, guard)
    extract_package(package, fmt, payload)
    source = payload / 'usr/bin/qsh'
    # Admission before the installation effect: package cannot silently
    # contain a different client from its matching archive producer.
    expected = equal_payloads(source, inputs / 'qsh')
    if fmt == 'deb':
        checked(['dpkg', '-i', str(package)])
    else:
        checked(['dnf', '-y', '--disablerepo=*', 'install', str(package)])
    installed = Path('/usr/bin/qsh')
    installed_identity(fmt, guard, package, version, arch)
    equal_payloads(source, inputs / 'qsh', installed)
    root.chmod(0o755)
    inputs.chmod(0o755)
    payload.chmod(0o755)
    # No host account or PAM changes: use the image's existing account and
    # permanently drop all supplementary groups before entering the PTY.
    drop_privileges(nobody)
    result = helper.smoke(str(installed), str(inputs / 'qshd'), version)
    installed_identity(fmt, guard, package, version, arch)
    if equal_payloads(source, inputs / 'qsh', installed) != expected:
        raise ValueError('client payload changed during installed smoke')
    print(json.dumps({'installed_client': str(installed), 'sha256': expected,
                      'package': package.name, 'uid': os.geteuid(),
                      'python': platform.python_version(), 'glibc': libc,
                      'runtime': result}, sort_keys=True), flush=True)
    return result


def run_archive(archive, version, target, floor):
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('archive bootstrap requires the owned Linux root namespace')
    machine = {'x86_64-unknown-linux-musl': 'x86_64',
               'aarch64-unknown-linux-musl': 'aarch64'}[target]
    if platform.machine() != machine:
        raise ValueError('archive runtime architecture differs from selected target')
    libc = checked(['getconf', 'GNU_LIBC_VERSION'])
    if libc != 'glibc ' + floor:
        raise ValueError('archive runtime does not match the declared floor')
    guard = module('release_output', 'check-release-output.py')
    helper = module('artifact_smoke', 'client-artifact-smoke.py')
    nobody = pwd.getpwnam('nobody')
    if nobody.pw_uid == 0 or nobody.pw_gid == 0:
        raise ValueError('existing runtime account must be unprivileged')
    # Exact namespace owns storage after irreversible privilege drop.
    inputs = Path(tempfile.mkdtemp(prefix='qsh-archive-acceptance-'))
    archive_inputs(Path(archive), inputs, version, target, guard)
    before = {name: file_digest(inputs / name) for name in ('qsh', 'qshd')}
    inputs.chmod(0o755)
    drop_privileges(nobody)
    result = helper.smoke(str(inputs / 'qsh'), str(inputs / 'qshd'), version)
    if before != {name: file_digest(inputs / name) for name in before}:
        raise ValueError('archive programs changed during smoke')
    print(json.dumps({'archive': Path(archive).name, 'sha256': before,
                      'uid': os.geteuid(), 'python': platform.python_version(),
                      'glibc': libc, 'runtime': result}, sort_keys=True), flush=True)
    return result


if __name__ == '__main__':
    sys.exit('internal bootstrap; use packaging/client-acceptance.py')
