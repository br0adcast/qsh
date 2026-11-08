#!/usr/bin/env python3
"""Focused protocol-2 release gate against the reviewed, unchanged v0.5.0 pair.

The committed archive digest is the trust anchor, not a downloaded manifest.
CLI rejection proves zero shell starts; the transport-ensure negative additionally
checks zero connections on the old daemon. Neither proves absence of every
internal transient side effect. A future protocol boundary needs explicit tests.
"""
import argparse
import hashlib
import os
import platform
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

PREFIX = 'qsh-0.5.0-x86_64-unknown-linux-musl'
URL = 'https://github.com/br0adcast/qsh/releases/download/v0.5.0/' + PREFIX + '.tar.gz'
SHA256 = '2ef2a26a955797a414030ca55b742c3da826805c423523921d08917ed3869d62'
ARCHIVE_SIZE = 6282319
# Explicitly bounded even for a corrupt local input. The pinned digest also
# authenticates all uncompressed member sizes before any data is written.
MAX_ARCHIVE_SIZE = 8 * 1024 * 1024
MAX_MEMBER_SIZE = 32 * 1024 * 1024
MANIFEST_SHA256 = 'fb5b751b3830bbc2aeb6c3d0cde2e23b8b0b9eb26703df2699be8cc1e9930b96'
MANIFEST_SIZE = 1140
DARWIN_FIXTURES = {
    'arm64': ('aarch64-apple-darwin', 'db31e4a123459a9fd8151585301f7e0142c340cd1d9473a8e86d1f5be3f072cb', 5433857),
    'x86_64': ('x86_64-apple-darwin', '38b40b631ebd0a4fce856c7763cf4793c55e625cb404e2a93c4a3d391786d599', 5866506),
}


def fixture_for_host(system=None, machine=None):
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    if system == 'Linux' and machine == 'x86_64':
        return PREFIX, SHA256, ARCHIVE_SIZE
    if system == 'Darwin' and machine in DARWIN_FIXTURES:
        target, digest, size = DARWIN_FIXTURES[machine]
        return 'qsh-0.5.0-' + target, digest, size
    raise ValueError('no pinned released-peer fixture for this platform')


def verify_published_manifest(data, prefix, digest):
    if len(data) != MANIFEST_SIZE or hashlib.sha256(data).hexdigest() != MANIFEST_SHA256:
        raise ValueError('published checksum manifest mismatch')
    entries = [line.split() for line in data.decode('ascii').splitlines()]
    matches = [entry for entry in entries if len(entry) == 2 and entry[1] == prefix + '.tar.gz']
    if matches != [[digest, prefix + '.tar.gz']]:
        raise ValueError('published archive does not match pinned manifest entry')


CASES = (
    ('qsh', 'published_v050_pair_is_a_real_shell_start_positive_control', True),
    ('qsh', 'published_v050_client_cannot_mutate_protocol2_daemon', True),
    ('qsh', 'protocol2_client_cannot_mutate_published_v050_daemon', True),
    ('qsh', 'this_qsh_follows_a_flood_as_screen_repaints_with_the_header_under_aead', False),
    ('qsh', 'current_qsh_pastes_a_megabyte_into_current_daemon', False),
    ('qshd', 'protocol2_client_cannot_allocate_a_connection_on_published_v050', True),
    ('qsh', 'current_ensure_reports_busy_published_v050_without_interrupting_shell', True),
    ('qsh', 'published_v050_force_restarts_account_service_even_after_instance_change', True),
)


def download(destination, fixture=None):
    prefix, _, size = fixture or (PREFIX, SHA256, ARCHIVE_SIZE)
    url = URL.rsplit("/", 1)[0] + "/" + prefix + ".tar.gz"
    subprocess.run(['curl', '--fail', '--location', '--retry', '3',
                    '--connect-timeout', '20', '--max-time', '180',
                    '--max-filesize', str(MAX_ARCHIVE_SIZE),
                    url, '--output', str(destination)], check=True)
    if destination.stat().st_size != size:
        raise ValueError('published archive length mismatch')


def extract_pair(archive, destination, digest=SHA256, prefix=PREFIX):
    if archive.stat().st_size > MAX_ARCHIVE_SIZE:
        raise ValueError('archive exceeds size bound')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError('published archive checksum mismatch')
    expected = {prefix + '/' + name for name in
                ('qsh', 'qshd', 'README.md', 'LICENSE', 'CHANGELOG.md')}
    binaries = {prefix + '/qsh', prefix + '/qshd'}
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        seen = set()
        for member in members:
            name = member.name
            if name in seen:
                raise ValueError('duplicate archive member')
            seen.add(name)
            if name == prefix and member.isdir():
                continue
            if name not in expected or not member.isfile() or not 0 < member.size <= MAX_MEMBER_SIZE:
                raise ValueError('unexpected archive layout or member type/size')
        if not binaries <= seen:
            raise ValueError('archive is missing a peer executable')
        # No tar extraction API: write just authenticated regular binary bytes,
        # after validating every member, into a newly created private directory.
        destination.mkdir(mode=0o700)
        for name in ('qsh', 'qshd'):
            member = tar.getmember(prefix + '/' + name)
            with tar.extractfile(member) as source, (destination / name).open('xb') as output:
                output.write(source.read())
            (destination / name).chmod(0o700)
    return destination / 'qsh', destination / 'qshd'


def check_result(name, output, returncode):
    summaries = re.findall(r'^test result: (.*)$', output, re.MULTILINE)
    expected_summary = r'ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s'
    tests = re.findall(r'^test (\S+) \.\.\. (.*)$', output, re.MULTILINE)
    if (returncode != 0 or tests != [(name, 'ok')] or len(summaries) != 1
            or not re.fullmatch(expected_summary, summaries[0])
            or re.search(r'\bskip(?:ped|ping)?\b', output, re.IGNORECASE)):
        raise ValueError(f'{name}: expected exactly one actual pass, no skips, and exit zero')


def run_case(package, name, ignored, env, evidence):
    command = ['cargo', 'test', '--locked', '-p', package, '--test', 'mixed_versions',
               name, '--', '--exact', '--nocapture', '--test-threads=1', '--color=never']
    if ignored:
        command.append('--ignored')
    result = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    (evidence / (name + '.log')).write_text(result.stdout)
    print(result.stdout, end='', flush=True)
    check_result(name, result.stdout, result.returncode)
    print(f'ACCEPTED {package}::{name}: 1 passed; exit 0', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='already downloaded archive; still verified against the committed digest')
    parser.add_argument('--evidence', type=Path, required=True, help='new evidence directory outside the source tree')
    parser.add_argument('--service-only', action='store_true', help='run the two actual personal-service scenarios in an existing native lane')
    args = parser.parse_args()
    fixture = fixture_for_host()
    prefix, digest, _ = fixture
    fixture_url = URL.rsplit("/", 1)[0] + "/" + prefix + ".tar.gz"
    cases = CASES[-2:] if args.service_only else CASES
    source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    (args.evidence / 'identity.txt').write_text(f'source={source}\nfixture={fixture_url}\nsha256={digest}\n')
    print(f'Source: {source}\nFixture SHA-256: {digest}', flush=True)
    with tempfile.TemporaryDirectory(prefix='qsh-released-peer-') as runtime:
        root = Path(runtime)
        archive = args.archive
        if archive is None:
            archive = root / 'published.tar.gz'
            download(archive, fixture)
        if platform.system() == 'Darwin':
            manifest = root / 'SHA256SUMS'
            subprocess.run(['curl', '--fail', '--location', '--retry', '3',
                            '--connect-timeout', '20', '--max-time', '180', '--max-filesize', '4096',
                            URL.rsplit('/', 1)[0] + '/SHA256SUMS', '--output', str(manifest)], check=True)
            verify_published_manifest(manifest.read_bytes(), prefix, digest)
        old_qsh, old_qshd = extract_pair(archive, root / 'old', digest, prefix)
        env = os.environ.copy()
        env['CARGO_HOME'] = env.get('CARGO_HOME', str(Path.home() / '.cargo'))
        env['RUSTUP_HOME'] = env.get('RUSTUP_HOME', str(Path.home() / '.rustup'))
        for key, folder in (('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'), ('XDG_CACHE_HOME', 'cache')):
            (root / folder).mkdir(mode=0o700)
            env[key] = str(root / folder)
        env.update(HISTFILE='/dev/null', QSH_OLD_QSH=str(old_qsh), QSH_OLD_QSHD=str(old_qshd), CARGO_TERM_COLOR='never')
        env.pop('SSH_AUTH_SOCK', None)
        env.pop('SSH_AGENT_PID', None)
        # Build the pair together, even on a cache hit, before the CLI fixture
        # looks for its adjacent qshd. No old source or release mutation.
        subprocess.run(['cargo', 'build', '--locked', '-p', 'qsh', '-p', 'qshd', '--bins'], env=env, check=True)
        for case in cases:
            run_case(*case, env, args.evidence)
    (args.evidence / 'passed.txt').write_text(f'{len(cases)} selected tests; {len(cases)} passed; 0 skipped\n')


if __name__ == '__main__':
    main()
