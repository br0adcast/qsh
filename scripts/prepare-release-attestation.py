#!/usr/bin/env python3
"""Sign the release manifest once, or reuse its published signature.

The publish job runs three steps in order:

preflight  Checks the gates and the thirteen assembled files, then reads the
           tag, the release and both metadata assets through `gh api`,
           changing nothing. A published manifest must equal the local
           bytes. A published bundle is reused only if the native verifier
           accepts it for those bytes and this commit. Otherwise it writes
           the exact predicate and asks for one signature.
capture    Takes the one bundle `actions/attest` wrote and verifies it.
final      Rechecks the fourteen files and prints their paths for the
           uploader, the manifest last.

Python only moves bytes. Every bundle is authenticated by the release-auth
`verify-release` example built from this checkout; nothing here is a second
verifier. A bundle reaches the release directory only after that verifier
accepts it.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time

REPOSITORY = 'br0adcast/qsh'
MANIFEST = 'SHA256SUMS'
BUNDLE = 'SHA256SUMS.sigstore.json'
# The same bounds as release_auth::SUMS_LIMIT and BUNDLE_LIMIT.
LIMITS = {MANIFEST: 1024 * 1024, BUNDLE: 256 * 1024}
PREDICATE_TYPE = 'https://github.com/br0adcast/qsh/release-manifest/v1'
MANIFEST_FORMAT = 'qsh-sha256sums-v1'
# Published before release signing existed. Its tag and assets stay as they
# are: never sign it after the fact or add to it.
LEGACY_TAGS = frozenset({'v0.5.0'})
API_LIMIT = 4 * 1024 * 1024
PAGE_SIZE = 100
MAX_PAGES = 10
TIMEOUT = 120


class AttestationError(Exception):
    """A fixed diagnostic; never contains API bodies, bundle bytes or paths."""


def _sibling(name):
    spec = importlib.util.spec_from_file_location(
        name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_assembly = _sibling('assemble-release-assets')
_version = _sibling('check-release-version')


def products(version):
    return sorted(name for names in _assembly.expected_products(version).values()
                  for name in names)


def check_gates(repo, tag, version, commit):
    if repo != REPOSITORY:
        raise AttestationError('releases are signed only for ' + REPOSITORY)
    if not _version.valid_version(version) or tag != 'v' + version:
        raise AttestationError('release tag differs from the validated version')
    if not re.fullmatch(r'[0-9a-f]{40}', commit or ''):
        raise AttestationError('source commit must be 40 lowercase hex digits')
    if tag in LEGACY_TAGS:
        raise AttestationError(tag + ' was published unsigned and is never backfilled')


def run_bounded(argv, limit, what):
    """Runs `argv` and returns its status and at most `limit` bytes of output."""
    deadline = time.monotonic() + TIMEOUT
    chunks, size = [], 0
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
    except OSError:
        raise AttestationError(what + ' could not be started') from None
    with process:
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    left = deadline - time.monotonic()
                    if left <= 0 or not selector.select(left):
                        raise AttestationError(what + ' timed out')
                    chunk = os.read(process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise AttestationError(what + ' exceeded its size limit')
                    chunks.append(chunk)
            status = process.wait(max(deadline - time.monotonic(), 0.001))
        except subprocess.TimeoutExpired:
            process.kill()
            raise AttestationError(what + ' timed out') from None
        except BaseException:
            process.kill()
            raise
    return status, b''.join(chunks)


def api_get(endpoint):
    """Returns the decoded body, or None when GitHub answers 404 Not Found.

    Every other answer, and no answer at all, is a failure: an outage, a
    rejected token or a broken network is never taken for an absent asset.
    """
    what = 'GitHub API read'
    exit_status, output = run_bounded(['gh', 'api', '--include', '--method', 'GET', endpoint],
                                      API_LIMIT, what)
    # `--include` puts the status line and headers before the body, on
    # success and on HTTP errors alike.
    parts = re.split(rb'\r?\n\r?\n', output, maxsplit=1)
    status = re.match(rb'HTTP/[0-9.]+ ([0-9]{3})[ \r\n]', output)
    if len(parts) != 2 or status is None:
        raise AttestationError(what + ' failed without an HTTP answer')
    code = int(status.group(1))
    if code == 404:
        return None
    if code != 200:
        raise AttestationError(f'{what} failed with HTTP {code}')
    if exit_status:
        raise AttestationError(what + ' failed after an HTTP answer')
    try:
        return json.loads(parts[1])
    except ValueError:
        raise AttestationError(what + ' returned malformed JSON') from None


def api_list(endpoint):
    items = []
    for page in range(1, MAX_PAGES + 1):
        separator = '&' if '?' in endpoint else '?'
        data = api_get(f'{endpoint}{separator}per_page={PAGE_SIZE}&page={page}')
        if data is None:
            raise AttestationError('GitHub API listing was not found')
        if not isinstance(data, list):
            raise AttestationError('unexpected GitHub listing')
        items.extend(data)
        if len(data) < PAGE_SIZE:
            return items
    raise AttestationError('GitHub listing exceeds its page limit')


def tag_commit(repo, tag):
    ref = api_get(f'repos/{repo}/git/ref/tags/{tag}')
    if ref is None:
        raise AttestationError('release tag is absent')
    for _ in range(4):
        target = ref.get('object') if isinstance(ref, dict) else None
        if not isinstance(target, dict) or not isinstance(target.get('sha'), str):
            raise AttestationError('unexpected GitHub tag object')
        if target.get('type') == 'commit':
            return target['sha']
        if target.get('type') != 'tag':
            raise AttestationError('release tag does not name a commit')
        ref = api_get(f'repos/{repo}/git/tags/{target["sha"]}')
        if ref is None:
            raise AttestationError('annotated release tag object is absent')
    raise AttestationError('release tag nests too deeply')


def find_release(repo, tag):
    matches = []
    for release in api_list(f'repos/{repo}/releases'):
        if (not isinstance(release, dict) or type(release.get('id')) is not int
                or not isinstance(release.get('tag_name'), str)):
            raise AttestationError('unexpected GitHub release entry')
        if release['tag_name'] == tag:
            matches.append(release['id'])
    if len(matches) > 1:
        raise AttestationError('multiple releases for the requested tag')
    return matches[0] if matches else None


def metadata_assets(repo, release_id):
    """The published metadata assets by name, after checking every entry."""
    seen, found = set(), {}
    for asset in api_list(f'repos/{repo}/releases/{release_id}/assets'):
        if (not isinstance(asset, dict) or not isinstance(asset.get('name'), str)
                or type(asset.get('id')) is not int or type(asset.get('size')) is not int
                or not isinstance(asset.get('state'), str)
                or not isinstance(asset.get('content_type'), str)):
            raise AttestationError('unexpected GitHub asset entry')
        name = asset['name']
        if name in seen:
            raise AttestationError('duplicate published asset: ' + _safe(name))
        seen.add(name)
        if name in LIMITS:
            if asset['state'] != 'uploaded':
                raise AttestationError('incomplete published asset: ' + name)
            if not 0 < asset['size'] <= LIMITS[name]:
                raise AttestationError('published asset size is out of bounds: ' + name)
            found[name] = asset
    return found


def _safe(name):
    return name if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}', name) else '<unsafe name>'


def download(repo, asset):
    try:
        status, data = run_bounded(
            ['gh', 'api', '-H', 'Accept: application/octet-stream',
             f'repos/{repo}/releases/assets/{asset["id"]}'],
            asset['size'], 'GitHub asset download')
    except AttestationError:
        status, data = 1, b''
    if status or len(data) != asset['size']:
        raise AttestationError('published asset could not be read in full: ' + asset['name'])
    return data


def read_regular(path, limit):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise AttestationError('input must be a readable regular file') from None
    with os.fdopen(descriptor, 'rb') as source:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AttestationError('input must be a readable regular file')
        data = source.read(limit + 1)
    if len(data) > limit:
        raise AttestationError('input exceeds its size limit')
    return data


def write_new(path, data):
    try:
        with open(path, 'xb') as target:
            target.write(data)
    except OSError:
        raise AttestationError('output could not be created exclusively') from None


def check_release_files(dist, version, metadata):
    """Returns the manifest bytes after matching it to the products in `dist`."""
    names = products(version)
    expected = set(names) | set(metadata)
    try:
        present = {entry.name: entry for entry in os.scandir(dist)}
    except OSError:
        raise AttestationError('release directory is unreadable') from None
    if set(present) != expected:
        raise AttestationError(f'release directory must hold exactly {len(expected)} files')
    if not all(entry.is_file(follow_symlinks=False) for entry in present.values()):
        raise AttestationError('release files must be regular files')
    manifest = read_regular(Path(dist) / MANIFEST, LIMITS[MANIFEST])
    lines = []
    for name in names:
        digest = hashlib.sha256()
        try:
            with open(Path(dist) / name, 'rb') as product:
                for chunk in iter(lambda: product.read(1024 * 1024), b''):
                    digest.update(chunk)
        except OSError:
            raise AttestationError('release product is unreadable') from None
        lines.append(f'{digest.hexdigest()}  {name}\n')
    if manifest != ''.join(lines).encode('ascii'):
        raise AttestationError('manifest does not match the release products')
    return manifest


def verify(verifier, version, commit, manifest_path, bundle_path):
    status, output = run_bounded(
        [str(verifier), '--version', version, '--manifest', str(manifest_path),
         '--bundle', str(bundle_path), '--expected-source-commit', commit],
        4096, 'native release verifier')
    if status or output != f'verified release {version} source {commit}\n'.encode('ascii'):
        raise AttestationError('the native verifier rejected the bundle')


def predicate(version, commit):
    return json.dumps({'manifest_format': MANIFEST_FORMAT, 'version': version,
                       'tag': 'v' + version, 'source_commit': commit},
                      separators=(',', ':')).encode('ascii') + b'\n'


def new_work_directory(path):
    try:
        os.mkdir(path, 0o700)
    except OSError:
        raise AttestationError('work directory must not exist yet') from None
    return Path(path)


def adopt(work, dist, data, args):
    """Verifies `data` in the work directory, then copies it into `dist`."""
    candidate = work / ('candidate-' + BUNDLE)
    write_new(candidate, data)
    verify(args.verifier, args.version, args.source_commit, Path(args.dist) / MANIFEST, candidate)
    write_new(Path(dist) / BUNDLE, data)


def preflight(args):
    check_gates(args.repo, args.tag, args.version, args.source_commit)
    manifest = check_release_files(args.dist, args.version, [MANIFEST])
    work = new_work_directory(args.work)
    if tag_commit(args.repo, args.tag) != args.source_commit:
        raise AttestationError('release tag does not point at the source commit')
    release_id = find_release(args.repo, args.tag)
    published = {} if release_id is None else metadata_assets(args.repo, release_id)
    if MANIFEST in published and download(args.repo, published[MANIFEST]) != manifest:
        raise AttestationError('published manifest differs from the assembled one')
    outputs = {}
    if BUNDLE in published:
        adopt(work, args.dist, download(args.repo, published[BUNDLE]), args)
        print('Reusing the published bundle after native verification')
        outputs['sign'] = 'false'
    else:
        write_new(work / 'predicate.json', predicate(args.version, args.source_commit))
        print('No published bundle: signing ' + MANIFEST + ' once')
        outputs.update(sign='true', digest=hashlib.sha256(manifest).hexdigest(),
                       predicate=str(work / 'predicate.json'))
    with open(args.github_output, 'a', encoding='ascii') as output:
        output.write(''.join(f'{key}={value}\n' for key, value in outputs.items()))


def capture(args):
    check_gates(args.repo, args.tag, args.version, args.source_commit)
    check_release_files(args.dist, args.version, [MANIFEST])
    data = read_regular(args.bundle_path, LIMITS[BUNDLE])
    # actions/attest writes one JSON document and a newline. Anything else,
    # such as a second bundle appended, is not this signature.
    if data.count(b'\n') != 1 or not data.endswith(b'\n') or not data.startswith(b'{'):
        raise AttestationError('signing output must be exactly one bundle')
    adopt(Path(args.work), args.dist, data, args)
    print('Captured and verified the new bundle')


def final(args):
    check_gates(args.repo, args.tag, args.version, args.source_commit)
    check_release_files(args.dist, args.version, [MANIFEST, BUNDLE])
    dist = Path(args.dist)
    verify(args.verifier, args.version, args.source_commit, dist / MANIFEST, dist / BUNDLE)
    # The manifest goes last: a reader that finds it also finds its bundle.
    for name in products(args.version) + [BUNDLE, MANIFEST]:
        print(dist / name)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    for name, function in (('preflight', preflight), ('capture', capture), ('final', final)):
        command = commands.add_parser(name)
        command.set_defaults(function=function)
        command.add_argument('--repo', required=True)
        command.add_argument('--tag', required=True)
        command.add_argument('--version', required=True)
        command.add_argument('--source-commit', required=True)
        command.add_argument('--dist', required=True)
        command.add_argument('--verifier', required=True)
        if name != 'final':
            command.add_argument('--work', required=True)
        if name == 'preflight':
            command.add_argument('--github-output', required=True)
        if name == 'capture':
            command.add_argument('--bundle-path', required=True)
    args = parser.parse_args()
    try:
        args.function(args)
    except AttestationError as error:
        print('release attestation: ' + str(error), file=sys.stderr)
        return 1
    except _assembly.AssemblyError:
        print('release attestation: invalid release version', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
