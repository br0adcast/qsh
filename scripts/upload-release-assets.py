#!/usr/bin/env python3
"""Publish missing release assets, accepting retries only for identical bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


class UploadError(Exception):
    pass


def gh(*args, output=None):
    # Avoid reflecting API response bodies, credentials, or asset bytes in logs.
    result = subprocess.run(['gh', *args], stdout=output or subprocess.PIPE,
                            stderr=subprocess.PIPE)
    if result.returncode:
        raise UploadError('GitHub command failed: ' + ' '.join(args[:2]))
    return result.stdout


def pages(endpoint):
    data = json.loads(gh('api', '--paginate', '--slurp', endpoint))
    if not isinstance(data, list) or any(not isinstance(page, list) for page in data):
        raise UploadError('Unexpected GitHub pagination response')
    return [item for page in data for item in page]


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').digest()


def publish(args):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repo):
        raise UploadError('Invalid repository')
    if not args.tag or args.tag.startswith('-'):
        raise UploadError('Invalid tag')
    names = set()
    paths = [Path(value) for value in args.assets]
    for path in paths:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]*', path.name):
            raise UploadError('Unsafe asset name: ' + path.name)
        if path.name in names:
            raise UploadError('Duplicate asset name: ' + path.name)
        if not path.is_file() or path.is_symlink():
            raise UploadError('Asset must be a regular file: ' + path.name)
        names.add(path.name)
    with tempfile.TemporaryDirectory(prefix='release-upload-') as directory:
        snapshots = []
        for path in paths:
            snapshot = Path(directory) / path.name
            shutil.copyfile(path, snapshot)
            snapshots.append(snapshot)
        endpoint = f'repos/{args.repo}/releases'
        releases = pages(endpoint)
        matches = [release for release in releases if release['tag_name'] == args.tag]
        if len(matches) > 1:
            raise UploadError('Multiple releases for the requested tag')
        if not matches:
            command = ['release', 'create', args.tag, '--repo', args.repo,
                       '--verify-tag', '--title', 'qsh ' + args.tag.removeprefix('v'),
                       '--notes-file', args.notes_file]
            if '-' in args.tag:
                command.append('--prerelease')
            gh(*command)
            matches = [release for release in pages(endpoint)
                       if release['tag_name'] == args.tag]
            if len(matches) != 1:
                raise UploadError('Created release could not be read back')
        release_id = int(matches[0]['id'])
        assets = pages(f'{endpoint}/{release_id}/assets')
        remote = {}
        for asset in assets:
            name = asset['name']
            if name in remote:
                raise UploadError('Duplicate remote asset name: ' + name)
            remote[name] = int(asset['id'])
        # Complete preflight before the first upload, including later conflicts.
        for snapshot in snapshots:
            if snapshot.name in remote:
                with tempfile.TemporaryFile() as downloaded:
                    gh('api', '-H', 'Accept: application/octet-stream',
                       f'repos/{args.repo}/releases/assets/{remote[snapshot.name]}',
                       output=downloaded)
                    downloaded.seek(0)
                    checksum = hashlib.file_digest(downloaded, 'sha256').digest()
                if checksum != digest(snapshot):
                    raise UploadError('Conflicting release asset: ' + snapshot.name)
                print('Verified existing asset: ' + snapshot.name)
        for snapshot in snapshots:
            if snapshot.name not in remote:
                # GitHub rejects collisions; never pass --clobber or delete assets.
                gh('release', 'upload', args.tag, '--repo', args.repo, str(snapshot))
                print('Uploaded missing asset: ' + snapshot.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--notes-file', required=True)
    parser.add_argument('assets', nargs='+')
    args = parser.parse_args()
    try:
        publish(args)
    except (UploadError, OSError, ValueError, KeyError, TypeError) as error:
        # Unexpected malformed API fields also fail closed.
        print(f'Release upload failed: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
