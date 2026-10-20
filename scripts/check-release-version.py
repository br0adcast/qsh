#!/usr/bin/env python3
"""Select the shipped pair's version from Cargo metadata on standard input."""
import argparse
import json
import re
import sys

# Cargo package versions are SemVer. Check the resolved value before using it
# in an archive name or shell environment; do not normalize prerelease tags.
NUMBER = r'(?:0|[1-9][0-9]*)'
IDENTIFIER = r'[0-9A-Za-z-]+'
VERSION = re.compile(
    r'(' + NUMBER + r'\.' + NUMBER + r'\.' + NUMBER + r')'
    r'(?:-(' + IDENTIFIER + r'(?:\.' + IDENTIFIER + r')*))?'
    r'(?:\+(' + IDENTIFIER + r'(?:\.' + IDENTIFIER + r')*))?')


def valid_version(value):
    if not isinstance(value, str):
        return False
    match = VERSION.fullmatch(value)
    if match is None:
        return False
    # Numeric prerelease identifiers cannot have leading zeroes. Build
    # identifiers may, and must remain verbatim in the selected version.
    return all(not (part.isdigit() and len(part) > 1 and part[0] == '0')
               for part in (match.group(2) or '').split('.'))


def selected_version(metadata, ref_type, ref_name):
    if not isinstance(metadata, dict):
        raise ValueError('invalid Cargo metadata')
    packages = metadata.get('packages')
    members = metadata.get('workspace_members')
    if not isinstance(packages, list) or not isinstance(members, list):
        raise ValueError('invalid Cargo metadata')
    by_id = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError('invalid Cargo metadata')
        package_id = package.get('id')
        if not isinstance(package_id, str) or not package_id or package_id in by_id:
            raise ValueError('invalid Cargo metadata')
        by_id[package_id] = package
    if (any(not isinstance(member, str) or member not in by_id for member in members)
            or len(set(members)) != len(members)):
        raise ValueError('invalid Cargo workspace membership')
    versions = {}
    for name in ('qsh', 'qshd'):
        matches = [by_id[member] for member in members if by_id[member].get('name') == name]
        if len(matches) != 1:
            raise ValueError('expected one workspace member each for qsh and qshd')
        version = matches[0].get('version')
        if not valid_version(version):
            raise ValueError('invalid package version')
        versions[name] = version
    if versions['qsh'] != versions['qshd']:
        raise ValueError('qsh and qshd package versions differ')
    version = versions['qsh']
    if ref_type == 'tag' and ref_name != 'v' + version:
        raise ValueError('release tag differs from the qsh/qshd package version')
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref-type', choices=('tag', 'branch'), required=True)
    parser.add_argument('--ref-name', required=True)
    args = parser.parse_args()
    try:
        try:
            metadata = json.load(sys.stdin)
        except (ValueError, UnicodeError):
            raise ValueError('invalid Cargo metadata')
        version = selected_version(metadata, args.ref_type, args.ref_name)
    except ValueError as error:
        print('release version: ' + str(error), file=sys.stderr)
        return 1
    print(version)
    return 0


if __name__ == '__main__':
    sys.exit(main())
