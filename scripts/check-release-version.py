#!/usr/bin/env python3
"""Select the shipped pair's version from Cargo metadata on standard input.

With --existing-tags, instead check a release tag against the repository's
existing version tags: no Cargo metadata is read.
"""
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


# Release tags spell prereleases as alpha.N, beta.N or rc.N. SemVer compares a
# dot-separated number numerically, while an attached one (rc10) compares as
# text, so rc10 would order before rc2 and every rc.N before rc1 (#554).
RELEASE_PRERELEASE = re.compile(r'(?:alpha|beta|rc)\.' + NUMBER)


def valid_release_version(value):
    if not valid_version(value):
        return False
    prerelease = VERSION.fullmatch(value).group(2)
    return prerelease is None or RELEASE_PRERELEASE.fullmatch(prerelease) is not None


def precedence(value):
    """SemVer 2.0.0 precedence key of a valid version; build metadata is ignored."""
    match = VERSION.fullmatch(value)
    core = tuple(int(part) for part in match.group(1).split('.'))
    if match.group(2) is None:
        # A normal version has higher precedence than any of its prereleases.
        return core, (1,)
    # Numeric identifiers order before alphanumeric ones; a longer list of
    # otherwise equal identifiers has higher precedence.
    identifiers = tuple((0, int(part), '') if part.isdigit() else (1, 0, part)
                        for part in match.group(2).split('.'))
    return core, (0, identifiers)


def order_error(version, tags):
    """Describe why a release version cannot follow the existing version tags.

    Every other version tag of the same major.minor.patch must have lower
    precedence: a prerelease cannot follow a later prerelease or the final
    version, and another tag with equal precedence would be ambiguous. Older
    or newer release lines are unconstrained, so patch releases of an earlier
    line remain possible. Tags that are not versions are ignored.
    """
    core, key = precedence(version)
    for tag in tags:
        if tag == 'v' + version or not tag.startswith('v') or not valid_version(tag[1:]):
            continue
        other_core, other_key = precedence(tag[1:])
        if other_core == core and other_key >= key:
            return 'release tag does not follow existing tag ' + tag
    return None


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
    if ref_type == 'tag' and not valid_release_version(version):
        raise ValueError('release prerelease must be alpha.N, beta.N or rc.N')
    return version


def checked_order(ref_type, ref_name, tags_text):
    if ref_type != 'tag':
        raise ValueError('tag order applies only to a release tag')
    version = ref_name[1:] if ref_name.startswith('v') else ''
    if not valid_version(version):
        raise ValueError('invalid release tag')
    if not valid_release_version(version):
        raise ValueError('release prerelease must be alpha.N, beta.N or rc.N')
    tags = tags_text.splitlines()
    if ref_name not in tags:
        raise ValueError('release tag is missing from the existing tags')
    error = order_error(version, tags)
    if error is not None:
        raise ValueError(error)
    return version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref-type', choices=('tag', 'branch'), required=True)
    parser.add_argument('--ref-name', required=True)
    parser.add_argument('--existing-tags', metavar='FILE',
                        help='existing tag names, one per line, instead of Cargo metadata')
    args = parser.parse_args()
    try:
        if args.existing_tags is not None:
            try:
                with open(args.existing_tags, encoding='utf-8') as tags:
                    text = tags.read()
            except (OSError, UnicodeError):
                raise ValueError('unreadable existing tags')
            version = checked_order(args.ref_type, args.ref_name, text)
        else:
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
