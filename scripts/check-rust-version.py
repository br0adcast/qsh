#!/usr/bin/env python3
"""Require the supported Rust floor in every effective Cargo workspace member."""
import json
import sys

SUPPORTED_RUST = '1.98.1'


def check_metadata(metadata):
    if not isinstance(metadata, dict):
        raise ValueError('invalid Cargo metadata')
    packages = metadata.get('packages')
    members = metadata.get('workspace_members')
    if not isinstance(packages, list) or not isinstance(members, list) or not members:
        raise ValueError('invalid Cargo metadata or empty workspace')
    by_id = {}
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError('invalid Cargo package record')
        package_id = package.get('id')
        if not isinstance(package_id, str) or not package_id or package_id in by_id:
            raise ValueError('invalid or duplicate Cargo package record')
        by_id[package_id] = package
    if any(not isinstance(member, str) or not member for member in members):
        raise ValueError('invalid Cargo workspace member')
    if len(set(members)) != len(members):
        raise ValueError('duplicate Cargo workspace member')
    for member in members:
        if member not in by_id:
            raise ValueError('workspace member package record missing: ' + member)
        package = by_id[member]
        name = package.get('name')
        if not isinstance(name, str) or not name:
            raise ValueError('workspace member package name missing')
        if package.get('rust_version') != SUPPORTED_RUST:
            raise ValueError(name + ': effective rust-version must equal ' + SUPPORTED_RUST)
    return len(members)


def main():
    try:
        try:
            metadata = json.load(sys.stdin)
        except (ValueError, UnicodeError):
            raise ValueError('invalid Cargo metadata')
        count = check_metadata(metadata)
    except ValueError as error:
        print('Rust support floor: ' + str(error), file=sys.stderr)
        return 1
    print('Rust support floor ' + SUPPORTED_RUST + ': verified ' + str(count) + ' workspace members')
    return 0


if __name__ == '__main__':
    sys.exit(main())
