#!/usr/bin/env python3
"""Check the reviewed dependency baseline without compiling product crates."""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def load_exceptions(path, today):
    entries = json.loads(path.read_text())
    if not isinstance(entries, list):
        raise ValueError('exceptions must be a list')
    reviewed = {}
    required = {'id', 'package', 'version', 'kind', 'owner', 'review_by', 'tracking', 'reason'}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError('exception requires exact identity, review date, owner, reason and tracking')
        if any(not isinstance(value, str) or not value.strip() for value in entry.values()):
            raise ValueError('empty exception metadata')
        if not re.fullmatch(r'RUSTSEC-\d{4}-\d{4}', entry['id']):
            raise ValueError('invalid advisory ID')
        if not re.fullmatch(r'[A-Za-z0-9_-]+', entry['package']):
            raise ValueError('invalid package name')
        if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?', entry['version']):
            raise ValueError('exception version must be exact')
        if entry['kind'] not in {'vulnerability', 'unmaintained', 'unsound'}:
            raise ValueError('unsupported exception kind')
        review_by = datetime.date.fromisoformat(entry['review_by'])
        if today > review_by:
            raise ValueError(f"expired exception: {entry['id']} (review by {review_by})")
        identity = (entry['kind'], entry['id'], entry['package'], entry['version'])
        if identity in reviewed:
            raise ValueError('duplicate exception')
        reviewed[identity] = entry
    return reviewed


def policy_command(binary, manifest, config, metadata=None):
    command = [str(binary), '--manifest-path', str(manifest), '--config', str(config),
               '--workspace', '--all-features', '--locked', '--format', 'json']
    if metadata is not None:
        command += ['--metadata-path', str(metadata), '--offline']
    return command + ['check', 'licenses', 'sources', 'bans']


def audit_command(binary, lock, database, exceptions):
    command = [str(binary), 'audit', '--file', str(lock), '--db', str(database),
               '--format', 'terminal', '--color', 'never',
               '--deny', 'unmaintained', '--deny', 'unsound', '--deny', 'yanked']
    for _, identifier, _, _ in sorted(exceptions):
        command += ['--ignore', identifier]
    return command


def validate_exception_versions(exceptions, packages):
    for _, identifier, name, version in exceptions:
        versions = {package['version'] for package in packages if package['name'] == name}
        if versions != {version}:
            raise ValueError(f'exception does not match every locked version: {identifier} {name}@{version}')


def validate_exception_advisories(exceptions, database):
    for kind, identifier, name, _ in exceptions:
        path = database / 'crates' / name / (identifier + '.md')
        try:
            match = re.match(r'```toml\r?\n(.*?)\r?\n```(?:\r?\n|$)', path.read_text(), re.DOTALL)
            if match is None:
                raise ValueError('missing advisory TOML metadata')
            metadata = tomllib.loads(match[1])['advisory']
            actual_kind = metadata.get('informational', 'vulnerability')
            if (metadata['id'], metadata['package'], actual_kind) != (identifier, name, kind):
                raise ValueError('advisory identity or kind changed')
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise ValueError(f'reviewed advisory metadata no longer matches: {identifier}: {error}') from error


def audit_passed(result, lock, database, dependency_count):
    # cargo-audit0.22.2 JSON mode hides index-initialization errors. Keep this
    # pinned terminal receipt strict; tool upgrades must qualify these controls.
    lines = result.stderr.splitlines()
    expected = [r"\s*Fetching advisory database from `https://github\.com/RustSec/advisory-db\.git`",
                rf'\s*Loaded [1-9][0-9]* security advisories \(from {re.escape(str(database))}\)',
                r'\s*Updating crates\.io index',
                rf'\s*Scanning {re.escape(str(lock))} for vulnerabilities \({dependency_count} crate dependencies\)']
    if len(lines) < 4 or any(re.fullmatch(pattern, line) is None
                             for pattern, line in zip(expected, lines[:4])):
        raise ValueError('cargo-audit did not provide the required fetch/index/lock receipt')
    error_count = notice_count = 0
    seen = set()
    for line in lines[4:]:
        error = re.fullmatch(r'error: ([1-9][0-9]*) (vulnerability|vulnerabilities|denied warning|denied warnings) found!', line)
        notice = re.fullmatch(r'warning: ([1-9][0-9]*) allowed warnings? found', line)
        if error:
            category = 'vulnerability' if error[2].startswith('vulnerabilit') else 'denied'
            if category in seen:
                raise ValueError('duplicate cargo-audit findings summary')
            seen.add(category)
            error_count += int(error[1])
        elif notice and not notice_count:
            notice_count = int(notice[1])
        else:
            raise ValueError('cargo-audit emitted an unexpected diagnostic; index checks may be incomplete')
    if result.returncode not in {0, 1} or bool(result.returncode) != bool(error_count):
        raise ValueError('cargo-audit exit status does not match its findings summary')
    warnings = re.findall(r'^Warning:\s+([^\n]+)$', result.stdout, re.MULTILINE)
    if warnings.count('notice') != notice_count:
        raise ValueError('cargo-audit notice report does not match its summary')
    if result.returncode == 0 and (any(kind != 'notice' for kind in warnings)
                                   or (result.stdout.strip() and not notice_count)):
        raise ValueError('unexpected successful cargo-audit finding output')
    return result.returncode == 0


def policy_passed(result):
    try:
        rows = [json.loads(line) for line in result.stderr.splitlines() if line.strip()]
        summary = rows[-1]
        if summary['type'] != 'summary' or set(summary['fields']) != {'licenses', 'sources', 'bans'}:
            raise ValueError('missing selected policy check summary')
        counts = [summary['fields'][name]['errors'] for name in ['licenses', 'sources', 'bans']]
        if any(type(count) is not int or count < 0 for count in counts):
            raise ValueError('invalid policy check counts')
        if (result.returncode == 0) != (sum(counts) == 0):
            raise ValueError('cargo-deny exit status does not match its findings')
        return result.returncode == 0
    except (KeyError, TypeError, IndexError) as error:
        raise ValueError(f'malformed cargo-deny summary: {error}') from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools-directory', type=Path, required=True)
    parser.add_argument('--output-directory', type=Path, required=True)
    args = parser.parse_args()
    tools = args.tools_directory.resolve()
    output = args.output_directory.resolve()
    output.mkdir(parents=True, exist_ok=True)
    installer = runpy.run_path(str(ROOT / 'scripts/install-dependency-tools.py'))
    for pin in installer['load_pins']():
        installer['verify_tool'](pin, tools / pin['name'])
    exceptions = load_exceptions(ROOT / 'scripts/dependency-exceptions.json',
                                 datetime.datetime.now(datetime.timezone.utc).date())
    lock = ROOT / 'Cargo.lock'
    packages = tomllib.loads(lock.read_text())['package']
    validate_exception_versions(exceptions, packages)
    with tempfile.TemporaryDirectory(prefix='qsh-dependency-check-') as directory:
        runtime = Path(directory)
        env = dict(os.environ, HOME=str(runtime / 'home'), CARGO_TERM_COLOR='never',
                   XDG_CONFIG_HOME=str(runtime / 'config'), XDG_CACHE_HOME=str(runtime / 'cache'),
                   HISTFILE='/dev/null', CARGO_CACHE_RUSTC_INFO='0',
                   RUSTUP_HOME=os.environ.get('RUSTUP_HOME', str(Path.home() / '.rustup')))
        for name in ['home', 'config', 'cache']:
            (runtime / name).mkdir()
        # Audit has its own fresh index and configuration, independent of user Cargo settings.
        audit_env = dict(env, CARGO_HOME=str(runtime / 'audit-cargo'))
        database = runtime / 'advisory-db'
        result = subprocess.run(audit_command(tools / 'cargo-audit', lock, database, exceptions),
                                cwd=runtime, env=audit_env, capture_output=True, text=True, timeout=300)
        (output / 'audit-stdout.log').write_text(result.stdout)
        (output / 'audit-stderr.log').write_text(result.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr, end='')
        audit_ok = audit_passed(result, lock, database, len(packages))
        validate_exception_advisories(exceptions, database)
        if result.stdout:
            print(result.stdout, end='')
        revision = subprocess.check_output(['git', '-C', str(database), 'rev-parse', 'HEAD'],
                                           cwd=runtime, env=env, text=True).strip()
        (output / 'advisory-db-commit.txt').write_text(revision + '\n')
        print(f'RustSec database: {revision}; {len(packages)} locked packages')
        for identity, entry in exceptions.items():
            print(f'reviewed {identity[1]} {identity[2]}@{identity[3]} '
                  f"({identity[0]}, review by {entry['review_by']}; {entry['tracking']})")
        # cargo-deny uses Cargo's existing registry source cache, with isolated HOME/config.
        env['CARGO_HOME'] = os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))
        result = subprocess.run(policy_command(tools / 'cargo-deny', ROOT / 'Cargo.toml', ROOT / 'deny.toml'),
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
        (output / 'policy.jsonl').write_text(result.stderr)
        (output / 'policy-stdout.log').write_text(result.stdout)
        passed = policy_passed(result)
        for line in result.stderr.splitlines():
            row = json.loads(line)
            if row['type'] == 'diagnostic':
                fields = row['fields']
                packages = ', '.join(graph['Krate']['name'] + '@' + graph['Krate']['version']
                                     for graph in fields.get('graphs', []) if 'Krate' in graph)
                print(f"{fields['severity']}[{fields.get('code', 'policy')}]: "
                      f"{fields['message']} {packages}", file=sys.stderr)
            elif row['type'] == 'summary':
                print('dependency policy summary: ' + json.dumps(row['fields'], sort_keys=True))
        return 0 if audit_ok and passed else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f'dependency check failed: {error}', file=sys.stderr)
        sys.exit(1)
