#!/usr/bin/env python3
"""Select the CI lanes one exact source needs (#609).

The policy lives in scripts/ci-selection.json; docs/actions-maintenance.md
describes the lanes, contexts and failure handling. Every uncertainty selects
more coverage, never less. An invalid source identity is an error: the
selection job fails and the CI gate with it.
"""
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = 'scripts/ci-selection.json'
DIGEST_INPUTS = ('scripts/ci-selection.json', 'scripts/ci-select.py', 'scripts/ci-gate.py')
NATIVE_INPUTS = ('floors', 'intel-legacy', 'intel-owner', 'portable')
LINUX_SMOKE = ('check', 'container', 'docs')
MAX_TEXT = 4 * 1024 * 1024
SHA = re.compile(r'[0-9a-f]{40}')


class Uncertain(Exception):
    """The impact of a valid source cannot be bounded: select broad coverage."""


class InvalidIdentity(Exception):
    """The tested source is not the one the event names: fail qualification."""


def match(path, pattern):
    if pattern.endswith('/**'):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + '/')
    if pattern.startswith('**/'):
        tail = pattern[3:]
        return fnmatch.fnmatchcase(PurePosixPath(path).name, tail) or fnmatch.fnmatchcase(path, tail)
    return fnmatch.fnmatchcase(path, pattern) and ('/' in pattern or '/' not in path)


def any_match(path, patterns):
    return any(match(path, pattern) for pattern in patterns)


class Git:
    def __init__(self, root):
        self.root = Path(root)

    def run(self, *args, check=True):
        result = subprocess.run(['git', '--no-pager', '-c', 'core.quotepath=off', *args],
                                cwd=self.root, capture_output=True, timeout=60, check=False)
        if check and result.returncode:
            raise Uncertain('git ' + args[0] + ' failed')
        if len(result.stdout) > 64 * 1024 * 1024:
            raise Uncertain('git output too large')
        return result.stdout if check else result

    def commit(self, value):
        if type(value) is not str or not SHA.fullmatch(value) or value == '0' * 40:
            raise Uncertain('not a commit identity')
        result = self.run('cat-file', '-t', value, check=False)
        if result.returncode or result.stdout != b'commit\n':
            raise Uncertain('commit unavailable')
        return value

    def parents(self, value):
        headers = self.run('cat-file', '-p', value).split(b'\n\n', 1)[0].splitlines()
        return [line[7:].decode('ascii') for line in headers if line.startswith(b'parent ')]

    def files(self, revision):
        raw = self.run('ls-tree', '-r', '-z', '--full-tree', revision)
        entries = {}
        for record in raw.split(b'\0'):
            if not record:
                continue
            meta, name = record.split(b'\t', 1)
            mode, kind, blob = meta.split()
            entries[name.decode('utf-8')] = (mode.decode(), kind.decode(), blob.decode())
        return entries

    def blob(self, blob):
        return self.run('cat-file', 'blob', blob)

    def blobs(self, ids):
        """Read many blobs with one `git cat-file --batch`."""
        if not ids:
            return {}
        result = subprocess.run(['git', '--no-pager', 'cat-file', '--batch'], cwd=self.root,
                                input=''.join(blob + '\n' for blob in ids).encode('ascii'),
                                capture_output=True, timeout=120, check=False)
        if result.returncode:
            raise Uncertain('git cat-file failed')
        data, found, index = result.stdout, {}, 0
        for blob in ids:
            end = data.index(b'\n', index)
            header = data[index:end].split()
            if len(header) != 3 or header[0].decode() != blob or header[1] != b'blob':
                raise Uncertain('git cat-file output malformed')
            size = int(header[2])
            found[blob] = data[end + 1:end + 1 + size]
            index = end + 1 + size + 1
        return found

    def changes(self, base, head):
        raw = self.run('diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                       '--name-status', '-z', base, head, '--')
        fields = raw.split(b'\0')
        if fields and fields[-1] == b'':
            fields.pop()
        if len(fields) % 2:
            raise Uncertain('malformed diff')
        result = []
        for status, name in zip(fields[0::2], fields[1::2]):
            path = name.decode('utf-8')
            if (not path or path.startswith('/') or '\\' in path
                    or any(part in ('', '.', '..') for part in path.split('/'))):
                raise Uncertain('malformed path')
            result.append((status.decode('ascii')[:1], path))
        return result


class Tree:
    """One revision's tracked files, read lazily from Git."""

    def __init__(self, git, revision):
        self.git, self.revision = git, revision
        self.entries = git.files(revision)
        self.cache = {}

    def __contains__(self, path):
        return path in self.entries

    def paths(self):
        return self.entries.keys()

    def preload(self):
        wanted = sorted({blob for mode, kind, blob in self.entries.values() if kind == 'blob'})
        contents = self.git.blobs(wanted)
        for path, (mode, kind, blob) in self.entries.items():
            if kind == 'blob':
                self.cache[path] = contents[blob]

    def data(self, path):
        if path not in self.cache:
            mode, kind, blob = self.entries[path]
            self.cache[path] = self.git.blob(blob) if kind == 'blob' else b''
        return self.cache[path]

    def text(self, path):
        data = self.data(path)
        if len(data) > MAX_TEXT or b'\0' in data:
            return None
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return None


def manifest(tree, path):
    if path not in tree:
        raise Uncertain('manifest missing')
    try:
        return tomllib.loads(tree.data(path).decode('utf-8'))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        raise Uncertain('manifest unreadable') from None


def normal(path):
    parts = []
    for part in PurePosixPath(path).parts:
        if part == '..':
            if not parts:
                raise Uncertain('path leaves the repository')
            parts.pop()
        elif part not in ('.', ''):
            parts.append(part)
    return '/'.join(parts)


class Workspace:
    """Rust packages of one revision and their path edges of every kind."""

    def __init__(self, tree):
        root = manifest(tree, 'Cargo.toml')
        workspace = root.get('workspace', {})
        if 'dependencies' in workspace:
            raise Uncertain('workspace dependency inheritance is not classified')
        dirs = list(workspace.get('members', []))
        patches = {}
        for name, spec in root.get('patch', {}).get('crates-io', {}).items():
            if not isinstance(spec, dict) or 'path' not in spec:
                raise Uncertain('unclassified patch')
            patches[spec.get('package', name)] = normal(spec['path'])
            dirs.append(normal(spec['path']))
        if 'fuzz/Cargo.toml' in tree:
            dirs.append('fuzz')
        self.dirs, self.edges, self.names, self.closures = {}, {}, {}, {}
        specs, local_patches = {}, {}
        for folder in dirs:
            data = manifest(tree, folder + '/Cargo.toml')
            name = data.get('package', {}).get('name')
            if type(name) is not str or name in self.dirs:
                raise Uncertain('package identity')
            self.dirs[name] = folder
            self.names[folder] = name
            specs[name] = data
            local_patches[name] = dict(patches)
            for key, spec in data.get('patch', {}).get('crates-io', {}).items():
                if not isinstance(spec, dict) or 'path' not in spec:
                    raise Uncertain('unclassified patch')
                local_patches[name][spec.get('package', key)] = normal(folder + '/' + spec['path'])
        for name in specs:
            if any(folder not in self.names for folder in local_patches[name].values()):
                raise Uncertain('patch outside the classified packages')
        for name, data in specs.items():
            folder = self.dirs[name]
            patched = local_patches[name]
            self.edges[name] = set()
            tables = [data]
            for target in data.get('target', {}).values():
                tables.append(target)
            for table in tables:
                for kind in ('dependencies', 'dev-dependencies', 'build-dependencies'):
                    for key, spec in table.get(kind, {}).items():
                        package = spec.get('package', key) if isinstance(spec, dict) else key
                        if isinstance(spec, dict) and spec.get('workspace'):
                            raise Uncertain('workspace dependency inheritance is not classified')
                        if isinstance(spec, dict) and 'path' in spec:
                            target_dir = normal(folder + '/' + spec['path'])
                            if target_dir not in self.names:
                                raise Uncertain('path dependency outside the classified packages')
                            self.edges[name].add(self.names[target_dir])
                        elif package in patched:
                            self.edges[name].add(self.names[patched[package]])
            if 'build' in data.get('package', {}) or 'links' in data.get('package', {}):
                self.edges[name].add('<build>')

    def owner(self, path):
        best = None
        for folder, name in self.names.items():
            if path == folder or path.startswith(folder + '/'):
                if best is None or len(folder) > len(self.dirs[best]):
                    best = name
        return best

    def closure(self, name):
        if name in self.closures:
            return self.closures[name]
        seen, todo = set(), [name]
        while todo:
            item = todo.pop()
            if item in seen or item not in self.edges:
                continue
            seen.add(item)
            todo.extend(self.edges[item])
        self.closures[name] = frozenset(seen)
        return self.closures[name]

    def dependents(self, name):
        return {other for other in self.edges if other != name and name in self.closure(other)}


def merged(base_ws, head_ws, attribute, name):
    values = set()
    for ws in (base_ws, head_ws):
        if ws is not None and name in ws.edges:
            values |= getattr(ws, attribute)(name)
    return values


RUST_COMMENT = re.compile(r'^\s*(//|/\*|\*)')
INCLUDE = re.compile(r'\b(include|include_str|include_bytes)!\s*\(\s*("(?:[^"\\]|\\.)*")?')
GLOB_TOKEN = re.compile(r'(?:\.\./)*(?:scripts|packaging)/[^\s\'"`)\]]*')


def globs(text):
    found = set()
    for token in GLOB_TOKEN.findall(text):
        while token.startswith('../'):
            token = token[3:]
        pattern = re.sub(r'\$\{\{.*?\}\}|\$\{[^}]*\}|\$[A-Za-z_]\w*', '*', token)
        if '*' in pattern:
            found.add(pattern)
    return sorted(found)


def includes(path, text):
    """Literal include targets of one Rust file, resolved from the repository root."""
    found = []
    for item in INCLUDE.finditer(text):
        if item.group(2) is None:
            raise Uncertain('non-literal include')
        literal = json.loads(item.group(2))
        found.append(normal(str(PurePosixPath(path).parent / literal)))
    return found


class Corpus:
    """Consumer texts at head: every tracked file that can read another path."""

    def __init__(self, policy, tree, workflows):
        self.policy, self.tree = policy, tree
        self.texts, self.cache = {}, {}
        tree.preload()
        for path in tree.paths():
            if (path.endswith(('.md', '.gitignore')) or path.startswith('docs/')
                    or path in ('LICENSE', 'CHANGELOG.md') or any_match(path, policy['policy_files'])
                    or path.startswith('.github/workflows/')):
                continue
            text = tree.text(path)
            if text is None:
                continue
            if path.endswith('.rs'):
                text = '\n'.join(line for line in text.splitlines() if not RUST_COMMENT.match(line))
            self.texts[path] = text
        self.globs = {path: globs(text) for path, text in self.texts.items()}
        self.basenames = {}
        for path in tree.paths():
            name = PurePosixPath(path).name
            self.basenames[name] = self.basenames.get(name, 0) + 1
        self.jobs = {}
        for workflow, source in workflows.items():
            for job, body in workflow_jobs(source).items():
                self.jobs[(workflow, job)] = body
                self.globs[(workflow, job)] = globs(body)
        self.lane_of = {(spec['workflow'], spec['job']): lane for lane, spec in policy['lanes'].items()}
        self.include_targets = {}
        for path, text in self.texts.items():
            if path.endswith('.rs'):
                for target in includes(path, text):
                    self.include_targets.setdefault(target, set()).add(path)

    @staticmethod
    def needles(target):
        name = PurePosixPath(target).name
        found = [re.compile(r'(?<![\w.-])' + re.escape(name) + r'(?![\w-])')]
        stem = PurePosixPath(target).stem
        if target.endswith('.py') and stem.isidentifier():
            found.append(re.compile(r'\b(?:import|from)\s+' + re.escape(stem) + r'\b'))
        return PurePosixPath(target).name, found

    def mentions(self, target, key, text, needles):
        name, patterns = needles
        if target in text:
            return True
        # A bare file name names one file only when it is unique, or when a
        # sibling refers to it; a shared name such as README.md elsewhere does not.
        sibling = type(key) is str and PurePosixPath(key).parent == PurePosixPath(target).parent
        bare = self.basenames.get(name, 0) <= 1 or sibling
        if bare and name in text and patterns[0].search(text):
            return True
        if not bare and re.search(r'(?<![\w.-])[\w.-]+/' + re.escape(name) + r'(?![\w-])', text):
            suffixes = [str(PurePosixPath(*PurePosixPath(target).parts[i:]))
                        for i in range(1, len(PurePosixPath(target).parts) - 1)]
            if any(suffix in text for suffix in suffixes):
                return True
        if any(pattern.search(text) for pattern in patterns[1:]):
            return True
        return any(fnmatch.fnmatchcase(target, pattern) for pattern in self.globs[key])

    def consumers(self, target):
        if target not in self.cache:
            self.cache[target] = self.scan(target)
        return self.cache[target]

    def scan(self, target):
        needles = self.needles(target)
        files = [path for path, text in self.texts.items()
                 if path != target and self.mentions(target, path, text, needles)]
        files.extend(self.include_targets.get(target, ()))
        jobs = [key for key, body in self.jobs.items() if self.mentions(target, key, body, needles)]
        return sorted(set(files)), jobs


def workflow_jobs(source):
    lines = source.splitlines(keepends=True)
    try:
        start = next(i for i, line in enumerate(lines) if line == 'jobs:\n')
    except StopIteration:
        raise Uncertain('workflow without jobs') from None
    jobs, current = {}, None
    for line in lines[start + 1:]:
        found = re.match(r'^  ([A-Za-z0-9_-]+):\s*$', line)
        if found:
            current = found.group(1)
            if current in jobs:
                raise Uncertain('duplicate job')
            jobs[current] = ''
        elif not line.strip() or line.lstrip().startswith('#'):
            if current is not None:
                jobs[current] += line
        elif current is not None and line.startswith('    '):
            jobs[current] += line
        else:
            raise Uncertain('unparsed workflow line')
    return jobs


class Selector:
    def __init__(self, policy, git, base, head, cache=None):
        self.policy, self.git = policy, git
        self.lanes = set(policy['lanes'])
        cache = {} if cache is None else cache
        self.base_tree, self.base_ws, base_corpus = self.revision(cache, base, required=False)
        self.head_tree, self.head_ws, head_corpus = self.revision(cache, head, required=True)
        if self.head_ws is None:
            raise Uncertain('head workspace unreadable')
        self.corpora = [head_corpus] + ([base_corpus] if base_corpus is not None else [])
        self.reasons, self.verdicts = {}, {}

    def revision(self, cache, revision, required):
        key = (self.git.run('rev-parse', revision + '^{commit}').strip().decode('ascii'), required)
        if key not in cache:
            tree = Tree(self.git, key[0])
            workspace = self.workspace(tree)
            cache[key] = (tree, workspace, self.corpus(tree, required))
        return cache[key]

    def corpus(self, tree, required):
        workflows = {}
        for path in sorted({spec['workflow'] for spec in self.policy['lanes'].values()}):
            text = tree.text(path) if path in tree else None
            if text is None:
                if required:
                    raise Uncertain('lane workflow missing')
                return None
            workflows[path] = text
        corpus = Corpus(self.policy, tree, workflows)
        for lane, spec in self.policy['lanes'].items():
            if (spec['workflow'], spec['job']) not in corpus.jobs:
                if required:
                    raise Uncertain('lane job missing: ' + lane)
                return None
        return corpus

    @staticmethod
    def workspace(tree):
        if 'Cargo.toml' not in tree:
            return None
        return Workspace(tree)

    def add(self, lanes, reason):
        for lane in lanes:
            self.reasons.setdefault(lane, set()).add(reason)

    def full(self, reason):
        self.add(self.lanes, reason)

    def package(self, folder):
        for ws in (self.head_ws, self.base_ws):
            if ws is not None and folder in ws.names:
                return ws.names[folder]
        return None

    def consumed_by(self, lane, crate):
        rule = self.policy['lanes'][lane]['rust']
        if rule == 'workspace':
            return crate != self.package('fuzz')
        if rule.startswith('closure:'):
            root = rule.split(':', 1)[1]
            root = self.package('fuzz') if root == 'fuzz' else root
            return crate in merged(self.base_ws, self.head_ws, 'closure', root)
        return False

    def boundary(self, crate):
        if crate not in self.verdicts:
            self.verdicts[crate] = self.boundary_verdict(crate)
        return self.verdicts[crate]

    def boundary_verdict(self, crate):
        spec = self.policy['boundary']['crates'].get(crate)
        if spec is None:
            return None
        for ws in (self.base_ws, self.head_ws):
            if ws is None or crate not in ws.edges:
                return 'REVOKED_IDENTITY'
            if crate in ws.closure('qshd'):
                return 'REVOKED_QSHD_CLOSURE'
        if sorted(self.head_ws.dependents(crate)) != sorted(spec['dependents']):
            return 'REVOKED_DEPENDENTS'
        if sorted(self.head_ws.edges[crate]) != sorted(spec['dependencies']):
            return 'REVOKED_DEPENDENCIES'
        folder = self.head_ws.dirs[crate]
        data = manifest(self.head_tree, folder + '/Cargo.toml')
        package = data.get('package', {})
        if 'features' in data or 'target' in data or 'build' in package or 'links' in package:
            return 'REVOKED_MANIFEST'
        lib = self.head_tree.text(folder + '/src/lib.rs') if folder + '/src/lib.rs' in self.head_tree else None
        if lib is None or not re.search(r'(?m)^#!\[forbid\(unsafe_code\)\]$', lib):
            return 'REVOKED_UNSAFE_POLICY'
        allowed = set(self.policy['boundary']['std_modules'])
        for path in self.head_tree.paths():
            if not path.startswith(folder + '/'):
                continue
            if path == folder + '/Cargo.toml':
                continue
            text = self.head_tree.text(path)
            if text is None or not path.endswith('.rs'):
                return 'REVOKED_NON_RUST_INPUT'
            if tripwire(text, allowed):
                return 'REVOKED_TRIPWIRE'
        for corpus in self.corpora:
            for target, includers in corpus.include_targets.items():
                if target.startswith(folder + '/') and any(not i.startswith(folder + '/') for i in includers):
                    return 'REVOKED_EXTERNAL_INCLUDE'
        return 'BOUNDARY'

    def crate_row(self, crate, path, reason):
        verdict = self.boundary(crate)
        if verdict == 'BOUNDARY':
            return self.add(self.policy['boundary']['lanes'], 'BOUNDARY_' + crate)
        label = reason + ':' + crate + (':BOUNDARY_' + verdict if verdict else '')
        for lane in sorted(self.lanes):
            if self.consumed_by(lane, crate):
                self.add([lane], label)
        if any_match(path, self.policy['peer_paths']):
            self.add(['peers'], 'PEER_PATH')

    def owners(self, path):
        owners = set()
        for ws in (self.base_ws, self.head_ws):
            if ws is not None:
                owner = ws.owner(path)
                if owner is not None:
                    owners.add(owner)
        return owners

    def includers(self, path):
        found = set()
        for corpus in self.corpora:
            found |= corpus.include_targets.get(path, set())
        return found

    def classify(self, path):
        policy = self.policy
        if any_match(path, policy['full']):
            return self.full('FULL_RULE')
        for includer in sorted(self.includers(path)):
            for crate in sorted(self.owners(includer)):
                self.crate_row(crate, includer, 'INCLUDED_BY')
        owners = self.owners(path)
        if owners:
            for crate in sorted(owners):
                self.crate_row(crate, path, 'CRATE')
            return None
        if path.startswith(('scripts/', 'packaging/')):
            lanes = policy['packaging_lanes'] if path.startswith('packaging/') else policy['script_lanes']
            self.add(lanes, 'SCRIPT_OR_PACKAGE')
            return self.consumers(path)
        documents = policy['documents']
        for pattern, lanes in documents['consumed'].items():
            if match(path, pattern):
                return self.add(lanes, 'CONSUMED_DOCUMENT')
        if path in documents['prose']:
            reviewed = {(item['document'], item['file']) for item in documents['reviewed_mentions']}
            if self.includers(path):
                return self.full('INCLUDED_DOCUMENT')
            for corpus in self.corpora:
                files, jobs = corpus.consumers(path)
                if jobs or any((path, item) not in reviewed for item in files):
                    return self.full('UNREVIEWED_DOCUMENT_CONSUMER')
            return self.add(['docs'], 'PROSE_DOCUMENT')
        if path in policy['check_only']:
            return self.add(['check'], 'CHECK_ONLY')
        return self.full('UNKNOWN_PATH')

    def consumers(self, start):
        seen, todo = {start}, [start]
        while todo:
            target = todo.pop()
            for corpus in self.corpora:
                files, jobs = corpus.consumers(target)
                for key in jobs:
                    lane = corpus.lane_of.get(key)
                    if lane is not None:
                        self.add([lane], 'CONSUMER_JOB')
                for path in files:
                    if path in seen:
                        continue
                    seen.add(path)
                    owners = self.owners(path)
                    if owners:
                        for crate in sorted(owners):
                            self.crate_row(crate, path, 'CONSUMED_BY')
                    elif path.startswith('scripts/tests/'):
                        # A test that reads the input changes only its own result:
                        # the lanes that execute the test consume it.
                        self.add(self.policy['script_lanes'], 'TEST_CONSUMER')
                        todo.append(path)
                    elif any_match(path, self.policy['full']):
                        return self.full('FULL_RULE_CONSUMER')
                    elif path.startswith(('scripts/', 'packaging/')):
                        lanes = (self.policy['packaging_lanes'] if path.startswith('packaging/')
                                 else self.policy['script_lanes'])
                        self.add(lanes, 'SCRIPT_OR_PACKAGE_CONSUMER')
                        todo.append(path)
                    else:
                        return self.full('UNCLASSIFIED_CONSUMER')
        return None

    def select(self, changes):
        if not changes:
            raise Uncertain('empty change set')
        for _status, path in changes:
            self.classify(path)
        return {lane: sorted(reasons) for lane, reasons in sorted(self.reasons.items())}


def tripwire(text, allowed_std):
    code = '\n'.join(line for line in text.splitlines() if not RUST_COMMENT.match(line))
    for item in re.finditer(r'\bcfg(?:_attr)?!?\s*\(', code):
        depth, index = 1, item.end()
        while index < len(code) and depth:
            depth += {'(': 1, ')': -1}.get(code[index], 0)
            index += 1
        predicate = re.sub(r'\s+', '', code[item.end():index - 1])
        if 'cfg_attr' in item.group(0) or predicate not in ('test', 'not(test)'):
            return True
    if re.search(r'\b(Instant|SystemTime|unsafe|extern)\b|#\s*!?\s*\[\s*link|\b(?:global_)?asm!'
                 r'|\b(?:env|option_env|file|include|include_str|include_bytes)!', code):
        return True
    for root in ('std', 'core', 'alloc'):
        for item in re.finditer(r'\b' + root + r'::(\{[^}]*\}|[A-Za-z_]\w*)', code):
            segment = item.group(1)
            names = re.findall(r'(?:^|[{,])\s*([A-Za-z_]\w*)', segment) if segment.startswith('{') else [segment]
            if any(name not in allowed_std for name in names):
                return True
    return False


def load_policy(root=ROOT):
    policy = json.loads((Path(root) / POLICY_PATH).read_text())
    if policy.get('schema') != 1:
        raise SystemExit('unsupported selection policy')
    return policy


def policy_digest(root=ROOT):
    digest = hashlib.sha256()
    for name in DIGEST_INPUTS:
        data = (Path(root) / name).read_bytes()
        digest.update(name.encode() + b'\0' + str(len(data)).encode() + b'\0' + data)
    return digest.hexdigest()


def canonical(values, allowed):
    if any(type(item) is not str or item not in allowed for item in values):
        raise ValueError('unknown lane')
    items = sorted(set(values))
    return json.dumps(items, separators=(',', ':'))


def outputs(policy, record):
    lanes = record['lanes']
    if any(lane not in policy['lanes'] for lane in lanes):
        raise ValueError('unknown lane')
    native = sorted(policy['lanes'][lane]['input'] for lane in lanes if 'input' in policy['lanes'][lane])
    calls = sorted({call for call, workflow in policy['calls'].items()
                    for lane in lanes if policy['lanes'][lane]['workflow'] == workflow})
    return {
        'lanes': canonical(lanes, set(policy['lanes'])),
        'native_lanes': canonical(native, set(NATIVE_INPUTS)),
        'calls': canonical(calls, set(policy['calls'])),
        'record': json.dumps(record, sort_keys=True, separators=(',', ':')),
    }


def context(env, policy):
    """Return whether CI is the top-level workflow, after checking the caller declaration."""
    repository = env.get('GITHUB_REPOSITORY', '')
    ref = env.get('GITHUB_REF', '')
    top = env.get('GITHUB_WORKFLOW_REF', '') == repository + '/.github/workflows/ci.yml@' + ref
    declared = env.get('QSH_CALLER_RUNS', '')
    job_ref = env.get('QSH_JOB_WORKFLOW_REF', '')
    if repository != policy['repository']:
        raise InvalidIdentity('repository')
    if not job_ref.startswith(repository + '/.github/workflows/ci.yml@'):
        raise InvalidIdentity('selection job is not defined by ci.yml')
    if top and declared:
        raise InvalidIdentity('top-level run declares a caller')
    if not top and declared != policy['caller_runs']:
        raise InvalidIdentity('caller declaration missing or different')
    return top


def identity(env, git):
    """Return (event, source, base, head, api_head, event_base) for a top-level run."""
    source = env.get('GITHUB_SHA', '')
    if not SHA.fullmatch(source):
        raise InvalidIdentity('source')
    actual = git.run('rev-parse', 'HEAD').strip().decode('ascii')
    if actual != source:
        raise InvalidIdentity('checkout differs from GITHUB_SHA')
    event_name = env.get('GITHUB_EVENT_NAME', '')
    raw = Path(env['GITHUB_EVENT_PATH']).read_bytes()
    if len(raw) > 8 * 1024 * 1024:
        raise InvalidIdentity('event payload')
    try:
        event = json.loads(raw)
    except ValueError:
        raise InvalidIdentity('event payload') from None
    if type(event) is not dict:
        raise InvalidIdentity('event payload')
    ref = env.get('GITHUB_REF', '')
    if event_name == 'pull_request':
        number = event.get('number')
        if type(number) is not int or ref != 'refs/pull/' + str(number) + '/merge':
            raise InvalidIdentity('pull request ref')
        pull = event.get('pull_request')
        head = pull.get('head') if isinstance(pull, dict) else None
        head = head.get('sha') if isinstance(head, dict) else None
        base = pull.get('base') if isinstance(pull, dict) else None
        base = base.get('sha') if isinstance(base, dict) else None
        parents = git.parents(source)
        if type(head) is not str or len(parents) != 2 or parents[1] != head:
            raise InvalidIdentity('merge parents')
        return event_name, source, parents[0], head, head, base
    if event_name == 'push':
        if ref != 'refs/heads/main' or event.get('after') != source:
            raise InvalidIdentity('push identity')
        return event_name, source, event.get('before'), source, source, None
    return event_name, source, None, source, source, None


def decide(env, root=ROOT, git=None):
    policy = load_policy(root)
    git = git or Git(root)
    lanes = set(policy['lanes'])
    ci_lanes = {lane for lane, spec in policy['lanes'].items() if spec['workflow'] == '.github/workflows/ci.yml'}
    record = {'schema': 1, 'policy_digest': policy_digest(root), 'repository': policy['repository'],
              'run_id': env.get('GITHUB_RUN_ID'), 'run_attempt': env.get('GITHUB_RUN_ATTEMPT'),
              'deferred': [], 'delegated': [], 'reasons': {}}
    top = context(env, policy)
    if not top:
        source = env.get('GITHUB_SHA', '')
        if not SHA.fullmatch(source) or git.run('rev-parse', 'HEAD').strip().decode('ascii') != source:
            raise InvalidIdentity('called source')
        record.update(context='called', mode='called', event=env.get('GITHUB_EVENT_NAME'), source=source,
                      api_head=source, base=None, head=source, lanes=sorted(ci_lanes),
                      delegated=sorted(lanes - ci_lanes), reasons={lane: ['CALLED_FULL'] for lane in sorted(ci_lanes)})
        return policy, record
    event_name, source, base, head, api_head, event_base = identity(env, git)
    record.update(context='top-level', event=event_name, source=source, api_head=api_head,
                  base=base, head=head, event_base=event_base)
    if event_name not in ('pull_request', 'push'):
        record.update(mode='full', lanes=sorted(lanes), reasons={lane: ['FULL_EVENT'] for lane in sorted(lanes)})
        return policy, record
    try:
        base = git.commit(base)
        if event_name == 'push':
            merge_base = git.run('merge-base', base, source, check=False)
            if merge_base.returncode or merge_base.stdout.strip().decode() != base:
                raise Uncertain('push base is not an ancestor')
        selector = Selector(policy, git, base, source)
        reasons = selector.select(git.changes(base, source))
    except Uncertain as error:
        reasons = {lane: ['UNCERTAIN:' + str(error)[:80]] for lane in sorted(lanes)}
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, OSError,
            subprocess.SubprocessError) as error:
        # The identity is valid; only the analysis failed. Select broadly.
        reasons = {lane: ['UNCERTAIN:' + type(error).__name__] for lane in sorted(lanes)}
    selected = set(reasons)
    if event_name == 'push':
        smoke = {'docs'} if selected <= {'docs'} else ({'check', 'container'} | (selected & {'docs'}))
        record.update(mode='smoke', lanes=sorted(smoke), deferred=sorted(lanes - smoke))
    else:
        record.update(mode='full' if selected == lanes else 'selected', lanes=sorted(selected))
    record['reasons'] = reasons
    return policy, record


def main():
    env = dict(os.environ)
    try:
        policy, record = decide(env)
        values = outputs(policy, record)
    except InvalidIdentity as error:
        print('::error::CI selection refused: ' + str(error))
        return 1
    with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as handle:
        for key, value in values.items():
            if '\n' in value or '\r' in value:
                raise SystemExit('multiline output refused')
            handle.write(key + '=' + value + '\n')
    print('CI selection mode=' + record['mode'] + ' context=' + record['context']
          + ' source=' + record['source'] + ' api_head=' + str(record['api_head'])
          + ' base=' + str(record['base']))
    print('lanes=' + values['lanes'] + ' native_lanes=' + values['native_lanes'] + ' calls=' + values['calls'])
    for lane, reasons in record['reasons'].items():
        print('  ' + lane + ': ' + ', '.join(reasons))
    if record['deferred']:
        print('DEFERRED_TO_NIGHTLY: ' + ', '.join(record['deferred']))
    if record['delegated']:
        print('DELEGATED_TO_CALLER: ' + ', '.join(record['delegated']))
    summary = env.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as handle:
            handle.write('### CI selection\n\n| Lane | State | Reasons |\n|---|---|---|\n')
            for lane in sorted(policy['lanes']):
                state = ('SELECTED' if lane in record['lanes'] else 'DEFERRED_TO_NIGHTLY'
                         if lane in record['deferred'] else 'DELEGATED_TO_CALLER'
                         if lane in record['delegated'] else 'NOT_APPLICABLE')
                handle.write('| ' + lane + ' | ' + state + ' | '
                             + ', '.join(record['reasons'].get(lane, [])) + ' |\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
