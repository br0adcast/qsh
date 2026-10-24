"""Bounded diagnostics for a timed-out fixture's still-owned Linux process tree."""
import itertools
import os
from pathlib import Path
import shutil

MAX_PROCESSES = 8
MAX_DEPTH = 6
MAX_TASKS = 16
MAX_CHILDREN = 32


def _read(path, limit=4096):
    with path.open('r', encoding='utf-8', errors='replace') as source:
        return source.read(limit)


def _stat(proc, pid):
    text = _read(proc / str(pid) / 'stat')
    fields = text[text.rindex(')') + 2:].split()
    return {'pid': pid, 'state': fields[0], 'parent': int(fields[1]),
            'group': int(fields[2]), 'session': int(fields[3]),
            'user_ticks': int(fields[11]), 'system_ticks': int(fields[12]),
            'started': int(fields[19])}


def _same_process(first, second):
    return all(first[key] == second[key] for key in ('pid', 'parent', 'started'))


def timeout_snapshot(pid, command, env, fixture, checkout, *, proc=Path('/proc')):
    """Read only descendants of an unreaped Popen child; never argv or environ.

    The caller retains that child through diagnostics and cancellation. Recheck
    parent/start identities before recording each descendant, so exited/reused
    PIDs cannot redirect inspection to another process. Missing/raced branches
    are omitted explicitly; this is a bounded observation, not custody proof.
    """
    roots = [(str(Path(fixture)), '<fixture>'), (str(Path(checkout)), '<checkout>'),
             (str(Path.home()), '<home>')]

    def clean(value):
        for prefix, label in sorted(roots, key=lambda pair: -len(pair[0])):
            if prefix != '/':
                value = value.replace(prefix, label)
        return ''.join(char if char.isprintable() else '?' for char in value)[:256]

    def tool(name):
        path = shutil.which(name, path=env.get('PATH', os.defpath))
        if path is None:
            return {'status': 'not found'}
        try:
            resolved = Path(path).resolve(strict=True)
            info = resolved.stat()
            return {'path': clean(str(Path(path).absolute())), 'resolved': clean(str(resolved)),
                    'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size}
        except (OSError, RuntimeError):
            return {'path': clean(path), 'status': 'unavailable'}

    tools = {}
    for name in ('cc', 'ar', 'ranlib'):
        selected = name
        if name == 'cc' and '--target' in command:
            target_index = command.index('--target') + 1
            if target_index < len(command) and command[target_index].endswith('-musl'):
                selected = 'musl-gcc'
        option = '--' + name
        if option in command and command.index(option) + 1 < len(command):
            selected = command[command.index(option) + 1]
        tools['selected_' + name] = tool(selected)
        tools['path_' + name] = tool(name)

    result = {'tools': tools, 'processes': [], 'process_status': 'bounded owned snapshot'}
    pending = [(pid, [])]
    limited = False
    while pending and len(result['processes']) < MAX_PROCESSES:
        current, ancestors = pending.pop(0)
        try:
            if any(not _same_process(parent, _stat(proc, parent['pid'])) for parent in ancestors):
                continue
            before = _stat(proc, current)
            if ancestors and before['parent'] != ancestors[-1]['pid']:
                continue
            try:
                executable = clean(os.readlink(proc / str(current) / 'exe'))
            except OSError:
                executable = 'unavailable'
            try:
                wait = clean(_read(proc / str(current) / 'wchan', 80).strip())
            except OSError:
                wait = 'unavailable'
            children = []
            tasks = proc / str(current) / 'task'
            with os.scandir(tasks) as entries:
                for index, entry in enumerate(itertools.islice(entries, MAX_TASKS + 1)):
                    if index == MAX_TASKS:
                        limited = True
                        break
                    if len(children) >= MAX_CHILDREN:
                        limited = True
                        break
                    if not entry.name.isdigit():
                        continue
                    found = _read(Path(entry.path) / 'children', 512).split()
                    remaining = MAX_CHILDREN - len(children)
                    if len(found) > remaining:
                        limited = True
                    children.extend(int(child) for child in found[:remaining] if child.isdigit())
            if not _same_process(before, _stat(proc, current)):
                continue
            if any(not _same_process(parent, _stat(proc, parent['pid'])) for parent in ancestors):
                continue
            result['processes'].append(dict(before, executable=executable, wait=wait))
            if len(ancestors) < MAX_DEPTH:
                pending.extend((child, ancestors + [before]) for child in dict.fromkeys(children[:MAX_CHILDREN]))
            elif children:
                limited = True
        except (OSError, ValueError, IndexError):
            # The owner may exit while being sampled; never replace it by a
            # global /proc search, and never make diagnostics a cleanup error.
            continue
    if pending or limited:
        result['process_status'] = 'bounded owned snapshot; process/depth limit reached'
    if not result['processes']:
        result['process_status'] = 'owned root unavailable or changed during snapshot'
    return result
