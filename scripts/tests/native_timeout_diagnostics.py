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


def _fd_metadata(directory, number, clean):
    """Only the selected fd's link and whitelisted numeric fdinfo, never data."""
    def info():
        result = {}
        for line in _read(directory / 'fdinfo' / str(number), 512).splitlines():
            key, separator, value = line.partition(':')
            if separator and key in ('pos', 'flags', 'mnt_id', 'ino'):
                try:
                    result[key] = int(value.strip(), 8 if key == 'flags' else 10)
                except ValueError:
                    pass
        return result

    try:
        target = os.readlink(directory / 'fd' / str(number))
        metadata = info()
        if target != os.readlink(directory / 'fd' / str(number)) or metadata != info():
            return {'number': number, 'status': 'changed during snapshot'}
        return {'number': number, 'target': clean(target), 'metadata': metadata}
    except OSError:
        return {'number': number, 'status': 'unavailable'}


def _syscall(directory, clean):
    """Decode only Linux x86-64 ELF64, verified from 20 bytes of ELF metadata.

    /proc/PID/syscall contains nr, six argument registers, SP and PC, or a
    running/outside-syscall marker. Do not emit registers or dereference any
    pointer. The table is a small subset of Linux's x86 syscall_64.tbl:
    https://github.com/torvalds/linux/blob/v6.17/arch/x86/entry/syscalls/syscall_64.tbl
    Other executable ABIs (including x32/i386/AArch64) retain the number only.
    ELF64 alone cannot identify a deliberately invoked compat syscall entry;
    decoding assumes the normal native entry used by the GNU tools here.
    Fd paths describe the observed fd table, not a proof of the kernel's held
    file reference; concurrent close/reopen cannot be ruled out by procfs.
    """
    try:
        original = _read(directory / 'syscall', 256).strip()
        if original == 'running':
            return {'status': 'running; no stable syscall'}
        fields = original.split()
        number = int(fields[0], 10)
        result = {'number': number}
        if number == -1:
            return dict(result, status='outside syscall; registers omitted')
        if len(fields) != 9 or number < 0:
            return {'status': 'unavailable or malformed syscall'}
        # This is executable format metadata, not syscall buffer/file contents.
        try:
            with (directory / 'exe').open('rb') as executable:
                elf = executable.read(20)
        except OSError:
            return dict(result, status='unsupported or unavailable executable ABI; fd not decoded')
        if len(elf) != 20 or elf[:7] != b'\x7fELF\x02\x01\x01' or elf[18:20] != b'\x3e\x00':
            return dict(result, status='unsupported or unavailable executable ABI; fd not decoded')
        result['abi'] = 'Linux x86_64 ELF64'
        result['abi_note'] = 'fd decoding assumes native syscall entry'
        # Each tuple is (name, zero-based argument containing one fd).
        calls = {0: ('read', 0), 1: ('write', 0), 5: ('fstat', 0),
                 8: ('lseek', 0), 9: ('mmap', 4), 16: ('ioctl', 0),
                 17: ('pread64', 0), 18: ('pwrite64', 0),
                 19: ('readv', 0), 20: ('writev', 0), 72: ('fcntl', 0),
                 74: ('fsync', 0), 75: ('fdatasync', 0), 77: ('ftruncate', 0)}
        # openat's dirfd may be ignored for an absolute pathname. Without
        # reading the pathname buffer, relevance cannot be established.
        if number not in calls:
            return dict(result, status='syscall not in fd decoder subset')
        name, argument = calls[number]
        result['name'] = name
        # Linux x86-64 MAP_ANONYMOUS: fd is ignored even when it is positive.
        if number == 9 and int(fields[4], 0) & 0x20:
            return dict(result, status='anonymous mmap; fd is ignored')
        descriptor = int(fields[1 + argument], 0)
        # Negative/special values are not fd numbers.
        if not 0 <= descriptor < 2 ** 31:
            return dict(result, status='special or invalid fd; path not sampled')
        metadata = _fd_metadata(directory, descriptor, clean)
        if original != _read(directory / 'syscall', 256).strip():
            return dict(result, status='changed during snapshot; fd metadata omitted')
        result['descriptor'] = metadata
        return result
    except (OSError, ValueError, IndexError):
        return {'status': 'syscall or executable ABI unavailable'}


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
            syscall = _syscall(proc / str(current), clean)
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
            result['processes'].append(dict(before, executable=executable, wait=wait, syscall=syscall))
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
