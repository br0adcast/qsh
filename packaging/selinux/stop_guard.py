#!/usr/bin/python3
"""Read-only Fedora 44 managed-unit observation, not a lock or daemon inventory.

Administrators must drain/stop manual daemons and prevent concurrent starts.
Synthetic tests do not qualify the installed Fedora manager or package lifecycle.
"""
import argparse
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

LIMIT = 16384
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID',
              'ControlPID', 'ControlGroup', 'Slice', 'Job')
COMMAND = ('/usr/bin/systemctl', '--system', '--no-pager', 'show', 'qshd.service',
           '--property=' + ','.join(PROPERTIES))
PHASES = ('provider-pre', 'consumer-pre', 'provider-preun')


class Refusal(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def canonical_records(text, allow_tab=False):
    require(len(text) <= LIMIT and text.endswith('\n') and
            all(c == '\n' or 32 <= ord(c) < 127 or (allow_tab and c == '\t')
                for c in text), 'incomplete or noncanonical record output')
    return text[:-1].split('\n')


def snapshot(text, allow_absent=False):
    values = {}
    for line in canonical_records(text):
        key, sep, value = line.partition('=')
        require(sep and key in PROPERTIES and key not in values, 'ambiguous property output')
        values[key] = value
    require(set(values) == set(PROPERTIES), 'missing properties')
    require(values['Id'] == 'qshd.service', 'unsupported unit identity')
    for key in ('MainPID', 'ControlPID'):
        require(re.fullmatch(r'0|[1-9][0-9]*', values[key]) is not None, 'invalid PID')
        require(values[key] == '0', 'unit still has a PID')
    require(values['Job'] == '', 'unit has a job or noncanonical Job encoding')
    require(values['ControlGroup'] in ('', '/system.slice/qshd.service'), 'unsupported cgroup')
    if values['LoadState'] == 'not-found':
        require(allow_absent and values['ActiveState'] == 'inactive' and
                values['SubState'] == 'dead' and values['ControlGroup'] == '' and
                values['Slice'] == '', 'unit absence is not permitted or canonical')
    else:
        require(values['LoadState'] in ('loaded', 'masked'), 'unsupported load state')
        require((values['ActiveState'], values['SubState']) in
                (('inactive', 'dead'), ('failed', 'failed')), 'unit is not stopped')
        require(values['Slice'] == 'system.slice', 'unsupported slice')
    return values


def events(text):
    values = {}
    for line in canonical_records(text):
        parts = line.split(' ')
        require(len(parts) == 2 and parts[0] in ('populated', 'frozen') and
                parts[0] not in values and parts[1] in ('0', '1'), 'invalid cgroup events')
        values[parts[0]] = parts[1]
    require(values.get('populated') == '0', 'cgroup or descendants are populated')


def mount(text):
    mounts = []
    for line in canonical_records(text):
        fields = line.split()
        require(len(fields) >= 10 and '-' in fields, 'invalid mountinfo')
        split = fields.index('-')
        require(split >= 6 and len(fields) == split + 4, 'invalid mountinfo fields')
        target = fields[4]
        require('\\' not in target, 'unsupported escaped mount path')
        if fields[split+1] == 'cgroup':
            raise Refusal('cgroup v1/hybrid is unsupported')
        if target == '/sys/fs/cgroup' or target.startswith('/sys/fs/cgroup/'):
            mounts.append((fields, split))
    require(len(mounts) == 1, 'missing, duplicate or overmounted cgroup hierarchy')
    fields, split = mounts[0]
    require(fields[4] == '/sys/fs/cgroup' and fields[3] == '/' and
            fields[split+1] == 'cgroup2' and fields[0].isdigit(), 'unsupported cgroup mount')
    return int(fields[0])


def read_fd(fd):
    data = bytearray()
    while True:
        part = os.read(fd, min(4096, LIMIT + 1 - len(data)))
        if not part:
            break
        data.extend(part)
        require(len(data) <= LIMIT, 'file exceeds size bound')
    return data.decode('utf-8', errors='strict')


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        return read_fd(fd)
    finally:
        os.close(fd)


def mount_id(fd):
    records = [line for line in canonical_records(read(f'/proc/self/fdinfo/{fd}'), allow_tab=True)
               if line.startswith('mnt_id:')]
    require(len(records) == 1, 'missing descriptor mount identity')
    return int(records[0].split(':', 1)[1])


class Cgroup:
    """Fixed component descent; constructor injection is an API-only test seam."""
    def __init__(self, root, identity, expected):
        self.root, self.identity, self.expected = root, identity, expected

    def empty(self):
        opened = []
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(self.root, flags)
            opened.append(fd)
            require(self.identity(fd) == self.expected, 'foreign cgroup mount')
            for component in ('system.slice', 'qshd.service'):
                try:
                    fd = os.open(component, flags, dir_fd=fd)
                except FileNotFoundError:
                    # No absent-system.slice runtime qualification exists yet.
                    require(component == 'qshd.service', 'system.slice is absent')
                    return
                opened.append(fd)
                require(self.identity(fd) == self.expected, 'overmounted cgroup directory')
            event_fd = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW |
                               os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
            opened.append(event_fd)
            require(self.identity(event_fd) == self.expected, 'foreign events mount')
            events(read_fd(event_fd))
        except OSError as exc:
            raise Refusal(f'cannot inspect canonical cgroup (errno {exc.errno})') from exc
        finally:
            for fd in reversed(opened):
                os.close(fd)


def run_command(command=COMMAND, timeout=5):
    """Only production caller uses fixed COMMAND; tests inject harmless commands."""
    env = {'PATH': '/usr/sbin:/usr/bin', 'LANG': 'C', 'LC_ALL': 'C',
           'SYSTEMD_COLORS': '0', 'SYSTEMD_URLIFY': '0', 'SYSTEMD_PAGER': ''}
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=env) as process:
        selector = selectors.DefaultSelector()
        data = {process.stdout: bytearray(), process.stderr: bytearray()}
        for pipe in data:
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'systemctl timeout')
                for key, _ in selector.select(remaining):
                    part = os.read(key.fd, 4096)
                    if part:
                        data[key.fileobj].extend(part)
                        require(sum(map(len, data.values())) <= LIMIT, 'systemctl output bound exceeded')
                    else:
                        selector.unregister(key.fileobj)
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'systemctl timeout')
            try:
                status = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise Refusal('systemctl timeout') from exc
            require(status == 0 and not data[process.stderr], 'systemctl failed or wrote stderr')
            return bytes(data[process.stdout]).decode('utf-8', errors='strict')
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
                process.wait()


class Host:
    def preflight(self):
        require(os.geteuid() == 0, 'root is required')
        release = read('/usr/lib/os-release')
        require(re.search(r'^ID=[\"\']?fedora[\"\']?$', release, re.M) and
                re.search(r'^VERSION_ID=[\"\']?44[\"\']?$', release, re.M), 'Fedora 44 is required')
        require(Path('/run/systemd/system').is_dir() and
                not Path('/run/systemd/container').exists(), 'unsupported system manager environment')
        require(os.readlink('/proc/1/exe') == '/usr/lib/systemd/systemd', 'PID 1 is not the supported systemd')
        require(os.stat('/') == os.stat('/proc/1/root'), 'foreign root')
        for namespace in ('mnt', 'pid', 'user'):
            require(os.stat('/proc/self/ns/'+namespace) == os.stat('/proc/1/ns/'+namespace), 'foreign namespace')
        self.cgroup = Cgroup('/sys/fs/cgroup', mount_id, mount(read('/proc/self/mountinfo')))

    def empty(self):
        self.cgroup.empty()


def check(evidence, runner, allow_absent=False):
    evidence.preflight()
    first = snapshot(runner(), allow_absent)
    evidence.empty()
    second = snapshot(runner(), allow_absent)
    require(first == second, 'unit changed between observations')
    evidence.empty()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=PHASES, required=True)
    parser.add_argument('--allow-unit-absent', action='store_true')
    args = parser.parse_args()
    try:
        check(Host(), run_command, args.allow_unit_absent)
    except (Refusal, OSError, ValueError, UnicodeError) as exc:
        print(f'qshd stop guard ({args.phase}) refused: {exc}. Drain and stop managed and manual daemons and prevent starts through the transaction; this observation is not a lock.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
