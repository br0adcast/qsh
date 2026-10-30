"""Private fixed module-command binding, pending complete store observer work.

No store/configuration authority or scratch admission is implemented yet. This
partial library is not a CLI, package hook or independently usable observer.
"""
from qshd_selinux_process import _CommandError, _Limits, _Owner


_LIMITS = _Limits(15, 1024 * 1024)
_PREFIX = ('/usr/bin/semodule', '--store-path', '/var/lib/selinux', '-s', 'targeted')
_COMMANDS = {'list': _PREFIX + ('-lfull',),
             'extract': _PREFIX + ('-X', '400', '--hll', '-E', 'qshd')}


class _SemoduleOwner:
    """Only the future trusted observer selects these two fixed operations."""

    def __init__(self):
        self._owner = _Owner(_LIMITS)
        self._calls = 0

    @property
    def _last(self):
        return self._owner._last

    def _run(self, operation, cwd, *, deadline=None):
        if type(operation) is not str or operation not in _COMMANDS:
            raise _CommandError('COMMAND_KIND')
        if self._calls >= 4:
            raise _CommandError('COMMAND_BUDGET')
        self._calls += 1
        streams = self._owner._run(_COMMANDS[operation], cwd, deadline=deadline)
        if streams.stderr:
            raise _CommandError('COMMAND_STDERR')
        output = streams.stdout
        if operation == 'extract' and output:
            raise _CommandError('COMMAND_OUTPUT')
        return output
