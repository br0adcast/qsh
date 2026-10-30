"""Durable historical activation slot, never current-policy or package readiness.

Trusted callers perform the real load/observers/status checks before completion.
Existing protected directory/lock are required; no bootstrap, recovery, policy
call or context target registry is provided. Lock order is activation, context,
then one caller status window; retain exclusion through final publication.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import stat
import sys

import qshd_selinux_activation as model
from qshd_selinux_fs import Conflict, SafeFiles, decode, encode

LIMIT = 65536


class SlotError(Conflict):
    """Bounded slot category, without caller paths or document excerpts."""


class OutcomeUncertain(SlotError):
    """Completion replacement began; failure does not prove disk is PENDING."""


def _error(error, fallback='FILESYSTEM_REFUSED'):
    if isinstance(error, SlotError):
        raise error
    if isinstance(error, OSError):
        number = error.errno
        category = str(number) if type(number) is int and 0 <= number <= 4095 else 'INVALID'
        raise SlotError('FILESYSTEM_' + category) from None
    raise SlotError(fallback) from None


def _parse(data, kind=None):
    try:
        record = model.parse_activation(data)
    except model.ActivationError:
        raise SlotError('INVALID_DOCUMENT') from None
    if kind is not None and record.state != kind:
        raise SlotError('INVALID_STATE')
    return record


def _freeze(snapshot):
    return (snapshot['data'], tuple(snapshot['inode']), snapshot['uid'], snapshot['gid'],
            snapshot['mode'], tuple(sorted((name, decode(value)) for name, value in snapshot['xattrs'].items())),
            snapshot['mtime'], snapshot['ctime'])


def _thaw(snapshot):
    data, inode, uid, gid, mode, attrs, mtime, ctime = snapshot
    return dict(data=data, inode=list(inode), uid=uid, gid=gid, mode=mode,
                xattrs={name: encode(value) for name, value in attrs}, mtime=mtime, ctime=ctime)


@dataclass(frozen=True)
class SlotObservation:
    record: model.Activation | None
    document: bytes | None
    snapshot: tuple | None


@dataclass(frozen=True)
class _PendingToken:
    observation: SlotObservation


class _Reader:
    def __init__(self, slot):
        self._slot = slot
        self._active = True
        self._baseline = None

    def _live(self):
        if not self._active:
            raise SlotError('CLOSED_LEASE')

    def capture(self):
        self._live()
        if self._baseline is not None:
            raise SlotError('ALREADY_CAPTURED')
        self._baseline = self._slot._observe()
        return self._baseline

    def recheck(self, observation):
        self._live()
        if self._baseline is None or observation is not self._baseline:
            raise SlotError('FOREIGN_OBSERVATION')
        self._slot._recheck(observation)


class _Writer:
    def __init__(self, slot):
        self._slot = slot
        self._active = True
        self._phase = 'new'
        self._initial = None
        self._pending = None

    def _live(self):
        if not self._active:
            raise SlotError('CLOSED_LEASE')

    def capture_current(self):
        self._live()
        try:
            if self._phase != 'new':
                raise SlotError('WRITER_ORDER')
            self._initial = self._slot._observe()
            self._phase = 'captured'
            return self._initial
        except BaseException:
            self._phase = 'failed'
            raise

    def begin_pending(self, document, initial_baseline):
        self._live()
        try:
            if self._phase != 'captured' or initial_baseline is not self._initial:
                raise SlotError('WRITER_ORDER')
            self._phase = 'beginning'
            record = _parse(document, 'PENDING')
            if self._initial.record is not None and record.operation_id == self._initial.record.operation_id:
                raise SlotError('REUSED_OPERATION')
            observation = self._slot._publish(document, self._initial, lambda: None)
            self._pending = _PendingToken(observation)
            self._phase = 'pending'
            return self._pending
        except BaseException as error:
            self._phase = 'failed'
            if not isinstance(error, Exception):
                raise
            _error(error, 'PENDING_FAILED')

    def publish_complete(self, document, pending_token, *, trusted_artifact, trusted_context_binding):
        """Caller must finish the actual load and normal status finalization first."""
        self._live()
        replacement = False
        def boundary():
            nonlocal replacement
            replacement = True
        try:
            if self._phase != 'pending' or pending_token is not self._pending:
                raise SlotError('NO_FRESH_PENDING')
            self._phase = 'completing'
            complete = _parse(document, 'COMPLETE')
            pending = self._pending.observation.record
            fields = ('schema', 'profile', 'abi', 'query_profile', 'operation_id', 'artifact', 'module')
            if any(getattr(complete, key) != getattr(pending, key) for key in fields):
                raise SlotError('HEADER_MISMATCH')
            try:
                model.require_complete(complete, trusted_artifact, trusted_context_binding)
            except model.ActivationError:
                raise SlotError('INVALID_COMPLETION') from None
            result = self._slot._publish(document, self._pending.observation, boundary)
            self._phase = 'complete'
            return result
        except BaseException as error:
            self._phase = 'failed'
            if replacement:
                raise OutcomeUncertain('OUTCOME_UNCERTAIN') from None
            if not isinstance(error, Exception):
                raise
            _error(error, 'COMPLETION_FAILED')

    def observe_outcome(self):
        self._live()
        if self._phase != 'failed':
            raise SlotError('OUTCOME_NOT_AVAILABLE')
        return self._slot._observe()


class ActivationSlot(SafeFiles):
    """Trusted injected root seam; production() fixes the actual state path."""

    def __init__(self, state, *, uid=0, anchor=None, hook=None):
        try:
            self.state = Path(state)
            self.anchor = Path(anchor) if anchor is not None else self.state.parent
            for path in (self.state, self.anchor):
                if not path.is_absolute() or str(path) != os.path.normpath(str(path)) or '..' in path.parts:
                    raise SlotError('INVALID_PATH')
            self.state.relative_to(self.anchor)
        except (TypeError, ValueError):
            raise SlotError('INVALID_PATH') from None
        if type(uid) is not int or uid < 0:
            raise SlotError('INVALID_UID')
        if hook is not None and not callable(hook):
            raise SlotError('INVALID_HOOK')
        self.uid = uid
        self.hook = hook or (lambda event: None)
        self._busy = False

    def _validate(self):
        self._validate_directory_routes()
        self._dir_mode(self.state_fd)
        if stat.S_IMODE(os.fstat(self.state_fd).st_mode) != 0o700:
            raise SlotError('STATE_MODE')
        self._bound(self.state_fd, 'lock', self.lock_fd, state=True)

    def _once(self):
        self._validate()
        try:
            os.stat('activation.json', dir_fd=self.state_fd, follow_symlinks=False)
        except FileNotFoundError:
            observation = SlotObservation(None, None, None)
        else:
            snapshot = self._read(self.state_fd, 'activation.json', state=True, limit=LIMIT)
            observation = SlotObservation(_parse(snapshot['data']), snapshot['data'], _freeze(snapshot))
        self._validate()
        return observation

    def _observe(self):
        try:
            first = self._once()
            self.hook('observation_read')
            if self._once() != first:
                raise SlotError('SLOT_DRIFT')
            return first
        except Exception as error:
            _error(error)

    def _recheck(self, observation):
        if self._observe() != observation:
            raise SlotError('SLOT_DRIFT')

    def _publish(self, document, baseline, boundary):
        self._recheck(baseline)
        metadata = None if baseline.snapshot is None else _thaw(baseline.snapshot)
        stage = self._create(self.state_fd, document, metadata, state=True)
        self._stages[stage['name']] = stage
        self.hook('before_slot_rename')
        self._recheck(baseline)
        current = self._read(self.state_fd, stage['name'], state=True, limit=LIMIT)
        if not self._same(current, stage, times=True):
            raise SlotError('STAGE_CHANGED')
        self._validate()
        boundary()  # An attempted completion rename has an uncertain error outcome.
        os.rename(stage['name'], 'activation.json', src_dir_fd=self.state_fd, dst_dir_fd=self.state_fd)
        del self._stages[stage['name']]
        self.hook('slot_rename')
        os.fsync(self.state_fd)
        self.hook('slot_directory_sync')
        result = self._observe()
        if result.snapshot is None or not self._same(_thaw(result.snapshot), stage):
            raise SlotError('PUBLICATION_READBACK')
        self.hook('slot_readback')
        return result

    def _cleanup_stages(self):
        for name, stage in list(self._stages.items()):
            self._validate()
            try:
                os.stat(name, dir_fd=self.state_fd, follow_symlinks=False)
            except FileNotFoundError:
                del self._stages[name]
                continue
            current = self._read(self.state_fd, name, state=True, limit=LIMIT)
            if not self._same(current, stage, times=True):
                raise SlotError('STAGE_CLEANUP')
            os.unlink(name, dir_fd=self.state_fd)
            os.fsync(self.state_fd)
            del self._stages[name]

    @contextmanager
    def _lease(self, writer):
        if self._busy:
            raise SlotError('LEASE_ACTIVE')
        self._busy = True
        self.anchors, self.routes, self._stages = [], [], {}
        self.lock_fd = None
        facade = None
        try:
            try:
                self.state_fd = self._directory(self.state)
                if stat.S_IMODE(os.fstat(self.state_fd).st_mode) != 0o700:
                    raise SlotError('STATE_MODE')
                self.lock_fd = self._open(self.state_fd, 'lock', state=True)
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
                self._validate()
            except Exception as error:
                _error(error)
            facade = _Writer(self) if writer else _Reader(self)
            yield facade
            try:
                self._validate()
            except Exception as error:
                _error(error)
        finally:
            if facade is not None:
                facade._active = False
            original = sys.exc_info()[1]
            try:
                if self._stages:
                    try:
                        self._cleanup_stages()
                    except Exception:
                        if isinstance(original, OutcomeUncertain):
                            raise OutcomeUncertain('OUTCOME_UNCERTAIN_CLEANUP') from None
                        raise SlotError('STAGE_CLEANUP') from None
            finally:
                fds = set(self.anchors + [fd for route in self.routes for fd in (route[0], route[2])])
                if self.lock_fd is not None:
                    fds.add(self.lock_fd)
                close_failed = False
                for fd in fds:
                    try:
                        os.close(fd)
                    except OSError:
                        close_failed = True
                self.anchors, self.routes = [], []
                self._busy = False
                if close_failed:
                    if isinstance(original, OutcomeUncertain):
                        raise OutcomeUncertain('OUTCOME_UNCERTAIN_CLOSE') from None
                    raise SlotError('CLOSE_FAILED') from None

    def inspection(self):
        return self._lease(False)

    def writer(self):
        return self._lease(True)


def production():
    if os.geteuid() != 0:
        raise SlotError('ROOT_REQUIRED')
    return ActivationSlot('/var/lib/qshd/selinux-activation', anchor='/')
