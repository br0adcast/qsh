"""Installed consumer phases; historical observations, never future admission.

Caller drains/stops daemons, prevents starts and excludes privileged writers.
Run in a fresh bounded root child with an external hard deadline; library clock
checks cannot interrupt filesystem/native calls. No PAM migration or repair.
"""
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import time

import qshd_selinux_activation as model
from qshd_selinux_activation_state import OutcomeUncertain, SlotError, SlotObservation
from qshd_selinux_fs import SafeFiles
from qshd_selinux_module_install import _close_routes
from qshd_selinux_files import PAM_SHA256
from qshd_selinux_registry import RegistryObservation
from qshd_selinux_transaction import ContextObservation
from qshd_selinux_first_activation import (RuntimeBindings, _Coordinator as _PairCoordinator,
    CoordinatorError)


def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


class _ConsumerPaths:
    """Fixed bounded public PAM/absence inspection; private roots for tests."""
    def __init__(self,expected_pam,*,_root='/',_uid=0):
        if (type(expected_pam) is not bytes or not 0<len(expected_pam)<=65536
                or hashlib.sha256(expected_pam).hexdigest()!=PAM_SHA256):
            raise CoordinatorError('EXPECTED_PAM')
        self._pam=expected_pam;self._root=Path(_root);self._uid=_uid;self._active=False

    @contextmanager
    def inspection(self,*,fresh):
        if type(fresh) is not bool or self._active:raise CoordinatorError('CONSUMER_LEASE')
        self._active=True;reader=_ConsumerReader(self,fresh)
        try:
            reader._setup()
            yield reader
            if reader._state!='checked':raise CoordinatorError('CONSUMER_RECHECK')
        finally:
            reader._state='closed'
            try:_close_routes(reader)
            finally:self._active=False


class _ConsumerReader(SafeFiles):
    def __init__(self,paths,fresh):
        self.anchor=paths._root;self.uid=paths._uid;self._pam=paths._pam;self._fresh=fresh
        self.anchors=[];self.routes=[];self.hook=lambda event:None
        self._state='open';self._baseline=None;self._parents={}

    def _setup(self):
        for path in ('/usr/bin','/etc/pam.d'):
            self._parents[path]=self._directory(self.anchor/path[1:])

    def _sample(self):
        self._validate_directory_routes()
        if self._fresh:
            for path in ('/usr/bin/qshd','/etc/pam.d/qshd','/etc/pam.d/qshd.rpmnew','/etc/pam.d/qshd.rpmsave'):
                parent=self._parents[str(Path(path).parent)]
                try:os.stat(Path(path).name,dir_fd=parent,follow_symlinks=False)
                except FileNotFoundError:continue
                raise CoordinatorError('CONSUMER_EXISTS')
            return ('absent',)
        for name in ('qshd.rpmnew','qshd.rpmsave'):
            try:os.stat(name,dir_fd=self._parents['/etc/pam.d'],follow_symlinks=False)
            except FileNotFoundError:continue
            raise CoordinatorError('CONSUMER_SIDECAR')
        value=self._read(self._parents['/etc/pam.d'],'qshd',limit=65536)
        if (value['data']!=self._pam or value['mode']&0o7000
                or value['mode']&0o022 or not value['mode']&0o400):
            raise CoordinatorError('PAM_AUTHORITY')
        return value

    def capture(self):
        if self._state!='open':raise CoordinatorError('CONSUMER_ORDER')
        self._state='failed';self._baseline=self._sample();self._state='captured'
        return self._baseline

    def recheck(self,observed):
        if self._state not in ('captured','checked') or observed is not self._baseline:
            self._state='failed';raise CoordinatorError('CONSUMER_ORDER')
        self._state='failed'
        if self._sample()!=observed:raise CoordinatorError('CONSUMER_DRIFT')
        self._state='checked'




class _Production(RuntimeBindings):
    def package(self):return self.package_operation()


def invalidate_installed_consumer_pre(*,fresh,deadline):
    """Matching COMPLETE to fresh PENDING; no payload mutation or migration.

    Failure after publication attempt is outcome-uncertain, including normal
    finalizer/deadline failure. Earlier refusal may leave preexisting state.
    """
    return _Coordinator(_Production()).invalidate_installed_consumer_pre(fresh=fresh,deadline=deadline)


def finalize_installed_owned_pending_consumer(*,deadline):
    """Requalify exact owned PENDING; never reconcile, adopt or repair.

    Caller supplies external maintenance exclusion and a hard process owner.
    A failed phase may leave PENDING or loaded policy; possible COMPLETE plus
    any later failure is OutcomeUncertain. No rollback or retry is performed.
    """
    return _Coordinator(_Production()).finalize_installed_owned_pending_consumer(deadline=deadline)


def invalidate_installed_consumer_erase(*,deadline):
    """Fresh PENDING before canonical owned consumer removal, never payload erase.

    Caller retains maintenance exclusion and an external hard process owner.
    Any failure after the publication attempt is outcome-uncertain.
    """
    return _Coordinator(_Production()).invalidate_installed_consumer_erase(deadline=deadline)


@dataclass(frozen=True)
class _OwnedEraseAdmission:
    """Closed immutable views, not permission for start or module removal.

    Only the exact slot object may be used with the same still-live activation
    writer. The other observations are full comparison evidence from closed
    leases, not live recheck tokens or a durable authority record.
    """
    slot: SlotObservation
    routing: bytes
    registry: RegistryObservation
    contexts: ContextObservation


class _Coordinator(_PairCoordinator):
    """Consumer transitions reuse the one pair admission and original phase end."""
    def invalidate_installed_consumer_pre(self,*,fresh,deadline):
        if type(fresh) is not bool:
            self._used=True;raise CoordinatorError('FRESH_MODE')
        return self._invalidate_owned(None,deadline=deadline,intent='consumer-install',fresh=fresh)

    def finalize_installed_owned_pending_consumer(self,*,deadline):
        return self._activate_owned(deadline=deadline,intent='consumer-install')

    def invalidate_installed_consumer_erase(self,*,deadline):
        return self._invalidate_owned(None,deadline=deadline,intent='consumer-erase',fresh=False)

    def _admit_owned_erase(self,activation,trusted_artifact):
        """Current owned pair proof; PENDING needs an explicit admitted basis."""
        try:
            self._check(140);current=activation.capture_current();record=current.record
            if type(record) is not model.Activation or record.artifact!=trusted_artifact:
                raise CoordinatorError('ERASE_SLOT')
            if record.state=='PENDING':
                if (record.intent not in ('consumer-install','consumer-erase')
                        or type(record.basis) is not model.HistoricalBasis
                        or record.basis.artifact!=trusted_artifact):raise CoordinatorError('ERASE_SLOT')
                completion=record.basis.completion
            else:completion=record.completion
            b=self._bindings
            with b.registry() as registry:
                routing,identities=self._routing(registry);self._check(140)
                with b.context_inspection(sorted(identities),identities) as contexts:
                    with b.retained(deadline=self._end) as retained:
                        with b.modules(trusted_artifact,deadline=self._end) as modules:
                            with b.window() as status:
                                with b.queries(status):
                                    discovered,context=self._views(registry,contexts,routing,owned=True)
                                    binding=model.ContextBinding(context.registry_sha256,context.receipts_sha256)
                                    if completion.contexts!=binding:raise CoordinatorError('ERASE_CONTEXTS')
                                    if record.state=='COMPLETE':model.require_complete(record,trusted_artifact,binding)
                                    labels=retained.capture(status=status);module=modules.capture();self._pair(module,trusted_artifact)
                                    retained.recheck(labels,status=status);modules.recheck(module)
                                    contexts.recheck(context);registry.recheck(discovered)
            self._check();return _OwnedEraseAdmission(current,routing,discovered,context)
        except BaseException as error:
            if not isinstance(error,Exception) or isinstance(error,CoordinatorError):raise
            raise CoordinatorError('OWNED_ERASE_ADMISSION') from error

    def _owned(self,context,identities):
        receipts=json.loads(context.receipts_bytes)
        if type(receipts) is not dict or set(receipts)!=set(identities):
            raise CoordinatorError('RECEIPT_KEYS')
        for name,identity in identities.items():
            receipt=receipts[name]
            if (type(receipt) is not dict or receipt.get('owner')!='qshd'
                    or receipt.get('identity')!=identity):raise CoordinatorError('CONTEXT_NOT_OWNED')
        # The retained inspection has already checked exact source/block/current
        # semantics. Never treat administrator or receipt-free current rows as ours.

    def _erase_authority(self,authority,expected_pam):
        from qshd_selinux_rpm_query import ConsumerRpmAuthority
        if type(authority) is not ConsumerRpmAuthority:
            raise CoordinatorError('ERASE_AUTHORITY')
        authority.__post_init__()
        if authority.package.arch not in ('x86_64','aarch64'):
            raise CoordinatorError('ERASE_ARCH')
        selected={item.path:item for item in authority.files}
        binary=selected['/usr/bin/qshd'];pam=selected['/etc/pam.d/qshd']
        if (binary.mode!=0o100755 or binary.flags!=0 or not 0<binary.size<=128*1024**2
                or pam.mode!=0o100644 or pam.flags!=17 or pam.size!=len(expected_pam)
                or pam.sha256!=PAM_SHA256 or hashlib.sha256(expected_pam).hexdigest()!=PAM_SHA256
                or any(item.owner!='root' or item.group!='root' for item in authority.files)):
            raise CoordinatorError('ERASE_AUTHORITY')

    def _erase_paths(self,observed,authority):
        from qshd_selinux_files import FilesObservation
        if type(observed) is not FilesObservation or observed.phase!='consumer-erase':
            raise CoordinatorError('ERASE_FILES')
        for item in authority.files:
            selected=[value for value in observed.paths if value.path==item.path]
            if len(selected)!=1:raise CoordinatorError('ERASE_FILES')
            value=selected[0];metadata=value.metadata
            if (not value.present or metadata is None
                    or (metadata[2],metadata[3],metadata[4],metadata[6])!=(0,0,item.mode,item.size)
                    or (item.path=='/etc/pam.d/qshd' and value.pam_sha256!=item.sha256)):
                raise CoordinatorError('ERASE_FILES')
