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
from qshd_selinux_module_install import _close_routes, _DeadlineOwner
from qshd_selinux_files import PAM_SHA256
from qshd_selinux_registry import RegistryObservation
from qshd_selinux_transaction import ContextObservation


class CoordinatorError(RuntimeError):
    """Fixed phase category without private paths, PAM or tool diagnostics."""


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
            for path in ('/usr/bin/qshd','/etc/pam.d/qshd'):
                parent=self._parents[str(Path(path).parent)]
                try:os.stat(Path(path).name,dir_fd=parent,follow_symlinks=False)
                except FileNotFoundError:continue
                raise CoordinatorError('CONSUMER_EXISTS')
            return ('absent',)
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
        if self._state!='captured' or observed is not self._baseline:
            self._state='failed';raise CoordinatorError('CONSUMER_ORDER')
        self._state='failed'
        if self._sample()!=observed:raise CoordinatorError('CONSUMER_DRIFT')
        self._state='checked'


class _Production:
    def preconditions(self):
        from qshd_selinux_process import _preconditions
        if os.geteuid()!=0:raise CoordinatorError('ROOT_REQUIRED')
        _preconditions()

    def guard(self,deadline):
        import stop_guard
        from qshd_selinux_process import _Owner,_Limits
        owner=_Owner(_Limits(5,16384))
        def run():
            streams=owner._run(stop_guard.COMMAND,'/',deadline=deadline)
            outcome=owner._last
            if (outcome is None or outcome.failure is not None or outcome.exit_code!=0
                    or not outcome.settled or outcome.unreaped or streams.stderr):
                raise CoordinatorError('GUARD')
            return streams.stdout.decode('utf-8','strict')
        stop_guard.check(stop_guard.Host(),run,allow_absent=True)

    def package(self):
        from qshd_selinux_package_state import production
        return production().operation()
    def references(self):
        from qshd_selinux_reference_loader import production_references
        return production_references()
    def slot_object(self):
        from qshd_selinux_activation_state import production
        return production()
    def activation(self):return self.slot_object().writer()
    def policy_context(self,trust):
        from qshd_selinux_observer import _observe_policy_context
        return _observe_policy_context(trust)
    def consumer_paths(self,expected_pam,*,fresh):
        return _ConsumerPaths(expected_pam).inspection(fresh=fresh)


    def registry(self, *, deadline):
        from qshd_selinux_registry import production
        return production().inspection(deadline=deadline)
    def context_inspection(self,paths,identities):
        from qshd_selinux_transaction import production
        return production(paths).inspection(identities)
    def contexts(self,paths):
        from qshd_selinux_transaction import production
        return production(paths).writer()
    def reloader(self,trust,pp):
        from qshd_selinux_module_install import production_owned_reloader
        return production_owned_reloader(trust,pp)
    def modules(self,trust):
        from qshd_selinux_module_observer import production_observer
        return production_observer(trust)
    def window(self):
        from qshd_selinux_api import SelinuxApi
        from qshd_selinux_queries import required_observation
        self._api=SelinuxApi()
        return required_observation(self._api)
    def files(self,expected_pam):
        from qshd_selinux_files import production
        return production(expected_pam,self._api).inspection()


    def erase_files(self,expected_pam):
        from qshd_selinux_files import production
        return production(expected_pam,self._api).erase_inspection()

    def consumer_authority(self,deadline):
        from qshd_selinux_rpm_query import production_consumer_authority
        return production_consumer_authority().inspection(deadline=deadline)

    def rpm_query(self,deadline):
        from qshd_selinux_rpm_query import production_query
        return production_query().inspection(deadline=deadline)


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


class _Coordinator:
    """Private trusted test seam; no public path/tool/policy injection."""
    def __init__(self,bindings,*,clock=time.monotonic):
        self._bindings=bindings;self._clock=clock;self._used=False
        self._stage='INPUT';self._uncertain=False

    def _check(self,reserve=0):
        if self._clock()+reserve>=self._end:raise CoordinatorError('DEADLINE')

    def _start(self,deadline):
        if type(deadline) not in (int,float) or not math.isfinite(deadline):
            raise CoordinatorError('DEADLINE')
        self._end=min(deadline,self._clock()+240);self._check(70)
        self._stage='PROCESS';self._bindings.preconditions();self._check(70)
        self._stage='GUARD';self._bindings.guard(self._end);self._check(70)

    def _pending(self,trust):
        return model.Activation(1,'PENDING',secrets.token_hex(16),'fedora44-targeted-v1',1,1,
                                trust,model.ModuleIdentity('qshd',400,'targeted','pp'),None)

    def invalidate_installed_consumer_pre(self,*,fresh,deadline):
        if self._used:raise CoordinatorError('COORDINATOR_USED')
        self._used=True
        try:
            if type(fresh) is not bool:raise CoordinatorError('FRESH_MODE')
            self._start(deadline);b=self._bindings
            self._stage='PACKAGE'
            with b.package():
                self._check(70);self._stage='REFERENCES'
                with b.references() as references:
                    captured=references.capture();self._check(70)
                    self._stage='POLICY_CONTEXT'
                    observed=b.policy_context(captured.artifact);self._check()
                    if observed.profile!='fedora44-targeted-v1':raise CoordinatorError('PROFILE')
                    self._stage='CONSUMER'
                    with b.consumer_paths(captured.expected_pam,fresh=fresh) as paths:
                        consumer=paths.capture();self._check()
                        self._stage='ACTIVATION'
                        with b.activation() as writer:
                            current=writer.capture_current()
                            model.require_complete(current.record,captured.artifact,observed.contexts)
                            references.recheck(captured);paths.recheck(consumer);self._check()
                            self._stage='GUARD';b.guard(self._end);self._check(10)
                            pending=self._pending(captured.artifact);document=_json(asdict(pending))
                            self._stage='PENDING';self._uncertain=True
                            writer.begin_pending(document,current);self._check()
                        self._stage='READBACK'
                        with b.slot_object().inspection() as reader:
                            value=reader.capture();reader.recheck(value)
                            if value.record!=pending or value.document!=document:raise CoordinatorError('PENDING_READBACK')
                            self._check()
                        references.recheck(captured);self._check()
            self._check();return pending
        except BaseException as error:
            if self._uncertain:raise OutcomeUncertain('CONSUMER_OUTCOME_UNCERTAIN') from None
            if not isinstance(error,Exception) or isinstance(error,CoordinatorError):raise
            raise CoordinatorError(self._stage) from None


    def _routing(self,registry):
        routing=registry.routing()
        if type(routing) is not bytes or len(routing)>1024**2:raise CoordinatorError('ROUTING')
        identities=json.loads(routing)
        if type(identities) is not dict or not 0<len(identities)<=16 or _json(identities)!=routing:
            raise CoordinatorError('ROUTING')
        return routing,identities

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

    def _context_views(self,registry,contexts,routing,identities,*,recheck=True):
        self._check();discovered=registry.capture();context=contexts.capture()
        if (discovered.registry_bytes!=routing or context.registry_bytes!=routing
                or discovered.registry_sha256!=context.registry_sha256):
            raise CoordinatorError('CONTEXT_BINDING')
        self._owned(context,identities)
        if recheck:
            contexts.recheck(context);registry.recheck(discovered)
        self._check();return discovered,context

    def _readonly_owned(self):
        b=self._bindings;self._stage='PREFLIGHT'
        with b.registry(deadline=self._end) as registry:
            routing,identities=self._routing(registry);self._check(170)
            with b.context_inspection(sorted(identities),identities) as contexts:
                with b.window():
                    views=self._context_views(registry,contexts,routing,identities)
        self._check(170)
        return routing,identities,views

    def _admit_owned_erase(self,activation,trusted_artifact):
        """Read-only exact-owned admission under caller-held outer leases."""
        try:
            self._check(70)
            if type(trusted_artifact) is not model.TrustedArtifact:
                raise CoordinatorError('ERASE_TRUST')
            trusted_artifact.__post_init__()
            current=activation.capture_current()
            if (type(current) is not SlotObservation or type(current.record) is not model.Activation
                    or type(current.document) is not bytes):raise CoordinatorError('ERASE_SLOT')
            record=model.parse_activation(current.document)
            if record!=current.record or record.artifact!=trusted_artifact:
                raise CoordinatorError('ERASE_SLOT')
            b=self._bindings
            with b.registry(deadline=self._end) as registry:
                routing,identities=self._routing(registry);self._check(70)
                with b.context_inspection(sorted(identities),identities) as contexts:
                    self._check(70)
                    with b.modules(trusted_artifact) as modules:
                        if modules._owner is None:raise CoordinatorError('ERASE_MODULE_OWNER')
                        modules._owner=_DeadlineOwner(modules._owner,self._end-10)
                        with b.window():
                            discovered,context=self._context_views(registry,contexts,routing,identities,recheck=False)
                            self._check(70);module=modules.capture();self._check()
                            if module.hll.sha256!=trusted_artifact.pp_sha256:
                                raise CoordinatorError('ERASE_MODULE_BINDING')
                            modules.recheck(module)
                            contexts.recheck(context);registry.recheck(discovered);self._check()
                            if record.state=='COMPLETE':
                                binding=model.ContextBinding(context.registry_sha256,context.receipts_sha256)
                                model.require_complete(record,trusted_artifact,binding)
                            elif record.state!='PENDING' or record.completion is not None:
                                raise CoordinatorError('ERASE_SLOT')
            self._check()
            return _OwnedEraseAdmission(current,routing,discovered,context)
        except BaseException as error:
            if not isinstance(error,Exception) or isinstance(error,CoordinatorError):raise
            raise CoordinatorError('OWNED_ERASE_ADMISSION') from None

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

    def invalidate_installed_consumer_erase(self,*,deadline):
        if self._used:raise CoordinatorError('COORDINATOR_USED')
        self._used=True
        try:
            self._start(deadline);b=self._bindings;self._stage='PACKAGE'
            with b.package():
                self._stage='REFERENCES'
                with b.references() as references:
                    captured=references.capture();self._check(170)
                    self._stage='AUTHORITY'
                    with b.consumer_authority(self._end) as manifest:
                        authority=manifest.capture();self._erase_authority(authority,captured.expected_pam)
                        self._check(170);self._stage='RPM'
                        with b.rpm_query(self._end) as query:
                            self._check(170);owned=query.capture_owned(authority);self._check(130)
                            self._stage='ACTIVATION'
                            with b.activation() as writer:
                                self._check(130)
                                admission=self._admit_owned_erase(writer,captured.artifact);self._check(60)
                                self._stage='ERASE_FILES'
                                with b.window():
                                    with b.erase_files(captured.expected_pam) as deployed:
                                        paths=deployed.capture();self._erase_paths(paths,authority)
                                        references.recheck(captured);manifest.recheck(authority);self._check(60)
                                        self._stage='RPM_RECHECK';query.recheck(owned);self._check()
                                        self._stage='GUARD';b.guard(self._end);self._check()
                                        deployed.recheck(paths);self._check()
                                references.recheck(captured);manifest.recheck(authority);self._check(10)
                                pending=self._pending(captured.artifact)
                                if pending.operation_id==admission.slot.record.operation_id:
                                    raise CoordinatorError('ERASE_OPERATION')
                                document=_json(asdict(pending));self._stage='PENDING';self._uncertain=True
                                writer.begin_pending(document,admission.slot);self._check()
                            self._stage='READBACK'
                            with b.slot_object().inspection() as reader:
                                value=reader.capture();reader.recheck(value)
                                if value.record!=pending or value.document!=document:
                                    raise CoordinatorError('PENDING_READBACK')
                                self._check()
                            references.recheck(captured);manifest.recheck(authority);self._check()
            self._check();return pending
        except BaseException as error:
            if self._uncertain:raise OutcomeUncertain('CONSUMER_OUTCOME_UNCERTAIN') from None
            if not isinstance(error,Exception) or isinstance(error,CoordinatorError):raise
            raise CoordinatorError(self._stage) from None

    def finalize_installed_owned_pending_consumer(self,*,deadline):
        if self._used:raise CoordinatorError('COORDINATOR_USED')
        self._used=True
        try:
            self._start(deadline);b=self._bindings;self._stage='PACKAGE'
            with b.package():
                self._check(170);self._stage='REFERENCES'
                with b.references() as references:
                    captured=references.capture();self._check(170)
                    self._stage='ACTIVATION'
                    with b.activation() as activation:
                        current=activation.capture_current();record=current.record
                        if (record is None or record.state!='PENDING' or record.artifact!=captured.artifact):
                            raise CoordinatorError('MATCHING_PENDING_REQUIRED')
                        routing,identities,preflight=self._readonly_owned()
                        # Preflight is fully closed. Cooperating writers remain
                        # excluded by package+activation; arbitrary root races are
                        # outside the documented administrator maintenance boundary.
                        self._stage='OWNED_CONTEXTS'
                        with b.contexts(sorted(identities)) as writer:
                            with b.registry(deadline=self._end) as registry:
                                if self._routing(registry)!=(routing,identities):raise CoordinatorError('ROUTING_DRIFT')
                                with writer.inspection(identities) as contexts:
                                    with b.window():
                                        borrowed=self._context_views(registry,contexts,routing,identities)
                                        if borrowed!=preflight:raise CoordinatorError('OWNED_STATE_DRIFT')
                            self._check(170);references.recheck(captured)
                            self._stage='GUARD';b.guard(self._end);self._check(170)
                            pending=self._pending(captured.artifact);self._stage='PENDING'
                            token=activation.begin_pending(_json(asdict(pending)),current)
                            self._stage='RELOAD';self._check(170)
                            loaded=b.reloader(captured.artifact,captured.pp_bytes).reload(deadline=self._end)
                            if loaded.artifact!=captured.artifact or loaded.pp_sha256!=captured.artifact.pp_sha256:
                                raise CoordinatorError('RELOAD_BINDING')
                            self._check(60);self._stage='OBSERVATION'
                            with b.registry(deadline=self._end) as registry:
                                if self._routing(registry)!=(routing,identities):raise CoordinatorError('ROUTING_DRIFT')
                                with writer.inspection(identities) as contexts:
                                    with b.modules(captured.artifact) as modules:
                                        with b.window():
                                            with b.files(captured.expected_pam) as deployed:
                                                discovered,context=self._context_views(registry,contexts,routing,identities,recheck=False)
                                                module=modules.capture();paths=deployed.capture();self._check()
                                                if ((discovered,context)!=preflight or module.hll.sha256!=captured.artifact.pp_sha256):
                                                    raise CoordinatorError('POST_BINDING')
                                                deployed.recheck(paths);modules.recheck(module)
                                                contexts.recheck(context);registry.recheck(discovered);self._check()
                            references.recheck(captured);self._check(10)
                            binding=model.ContextBinding(context.registry_sha256,context.receipts_sha256)
                            complete=replace(pending,state='COMPLETE',completion=model.Completion(
                                'normal-install-reload-v1',module.hll.sha256,binding))
                            self._stage='COMPLETE';self._uncertain=True
                            try:
                                result=activation.publish_complete(_json(asdict(complete)),token,
                                    trusted_artifact=captured.artifact,trusted_context_binding=binding)
                            except OutcomeUncertain:raise
                            except SlotError:
                                self._uncertain=False;raise
                            model.require_complete(result.record,captured.artifact,binding)
                            result=result.record;self._check()
            self._check();return result
        except BaseException as error:
            if self._uncertain:raise OutcomeUncertain('CONSUMER_OUTCOME_UNCERTAIN') from None
            if not isinstance(error,Exception) or isinstance(error,CoordinatorError):raise
            raise CoordinatorError(self._stage) from None
