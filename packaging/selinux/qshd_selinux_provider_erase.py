"""Ordered installed pair erasure under one original maintenance owner.

The caller excludes starts and privileged writers and supplies the hard owner.
Erasure is historical completion, never installation or readiness authority.
"""
from contextlib import ExitStack
from dataclasses import asdict, dataclass
import hashlib
import json
import re

from qshd_selinux_activation import TrustedArtifact, HistoricalBasis, ContextBinding, require_complete
from qshd_selinux_activation_state import SlotError, OutcomeUncertain, SlotObservation
from qshd_selinux_first_activation import (RuntimeBindings, _Coordinator as _PairCoordinator,
    CoordinatorError, _pending, _json)


@dataclass(frozen=True)
class ErasureResult:
    operation_id: str
    artifact: TrustedArtifact
    result: str = 'ERASED'

    def __post_init__(self):
        if (type(self.operation_id) is not str or re.fullmatch('[0-9a-f]{32}',self.operation_id) is None
                or type(self.artifact) is not TrustedArtifact or self.result!='ERASED'
                or type(self.result) is not str):raise ValueError('ERASURE_RESULT')
        self.artifact.__post_init__()


class _Production(RuntimeBindings):
    def removal_session(self,captured,*,deadline):
        from qshd_selinux_module_install import production_removal_session
        return production_removal_session(captured.artifact,captured.core_pp_bytes,
            captured.contexts_pp_bytes,deadline=deadline)

    def retained_erase(self,*,deadline):
        from qshd_selinux_retained_labels import production
        return production().inspection(deadline=deadline)


def erase_installed_provider(*,deadline):
    return _Coordinator(_Production()).erase_installed_provider(deadline=deadline)


def _bind_removed_registry(before,after,removed,identities):
    """Bind exact historical B/current C to the live writer's checked removal.

    The caller brackets this bridge with that same writer's recheck_removed;
    this is neither a transferable certificate nor arbitrary-record authority.
    """
    from qshd_selinux_registry import RegistryObservation
    from qshd_selinux_transaction import Transaction, _RemovalObservation
    if (type(before) is not RegistryObservation or type(after) is not RegistryObservation
            or type(removed) is not _RemovalObservation):raise CoordinatorError('REMOVED_REGISTRY')
    routing=_json(identities);digest=hashlib.sha256(routing).hexdigest()
    if (before.registry_bytes!=routing or after.registry_bytes!=routing
            or before.registry_sha256!=digest or after.registry_sha256!=digest
            or before.owners!=after.owners or before.manifests!=after.manifests):
        raise CoordinatorError('REMOVED_REGISTRY')
    old=dict(before.candidates);new=dict(after.candidates);targets=dict(removed.target_snapshots)
    if (len(old)!=len(before.candidates) or len(new)!=len(after.candidates)
            or len(targets)!=len(removed.target_snapshots) or set(old)!=set(new)
            or set(targets)!=set(identities) or not set(targets)<=set(new)):
        raise CoordinatorError('REMOVED_REGISTRY')
    for path in old:
        if path not in targets:
            if old[path]!=new[path]:raise CoordinatorError('REMOVED_REGISTRY')
            continue
        packed=json.loads(new[path]);data=bytes.fromhex(packed['data'])
        # Reuse the maintained strict decoder for both explicit encodings.
        from qshd_selinux_fs import encode
        packed=dict(packed,data=encode(data),sha256=hashlib.sha256(data).hexdigest())
        observed=Transaction._unpack(packed)
        expected=Transaction._unpack(json.loads(targets[path]))
        if observed!=expected:raise CoordinatorError('REMOVED_REGISTRY')
    if len(before.directories)!=len(after.directories):raise CoordinatorError('REMOVED_REGISTRY')
    for old_dir,new_dir in zip(before.directories,after.directories):
        old_value=json.loads(old_dir);new_value=json.loads(new_dir)
        if (len(old_value)!=7 or len(new_value)!=7 or old_value[:5]!=new_value[:5]):
            raise CoordinatorError('REMOVED_REGISTRY')


class _Coordinator(_PairCoordinator):
    def erase_installed_provider(self,*,deadline):
        with self._operation(deadline,0):
            b=self._bindings;self._stage='PACKAGE'
            with b.package_operation():
                self._stage='ACTIVATION'
                with b.activation() as activation:
                    current=activation.capture_current();record=current.record
                    with ExitStack() as proofs:
                        self._stage='REFERENCES'
                        references=proofs.enter_context(b.references());captured=references.capture()
                        trust=captured.artifact
                        self._inputs(trust,captured.core_pp_bytes,captured.contexts_pp_bytes)
                        if (record is None or record.artifact!=trust
                                or record.state=='PENDING' and (record.intent!='consumer-erase'
                                    or type(record.basis) is not HistoricalBasis or record.basis.artifact!=trust)):
                            raise CoordinatorError('ERASE_SLOT')
                        self._stage='CONSUMER'
                        consumer=proofs.enter_context(b.consumer_paths(captured.expected_pam,fresh=True))
                        consumer_absent=consumer.capture()
                        with ExitStack() as rpm_scope:
                            self._stage='RPM';rpm=rpm_scope.enter_context(b.rpm_query(self._end))
                            rpm_absent=rpm.capture_absent();self._check()
                            # A: strictly read-only eligibility precedes writer provisioning.
                            self._stage='PREFLIGHT'
                            with b.registry(deadline=self._end) as registry:
                                routing,identities=self._routing(registry)
                                with b.context_inspection(sorted(identities),identities) as contexts:
                                    preliminary=self._views(registry,contexts,routing,owned=True)
                                    binding=ContextBinding(preliminary[1].registry_sha256,preliminary[1].receipts_sha256)
                                    if record.state=='COMPLETE':require_complete(record,trust,binding)
                                    elif record.basis.completion.contexts!=binding:raise CoordinatorError('BASIS_CONTEXTS')
                                    registry.recheck(preliminary[0]);contexts.recheck(preliminary[1])
                            self._check()
                            with b.contexts(sorted(identities)) as contexts:
                                with b.retained_erase(deadline=self._end) as labels:
                                    self._stage='OBSERVATION'
                                    with b.removal_session(captured,deadline=self._end) as session:
                                        # B: exact old snapshots under this pair's one owner.
                                        with b.registry(deadline=self._end) as registry:
                                            if self._routing(registry)!=(routing,identities):raise CoordinatorError('ROUTING_DRIFT')
                                            with contexts.inspection(identities) as owned:
                                                with session.observation('pair') as pair:
                                                    pair_token=pair.capture()
                                                    with b.queries(pair.status_token):
                                                        admitted=self._views(registry,owned,routing,owned=True)
                                                        if admitted!=preliminary:raise CoordinatorError('OWNED_STATE_DRIFT')
                                                        old=labels.capture(status=pair.status_token)
                                                        labels.recheck_before_removal(old,status=pair.status_token)
                                                        pair.recheck(pair_token);registry.recheck(admitted[0]);owned.recheck(admitted[1])
                                        # No observer is added: these are the same two RPM/four guard calls.
                                        self._stage='RPM_RECHECK';rpm.recheck(rpm_absent);rpm_scope.close()
                                        references.recheck(captured);consumer.recheck(consumer_absent)
                                        self._stage='GUARD';b.guard(self._end);self._check(290)
                                        basis=HistoricalBasis(trust,record.completion) if record.state=='COMPLETE' else record.basis
                                        pending=_pending(trust,'provider-erase',basis)
                                        self._stage='PENDING';pending_token=activation.begin_pending(_json(asdict(pending)),current)
                                        self._check(290);self._stage='CONTEXT_REMOVE'
                                        removed=contexts.remove_owned(identities);contexts.recheck_removed(removed)
                                        self._stage='CONTEXTS_UNLOAD';session.remove_contexts(pair_token)
                                        with session.observation('core-only') as core:
                                            core_token=core.capture()
                                            self._stage='RESTORE';restored=labels.restore_defaults(old,status=core.status_token)
                                            core.recheck(core_token)
                                            restoration=core.recheck_restoration(core_token,lambda:labels.recheck_restored(restored))
                                        self._stage='CORE_UNLOAD';session.remove_core(core_token,restoration)
                                        # C: new strict lease, explicitly joined to this exact removal.
                                        self._stage='ABSENT'
                                        with b.registry(deadline=self._end) as registry:
                                            if self._routing(registry)!=(routing,identities):raise CoordinatorError('ROUTING_DRIFT')
                                            with session.observation('absent') as absent:
                                                with labels.final_policy(restored,status=absent.status_token) as final:
                                                    absent_token=absent.capture();contexts.recheck_removed(removed)
                                                    after=registry.capture();contexts.recheck_removed(removed)
                                                    _bind_removed_registry(admitted[0],after,removed,identities)
                                                    final.capture();absent.recheck(absent_token);final.recheck()
                                                    registry.recheck(after);contexts.recheck_removed(removed)
                                    self._check()
                                self._check();contexts.recheck_removed(removed)
                                references.recheck(captured);consumer.recheck(consumer_absent)
                            self._check()
                        references.recheck(captured);consumer.recheck(consumer_absent)
                        proofs.close();self._check()
                    # All proof/native/module/retained/reference FDs closed normally.
                    self._stage='RETIRE';self._completion_possible=True
                    try:absent=activation.retire_erased(pending_token)
                    except OutcomeUncertain:raise
                    except SlotError:self._completion_possible=False;raise
                    if absent!=SlotObservation(None,None,None):raise OutcomeUncertain('ERASE_READBACK')
                self._check();self._stage='READBACK'
                with b.slot_object().inspection() as reader:
                    absent=reader.capture();reader.recheck(absent)
                    if absent!=SlotObservation(None,None,None):raise OutcomeUncertain('ERASE_READBACK')
                self._check();result=ErasureResult(pending.operation_id,trust)
        return result
