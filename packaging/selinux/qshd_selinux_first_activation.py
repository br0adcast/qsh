"""Fixed fresh and owned ABI2 activation under one original maintenance owner.

Caller excludes privileged writers and starts, drains daemons and supplies the
external hard owner. Failed mutation leaves PENDING; no rollback or adoption.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import asdict, replace
import hashlib
import json
import math
import os
import secrets
import time

from qshd_selinux_activation import (Activation, Completion, ContextBinding,
    ModuleIdentity, ModulePair, PairDigests, HistoricalBasis, TrustedArtifact,
    require_complete)
from qshd_selinux_activation_state import OutcomeUncertain, SlotError
from qshd_selinux_modules import MAX_HLL


class CoordinatorError(RuntimeError):
    """Bounded coordinator stage; no private content."""


def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def _pending(trust,intent,basis=None):
    return Activation(2,'PENDING',secrets.token_hex(16),'fedora44-targeted-pair-v2',2,1,
        trust,ModulePair(ModuleIdentity('qshd',400,'targeted','pp'),
                         ModuleIdentity('qshd_contexts',400,'targeted','pp')),intent,basis,None)


class RuntimeBindings:
    """Fixed factories with explicit borrowed status custody for every native use."""
    def preconditions(self):
        from qshd_selinux_process import _preconditions
        if os.geteuid()!=0:raise CoordinatorError('ROOT_REQUIRED')
        _preconditions()
    def guard(self,deadline):
        import stop_guard
        from qshd_selinux_process import _Owner,_Limits,_normal_outcome
        owner=_Owner(_Limits(5,16384))
        def run():
            streams=owner._run(stop_guard.COMMAND,'/',deadline=deadline)
            if not _normal_outcome(owner._last) or owner._last.exit_code!=0 or streams.stderr:
                raise CoordinatorError('GUARD')
            return streams.stdout.decode('utf-8','strict')
        stop_guard.check(stop_guard.Host(),run,allow_absent=True)
    def package(self):
        from qshd_selinux_package_state import production
        return production().initialize()
    def package_operation(self):
        from qshd_selinux_package_state import production
        return production().operation()
    def references(self):
        from qshd_selinux_reference_loader import production_references
        return production_references()
    def slot_object(self):
        from qshd_selinux_activation_state import production
        return production()
    def activation(self):return self.slot_object().writer()
    def registry(self,*,deadline):
        from qshd_selinux_registry import production
        return production().inspection(deadline=deadline)
    def contexts(self,paths):
        from qshd_selinux_transaction import production
        return production(paths).writer()
    def context_inspection(self,paths,identities):
        from qshd_selinux_transaction import production
        return production(paths).inspection(identities)
    def installer(self,trust,core,contexts):
        from qshd_selinux_module_install import production_installer
        return production_installer(trust,core,contexts)
    def reloader(self,owned,incoming,core,contexts):
        from qshd_selinux_module_install import production_owned_reloader
        return production_owned_reloader(owned,incoming,core,contexts)
    def modules(self,trust,*,deadline,mode='pair'):
        from qshd_selinux_module_observer import production_observer
        return production_observer(trust,deadline=deadline,mode=mode)
    def window(self):
        from qshd_selinux_api import SelinuxApi
        return SelinuxApi().status_observation()
    def queries(self,status):
        from qshd_selinux_queries import required_observation
        return required_observation(status.require_open(),status=status)
    def retained(self,*,deadline,pristine=False):
        from qshd_selinux_retained_labels import production
        value=production()
        return value.pristine_install(deadline=deadline) if pristine else value.managed_inspection(deadline=deadline)
    def files(self,pam,*,status,erase=False):
        from qshd_selinux_files import production
        value=production(pam,status.require_open())
        return value.erase_inspection() if erase else value.inspection()
    def erase_files(self,pam,*,status):return self.files(pam,status=status,erase=True)
    def consumer_paths(self,pam,*,fresh):
        from qshd_selinux_consumer_activation import _ConsumerPaths
        return _ConsumerPaths(pam).inspection(fresh=fresh)
    def consumer_selection(self,deadline):
        from qshd_selinux_rpm_query import production_consumer_authority
        return production_consumer_authority().selection(deadline=deadline)
    def consumer_authority(self,deadline):
        from qshd_selinux_rpm_query import production_consumer_authority
        return production_consumer_authority().inspection(deadline=deadline)
    def rpm_query(self,deadline):
        from qshd_selinux_rpm_query import production_query
        return production_query().inspection(deadline=deadline)


class _Production(RuntimeBindings):pass


def activate_first(trusted_artifact,core_pp_bytes,contexts_pp_bytes,*,deadline):
    return _Coordinator(_Production()).activate_first(trusted_artifact,core_pp_bytes,contexts_pp_bytes,deadline=deadline)


def activate_installed_first(*,deadline):
    return _Coordinator(_Production()).activate_installed_first(deadline=deadline)


def activate_installed_pristine_pending_first(*,deadline):
    return _Coordinator(_Production()).activate_installed_pristine_pending_first(deadline=deadline)


def invalidate_installed_provider_upgrade(incoming_artifact,*,deadline):
    return _Coordinator(_Production()).invalidate_installed_provider_upgrade(incoming_artifact,deadline=deadline)


def activate_installed_owned_provider(*,deadline):
    return _Coordinator(_Production()).activate_installed_owned_provider(deadline=deadline)


class _Coordinator:
    def __init__(self,bindings,*,clock=time.monotonic):
        self._bindings=bindings;self._clock=clock;self._used=False
        self._completion_possible=False;self._stage='INPUT'
    def _check(self,reserve=0):
        if self._clock()+reserve>=self._end:raise CoordinatorError('DEADLINE')
    @contextmanager
    def _operation(self,deadline,reserve):
        if self._used:raise CoordinatorError('COORDINATOR_USED')
        self._used=True
        try:
            try:valid=type(deadline) in (int,float) and math.isfinite(deadline)
            except OverflowError:valid=False
            if not valid:raise CoordinatorError('DEADLINE')
            self._end=deadline;self._check(reserve)
            self._stage='PROCESS';self._bindings.preconditions();self._check(reserve)
            self._stage='GUARD';self._bindings.guard(self._end);self._check()
            yield
            self._check()
        except OutcomeUncertain:raise
        except BaseException as error:
            if self._completion_possible:raise OutcomeUncertain('COORDINATOR_OUTCOME_UNCERTAIN') from error
            if not isinstance(error,Exception) or isinstance(error,CoordinatorError):raise
            if self._clock()>=self._end:raise CoordinatorError('DEADLINE') from error
            raise CoordinatorError(self._stage) from error
    def _inputs(self,trust,core,contexts):
        if type(trust) is not TrustedArtifact:raise CoordinatorError('TRUSTED_ARTIFACT')
        trust.__post_init__()
        for data,digest in ((core,trust.core_pp_sha256),(contexts,trust.contexts_pp_sha256)):
            if type(data) is not bytes or not 0<len(data)<=MAX_HLL:raise CoordinatorError('PP_INPUT')
            if hashlib.sha256(data).hexdigest()!=digest:raise CoordinatorError('PP_IDENTITY')
    def _routing(self,registry):
        routing=registry.routing();identities=json.loads(routing)
        if (type(routing) is not bytes or len(routing)>1024**2 or type(identities) is not dict
                or not 0<len(identities)<=16 or _json(identities)!=routing):raise CoordinatorError('ROUTING')
        return routing,identities
    def _views(self,registry,contexts,routing,*,owned=False):
        discovered=registry.capture();context=contexts.capture()
        if discovered.registry_bytes!=routing or context.registry_bytes!=routing or discovered.registry_sha256!=context.registry_sha256:
            raise CoordinatorError('BINDING')
        if owned:
            from qshd_selinux_consumer_activation import _Coordinator as Consumer
            Consumer._owned(self,context,json.loads(routing))
        return discovered,context
    def _pair(self,module,trust):
        if module.core.hll.sha256!=trust.core_pp_sha256 or module.contexts.hll.sha256!=trust.contexts_pp_sha256:
            raise CoordinatorError('BINDING')
    def _publish(self,activation,pending,token,context,trust):
        binding=ContextBinding(context.registry_sha256,context.receipts_sha256)
        complete=replace(pending,state='COMPLETE',basis=None,completion=Completion(
            'normal-pair-install-reload-v2',PairDigests(trust.core_pp_sha256,trust.contexts_pp_sha256),binding))
        self._stage='COMPLETE';self._check(10);self._completion_possible=True
        try:result=activation.publish_complete(_json(asdict(complete)),token,trusted_artifact=trust,trusted_context_binding=binding)
        except OutcomeUncertain:raise
        except SlotError:self._completion_possible=False;raise
        require_complete(result.record,trust,binding);self._stage='FINALIZE';return result.record
    def activate_first(self,trust,core,contexts,*,deadline):
        with self._operation(deadline,280):
            self._inputs(trust,core,contexts)
            with self._bindings.package():
                result=self._fresh_locked(trust,core,contexts,None,False)
        return result
    def _installed_fresh(self,deadline,pending):
        with self._operation(deadline,280):
            b=self._bindings
            with b.package_operation() if pending else b.package():
                with ExitStack() as reference_scope:
                    reader=reference_scope.enter_context(b.references())
                    captured=reader.capture();self._inputs(captured.artifact,captured.core_pp_bytes,captured.contexts_pp_bytes)
                    result=self._fresh_locked(captured.artifact,captured.core_pp_bytes,captured.contexts_pp_bytes,
                        (reader,captured),pending,reference_scope=reference_scope)
        return result
    def activate_installed_first(self,*,deadline):return self._installed_fresh(deadline,False)
    def activate_installed_pristine_pending_first(self,*,deadline):return self._installed_fresh(deadline,True)
    def _fresh_locked(self,trust,core,contexts_pp,references,pending_required,*,reference_scope=None):
        b=self._bindings;self._stage='ACTIVATION'
        with b.activation() as activation:
            initial=activation.capture_current();record=initial.record
            if pending_required:
                if record is None or record.state!='PENDING':raise CoordinatorError('PENDING_REQUIRED')
                if (record is None or record.state!='PENDING' or record.intent!='provider-fresh'
                        or record.basis is not None or record.artifact!=trust):raise CoordinatorError('PENDING_IDENTITY')
            elif record is not None:raise CoordinatorError('ACTIVATION_EXISTS')
            self._stage='ROUTING'
            with b.registry(deadline=self._end) as registry:routing,identities=self._routing(registry)
            self._check(270)
            pending=_pending(trust,'provider-fresh');self._stage='PENDING'
            token=activation.begin_pending(_json(asdict(pending)),initial)
            with b.contexts(sorted(identities)) as writer:
                self._stage='CONTEXT_PRISTINE';writer.require_pristine(identities)
                with b.retained(deadline=self._end,pristine=True) as retained:
                    pam=references[1].expected_pam if references is not None else self._pam()
                    with b.consumer_paths(pam,fresh=True) as consumer:
                        absent=consumer.capture()
                        with b.modules(trust,mode='absent',deadline=self._end) as modules:
                            with b.window() as status:
                                labels=retained.capture_defaults(status=status)
                                empty=modules.capture();modules.recheck(empty)
                                retained.recheck_defaults(labels,status=status)
                        consumer.recheck(absent)
                        self._stage='GUARD';b.guard(self._end);self._check(230)
                        self._stage='INSTALL';b.installer(trust,core,contexts_pp).install(deadline=self._end)
                        self._check(140);self._stage='RECONCILE';writer.reconcile(identities)
                        self._stage='OBSERVATION'
                        with b.registry(deadline=self._end) as registry:
                            if self._routing(registry)!=(routing,identities):raise CoordinatorError('ROUTING_DRIFT')
                            with writer.inspection(identities) as contexts:
                                with b.modules(trust,deadline=self._end) as modules:
                                    with b.window() as status:
                                        with b.queries(status):
                                            discovered,context=self._views(registry,contexts,routing)
                                            module=modules.capture();self._pair(module,trust)
                                            managed=retained.apply_managed(labels,status=status)
                                            retained.recheck_managed(managed,status=status)
                                            modules.recheck(module);registry.recheck(discovered);contexts.recheck(context)
                                            # A fresh post never admits consumer payload or sidecars.
                                            consumer.recheck(absent)
                        self._check()
                self._check()
                # Every retained/native/module/context proof has closed normally.
                if references is not None:
                    references[0].recheck(references[1])
                    reference_scope.close()
                    self._check()
                result=self._publish(activation,pending,token,context,trust)
        return result
    @staticmethod
    def _pam():
        # Fixed canonical bytes are installed reference authority, never live PAM.
        return b'# The `auth` line is load-bearing -- do not remove it. qshd never calls\n# pam_authenticate (a signature proves the identity before PAM is reached),\n# but it does call pam_setcred(PAM_ESTABLISH_CRED), which runs the AUTH\n# stack\'s setcred half; Linux-PAM answers PAM_PERM_DENIED when there is no\n# auth section at all. A file of account and session lines alone therefore\n# refuses EVERY login, with "authentication failed" on the wire and the\n# real reason only in the daemon\'s log.\nauth     required  pam_permit.so\naccount  required  pam_nologin.so\naccount  include   system-auth\n# Restore the saved execution context before other session modules can exec.\nsession  required  pam_selinux.so close\nsession  required  pam_loginuid.so\nsession  include   system-auth\n# Set pending exec context last. qshd owns per-channel PTY labels and restoration.\nsession  required  pam_selinux.so open nottys\n'

    @contextmanager
    def _eligibility(self,captured,*,required=False):
        b=self._bindings
        self._stage='AUTHORITY'
        with b.consumer_authority(self._end) if required else b.consumer_selection(self._end) as manifest:
            selected=manifest.capture();authority=selected if required else selected.authority
            if authority is not None:
                from qshd_selinux_consumer_activation import _Coordinator as Consumer
                Consumer._erase_authority(self,authority,captured.expected_pam)
            self._stage='RPM'
            with b.rpm_query(self._end) as query:
                rpm=query.capture_absent() if authority is None else query.capture_owned(authority)
                with b.consumer_paths(captured.expected_pam,fresh=authority is None) as paths:
                    paths_token=paths.capture()
                    yield authority
                    paths.recheck(paths_token)
                self._stage='RPM_RECHECK';query.recheck(rpm);manifest.recheck(selected)
        self._check()

    def _consumer_file_check(self,captured,authority,status):
        if authority is None:return None
        from qshd_selinux_consumer_activation import _Coordinator as Consumer
        b=self._bindings
        scope=b.erase_files(captured.expected_pam,status=status) if getattr(self,'_consumer_erase',False) else b.files(captured.expected_pam,status=status,erase=True)
        with scope as deployed:
            files=deployed.capture();Consumer._erase_paths(self,files,authority)
            deployed.recheck(files)
        return files

    def invalidate_installed_provider_upgrade(self,incoming_artifact,*,deadline):
        if type(incoming_artifact) is not TrustedArtifact:raise CoordinatorError('TRUSTED_ARTIFACT')
        return self._invalidate_owned(incoming_artifact,deadline=deadline,intent='provider-refresh')

    def _invalidate_owned(self,incoming_artifact,*,deadline,intent,fresh=None):
        with self._operation(deadline,250):
            if incoming_artifact is not None:incoming_artifact.__post_init__()
            b=self._bindings;self._consumer_erase=intent=='consumer-erase'
            with b.package_operation():
                with b.references() as references:
                    captured=references.capture();owned=captured.artifact
                    with b.activation() as activation:
                        current=activation.capture_current();record=current.record
                        if record is None:raise CoordinatorError('COMPLETE_REQUIRED')
                        if record.state=='PENDING':
                            if (intent!='consumer-erase' or record.intent not in ('consumer-install','consumer-erase')
                                    or type(record.basis) is not HistoricalBasis or record.basis.artifact!=owned):raise CoordinatorError('COMPLETE_REQUIRED')
                            old_completion=record.basis.completion
                        else:old_completion=record.completion
                        with self._eligibility(captured,required=self._consumer_erase) as authority:
                            self._check(165 if authority is None else 195)
                            if fresh is not None and fresh!=(authority is None):raise CoordinatorError('CONSUMER_MODE')
                            with b.registry(deadline=self._end) as registry:
                                routing,identities=self._routing(registry)
                                with b.context_inspection(sorted(identities),identities) as contexts:
                                    with b.retained(deadline=self._end) as retained:
                                        with b.modules(owned,deadline=self._end) as modules:
                                            with b.window() as status:
                                                with b.queries(status):
                                                    discovered,context=self._views(registry,contexts,routing,owned=True)
                                                    binding=ContextBinding(context.registry_sha256,context.receipts_sha256)
                                                    if record.state=='COMPLETE':require_complete(record,owned,binding)
                                                    elif old_completion.contexts!=binding:raise CoordinatorError('BASIS_CONTEXTS')
                                                    labels=retained.capture(status=status)
                                                    module=modules.capture();self._pair(module,owned)
                                                    self._consumer_file_check(captured,authority,status)
                                                    retained.recheck(labels,status=status);modules.recheck(module)
                                                    registry.recheck(discovered);contexts.recheck(context)
                            references.recheck(captured);self._stage='GUARD';b.guard(self._end);self._check(10)
                        pending=_pending(owned if incoming_artifact is None else incoming_artifact,intent,HistoricalBasis(owned,old_completion))
                        self._stage='PENDING';self._completion_possible=True
                        activation.begin_pending(_json(asdict(pending)),current)
                    # Reopen protected current state; no cross-process token transfer.
                    with b.slot_object().inspection() as reader:
                        observed=reader.capture();reader.recheck(observed)
                        if observed.record!=pending or observed.document!=_json(asdict(pending)):raise CoordinatorError('PENDING_READBACK')
                    references.recheck(captured)
        return pending

    def activate_installed_owned_provider(self,*,deadline):
        return self._activate_owned(deadline=deadline,intent='provider-refresh')

    def _activate_owned(self,*,deadline,intent):
        with self._operation(deadline,415):
            b=self._bindings
            with b.package_operation():
                with ExitStack() as reference_scope:
                    references=reference_scope.enter_context(b.references())
                    captured=references.capture();target=captured.artifact
                    self._inputs(target,captured.core_pp_bytes,captured.contexts_pp_bytes)
                    with b.activation() as activation:
                        current=activation.capture_current();record=current.record
                        if (record is None or record.state!='PENDING' or record.intent!=intent
                                or record.artifact!=target or type(record.basis) is not HistoricalBasis):
                            raise CoordinatorError('MATCHING_PENDING_REQUIRED')
                        basis=record.basis
                        if intent=='consumer-install' and basis.artifact!=target:raise CoordinatorError('BASIS_ARTIFACT')
                        self._stage='PREFLIGHT'
                        with b.registry(deadline=self._end) as registry:
                            routing,identities=self._routing(registry)
                            with b.context_inspection(sorted(identities),identities) as contexts:
                                preflight=self._views(registry,contexts,routing,owned=True)
                                registry.recheck(preflight[0]);contexts.recheck(preflight[1])
                        self._check(405)
                        with b.contexts(sorted(identities)) as writer:
                            with self._eligibility(captured,required=intent=='consumer-install') as authority:
                                self._check(330 if authority is None else 360)
                                with b.retained(deadline=self._end) as retained:
                                    # Current non-mutating row eligibility precedes new generation.
                                    with writer.inspection(identities) as contexts:
                                        with b.registry(deadline=self._end) as registry:
                                            discovered,context=self._views(registry,contexts,routing,owned=True)
                                            if (discovered,context)!=preflight:raise CoordinatorError('OWNED_STATE_DRIFT')
                                            binding=ContextBinding(context.registry_sha256,context.receipts_sha256)
                                            if binding!=basis.completion.contexts:raise CoordinatorError('BASIS_CONTEXTS')
                                            registry.recheck(discovered);contexts.recheck(context)
                                    references.recheck(captured);self._stage='GUARD';b.guard(self._end);self._check(320 if authority is None else 350)
                                    pending=_pending(target,intent,basis)
                                    self._stage='PENDING';token=activation.begin_pending(_json(asdict(pending)),current)
                                    labels=None;old_files=None
                                    def old_check(status):
                                        nonlocal labels,old_files
                                        with b.queries(status):
                                            with b.registry(deadline=self._end) as registry:
                                                if self._routing(registry)!=(routing,identities):raise CoordinatorError('ROUTING_DRIFT')
                                                with writer.inspection(identities) as contexts:
                                                    discovered,context=self._views(registry,contexts,routing,owned=True)
                                                    if (discovered,context)!=preflight:raise CoordinatorError('OWNED_STATE_DRIFT')
                                                    actual=ContextBinding(context.registry_sha256,context.receipts_sha256)
                                                    if actual!=basis.completion.contexts:raise CoordinatorError('BASIS_CONTEXTS')
                                                    labels=retained.capture(status=status);retained.recheck(labels,status=status)
                                                    old_files=self._consumer_file_check(captured,authority,status)
                                                    registry.recheck(discovered);contexts.recheck(context)
                                            references.recheck(captured)
                                    self._stage='RELOAD'
                                    loaded=b.reloader(basis.artifact,target,captured.core_pp_bytes,captured.contexts_pp_bytes).reload(
                                        deadline=self._end,old_check=old_check)
                                    if (loaded.artifact!=target or loaded.core_pp_sha256!=target.core_pp_sha256
                                            or loaded.contexts_pp_sha256!=target.contexts_pp_sha256):raise CoordinatorError('RELOAD_BINDING')
                                    self._check(155 if authority is None else 185);self._stage='OBSERVATION'
                                    with b.registry(deadline=self._end) as registry:
                                        if self._routing(registry)!=(routing,identities):raise CoordinatorError('ROUTING_DRIFT')
                                        with writer.inspection(identities) as contexts:
                                            with b.modules(target,deadline=self._end) as modules:
                                                with b.window() as status:
                                                    with b.queries(status):
                                                        discovered,context=self._views(registry,contexts,routing,owned=True)
                                                        if (discovered,context)!=preflight:raise CoordinatorError('OWNED_STATE_DRIFT')
                                                        actual=ContextBinding(context.registry_sha256,context.receipts_sha256)
                                                        if actual!=basis.completion.contexts:raise CoordinatorError('BASIS_CONTEXTS')
                                                        module=modules.capture();self._pair(module,target)
                                                        if self._consumer_file_check(captured,authority,status)!=old_files:raise CoordinatorError('FILES_DRIFT')
                                                        retained.recheck(labels,status=status);modules.recheck(module)
                                                        registry.recheck(discovered);contexts.recheck(context)
                            references.recheck(captured)
                            reference_scope.close()
                            self._check()
                            result=self._publish(activation,pending,token,context,target)
        return result
