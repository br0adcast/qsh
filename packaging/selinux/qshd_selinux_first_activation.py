"""First policy/context activation only; not package hooks or startup readiness.

Caller excludes nonparticipating privileged writers and manual/managed daemon
starts, drains/stops service and completes the maintained administrator stop
guard. Run in a fresh root child with finite process resources and an external
hard deadline. Library clock checks cannot interrupt native/filesystem calls.
No adoption, update, recovery or rollback of a prior attempt is performed.
"""
from dataclasses import asdict, replace
import hashlib
import json
import math
import os
import secrets
import time

from qshd_selinux_activation import (
    Activation, Completion, ContextBinding, ModuleIdentity,
    TrustedArtifact, require_complete,
)
from qshd_selinux_activation_state import OutcomeUncertain, SlotError
from qshd_selinux_modules import MAX_HLL


class CoordinatorError(RuntimeError):
    """Bounded stage refusal; original trusted-library diagnostic is chained."""


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


class _Production:
    """Fixed trusted factories; imports do not invoke native/policy operations."""
    def preconditions(self):
        from qshd_selinux_process import _preconditions
        if os.geteuid()!=0:raise CoordinatorError('ROOT_REQUIRED')
        _preconditions()
    def package(self):
        from qshd_selinux_package_state import production
        return production().initialize()
    def references(self):
        from qshd_selinux_reference_loader import production_references
        return production_references()
    def activation(self):
        from qshd_selinux_activation_state import production
        return production().writer()
    def registry(self):
        from qshd_selinux_registry import production
        return production().inspection()
    def contexts(self,paths):
        from qshd_selinux_transaction import production
        return production(paths).writer()
    def installer(self,trust,pp):
        from qshd_selinux_module_install import production_installer
        return production_installer(trust,pp)
    def modules(self,trust):
        from qshd_selinux_module_observer import production_observer
        return production_observer(trust)
    def window(self):
        from qshd_selinux_api import SelinuxApi
        from qshd_selinux_queries import required_observation
        return required_observation(SelinuxApi())


def activate_first(trusted_artifact,pp_bytes,*,deadline):
    """Return frozen historical COMPLETE only after all normal scope exits.

    Protected package/activation prerequisites may be initialized. Fresh durable
    PENDING precedes context/policy changes. Later failure may leave that state,
    a context journal or loaded module. Post-publication failures are uncertain;
    no automatic rollback, reset or repeated first-install attempt is safe.
    Fixed file/PAM and managed-prestart evidence remain separate caller work.
    """
    return _Coordinator(_Production()).activate_first(trusted_artifact,pp_bytes,deadline=deadline)


def activate_installed_first(*,deadline):
    """Capture protected installed references under one owned package lease.

    The same administrative exclusion/hard-owner prerequisites as activate_first
    apply. Reference finalization after possible COMPLETE is outcome-uncertain.
    """
    return _Coordinator(_Production()).activate_installed_first(deadline=deadline)


class _Coordinator:
    """Private trusted test seam, not a configurable production orchestrator."""
    def __init__(self,bindings,*,clock=time.monotonic):
        self._bindings=bindings;self._clock=clock;self._used=False;self._completion_possible=False
        self._stage='INPUT'

    def _check(self,reserve=0):
        if self._clock()+reserve>=self._end:raise CoordinatorError('DEADLINE')

    def activate_first(self,trusted_artifact,pp_bytes,*,deadline):
        if self._used:raise CoordinatorError('COORDINATOR_USED')
        self._used=True
        try:
            start=self._clock()
            if type(deadline) not in (int,float) or not math.isfinite(deadline):
                raise CoordinatorError('DEADLINE')
            self._end=min(deadline,start+240)
            self._check(60)  # Refuse insufficient initial budget before setup.
            if type(trusted_artifact) is not TrustedArtifact:raise CoordinatorError('TRUSTED_ARTIFACT')
            trusted_artifact.__post_init__()
            trust=TrustedArtifact(trusted_artifact.provider_version,trusted_artifact.manifest_sha256,
                                  trusted_artifact.pp_sha256)
            if type(pp_bytes) is not bytes or not 0<len(pp_bytes)<=MAX_HLL:
                raise CoordinatorError('PP_INPUT')
            if hashlib.sha256(pp_bytes).hexdigest()!=trust.pp_sha256:raise CoordinatorError('PP_IDENTITY')
            self._check()
            b=self._bindings
            self._stage='PROCESS';b.preconditions();self._check(60)
            self._stage='PACKAGE'
            with b.package():
                result=self._activate_locked(trust,pp_bytes)
            self._check()
            return result
        except OutcomeUncertain:
            raise
        except BaseException as error:
            if self._completion_possible:
                raise OutcomeUncertain('COORDINATOR_OUTCOME_UNCERTAIN') from error
            if not isinstance(error,Exception) or isinstance(error,CoordinatorError):raise
            raise CoordinatorError(self._stage) from error

    def _activate_locked(self,trust,pp_bytes,*,references=None):
        # Caller owns the one package lease; no public lock-taking recursion.
        b=self._bindings
        self._stage='ACTIVATION'
        with b.activation() as activation:
            initial=activation.capture_current()
            if initial.record is not None:raise CoordinatorError('ACTIVATION_EXISTS')
            self._stage='ROUTING';self._check(60)
            with b.registry() as registry:
                routing=registry.routing()
            if type(routing) is not bytes or len(routing)>1024**2:raise CoordinatorError('ROUTING')
            identities=json.loads(routing)
            if type(identities) is not dict or not 0<len(identities)<=16 or _json(identities)!=routing:
                raise CoordinatorError('ROUTING')
            self._check(110)
            pending=Activation(1,'PENDING',secrets.token_hex(16),'fedora44-targeted-v1',1,1,
                               trust,ModuleIdentity('qshd',400,'targeted','pp'),None)
            self._stage='PENDING'
            token=activation.begin_pending(_json(asdict(pending)),initial)
            self._check()
            self._stage='CONTEXT_PRISTINE'
            with b.contexts(sorted(identities)) as writer:
                writer.require_pristine(identities)
                self._stage='INSTALL';self._check(110)
                b.installer(trust,pp_bytes).install(deadline=self._end)
                self._check()
                self._stage='RECONCILE';writer.reconcile(identities);self._check(60)
                self._stage='OBSERVATION'
                with b.registry() as registry:
                    if registry.routing()!=routing:raise CoordinatorError('ROUTING_DRIFT')
                    with writer.inspection(identities) as contexts:
                        with b.modules(trust) as modules:
                            with b.window():
                                self._check()
                                discovered=registry.capture()
                                context=contexts.capture()
                                module=modules.capture()
                                if (discovered.registry_bytes!=routing or context.registry_bytes!=routing
                                        or discovered.registry_sha256!=context.registry_sha256
                                        or module.hll.sha256!=trust.pp_sha256):
                                    raise CoordinatorError('BINDING')
                                modules.recheck(module)
                                registry.recheck(discovered)
                                contexts.recheck(context)
                                self._check()
                # Status/module/borrowed view/registry all exited normally;
                # the same context writer and activation writer remain held.
                self._stage='COMPLETE';self._check(10)
                if references is not None:
                    reader,captured=references
                    reader.recheck(captured)
                    self._check(10)
                binding=ContextBinding(context.registry_sha256,context.receipts_sha256)
                complete=replace(pending,state='COMPLETE',completion=Completion(
                    'normal-install-reload-v1',module.hll.sha256,binding))
                # Pre-arm before invocation: an unknown interruption may
                # arrive after the actual return but before assignment.
                self._completion_possible=True
                try:
                    observed=activation.publish_complete(_json(asdict(complete)),token,
                        trusted_artifact=trust,trusted_context_binding=binding)
                except OutcomeUncertain:
                    raise
                except SlotError:
                    # The slot contract classifies this before replacement.
                    self._completion_possible=False
                    raise
                require_complete(observed.record,trust,binding)
                result=observed.record
                self._stage='FINALIZE';self._check()
        return result

    def activate_installed_first(self,*,deadline):
        if self._used:raise CoordinatorError('COORDINATOR_USED')
        self._used=True
        try:
            start=self._clock()
            if type(deadline) not in (int,float) or not math.isfinite(deadline):
                raise CoordinatorError('DEADLINE')
            self._end=min(deadline,start+240)
            self._check(60)
            b=self._bindings
            self._stage='PROCESS';b.preconditions();self._check(60)
            self._stage='PACKAGE'
            with b.package():
                self._stage='REFERENCES'
                with b.references() as reader:
                    captured=reader.capture()
                    trust=captured.artifact
                    if type(trust) is not TrustedArtifact:raise CoordinatorError('TRUSTED_ARTIFACT')
                    trust.__post_init__()
                    pp=captured.pp_bytes
                    if type(pp) is not bytes or not 0<len(pp)<=MAX_HLL:raise CoordinatorError('PP_INPUT')
                    if hashlib.sha256(pp).hexdigest()!=trust.pp_sha256:raise CoordinatorError('PP_IDENTITY')
                    self._check(60)
                    result=self._activate_locked(trust,pp,references=(reader,captured))
            self._check()
            return result
        except OutcomeUncertain:
            raise
        except BaseException as error:
            if self._completion_possible:
                raise OutcomeUncertain('COORDINATOR_OUTCOME_UNCERTAIN') from error
            if not isinstance(error,Exception) or isinstance(error,CoordinatorError):raise
            raise CoordinatorError(self._stage) from error
