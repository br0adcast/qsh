"""Ordered provider erase on owned temporary layouts; no host policy changes."""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'packaging/selinux'))
import qshd_selinux_activation as model
import qshd_selinux_provider_erase as erase


class ResultTests(unittest.TestCase):
    def test_erased_result_is_frozen_bounded_and_not_activation_authority(self):
        trust=model.TrustedArtifact('fixture','a'*64,'b'*64,'c'*64)
        value=erase.ErasureResult('d'*32,trust)
        self.assertEqual(value.result,'ERASED')
        self.assertNotIsInstance(value,model.Activation)
        with self.assertRaises(FrozenInstanceError):value.result='COMPLETE'
        for changes in ({'operation_id':'bad'},{'operation_id':True},{'artifact':object()},
                        {'result':'COMPLETE'},{'result':True}):
            with self.subTest(changes=changes),self.assertRaises((ValueError,TypeError)):
                replace(value,**changes)

    def test_fixed_public_factory_and_real_production_factories(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        trust=model.TrustedArtifact('fixture','a'*64,'b'*64,'c'*64)
        captured=SimpleNamespace(artifact=trust,core_pp_bytes=b'core',contexts_pp_bytes=b'contexts')
        with patch.object(erase,'_Production',return_value='bindings'),patch.object(erase,'_Coordinator') as coordinator:
            erase.erase_installed_provider(deadline=530)
            coordinator.assert_called_once_with('bindings')
            coordinator.return_value.erase_installed_provider.assert_called_once_with(deadline=530)
        import qshd_selinux_module_install as install
        import qshd_selinux_retained_labels as retained
        with patch.object(install,'production_removal_session',return_value='session') as factory:
            self.assertEqual(erase._Production().removal_session(captured,deadline=530),'session')
            factory.assert_called_once_with(trust,b'core',b'contexts',deadline=530)
        with patch.object(retained,'production') as factory:
            erase._Production().retained_erase(deadline=530)
            factory.return_value.inspection.assert_called_once_with(deadline=530)


class RegistryBridgeTests(unittest.TestCase):
    """Bridge actual strict snapshots; the originating writer still checks custody."""
    def setUp(self):
        import tempfile,os,json
        from scripts.tests.test_selinux_registry import Replies,ROW,BASE
        import qshd_selinux_registry as registry
        import qshd_selinux_transaction as transaction
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.base=self.root/'contexts';self.base.mkdir(mode=0o755)
        (self.base/'users').mkdir(mode=0o755);self.paths=[BASE+'/default_contexts',BASE+'/users/user_u']
        self.targets={self.paths[0]:self.base/'default_contexts',self.paths[1]:self.base/'users/user_u'}
        for p in self.targets.values():p.write_bytes(ROW);p.chmod(0o644)
        self.unrelated=self.base/'users/root';self.unrelated.write_bytes(b'user_r:user_t:s0 user_r:user_t:s0\n');self.unrelated.chmod(0o644)
        self.runner=Replies(self.paths);self.now=100.
        if getattr(self,'two_owners',False):self.runner.mapping[self.paths[1]]='container-selinux'
        self.registry=lambda:registry.Registry(self.base,anchor=self.root,uid=os.getuid(),owner=self.runner,clock=lambda:self.now).inspection()
        with self.registry() as r:self.routing=r.routing();self.identities=json.loads(self.routing)
        self.transaction=lambda:transaction.Transaction(self.root/'state',self.targets,uid=os.getuid(),anchor=self.root)
        with self.transaction().writer() as w:w.reconcile(self.identities)

    def observed(self):
        with self.registry() as r:
            self.assertEqual(r.routing(),self.routing);value=r.capture();r.recheck(value)
        return value

    def test_actual_removed_snapshots_bridge_but_old_full_registry_recheck_refuses(self):
        import qshd_selinux_registry as registry
        before=self.observed()
        with self.registry() as old:
            old.routing();baseline=old.capture()
            with self.transaction().writer() as w:
                removed=w.remove_owned(self.identities);w.recheck_removed(removed)
                with self.assertRaisesRegex(registry.RegistryError,'REGISTRY_DRIFT'):old.recheck(baseline)
                after=self.observed();w.recheck_removed(removed)
                self.assertIsNone(erase._bind_removed_registry(before,after,removed,self.identities))
                self.assertNotEqual(before,after)

    def test_wrong_copied_foreign_removal_refused_by_actual_writer(self):
        from dataclasses import replace
        with self.transaction().writer() as w:
            removed=w.remove_owned(self.identities)
            with self.assertRaises(ValueError):w.recheck_removed(replace(removed))
        self.assertNotEqual(self.observed().registry_bytes,b'{}')

    def test_unrelated_candidate_and_directory_metadata_are_not_adopted(self):
        import os
        for change in ('unrelated','directory'):
            with self.subTest(change=change):
                self.setUp();before=self.observed()
                with self.transaction().writer() as w:
                    removed=w.remove_owned(self.identities);w.recheck_removed(removed)
                    if change=='unrelated':self.unrelated.write_bytes(b'user_r:staff_t:s0 user_r:staff_t:s0\n')
                    else:(self.base/'users').chmod(0o750)
                    after=self.observed();w.recheck_removed(removed)
                    with self.assertRaises(erase.CoordinatorError):erase._bind_removed_registry(before,after,removed,self.identities)

    def test_target_mutation_and_late_receipt_or_journal_refuse_writer_before_bridge(self):
        for change in ('inode','bytes','mode','xattr','receipt','journal'):
            with self.subTest(change=change):
                self.setUp()
                with self.transaction().writer() as w:
                    removed=w.remove_owned(self.identities);w.recheck_removed(removed)
                    target=next(iter(self.targets.values()))
                    if change=='inode':
                        replacement=target.with_name('replacement');replacement.write_bytes(target.read_bytes());replacement.chmod(0o644);replacement.replace(target)
                    elif change=='bytes':target.write_bytes(target.read_bytes()+b'# drift\n')
                    elif change=='mode':target.chmod(0o600)
                    elif change=='xattr':
                        import os
                        os.setxattr(target,'user.fixture',b'changed')
                    elif change=='receipt':(self.root/'state/receipts').write_bytes(b'{"wrong":{}}')
                    else:(self.root/'state/journal').write_bytes(b'{}');(self.root/'state/journal').chmod(0o600)
                    with self.assertRaises(ValueError):w.recheck_removed(removed)


class EraseBindings:
    """Real filesystem helpers; only platform/native and command IO are injected."""
    def __init__(self,fixture):
        from contextlib import contextmanager
        from dataclasses import asdict,replace
        import hashlib,json,os,importlib.util
        import qshd_selinux_package_state as package
        import qshd_selinux_activation_state as slot
        import qshd_selinux_transaction as transaction
        from qshd_selinux_first_activation import _pending
        self.f=fixture;self.root=fixture.root;self.now=100.;self.end=530.;self.events=[];self.commands=[]
        self.active=set();self.fail=None;self.action=None;self.shared=[];self.duration=.01
        self.phase='pair';self.registry_count=0;self.guard_count=0;self.setters=[];self.retired=False
        self.core=b'inert synthetic core policy';self.contexts_pp=b'inert synthetic contexts policy'
        self.common=self.root/'var/lib/qshd'
        for path in ('usr/bin','usr/lib','etc/pam.d','etc/selinux','var/lib/selinux/targeted/active/modules','var/log','run','usr/lib/sysimage/rpm','cgroup/system.slice/qshd.service'):
            target=self.root
            for part in Path(path).parts:
                target=target/part
                target.mkdir(mode=0o755,exist_ok=True)
        (self.root/'var/run').symlink_to('../run')
        for name,data,mode in [('usr/bin/rpm',b'inert rpm',0o755),('usr/lib/sysimage/rpm/rpmdb.sqlite',b'inert database sentinel',0o644),('cgroup/system.slice/qshd.service/cgroup.events',b'populated 0\nfrozen 0\n',0o644),('usr/bin/semodule',b'inert',0o755),('usr/lib/os-release',b'ID=fedora\nVERSION_ID=44\n',0o644),('etc/selinux/semanage.conf',b'# fixture',0o644),('var/lib/selinux/targeted/semanage.read.LOCK',b'',0o600)]:
            p=self.root/name;p.write_bytes(data);p.chmod(mode)
        source=Path(__file__).resolve().parents[2]/'packaging/selinux'
        spec=importlib.util.spec_from_file_location('erase_payload_builder',source/'assemble_payload.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        pp=self.root/'qshd.pp';pp.write_bytes(self.core);cpp=self.root/'qshd_contexts.pp';cpp.write_bytes(self.contexts_pp)
        artifact=source/'artifact.json';pam=source.parent/'pam.d/qshd.fedora-selinux';self.pam=pam.read_bytes()
        expected={p:hashlib.sha256((source/p).read_bytes()).hexdigest() for p in builder.MODULES}
        expected.update({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (pp,cpp,artifact,pam)})
        self.provider=self.root/'provider';builder.assemble_payload(source,pp,cpp,artifact,pam,expected,self.provider,1000000000)
        self.trust=model.TrustedArtifact('0.3.0',expected['artifact.json'],expected['qshd.pp'],expected['qshd_contexts.pp'])
        self.package_engine=lambda:package.PackageState(self.common,uid=os.getuid(),anchor=self.root)
        self.slot_engine=lambda:slot.ActivationSlot(self.common/'selinux-activation',uid=os.getuid(),anchor=self.root,hook=self.slot_hook)
        with self.package_engine().initialize():
            (self.root/'state').rename(self.common/'selinux-contexts')
            with self.slot_engine().writer() as writer:
                initial=writer.capture_current();pending=_pending(self.trust,'provider-fresh')
                token=writer.begin_pending(erase._json(asdict(pending)),initial)
                with self.transaction().inspection(fixture.identities) as r:
                    view=r.capture();r.recheck(view)
                binding=model.ContextBinding(view.registry_sha256,view.receipts_sha256)
                complete=replace(pending,state='COMPLETE',completion=model.Completion('normal-pair-install-reload-v2',model.PairDigests(self.trust.core_pp_sha256,self.trust.contexts_pp_sha256),binding))
                writer.publish_complete(erase._json(asdict(complete)),token,trusted_artifact=self.trust,trusted_context_binding=binding)
        import qshd_selinux_retained_labels as retained
        for name in ('etc/qshd','var/log/qshd','run/qshd'):(self.root/name).mkdir(mode=0o700 if name=='run/qshd' else 0o755)
        for name,data,mode in [('etc/qshd/host_key',b'k'*64,0o400),('var/log/qshd/qshd.log',b'synthetic private log',0o600),('var/log/qshd/qshd.log.1',b'old synthetic log',0o600),('run/qshd/helper-status.sock.lock',b'synthetic lock',0o600)]:
            p=self.root/name;p.write_bytes(data);p.chmod(mode)
        self.labels={};self.private={}
        for path,kind,role,label in retained._ITEMS:
            p=self.root/path[1:];self.labels[self.key_path(p)]=label.encode()+b'\0'
            mode=p.stat().st_mode & 0o777;p.chmod(mode | 0o200);os.setxattr(p,'user.fixture',b'preserved');p.chmod(mode)
            if p.is_file():self.private[path]=(hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_mode)
        self.lock_identity=self.key_path(self.common/'selinux-activation/lock')
        self.events=[];self.ready=True

    def key_path(self,path):
        s=path.stat();return s.st_dev,s.st_ino
    def key(self,fd):
        import os
        s=os.fstat(fd);return s.st_dev,s.st_ino
    def point(self,event):
        self.events.append(event)
        if self.action:self.action(event)
        if event==self.fail:raise RuntimeError('controlled '+event)
    def command(self,kind,deadline):
        self.f.assertLess(self.now,deadline);self.f.assertLessEqual(deadline,self.end)
        self.commands.append((kind,deadline,self.now));self.now+=self.duration;self.point('command '+kind)
    def preconditions(self):self.point('preconditions')
    def guard(self,deadline):
        import stop_guard
        self.f.assertEqual(deadline,self.end);self.guard_count+=1;b=self
        class Evidence:
            def preflight(inner):b.point('guard platform')
            def empty(inner):stop_guard.Cgroup(b.root/'cgroup',lambda fd:1,1).empty()
        def run():
            b.command('guard',deadline)
            return 'Id=qshd.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\nJob=\nControlGroup=/system.slice/qshd.service\nSlice=system.slice\n'
        stop_guard.check(Evidence(),run,allow_absent=True)
    def track(self,name,scope):
        from contextlib import contextmanager
        @contextmanager
        def tracked():
            self.point(name+' enter')
            with scope as value:
                self.active.add(name)
                try:yield value
                finally:self.active.remove(name)
            self.point(name+' exit')
        return tracked()
    def package_operation(self):return self.track('package',self.package_engine().operation())
    def activation(self):return self.track('activation',self.slot_engine().writer())
    def slot_object(self):return self.slot_engine()
    def references(self):
        import qshd_selinux_reference_loader as r
        return self.track('references',r._testing_references(self.provider))
    def transaction(self):
        import os,qshd_selinux_transaction as tx
        return tx.Transaction(self.common/'selinux-contexts',self.f.targets,uid=os.getuid(),anchor=self.root,hook=lambda event:self.point('transaction '+event))
    def consumer_paths(self,pam,*,fresh):
        import os,qshd_selinux_consumer_activation as consumer
        self.f.assertIs(fresh,True)
        return self.track('consumer',consumer._ConsumerPaths(pam,_root=self.root,_uid=os.getuid()).inspection(fresh=fresh))
    def registry(self,*,deadline):
        import os,qshd_selinux_registry as registry
        self.f.assertEqual(deadline,self.end);self.registry_count+=1;count=self.registry_count;binding=self
        class Owner:
            def _run(self,argv,cwd,*,deadline):
                binding.command('registry'+str(count),deadline)
                return binding.f.runner._run(argv,cwd,deadline=deadline)
        return self.track('registry'+str(count),registry.Registry(self.f.base,anchor=self.root,uid=os.getuid(),owner=Owner(),clock=lambda:self.now).inspection(deadline=deadline))
    def context_inspection(self,paths,identities):return self.track('preflight',self.transaction().inspection(identities))
    def contexts(self,paths):
        from contextlib import contextmanager
        from unittest.mock import patch
        @contextmanager
        def writer():
            with self.track('contexts',self.transaction().writer()) as w:
                original=w.remove_owned
                def remove(identities):self.point('rows remove');return original(identities)
                with patch.object(w,'remove_owned',side_effect=remove):yield w
        return writer()
    def rpm_query(self,deadline):
        import os,qshd_selinux_rpm_query as rpm
        from qshd_selinux_process import _Streams
        from scripts.tests.test_selinux_module_install import natural_outcome
        from scripts.tests.test_selinux_rpm_query import package
        b=self
        class Owner:
            _last=None
            def _run(inner,argv,cwd,*,deadline):
                b.command('rpm',deadline);inner._last=natural_outcome(b'',b'',0,None,True)
                return _Streams(getattr(b,'rpm_inventory',package('unrelated')),b'')
        query=rpm.RpmQuery(_root=self.root,_uid=os.getuid(),_owner=Owner(),_clock=lambda:self.now)
        return self.track('rpm',query.inspection(deadline=deadline))
    def window(self):
        from contextlib import contextmanager
        import qshd_selinux_api as native
        from scripts.tests.test_selinux_api import SharedStatus
        from scripts.tests.test_selinux_queries import FakeApi
        import qshd_selinux_retained_labels as retained
        b=self;shared=SharedStatus();owner=native.SelinuxApi(shared.library());fake=FakeApi();fake.active=True
        for name in ('check_context','require_av','compute_create','compute_relabel','validate_transition'):setattr(owner,name,getattr(fake,name))
        @contextmanager
        def defaults():
            class Defaults:
                def lookup(inner,path,kind):
                    b.point('default '+b.phase)
                    if b.phase=='pair':return next(row[3] for row in retained._ITEMS if row[0]==path)
                    return getattr(b,'default_drift','system_u:object_r:etc_t:s0')
            yield Defaults()
        owner.file_defaults=defaults
        owner.file_context=lambda fd:b.labels[b.key(fd)].removesuffix(b'\0').decode()
        self.shared.append(shared)
        return self.track('native'+str(len(self.shared)),owner.status_observation())
    def queries(self,status):
        from qshd_selinux_queries import required_observation
        return required_observation(status.require_open(),status=status)
    def retained_erase(self,*,deadline):
        import os,qshd_selinux_retained_labels as retained
        def get(fd,name):return self.labels[self.key(fd)] if name=='security.selinux' else os.getxattr(fd,name)
        def set(fd,name,value,flags):
            self.f.assertEqual(self.phase,'core-only');self.f.assertEqual((name,flags),('security.selinux',os.XATTR_REPLACE))
            self.point('setter');self.setters.append(self.key(fd));self.labels[self.key(fd)]=value
            os.fchmod(fd,os.fstat(fd).st_mode & 0o777)
        factory=retained.RetainedLabels(_root=self.root,_uid=os.getuid(),_clock=lambda:self.now,
            _getxattr=get,_listxattr=lambda fd:os.listxattr(fd)+['security.selinux'],_setxattr=set)
        return self.track('retained',factory.inspection(deadline=deadline))
    def removal_session(self,captured,*,deadline):
        import os,qshd_selinux_module_install as install
        import qshd_selinux_module_observer as observer
        from qshd_selinux_process import _Streams
        from scripts.tests.test_selinux_module_install import natural_outcome
        b=self
        def runner(operation,cwd,*,deadline):
            b.command(operation,deadline)
            if operation=='list':
                return {'pair':b'100 base cil\n400 qshd pp\n400 qshd_contexts pp\n','core-only':b'100 base cil\n400 qshd pp\n','absent':b'100 base cil\n'}[b.phase]
            name,data=('qshd.pp',b.core) if operation=='extract-core' else ('qshd_contexts.pp',b.contexts_pp)
            p=Path(cwd)/name;p.write_bytes(data);p.chmod(0o600);return b''
        def module(trust,*,mode,deadline):
            b.f.assertEqual(mode,b.phase)
            return observer._testing_observer(trust,b.root,runner,mode=mode,deadline=deadline,_clock=lambda:b.now)
        class Owner:
            _last=None
            def _run(inner,argv,cwd,*,deadline):
                b.f.assertFalse(any(n.startswith('native') for n in b.active));b.command('remove '+argv[-1],deadline)
                b.phase='core-only' if argv[-1]=='qshd_contexts' else 'absent'
                inner._last=natural_outcome(b'',b'',0,None,True);return _Streams(b'',b'')
        return self.track('session',install.PairRemovalSession(captured.artifact,captured.core_pp_bytes,captured.contexts_pp_bytes,deadline=deadline,_root=self.root,_uid=os.getuid(),_owner=Owner(),_clock=lambda:self.now,_observer=module,_window=self.window))
    def package(self):return self.track('package',self.package_engine().initialize())
    def retained(self,*,deadline,pristine=False):
        import os,qshd_selinux_retained_labels as retained
        def get(fd,name):return self.labels[self.key(fd)] if name=='security.selinux' else os.getxattr(fd,name)
        def set(fd,name,value,flags):
            self.f.assertEqual(self.phase,'pair');self.point('install setter')
            self.labels[self.key(fd)]=value;os.fchmod(fd,os.fstat(fd).st_mode & 0o777)
        factory=retained.RetainedLabels(_root=self.root,_uid=os.getuid(),_clock=lambda:self.now,
            _getxattr=get,_listxattr=lambda fd:os.listxattr(fd)+['security.selinux'],_setxattr=set)
        return self.track('install retained',factory.pristine_install(deadline=deadline) if pristine else factory.managed_inspection(deadline=deadline))
    def installer(self,trust,core,contexts):
        import os,qshd_selinux_module_install as install
        from qshd_selinux_process import _Streams
        from scripts.tests.test_selinux_module_install import natural_outcome
        b=self
        class Owner:
            _last=None
            def _run(inner,argv,cwd,*,deadline):
                b.command('install-list' if argv[-1]=='-lfull' else 'install-load',deadline)
                inner._last=natural_outcome(b'',b'',0,None,True)
                if argv[-1]=='-lfull':return _Streams(b'100 base cil\n',b'')
                b.f.assertEqual((Path(argv[-2]).read_bytes(),Path(argv[-1]).read_bytes()),(core,contexts))
                b.phase='pair';return _Streams(b'',b'')
        return install.FirstInstall(trust,core,contexts,_root=self.root,_uid=os.getuid(),_owner=Owner(),_clock=lambda:self.now)
    def modules(self,trust,*,mode='pair',deadline):
        import os,qshd_selinux_module_observer as observer
        def runner(operation,cwd,*,deadline):
            self.command('install-observe-'+operation,deadline)
            if operation=='list':return b'100 base cil\n' if self.phase=='absent' else b'100 base cil\n400 qshd pp\n400 qshd_contexts pp\n'
            name,data=('qshd.pp',self.core) if operation=='extract-core' else ('qshd_contexts.pp',self.contexts_pp)
            p=Path(cwd)/name;p.write_bytes(data);p.chmod(0o600);return b''
        return observer._testing_observer(trust,self.root,runner,mode=mode,deadline=deadline,_clock=lambda:self.now)
    def slot_hook(self,event):
        if not getattr(self,'ready',False):return
        self.point(event)
        if event=='before_slot_unlink':
            self.f.assertEqual(self.active,{'package','activation'});self.retired=True
        if self.retired and event=='observation_read' and 'activation' not in self.active:
            self.f.assertEqual(self.active,{'package'});self.point('independent absent read')
    def record(self):return model.parse_activation((self.common/'selinux-activation/activation.json').read_bytes())


def _value_scope(value):
    from contextlib import contextmanager
    @contextmanager
    def scope():yield value
    return scope()


class CoordinatorTests(unittest.TestCase):
    # Reuse the concrete initial registry/transaction setup, not its tests.
    def setUp(self):RegistryBridgeTests.setUp(self);self.b=EraseBindings(self)
    def run_erase(self):return erase._Coordinator(self.b,clock=lambda:self.b.now).erase_installed_provider(deadline=self.b.end)
    def test_normal_47_calls_three_windows_all_proofs_before_retirement_and_absent_read_after(self):
        import hashlib
        result=self.run_erase();self.assertIs(type(result),erase.ErasureResult)
        self.assertEqual(result.artifact,self.b.trust);self.assertFalse((self.b.common/'selinux-activation/activation.json').exists())
        self.assertEqual(self.b.key_path(self.b.common/'selinux-activation/lock'),self.b.lock_identity)
        self.assertEqual(len(self.b.commands),47)
        self.assertEqual(sum(k.startswith('registry') for k,_,_ in self.b.commands),27)
        self.assertEqual(self.b.registry_count,3);self.assertEqual(len(self.b.shared),3)
        for s in self.b.shared:self.assertEqual(s.events,['open','updated','updated','close'])
        self.assertEqual(len(self.b.setters),7);self.assertEqual(set(self.b.setters),set(self.b.labels))
        self.assertLess(self.b.events.index('retained exit'),self.b.events.index('before_slot_unlink'))
        self.assertLess(self.b.events.index('references exit'),self.b.events.index('before_slot_unlink'))
        self.assertLess(self.b.events.index('activation exit'),self.b.events.index('independent absent read'))
        for path,(digest,mode) in self.b.private.items():
            p=self.root/path[1:];self.assertEqual((hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_mode),(digest,mode))
            import os
            self.assertEqual(os.getxattr(p,'user.fixture'),b'preserved')

    def fresh(self):
        RegistryBridgeTests.setUp(self);self.b=EraseBindings(self)

    def test_consumer_erase_pending_and_public_entry_use_current_real_proofs(self):
        from dataclasses import asdict,replace
        from unittest.mock import patch
        from qshd_selinux_first_activation import _pending
        with self.b.package_engine().operation():
            with self.b.slot_engine().writer() as w:
                current=w.capture_current();prior=current.record
                pending=_pending(self.b.trust,'consumer-erase',model.HistoricalBasis(self.b.trust,prior.completion))
                w.begin_pending(erase._json(asdict(pending)),current)
        self.b.events=[]
        coordinator=erase._Coordinator
        with patch.object(erase,'_Production',return_value=self.b):
            # The real coordinator's clock seam is supplied separately; factory is fixed.
            with patch.object(erase,'_Coordinator',side_effect=lambda b:coordinator(b,clock=lambda:self.b.now)):
                result=erase.erase_installed_provider(deadline=self.b.end)
        self.assertEqual(result.result,'ERASED');self.assertEqual(len(self.b.commands),47)

    def test_unsupported_slots_consumer_files_and_dirty_contexts_refuse_before_mutation(self):
        from dataclasses import asdict
        from qshd_selinux_first_activation import _pending
        for case in ('absent','provider-fresh','provider-refresh','provider-erase','consumer-install','binary','pam','rpmnew','rpmsave','journal','missing-receipts'):
            with self.subTest(case=case):
                self.fresh();slotpath=self.b.common/'selinux-activation/activation.json'
                if case=='absent':slotpath.unlink()
                elif case in ('provider-fresh','provider-refresh','provider-erase','consumer-install'):
                    with self.b.package_engine().operation():
                        with self.b.slot_engine().writer() as w:
                            current=w.capture_current();prior=current.record
                            basis=None if case=='provider-fresh' else model.HistoricalBasis(self.b.trust,prior.completion)
                            w.begin_pending(erase._json(asdict(_pending(self.b.trust,case,basis))),current)
                elif case in ('binary','pam','rpmnew','rpmsave'):
                    path={'binary':'usr/bin/qshd','pam':'etc/pam.d/qshd','rpmnew':'etc/pam.d/qshd.rpmnew','rpmsave':'etc/pam.d/qshd.rpmsave'}[case]
                    (self.root/path).write_bytes(b'inert leftover');(self.root/path).chmod(0o644)
                elif case=='journal':(self.b.common/'selinux-contexts/journal').write_bytes(b'{}')
                else:(self.b.common/'selinux-contexts/receipts').unlink()
                with self.assertRaises(Exception):self.run_erase()
                self.assertNotIn('rows remove',self.b.events);self.assertFalse(self.b.setters);self.assertFalse(self.b.retired)

    def test_each_real_proof_finalizer_prevents_retirement(self):
        for point in ('preflight exit','registry1 exit','registry2 exit','registry3 exit','native1 exit','native2 exit','native3 exit','rpm exit','session exit','retained exit','contexts exit','consumer exit','references exit'):
            with self.subTest(point=point):
                self.fresh();self.b.fail=point
                with self.assertRaises(Exception):self.run_erase()
                self.assertFalse(self.b.retired);self.assertTrue((self.b.common/'selinux-activation/activation.json').exists())
                if point in ('preflight exit','registry1 exit','registry2 exit','native1 exit','rpm exit'):
                    self.assertEqual(self.b.record().state,'COMPLETE');self.assertNotIn('rows remove',self.b.events)
                else:self.assertEqual(self.b.record().state,'PENDING')

    def test_mutation_failures_cut_all_later_commands_and_leave_actual_pending(self):
        for point in ('rows remove','command remove qshd_contexts','setter','command remove qshd'):
            with self.subTest(point=point):
                self.fresh();self.b.fail=point
                with self.assertRaises(Exception):self.run_erase()
                self.assertEqual(self.b.record().state,'PENDING');self.assertFalse(self.b.retired)
                if point=='rows remove':self.assertNotIn('command remove qshd_contexts',self.b.events)
                if point in ('rows remove','command remove qshd_contexts','setter'):self.assertNotIn('command remove qshd',self.b.events)

    def test_each_real_registry_expiry_and_final_close_expiry_forbid_retirement(self):
        for phase in (1,2,3,'close'):
            with self.subTest(phase=phase):
                self.fresh()
                def delay(event):
                    if event==('registry3 exit' if phase=='close' else 'command registry'+str(phase)):
                        self.b.now=self.b.end
                self.b.action=delay
                with self.assertRaises(Exception):self.run_erase()
                self.assertFalse(self.b.retired)
                self.assertTrue(all(start<end for _,end,start in self.b.commands))
                self.assertEqual(self.b.record().state,'PENDING' if phase in (3,'close') else 'COMPLETE')

    def test_380_290_155_guards_reject_equality_and_less_time_with_original_end(self):
        for reserve,event in ((380,'session enter'),(290,'last guard'),(155,'native2 exit')):
            for offset in (-.001,0,.001):
                with self.subTest(reserve=reserve,offset=offset):
                    self.fresh();self.b.duration=0
                    def delay(point):
                        if event=='last guard':
                            hit=point=='command guard' and sum(k=='guard' for k,_,_ in self.b.commands)==4
                        else:hit=point==event
                        if hit:self.b.now=self.b.end-reserve+offset
                    self.b.action=delay
                    if offset<0:self.assertEqual(self.run_erase().result,'ERASED')
                    else:
                        with self.assertRaises(Exception):self.run_erase()
                        self.assertFalse(self.b.retired)
                        if reserve==380:self.assertFalse(any(k=='list' for k,_,_ in self.b.commands))
                        elif reserve==290:self.assertNotIn('rows remove',self.b.events)
                        else:self.assertNotIn('command remove qshd',self.b.events)
                    self.assertTrue(all(end<=self.b.end for _,end,_ in self.b.commands))

    def test_accumulated_registry_and_prelude_time_can_exhaust_existing_session_reserve(self):
        self.b.duration=4.2 # legal small profiles individually; accumulated prelude consumes >50.
        with self.assertRaises(Exception):self.run_erase()
        self.assertNotIn('rows remove',self.b.events);self.assertFalse(self.b.retired)
        self.assertTrue(all(k in ('guard','rpm','registry1') for k,_,_ in self.b.commands))

    def test_changed_post_core_default_and_slow_final_default_block_retirement(self):
        for case in ('changed','slow'):
            with self.subTest(case=case):
                self.fresh()
                def drift(event):
                    if event=='command remove qshd' and case=='changed':self.b.default_drift='system_u:object_r:var_t:s0'
                    if event=='default absent' and case=='slow':self.b.now=self.b.end
                self.b.action=drift
                with self.assertRaises(Exception):self.run_erase()
                self.assertEqual(len(self.b.setters),7);self.assertFalse(self.b.retired)
                self.assertEqual(self.b.record().state,'PENDING')

    def test_retirement_and_later_closure_failures_are_uncertain_without_recreation(self):
        from qshd_selinux_activation_state import OutcomeUncertain
        for point in ('before_slot_unlink','slot_unlink','slot_retire_directory_sync','slot_retire_readback','activation exit','independent absent read','package exit'):
            with self.subTest(point=point):
                self.fresh();self.b.fail=point
                with self.assertRaises(Exception) as caught:self.run_erase()
                exists=(self.b.common/'selinux-activation/activation.json').exists()
                self.assertEqual(exists,point=='before_slot_unlink')
                if exists:
                    self.assertNotIsInstance(caught.exception,OutcomeUncertain);self.assertEqual(self.b.record().state,'PENDING')
                else:self.assertIsInstance(caught.exception,OutcomeUncertain)

    def test_all_optional_retained_objects_missing_still_finishes_without_setters(self):
        import qshd_selinux_retained_labels as retained
        for path,kind,role,label in sorted(retained._ITEMS,key=lambda row:len(row[0]),reverse=True):
            p=self.root/path[1:]
            p.rmdir() if p.is_dir() else p.unlink()
        self.b.labels={}
        self.assertEqual(self.run_erase().result,'ERASED');self.assertFalse(self.b.setters)

    def test_single_use_and_invalid_deadline_refuse_without_new_commands(self):
        coordinator=erase._Coordinator(self.b,clock=lambda:self.b.now)
        coordinator.erase_installed_provider(deadline=self.b.end);count=len(self.b.commands)
        with self.assertRaises(erase.CoordinatorError):coordinator.erase_installed_provider(deadline=self.b.end)
        self.assertEqual(len(self.b.commands),count)
        for deadline in (True,float('inf'),float('nan'),100):
            with self.assertRaises(erase.CoordinatorError):erase._Coordinator(self.b,clock=lambda:self.b.now).erase_installed_provider(deadline=deadline)


    def test_two_real_rpm_owners_use_36_registry_calls_plus20_fixed(self):
        self.two_owners=True;self.fresh()
        self.assertEqual(self.run_erase().result,'ERASED')
        self.assertEqual(sum(k.startswith('registry') for k,_,_ in self.b.commands),36)
        self.assertEqual(len(self.b.commands),56)

    def test_actual_unrelated_candidate_changed_after_core_unload_is_not_adopted(self):
        def drift(event):
            if event=='command remove qshd':self.unrelated.write_bytes(b'user_r:staff_t:s0 user_r:staff_t:s0\n')
        self.b.action=drift
        with self.assertRaises(erase.CoordinatorError):self.run_erase()
        self.assertEqual(self.b.record().state,'PENDING');self.assertFalse(self.b.retired)


    def test_actual_successful_erase_fresh_pre_and_pristine_reinstall_preserve_private_files(self):
        import hashlib
        from unittest.mock import patch
        import qshd_selinux_first_activation as first
        import qshd_selinux_provider_pre as pre
        result=self.run_erase();erase_calls=len(self.b.commands)
        self.assertEqual(erase_calls,47)
        # The erased historical result cannot act as a TrustedArtifact.
        with self.assertRaises(first.CoordinatorError):
            first._Coordinator(self.b,clock=lambda:self.b.now).activate_first(result,self.b.core,self.b.contexts_pp,deadline=self.b.now+430)
        self.b.end=self.b.now+430
        b=self.b;b.retired=False
        class FreshBindings:
            def preconditions(inner):b.preconditions()
            def guard(inner,deadline):
                for unused in range(2):b.command('freshpre-guard',deadline)
            def package(inner):return b.package_engine()
            def slot(inner):return b.slot_engine()
        # Explicit existing fresh-pre admission: no erased object is supplied.
        pre._Coordinator(FreshBindings(),clock=lambda:b.now).invalidate(b.trust,deadline=b.now+30)
        self.assertEqual(b.record().intent,'provider-fresh')
        b.retired=False
        complete=first._Coordinator(b,clock=lambda:b.now).activate_installed_pristine_pending_first(deadline=b.end)
        self.assertEqual(complete.state,'COMPLETE');self.assertEqual(complete.artifact,b.trust)
        self.assertEqual(b.phase,'pair')
        self.assertNotEqual(complete.operation_id,result.operation_id)
        for path,(digest,mode) in b.private.items():
            p=self.root/path[1:];self.assertEqual((hashlib.sha256(p.read_bytes()).hexdigest(),p.stat().st_mode),(digest,mode))


    def test_real_partial_context_replacement_preserves_journal_and_blocks_policy_removal(self):
        self.b.fail='transaction target_rename'
        with self.assertRaises(erase.CoordinatorError):self.run_erase()
        self.assertTrue((self.b.common/'selinux-contexts/journal').exists())
        self.assertEqual(self.b.record().state,'PENDING');self.assertFalse(self.b.retired)
        self.assertNotIn('command remove qshd_contexts',self.b.events)
        self.assertFalse(self.b.setters)

    def test_real_rpm_inventory_refuses_selected_consumer_and_incomplete_output(self):
        from scripts.tests.test_selinux_rpm_query import package
        for raw in (package('qshd'),b'incomplete'):
            with self.subTest(raw=raw):
                self.fresh();self.b.rpm_inventory=raw
                with self.assertRaises(erase.CoordinatorError):self.run_erase()
                self.assertEqual(self.b.record().state,'COMPLETE');self.assertNotIn('rows remove',self.b.events)

    def test_post_removal_owner_manifest_or_candidate_set_change_refuses_retirement(self):
        for case in ('owner','manifest','candidate'):
            with self.subTest(case=case):
                self.fresh()
                def drift(event):
                    if event!='command remove qshd':return
                    if case=='owner':self.runner.mapping[self.paths[1]]='container-selinux'
                    elif case=='manifest':self.runner.paths.append('/usr/share/public-fixture')
                    else:
                        p=self.base/'users/extra';p.write_bytes(b'user_r:user_t:s0 user_r:user_t:s0\n');p.chmod(0o644)
                self.b.action=drift
                with self.assertRaises(erase.CoordinatorError):self.run_erase()
                self.assertFalse(self.b.retired);self.assertEqual(self.b.record().state,'PENDING')

    def test_failed_erase_cannot_bypass_current_pristine_install_admission(self):
        import qshd_selinux_first_activation as first
        import qshd_selinux_provider_pre as pre
        self.b.fail='command remove qshd'
        with self.assertRaises(erase.CoordinatorError):self.run_erase()
        self.b.fail=None;count=len(self.b.commands)
        with self.assertRaises(first.CoordinatorError):
            first._Coordinator(self.b,clock=lambda:self.b.now).activate_installed_pristine_pending_first(deadline=self.b.end)
        self.assertEqual(self.b.record().intent,'provider-erase')
        self.assertFalse(any(kind.startswith('install-') for kind,_,_ in self.b.commands[count:]))
