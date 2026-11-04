"""Pure synthetic activation evidence tests; no native or filesystem observer."""
import copy
from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'packaging/selinux'))
import qshd_selinux_activation as model


def document(state='COMPLETE',intent='provider-fresh'):
    artifact=dict(provider_version='0.3.0',manifest_sha256='b'*64,core_pp_sha256='c'*64,contexts_pp_sha256='f'*64)
    completion=dict(load='normal-pair-install-reload-v2',extracted_hll_sha256=dict(core='c'*64,contexts='f'*64),
                    contexts=dict(registry_sha256='d'*64,receipts_sha256='e'*64))
    return dict(schema=2,state=state,operation_id='a'*32,profile='fedora44-targeted-pair-v2',abi=2,query_profile=1,
                artifact=artifact,modules={role:dict(name=name,priority=400,store='targeted',format='pp') for role,name in [('core','qshd'),('contexts','qshd_contexts')]},
                intent=intent,basis=None if state=='COMPLETE' or intent=='provider-fresh' else dict(artifact=copy.deepcopy(artifact),completion=copy.deepcopy(completion)),
                completion=completion if state=='COMPLETE' else None)


def encoded(value):
    return json.dumps(value).encode()


class ActivationTests(unittest.TestCase):
    def test_valid_records_and_trusted_evidence(self):
        for state in ('PENDING', 'COMPLETE'):
            record = model.parse_activation(encoded(document(state)))
            self.assertEqual(record.state, state)
            self.assertEqual(record.artifact.provider_version, '0.3.0')
            with self.assertRaises(FrozenInstanceError): record.state = 'COMPLETE'
            with self.assertRaises(FrozenInstanceError): record.artifact.core_pp_sha256 = 'f'*64
        record = model.parse_activation(encoded(document()))
        trusted = model.TrustedArtifact('0.3.0', 'b'*64, 'c'*64, 'f'*64)
        binding = model.ContextBinding('d'*64, 'e'*64)
        self.assertIs(model.require_complete(record, trusted, binding), record)
        self.assertFalse(hasattr(record, 'ready'))
        with self.assertRaises(model.ActivationError):
            model.require_complete(model.parse_activation(encoded(document('PENDING'))), trusted, binding)
        for artifact, context in ((model.TrustedArtifact('0.3', 'b'*64, 'c'*64, 'f'*64), binding),
                                  (trusted, model.ContextBinding('f'*64, 'e'*64))):
            with self.assertRaises(model.ActivationError): model.require_complete(record, artifact, context)

    def test_invalid_json_and_bounds_are_bounded(self):
        for raw in (b'', b'\xff', b'{}'*40000, b'[]', b'null', b'{"schema":1,"schema":1}',
                    encoded(document()).replace(b'"name": "qshd"', b'"name":"qshd","name":"qshd"'),
                    b'['*1500 + b']'*1500):
            with self.subTest(raw_length=len(raw)), self.assertRaises(model.ActivationError) as caught:
                model.parse_activation(raw)
            self.assertLess(len(str(caught.exception)), 80)
        with self.assertRaises(model.ActivationError): model.parse_activation('{}')

    def test_exact_keys_and_scalar_types(self):
        original = document()
        for location in ((), ('artifact',), ('modules',), ('modules','core'), ('modules','contexts'), ('completion',), ('completion','extracted_hll_sha256'), ('completion','contexts')):
            for action in ('missing', 'extra'):
                d = copy.deepcopy(original); node=d
                for key in location: node=node[key]
                if action == 'missing': del node[next(iter(node))]
                else: node['unexpected']='private diagnostic must not leak'
                with self.subTest(location=location, action=action), self.assertRaises(model.ActivationError):
                    model.parse_activation(encoded(d))
        changes = [(('schema',), True), (('abi',), True), (('query_profile',), '1'),
                   (('modules','core','priority'), True), (('modules','core','priority'), 400.0),
                   (('artifact','provider_version'), 2), (('operation_id',), None),
                   (('state',), 'READY'), (('profile',), 'other'), (('abi',), 1),
                   (('query_profile',), 2), (('modules','core','name'), 'other'),
                   (('modules','core','store'), 'mls'), (('modules','core','format'), 'cil'),
                   (('modules','core','priority'), 401), (('completion','load'), 'skip-reload')]
        for path, value in changes:
            d=copy.deepcopy(original);node=d
            for key in path[:-1]:node=node[key]
            node[path[-1]]=value
            with self.subTest(path=path,value=value), self.assertRaises(model.ActivationError): model.parse_activation(encoded(d))
        for state, completion in (('PENDING',original['completion']), ('COMPLETE',None)):
            d=document(state);d['completion']=completion
            with self.assertRaises(model.ActivationError):model.parse_activation(encoded(d))

    def test_hash_version_and_identity_validation(self):
        for key in ('manifest_sha256','core_pp_sha256','contexts_pp_sha256'):
            for value in ('A'*64,'a'*63,'z'*64,False):
                d=document();d['artifact'][key]=value
                with self.assertRaises(model.ActivationError):model.parse_activation(encoded(d))
        for value in ('a'*31,'A'*32,'a'*33,1):
            d=document();d['operation_id']=value
            with self.assertRaises(model.ActivationError):model.parse_activation(encoded(d))
        for value in ('','-bad','é','a'*81,'bad value'):
            with self.assertRaises(model.ActivationError): model.TrustedArtifact(value,'b'*64,'c'*64,'f'*64)
        for value in ('X'*64, None, 0):
            with self.assertRaises(model.ActivationError):model.ContextBinding(value,'e'*64)
        d=document();d['completion']['extracted_hll_sha256']['core']='f'*64
        with self.assertRaises(model.ActivationError):model.parse_activation(encoded(d))
        d=document();d['completion']['contexts']['receipts_sha256']='BAD'
        with self.assertRaises(model.ActivationError):model.parse_activation(encoded(d))

    def test_pair_roles_legacy_schema_and_historical_basis(self):
        for intent in ('provider-refresh','consumer-install','consumer-erase','provider-erase'):
            record=model.parse_activation(encoded(document('PENDING',intent)))
            self.assertEqual(record.basis.artifact,record.artifact)
            with self.assertRaises(FrozenInstanceError):record.basis.artifact.core_pp_sha256='0'*64
        for mutate in (lambda x:x.update(schema=1),lambda x:x.update(abi=1),
                       lambda x:x['modules'].update(contexts=x['modules']['core']),
                       lambda x:x['artifact'].update(pp_sha256='c'*64),
                       lambda x:x.update(basis={'artifact':x['artifact'],'completion':x['completion']}),
                       lambda x:x.update(intent='unknown')):
            value=document();mutate(value)
            with self.assertRaises(model.ActivationError):model.parse_activation(encoded(value))
        value=document('PENDING','consumer-erase');value['basis']['basis']=None
        with self.assertRaises(model.ActivationError):model.parse_activation(encoded(value))
        value=document('PENDING','consumer-erase');value['basis']['completion']['extracted_hll_sha256']['contexts']='0'*64
        with self.assertRaises(model.ActivationError):model.parse_activation(encoded(value))
        for intent,basis in [('provider-fresh',document('PENDING','consumer-erase')['basis']),('provider-erase',None)]:
            value=document('PENDING',intent);value['basis']=basis
            with self.assertRaises(model.ActivationError):model.parse_activation(encoded(value))

if __name__ == '__main__': unittest.main()
