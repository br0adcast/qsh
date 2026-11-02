#!/usr/bin/python3
"""Offline incoming-authority capsule renderer, not an RPM scriptlet.

The caller supplies explicitly reviewed incoming build bytes. Embedded hashes
bind those bytes, never authenticate arbitrary caller-provided source maps.
"""
import base64
import hashlib
import json
import zlib
from assemble_payload import _artifact
from qshd_selinux_activation import TrustedArtifact

MODULES=tuple('qshd_selinux_'+name for name in ('contexts','fs','activation',
    'activation_state','package_state','process'))+('stop_guard','qshd_selinux_provider_pre')
CHILD_LIMIT=98304


def _request(trusted):
    return json.dumps(dict(schema=1,phase='provider-pre-fresh',artifact=dict(
        provider_version=trusted.provider_version,manifest_sha256=trusted.manifest_sha256,
        pp_sha256=trusted.pp_sha256)),sort_keys=True,separators=(',',':')).encode('ascii')


def _loader(source_map):
    entries=[]
    for name in MODULES:
        data=source_map[name]
        entries.append((name,hashlib.sha256(data).hexdigest(),base64.b85encode(zlib.compress(data,9)).decode('ascii')))
    return '''import base64,hashlib,sys,types,zlib
_entries = '''+repr(entries)+'''
for _name,_digest,_encoded in _entries:
    if _name in sys.modules: raise RuntimeError('CAPSULE_MODULE_PRESENT')
    _raw=zlib.decompress(base64.b85decode(_encoded))
    if hashlib.sha256(_raw).hexdigest()!=_digest: raise RuntimeError('CAPSULE_SOURCE_HASH')
    _module=types.ModuleType(_name)
    _module.__file__='<qshd-provider-pre:'+_name+':' +_digest+'>'
    sys.modules[_name]=_module
    exec(compile(_raw,_module.__file__,'exec'),_module.__dict__)
'''


def _child_source(source_map,request):
    return _loader(source_map)+'''_pre=sys.modules['qshd_selinux_provider_pre']
raise SystemExit(_pre._child_main('''+repr(request)+''',sys.argv[1:]))
'''


def render(source_map,trusted_artifact,*,artifact_bytes,pp_bytes):
    if type(source_map) is not dict or set(source_map)!=set(MODULES):raise ValueError('SOURCE_MAP')
    for name,data in source_map.items():
        if type(data) is not bytes or not data or len(data)>131072 or b'\0' in data:raise ValueError('SOURCE_BYTES')
        try:compile(data.decode('utf-8','strict'),name,'exec')
        except (SyntaxError,UnicodeError):raise ValueError('SOURCE_BYTES') from None
    if type(trusted_artifact) is not TrustedArtifact:raise ValueError('ARTIFACT')
    if (type(artifact_bytes) is not bytes or not 0<len(artifact_bytes)<=65536 or
            type(pp_bytes) is not bytes or not 0<len(pp_bytes)<=16*1024**2 or
            hashlib.sha256(artifact_bytes).hexdigest()!=trusted_artifact.manifest_sha256 or
            hashlib.sha256(pp_bytes).hexdigest()!=trusted_artifact.pp_sha256 or
            _artifact(artifact_bytes)!=trusted_artifact.provider_version):raise ValueError('ARTIFACT')
    request=_request(trusted_artifact);child=_child_source(source_map,request)
    if len(child.encode('utf-8'))>CHILD_LIMIT:raise ValueError('CHILD_SIZE')
    return ('''import time
_capsule_started=time.monotonic()
'''+_loader(source_map)+'''_pre=sys.modules['qshd_selinux_provider_pre']
_pre._ENTRY_STARTED=_capsule_started
raise SystemExit(_pre.run_embedded_pre('''+repr(child)+','+repr(request)+'''))
''').encode('utf-8')
