"""Lock-free installed public references, never runtime-derived trust or readiness.

Trusted signed provider installation supplies the reference JSON/code/files
as one reviewed payload. Root metadata is not independent signature proof.
Future adapters must select one package lease for capture/use/recheck; do not
hold a second package flock around activate_first, which acquires its own.
No coordinator/start adapter or package hooks are wired here.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path

from qshd_selinux_activation import TrustedArtifact
from qshd_selinux_fs import SafeFiles

_SHARE='usr/share/qshd-selinux'
_LIMITS={'reference.json':16384,'qshd.pp':16*1024**2,
         'artifact.json':65536,'qshd.fedora-selinux':4096}
_KEYS={'provider_version','manifest_sha256','pp_sha256','pam_sha256','expected_pam'}


class ReferenceError(ValueError):
    """Fixed bounded refusal without file contents or caller path values."""


def _fail(code):raise ReferenceError(code)


def _pairs(items):
    value={}
    for key,item in items:
        if key in value:_fail('DUPLICATE_KEY')
        value[key]=item
    return value


def _document(raw):
    try:value=json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs)
    except (ValueError,UnicodeError,RecursionError):raise ReferenceError('REFERENCE_JSON') from None
    if type(value) is not dict or set(value)!=_KEYS or any(type(item) is not str for item in value.values()):
        _fail('REFERENCE_SCHEMA')
    artifact=TrustedArtifact(value['provider_version'],value['manifest_sha256'],value['pp_sha256'])
    digest=value['pam_sha256']
    if len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):_fail('REFERENCE_DIGEST')
    try:pam=value['expected_pam'].encode('utf-8')
    except UnicodeError:raise ReferenceError('PAM_UTF8') from None
    if not 0<len(pam)<=4096:_fail('PAM_LIMIT')
    if hashlib.sha256(pam).hexdigest()!=digest:_fail('PAM_IDENTITY')
    return artifact,digest,pam


@dataclass(frozen=True)
class InstalledReferences:
    """Trusted assembled identities and copied bytes; not current installed state."""
    artifact: TrustedArtifact
    pp_bytes: bytes
    expected_pam: bytes


def production_references():
    if os.geteuid()!=0:_fail('ROOT_REQUIRED')
    return References()


def _testing_references(root):
    return References(_root=root,_uid=os.getuid())


class References(SafeFiles):
    """Single-use read-only scope. Private roots are only for trusted tests."""
    def __init__(self,*,_root=None,_uid=0):
        try:
            self.anchor=Path('/') if _root is None else Path(_root)
            if not self.anchor.is_absolute() or '\0' in str(self.anchor) or '..' in self.anchor.parts:
                _fail('ANCHOR')
        except (TypeError,ValueError):raise ReferenceError('ANCHOR') from None
        if type(_uid) is not int or _uid<0:_fail('UID')
        self.uid=_uid;self.hook=lambda event:None
        self.anchors=[];self.routes=[];self._state='new';self._closed=False
        self._observed=None;self._snapshots=None;self._unclosed=()

    def __enter__(self):
        if self._state!='new':_fail('REFERENCE_LIFETIME')
        self._state='failed'
        try:
            self._directory_fd=self._directory(self.anchor/_SHARE)
            self._validate_directory_routes()
            self._state='open'
            return self
        except BaseException as error:
            self._close()
            if not isinstance(error,Exception):raise
            raise ReferenceError('REFERENCE_ADMISSION') from error

    def _sample(self):
        self._validate_directory_routes()
        snapshots={}
        for name,limit in _LIMITS.items():
            value=self._read(self._directory_fd,name,limit=limit)
            if value['mode']!=0o644:_fail('REFERENCE_MODE')
            if not value['data']:_fail('REFERENCE_EMPTY')
            snapshots[name]=value
        artifact,pam_digest,pam=_document(snapshots['reference.json']['data'])
        for name,digest in [('qshd.pp',artifact.pp_sha256),('artifact.json',artifact.manifest_sha256),
                            ('qshd.fedora-selinux',pam_digest)]:
            if hashlib.sha256(snapshots[name]['data']).hexdigest()!=digest:_fail('REFERENCE_HASH')
        if snapshots['qshd.fedora-selinux']['data']!=pam:_fail('PAM_BYTES')
        self._validate_directory_routes()
        return InstalledReferences(artifact,snapshots['qshd.pp']['data'],pam),snapshots

    def capture(self):
        if self._state!='open':
            if not self._closed:self._state='failed'
            _fail('REFERENCE_LIFETIME')
        self._state='failed'
        try:
            value,snapshots=self._sample()
            again,current=self._sample()
            if again!=value or not all(self._same(current[name],snapshots[name],times=True) for name in _LIMITS):
                _fail('REFERENCE_DRIFT')
            self._observed=value;self._snapshots=snapshots;self._state='captured'
            return value
        except BaseException as error:
            if not isinstance(error,Exception) or isinstance(error,ReferenceError):raise
            raise ReferenceError('REFERENCE_REFUSED') from error

    def recheck(self,value):
        if self._state not in ('captured','checked') or value is not self._observed:
            if not self._closed:self._state='failed'
            _fail('REFERENCE_LIFETIME')
        self._state='failed'
        try:
            current,snapshots=self._sample()
            if current!=value or not all(self._same(snapshots[name],self._snapshots[name],times=True) for name in _LIMITS):
                _fail('REFERENCE_DRIFT')
            self._state='checked'
        except BaseException as error:
            if not isinstance(error,Exception) or isinstance(error,ReferenceError):raise
            raise ReferenceError('REFERENCE_REFUSED') from error

    def _close(self):
        self._closed=True;self._state='closed';failed=[]
        fds=self.anchors+[part for route in self.routes for part in (route[0],route[2])]
        self.anchors=[];self.routes=[]
        for fd in reversed(list(dict.fromkeys(fds))):
            try:os.close(fd)
            except BaseException:failed.append(fd)
        self._unclosed=tuple(failed)
        if failed:_fail('REFERENCE_CLOSE')  # Do not retry uncertain numeric FDs.

    def __exit__(self,kind,value,traceback):
        try:
            if kind is None:
                if self._state!='checked':_fail('FINAL_RECHECK_REQUIRED')
                self.recheck(self._observed)
        finally:self._close()
        return False
