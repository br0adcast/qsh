#!/usr/bin/env python3
"""Bounded inert archive staging; producer evidence is not signature authority."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import zlib

_spec=importlib.util.spec_from_file_location('release_version',Path(__file__).with_name('check-release-version.py'))
_version=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_version)
DARWIN_TARGETS={'aarch64-apple-darwin':'arm64','x86_64-apple-darwin':'x86_64'}
ARCHIVE_LIMIT=512*1024**2
METADATA_LIMIT=64*1024
EXPANDED_LIMIT=768*1024**2
EXECUTABLE_LIMIT=256*1024**2
DOCUMENT_LIMIT=4*1024**2
PROGRAMS=('qsh','qshd')
# Archives carry both products, including the client's additional native code.
# This does not add notices or dependencies to server-only packages.
NOTICES={'LICENSE-OPENSSL.txt':'openssl.txt',
         'LICENSE-AWS-LC-RS.txt':'aws-lc-rs.txt','LICENSE-AWS-LC.txt':'aws-lc.txt'}
# Pinned to the maintained notice bytes; isolated tools need no source-tree data.
NOTICE_SHA256 = {
    'LICENSE-OPENSSL.txt': '7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a',
    'LICENSE-AWS-LC-RS.txt': 'b50b376e7d24a0598488b730c3034ffcd0b58dd36c0913a24b9903a3cfd04bf7',
    'LICENSE-AWS-LC.txt': '728536b4160e051f86d7c9c388f704866b3d512cd7df97ac3516c65279523c4e',
}
DOCUMENTS=('README.md','LICENSE','CHANGELOG.md',*NOTICES)

class SmokeError(ValueError):
    """Closed refusal category, without paths or input content."""


_CATEGORIES=frozenset('ARCHIVE_LIMIT ARCHIVE_NAME BINDING BOUNDS CLI DEADLINE DESTINATION EXECUTABLE '
    'EXPANDED_LIMIT FAILURE_CUSTODY HARNESS HARNESS_FAILED HARNESS_OUTPUT HOST INPUT INPUT_DRIFT '
    'INPUT_LIMIT JSON METADATA NATIVE_REFUSED NOTICE_BYTES PAYLOAD_DIGEST PREPARE RECEIPT SCHEMA '
    'SOURCE STAGING_CLEANUP STAGING_CLOSE STAGING_DRIFT TARGET TAR_CHECKSUM TAR_END TAR_FORMAT '
    'TAR_HEADER TAR_HEADERS TAR_LINK TAR_MEMBERS TAR_SIZE TAR_TRAILING TAR_UNSUPPORTED TRUNCATED '
    'UNSETTLED_HARNESS VERSION WRITE'.split())
_PHASES=frozenset('CLI HARNESS_SELECTION HOST STAGING PREPARE INPUT_BINDING CONTROLLED_EXECUTE '
    'CONTROLLED_VERIFY CONTROLLED_RECHECK POSITIVE_EXECUTE POSITIVE_VERIFY POSITIVE_RECHECK '
    'PUBLIC_PROJECTION EVIDENCE_WRITE PREPARE_COMMAND VERIFY_COMMAND'.split())
_STATES=frozenset(('NOT_ATTEMPTED','ABSENT','VALID','INVALID','UNSETTLED'))
_EXECUTE_CODES=frozenset(('INPUT','HOST','DEADLINE','START','CUSTODY','IO','CONNECT','OUTPUT',
    'IDENTITY','CANCELLED','CLIENT_EXIT','UNSETTLED','FAILURE_CUSTODY','unowned wait','OTHER_EXECUTE_ERROR'))


class DiagnosticContext:
    """Informational only; never admits an archive or proves native custody."""
    def __init__(self):
        self.phase='CLI'
        self.reset_harness()

    def reset_harness(self):
        self.harness_status=None
        self.rust_outcome=None
        self.diagnostic_state='NOT_ATTEMPTED'


def _status(value):
    return value if type(value) is int and -2147483648<=value<=2147483647 else None


def _outcome(value,mode):
    _keys(value,('schema','kind','mode','outcome','code'))
    if (type(value['schema']) is not int or value['schema']!=1
            or value['kind']!='darwin-archive-execute-outcome'
            or type(value['mode']) is not str or value['mode'] not in ('failure','positive')
            or value['mode']!=mode):fail('SCHEMA')
    if value['outcome']=='ok':
        if value['code'] is not None:fail('SCHEMA')
    elif value['outcome']=='error':
        if type(value['code']) is not str or value['code'] not in _EXECUTE_CODES:fail('SCHEMA')
    else:fail('SCHEMA')
    return value


def _read_outcome(directory,mode,*,held_directory=None):
    """Read fixed private scratch only after the exact writer has been reaped."""
    held=None;fd=None
    try:
        held=(os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
              if held_directory is None else os.dup(held_directory))
        before=os.fstat(held)
        if (before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o700
                or _snapshot(os.stat(directory,follow_symlinks=False))!=_snapshot(before)):
            return 'INVALID',None
        try:fd=os.open('execute-outcome.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=held)
        except FileNotFoundError:return 'ABSENT',None
        info=os.fstat(fd);snapshot=_snapshot(info)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid()
                or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=512):return 'INVALID',None
        if _snapshot(os.stat('execute-outcome.json',dir_fd=held,follow_symlinks=False))!=snapshot:return 'INVALID',None
        raw=bytearray()
        while True:
            chunk=os.read(fd,513-len(raw))
            if not chunk:break
            raw.extend(chunk)
            if len(raw)>512:return 'INVALID',None
        if (not raw.isascii() or _snapshot(os.fstat(fd))!=snapshot
                or _snapshot(os.stat('execute-outcome.json',dir_fd=held,follow_symlinks=False))!=snapshot
                or _snapshot(os.fstat(held))!=_snapshot(before)
                or _snapshot(os.stat(directory,follow_symlinks=False))!=_snapshot(before)):
            return 'INVALID',None
        return 'VALID',_outcome(_json(bytes(raw),512),mode)
    except (ValueError,OSError,EOFError):return 'INVALID',None
    finally:
        # Diagnostic close errors cannot replace the original refusal.
        for selected in (fd,held):
            if selected is not None:
                try:os.close(selected)
                except OSError:pass


def _refusal_record(error,context):
    category='INVALID'
    if isinstance(error,SmokeError):
        if len(error.args)==1 and type(error.args[0]) is str and error.args[0] in _CATEGORIES:category=error.args[0]
    elif isinstance(error,OSError):category='OS'
    elif isinstance(error,EOFError):category='EOF'
    elif isinstance(error,zlib.error):category='ZLIB'
    phase=context.phase if type(context.phase) is str and context.phase in _PHASES else 'CLI'
    state=context.diagnostic_state if type(context.diagnostic_state) is str and context.diagnostic_state in _STATES else 'NOT_ATTEMPTED'
    outcome=None
    if state=='VALID':
        try:
            value=context.rust_outcome
            outcome=_outcome(value,value.get('mode') if type(value) is dict else None)
        except (ValueError,TypeError):state='INVALID'
    return dict(schema=1,kind='darwin-archive-refusal',phase=phase,category=category,
                harness_status=_status(context.harness_status),rust_outcome=outcome,diagnostic_state=state)


def fail(code):raise SmokeError(code)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')+b'\n'
def digest(raw):return hashlib.sha256(raw).hexdigest()

def _pairs(items):
    value={}
    for key,item in items:
        if key in value:fail('JSON')
        value[key]=item
    return value


def _json(raw,limit):
    if type(raw) is not bytes or not 0<len(raw)<=limit:fail('JSON')
    try:return json.loads(raw.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=lambda value:fail('JSON'))
    except (ValueError,UnicodeError,RecursionError):fail('JSON')

def _keys(value,keys):
    if type(value) is not dict or set(value)!=set(keys):fail('SCHEMA')

def _token(value,pattern,limit=128):
    if type(value) is not str or len(value)>limit or re.fullmatch(pattern,value) is None:fail('SCHEMA')
    return value

def _sha(value):return _token(value,r'[0-9a-f]{64}',64)
def _numeric_version(value):return _token(value,r'[0-9]{1,5}(?:\.[0-9]{1,3}){0,2}',20)

def _metadata(raw,target):
    value=_json(raw,METADATA_LIMIT)
    _keys(value,('schema','source','target','host','sdk','rust','native','binaries'))
    if type(value['schema']) is not int or value['schema']!=1 or value['target']!=target:fail('METADATA')
    source=value['source'];_keys(source,('sha','run_id','run_attempt'))
    _token(source['sha'],r'[0-9a-f]{40}',40)
    _token(source['run_id'],r'[0-9]{1,30}',30);_token(source['run_attempt'],r'[0-9]{1,10}',10)
    host=value['host'];_keys(host,('arch','macos_version','macos_build','image_version'))
    _token(host['arch'],r'arm64|x86_64');_numeric_version(host['macos_version'])
    _token(host['macos_build'],r'[A-Za-z0-9.-]+',64)
    if host['image_version'] is not None:_token(host['image_version'],r'[A-Za-z0-9_.-]+',80)
    sdk=value['sdk'];_keys(sdk,('version','xcode_version','xcode_build'))
    _numeric_version(sdk['version']);_numeric_version(sdk['xcode_version']);_token(sdk['xcode_build'],r'[A-Za-z0-9.-]+',64)
    rust=value['rust'];_keys(rust,('release','commit-hash','host','reported_deployment_target','explicit_deployment_target'))
    for name in ('release','commit-hash','host'):_token(rust[name],r'[A-Za-z0-9_.+-]+',256)
    _numeric_version(rust['reported_deployment_target'])
    if rust['explicit_deployment_target'] is not None:_numeric_version(rust['explicit_deployment_target'])
    native=value['native'];_keys(native,('version','manifest_sha256','compiler_sha256','compiler_version','flags','macros'))
    _token(native['version'],r'[0-9]+(?:\.[0-9]+){1,2}');_sha(native['manifest_sha256']);_sha(native['compiler_sha256']);_numeric_version(native['compiler_version'])
    flags=native['flags']
    if type(flags) is not list or len(flags)>32:fail('METADATA')
    seen=set();index=0
    while index<len(flags):
        flag=flags[index]
        if flag in ('-arch','-isysroot'):
            if flag in seen or index+1>=len(flags):fail('METADATA')
            if flags[index+1]!=(DARWIN_TARGETS[target] if flag=='-arch' else '<SDK>'):fail('METADATA')
            seen.add(flag);index+=2
        else:
            _token(flag,r'-(?:O[0-3s]|fPIC|g0|mmacosx-version-min=[0-9]+(?:\.[0-9]+){0,2})');index+=1
    if seen!={'-arch','-isysroot'}:fail('METADATA')
    macros=native['macros'];allowed={'__APPLE__','__aarch64__','__arm64__','__x86_64__','__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__','__ENVIRONMENT_OS_VERSION_MIN_REQUIRED__'}
    if type(macros) is not dict or not set(macros)<=allowed:fail('METADATA')
    for item in macros.values():_token(item,r'[0-9]+',20)
    records=value['binaries']
    if type(records) is not list or len(records)!=5:fail('METADATA')
    found={}
    expected={(role,program) for role in ('staged','extracted') for program in PROGRAMS}|{('native-probe','version-probe')}
    for record in records:
        _keys(record,('role','program','sha256','arch','version_command'))
        if type(record['role']) is not str or type(record['program']) is not str:fail('METADATA')
        identity=(record['role'],record['program'])
        if identity not in expected or identity in found or record['arch']!=DARWIN_TARGETS[target]:fail('METADATA')
        _sha(record['sha256']);command=record['version_command'];_keys(command,('kind','platform','minos','sdk'))
        if command['kind'] not in ('LC_BUILD_VERSION','LC_VERSION_MIN_MACOSX') or command['platform']!='macos':fail('METADATA')
        _numeric_version(command['minos'])
        if command['sdk'] is not None:_numeric_version(command['sdk'])
        found[identity]=record['sha256']
    for program in PROGRAMS:
        if found['staged',program]!=found['extracted',program]:fail('METADATA')
    return source['sha'],{program:found['extracted',program] for program in PROGRAMS}


def _snapshot(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,info.st_gid,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def _open_input(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=limit:fail('INPUT')
        if _snapshot(os.stat(path,follow_symlinks=False))!=_snapshot(info):fail('INPUT_DRIFT')
        return fd,_snapshot(info)
    except BaseException:
        os.close(fd);raise


def _recheck(path,fd,snapshot):
    if _snapshot(os.fstat(fd))!=snapshot or _snapshot(os.stat(path,follow_symlinks=False))!=snapshot:fail('INPUT_DRIFT')

def _hash_fd(fd,limit=ARCHIVE_LIMIT):
    os.lseek(fd,0,os.SEEK_SET);value=hashlib.sha256();total=0
    while True:
        chunk=os.read(fd,min(65536,limit-total+1))
        if not chunk:break
        total+=len(chunk)
        if total>limit:fail('INPUT_LIMIT')
        value.update(chunk)
    return value.hexdigest()

RECEIPT_LIMIT=16*1024
_PREPARED_KEYS={'schema','kind','request_id','source_commit','version','target','archive_sha256',
                'metadata_sha256','binaries','challenge','expected_output_digest'}
_NATIVE_KEYS={'schema','kind','request_id','prepared_sha256','source_commit','version','target',
              'archive_sha256','metadata_sha256','binaries','host','status','failure','client_exit',
              'daemon_exit','output_digest','ownership'}
_FAILURES={'INPUT','HOST','START','IDENTITY','CONNECT','OUTPUT','CLIENT_EXIT','DAEMON_EXIT',
           'DEADLINE','CANCELLED','CUSTODY','IO','UNKNOWN'}


def _selection(version,target):
    if type(version) is not str or len(version)>128 or not version.isascii() or not _version.valid_version(version):fail('VERSION')
    if type(target) is not str or target not in DARWIN_TARGETS:fail('TARGET')


def _binaries(value):
    _keys(value,PROGRAMS)
    for record in value.values():
        _keys(record,('sha256','bytes'));_sha(record['sha256'])
        if type(record['bytes']) is not int or not 1<=record['bytes']<=EXECUTABLE_LIMIT:fail('RECEIPT')


def _receipt(raw,keys,kind):
    value=_json(raw,RECEIPT_LIMIT);_keys(value,keys)
    if canonical(value)!=raw or type(value['schema']) is not int or value['schema']!=1 or value['kind']!=kind:fail('RECEIPT')
    _token(value['request_id'],r'[0-9a-f]{32}',32);_token(value['source_commit'],r'[0-9a-f]{40}',40)
    _selection(value['version'],value['target']);_sha(value['archive_sha256']);_sha(value['metadata_sha256']);_binaries(value['binaries'])
    return value


def _prepared(raw):
    value=_receipt(raw,_PREPARED_KEYS,'darwin-archive-prepared')
    _token(value['challenge'],r'[0-9a-f]{48}',48);_sha(value['expected_output_digest'])
    if digest(value['challenge'].encode('ascii'))!=value['expected_output_digest']:fail('RECEIPT')
    return value


def verify_result(staging_receipt,native_receipt):
    """Validate trusted harness evidence consistency, never authenticate execution."""
    prepared=_prepared(staging_receipt)
    native=_receipt(native_receipt,_NATIVE_KEYS,'darwin-archive-smoke')
    _sha(native['prepared_sha256'])
    if native['prepared_sha256']!=digest(staging_receipt):fail('BINDING')
    for key in ('request_id','source_commit','version','target','archive_sha256','metadata_sha256','binaries'):
        if canonical(native[key])!=canonical(prepared[key]):fail('BINDING')
    host=native['host'];_keys(host,('arch','darwin_release','os_version','os_build','kernel_version','execution'))
    _token(host['arch'],r'arm64|x86_64')
    for key in ('darwin_release','os_version','os_build','kernel_version'):_token(host[key],r'[\x20-\x7e]+',256)
    if host['execution'] not in ('native','translated'):fail('HOST')
    if native['status'] not in ('passed','failed'):fail('RECEIPT')
    if native['failure'] is not None and (type(native['failure']) is not str or native['failure'] not in _FAILURES):fail('RECEIPT')
    for key in ('client_exit','daemon_exit'):
        if native[key] is not None and (type(native[key]) is not int or not -255<=native[key]<=255):fail('RECEIPT')
    if native['output_digest'] is not None:_sha(native['output_digest'])
    owner=native['ownership'];_keys(owner,('direct_children_started','direct_children_waited','command_exit_observed',
                                         'remaining_children','unresolved_owners','rescue_used','harness_io_joined','daemon_shutdown_completed'))
    for key in ('direct_children_started','direct_children_waited','remaining_children','unresolved_owners'):
        if type(owner[key]) is not int or not 0<=owner[key]<=32:fail('RECEIPT')
    for key in ('command_exit_observed','rescue_used','harness_io_joined','daemon_shutdown_completed'):
        if type(owner[key]) is not bool:fail('RECEIPT')
    if (native['status']!='passed' or native['failure'] is not None or host['execution']!='native'
            or host['arch']!=DARWIN_TARGETS[native['target']] or native['client_exit']!=37 or native['daemon_exit']!=0
            or native['output_digest']!=prepared['expected_output_digest'] or owner['direct_children_started']<2
            or owner['direct_children_waited']!=owner['direct_children_started'] or not owner['command_exit_observed']
            or owner['remaining_children']!=0 or owner['unresolved_owners']!=0 or owner['rescue_used']
            or not owner['harness_io_joined'] or not owner['daemon_shutdown_completed']):fail('NATIVE_REFUSED')
    return native

class _Compressed:
    """Limit all gzip members/headers to admitted bytes plus one EOF probe."""
    def __init__(self,stream,limit):
        if type(limit) is not int or not 0<limit<=ARCHIVE_LIMIT:fail('ARCHIVE_LIMIT')
        self.stream=stream;self.limit=limit;self.total=0
    def read(self,size=-1):
        if type(size) is not int:fail('BOUNDS')
        if size<0:size=65536
        size=min(size,65536,self.limit-self.total+1)
        data=self.stream.read(size);self.total+=len(data)
        if self.total>self.limit:fail('ARCHIVE_LIMIT')
        return data


class _Expanded:
    def __init__(self,stream):self.stream=stream;self.total=0
    def read(self,size):
        if not 0<=size<=65536:fail('BOUNDS')
        data=self.stream.read(size);self.total+=len(data)
        if self.total>EXPANDED_LIMIT:fail('EXPANDED_LIMIT')
        return data
    def exact(self,size):
        result=bytearray()
        while len(result)<size:
            data=self.read(min(65536,size-len(result)))
            if not data:fail('TRUNCATED')
            result.extend(data)
        return bytes(result)


def _octal(raw):
    value=raw.strip(b'\0 ')
    if not value:return 0
    if re.fullmatch(b'[0-7]+',value) is None or len(value)>12:fail('TAR_HEADER')
    number=int(value,8)
    if number>2**63-1:fail('TAR_HEADER')
    return number


def _tar_text(raw):
    value,separator,padding=raw.partition(b'\0')
    if separator and padding.strip(b'\0'):fail('TAR_HEADER')
    try:return value.decode('ascii')
    except UnicodeError:fail('TAR_HEADER')


def _write_all(fd,data):
    remaining=memoryview(data)
    while remaining:
        count=os.write(fd,remaining)
        if count<=0:fail('WRITE')
        remaining=remaining[count:]


def _scan(stream,root,stage_fd,known,*,compressed_limit):
    import gzip
    result={};seen=set();headers=0
    with gzip.GzipFile(fileobj=_Compressed(stream,compressed_limit),mode='rb') as compressed:
        reader=_Expanded(compressed)
        while True:
            header=reader.exact(512)
            if header==bytes(512):
                if reader.exact(512)!=bytes(512):fail('TAR_END')
                tail=0
                while True:
                    data=reader.read(65536)
                    if not data:break
                    tail+=len(data)
                    if tail>65536 or any(data):fail('TAR_TRAILING')
                break
            headers+=1
            if headers>32:fail('TAR_HEADERS')
            if header[257:265]!=b'ustar\x0000':fail('TAR_FORMAT')
            if _octal(header[148:156])!=sum(header[:148])+8*32+sum(header[156:]):fail('TAR_CHECKSUM')
            kind=header[156:157]
            if kind not in (b'0',b'\0',b'5'):fail('TAR_UNSUPPORTED')
            if header[157:257].strip(b'\0'):fail('TAR_LINK')
            for start,stop in ((100,108),(108,116),(116,124),(136,148),(329,337),(337,345)):_octal(header[start:stop])
            size=_octal(header[124:136]);name=_tar_text(header[:100]);prefix=_tar_text(header[345:500])
            if prefix:name=prefix+'/'+name
            if kind==b'5' and name.endswith('/'):name=name[:-1]
            expected={root}|{root+'/'+leaf for leaf in PROGRAMS+DOCUMENTS}
            if name not in expected or name in seen:fail('TAR_MEMBERS')
            seen.add(name)
            if name==root:
                if kind!=b'5' or size!=0:fail('TAR_MEMBERS')
                continue
            if kind==b'5':fail('TAR_MEMBERS')
            leaf=name[len(root)+1:];limit=EXECUTABLE_LIMIT if leaf in PROGRAMS else DOCUMENT_LIMIT
            if size>limit or (leaf in PROGRAMS and size==0):fail('TAR_SIZE')
            output=None;value=hashlib.sha256();remaining=size
            try:
                if leaf in PROGRAMS:
                    output=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700,dir_fd=stage_fd)
                    known[leaf]=(os.fstat(output).st_dev,os.fstat(output).st_ino)
                    os.fchmod(output,0o700)
                while remaining:
                    data=reader.exact(min(65536,remaining));remaining-=len(data);value.update(data)
                    if output is not None:_write_all(output,data)
                reader.exact((-size)%512)
                if leaf in NOTICES:
                    if value.hexdigest()!=NOTICE_SHA256[leaf]:fail('NOTICE_BYTES')
                if output is not None:
                    os.fsync(output);result[leaf]=dict(sha256=value.hexdigest(),bytes=size)
            finally:
                if output is not None:os.close(output)
        if seen!={root}|{root+'/'+leaf for leaf in PROGRAMS+DOCUMENTS}:fail('TAR_MEMBERS')
    return result


def _stage_bound(parent,name,fd,identity):
    named=os.stat(name,dir_fd=parent,follow_symlinks=False);held=os.fstat(fd)
    if ((named.st_dev,named.st_ino)!=identity or (held.st_dev,held.st_ino)!=identity
            or not stat.S_ISDIR(named.st_mode) or stat.S_IMODE(named.st_mode)!=0o700
            or named.st_uid!=os.geteuid()):fail('STAGING_DRIFT')


def _cleanup(parent,name,fd,identity,known):
    # Remove only files this invocation created and still identifies, never a tree.
    failed=False
    for leaf,owned in known.items():
        try:
            info=os.stat(leaf,dir_fd=fd,follow_symlinks=False)
            if (info.st_dev,info.st_ino)!=owned:failed=True;continue
            os.unlink(leaf,dir_fd=fd)
        except FileNotFoundError:continue
        except OSError:failed=True
    try:
        info=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if (info.st_dev,info.st_ino)==identity:os.rmdir(name,dir_fd=parent)
        else:failed=True
    except OSError:failed=True
    if failed:fail('STAGING_CLEANUP')


def prepare(archive,metadata,version,target,destination,*,source_commit):
    """Stage two inert byte streams; caller exclusively owns the private parent."""
    import gzip
    import secrets
    _selection(version,target);_token(source_commit,r'[0-9a-f]{40}',40)
    archive=Path(archive);metadata=Path(metadata);destination=Path(destination)
    root='qsh-'+version+'-'+target
    if archive.name!=root+'.tar.gz':fail('ARCHIVE_NAME')
    if not destination.is_absolute() or destination.name in ('','.','..') or '..' in destination.parts:fail('DESTINATION')
    opened=[];parent=None;stage=None;identity=None;known={};complete=False
    try:
        archive_fd,archive_info=_open_input(archive,ARCHIVE_LIMIT);opened.append(archive_fd)
        metadata_fd,metadata_info=_open_input(metadata,METADATA_LIMIT);opened.append(metadata_fd)
        raw=bytearray()
        while True:
            data=os.read(metadata_fd,min(65536,METADATA_LIMIT+1-len(raw)))
            if not data:break
            raw.extend(data)
            if len(raw)>METADATA_LIMIT:fail('METADATA')
        source,expected=_metadata(bytes(raw),target)
        if source!=source_commit:fail('SOURCE')
        _recheck(metadata,metadata_fd,metadata_info)
        archive_sha=_hash_fd(archive_fd,archive_info[6]);_recheck(archive,archive_fd,archive_info)
        parent=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        authority=os.fstat(parent)
        if authority.st_uid!=os.geteuid() or stat.S_IMODE(authority.st_mode)!=0o700:fail('DESTINATION')
        named_parent=os.stat(destination.parent,follow_symlinks=False)
        if (authority.st_dev,authority.st_ino)!=(named_parent.st_dev,named_parent.st_ino):fail('DESTINATION')
        os.mkdir(destination.name,0o700,dir_fd=parent)
        created=os.stat(destination.name,dir_fd=parent,follow_symlinks=False)
        identity=(created.st_dev,created.st_ino)
        stage=os.open(destination.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        os.fchmod(stage,0o700)
        _stage_bound(parent,destination.name,stage,identity)
        os.lseek(archive_fd,0,os.SEEK_SET)
        with os.fdopen(os.dup(archive_fd),'rb',buffering=0) as stream:
            result=_scan(stream,root,stage,known,compressed_limit=archive_info[6])
        for program in PROGRAMS:
            if result[program]['sha256']!=expected[program]:fail('PAYLOAD_DIGEST')
            selected=os.open(program,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=stage)
            try:
                current=os.fstat(selected)
                if ((current.st_dev,current.st_ino)!=known[program] or not stat.S_ISREG(current.st_mode)
                        or stat.S_IMODE(current.st_mode)!=0o700 or current.st_nlink!=1
                        or current.st_uid!=os.geteuid() or current.st_size!=result[program]['bytes']):fail('STAGING_DRIFT')
                before=_snapshot(current)
                if _hash_fd(selected,result[program]['bytes'])!=result[program]['sha256']:fail('STAGING_DRIFT')
                if _snapshot(os.fstat(selected))!=before or _snapshot(os.stat(program,dir_fd=stage,follow_symlinks=False))!=before:fail('STAGING_DRIFT')
            finally:os.close(selected)
        if _hash_fd(archive_fd,archive_info[6])!=archive_sha:fail('INPUT_DRIFT')
        _recheck(archive,archive_fd,archive_info);_recheck(metadata,metadata_fd,metadata_info)
        _stage_bound(parent,destination.name,stage,identity)
        current_parent=os.stat(destination.parent,follow_symlinks=False)
        if ((current_parent.st_dev,current_parent.st_ino)!=(authority.st_dev,authority.st_ino)
                or current_parent.st_uid!=os.geteuid() or stat.S_IMODE(current_parent.st_mode)!=0o700):fail('STAGING_DRIFT')
        challenge=secrets.token_hex(24)
        receipt=dict(schema=1,kind='darwin-archive-prepared',request_id=secrets.token_hex(16),source_commit=source_commit,
                     version=version,target=target,archive_sha256=archive_sha,metadata_sha256=digest(bytes(raw)),
                     binaries=result,challenge=challenge,expected_output_digest=digest(challenge.encode('ascii')))
        _prepared(canonical(receipt))
        while opened:os.close(opened.pop())
        complete=True
        return receipt
    except (OSError,EOFError,gzip.BadGzipFile,zlib.error):fail('PREPARE')
    finally:
        try:
            if not complete and identity is not None:_cleanup(parent,destination.name,stage,identity,known)
        finally:
            try:
                while opened:os.close(opened.pop())
            finally:
                try:
                    if stage is not None:
                        try:os.close(stage)
                        except OSError:
                            if complete:
                                # Never retry an uncertain numeric FD. Reopen only the
                                # exact still-private created directory for bounded cleanup.
                                cleanup_fd=os.open(destination.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                                try:
                                    _stage_bound(parent,destination.name,cleanup_fd,identity)
                                    _cleanup(parent,destination.name,cleanup_fd,identity,known)
                                finally:os.close(cleanup_fd)
                            fail('STAGING_CLOSE')
                finally:
                    if parent is not None:os.close(parent)


def _receipt_file(path):
    fd,snapshot=_open_input(Path(path),RECEIPT_LIMIT)
    try:
        value=bytearray()
        while True:
            chunk=os.read(fd,min(65536,RECEIPT_LIMIT+1-len(value)))
            if not chunk:break
            value.extend(chunk)
            if len(value)>RECEIPT_LIMIT:fail('RECEIPT')
        _recheck(path,fd,snapshot)
        return bytes(value)
    finally:os.close(fd)


# The runner is trusted source instrumentation; these checks do not authenticate
# arbitrary JSON, provide containment after runner loss, or qualify older macOS.
FIXED_TESTS={
    'failure':'darwin_process_scope::darwin_artifact_tests::native::darwin185_archive_failure_after_registration',
    'positive':'darwin_process_scope::darwin_artifact_tests::native::darwin185_archive_authenticated_pair',
}


def _native_host():
    import ctypes
    import platform
    import sys
    if sys.platform!='darwin':fail('HOST')
    library=ctypes.CDLL(None,use_errno=True)
    def sysctl(name):
        size=ctypes.c_size_t(256);data=ctypes.create_string_buffer(256)
        if library.sysctlbyname(name.encode(),data,ctypes.byref(size),None,0)!=0:fail('HOST')
        return data.raw[:size.value].rstrip(b'\0').decode('ascii')
    # ENOENT is normal on native Intel; every other unknown error refuses.
    translated=ctypes.c_int();size=ctypes.c_size_t(ctypes.sizeof(translated))
    code=library.sysctlbyname(b'sysctl.proc_translated',ctypes.byref(translated),ctypes.byref(size),None,0)
    import errno
    if code and ctypes.get_errno()!=errno.ENOENT:fail('HOST')
    if not code and translated.value not in (0,1):fail('HOST')
    return dict(arch=platform.machine(),execution='translated' if not code and translated.value else 'native',
                os_version=sysctl('kern.osproductversion'))


def select_harness(messages,root,target):
    """Select one fresh default-feature lib-test compiler artifact, never a bin."""
    root=Path(root)
    if not root.is_absolute() or root.resolve()!=root or root.name!='deps' or root.parent.name!='debug' or root.parent.parent.name!=target:fail('HARNESS')
    fd,snapshot=_open_input(messages,8*1024**2)
    try:
        with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(8*1024**2+1)
        _recheck(messages,fd,snapshot)
    finally:os.close(fd)
    selected=[]
    for line in raw.splitlines():
        if len(line)>1024**2:fail('HARNESS')
        value=_json(line,1024**2)
        if type(value) is not dict:fail('HARNESS')
        if value.get('reason')!='compiler-artifact' or not value.get('executable'):continue
        target_record=value.get('target',{});profile=value.get('profile',{})
        if type(target_record) is not dict or type(profile) is not dict:fail('HARNESS')
        if target_record.get('name')!='qshd' or target_record.get('kind')!=['lib'] or profile.get('test') is not True:continue
        if value.get('fresh') is not False or value.get('features')!=[]:fail('HARNESS')
        if type(value['executable']) is not str or type(value.get('manifest_path')) is not str:fail('HARNESS')
        path=Path(value['executable'])
        if path.parent!=root or not path.name.startswith('qshd-') or path.resolve()!=path:fail('HARNESS')
        manifest=Path(value.get('manifest_path',''))
        if manifest!=Path(__file__).resolve().parents[1]/'qshd/Cargo.toml':fail('HARNESS')
        selected.append(path)
    if len(selected)!=1:fail('HARNESS')
    return selected[0]


def _executable(path):
    path=Path(path)
    if not path.is_absolute() or path.resolve()!=path:fail('EXECUTABLE')
    fd,snapshot=_open_input(path,EXECUTABLE_LIMIT)
    try:
        if snapshot[3]!=1 or snapshot[4]!=os.geteuid() or not snapshot[2]&0o100 or snapshot[2]&0o022:fail('EXECUTABLE')
        return fd,snapshot,_hash_fd(fd,EXECUTABLE_LIMIT)
    except BaseException:os.close(fd);raise


def _failure_result(raw,prepared_sha):
    _keys(raw,('schema','kind','prepared_sha256','bound','actor_exit','daemon_exit','waited','io_joined','rescue','unresolved'))
    if (raw['schema']!=1 or type(raw['schema']) is not int or raw['kind']!='darwin-archive-controlled-failure'
            or raw['prepared_sha256']!=prepared_sha or any(raw[k] is not True for k in ('bound','actor_exit','waited','io_joined'))
            or raw['rescue'] is not False or type(raw['daemon_exit']) is not int or raw['daemon_exit']!=0
            or type(raw['unresolved']) is not int or raw['unresolved']!=0):fail('FAILURE_CUSTODY')
    return raw


def _invoke_fixed(harness,request,mode,*,diagnostic=None):
    import contextlib
    import subprocess
    import time
    diagnostic=diagnostic if diagnostic is not None else DiagnosticContext()
    diagnostic.reset_harness()
    # No generic timeout kill: the fixed harness owns the cancellation/settlement
    # protocol. An unresponsive runner retains fixtures and fails the job.
    directory=Path(request['directory'])/mode;directory.mkdir(mode=0o700)
    request=dict(request,directory=str(directory))
    request_file=directory/'request.json';request_file.write_bytes(canonical(request));request_file.chmod(0o600)
    env=os.environ.copy()
    env.update(HOME=str(directory),XDG_CACHE_HOME=str(directory/'cache'),XDG_CONFIG_HOME=str(directory/'config'),
               HISTFILE='/dev/null',QSH_DARWIN185_REQUEST=str(request_file))
    for key in ('SSH_AUTH_SOCK','SSH_AGENT_PID'):env.pop(key,None)
    # Capture to private bounded files in the harness; libtest's bounded summary
    # goes to a private regular file and never enters workflow stdout.
    with contextlib.ExitStack() as stack:
        held_directory=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        def close_directory():
            try:os.close(held_directory)
            except OSError:pass
        stack.callback(close_directory)
        log=stack.enter_context((directory/'harness.log').open('xb'))
        child=subprocess.Popen([str(harness),'--exact',FIXED_TESTS[mode],'--ignored','--test-threads=1'],
                               env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        failure=None
        try:
            end=time.monotonic()+60
            while child.poll() is None:
                if time.monotonic()>=end:fail('DEADLINE')
                if os.fstat(log.fileno()).st_size>65536:fail('HARNESS_OUTPUT')
                time.sleep(.02)
            status=child.wait()
            diagnostic.harness_status=_status(status)
            if os.fstat(log.fileno()).st_size>65536:fail('HARNESS_OUTPUT')
            if status!=0:fail('HARNESS_FAILED')
        except BaseException as error:
            failure=error
            # Every post-spawn refusal follows the same owned cancellation path.
            # No signal/timeout kill can erase a descendant obligation.
            try:(directory/'cancel').touch(mode=0o600,exist_ok=True)
            except OSError:pass
            end=time.monotonic()+20
            while child.poll() is None and time.monotonic()<end:time.sleep(.02)
            if child.poll() is None:
                diagnostic.diagnostic_state='UNSETTLED'
                fail('UNSETTLED_HARNESS')
            status=child.wait()
            diagnostic.harness_status=_status(status)
        if status!=0:
            diagnostic.diagnostic_state,diagnostic.rust_outcome=_read_outcome(
                directory,mode,held_directory=held_directory)
        if failure is not None:raise failure
    return _json(_receipt_file(directory/'result.json'),RECEIPT_LIMIT)


def run_archive(archive,metadata,version,target,destination,harness,*,source_commit,diagnostic=None):
    """Fixed failure then positive observation, surrounded by file bindings."""
    diagnostic=diagnostic if diagnostic is not None else DiagnosticContext()
    diagnostic.phase='HOST'
    _selection(version,target);host=_native_host()
    if host.get('arch')!=DARWIN_TARGETS[target] or host.get('execution')!='native' or host.get('os_version','').split('.')[0]!='15':fail('HOST')
    diagnostic.phase='STAGING'
    destination=Path(destination)
    if not destination.is_absolute() or destination.resolve()!=destination:fail('DESTINATION')
    destination.mkdir(mode=0o700)
    if stat.S_IMODE(destination.stat().st_mode)!=0o700:fail('DESTINATION')
    held=[]
    try:
        diagnostic.phase='INPUT_BINDING'
        for path,limit in ((Path(archive),ARCHIVE_LIMIT),(Path(metadata),METADATA_LIMIT)):
            fd,snapshot=_open_input(path,limit);held.append((path,fd,snapshot,_hash_fd(fd,limit)))
        diagnostic.phase='PREPARE'
        prepared=prepare(archive,metadata,version,target,destination/'pair',source_commit=source_commit)
        prepared_raw=canonical(prepared)
        diagnostic.phase='INPUT_BINDING'
        for name in PROGRAMS:
            path=destination/'pair'/name;fd,snapshot,sha=_executable(path);held.append((path,fd,snapshot,sha))
            if sha!=prepared['binaries'][name]['sha256']:fail('STAGING_DRIFT')
        harness=Path(harness);fd,snapshot,sha=_executable(harness);held.append((harness,fd,snapshot,sha))
        request=dict(schema=1,prepared=prepared,prepared_sha256=digest(prepared_raw),source_commit=source_commit,
                     harness_sha256=sha,client=str(destination/'pair'/'qsh'),daemon=str(destination/'pair'/'qshd'),directory=str(destination))
        def recheck():
            for path,fd,snapshot,sha in held:
                _recheck(path,fd,snapshot)
                if _hash_fd(fd)!=sha:fail('INPUT_DRIFT')
        recheck()
        diagnostic.phase='CONTROLLED_EXECUTE'
        negative=_invoke_fixed(harness,request,'failure',diagnostic=diagnostic)
        diagnostic.phase='CONTROLLED_VERIFY'
        negative=_failure_result(negative,request['prepared_sha256'])
        diagnostic.phase='CONTROLLED_RECHECK'
        recheck()
        diagnostic.phase='POSITIVE_EXECUTE'
        native=_invoke_fixed(harness,request,'positive',diagnostic=diagnostic)
        diagnostic.phase='POSITIVE_VERIFY'
        verify_result(prepared_raw,canonical(native))
        diagnostic.phase='POSITIVE_RECHECK'
        recheck()
        diagnostic.phase='PUBLIC_PROJECTION'
        # Public closed evidence excludes the private prepared nonce and paths.
        public_native={key:value for key,value in native.items() if key!='request_id'}
        public_native['kind']='darwin-archive-observation'
        public_native['receipt_sha256']=digest(canonical(native))
        return dict(native=public_native,controlled_failure=negative,
                    harness=dict(schema=1,kind='darwin-archive-harness',source_commit=source_commit,
                                 target=target,sha256=sha,features=[],profile='test'))
    finally:
        for _,fd,_,_ in reversed(held):os.close(fd)


def main(argv=None):
    import argparse
    import sys
    class Parser(argparse.ArgumentParser):
        def error(self,message):fail('CLI')
    diagnostic=DiagnosticContext()
    try:
        parser=Parser(description=__doc__);commands=parser.add_subparsers(dest='command',required=True)
        stage=commands.add_parser('prepare')
        for name in ('archive','metadata','version','target','destination','source-commit'):stage.add_argument('--'+name,required=True)
        verify=commands.add_parser('verify-result')
        verify.add_argument('--prepared',required=True);verify.add_argument('--native',required=True)
        run=commands.add_parser('run-archive')
        for name in ('archive','metadata','version','target','destination','source-commit','cargo-messages','harness-root','evidence'):
            run.add_argument('--'+name,required=True)
        args=parser.parse_args(argv)
        if args.command=='prepare':
            diagnostic.phase='PREPARE_COMMAND'
            result=prepare(args.archive,args.metadata,args.version,args.target,args.destination,source_commit=args.source_commit)
        elif args.command=='run-archive':
            diagnostic.phase='HARNESS_SELECTION'
            harness=select_harness(args.cargo_messages,Path(args.harness_root),args.target)
            result=run_archive(args.archive,args.metadata,args.version,args.target,args.destination,harness,
                               source_commit=args.source_commit,diagnostic=diagnostic)
            diagnostic.phase='EVIDENCE_WRITE'
            evidence=Path(args.evidence)
            for key,value in result.items():
                with (evidence/(args.target+'-'+key+'.json')).open('xb') as output:output.write(canonical(value))
            return 0
        else:
            diagnostic.phase='VERIFY_COMMAND'
            result=verify_result(_receipt_file(args.prepared),_receipt_file(args.native))
        sys.stdout.buffer.write(canonical(result));sys.stdout.buffer.flush()
        return 0
    except (ValueError,OSError,EOFError,zlib.error) as error:
        try:
            line=b'DARWIN_SMOKE_REFUSED '+canonical(_refusal_record(error,diagnostic))
            if len(line)<=1024:sys.stderr.write(line.decode('ascii'))
        except (ValueError,OSError,EOFError,zlib.error):pass
        return 1


if __name__=='__main__':
    import sys
    raise SystemExit(main())
