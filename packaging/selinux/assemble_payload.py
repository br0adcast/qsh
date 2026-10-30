#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Stage reviewed provider bytes offline; never install or load policy.

This is a staging payload, NOT a redistributable complete RPM/package. License,
source-offer/spec assets and runtime reference admission remain later work.
Expected hashes are explicit independently reviewed build inputs, not proof of
provenance or values inferred from current installed files. Input code is never
executed; the fixed direct-import check is not a general dynamic-code verifier.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MODULES=tuple('qshd_selinux_'+name+'.py' for name in (
    'activation','activation_state','contexts','transaction','fs','registry',
    'process','modules','module_observer','api','queries','files','observer','reference_loader'))
_KEYS=frozenset(MODULES+('qshd.pp','artifact.json','qshd.fedora-selinux'))
_PAM_SHA='61dc7f9dc6ada9a612a66b1bfda1f8d1802ec9734a9325edc4f600b0e55622c7'
_SCHEMA=dict(name='qshd-selinux',architecture='noarch',policy_module='qshd',
    module_priority=400,authored_source_license='AGPL-3.0-only',
    reference_policy_source_license='GPL-2.0-or-later',
    combined_artifact_license='AGPL-3.0-only AND GPL-2.0-or-later',
    reference_policy_selected_terms='GPL-3.0 (GPL-2.0-or-later option; GNU GPLv3 section 13 combination)',
    runtime_qualification='Fedora 44 targeted policy')


def _fail(code):raise ValueError(code)


def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:_fail('DUPLICATE_KEY')
        result[key]=value
    return result


def _snapshot(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _read(path,limit):
    """Stable bounded regular leaf read; inherited input parents are trusted."""
    path=Path(path)
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=limit:_fail('INPUT_TYPE_OR_SIZE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        opened=os.fstat(fd)
        if _snapshot(before)!=_snapshot(opened):_fail('INPUT_CHANGED')
        parts=[];size=0
        while True:
            chunk=os.read(fd,min(65536,limit+1-size))
            if not chunk:break
            parts.append(chunk);size+=len(chunk)
            if size>limit:_fail('INPUT_TYPE_OR_SIZE')
        if (_snapshot(opened)!=_snapshot(os.fstat(fd))
                or _snapshot(opened)!=_snapshot(path.lstat())):_fail('INPUT_CHANGED')
        data=b''.join(parts)
        if len(data)!=opened.st_size:_fail('INPUT_CHANGED')
        return data
    finally:os.close(fd)


def _expected(value):
    if type(value) is not dict or set(value)!=_KEYS:_fail('EXPECTED_KEYS')
    if any(type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None for digest in value.values()):
        _fail('EXPECTED_HASH')
    return dict(value)


def _artifact(data):
    try:value=json.loads(data,object_pairs_hook=_pairs)
    except (ValueError,UnicodeError,RecursionError):_fail('ARTIFACT_SCHEMA')
    if type(value) is not dict or set(value)!=set(_SCHEMA)|{'policy_version'}:_fail('ARTIFACT_SCHEMA')
    for key,expected in _SCHEMA.items():
        if type(value[key]) is not type(expected) or value[key]!=expected:_fail('ARTIFACT_SCHEMA')
    version=value['policy_version']
    if type(version) is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}',version) is None:
        _fail('ARTIFACT_SCHEMA')
    return version


def _imports(name,data):
    try:tree=ast.parse(data,filename=name)
    except (SyntaxError,ValueError,UnicodeError,RecursionError):_fail('SOURCE_SYNTAX')
    allowed={item[:-3] for item in MODULES}
    for node in ast.walk(tree):
        imports=[]
        if isinstance(node,ast.Import):imports=[item.name for item in node.names]
        elif isinstance(node,ast.ImportFrom):
            if node.level:_fail('SOURCE_IMPORT')
            imports=[node.module or '']
        for imported in imports:
            if imported.startswith('qshd_selinux_') and imported not in allowed:_fail('SOURCE_IMPORT')


def _references(version,artifact,pp,pam):
    try:text=pam.decode('utf-8')
    except UnicodeError:_fail('PAM_UTF8')
    if not 0<len(pam)<=4096:_fail('PAM_LIMIT')
    values=dict(provider_version=version,manifest_sha256=hashlib.sha256(artifact).hexdigest(),
                pp_sha256=hashlib.sha256(pp).hexdigest(),pam_sha256=_PAM_SHA,expected_pam=text)
    return json.dumps(values,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')+b'\n'


def _output(source,inputs,output):
    # Canonicalize existing ancestors before checking overlap or doing any write.
    requested=Path(output).absolute()
    if os.path.lexists(requested):_fail('OUTPUT_EXISTS')
    parent=requested.parent.resolve(strict=True)
    if not parent.is_dir():_fail('OUTPUT_PARENT')
    resolved=parent/requested.name
    if os.path.lexists(resolved):_fail('OUTPUT_EXISTS')
    source=Path(source).resolve(strict=True)
    if source==resolved or source.is_relative_to(resolved) or resolved.is_relative_to(source):
        _fail('OUTPUT_OVERLAP')
    for path in inputs:
        canonical=Path(path).resolve(strict=True)
        if canonical==resolved or canonical.is_relative_to(resolved):_fail('OUTPUT_OVERLAP')
    return resolved


def _write_file(path,data,epoch):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        remaining=memoryview(data)
        while remaining:
            count=os.write(fd,remaining)
            if count<=0:_fail('OUTPUT_WRITE')
            remaining=remaining[count:]
        os.fchmod(fd,0o644)
        os.utime(fd,(epoch,epoch))
    finally:os.close(fd)


def assemble_payload(source,pp,artifact,pam,expected,output,epoch):
    """Return sorted relative-path/hash/size/mode records after complete staging.

    All inputs are validated before mkdir. Later IO errors leave partial staging
    for inspection; it is never recursively removed, reused or reported complete.
    This build tool trusts inherited input parents, not hostile privileged races.
    """
    try:
        if type(epoch) is not int or not 0<=epoch<=2147483647:_fail('EPOCH')
        expected=_expected(expected)
        source=Path(source)
        paths={name:source/name for name in MODULES}
        paths.update({'qshd.pp':Path(pp),'artifact.json':Path(artifact),'qshd.fedora-selinux':Path(pam)})
        if len({str(path.resolve(strict=True)) for path in paths.values()})!=len(paths):_fail('INPUT_ALIAS')
        out=_output(source,paths.values(),output)
        data={}
        for name,path in paths.items():
            limit=16*1024**2 if name=='qshd.pp' else 4096 if name=='qshd.fedora-selinux' else 65536
            value=_read(path,limit)
            if hashlib.sha256(value).hexdigest()!=expected[name]:_fail('HASH_MISMATCH')
            data[name]=value
        version=_artifact(data['artifact.json'])
        if hashlib.sha256(data['qshd.fedora-selinux']).hexdigest()!=_PAM_SHA:_fail('CANONICAL_PAM')
        for name in MODULES:_imports(name,data[name])
        staged={'usr/libexec/qshd-selinux/'+name:data[name] for name in MODULES}
        staged['usr/share/qshd-selinux/reference.json']=_references(version,data['artifact.json'],data['qshd.pp'],data['qshd.fedora-selinux'])
        staged.update({'usr/share/qshd-selinux/'+name:data[name] for name in ('qshd.pp','artifact.json','qshd.fedora-selinux')})
        directories={out}
        for name in staged:
            parent=(out/name).parent
            while parent!=out:
                directories.add(parent);parent=parent.parent
        for directory in sorted(directories,key=lambda p:(len(p.parts),str(p))):
            directory.mkdir(mode=0o700)
            directory.chmod(0o755)
        inventory=[]
        for name,value in sorted(staged.items()):
            _write_file(out/name,value,epoch)
            inventory.append(dict(path=name,sha256=hashlib.sha256(value).hexdigest(),size=len(value),mode=0o644))
        for directory in sorted(directories,key=lambda p:len(p.parts),reverse=True):os.utime(directory,(epoch,epoch))
        return tuple(inventory)
    except OSError:_fail('ASSEMBLY_IO')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','pp','artifact','pam','expected','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--epoch',type=int,required=True)
    args=parser.parse_args()
    try:
        expected=json.loads(_read(args.expected,16384),object_pairs_hook=_pairs)
        result=assemble_payload(args.source,args.pp,args.artifact,args.pam,expected,args.output,args.epoch)
        print(json.dumps(result,sort_keys=True,separators=(',',':')))
    except (ValueError,OSError,UnicodeError,RecursionError):
        parser.exit(1,'PAYLOAD_ASSEMBLY_REFUSED\n')


if __name__=='__main__':main()
