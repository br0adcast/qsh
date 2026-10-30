#!/usr/bin/env python3
"""Check versions and identities of the release pipeline's own built outputs."""
import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    'release_version', Path(__file__).with_name('check-release-version.py'))
_version = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_version)
LIMIT = 8192


def parse_version(data, program, expected=None):
    if len(data) > LIMIT:
        raise ValueError('version output exceeds limit')
    try:
        first = data.decode('utf-8').splitlines()[0]
    except (UnicodeError, IndexError):
        raise ValueError('invalid version output')
    pattern = r'qsh ([^ ]+)' if program == 'qsh' else r'qshd ([^ ]+) \(build [^\r\n]+\)'
    match = re.fullmatch(pattern, first)
    if match is None or not _version.valid_version(match.group(1)):
        raise ValueError('invalid program/version first line')
    version = match.group(1)
    if expected is not None and version != expected:
        raise ValueError('binary version differs from selected release version')
    return version


def check_binary(path, program, version, timeout=10):
    # --version exits before either product starts sessions or descendants.
    # This owner keeps its exact direct child through timeout/interrupt cleanup.
    path = Path(path).resolve()
    with tempfile.TemporaryDirectory(prefix='qsh-release-version-') as home:
        env = os.environ.copy()
        env.update(HOME=home, XDG_CACHE_HOME=home + '/cache',
                   XDG_CONFIG_HOME=home + '/config', HISTFILE='/dev/null')
        env.pop('SSH_AUTH_SOCK', None)
        master, slave = os.openpty()
        child = None
        try:
            os.set_blocking(master, False)
            deadline = time.monotonic() + timeout
            child = subprocess.Popen([str(path), '--version'], stdin=slave,
                                     stdout=slave, stderr=slave, env=env,
                                     start_new_session=True)
            os.close(slave)
            slave = None
            captured = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('binary version probe timed out')
                ready, _, _ = select.select([master], [], [], remaining)
                if not ready:
                    raise ValueError('binary version probe timed out')
                try:
                    chunk = os.read(master, 4096)
                except BlockingIOError:
                    continue
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break  # PTY slave closed; still wait for the owned child.
                if not chunk:
                    break
                if len(captured) + len(chunk) > LIMIT:
                    raise ValueError('version output exceeds limit')
                captured.extend(chunk)
            try:
                status = child.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise ValueError('binary version probe timed out')
            if status != 0:
                raise ValueError('binary version probe exited unsuccessfully')
            return parse_version(bytes(captured), program, version)
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait()
            if slave is not None:
                os.close(slave)
            os.close(master)


def digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(65536), b''):
        result.update(chunk)
    return result.digest()


# Producer-only static evidence. Apple text formats are documented in cctools'
# loader.h/ofile_print.c; this does not parse Mach-O bytes or select an OS floor.
DARWIN_TARGETS = {'aarch64-apple-darwin': 'arm64', 'x86_64-apple-darwin': 'x86_64'}
METADATA_LIMIT = 65536


def metadata_command(argv, timeout=10):
    """Bounded static-tool query; retain and reap the exact direct child."""
    with tempfile.TemporaryDirectory(prefix='qsh-release-metadata-') as home:
        env = os.environ.copy()
        env.update(HOME=home, XDG_CACHE_HOME=home+'/cache', XDG_CONFIG_HOME=home+'/config',
                   HISTFILE='/dev/null', LANG='C', LC_ALL='C')
        env.pop('SSH_AUTH_SOCK', None)
        child = None
        try:
            deadline = time.monotonic()+timeout
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env=env, start_new_session=True)
            pipes = [child.stdout, child.stderr]
            captured = [bytearray(), bytearray()]
            live = set(range(2))
            for pipe in pipes: os.set_blocking(pipe.fileno(), False)
            while live:
                remaining = deadline-time.monotonic()
                if remaining <= 0: raise ValueError('Darwin metadata tool timed out')
                ready, _, _ = select.select([pipes[i] for i in live], [], [], remaining)
                if not ready: raise ValueError('Darwin metadata tool timed out')
                for index in tuple(live):
                    if pipes[index] not in ready: continue
                    try: data = os.read(pipes[index].fileno(), 4096)
                    except BlockingIOError: continue
                    if not data: live.remove(index); continue
                    if sum(map(len, captured))+len(data)>METADATA_LIMIT:
                        raise ValueError('Darwin metadata output exceeds limit')
                    captured[index].extend(data)
            try: status=child.wait(timeout=max(0,deadline-time.monotonic()))
            except subprocess.TimeoutExpired: raise ValueError('Darwin metadata tool timed out')
            if time.monotonic()>=deadline: raise ValueError('Darwin metadata tool timed out')
            if status or captured[1]: raise ValueError('Darwin metadata tool refused')
            return bytes(captured[0])
        finally:
            if child is not None:
                if child.poll() is None: child.kill()
                child.wait()
                for pipe in (child.stdout, child.stderr):
                    if pipe is not None: pipe.close()


def _metadata_token(value, pattern, limit=256):
    if type(value) is not str or len(value)>limit or re.fullmatch(pattern,value) is None:
        raise ValueError('invalid Darwin metadata field')
    return value


def _metadata_version(value):
    return _metadata_token(value,r'[0-9]{1,5}(?:\.[0-9]{1,3}){0,2}',20)


def parse_darwin_load_commands(data):
    if len(data)>METADATA_LIMIT: raise ValueError('Darwin metadata output exceeds limit')
    blocks=[];current=None
    for line in data.decode('utf-8').splitlines():
        match=re.fullmatch(r'\s*cmd (LC_[A-Z0-9_]+)\s*',line)
        if match:
            current={'cmd':match.group(1)};blocks.append(current)
        elif current is not None:
            field=re.fullmatch(r'\s*(platform|minos|sdk|version)\s+(\S+)\s*',line)
            if field and ((current['cmd']=='LC_BUILD_VERSION' and field.group(1)!='version') or
                          (current['cmd']=='LC_VERSION_MIN_MACOSX' and field.group(1) in ('version','sdk'))):
                if field.group(1) in current: raise ValueError('ambiguous Darwin version metadata')
                current[field.group(1)]=field.group(2)
    selected=[block for block in blocks if block['cmd']=='LC_BUILD_VERSION' or block['cmd'].startswith('LC_VERSION_MIN_')]
    if len(selected)!=1: raise ValueError('missing or ambiguous Darwin version command')
    value=selected[0];kind=value['cmd']
    if kind=='LC_BUILD_VERSION':
        if set(value)!={'cmd','platform','minos','sdk'} or value['platform'] not in ('1','MACOS'):
            raise ValueError('unexpected Darwin platform metadata')
        minimum=value['minos']
    elif kind=='LC_VERSION_MIN_MACOSX':
        if set(value)!={'cmd','version','sdk'}: raise ValueError('invalid Darwin version metadata')
        minimum=value['version']
    else: raise ValueError('unexpected Darwin platform metadata')
    return dict(kind=kind,platform='macos',minos=_metadata_version(minimum),
                sdk=None if value['sdk']=='n/a' else _metadata_version(value['sdk']))


def _metadata_digest(path):
    info=Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=256*1024**2:
        raise ValueError('invalid Darwin metadata input')
    with Path(path).open('rb') as stream: return digest(stream).hex()


def _metadata_text(argv):
    return metadata_command(argv).decode('utf-8').strip()


def _metadata_compiler_version(text):
    if type(text) is not str: raise ValueError('invalid compiler metadata')
    match=re.match(r'(?:Apple clang|Apple LLVM|clang) version ([0-9]+(?:\.[0-9]+){1,2})(?: |$)',text.splitlines()[0])
    if match is None: raise ValueError('invalid compiler metadata')
    return _metadata_version(match.group(1))


def _metadata_native(prefix,target,sdk):
    with (Path(prefix)/'manifest.json').open('rb') as stream: raw=stream.read(262145)
    if len(raw)>262144: raise ValueError('native metadata exceeds limit')
    try:
        value=json.loads(raw);identity=value['identity'];compiler=identity['compiler']
        if identity['target']!=target: raise ValueError('native metadata target mismatch')
        flags=compiler['flags'];normalized=[];index=0;seen=set()
        if type(flags) is not list or len(flags)>32: raise ValueError('invalid native metadata flags')
        while index<len(flags):
            flag=flags[index]
            if flag in ('-arch','-isysroot'):
                if flag in seen or index+1>=len(flags): raise ValueError('invalid native metadata flags')
                seen.add(flag);operand=flags[index+1]
                if flag=='-arch' and operand!=DARWIN_TARGETS[target]: raise ValueError('native metadata architecture mismatch')
                if flag=='-isysroot' and Path(operand).resolve()!=Path(sdk).resolve(): raise ValueError('native metadata SDK mismatch')
                normalized.extend([flag,'<SDK>' if flag=='-isysroot' else operand]);index+=2
            else:
                _metadata_token(flag,r'-(?:O[0-3s]|fPIC|g0|mmacosx-version-min=[0-9]+(?:\.[0-9]+){0,2})')
                normalized.append(flag);index+=1
        if seen!={'-arch','-isysroot'}: raise ValueError('missing native metadata flags')
        macros={}
        allowed={'__APPLE__','__aarch64__','__arm64__','__x86_64__','__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__','__ENVIRONMENT_OS_VERSION_MIN_REQUIRED__'}
        for line in compiler['macros'].splitlines():
            match=re.fullmatch(r'#define (\S+) (\S+)',line)
            if match and match.group(1) in allowed:
                if match.group(1) in macros: raise ValueError('ambiguous native metadata macro')
                macros[match.group(1)]=_metadata_token(match.group(2),r'[0-9]+',20)
        result=dict(version=_metadata_token(identity['source']['version'],r'[0-9]+(?:\.[0-9]+){1,2}'),
                    manifest_sha256=hashlib.sha256(raw).hexdigest(),
                    compiler_sha256=_metadata_token(compiler['sha256'],r'[0-9a-f]{64}',64),
                    compiler_version=_metadata_compiler_version(compiler['version']),
                    flags=normalized,macros=macros)
        probe=_metadata_token(value['artifacts']['version-probe'],r'[0-9a-f]{64}',64)
        return result,probe
    except (KeyError,TypeError,AttributeError,IndexError,RecursionError):
        raise ValueError('invalid native metadata manifest') from None


def _darwin_context(prefix,target):
    if sys.platform!='darwin': raise ValueError('Darwin metadata requires the Darwin producer')
    sdk=_metadata_text(['/usr/bin/xcrun','--show-sdk-path'])
    if not Path(sdk).is_absolute(): raise ValueError('invalid selected SDK metadata')
    native,probe=_metadata_native(prefix,target,sdk)
    xcode=_metadata_text(['/usr/bin/xcodebuild','-version']).splitlines()
    if len(xcode)!=2 or not xcode[0].startswith('Xcode ') or not xcode[1].startswith('Build version '):
        raise ValueError('invalid Xcode metadata')
    rust={}
    for line in _metadata_text(['rustc','--version','--verbose']).splitlines():
        key,separator,item=line.partition(': ')
        if separator and key in ('release','commit-hash','host'):
            if key in rust: raise ValueError('ambiguous Rust metadata')
            rust[key]=_metadata_token(item,r'[A-Za-z0-9_.+-]+')
    if set(rust)!={'release','commit-hash','host'}: raise ValueError('missing Rust metadata')
    reported=_metadata_text(['rustc','--print=deployment-target','--target',target])
    if not reported.startswith('MACOSX_DEPLOYMENT_TARGET='): raise ValueError('invalid Rust deployment metadata')
    rust['reported_deployment_target']=_metadata_version(reported.split('=',1)[1])
    explicit=os.environ.get('MACOSX_DEPLOYMENT_TARGET')
    rust['explicit_deployment_target']=None if explicit is None else _metadata_version(explicit)
    result=dict(schema=1,target=target,
        source=dict(sha=_metadata_token(os.environ.get('GITHUB_SHA'),r'[0-9a-f]{40}',40),
                    run_id=_metadata_token(os.environ.get('GITHUB_RUN_ID'),r'[0-9]+',30),
                    run_attempt=_metadata_token(os.environ.get('GITHUB_RUN_ATTEMPT'),r'[0-9]+',10)),
        host=dict(arch=_metadata_token(_metadata_text(['/usr/bin/uname','-m']),r'arm64|x86_64'),
                  macos_version=_metadata_version(_metadata_text(['/usr/bin/sw_vers','-productVersion'])),
                  macos_build=_metadata_token(_metadata_text(['/usr/bin/sw_vers','-buildVersion']),r'[A-Za-z0-9.-]+',64),
                  image_version=None if 'ImageVersion' not in os.environ else _metadata_token(os.environ['ImageVersion'],r'[A-Za-z0-9_.-]+',80)),
        sdk=dict(version=_metadata_version(_metadata_text(['/usr/bin/xcrun','--show-sdk-version'])),
                 xcode_version=_metadata_version(xcode[0][6:]),xcode_build=_metadata_token(xcode[1][14:],r'[A-Za-z0-9.-]+',64)),
        rust=rust,native=native,binaries=[])
    tools={name:_metadata_text(['/usr/bin/xcrun','--find',name]) for name in ('otool','lipo')}
    if any(not Path(path).is_absolute() for path in tools.values()): raise ValueError('invalid Darwin tool metadata')
    return result,tools,probe


def _darwin_binary(path,role,program,target,tools):
    before=_metadata_digest(path)
    arch=_metadata_text([tools['lipo'],'-archs',str(path)])
    if arch!=DARWIN_TARGETS[target]: raise ValueError('Darwin metadata architecture mismatch')
    command=parse_darwin_load_commands(metadata_command([tools['otool'],'-l',str(path)]))
    if _metadata_digest(path)!=before: raise ValueError('Darwin metadata input changed')
    return dict(role=role,program=program,sha256=before,arch=arch,version_command=command)


def _write_darwin_metadata(path,value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
    if len(raw)>32768: raise ValueError('Darwin evidence exceeds limit')
    fd,temporary=tempfile.mkstemp(prefix='.darwin-metadata-',dir=Path(path).parent)
    try:
        with os.fdopen(fd,'wb') as stream: stream.write(raw)
        os.link(temporary,path)  # Exclusive publication; never replace prior evidence.
    finally: os.unlink(temporary)


def check_archive(path, inputs, version, target, *, darwin_metadata=None, native_prefix=None):
    enabled=darwin_metadata is not None
    if enabled!=(native_prefix is not None) or (enabled and target not in DARWIN_TARGETS):
        raise ValueError('Darwin metadata arguments require a selected Darwin pair')
    if enabled and os.path.lexists(darwin_metadata): raise ValueError('Darwin evidence already exists')
    evidence,tools,probe=_darwin_context(native_prefix,target) if enabled else (None,None,None)
    root = 'qsh-' + version + '-' + target
    if Path(path).name != root + '.tar.gz':
        raise ValueError('archive filename differs from selected version/target')
    verified={}
    with tarfile.open(str(path), 'r:gz') as archive:
        members = archive.getmembers()
        names = set()
        for member in members:
            # A normal directory header may end in '/'. Alternate spellings
            # must not overwrite the canonical program after its digest check.
            # Release inputs are regular files/directories; no link aliases.
            name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
            parts = name.split('/')
            if (not (member.isfile() or member.isdir())
                    or parts[0] != root or any(part in ('', '.', '..') for part in parts)
                    or name in names or (name == root and not member.isdir())):
                raise ValueError('archive member paths are not canonical and unique')
            names.add(name)
        for program in ('qsh', 'qshd'):
            matches = [member for member in members if member.name == root + '/' + program]
            if len(matches) != 1 or not matches[0].isfile():
                raise ValueError('archive must contain one regular file for each program')
            source = Path(inputs) / program
            with source.open('rb') as stream:
                before = digest(stream)
            check_binary(source, program, version)
            with source.open('rb') as stream:
                after = digest(stream)
            with archive.extractfile(matches[0]) as stream:
                archived = digest(stream)
            if before != after or before != archived:
                raise ValueError('archive payload differs from the probed binary')
            verified[program]=before.hex()

        if enabled:
            with tempfile.TemporaryDirectory(prefix='qsh-release-static-') as directory:
                for program in ('qsh','qshd'):
                    source=Path(inputs)/program
                    member=next(member for member in members if member.name==root+'/'+program)
                    if not 0<member.size<=256*1024**2: raise ValueError('invalid Darwin archive metadata size')
                    extracted=Path(directory)/program
                    with archive.extractfile(member) as stream,extracted.open('xb') as destination:
                        remaining=member.size
                        while remaining:
                            data=stream.read(min(65536,remaining))
                            if not data: raise ValueError('truncated Darwin metadata input')
                            destination.write(data);remaining-=len(data)
                    staged=_darwin_binary(source,'staged',program,target,tools)
                    copied=_darwin_binary(extracted,'extracted',program,target,tools)
                    with archive.extractfile(member) as stream: archived=digest(stream).hex()
                    if staged['sha256']!=copied['sha256'] or copied['sha256']!=archived or archived!=verified[program]:
                        raise ValueError('Darwin metadata archive identity changed')
                    evidence['binaries'].extend([staged,copied])
            native=_darwin_binary(Path(native_prefix)/'version-probe','native-probe','version-probe',target,tools)
            if native['sha256']!=probe: raise ValueError('native metadata probe identity mismatch')
            evidence['binaries'].append(native)
            _write_darwin_metadata(darwin_metadata,evidence)


def debian_version(version):
    # cargo-deb 3.8.0 parse/manifest.rs::manifest_version_string, default
    # revision 1. Preserve its conditional prerelease mapping, not a new policy.
    main, separator, pre = version.partition('-')
    if separator and any(c.isdigit() for c in pre) and any(not c.isdigit() for c in pre):
        version = main + '~' + pre
    return version + '-1'


def check_fields(fmt, fields, filename, program, version, arch):
    if fmt == 'deb':
        package_version = debian_version(version)
        expected = [program, package_version, arch]
        name = '{}_{}_{}.deb'.format(program, package_version, arch)
    else:
        # cargo-generate-rpm 0.21.0 passes the raw version, Release defaults
        # to 1. Its pinned rpm library rejects '-' rather than normalizing it.
        expected = [program, version, '1', arch]
        name = '{}-{}-1.{}.rpm'.format(program, version, arch)
    if fields != expected or Path(filename).name != name:
        raise ValueError('package metadata or filename differs from selected version/identity')


def package_fields(path, fmt):
    if fmt == 'deb':
        command = ['dpkg-deb', '-f', str(path), 'Package', 'Version', 'Architecture']
    else:
        command = ['rpm', '-qp', '--qf', '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n', str(path)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=10, check=True)
    lines = result.stdout.splitlines()
    if fmt == 'deb':
        prefixes = ['Package: ', 'Version: ', 'Architecture: ']
        if len(lines) != 3 or any(not line.startswith(prefix) for line, prefix in zip(lines, prefixes)):
            raise ValueError('invalid Debian package metadata')
        lines = [line[len(prefix):] for line, prefix in zip(lines, prefixes)]
    return lines


def check_package(path, fmt, program, version, arch, probe=False):
    path = Path(path).resolve()
    check_fields(fmt, package_fields(path, fmt), path.name, program, version, arch)
    if probe:
        with tempfile.TemporaryDirectory(prefix='qsh-release-package-') as directory:
            # Inputs are the pipeline's own packages, never downloaded user data.
            if fmt == 'deb':
                subprocess.run(['dpkg-deb', '-x', str(path), directory],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               timeout=10, check=True)
            else:
                producer = subprocess.Popen(['rpm2cpio', str(path)], stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL)
                try:
                    subprocess.run(['cpio', '-idm', '--quiet'], cwd=directory,
                                   stdin=producer.stdout, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, timeout=10, check=True)
                    if producer.wait(timeout=10) != 0:
                        raise ValueError('RPM payload extraction failed')
                finally:
                    producer.stdout.close()
                    if producer.poll() is None:
                        producer.kill()
                    producer.wait()
            check_binary(Path(directory) / 'usr/bin' / program, program, version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command')
    for name in ('archive', 'package', 'text', 'fields'):
        command = sub.add_parser(name)
        command.add_argument('--version', required=name != 'text')
        if name != 'archive':
            command.add_argument('--program', choices=('qsh', 'qshd'), required=True)
        if name in ('package', 'fields'):
            command.add_argument('--format', choices=('deb', 'rpm'), required=True)
            command.add_argument('--arch', required=True)
            command.add_argument('path')
        if name == 'archive':
            command.add_argument('--inputs', required=True)
            command.add_argument('--target', required=True)
            command.add_argument('--darwin-metadata')
            command.add_argument('--native-prefix')
            command.add_argument('path')
        if name == 'package':
            command.add_argument('--probe', action='store_true')
    args = parser.parse_args()
    if args.command is None:
        parser.error('a command is required')
    try:
        if args.version is not None and not _version.valid_version(args.version):
            raise ValueError('invalid selected version')
        if args.command == 'archive':
            check_archive(args.path, args.inputs, args.version, args.target,
                          darwin_metadata=args.darwin_metadata,native_prefix=args.native_prefix)
        elif args.command == 'package':
            check_package(args.path, args.format, args.program, args.version, args.arch, args.probe)
        else:
            data = sys.stdin.buffer.read(LIMIT + 1)
            if len(data) > LIMIT:
                raise ValueError('output exceeds limit')
            if args.command == 'text':
                print(parse_version(data, args.program, args.version))
            else:
                fields = data.decode('utf-8').splitlines()
                check_fields(args.format, fields, args.path, args.program, args.version, args.arch)
    except UnicodeError:
        print('release output: invalid encoded metadata', file=sys.stderr)
        return 1
    except ValueError as error:
        # These are fixed diagnostics, never binary/tool output or paths.
        print('release output: ' + str(error), file=sys.stderr)
        return 1
    except OSError:
        print('release output: tool/target execution unavailable; check architecture prerequisites',
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('release output: interrupted; owned probe cleanup completed', file=sys.stderr)
        return 130
    except (subprocess.SubprocessError, tarfile.TarError):
        print('release output: package/archive validation failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
