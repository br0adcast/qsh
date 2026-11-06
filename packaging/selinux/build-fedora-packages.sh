#!/usr/bin/env bash
# Assemble explicit reviewed inputs; never compile, install, execute qshd or fetch.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
python3 -B - "$root" "$@" <<'PY'
import argparse
import base64
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tomllib


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit=128 * 1024**2, *, single_link=True):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or (single_link and before.st_nlink != 1) or before.st_size > limit:
        raise ValueError('invalid input file')
    data = path.read_bytes()
    after = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(after, key) != getattr(before, key) for key in fields) or len(data) != before.st_size:
        raise ValueError('input changed')
    return data


def document(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(argv, *, cwd=None, input=None):
    # No shell evaluation, candidate execution, download or asynchronous child.
    return subprocess.run(list(map(str, argv)), cwd=cwd, input=input, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def toml_value(value):
    if type(value) is str: return json.dumps(value)
    if type(value) is bool: return str(value).lower()
    if type(value) is int: return str(value)
    if type(value) is list: return '[' + ','.join(toml_value(item) for item in value) + ']'
    if type(value) is dict:
        return '{' + ','.join(json.dumps(key) + '=' + toml_value(item) for key, item in value.items()) + '}'
    raise ValueError('unsupported metadata')


def toml_table(value):
    return '\n'.join(json.dumps(key) + '=' + toml_value(item) for key, item in value.items()) + '\n'


def consumer_metadata(repo, variant, binary, manifest, release):
    assets = []
    selected = {'/usr/bin/qshd': binary, '/usr/share/qshd/consumer-rpm.json': manifest}
    for row in variant['assets']:
        path = selected.get(row['dest'])
        if path is None: path = (repo / 'cli' / row['source']).resolve()
        assets.append(dict(row, source=str(path)))
    return dict(epoch=0, release=release, assets=assets)


def consumer_dependencies(rows):
    for row in [('qshd-selinux-abi', 8, '2'), ('qshd-selinux', 512, ''),
                ('qshd-selinux', 1024, ''), ('qshd-selinux', 2048, ''),
                ('/usr/bin/getent', 1024, ''), ('/usr/sbin/useradd', 1024, '')]:
        if row not in rows: raise ValueError('missing consumer phase/ABI requirement')
    for library in ('libc.so.6', 'libpam.so.0', 'libselinux.so.1'):
        if not any(name == library or name.startswith(library + '(') for name, _, _ in rows):
            raise ValueError('missing automatic ELF requirement')


def binary_checks(repo, path, arch):
    data = read(path, single_link=False)
    if (len(data) < 64 or data[:6] != b'\x7fELF\x02\x01'
            or struct.unpack_from('<H', data, 18)[0] != {'x86_64': 62, 'aarch64': 183}[arch]
            or struct.unpack_from('<H', data, 16)[0] not in (2, 3)):
        raise ValueError('wrong final ELF architecture')
    dynamic = run(['readelf', '-d', path]).decode()
    needed = set(re.findall(r'\(NEEDED\).*?\[([^]]+)\]', dynamic))
    for library in ('libc.so.6', 'libpam.so.0', 'libselinux.so.1'):
        if library not in needed: raise ValueError('missing system ELF linkage')
    versions = run(['readelf', '-V', '--wide', path]).decode()
    nodes = re.findall(r'GLIBC_([0-9]+(?:\.[0-9]+)+)', versions)
    if not nodes or max(tuple(map(int, node.split('.'))) for node in nodes) > (2, 28):
        raise ValueError('ELF exceeds reviewed glibc 2.28 floor')
    run(['bash', repo / 'scripts/check-pam-linkage.sh', path])
    run(['bash', repo / 'scripts/check-selinux-linkage.sh', path])
    return data


def source_offer(repo, policy, archive, epoch, build):
    pins = json.loads(read(repo / 'packaging/selinux/inputs.json', 65536))
    files = build.bundle_source_files(repo / 'packaging/selinux')
    expected = {name: read(path) for name, path in files.items()}
    input_names = {'inputs/' + pins[key] for key in ('policy_source', 'policy_devel')}
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        if [item.name for item in members] != sorted(set(expected) | input_names):
            raise ValueError('source offer does not match current explicit closure')
        for member in members:
            if not member.isfile() or (member.uid, member.gid, member.mode, member.mtime) != (0, 0, 0o644, epoch):
                raise ValueError('source offer member metadata')
            if member.size > 128 * 1024**2: raise ValueError('source offer member too large')
            data = stream.extractfile(member).read()
            if member.name in expected:
                if data != expected[member.name]: raise ValueError('stale corresponding source')
            elif digest(data) != pins['rpms'][member.name[7:]]:
                raise ValueError('source offer reference-policy input mismatch')
    return read(archive)


def rpm_capsule(capsule):
    # RPM expands macros in -f script files, including encoded source strings.
    # Transport the exact reviewed renderer bytes with no percent characters
    # and short physical lines; the runtime helper/budgets remain unchanged.
    if type(capsule) is not bytes or not 0 < len(capsule) <= 262144:
        raise ValueError('capsule transport size')
    entry = b'import time\n_capsule_started=time.monotonic()\n'
    if not capsule.startswith(entry): raise ValueError('renderer entry contract changed')
    encoded = base64.b64encode(capsule).decode('ascii')
    lines = '\n'.join(repr(encoded[index:index + 76]) for index in range(0, len(encoded), 76))
    # Execute the identical reviewed entry once, BEFORE transport decoding. The
    # full render bytes stay hash-bound; their suffix reuses that original clock
    # in the same __main__/globals rather than renewing the fresh 30s deadline.
    return entry + ('import base64,hashlib\n_capsule_bytes=base64.b64decode(\n' + lines + '\n)\n'
            + "if hashlib.sha256(_capsule_bytes).hexdigest()!=" + repr(digest(capsule)) + ": raise RuntimeError('CAPSULE_HASH')\n"
            + "exec(compile(_capsule_bytes[" + str(len(entry)) + ":],'<qshd-reviewed-provider-pre>','exec'))\n").encode('ascii')


def provider_inventory(inventory, extras):
    # Authority comes from the independently admitted assembler inventory and
    # reviewed source bytes, never from an observed RPM or a mutable stage.
    result = {'/' + row['path']: (row['size'], 0o100644, 0, 'root', 'root', row['sha256']) for row in inventory}
    if len(result) != 28: raise ValueError('provider runtime closure')
    for name, data in extras.items():
        relative = '/' + name
        flags = 128 if relative.startswith('/usr/share/licenses/') else 2 if relative.startswith('/usr/share/doc/') else 0
        if relative in result: raise ValueError('duplicate provider source asset')
        result[relative] = (len(data), 0o100644, flags, 'root', 'root', digest(data))
    if len(result) != 32: raise ValueError('provider source/license closure')
    return result


def stage_check(stage, wanted):
    actual = {}
    for path in stage.rglob('*'):
        if path.is_symlink(): raise ValueError('provider stage symlink')
        if path.is_file():
            data = read(path)
            actual['/' + path.relative_to(stage).as_posix()] = (len(data), stat.S_IMODE(path.stat().st_mode), digest(data))
    if actual != {name: (row[0], 0o644, row[5]) for name, row in wanted.items()}:
        raise ValueError('provider stage differs from admitted inputs')


def query(rpm, expression):
    return run(['/usr/bin/rpm', '--rcfile', '/dev/null', '--macros', '/dev/null', '--noplugins',
                '-qp', '--nosignature', '--qf', expression, rpm]).decode()


def requirements(rpm):
    raw = query(rpm, '[%{REQUIRENAME}\t%{REQUIREFLAGS}\t%{REQUIREVERSION}\n]')
    return [(name, int(flags), version) for name, flags, version in (line.split('\t') for line in raw.splitlines())]


def scripts(rpm, expected):
    actual = {}
    for tag, path in expected.items():
        data = query(rpm, '%{' + tag + '}').encode()
        if data != read(path): raise ValueError('scriptlet bytes differ from reviewed hook')
        actual[tag] = dict(size=len(data), sha256=digest(data))
    return actual


def file_headers(rpm):
    raw = query(rpm, '[%{FILENAMES}\t%{FILESIZES}\t%{FILEMODES}\t%{FILEFLAGS}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILEDIGESTS}\t%{FILELINKTOS}\n]')
    actual = {}
    for line in raw.splitlines():
        name, size, mode, flags, owner, group, checksum, link = line.split('\t')
        if name in actual or link: raise ValueError('duplicate/link package leaf')
        actual[name] = (int(size), int(mode), int(flags), owner, group, checksum)
    return actual


def provider_headers(rpm, wanted, version, release, hooks):
    identity = query(rpm, '%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{FILEDIGESTALGO}')
    if identity != '\t'.join(['qshd-selinux', '0', version, release, 'noarch', '8']):
        raise ValueError('provider identity/digest algorithm')
    if ('qshd-selinux-abi', '8', '2') not in [tuple(line.split('\t')) for line in query(rpm, '[%{PROVIDENAME}\t%{PROVIDEFLAGS}\t%{PROVIDEVERSION}\n]').splitlines()]:
        raise ValueError('provider ABI declaration')
    files = file_headers(rpm)
    if files != wanted: raise ValueError('provider header payload closure')
    rows = requirements(rpm)
    for tool in ('/usr/bin/python3', '/usr/bin/semodule', '/usr/bin/rpm', '/usr/bin/systemctl'):
        for flag in (512, 1024, 2048):
            if not any(name == tool and flags & flag for name, flags, _ in rows):
                raise ValueError('provider phase tool dependency')
    scriptlets = scripts(rpm, {tag: hooks / name for tag, name in [('PREIN', 'provider-pre'), ('POSTIN', 'provider-post'), ('PREUN', 'provider-preun'), ('POSTUN', 'provider-postun')]})
    return dict(identity=identity, files=files, requires=rows, scriptlets=scriptlets)


def payload_bytes(rpm, wanted, archive):
    # Native decoders only. Select each admitted ordinary leaf to stdout, never
    # extract paths or execute any payload/scriptlet from the RPM.
    with archive.open('xb') as output:
        subprocess.run(['/usr/bin/rpm2cpio', str(rpm)], check=True, stdout=output, stderr=subprocess.PIPE)
    inspected = {}
    for name, row in wanted.items():
        with archive.open('rb') as source:
            data = subprocess.run(['cpio', '--quiet', '-i', '--to-stdout', '.' + name], stdin=source,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True).stdout
        if (len(data), digest(data)) != (row[0], row[5]): raise ValueError('package payload bytes')
        inspected[name] = dict(size=len(data), sha256=digest(data))
    return inspected


def main(repo, arguments):
    parser = argparse.ArgumentParser(description='Offline Fedora pair RPM assembly from reviewed final inputs')
    for key in ('policy-output', 'expected', 'x86_64-binary', 'aarch64-binary', 'output'):
        parser.add_argument('--' + key, required=True, type=Path)
    parser.add_argument('--release', required=True)
    parser.add_argument('--epoch', required=True, type=int)
    args = parser.parse_args(arguments)
    try:
        if not re.fullmatch(r'[1-9][0-9]*\.fc44', args.release) or not 0 <= args.epoch <= 4294967295:
            raise ValueError('release/epoch')
        policy, output = args.policy_output.absolute(), args.output.absolute()
        if any(re.fullmatch(r'/[A-Za-z0-9_./+-]+', str(path)) is None for path in (repo, output)):
            raise ValueError('repository/output path is unsafe for RPM macro arguments')
        if output.exists() or output.is_symlink() or policy.resolve() == output.resolve() or policy.resolve() in output.resolve().parents:
            raise ValueError('output must be fresh and separate from policy inputs')
        tool = Path(os.environ.get('QSH_RPM_TOOL', ''))
        tool_sha = os.environ.get('QSH_RPM_TOOL_SHA256', '')
        if not tool.is_absolute() or not re.fullmatch('[0-9a-f]{64}', tool_sha) or digest(read(tool, single_link=False)) != tool_sha:
            raise ValueError('explicit reviewed pinned generator required')
        for command in ('rpmbuild', 'rpm', 'rpm2cpio', 'cpio', 'readelf', 'nm', 'bash'):
            if shutil.which(command) is None: raise ValueError('missing tool: ' + command)
        if not all(Path(path).is_file() for path in ('/usr/bin/rpm', '/usr/bin/rpm2cpio')):
            raise ValueError('fixed RPM query/decoder missing')
        if not Path('/usr/lib/rpm/find-requires').is_file(): raise ValueError('fixed RPM find-requires missing')
        source = repo / 'packaging/selinux'
        sys.path.insert(0, str(source))
        build = load('fedora_policy_build', source / 'build.py')
        assembler = load('fedora_assembler', source / 'assemble_payload.py')
        embed = load('fedora_pre_embed', source / 'embed_provider_pre.py')
        from qshd_selinux_activation import TrustedArtifact
        version = build.workspace_version(repo / 'Cargo.toml')
        expected = assembler._expected(json.loads(read(args.expected)))
        archive = policy / ('qshd-selinux-' + version + '-source.tar.gz')
        offered = source_offer(repo, policy, archive, args.epoch, build)
        reviewed_source = {name: digest(read(path)) for name, path in build.bundle_source_files(source).items()}
        binaries = {arch: binary_checks(repo, path.absolute(), arch) for arch, path in [('x86_64', args.x86_64_binary), ('aarch64', args.aarch64_binary)]}
        core, contexts = read(policy / 'qshd.pp'), read(policy / 'qshd_contexts.pp')
        expanded = read(policy / 'qshd_contexts.fc')
        build.validate_sources(source)
        build.validate_package(core, role='core', expected_contexts=core[struct.unpack_from('<I', core, 16)[0]+4:])
        build.validate_package(contexts, role='contexts', expected_contexts=expanded)
        artifact = read(source / 'artifact.json')
        trusted = TrustedArtifact(assembler._artifact(artifact), digest(artifact), digest(core), digest(contexts))
        output.mkdir(mode=0o755)
        for name in ('work', 'home', 'cache', 'config', 'tmp'): (output / name).mkdir(mode=0o700)
        os.environ.update(HOME=str(output / 'home'), XDG_CACHE_HOME=str(output / 'cache'), XDG_CONFIG_HOME=str(output / 'config'), TMPDIR=str(output / 'tmp'), HISTFILE='/dev/null', PYTHONDONTWRITEBYTECODE='1', SOURCE_DATE_EPOCH=str(args.epoch), LANG='C', LC_ALL='C')
        work, stage, hooks = output / 'work', output / 'work/provider-stage', output / 'work/provider-hooks'
        inventory = assembler.assemble_payload(source, policy / 'qshd.pp', policy / 'qshd_contexts.pp', source / 'artifact.json', repo / 'packaging/pam.d/qshd.fedora-selinux', expected, stage, args.epoch)
        if len(inventory) != 28: raise ValueError('runtime closure')
        extras = {'usr/share/qshd-selinux/source/' + archive.name: offered,
                  'usr/share/licenses/qshd-selinux/LICENSE': read(repo / 'LICENSE'),
                  'usr/share/licenses/qshd-selinux/GPL-3.0.txt': read(source / 'GPL-3.0.txt'),
                  'usr/share/doc/qshd-selinux/README.md': read(source / 'README.md')}
        for name, data in extras.items():
            path = stage / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(0o644); os.utime(path, (args.epoch, args.epoch))
        wanted = provider_inventory(inventory, extras)
        stage_check(stage, wanted)
        hooks.mkdir()
        sources = {name: read(source / (name + '.py'), 131072) for name in embed.MODULES}
        capsule = embed.render(sources, trusted, artifact_bytes=artifact, core_pp_bytes=core, contexts_pp_bytes=contexts)
        for name in ('provider-pre', 'provider-post', 'provider-preun', 'provider-postun'):
            data = read(source / 'maintainer' / name)
            if name == 'provider-pre':
                if data.count(b'@QSHD_PROVIDER_PRE_CAPSULE@') != 1 or data.count(b'@QSHD_INCOMING_ARTIFACT_JSON@') != 1 or b'\nQSHD_PROVIDER_PRE_CAPSULE\n' in capsule:
                    raise ValueError('provider template markers')
                data = data.replace(b'@QSHD_PROVIDER_PRE_CAPSULE@', rpm_capsule(capsule)).replace(b'@QSHD_INCOMING_ARTIFACT_JSON@', document(asdict(trusted)).rstrip())
            if b'%' in data: raise ValueError('macro-active provider script input')
            (hooks / name).write_bytes(data)
        receipt = dict(schema=1, version=version, release=args.release, epoch=args.epoch,
                       expected=expected, incoming_artifact=asdict(trusted), tool_sha256=tool_sha,
                       capsule_sources={name: digest(data) for name, data in sources.items()},
                       capsule_sha256=digest(capsule), capsule_transport_sha256=digest(rpm_capsule(capsule)),
                       provider_template_sha256=digest(read(source / 'maintainer/provider-pre')),
                       source_offer_sha256=digest(offered), binaries={arch: digest(data) for arch, data in binaries.items()})
        (work / 'build-inputs.json').write_bytes(document(receipt))
        top = work / 'rpmbuild'; top.mkdir()
        for directory in ('BUILD', 'BUILDROOT', 'RPMS', 'SOURCES', 'SPECS', 'SRPMS'): (top / directory).mkdir()
        run(['rpmbuild', '-bb', '--define', '_topdir ' + str(top), '--define', '_builddir ' + str(top / 'BUILD'), '--define', '_tmppath ' + str(output / 'tmp'),
             '--define', '_buildhost reproducible.invalid',
             '--define', '_binary_filedigest_algorithm 8',
             '--define', 'qsh_version ' + version, '--define', 'qsh_release ' + args.release,
             '--define', 'qsh_stage ' + str(stage), '--define', 'qsh_hooks_source ' + str(hooks),
             '--define', 'qsh_hooks qsh-provider-hooks', source / 'qshd-selinux.spec'])
        provider = output / ('qshd-selinux-' + version + '-' + args.release + '.noarch.rpm')
        shutil.copyfile(top / 'RPMS/noarch' / provider.name, provider)
        provider_inspection = provider_headers(provider, wanted, version, args.release, hooks)
        provider_inspection['payload'] = payload_bytes(provider, wanted, work / 'provider.cpio')
        (work / 'provider-inspection.json').write_bytes(document(provider_inspection))
        stage_check(stage, wanted)
        variant = tomllib.loads(read(repo / 'cli/Cargo.toml').decode())['package']['metadata']['generate-rpm']['variants']['qshd-fedora-selinux']
        for arch, data in binaries.items():
            directory = work / arch; directory.mkdir()
            binary = directory / 'qshd'; binary.write_bytes(data); binary.chmod(0o755); os.utime(binary, (args.epoch, args.epoch))
            pam = directory / 'qshd.pam'; pam.write_bytes(read(repo / 'packaging/pam.d/qshd.fedora-selinux')); pam.chmod(0o644); os.utime(pam, (args.epoch, args.epoch))
            metadata = dict(schema=1, package=dict(name='qshd', epoch=0, version=version, release=args.release, arch=arch), files=[
                dict(path='/etc/pam.d/qshd', mode=0o100644, owner='root', group='root', flags=17),
                dict(path='/usr/bin/qshd', mode=0o100755, owner='root', group='root', flags=0)])
            build_metadata = directory / 'build-metadata.json'; build_metadata.write_bytes(document(metadata))
            authority = directory / 'authority'
            run([sys.executable, '-B', repo / 'scripts/generate-selinux-consumer-authority.py', '--binary', binary, '--pam', pam, '--build-metadata', build_metadata, '--output-directory', authority])
            overrides = consumer_metadata(repo, variant, binary, authority / 'consumer-rpm.json', args.release)
            os.utime(authority / 'consumer-rpm.json', (args.epoch, args.epoch))
            for row in overrides['assets']:
                if row['dest'] == '/etc/pam.d/qshd': row['source'] = str(pam)
                elif row['dest'] not in ('/usr/bin/qshd', '/usr/share/qshd/consumer-rpm.json'):
                    copied = directory / 'assets' / row['dest'].lstrip('/')
                    copied.parent.mkdir(parents=True, exist_ok=True)
                    copied.write_bytes(read(Path(row['source']))); copied.chmod(int(row['mode'], 8)); os.utime(copied, (args.epoch, args.epoch))
                    row['source'] = str(copied)
            final_metadata = directory / ('qshd-fedora-selinux-' + arch + '.toml'); final_metadata.write_text(toml_table(overrides))
            rpm = output / ('qshd-' + version + '-' + args.release + '.' + arch + '.rpm')
            run([tool, '--package', 'cli', '--variant', 'qshd-fedora-selinux', '--arch', arch,
                 '--target-dir', directory / 'target', '--auto-req', 'find-requires', '--source-date', args.epoch,
                 '--metadata-overwrite', final_metadata, '--output', rpm], cwd=repo)
            rows = requirements(rpm)
            consumer_dependencies(rows)
            consumer_wanted = {}
            for row in overrides['assets']:
                content = read(Path(row['source']))
                flags = 17 if row.get('config') == 'noreplace' else 2 if row.get('doc') else 0
                consumer_wanted[row['dest']] = (len(content), stat.S_IFREG | int(row['mode'], 8), flags, 'root', 'root', digest(content))
            actual = file_headers(rpm)
            if actual != consumer_wanted: raise ValueError('consumer full header closure')
            payload_inspection = payload_bytes(rpm, consumer_wanted, directory / 'consumer.cpio')
            script_inspection = scripts(rpm, {tag: source / 'maintainer' / name for tag, name in [('PREIN', 'consumer-pre'), ('POSTIN', 'consumer-post'), ('PREUN', 'consumer-preun'), ('POSTUN', 'consumer-postun')]})
            verdict = run([sys.executable, '-B', repo / 'scripts/check-selinux-consumer-rpm.py', '--rpm', rpm, '--manifest', authority / 'consumer-rpm.json', '--receipt', authority / 'generation-receipt.json'])
            (directory / 'final-rpm-verdict.json').write_bytes(verdict)
            (directory / 'package-inspection.json').write_bytes(document(dict(files=actual, requires=rows, payload=payload_inspection, scriptlets=script_inspection)))
            if read(binary) != data or read(pam) != read(repo / 'packaging/pam.d/qshd.fedora-selinux'):
                raise ValueError('transformation after authority generation')
        if any(read(path.absolute(), single_link=False) != binaries[arch] for arch, path in [('x86_64', args.x86_64_binary), ('aarch64', args.aarch64_binary)]):
            raise ValueError('original binary changed')
        if digest(read(tool, single_link=False)) != tool_sha: raise ValueError('reviewed tool changed')
        if reviewed_source != {name: digest(read(path)) for name, path in build.bundle_source_files(source).items()}:
            raise ValueError('reviewed source changed')
        if read(policy / 'qshd.pp') != core or read(policy / 'qshd_contexts.pp') != contexts or read(archive) != offered:
            raise ValueError('reviewed policy/source input changed')
        (output / 'inspection.json').write_bytes(document(dict(schema=1, result='constructed-and-inspected',
            packages={p.name: digest(read(p)) for p in (provider, output / ('qshd-' + version + '-' + args.release + '.x86_64.rpm'), output / ('qshd-' + version + '-' + args.release + '.aarch64.rpm'))})))
    except (ValueError, OSError, subprocess.CalledProcessError, KeyError, struct.error, tarfile.TarError) as error:
        parser.exit(1, 'Fedora assembly refused: ' + type(error).__name__ + '\n')


if __name__ == '__main__':
    main(Path(sys.argv[1]), sys.argv[2:])
PY
