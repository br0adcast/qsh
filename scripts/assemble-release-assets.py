#!/usr/bin/env python3
"""Select the fixed producer products into a fresh release directory."""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


def _sibling(name):
    spec=importlib.util.spec_from_file_location(name.replace('-','_'),Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_version=_sibling('check-release-version')
_output=_sibling('check-release-output')


class AssemblyError(ValueError):
    """Fixed safe assembly failure; never contains input contents or paths."""


def expected_products(version):
    if not _version.valid_version(version):
        raise AssemblyError('invalid release version')
    deb=_output.debian_version(version)
    rpm=_output.rpm_version(version)
    products={}
    for target,deb_arch,rpm_arch in (
            ('x86_64-unknown-linux-musl','amd64','x86_64'),
            ('aarch64-unknown-linux-musl','arm64','aarch64')):
        products['linux-'+target]=(f'qsh-{version}-{target}.tar.gz',
            f'qsh_{deb}_{deb_arch}.deb',f'qsh-{rpm}-1.{rpm_arch}.rpm')
    products['macos']=tuple(f'qsh-{version}-{target}.tar.gz'
        for target in ('aarch64-apple-darwin','x86_64-apple-darwin'))
    products['server-packages']=tuple(f'qshd_{deb}_{arch}.deb' for arch in ('amd64','arm64'))+tuple(
        f'qshd-{rpm}-1.{arch}.rpm' for arch in ('x86_64','aarch64'))
    names=[name for values in products.values() for name in values]
    if len(names)!=12 or len(set(names))!=12:
        raise AssemblyError('ambiguous product names')
    return products


def _directory(stack,path,*,dir_fd=None):
    descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dir_fd)
    stack.callback(os.close,descriptor)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        raise AssemblyError('producer must be a real directory')
    return descriptor


def _copy_file(descriptor,destination):
    digest=hashlib.sha256()
    with destination.open('xb') as copied:
        while True:
            chunk=os.read(descriptor,1024*1024)
            if not chunk:break
            copied.write(chunk);digest.update(chunk)
    return digest.hexdigest()


def assemble(artifacts,version,output):
    """CI inputs are immutable; this is not a concurrent filesystem authority."""
    products=expected_products(version)
    artifacts=Path(artifacts);output=Path(output)
    stage=None
    try:
        if output.name in ('','.','..') or os.path.lexists(output):
            raise AssemblyError('output must not exist')
        if not stat.S_ISDIR(output.parent.lstat().st_mode):
            raise AssemblyError('output parent must be a real directory')
        source=artifacts.resolve(strict=True);parent=output.parent.resolve(strict=True)
        destination=parent/output.name
        if parent==source or parent.is_relative_to(source) or source.is_relative_to(destination):
            raise AssemblyError('input and output must be separate')
        with ExitStack() as descriptors:
            root=_directory(descriptors,artifacts)
            selected={}
            # Admit every producer and opened input before creating any output.
            # Unselected artifact directories are never enumerated or traversed.
            for producer,names in products.items():
                directory=_directory(descriptors,producer,dir_fd=root)
                if set(os.listdir(directory))!=set(names):
                    raise AssemblyError('producer contents differ from expected products')
                for name in names:
                    descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
                    descriptors.callback(os.close,descriptor)
                    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                        raise AssemblyError('product must be a regular file')
                    if name in selected:raise AssemblyError('ambiguous product names')
                    selected[name]=descriptor
            stage=Path(tempfile.mkdtemp(prefix='.release-assets-',dir=parent))
            hashes={name:_copy_file(selected[name],stage/name) for name in sorted(selected)}
            with (stage/'SHA256SUMS').open('x',encoding='ascii',newline='\n') as manifest:
                manifest.write(''.join(hashes[name]+'  '+name+'\n' for name in sorted(hashes)))
        # All opened input descriptors must finalize before publication.
        if os.path.lexists(destination):raise AssemblyError('output must not exist')
        # Same-parent rename publishes a complete set. The CI-owned workspace
        # excludes competing destination creators; this is not a portable
        # adversarial atomic no-replace primitive.
        os.rename(stage,destination)
        stage=None
    except (OSError,RuntimeError):
        raise AssemblyError('filesystem operation failed') from None
    finally:
        if stage is not None:
            try:shutil.rmtree(stage)
            except OSError:raise AssemblyError('staging cleanup failed') from None



def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts',required=True,type=Path)
    parser.add_argument('--version',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    try:assemble(args.artifacts,args.version,args.output)
    except AssemblyError as error:
        print('release assembly: '+str(error),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':sys.exit(main())
