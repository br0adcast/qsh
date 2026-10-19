#!/usr/bin/env python3
"""Qualify one native prefix, without adding a production Rust dependency."""
import argparse
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile


def run(command, **kwargs):
    check = kwargs.pop('check', True)
    with subprocess.Popen(command, start_new_session=True, **kwargs) as child:
        try:
            stdout, stderr = child.communicate()
        except BaseException:
            # The builder owns its nested make groups and handles SIGTERM by
            # stopping them before exit. Allow that cleanup before escalation.
            child.terminate()
            try:
                child.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.communicate()
            raise
        result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', help='explicit target emulator, never a shell command')
    parser.add_argument('--runner-arg', action='append', default=[])
    args, build_args = parser.parse_known_args()
    scripts = Path(__file__).resolve().parent
    prefix = Path(run(['bash', str(scripts / 'build-openssl.sh'), *build_args],
                      stdout=subprocess.PIPE, universal_newlines=True).stdout.strip())
    manifest = json.loads((prefix / 'manifest.json').read_text())
    version = manifest['identity']['source']['version']
    runner = [args.runner, *args.runner_arg] if args.runner else []
    executable = [*runner, str(prefix / 'bin/openssl')]
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix='qsh-native-qualification-') as name:
            work = Path(name)
            env = dict(os.environ, HISTFILE='/dev/null')
            for name in ['SSH_AUTH_SOCK', 'OPENSSL_MODULES', 'RANDFILE',
                         'SSL_CERT_FILE', 'SSL_CERT_DIR']:
                env.pop(name, None)
            for name, directory in [('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'),
                                    ('XDG_CACHE_HOME', 'cache')]:
                owned = work / directory
                owned.mkdir()
                env[name] = str(owned)
            config = work / 'openssl.cnf'
            config.write_text('')
            env['OPENSSL_CONF'] = str(config)
            run([*runner, str(prefix / 'version-probe')], env=env)
            actual = run([*executable, 'version'], env=env, universal_newlines=True,
                         stdout=subprocess.PIPE).stdout
            if not actual.startswith('OpenSSL ' + version + ' '):
                raise RuntimeError('runtime OpenSSL version differs from the pin')
            print(actual.strip())
            key, public = work / 'private.pem', work / 'public.pem'
            # Generated ephemeral keys are never printed or uploaded.
            run([*executable, 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
                 'rsa_keygen_bits:2048', '-out', str(key)], env=env, stderr=subprocess.DEVNULL)
            run([*executable, 'pkey', '-in', str(key), '-pubout', '-out', str(public)], env=env)
            message = work / 'message'
            message.write_bytes(b'qsh native prerequisite qualification\n')
            changed = work / 'changed'
            changed.write_bytes(b'changed message\n')
            for algorithm in ['sha1', 'sha256', 'sha512']:
                signature = work / (algorithm + '.sig')
                run([*executable, 'dgst', '-' + algorithm, '-sign', str(key),
                     '-out', str(signature), str(message)], env=env)
                check = [*executable, 'dgst', '-' + algorithm, '-verify', str(public),
                         '-signature', str(signature)]
                run([*check, str(message)], env=env, stdout=subprocess.DEVNULL)
                negative = run([*check, str(changed)], env=env, check=False,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if negative.returncode != 1:
                    raise RuntimeError('changed-message negative control did not reject normally')
                print(algorithm + ': generated RSA sign/verify and changed-message rejection PASS')
    finally:
        os.umask(old_umask)
    print('Qualified: ' + manifest['identity']['target'])


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise InterruptedError('qualification interrupted by signal ' + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print('native qualification: ' + str(error), file=sys.stderr)
        sys.exit(1)
