#!/bin/sh
# HTTPS bootstrap only. Persistent installation is owned by the Rust engine.
set -eu
fail() { printf 'qsh installer: %s\n' "$*" >&2; exit 1; }
usage() { printf 'Usage: install.sh [--version VERSION] [--prefix PATH]\n'; }
version=
version_set=no
prefix=
prefix_set=no
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version) [ "$#" -ge 2 ] || fail '--version requires a value'; [ "$version_set" = no ] || fail 'duplicate --version'; version_set=yes; version=$2; [ -n "$version" ] || fail 'empty version'; shift 2 ;;
        --prefix) [ "$#" -ge 2 ] || fail '--prefix requires a value'; [ "$prefix_set" = no ] || fail 'duplicate --prefix'; prefix=$2; [ -n "$prefix" ] || fail 'empty prefix'; prefix_set=yes; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown argument: $1" ;;
    esac
done
valid_version() {
    # An argument must be one ASCII token, not several grep input lines.
    case "$1" in ''|*[!0-9A-Za-z.-]*) return 1 ;; esac
    # Match exact release SemVer without build metadata (ImageRequest policy).
    [ "${#1}" -le 128 ] || return 1
    identifier='(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
    printf '%s\n' "$1" | LC_ALL=C grep -Eq "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-$identifier(\\.$identifier)*)?$"
}
[ "$version_set" = no ] || valid_version "$version" || fail 'expected VERSION such as 0.6.0 or 0.6.0-rc.2 (without v)'
case "$(uname -s)" in Linux) platform=unknown-linux-musl ;; Darwin) platform=apple-darwin ;; *) fail 'supported systems are Linux and macOS' ;; esac
case "$(uname -m)" in x86_64|amd64) cpu=x86_64 ;; aarch64|arm64) cpu=aarch64 ;; *) fail 'supported architectures are x86_64 and aarch64' ;; esac
for tool in curl tar grep mktemp chmod rm; do command -v "$tool" >/dev/null 2>&1 || fail "required command missing: $tool"; done
printf '%s\n' 'Bootstrap trust: the script and temporary qsh executable come from official GitHub HTTPS.' 'The temporary executable authenticates the final release before persistent installation.' >&2
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/qsh-install.XXXXXXXX") || fail 'cannot create temporary directory'
trap 'rm -rf "$work"' 0
trap 'exit 130' INT
trap 'exit 143' TERM HUP
fetch() {
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 --max-filesize 134217728 "$@"
}
if [ "$version_set" = no ]; then
    release_url=$(fetch --output /dev/null --write-out '%{url_effective}' https://github.com/br0adcast/qsh/releases/latest) || fail 'cannot resolve latest stable release'
    case "$release_url" in https://github.com/br0adcast/qsh/releases/tag/v*) version=${release_url#https://github.com/br0adcast/qsh/releases/tag/v} ;; *) fail 'unexpected latest release URL' ;; esac
    valid_version "$version" || fail 'invalid latest release version'
    case "$version" in *-*) fail 'latest release is not stable' ;; esac
fi
stem=qsh-$version-$cpu-$platform
fetch --output "$work/archive.tar.gz" "https://github.com/br0adcast/qsh/releases/download/v$version/$stem.tar.gz" || fail 'bootstrap download failed'
# Inspect every name and type, then stream just qsh; never extract archive paths.
# Child-only file limits cap each output at 64 MiB with POSIX 512-byte blocks
# (128 MiB on shells using 1024-byte blocks), including decompressed qsh.
(ulimit -f 131072; tar -tzf "$work/archive.tar.gz") > "$work/names" || fail 'invalid archive'
count=0
while IFS= read -r entry; do
    case "$entry" in
        "$stem/"|"$stem/qshd"|"$stem/README.md"|"$stem/LICENSE"|"$stem/CHANGELOG.md"|"$stem/LICENSE-OPENSSL.txt"|"$stem/LICENSE-AWS-LC-RS.txt"|"$stem/LICENSE-AWS-LC.txt") ;;
        "$stem/qsh") count=$((count + 1)) ;;
        *) fail 'unexpected archive entry' ;;
    esac
done < "$work/names"
[ "$count" -eq 1 ] || fail 'archive must contain exactly one qsh'
(ulimit -f 131072; tar -tvzf "$work/archive.tar.gz") > "$work/types" || fail 'invalid archive types'
LC_ALL=C grep -Eq '^[^-d]' "$work/types" && fail 'archive links or special files are forbidden'
# The exact selected member must be a regular file, not a directory.
(ulimit -f 131072; tar -tvzf "$work/archive.tar.gz" "$stem/qsh") > "$work/member" || fail 'missing bootstrap member'
IFS= read -r member < "$work/member" || fail 'missing bootstrap type'
case "$member" in -*) ;; *) fail 'qsh bootstrap is not a regular file' ;; esac
(ulimit -f 131072; tar -xOzf "$work/archive.tar.gz" "$stem/qsh") > "$work/qsh" || fail 'cannot read bootstrap member'
chmod 700 "$work/qsh"
"$work/qsh" --self-install --help > "$work/help" 2>&1 || fail 'this release cannot install qsh; select a later installer-capable release with --version'
grep -Fx 'Usage: qsh --self-install [--version VERSION] [--prefix PATH]' "$work/help" >/dev/null || fail 'this release cannot install qsh; select a later installer-capable release with --version'
if [ "$prefix_set" = yes ]; then
    "$work/qsh" --self-install --version "$version" --prefix "$prefix"
else
    "$work/qsh" --self-install --version "$version"
fi
