# qshd SELinux policy source

The authored files and build script are licensed under AGPL-3.0-only, like qsh.
The policy source version is independently maintained at `0.2.0`; the eventual
`qshd-selinux` noarch package version follows the source workspace version.
The qualified module priority is **400**. This recipe compiles a module; it does
not install policy, change auditing, label files, modify PAM, or start services.

The source implements the reviewed daemon, helper and worker domain contract.
Both `/run/qshd` and `/var/run/qshd` contexts are intentional for distribution
path substitutions. Runtime qualification applies to Fedora 44 targeted policy;
compilation with EL8 interfaces does not establish EL8 runtime support. Generic
qshd packages do not acquire a Fedora policy dependency from this recipe.

## Build inputs

`inputs.json` pins the signed Rocky Linux RPM inputs by SHA-256 and the selected
compiler package versions. The include floor is exactly
`selinux-policy-devel-3.14.3-67.el8.noarch`; using a newer installed devel tree
would change the expanded policy. The matching source RPM is
`selinux-policy-3.14.3-67.el8.src.rpm`. Upstream sources originate in the
[Fedora SELinux policy repository](https://github.com/fedora-selinux/selinux-policy)
and its contrib submodule; the exact commits and downstream patches are retained
in that source RPM. No reference-policy implementation is vendored into qsh.

Build the disposable linux/amd64 environment from the maintained `Dockerfile`:

```sh
timeout 720 docker build --platform linux/amd64 --network default \
  --memory 2g --cpu-quota 200000 -t qshd-policy-builder \
  -f packaging/selinux/Dockerfile packaging/selinux
```

The base has a registry-qualified immutable digest in `inputs.json` and the
Dockerfile. A previously qualified local image is not a build prerequisite.
The Dockerfile verifies
the base's Rocky 8 key by SHA-256 before importing it into both the system RPM
database and a separate build-verification database. The reviewed fingerprint is
`7051C470A929F454CEBE37B715AF5DAC6D745A60`.

Only the explicit Rocky 8.10 BaseOS/AppStream repositories are enabled. DNF
resolves all required transitive dependencies with signature checks, weak
packages disabled, two retries, a 30-second transfer timeout and a 600-second
transaction bound. The six compiler packages are version-pinned, including gawk
and libsepol; `build.py` independently checks their installed versions. The base
pins the bootstrap Python/RPM/DNF/key. Repository metadata and noncompiler
transitive dependencies may change; this is a runnable construction recipe,
not a claim of byte-identical container images. Missing pinned compiler versions
fail the build rather than silently selecting newer tools. No host packages,
policy store, PAM files or services are mounted or modified.

Download the six explicit input RPMs into a new directory on the host (Python 3):

```sh
mkdir policy-inputs
python3 - <<'PYTHON'
import hashlib, json, pathlib, urllib.request
pins = json.loads(pathlib.Path('packaging/selinux/inputs.json').read_text())
urls = dict(pins['compiler_rpm_urls'], **pins['policy_rpm_urls'])
for name, digest in pins['rpms'].items():
    with urllib.request.urlopen(urls[name], timeout=30) as response:
        data = response.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != digest:
        raise SystemExit('input size/checksum mismatch: ' + name)
    with (pathlib.Path('policy-inputs') / name).open('xb') as output:
        output.write(data)
PYTHON
```

Hashes are not a substitute for signatures: `build.py` verifies every RPM using
the separate key database prepared by the Dockerfile. Compilation runs offline:

```sh
mkdir policy-result
timeout 180 docker run --rm --name qshd-policy-build --network none \
  --platform linux/amd64 --cpus 2 --memory 2g --pids-limit 256 \
  -v "$PWD:/src:ro" -v "$PWD/policy-inputs:/build/inputs:ro" \
  -v "$PWD/policy-result:/result" qshd-policy-builder \
  /usr/libexec/platform-python packaging/selinux/build.py \
  --inputs /build/inputs --keyring /build/keyring \
  --work /build/work --output /result/output \
  --epoch "$SOURCE_DATE_EPOCH" --version "$WORKSPACE_VERSION"
```

The outer timeout is a failure bound; if it expires, explicitly stop, wait for
and remove the named owned container before retrying. Source and input mounts
are read-only. The container writes only its disposable build tree and the
selected result directory.

Run inside that environment, supplying explicit absolute paths:

```sh
/usr/libexec/platform-python packaging/selinux/build.py \
  --inputs /build/inputs --keyring /build/keyring \
  --work /build/work --output /build/output \
  --epoch "$SOURCE_DATE_EPOCH" --version "$WORKSPACE_VERSION"
```

Obtain `SOURCE_DATE_EPOCH` from the source commit, and `WORKSPACE_VERSION` from
`[workspace.package]` in `Cargo.toml`. Work/output directories must not already
exist or overlap each other or the source directory. The selected RPM is freshly
extracted and its Makefile is invoked with explicit `SHAREDIR`, `NAME=targeted`,
`TYPE=mcs`, `DIRECT_INITRC=n`, explicit make/m4/gawk tool paths, `LC_ALL=C`,
`TZ=UTC`, and the sole target `qshd.pp`. A minimal environment excludes inherited
make macros (including `M4PARAM`), loader overrides and shell startup hooks.
The pinned Makefile still supplies its own required MCS macro flags. Compilation never
falls back to the host include tree. The builder validates PP v1, module format
19, name/version and the exact embedded file-context rules. A semantic source
fingerprint prevents unnoticed rule additions, including permissive/debug rules.
Intentional policy changes require review and updating that maintained contract.

Outputs are `qshd.pp`, expanded `qshd.fc`, and a source archive containing authored
source, recipe (including the environment Dockerfile), pin manifest, project license, exact signed reference-policy source
and devel RPMs, and applicable GPLv3 text. Compiler RPMs are pinned with upstream URLs but are
external build tools and are not redistributed in this policy source archive. Archive order, ownership, modes, gzip
header and mtimes are fixed. This controls the source archive format; it does not
claim that an RPM package or two independently built modules are byte-identical.
The source archive is part of any future distribution of the derived module.

## Expanded artifact licensing and publication gate

The authored `.te` calls reference-policy interfaces; the compiled `.pp` embeds
their expanded implementations. Its provenance and license cannot be described
only by the authored source's AGPL identifier. The exact source RPM spec declares
`GPLv2+`, while its main source archive's `COPYING` contains the GPL version 2
text. Preserve those upstream sources, license texts, downstream patches and
notices in the accompanying source archive without replacing their licenses.

[GNU's GPLv3 guide](https://www.gnu.org/licenses/quick-guide-gplv3.html) explains
that GPLv2-or-later permits selecting GPLv3, and
[GPLv3 section 13](https://www.gnu.org/licenses/gpl-3.0.html#section13) permits a
combined work with AGPLv3 while retaining each part's license.
[GPLv3 sections 1 and 6](https://www.gnu.org/licenses/gpl-3.0.html) govern
corresponding source and conveying object code; corresponding source includes
build-control scripts and required source inputs, not just the authored `.te`.
These are the basis for reviewing the combined artifact, not a relicensing of
the authored files.

The signed distribution source and devel RPM headers both declare `GPLv2+`.
That declaration records the upstream later-version grant; it is not inferred
from the version of the license document alone. The expanded reference-policy
parts use the permitted GPLv3 option when combined with the AGPLv3 authored
source. `artifact.json` records the combined expression
`AGPL-3.0-only AND GPL-2.0-or-later`, retaining the original upstream grant.
`GPL-3.0.txt` supplies the selected GPLv3 terms; upstream GPLv2 texts and notices
remain in the exact source RPM. Compiler binaries are not part of this combined
artifact and are not included in the source archive.

This recipe builds the module and corresponding source; RPM lifecycle
integration is separate. It does not supply an RPM spec or runtime dependency
capability names.
The native RPM's Fedora 44 targeted-policy bounds and phase-specific dependency
headers must be finalized from actual package headers before packaging or
activation is integrated.
