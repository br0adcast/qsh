# qshd SELinux policy source

The authored files and build script are licensed under AGPL-3.0-only, like qsh.
The policy source version is independently maintained at `0.3.0`; the eventual
`qshd-selinux` noarch package version follows the source workspace version.
The qualified module priority is **400**. This recipe compiles the fixed core/context pair; it does
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
`TZ=UTC`, and the two explicit targets `qshd.pp` and `qshd_contexts.pp`. A minimal environment excludes inherited
make macros (including `M4PARAM`), loader overrides and shell startup hooks.
The pinned Makefile still supplies its own required MCS macro flags. Compilation never
falls back to the host include tree. The builder validates PP v1, module format
19, MCS flags, exact role/name/version and the exact reviewed expanded file-context bytes.
The core has no canonical mappings; its generated support comments/whitespace
remain exact build inputs, not a permissive parser fallback. The require-only
companion imports the four mapped core types without adding access rules. A semantic source
fingerprint prevents unnoticed rule additions, including permissive/debug rules.
Intentional policy changes require review and updating that maintained contract.

Outputs are `qshd.pp`, `qshd_contexts.pp`, expanded `qshd_contexts.fc`, and a source archive containing authored
source (both `.te/.fc/.if` triplets), recipe (including the environment Dockerfile), pin manifest, project license, exact signed reference-policy source
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

## Fedora RPM assembly

`build-fedora-packages.sh` assembles one independent `qshd-selinux` noarch provider
and two `qshd` consumers for x86_64 and aarch64. The provider declares
`qshd-selinux-abi = 2`; consumers require that exact ABI and the provider in real
PRE, POST and PREUN phases. Generic qsh/qshd RPM and Debian variants keep their
existing behavior.

Prepare the qualified policy output and its matching source archive first, using
the source workspace version and one source epoch. The archive now includes the
23 installed helpers, fresh-pre helper, renderers, assembler, RPM spec/hooks/unit,
consumer-authority tools, pinned RPM-tool patches and build-control inputs. The
exact reference-policy source/devel RPMs and their notices remain included;
compiler RPMs, caches, local evidence and private files are excluded. The old-floor
Python 3.6 policy builder reads helper sources as bytes and does not import them.
This offer covers policy/helpers and packaging inputs; the complete Rust consumer
source continues to use the project's full source-distribution contract.

RPM assembly requires Python 3.11 or newer, Bash, rpmbuild, `/usr/bin/rpm`,
`/usr/bin/rpm2cpio`, cpio, readelf, nm and `/usr/lib/rpm/find-requires` with its RPM
dependency tools. Use the patched pinned generator from `packaging/rpm-tool` and
supply its independently reviewed binary SHA-256. There is no tool download,
compiler invocation, candidate execution or fallback to ldd-based discovery.

```sh
QSH_RPM_TOOL=/absolute/reviewed/cargo-generate-rpm \
QSH_RPM_TOOL_SHA256=REVIEWED_GENERATOR_SHA256 \
bash packaging/selinux/build-fedora-packages.sh \
  --policy-output /absolute/reviewed-policy-output \
  --expected /absolute/reviewed-27-input-hashes.json \
  --x86_64-binary /absolute/final/x86_64/qshd \
  --aarch64-binary /absolute/final/aarch64/qshd \
  --output /absolute/new-output-directory --release 1.fc44 --epoch 1800000000
```

The input binaries must already have their final strip/transforms and qualified
system-feature glibc/PAM/SELinux linkage. Assembly inspects architecture and version
nodes without executing either binary and enforces the existing glibc 2.28 floor.
Use plain absolute repository/output paths without whitespace or macro/shell
metacharacters. Caller owns immutable reviewed inputs and an exclusive output
parent. Existing
outputs refuse; failure preserves partial evidence for inspection, never retries
or cleans unknown files. Version comes from `[workspace.package]`; policy version
stays `0.3.0` and protocol/ABI versions are unchanged.

The builder stages exactly **23 code / 27 independently hashed inputs / 28 runtime
outputs**. Source/license/documentation assets are separate. It binds the fresh
incoming eight-module capsule, artifact identity, template and source offer;
upgrade pre uses installed A's helper with literal trusted incoming B. RPM
[macro-expands scriptlet files](https://github.com/rpm-software-management/rpm/blob/rpm-4.20.0-release/build/files.c#L2132),
so the exact reviewed capsule uses short base64 transport lines and a SHA-256
check before decoding; macro-looking capsule bytes never reach the spec parser.
The original renderer entry clock runs before decoding; the hash-bound suffix
executes in the same globals without renewing the fresh 30-second budget. Each
consumer gets explicit final metadata and its own architecture-specific staging,
manifest, output and receipt. Only `consumer-rpm.json` is installed; generation
receipts and `work/` stay local build evidence. Nothing transforms binary or PAM
bytes after authority generation.

Before reporting construction, the builder queries actual headers, dependency
flags and scriptlets, decodes payload leaves to stdout without extraction, and
runs the maintained final consumer RPM checker on each exact RPM/manifest/receipt.
The noarch payload includes the complete corresponding source offer and license
texts, with no runtime activation, lock, journal or cache state. `inspection.json`
records the exact three completed artifacts; it is a construction receipt, not
installed-policy qualification or source-origin authentication.

## Maintenance and managed start

The supported contract is Fedora 44 live Enforcing targeted policy with ABI 2,
activation schema 2, canonical PAM and the fixed pair/type/path profile. Before
install, upgrade or erase, the administrator must stop and drain the system
service and manual daemons, and exclude concurrent starts and privileged writers
through maintenance. Hooks never force stop, kill, enable, start or restart the
service. Only after final consumer erase admission succeeds, while the unit file
still exists, consumer preun runs `systemctl --no-reload disable qshd.service`
without `--now`; upgrades and non-final erase leave enablement unchanged. A
failed disable fails the erase after PENDING publication, keeping the package
for a retried erase. The consumer system unit checks current readiness through
`managed-prestart` before ExecStart; its 460-second outer startup allowance does
not renew helper deadlines or exclude maintenance begun afterward.

Fresh provider pre uses a reviewed incoming capsule before installed helpers
exist. Consumer pre admits canonical installed PAM or the separately allowed
fresh absence before payload replacement. Custom/legacy PAM, `.rpmnew`/`.rpmsave`,
legacy schema 1, mixed/missing pairs and unsupported ABI changes refuse. There is
no implicit migration or administrative repair. ABI 2 artifact-changing A→B
upgrades use distinct old/incoming authority; old-package positive-count preun
hooks do not erase the new pair.

Successful final provider erase restores the supported defaults and retires the
exact PENDING slot to absence, allowing a separately admitted ordinary pristine
reinstall. Partial failure or uncertain publication may leave PENDING or changed
state and must refuse readiness. Historical basis and a parsed COMPLETE record
alone do not prove current policy state or authorize repair.

Actual finished three-RPM construction/header/payload review and Fedora Enforcing
x86_64/aarch64 installed lifecycle qualification remain pending. Source, staging
and synthetic-header checks do not establish policy load/HLL equality, package
transaction ordering, managed connectivity, erase/default restoration or reinstall
acceptance. Those require the separately gated real artifact and native lifecycle
checks; this recipe does not close that acceptance work.
