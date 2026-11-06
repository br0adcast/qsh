#!/usr/bin/env python3
"""Closed, source-bound build/owner for the standalone PTY EOF contrasts.

Raw compiler/test/descriptor records stay in private runner files. Only the
closed result schema is public. This tool never terminates an owned controller:
a pending consuming wait retains this process and its runner lease.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys
import tempfile
import time
import tomllib

SELECTOR = "darwin_process_scope::keeper_pty_eof_tests::native::standalone_pty_eof_contrasts"
PREFIX = "darwin_process_scope::keeper_pty_eof_tests::wire::"
PORTABLE = sorted(PREFIX + name for name in (
    "evidence_tests::actual_refusal_and_wrong_direction_cannot_complete_setup",
    "evidence_tests::negative_ctty_and_alias_close_identity_are_refused",
    "evidence_tests::real_ctty_close_and_ready_gate_requires_matched_actual_open",
    "evidence_tests::typed_refusal_is_recorded_before_actual_semantic_rejection",
    "tests::actual_codec_roundtrip_and_refusal_preserves_errno",
    "tests::bindings_replay_and_corrupt_receipts_are_rejected",
    "tests::finite_inventory_overflow_is_a_real_receiver_refusal",
))
TARGETS = {"aarch64-apple-darwin": "arm64", "x86_64-apple-darwin": "x86_64"}
LIBC_CHECKSUM = "3eaf3ede3fee6db1a4c2ee091bf8a8b4dccdc6d17f656fb07896ee72867612f2"
LABELS = ((1, True, False), (2, True, False), (3, True, False), (4, True, False),
          (2, False, False), (3, False, False), (2, False, True), (3, False, True))


def route(event, mode):
    if event != "workflow_dispatch":
        return "qualification"
    if mode in ("", "qualification"):
        return "qualification"
    if mode not in ("pty-eof-build", "pty-eof-control"):
        raise ValueError("mode")
    return mode


def launch_native(mode):
    if mode not in ("pty-eof-build", "pty-eof-control"):
        raise ValueError("diagnostic mode")
    return mode == "pty-eof-control"


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def bounded(path, limit):
    with Path(path).open("rb") as f:
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ValueError("capture ceiling")
    return data


def admit_list(text, expected):
    rows = re.findall(r"^(.+): test$", text, re.M)
    if sorted(rows) != sorted(expected) or len(rows) != len(set(rows)):
        raise ValueError("test selection")
    if not re.search(rf"^{len(expected)} tests?, 0 benchmarks$", text, re.M):
        raise ValueError("test selection count")


def admit_results(text, expected):
    passed = re.findall(r"^test (\S+) \.\.\. ok$", text, re.M)
    if sorted(passed) != sorted(expected) or len(passed) != len(set(passed)):
        raise ValueError("executed test count")
    if not re.search(rf"^test result: ok\. {len(expected)} passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out;", text, re.M):
        raise ValueError("test result")


def module_body(text, marker):
    start = text.index(marker) + len(marker)
    depth = 1
    # Reviewed bodies contain balanced literal braces; compare exact deindented
    # source between known module boundaries rather than interpreting Rust.
    for end in range(start, len(text)):
        depth += (text[end] == "{") - (text[end] == "}")
        if depth == 0:
            import textwrap
            return textwrap.dedent(text[start:end]).strip() + "\n"
    raise ValueError("module boundary")


def verify_copies(root):
    source = (root / "qshd/src/darwin_process_scope/keeper_pty_eof_tests.rs").read_text()
    fixture = root / "qshd/tests/fixtures/pty_eof"
    for name, marker in (("wire.rs", "mod wire {"), ("ipc.rs", "mod ipc {")):
        body = module_body(source, marker)
        actual = (fixture / name).read_text()
        # The only permitted copy difference is the import's module depth.
        body = body.replace("super::super::wire", "crate::wire")
        if body != actual:
            raise ValueError("fixture copy")


def select_artifacts(records, root, target_dir, target=None):
    if target not in TARGETS:
        raise ValueError("artifact target")
    target_deps = target_dir / target / "debug/deps"
    artifacts = [r for r in records if r.get("reason") == "compiler-artifact"]
    tests = [r for r in artifacts if r.get("target", {}).get("name") == "qshd"
             and r.get("target", {}).get("kind") == ["lib"] and r.get("executable")
             and r.get("profile", {}).get("test") is True]
    libs = [r for r in artifacts if r.get("target", {}).get("name") == "libc"
            and "lib" in r.get("target", {}).get("kind", [])
            and re.search(r"(?:libc@0\.2\.189|libc 0\.2\.189)", r.get("package_id", ""))
            and any(Path(p).resolve().parent == target_deps for p in r.get("filenames", []) if p.endswith(".rlib"))]
    if len(tests) != 1 or len(libs) != 1:
        raise ValueError("artifact ambiguity")
    test, lib = tests[0], libs[0]
    if set(test.get("features", [])) != {"test-build-labels", "test-darwin-keeper"}:
        raise ValueError("test features")
    if Path(test["manifest_path"]).resolve() != root / "qshd/Cargo.toml" or Path(test["target"]["src_path"]).resolve() != root / "qshd/src/lib.rs":
        raise ValueError("test source")
    rlibs = [Path(p).resolve() for p in lib.get("filenames", []) if p.endswith(".rlib")]
    if len(rlibs) != 1:
        raise ValueError("libc artifact")
    image = Path(test["executable"]).resolve()
    for p in (image, rlibs[0]):
        if p.parent != target_deps or not p.is_file():
            raise ValueError("artifact placement")
    if not os.access(image, os.X_OK):
        raise ValueError("test executable")
    libroot = Path(lib["manifest_path"]).resolve().parent
    checksum = json.loads(bounded(libroot / ".cargo-checksum.json", 1024 * 1024))
    if checksum.get("package") != LIBC_CHECKSUM:
        raise ValueError("locked libc checksum")
    return image, rlibs[0]


SIZE=128
COMMANDS={4,6,8}
class Admission:
    def __init__(self,nonce,arm,*,control_fd,slave_fd,expected_pid,cap=4096):
        self.nonce=nonce;self.arm=arm;self.next=0;self.inventory=0;self.cap=cap;self.records=[]
        if expected_pid<=0:raise ValueError('owned helper PID')
        self.expected_pid=expected_pid;self.control=control_fd;self.slave=slave_fd;self.phase=0;self.entries={};self.enum=False
        self.base={};self.session=False;self.controlling=False;self.foreground=False
        self.ctty=None;self.closed=False;self.ready=False;self.alias=None;self.slave_closed=False;self.alias_closed=False
    @staticmethod
    def identity(b):return struct.unpack_from('<QQQI',b,36)
    def command(self,op):
        if op==4 and self.phase==2:self.phase=3;return
        if op==6 and self.phase==4:self.phase=5;return
        if op==8 and self.phase==6:self.phase=7;return
        raise ValueError('command transition')
    def accept(self,b):
        if len(b)!=SIZE or b[:4]!=b'PEF1' or b[23] or any(b[76:]):raise ValueError('framing')
        op=b[21]
        if op not in range(1,18) or op in COMMANDS or b[22]!=2:raise ValueError('operation/role')
        if b[4:20]!=self.nonce or b[20]!=self.arm or struct.unpack_from('<I',b,24)[0]!=self.next:raise ValueError('binding/sequence')
        self.next+=1;self.records.append(bytes(b)) # typed refusal is retained before semantic rejection
        fd,errno=struct.unpack_from('<ii',b,28);identity=self.identity(b)
        if struct.unpack_from('<i',b,64)[0]!=self.expected_pid:raise ValueError('helper process identity')
        if errno or op==10:raise ValueError('actual refusal')
        if op==1:
            if self.inventory==self.cap:raise ValueError('inventory cap')
            self.inventory+=1
        if self.phase>=2 and struct.unpack_from('<iii',b,64)!=(self.expected_pid,)*3:raise ValueError('session identity drift')
        if self.phase in (0,3,5):
            if op==5 and self.phase==3 and not self.slave_closed and (fd,identity)==(self.slave,self.base[self.slave]):
                self.slave_closed=True;return op
            if op==7 and self.phase==5 and not self.alias_closed and (fd,identity)==self.alias:
                self.alias_closed=True;return op
            can_scan=self.phase==0 or self.phase==3 and self.slave_closed or self.phase==5 and self.alias_closed
            if not can_scan:raise ValueError('missing actual close')
            if op==17 and not self.enum and fd>=0 and identity[3]&0o170000==0o040000:self.enum=True;return op
            if op==1 and self.enum and fd>=0 and fd not in self.entries:
                if self.phase and fd not in (self.control, self.alias[0] if self.phase==3 and self.alias else -1):raise ValueError('unexpected post-close fd')
                self.entries[fd]=identity;return op
            if op==7 and self.phase==0 and self.entries.get(fd)==identity and fd not in (self.control,self.slave):
                del self.entries[fd];return op
            if op==2 and self.enum:
                expected={self.control,self.slave} if self.phase==0 else {self.control}|({self.alias[0]} if self.phase==3 and self.alias else set())
                if set(self.entries)!=expected:raise ValueError('incomplete inventory')
                if self.phase==0:
                    if self.entries[self.control][3]&0o170000!=0o140000 or self.entries[self.slave][3]&0o170000!=0o020000:raise ValueError('handoff fd type')
                    self.base=dict(self.entries);self.phase=1
                else:
                    if self.entries[self.control]!=self.base[self.control]:raise ValueError('IPC identity changed')
                    if self.phase==3 and self.alias and self.entries[self.alias[0]]!=self.alias[1]:raise ValueError('alias identity changed')
                    self.phase=4 if self.phase==3 and self.alias else 6
                self.entries={};self.enum=False;return op
            raise ValueError('inventory transition')
        if self.phase==1:
            if op in (15,16,11,12,13,3) and struct.unpack_from('<iii',b,64)!=(self.expected_pid,)*3:raise ValueError('session identity')
            if op==14 and not self.session and (fd,identity)==(self.slave,self.base[self.slave]):
                pid,sid,group=struct.unpack_from('<iii',b,64)
                if pid<=0 or sid!=pid or group!=pid:raise ValueError('session')
                self.session=True;return op
            if op==15 and self.arm>=2 and self.session and not self.controlling and (fd,identity)==(self.slave,self.base[self.slave]) and struct.unpack_from('<iii',b,64)==(self.expected_pid,)*3:self.controlling=True;return op
            if op==16 and self.controlling and not self.foreground and (fd,identity)==(self.slave,self.base[self.slave]) and struct.unpack_from('<iii',b,64)==(self.expected_pid,)*3:self.foreground=True;return op
            setup=self.session and (self.arm==1 or self.controlling and self.foreground)
            if op==11 and self.arm==3 and setup and self.ctty is None and fd>=0 and identity[3]&0o170000==0o020000:self.ctty=(fd,identity);return op
            if op==12 and self.ctty==(fd,identity) and not self.closed:self.closed=True;return op
            if op==13 and self.arm==4 and setup and self.alias is None and fd>=3 and fd not in (self.control,self.slave) and identity==self.base[self.slave]:self.alias=(fd,identity);return op
            if op==3 and setup and (self.arm!=3 or self.closed) and (self.arm!=4 or self.alias is not None) and (fd,identity)==(self.slave,self.base[self.slave]):self.ready=True;self.phase=2;return op
            raise ValueError('setup transition')
        if op==9 and self.phase==7:self.phase=8;return op
        raise ValueError('unexpected receipt')


BINDING = re.compile(r"arm_binding arm=([1-4]) direct=(true|false) normalized=(true|false) pid=([1-9][0-9]*) nonce=([0-9a-f]{32}) control=([0-9]+) slave=([0-9]+) dev=([0-9]+) rdev=([0-9]+) ino=([0-9]+) mode=([0-9]+)")
CONTRAST = re.compile(r"contrast arm=([1-4]) direct=(true|false) normalized=(true|false) before=(zero|would_block|eio|error_without_code|other_error|unavailable) after=(zero|would_block|eio|error_without_code|other_error|none|unavailable) post=(zero|would_block|eio|error_without_code|other_error|unavailable) normal_wait=true fallback=false pending=false bundle_drop_returned=true agreement=(true|false) natural=(true|false)")
WAIT_ENTRY = re.compile(r"consuming_wait_enter pid=([1-9][0-9]*) arm=([1-4]) direct=(true|false) normalized=(true|false) released=true observed_status=none acceptance_expired=false full_bundle_retained=true")
COMPLETE = re.compile(r"campaign_complete attempted=([0-8]) settled=([0-8]) disagreements=([0-8]) failed=(true|false) current_pending=false")


def admit_capture(data):
    """Return only closed fields; raw identities never cross this boundary."""
    if len(data) > 3 * 1024 * 1024:
        raise ValueError("capture ceiling")
    lines = data.decode("ascii").splitlines()
    results, admission, parent, command_sequence, frames, complete = [], None, None, 0, 0, None
    begun = parent_dropped = settled = wait_entered = False
    settlement_agreement = None
    for line in lines:
        if complete is not None:
            raise ValueError("records after completion")
        binding = BINDING.fullmatch(line)
        contrast = CONTRAST.fullmatch(line)
        if binding:
            if admission is not None or len(results) >= 8:
                raise ValueError("arm ownership order")
            arm, direct, normalized, pid, nonce, control, slave, dev, rdev, ino, mode = binding.groups()
            label = (int(arm), direct == "true", normalized == "true")
            if label != LABELS[len(results)]:
                raise ValueError("matrix order")
            admission = Admission(bytes.fromhex(nonce), int(arm), control_fd=int(control), slave_fd=int(slave), expected_pid=int(pid))
            parent = tuple(map(int, (dev, rdev, ino, mode)))
            command_sequence = 0
            begun = parent_dropped = settled = wait_entered = False
        elif line.startswith(("helper_receipt=", "command_attempt=")):
            if admission is None or not begun or settled:
                raise ValueError("unowned frame")
            frames += 1
            if frames > 8192:
                raise ValueError("record ceiling")
            kind, encoded = line.split("=", 1)
            if not re.fullmatch(r"[0-9a-f]{256}", encoded):
                raise ValueError("frame encoding")
            b = bytes.fromhex(encoded)
            if kind == "helper_receipt":
                op = admission.accept(b)
                if op == 3 and Admission.identity(b) != parent:
                    raise ValueError("parent Ready identity")
            else:
                if b[:4] != b"PEF1" or b[4:20] != admission.nonce or b[20] != admission.arm or b[21] not in COMMANDS or b[22] != 1 or b[23] or any(b[76:]) or struct.unpack_from("<I", b, 24)[0] != command_sequence:
                    raise ValueError("command binding")
                command_sequence += 1
                if b[21] == 4 and not parent_dropped:
                    raise ValueError("parent slave custody")
                admission.command(b[21])
        elif WAIT_ENTRY.fullmatch(line):
            entry = WAIT_ENTRY.fullmatch(line)
            pid, arm, direct, normalized = entry.groups()
            if admission is None or admission.phase != 8 or settled or wait_entered or not parent_dropped:
                raise ValueError("consuming wait entry order")
            if int(pid) != admission.expected_pid or (int(arm), direct == "true", normalized == "true") != LABELS[len(results)]:
                raise ValueError("consuming wait owner")
            # Entry supplies no status/wait proof. The actual settlement record,
            # full eight-arm footer and consuming controller wait remain required.
            wait_entered = True
        elif contrast:
            if admission is None or admission.phase != 8 or not settled or not parent_dropped:
                raise ValueError("incomplete actual receipt proof")
            arm, direct, normalized, before, after, post, agreement, natural = contrast.groups()
            label = (int(arm), direct == "true", normalized == "true")
            if label != LABELS[len(results)] or natural != "true" or "unavailable" in (before, after, post):
                raise ValueError("unsafe or mismatched settlement")
            expected_agreement = ((before in ("zero", "eio")) if label[0] in (1, 2) else before == "would_block" and (label[0] != 4 or after in ("zero", "eio")))
            if (agreement == "true") != expected_agreement or agreement != settlement_agreement:
                raise ValueError("prediction record")
            if (label[0] == 4) != (after != "none"):
                raise ValueError("alias observation")
            results.append(dict(index=len(results) + 1, arm=label[0], direct=label[1], normalized=label[2], before=before, after=after, post_exit=post, normal_wait=True, agreement=agreement == "true"))
            admission = None
        elif COMPLETE.fullmatch(line):
            if complete is not None:
                raise ValueError("duplicate completion")
            complete = COMPLETE.fullmatch(line).groups()
        elif line.startswith("arm_begin "):
            if admission is None or begun:
                raise ValueError("arm begin order")
            begun = True
        elif line == "parent_slave_drop_returned syscall_close_result=not_exposed":
            if admission is None or admission.phase != 2 or parent_dropped:
                raise ValueError("parent close order")
            parent_dropped = True
        elif line.startswith("arm_settled "):
            if admission is None or admission.phase != 8 or settled or not line.endswith(" normal_wait=true fallback=false pending=false bundle_drop_returned=true agreement=true natural=true") and not line.endswith(" normal_wait=true fallback=false pending=false bundle_drop_returned=true agreement=false natural=true"):
                raise ValueError("settlement publication")
            settled = True
            settlement_agreement = "false" if line.endswith("agreement=false natural=true") else "true"
        else:
            # Includes pending, fallback, refusal, setup failure and cleanup error.
            raise ValueError("unsettled or unknown record")
    disagreements = sum(not r["agreement"] for r in results)
    if admission is not None or len(results) != 8 or complete != ("8", "8", str(disagreements), "true" if disagreements else "false"):
        raise ValueError("campaign completion")
    return results


class Owner:
    def __init__(self, root, runtime, env):
        self.root, self.runtime, self.env = root, runtime, env
        self.serial = 0

    def command(self, argv, *, limit=32 * 1024 * 1024, success=True):
        """Wait the actual owned process; no timeout kill/detach path."""
        self.serial += 1
        path = self.runtime / ("command-%03d" % self.serial)
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600), "wb") as output:
            process = subprocess.Popen(argv, cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.STDOUT)
            interrupted = False
            while True:
                try:
                    status = process.wait()
                    break
                except BaseException:
                    # Retain the process and its output file until an actual
                    # consuming wait. Infrastructure cancellation is no receipt.
                    interrupted = True
                    time.sleep(1)
            if interrupted:
                raise ValueError("interrupted controller custody")
        data = bounded(path, limit)
        if success and status != 0:
            raise ValueError("command failed")
        return status, data


def main():
    # This interface supplies no caller command, selector, source or phase string.
    stage = "preflight"
    summary = dict(schema=1, kind="pty-eof-control", status="refused")
    try:
        if len(sys.argv) != 3:
            raise ValueError("arguments")
        mode, target = sys.argv[1:]
        if target not in TARGETS or route(os.environ.get("GITHUB_EVENT_NAME"), os.environ.get("PTY_EOF_MODE", "")) != mode:
            raise ValueError("dispatch binding")
        native = launch_native(mode)
        if sys.platform != "darwin" or platform.machine() != TARGETS[target]:
            raise ValueError("native host")
        root = Path(__file__).resolve().parents[1]
        verify_copies(root)
        sha = os.environ.get("GITHUB_SHA", "")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("source SHA")
        base = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        # Preserve private captures until infrastructure teardown; never upload.
        runtime = Path(tempfile.mkdtemp(prefix="pty-eof-", dir=base))
        runtime.chmod(0o700)
        env = os.environ.copy()
        env.update(CARGO_HOME=os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
                   RUSTUP_HOME=os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")), HISTFILE="/dev/null")
        for key, leaf in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"), ("TMPDIR", "tmp")):
            p = runtime / leaf
            p.mkdir(mode=0o700)
            env[key] = str(p)
        target_dir = runtime / "target"
        env["CARGO_TARGET_DIR"] = str(target_dir)
        if env.get("CARGO_ENCODED_RUSTFLAGS"):
            raise ValueError("encoded flags")
        flags = ["--remap-path-prefix=" + str(root) + "=/qsh", "--remap-path-prefix=" + env["CARGO_HOME"] + "=/cargo", "--remap-path-prefix=" + str(base) + "=/build", "-C", "link-arg=-Wl,-oso_prefix," + str(root) + "/"]
        env["RUSTFLAGS"] = " ".join(flags)
        env.update(AWS_LC_SYS_USE_SYSTEM="0", AWS_LC_SYS_CFLAGS=" ".join("-ffile-prefix-map=" + a + "=" + b for a, b in ((str(root), "/qsh"), (env["CARGO_HOME"], "/cargo"), (str(base), "/build"))))
        owner = Owner(root, runtime, env)
        _, checkout = owner.command(["git", "rev-parse", "HEAD"], limit=128)
        if checkout.decode().strip() != sha:
            raise ValueError("checkout")
        lock = tomllib.loads(bounded(root / "Cargo.lock", 1024 * 1024).decode())
        libc_locked = [p for p in lock["package"] if p["name"] == "libc"]
        if len(libc_locked) != 1 or libc_locked[0]["version"] != "0.2.189" or libc_locked[0]["checksum"] != LIBC_CHECKSUM:
            raise ValueError("locked libc")
        summary.update(mode=mode, target=target, source_sha=sha, cargo_lock_sha256=digest(root / "Cargo.lock"))
        stage = "provenance"
        _, version = owner.command(["rustc", "-vV"], limit=65536)
        if not re.search(rb"^host: " + target.encode() + rb"$", version, re.M):
            raise ValueError("compiler host")
        _, compiler = owner.command(["rustup", "which", "rustc"], limit=65536)
        compiler_image = Path(compiler.decode().strip()).resolve(strict=True)
        provenance = {"rustc_vv_sha256": hashlib.sha256(version).hexdigest(), "rustc_image_sha256": digest(compiler_image)}
        for name, argv in (("kernel", ["/usr/sbin/sysctl", "-n", "kern.version"]), ("osrelease", ["/usr/sbin/sysctl", "-n", "kern.osrelease"]), ("os_build", ["/usr/sbin/sysctl", "-n", "kern.osversion"]), ("sdk", ["/usr/bin/xcrun", "--show-sdk-version"])):
            _, data = owner.command(argv, limit=65536)
            provenance[name + "_sha256"] = hashlib.sha256(data).hexdigest()
        for name in ("ImageOS", "ImageVersion"):
            provenance[name + "_sha256"] = hashlib.sha256(os.environ.get(name, "").encode()).hexdigest()
        provenance["source_files"] = {p: digest(root / p) for p in (
            "qshd/src/darwin_process_scope/keeper_pty_eof_tests.rs", "qshd/src/darwin_process_scope/keeper_pty.rs", "qshd/src/darwin_process_scope/mod.rs", "qshd/tests/fixtures/pty_eof/helper.rs", "qshd/tests/fixtures/pty_eof/wire.rs", "qshd/tests/fixtures/pty_eof/ipc.rs", "scripts/qualify-pty-eof-control.py")}
        crypto_manifest = Path(env["OPENSSL_DIR"]) / "manifest.json"
        crypto = json.loads(bounded(crypto_manifest, 1024 * 1024))
        if crypto["identity"]["target"] != target:
            raise ValueError("qualified crypto target")
        provenance["openssl_manifest_sha256"] = digest(crypto_manifest)
        summary["bindings"] = provenance
        stage = "build"
        owner.command(["cargo", "clippy", "--locked", "-p", "qshd", "--lib", "--bin", "qshd", "--features", "test-darwin-keeper", "--target", target, "--", "-D", "warnings"])
        _, messages = owner.command(["cargo", "test", "--locked", "-p", "qshd", "--lib", "--features", "test-darwin-keeper", "--target", target, "--no-run", "--message-format=json"])
        records = [json.loads(line) for line in messages.decode().splitlines() if line.startswith("{")]
        image, libc = select_artifacts(records, root, target_dir, target)
        helper = runtime / "helper"
        owner.command(["rustc", "--edition=2024", "--target", target, str(root / "qshd/tests/fixtures/pty_eof/helper.rs"), "--extern", "libc=" + str(libc), "-L", "dependency=" + str(libc.parent), *flags, "-o", str(helper)])
        helper.chmod(0o500)
        summary["artifacts"] = {"test_sha256": digest(image), "helper_sha256": digest(helper), "libc_rlib_sha256": digest(libc), "libc_package_sha256": LIBC_CHECKSUM}
        stage = "portable"
        _, listing = owner.command([str(image), PREFIX, "--list"], limit=1024 * 1024)
        admit_list(listing.decode(), PORTABLE)
        _, results = owner.command([str(image), PREFIX, "--nocapture", "--test-threads=1"], limit=1024 * 1024)
        admit_results(results.decode(), PORTABLE)
        summary["portable_passed"] = 7
        # Exact ignored selection listing executes no test body in either mode.
        _, listing = owner.command([str(image), "--ignored", "--exact", SELECTOR, "--list"], limit=1024 * 1024)
        admit_list(listing.decode(), [SELECTOR])
        if not native:
            summary.update(status="build_passed", native_executed=0)
        else:
            stage = "native"
            if digest(image) != summary["artifacts"]["test_sha256"] or digest(helper) != summary["artifacts"]["helper_sha256"]:
                raise ValueError("image changed")
            capture = runtime / "typed-capture"
            env.update(QSH_PTY_EOF_HELPER=str(helper), QSH_PTY_EOF_HELPER_SHA256=digest(helper), QSH_PTY_EOF_CAPTURE=str(capture))
            status, output = owner.command([str(image), "--ignored", "--exact", SELECTOR, "--nocapture", "--test-threads=1"], limit=1024 * 1024, success=False)
            # Owner.command has completed the consuming controller wait here.
            contrasts = admit_capture(bounded(capture, 3 * 1024 * 1024))
            summary.update(contrasts=contrasts, controller_waited=True, native_executed=1)
            disagreements = sum(not r["agreement"] for r in contrasts)
            if disagreements:
                if status == 0 or not re.search(r"^running 1 test$", output.decode(), re.M) or not re.search(r"^test result: FAILED\. 0 passed; 1 failed; 0 ignored; 0 measured;", output.decode(), re.M) or len(re.findall(r"^test " + re.escape(SELECTOR) + r" \.\.\.", output.decode(), re.M)) != 1:
                    raise ValueError("failed prediction execution")
                summary.update(status="settled_disagreement", disagreements=disagreements)
            else:
                if status != 0:
                    raise ValueError("controller failed")
                admit_results(output.decode(), [SELECTOR])
                summary.update(status="control_passed", disagreements=0)
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0 if summary["status"] in ("build_passed", "control_passed") else 1
    except Exception:
        # Do not expose exception messages, raw compiler diagnostics or paths.
        summary.update(status="refused", stage=stage)
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
