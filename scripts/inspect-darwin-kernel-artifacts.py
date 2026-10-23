#!/usr/bin/env python3
"""Bounded metadata inventory; image availability is not source qualification."""

import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


CANDIDATES = (
    "/System/Library/Kernels/kernel",
    "/System/Library/KernelCollections/BootKernelExtensions.kc",
)
TOOL_SECONDS = 3
OUTPUT_LIMIT = 8192
UUID = r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}"
STOP_SIGNAL = None


def interrupted(signum, _frame):
    global STOP_SIGNAL
    if STOP_SIGNAL is None:
        STOP_SIGNAL = signum


def command(argv, pass_fds=()):
    """Own one installed metadata tool, bounding capture and waiting after kill."""
    if STOP_SIGNAL is not None:
        return "interrupted", ""
    try:
        child = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, pass_fds=pass_fds,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HISTFILE": "/dev/null"},
        )
    except OSError:
        return "unavailable", ""
    output = bytearray()
    reason = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + TOOL_SECONDS
            while selector.get_map():
                if STOP_SIGNAL is not None:
                    reason = "interrupted"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "timeout"
                    break
                for key, _ in selector.select(remaining):
                    data = os.read(key.fd, min(4096, OUTPUT_LIMIT + 1 - len(output)))
                    if not data:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(data)
                        if len(output) > OUTPUT_LIMIT:
                            reason = "output_limit"
                            break
                if reason:
                    break
            if STOP_SIGNAL is not None:
                reason = "interrupted"
            if reason is None:
                try:
                    child.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    reason = "timeout"
    finally:
        # Also preserve custody on selector/read exceptions or interruption.
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
    if STOP_SIGNAL is not None:
        return "interrupted", ""
    if reason:
        return reason, ""
    if child.returncode != 0:
        return "tool_error", ""
    try:
        return "ok", output.decode("ascii")
    except UnicodeDecodeError:
        return "malformed", ""


def installed_tool(name):
    status, value = command(["/usr/bin/xcrun", "--no-cache", "--find", name])
    value = value.strip()
    if status != "ok":
        return status, None
    if not value.startswith("/") or "\n" in value:
        return "malformed", None
    return "ok", value


def header_kind(text):
    # otool -hv prints column names followed by symbolic Mach-O fields.
    # Accept only one thin image; FAT/multi-header ambiguity stays unknown.
    rows = [line.split() for line in text.splitlines()]
    if "fat" in text.lower() or "(architecture " in text:
        return "unsupported"
    records = [row for row in rows if row and row[0] in ("MH_MAGIC", "MH_MAGIC_64")]
    if len(records) != 1:
        return "unsupported"
    row = records[0]
    if len(row) < 5:
        return "malformed"
    return {"EXECUTE": "standalone_execute", "FILESET": "fileset"}.get(row[4], "unsupported")


def inventory(path, tools, running_uuid, architecture):
    result = {"candidate": path, "status": "unknown", "type": "unknown",
              "readable": False, "uuid_match": "unknown"}
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return dict(result, status="absent")
    except PermissionError:
        return dict(result, status="denied")
    except OSError:
        return dict(result, status="stat_error")
    if stat.S_ISLNK(info.st_mode):
        return dict(result, status="symlink_skipped", type="symlink")
    if not stat.S_ISREG(info.st_mode):
        return dict(result, status="nonregular_skipped", type="other")
    result["type"] = "regular"
    result["bytes"] = info.st_size
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except PermissionError:
        return dict(result, status="denied")
    except OSError:
        return dict(result, status="open_error")
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            return dict(result, status="changed_or_nonregular")
        result["readable"] = True
        if not tools["otool"] or not tools["dwarfdump"]:
            return dict(result, status="metadata_tool_unavailable")
        # Retained no-follow fd prevents a pathname replacement/symlink race.
        reference = "/dev/fd/" + str(fd)
        status, header = command([tools["otool"], "-hv", reference], (fd,))
        if status != "ok":
            return dict(result, status="header_" + status)
        kind = header_kind(header)
        result["format"] = kind
        if kind not in ("standalone_execute", "fileset"):
            return dict(result, status="header_" + kind)
        status, text = command([tools["dwarfdump"], "--uuid", reference], (fd,))
        if status != "ok":
            return dict(result, status="uuid_" + status)
        records = []
        for line in text.splitlines():
            match = re.fullmatch(r"UUID: (" + UUID + r") \(([^() ]+)\) .+", line)
            if not match:
                return dict(result, status="uuid_malformed")
            records.append((match[1].upper(), match[2]))
        if kind == "fileset":
            # Never interpret an outer collection UUID as its kernel member.
            result["outer_uuids"] = [{"uuid": u, "architecture": a} for u, a in records]
            return dict(result, status="embedded_kernel_unidentified")
        if len(records) != 1:
            return dict(result, status="uuid_ambiguous_or_missing")
        image_uuid, image_arch = records[0]
        result.update(uuid=image_uuid, architecture=image_arch)
        if image_arch != architecture:
            return dict(result, status="architecture_unqualified")
        if running_uuid is None:
            return dict(result, status="running_uuid_unavailable")
        return dict(result, status="standalone_metadata", uuid_match=("match" if image_uuid == running_uuid else "mismatch"))
    finally:
        os.close(fd)


def main():
    if platform.system() != "Darwin":
        print("Darwin kernel artifact inventory requires macOS", file=sys.stderr)
        return 1
    # Never raise from a handler: Popen acquisition and final wait must settle.
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    status, text = command(["/usr/sbin/sysctl", "-n", "kern.uuid"])
    if STOP_SIGNAL is not None:
        return 128 + STOP_SIGNAL
    text = text.strip()
    running_uuid = text.upper() if status == "ok" and re.fullmatch(UUID, text) else None
    uuid_status = "malformed" if status == "ok" and running_uuid is None else status
    tools = {}
    tool_status = {}
    for name in ("otool", "dwarfdump"):
        tool_status[name], tools[name] = installed_tool(name)
        if STOP_SIGNAL is not None:
            return 128 + STOP_SIGNAL
    print(json.dumps({"inventory": "metadata_only", "kern_uuid": running_uuid,
                      "kern_uuid_status": uuid_status, "tools": tool_status,
                      "source_correspondence": "unqualified"}, sort_keys=True))
    matched = False
    for path in CANDIDATES:
        if STOP_SIGNAL is not None:
            return 128 + STOP_SIGNAL
        try:
            row = inventory(path, tools, running_uuid, platform.machine())
        except (OSError, ValueError):
            row = {"candidate": path, "status": "inspection_error", "uuid_match": "unknown"}
        if STOP_SIGNAL is not None:
            return 128 + STOP_SIGNAL
        print(json.dumps(row, sort_keys=True))
        matched |= row.get("uuid_match") == "match"
    print("usable_artifact=" + ("standalone_uuid_match_only" if matched else "not_established"))
    print("capacity_qualification=unqualified")
    return 128 + STOP_SIGNAL if STOP_SIGNAL is not None else 0


if __name__ == "__main__":
    sys.exit(main())
