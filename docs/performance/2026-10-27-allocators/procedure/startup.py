"""Startup cost of `qsh --help` and `qshd --help` per build, inside a PTY.

Each command runs under `perf stat -r N` with a private HOME and XDG
directories and HISTFILE=/dev/null; only PATH is inherited. perf needs root
here, so the command itself runs as the invoking user through `setpriv`;
`/bin/true` under the same wrapper is measured as the baseline to subtract.
Prints one JSON object per build and binary.

    startup.py REPEATS BUILD_DIRECTORY...
"""
import json, os, pty, subprocess, sys, tempfile

def run(argv, env):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(argv[0], argv, env)
    out = b""
    while True:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    _, status = os.waitpid(pid, 0)
    return status, out

builds, repeats = sys.argv[2:], int(sys.argv[1])
user = ["setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups", "--"]
targets = [("baseline", "true", ["/bin/true"])]
for build in builds:
    for binary in ("qsh", "qshd"):
        targets.append((os.path.basename(build.rstrip("/")), binary, [f"{build}/{binary}", "--help"]))
for name, binary, command in targets:
    if True:
        with tempfile.TemporaryDirectory(prefix="startup.") as home:
            env = {"PATH": os.environ["PATH"], "HOME": home, "HISTFILE": "/dev/null",
                   "XDG_CONFIG_HOME": f"{home}/.config", "XDG_CACHE_HOME": f"{home}/.cache",
                   "XDG_STATE_HOME": f"{home}/.state", "XDG_DATA_HOME": f"{home}/.data",
                   "XDG_RUNTIME_DIR": f"{home}/run", "TERM": "xterm-256color"}
            os.makedirs(env["XDG_RUNTIME_DIR"], mode=0o700)
            report = f"{home}/perf.csv"
            argv = ["sudo", "-n", "perf", "stat", "-x", ",", "-o", report, "-r", str(repeats),
                    "-e", "instructions:u,task-clock,page-faults", "--", *user, *command]
            status, out = run(argv, env)
            fields = {}
            text = subprocess.run(["sudo", "-n", "cat", report], check=True, capture_output=True, text=True).stdout
            subprocess.run(["sudo", "-n", "rm", "-f", report], check=True)
            for line in text.splitlines():
                parts = line.strip().split(",")
                if len(parts) > 3 and not line.startswith("#"):
                    fields[parts[2]] = {"value": float(parts[0]), "unit": parts[1], "variance_percent": parts[3]}
            print(json.dumps({"build": name, "binary": binary,
                              "repeats": repeats, "exit_status": status, "perf": fields}))
