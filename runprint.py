"""Run a Python script inside a local Bubblewrap sandbox."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import tempfile


OUTPUT_LIMIT = 64 * 1024
WORKSPACE_SIZE = 16 * 1024 * 1024
SCRIPT_LIMIT = 1024 * 1024
PYTHON_EXEC = re.compile(r'^(\d+)\s+execve\("/usr/bin/python3", .*\)\s+= 0$')
WRITE_OPEN = re.compile(
    r'^\d+\s+(?:open\(|openat\([^,]+, )"((?:\\.|[^"\\])*)", '
    r'[^,)]*\b(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)\b'
)
IPV4_CONNECT = re.compile(
    r'^\d+\s+connect\(\d+, \{sa_family=AF_INET, sin_port=htons\((\d+)\), '
    r'sin_addr=inet_addr\("([0-9.]+)"\)'
)
CALL_RESULT = re.compile(r'\)\s+= (-?\d+)(?: ([A-Z][A-Z0-9]+)\b)?')
UNFINISHED = re.compile(r'^(\d+)\s+(\w+)\(.*\s+<unfinished \.\.\.>$')
RESUMED = re.compile(r'^(\d+)\s+<\.\.\. (\w+) resumed>(.*)$')


def sandbox_command(bwrap, script):
    command = [
        bwrap,
        "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent",
        "--new-session", "--cap-drop", "ALL", "--clearenv",
        "--setenv", "PATH", "/usr/bin",
        "--setenv", "HOME", "/work",
        "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib",
    ]
    if Path("/usr/lib64").is_dir():
        command.extend(["--symlink", "usr/lib64", "/lib64"])
    command.extend([
        "--dev", "/dev", "--proc", "/proc",
        "--size", str(WORKSPACE_SIZE), "--tmpfs", "/work",
        "--size", str(WORKSPACE_SIZE), "--tmpfs", "/tmp",
        "--ro-bind", str(script), "/script.py",
        "--chdir", "/work",
        "--", "/usr/bin/python3", "-I", "-B", "-u", "/script.py",
    ])
    return command


def limit_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT, OUTPUT_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def read_output(stream):
    stream.seek(0)
    return stream.read(OUTPUT_LIMIT).decode("utf-8", errors="replace")


def completed_lines(lines):
    pending = {}
    for line in lines:
        unfinished = UNFINISHED.match(line)
        if unfinished:
            pending[unfinished.groups()] = line.removesuffix("<unfinished ...>").rstrip()
            continue
        resumed = RESUMED.match(line)
        if resumed:
            prefix = pending.pop((resumed[1], resumed[2]), None)
            if prefix is not None:
                yield prefix + resumed[3]
            continue
        yield line


def summarize_activity(lines):
    events = Counter()
    for line in lines:
        result = CALL_RESULT.search(line)
        if result is None:
            continue
        write = WRITE_OPEN.match(line)
        connection = IPV4_CONNECT.match(line)
        if write:
            action, target = "open_for_write", write[1]
        elif connection:
            action, target = "connect_ipv4", f"{connection[2]}:{connection[1]}"
        else:
            continue
        outcome = "success" if int(result[1]) >= 0 else "failed"
        if connection and result[2] in {"EINPROGRESS", "EALREADY"}:
            outcome = "pending"
        events[action, target, outcome, result[2]] += 1
    return [
        {"action": action, "target": target, "outcome": outcome, "errno": errno, "count": count}
        for (action, target, outcome, errno), count in events.items()
    ]


def read_trace(path, include_raw=False, *, timed_out=False):
    raw = path.read_bytes()
    lines = raw.decode("utf-8", errors="replace").splitlines()
    start_index, python_pid = next(
        ((index, match[1]) for index, line in enumerate(lines)
         if (match := PYTHON_EXEC.fullmatch(line))),
        (None, None),
    )
    syscalls = lines[start_index + 1:] if start_index is not None else []
    limit_reached = len(raw) >= OUTPUT_LIMIT
    end_marker = re.compile(rf"^{python_pid}\s+\+\+\+ (exited with|killed by) ")
    python_ended = python_pid is not None and any(end_marker.match(line) for line in syscalls)
    gaps = []
    if python_pid is None:
        gaps.append("python_start_unobserved")
    elif not python_ended:
        gaps.append("python_end_unobserved")
    if timed_out:
        gaps.append("timeout")
    if limit_reached:
        gaps.append("trace_limit")
    activity = summarize_activity(completed_lines(syscalls))
    report = {
        "python_started": python_pid is not None,
        "python_ended": python_ended,
        "limit_reached": limit_reached,
        "capture_status": "partial" if gaps else "completed",
        "capture_gaps": gaps,
        "activity": activity,
        "failed_attempts": [
            {"action": event["action"], "target": event["target"], "errno": event["errno"]}
            for event in activity if event["outcome"] == "failed"
        ],
    }
    if include_raw:
        report["syscalls"] = syscalls
    return report


def run_script(bwrap, script_bytes, timeout, tracer=None, include_raw=False):
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "script.py"
        script.write_bytes(script_bytes)
        trace = Path(directory) / "syscalls.log"
        command = sandbox_command(bwrap, script)
        if tracer:
            trace.touch()
            command = [
                tracer, "-f", "-q", "--kill-on-exit", "-s", "160",
                "-e", "trace=%file,%network", "-o", str(trace), "--",
                *command,
            ]
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            with subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
                preexec_fn=limit_output,
            ) as process:
                timed_out = False
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                finally:
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                report = {
                    "timed_out": timed_out,
                    "exit_code": process.returncode,
                    "stdout": read_output(stdout),
                    "stderr": read_output(stderr),
                }
        if tracer:
            report["trace"] = read_trace(trace, include_raw, timed_out=timed_out)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("script", type=Path)
    parser.add_argument("--timeout", type=int, default=3, choices=range(1, 61),
                        metavar="SECONDS", help="wall-clock limit (1–60 seconds)")
    parser.add_argument("--trace", action="store_true", help="capture file and network syscalls with strace")
    parser.add_argument("--raw-syscalls", action="store_true",
                        help="include raw syscall lines in the trace report")
    args = parser.parse_args()

    if args.raw_syscalls and not args.trace:
        parser.error("--raw-syscalls requires --trace")
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        parser.error("Bubblewrap (bwrap) is required")
    tracer = shutil.which("strace") if args.trace else None
    if args.trace and tracer is None:
        parser.error("--trace requires strace")
    try:
        with args.script.open("rb") as source:
            script_bytes = source.read(SCRIPT_LIMIT + 1)
        if len(script_bytes) > SCRIPT_LIMIT:
            parser.error("script exceeds the 1 MiB input limit")
        report = run_script(bwrap, script_bytes, args.timeout, tracer, args.raw_syscalls)
    except (OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"runprint: {error}\n")

    print(json.dumps(report, indent=2))
    if report["timed_out"]:
        return 124
    if args.trace and not report["trace"]["python_started"]:
        return 1
    return 0 if report["exit_code"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
