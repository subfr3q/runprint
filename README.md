# Runprint

Runprint runs Python scripts in a Bubblewrap sandbox on Linux. Its JSON report captures process output and exit status. Turn on syscall tracing to see file and network activity even when the script prints nothing.

## Quick start

Run these commands from the repository root. The CLI requires Python 3 and Bubblewrap on a merged-/usr Linux system where unprivileged user and network namespaces are permitted. Trace mode also requires strace with `--kill-on-exit` and permission to trace Bubblewrap.

```sh
python3 runprint.py examples/hello.py
python3 runprint.py --trace examples/silent_probe.py
```

The [silent probe](examples/silent_probe.py) writes to its temporary workspace, attempts to open `/usr/bin/python3` for writing, and tries to connect to the documentation address `192.0.2.1:443`. It prints nothing when the last two operations fail. The tracer records those attempts independently.

### Example report

Excerpt from the expected structure of `trace.activity`. The exact error codes depend on the environment. The write-open can also fail with `EROFS`.

```json
[
  {"action": "open_for_write", "target": "/work/result.txt", "outcome": "success", "errno": null, "count": 1},
  {"action": "open_for_write", "target": "/usr/bin/python3", "outcome": "failed", "errno": "EACCES", "count": 1},
  {"action": "connect_ipv4", "target": "192.0.2.1:443", "outcome": "failed", "errno": "ENETUNREACH", "count": 1}
]
```

## Reading the report

| Field | Meaning |
| --- | --- |
| `stdout`, `stderr` | Captured output from the run, including launcher errors when present. |
| `exit_code`, `timed_out` | Subprocess return code and whether the wall-clock deadline expired. |
| `trace.activity` | Events grouped by action, target, outcome, and errno. Covers write-capable `open` and `openat` calls and IPv4 `connect`. A successful write-open confirms the file was opened with write access. A nonblocking connection can show as `pending`. |
| `trace.capture_status`, `trace.capture_gaps` | `completed` means the Python process start and end were observed within the time and trace budgets. `partial` lists unobserved markers, a timeout, or the 64 KiB trace cap. Check the exit code separately. |

Add `--raw-syscalls` alongside `--trace` to include the captured file and network syscall lines in `trace.syscalls`. Those lines can include Python startup activity and launcher cleanup. The CLI exits with status `0` on success, `1` on launcher or script failure, and `124` on timeout. Argument errors use status `2`.

## Isolation and scope

The [launcher](runprint.py) copies the entry script and mounts it read-only. Bubblewrap provides a read-only view of the host's `/usr`, size-limited temporary mounts at `/work` and `/tmp`, and separate PID and network namespaces. The script starts with a cleared environment and explicit `PATH` and `HOME`. The launcher applies a wall-clock deadline and caps each output stream at 64 KiB. In trace mode, strace runs outside the sandbox and follows child processes.

This prototype shares the host kernel, provides no aggregate memory or process-count quotas, and records selected syscalls from one run. Evaluate it with the included demos.

## Verify the demos

```sh
python3 check_demos.py
```

The [integration checks](check_demos.py) cover ordinary execution, the silent probe's three actions, and timeout reporting. All three passed in a network-disabled Linux VM with Bubblewrap and strace.
