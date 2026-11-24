"""Verify the real CLI demos on a Linux host with tracing enabled."""

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parent


def run_demo(name, *options, timeout=15):
    run = subprocess.run(
        [sys.executable, str(ROOT / "runprint.py"), "--trace",
         str(ROOT / "examples" / name), "--timeout", str(timeout), *options],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout + 5,
    )
    return run.returncode, json.loads(run.stdout)


class SandboxDemos(unittest.TestCase):
    def test_hello(self):
        status, report = run_demo("hello.py")
        self.assertEqual(status, 0, report)
        self.assertEqual(report["stdout"], "hello from the sandbox\n")
        self.assertEqual(report["trace"]["capture_status"], "completed", report)

    def test_silent_probe(self):
        status, report = run_demo("silent_probe.py", "--raw-syscalls")
        self.assertEqual(status, 0, report)
        self.assertEqual(report["stdout"], "")
        trace = report["trace"]
        self.assertEqual(trace["capture_status"], "completed", report)
        results = {
            (event["action"], event["target"]): (event["outcome"], event["errno"])
            for event in trace["activity"]
        }
        self.assertEqual(results["open_for_write", "/work/result.txt"], ("success", None))
        outcome, errno = results["open_for_write", "/usr/bin/python3"]
        self.assertEqual(outcome, "failed")
        self.assertIn(errno, {"EROFS", "EACCES"})
        self.assertEqual(results["connect_ipv4", "192.0.2.1:443"], ("failed", "ENETUNREACH"))
        self.assertTrue(trace["syscalls"])

    def test_timeout(self):
        status, report = run_demo("timeout.py", timeout=8)
        self.assertEqual(status, 124, report)
        self.assertTrue(report["timed_out"])
        self.assertTrue(report["trace"]["python_started"], report)
        self.assertEqual(report["trace"]["capture_status"], "partial")
        self.assertIn("timeout", report["trace"]["capture_gaps"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
