"""Write to the workspace, then probe filesystem and network boundaries."""

from pathlib import Path
import socket


Path("/work/result.txt").write_text("hello\n")

try:
    with Path("/usr/bin/python3").open("ab"):
        raise SystemExit("Unexpected write access to /usr")
except OSError:
    pass

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
    connection.settimeout(1)
    try:
        connection.connect(("192.0.2.1", 443))
    except OSError:
        pass
    else:
        raise SystemExit("Unexpected network access")
