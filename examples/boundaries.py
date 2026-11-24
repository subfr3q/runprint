import errno
from pathlib import Path
import socket

try:
    Path("/sandbox-probe.txt").touch(exist_ok=False)
except OSError as error:
    if error.errno not in {errno.EACCES, errno.EROFS, errno.EPERM}:
        raise
    print(f"Write outside /work and /tmp denied (errno {error.errno})")
else:
    raise SystemExit("Unexpected write outside /work and /tmp")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
    connection.settimeout(1)
    try:
        connection.connect(("192.0.2.1", 443))
    except OSError as error:
        if error.errno not in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM}:
            raise
        print(f"Network connection blocked (errno {error.errno})")
    else:
        raise SystemExit("Unexpected network access")
