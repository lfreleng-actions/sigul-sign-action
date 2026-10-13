# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""A stand-in Docker daemon socket that inspects whoever calls it.

The action runs the real docker CLI, found only in the system's own
directories, so a test cannot slip a fake 'docker' onto PATH to watch
it. Instead DOCKER_HOST points the real CLI at this socket. Each
connection records the environment and open descriptors of the CLI's
PARENT -- the signing process -- as any same-user process could read
them from /proc, and is answered with an error, so the action stops
before it pulls anything. Linux only: it reads /proc and SO_PEERCRED.
"""

from __future__ import annotations

import os
import re
import socket
import sys
import threading
from pathlib import Path

# struct ucred: pid, uid and gid, each a native 32-bit integer.
_UCRED_SIZE = 12
_PARENT = re.compile(r"^PPid:\s+(\d+)", re.MULTILINE)
_ERROR_RESPONSE = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"


class FakeDockerDaemon:
    """Listen on a Unix socket; record each caller's parent process."""

    def __init__(self, path: Path) -> None:
        self.path: Path = path
        self.environments: list[bytes] = []
        self.descriptors: list[str] = []
        self.listener: socket.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(16)
        self.thread: threading.Thread = threading.Thread(target=self.serve, daemon=True)

    @property
    def url(self) -> str:
        return f"unix://{self.path}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.listener.close()

    def serve(self) -> None:
        """Answer connections until the listener closes."""
        while True:
            try:
                connection = self.listener.accept()[0]
            except OSError:
                return
            threading.Thread(
                target=self.answer, args=(connection,), daemon=True
            ).start()

    def answer(self, connection: socket.socket) -> None:
        """Record the caller, read its request, and refuse it."""
        with connection:
            self.inspect(connection)
            with connection.makefile("rb") as stream:
                while stream.readline() not in (b"\r\n", b""):
                    pass
            connection.sendall(_ERROR_RESPONSE)

    def inspect(self, connection: socket.socket) -> None:
        """Record the calling CLI's parent: its environment and fds."""
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED_SIZE)
        pid = int.from_bytes(raw[:4], sys.byteorder, signed=True)
        found = _PARENT.search(Path(f"/proc/{pid}/status").read_text())
        if found is None:
            return
        parent = Path(f"/proc/{found.group(1)}")
        self.environments.append((parent / "environ").read_bytes())
        self.descriptors.extend(
            os.readlink(entry) for entry in (parent / "fd").iterdir()
        )
