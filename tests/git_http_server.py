# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""A git smart-HTTP server that demands Basic authentication, for tests.

It serves bare repositories under one directory through git's own
http-backend, the CGI program git ships, and refuses any request whose
credentials differ from the expected pair. That lets a test prove a
push sends exactly the configured user and token, and nothing when it
should not.
"""

from __future__ import annotations

import base64
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import final


class GitServer:
    """Serve the bare repositories under root on 127.0.0.1."""

    def __init__(self, root: Path, user: str, token: str) -> None:
        self.root: Path = root
        self.expected: str = (
            "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
        )
        self.seen: list[str] = []
        server = self

        @final
        class Handler(BaseHTTPRequestHandler):
            def handle_git(self) -> None:
                authorization = self.headers.get("Authorization") or ""
                server.seen.append(authorization)
                if authorization != server.expected:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="git"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                server.run_backend(self)

            # The names BaseHTTPRequestHandler dispatches to.
            do_GET = handle_git
            do_POST = handle_git

        self.httpd: ThreadingHTTPServer = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread: threading.Thread = threading.Thread(
            target=self.httpd.serve_forever, daemon=True
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def run_backend(self, request: BaseHTTPRequestHandler) -> None:
        """Answer one request through git http-backend."""
        path, _, query = request.path.partition("?")
        length = int(request.headers.get("Content-Length") or 0)
        body = request.rfile.read(length) if length else b""
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_PROJECT_ROOT": str(self.root),
            "GIT_HTTP_EXPORT_ALL": "1",
            # http-backend accepts a push only from an authenticated user.
            "REMOTE_USER": "authenticated",
            "REQUEST_METHOD": request.command,
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "CONTENT_TYPE": request.headers.get("Content-Type") or "",
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_CONTENT_ENCODING": request.headers.get("Content-Encoding") or "",
            "GIT_PROTOCOL": request.headers.get("Git-Protocol") or "",
        }
        done = subprocess.run(
            ["git", "http-backend"],
            input=body,
            env=env,
            capture_output=True,
            check=False,
        )
        head, _, payload = done.stdout.partition(b"\r\n\r\n")
        status = 200
        headers: list[tuple[str, str]] = []
        for line in head.decode("latin-1").split("\r\n"):
            name, _, value = line.partition(":")
            if name.lower() == "status":
                status = int(value.split()[0])
            elif name:
                headers.append((name, value.strip()))
        request.send_response(status)
        for name, value in headers:
            request.send_header(name, value)
        request.send_header("Content-Length", str(len(payload)))
        request.end_headers()
        _ = request.wfile.write(payload)
