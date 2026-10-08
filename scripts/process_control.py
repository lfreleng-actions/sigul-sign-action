# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Captured runner processes without an unbounded post-cancellation reap."""

from __future__ import annotations

import subprocess
from pathlib import Path


def kill_and_poll(process: subprocess.Popen[bytes] | subprocess.Popen[str]) -> None:
    """Request termination without waiting for uninterruptible kernel I/O."""
    try:
        process.kill()
    except ProcessLookupError:
        _ = process.poll()
        return
    _ = process.poll()


def capture_bytes(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Capture a command; cancellation and timeouts never wait after killing it.

    subprocess.run's timeout path kills and then waits without a deadline.
    That is unsuitable when an outer finally must still erase credentials.
    A surviving process remains the runner's responsibility at job termination.
    """
    process = subprocess.Popen(
        argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        out, err = process.communicate(timeout=timeout)
    except BaseException:
        kill_and_poll(process)
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    status = process.returncode if process.returncode is not None else -1
    return subprocess.CompletedProcess(argv, status, out, err)


def capture_text(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Decode command output without normalizing payload bytes in other callers."""
    done = capture_bytes(argv, env=env, cwd=cwd, timeout=timeout)
    return subprocess.CompletedProcess(
        argv,
        done.returncode,
        done.stdout.decode("utf-8", "replace"),
        done.stderr.decode("utf-8", "replace"),
    )
