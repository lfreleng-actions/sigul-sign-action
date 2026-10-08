# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Captured runner processes without an unbounded post-cancellation reap."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

GROUP_EXIT_TIMEOUT_SECONDS = 0.2
_GROUP_POLL_SECONDS = 0.01


def _group_exists(group: int) -> bool:
    """Treat a denied probe as unresolved, never as proof the helpers exited."""
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def kill_and_poll(process: subprocess.Popen[bytes] | subprocess.Popen[str]) -> None:
    """Kill a dedicated command group, then poll briefly without a blocking reap.

    Callers must launch with start_new_session=True: the child's PID is the
    group ID even after that child exits, while its helpers may still live.
    Detached daemons and uninterruptible I/O still need runner-level cleanup.
    """
    group = process.pid
    if group <= 0 or group == os.getpgrp():
        raise ValueError("refusing to terminate the action's own process group")
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        _ = process.poll()
        return
    deadline = time.monotonic() + GROUP_EXIT_TIMEOUT_SECONDS
    while True:
        _ = process.poll()
        if not _group_exists(group) or time.monotonic() >= deadline:
            return
        time.sleep(_GROUP_POLL_SECONDS)


def capture_bytes(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Capture an isolated command; interruption kills its whole process group.

    subprocess.run's timeout path kills and then waits without a deadline.
    That is unsuitable when an outer finally must still erase credentials.
    A surviving process remains the runner's responsibility at job termination.
    """
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
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
