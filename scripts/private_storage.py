# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Private temporary directories for credentials, in memory where possible."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Prefer tmpfs over persistent storage. Swap, crash dumps, and a lost
# runner still prevent an unconditional memory-only/erasure guarantee.
SHARED_MEMORY = "/dev/shm"


def is_memory_backed(path: str) -> bool:
    """Return True when path is itself a tmpfs mount, per /proc/mounts.

    Without a readable mount table, which is Linux's, nothing is known
    to be in memory.
    """
    table = Path("/proc/mounts")
    if not table.is_file():
        return False
    for line in table.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == path and fields[2] == "tmpfs":
            return True
    return False


def private_directory(prefix: str, fallback: str | None) -> Path:
    """Create a mode-0700 temporary directory, in memory where possible.

    tmpfs avoids ordinary persistent writes but can be swapped. Its
    short path also fits gpg-agent sockets. Without a usable tmpfs,
    fall back to the supplied directory and overwrite files on cleanup;
    that cannot erase older CoW, journal, snapshot, or crash-dump copies.
    """
    if is_memory_backed(SHARED_MEMORY) and os.access(SHARED_MEMORY, os.W_OK):
        return Path(tempfile.mkdtemp(prefix=prefix, dir=SHARED_MEMORY))
    return Path(tempfile.mkdtemp(prefix=prefix, dir=fallback))
