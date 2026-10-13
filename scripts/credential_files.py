# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Exclusive, owner-only creation of credential files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO


def create_private(path: Path) -> BinaryIO:
    """Create a new mode-0600 file without following or replacing a link."""
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        return os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise


def write_private(path: Path, data: bytes) -> None:
    """Write bytes through the same descriptor that created the private file."""
    with create_private(path) as stream:
        _ = stream.write(data)
