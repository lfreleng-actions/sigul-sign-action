# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Bounded credential archives: regular files and directories, never links."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import time
import zlib
from pathlib import Path, PurePosixPath

from action_common import ActionError
from credential_files import create_private

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_MEMBERS = 256
MAX_PATH_COMPONENTS = 16
MAX_PATH_BYTES = 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_LZMA_MEMORY = 128 * 1024 * 1024
ARCHIVE_TIMEOUT_SECONDS = 60
CHUNK_BYTES = 65536


def check_deadline(deadline: float) -> None:
    """Bound decompression and extraction work between local I/O operations."""
    if time.monotonic() >= deadline:
        raise ActionError("sigul-pki archive processing exceeded 60 seconds")


def append_chunk(output: io.BytesIO, chunk: bytes, deadline: float) -> None:
    """Cap the entire tar stream, including metadata hidden from member iteration."""
    check_deadline(deadline)
    if output.tell() + len(chunk) > MAX_ARCHIVE_BYTES:
        raise ActionError("sigul-pki decompressed tar exceeds 64 MiB")
    _ = output.write(chunk)


def unpack_xz(raw: bytes, output: io.BytesIO, deadline: float) -> None:
    """Limit the XZ dictionary as well as its output, including concatenated streams."""
    pending = raw
    while pending:
        decoder = lzma.LZMADecompressor(memlimit=MAX_LZMA_MEMORY)
        chunk = decoder.decompress(pending, max_length=CHUNK_BYTES)
        while True:
            append_chunk(output, chunk, deadline)
            if decoder.eof:
                # XZ permits zero padding between streams.
                pending = decoder.unused_data.lstrip(b"\0")
                break
            if decoder.needs_input:
                raise ActionError("sigul-pki contains a truncated XZ archive")
            chunk = decoder.decompress(b"", max_length=CHUNK_BYTES)


def tar_payload(archive: Path, deadline: float) -> io.BytesIO:
    """Decode a bounded tar before its parser can allocate oversized PAX headers.

    The additional plaintext copy is memory-only. Reading with a size limit
    also bounds GNU long-name records and metadata chains before tarfile sees
    them; per-file quotas alone cannot protect tarfile's header parsing.
    """
    with archive.open("rb") as source:
        raw = source.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ActionError("sigul-pki decrypted archive exceeds 64 MiB")
    output = io.BytesIO()
    if raw.startswith(b"\xfd7zXZ\0"):
        unpack_xz(raw, output, deadline)
    elif raw.startswith((b"\x1f\x8b", b"BZh")):
        compressed = io.BytesIO(raw)
        reader = (
            gzip.GzipFile(fileobj=compressed)
            if raw.startswith(b"\x1f\x8b")
            else bz2.BZ2File(compressed)
        )
        with reader:
            while chunk := reader.read(CHUNK_BYTES):
                append_chunk(output, chunk, deadline)
    else:
        append_chunk(output, raw, deadline)
    _ = output.seek(0)
    return output


def member_path(member: tarfile.TarInfo) -> tuple[str, ...]:
    """Accept only relative printable paths with bounded, unambiguous components."""
    name = member.name
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or not name.isprintable()
        or len(name.encode("utf-8")) > MAX_PATH_BYTES
        or ".." in name.split("/")
    ):
        raise ActionError("sigul-pki contains an unsafe archive path")
    parts = PurePosixPath(name).parts
    if len(parts) > MAX_PATH_COMPONENTS:
        raise ActionError("sigul-pki archive paths exceed 16 components")
    if any(part != part.strip() or len(part.encode("utf-8")) > 255 for part in parts):
        raise ActionError("sigul-pki contains an unsafe archive path component")
    if not parts and not member.isdir():
        raise ActionError("sigul-pki contains an empty file path")
    return parts


def checked_members(
    tar: tarfile.TarFile, deadline: float
) -> list[tuple[tarfile.TarInfo, tuple[str, ...]]]:
    """Validate the complete archive before writing any of its contents."""
    checked: list[tuple[tarfile.TarInfo, tuple[str, ...]]] = []
    files: set[tuple[str, ...]] = set()
    total = 0
    for count, member in enumerate(tar, 1):
        check_deadline(deadline)
        if count > MAX_MEMBERS:
            raise ActionError("sigul-pki archive exceeds 256 entries")
        if member.issym() or member.islnk():
            raise ActionError(
                "sigul-pki contains a symlink or hardlink; repack with files and directories only"
            )
        if (
            member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
            or member.issparse()
        ):
            raise ActionError("sigul-pki contains a special or sparse file")
        parts = member_path(member)
        if member.size < 0 or member.size > MAX_FILE_BYTES:
            raise ActionError("sigul-pki archive file exceeds 16 MiB")
        if member.isdir() and member.size:
            raise ActionError("sigul-pki contains a directory with file data")
        total += member.size
        if total > MAX_TOTAL_BYTES:
            raise ActionError("sigul-pki archive expansion exceeds 32 MiB")
        if not member.isdir():
            if parts in files:
                raise ActionError("sigul-pki contains duplicate file paths")
            files.add(parts)
        checked.append((member, parts))
    return checked


def copy_member(
    tar: tarfile.TarFile, member: tarfile.TarInfo, target: Path, deadline: float
) -> None:
    """Copy only a validated regular member, with no extraction/link fallback."""
    source = tar.extractfile(member)
    if source is None:
        raise ActionError("sigul-pki archive file has no readable data")
    with source, create_private(target) as output:
        remaining = member.size
        while remaining:
            check_deadline(deadline)
            chunk = source.read(min(remaining, CHUNK_BYTES))
            if not chunk:
                raise ActionError("sigul-pki archive contains a truncated file")
            _ = output.write(chunk)
            remaining -= len(chunk)


def extract_bundle(archive: Path, destination: Path) -> None:
    """Extract into a fresh private tree without applying archive metadata.

    No member can create a link or special file. Exclusively created files
    and mode-0700 directories remove any dependency on tarfile's historical
    extraction filters; the job and its user remain the trust boundary.
    """
    deadline = time.monotonic() + ARCHIVE_TIMEOUT_SECONDS
    try:
        with (
            tar_payload(archive, deadline) as payload,
            tarfile.open(fileobj=payload, mode="r:") as tar,
        ):
            members = checked_members(tar, deadline)
            destination.mkdir(mode=0o700, parents=True, exist_ok=False)
            for member, parts in members:
                check_deadline(deadline)
                parent = destination
                for component in parts if member.isdir() else parts[:-1]:
                    parent /= component
                    parent.mkdir(mode=0o700, exist_ok=True)
                if not member.isdir():
                    copy_member(tar, member, parent / parts[-1], deadline)
    except (
        OSError,
        EOFError,
        tarfile.TarError,
        lzma.LZMAError,
        zlib.error,
        ValueError,
        OverflowError,
        RecursionError,
    ):
        raise ActionError("sigul-pki is not a readable, safe tar archive") from None
