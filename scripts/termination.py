# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Defer termination exceptions while credential cleanup is in progress."""

from __future__ import annotations

import signal
import sys
from collections.abc import Generator
from contextlib import contextmanager
from types import FrameType

from action_common import ActionError

TERMINATION_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


class Cancelled(ActionError):
    """A termination request that must still allow credential cleanup."""


def on_signal(signum: int, _frame: FrameType | None) -> None:
    """Raise once; subsequent requests must not interrupt unwinding."""
    for other in TERMINATION_SIGNALS:
        _ = signal.signal(other, signal.SIG_IGN)
    raise Cancelled(f"interrupted by signal {signum}; cleaning up")


@contextmanager
def defer_termination() -> Generator[None, None, None]:
    """Finish cleanup before reporting a first signal received during it."""
    pending: list[int] = []
    unwinding = sys.exc_info()[0] is not None

    def record(signum: int, _frame: FrameType | None) -> None:
        if not pending:
            pending.append(signum)

    previous = {signum: signal.getsignal(signum) for signum in TERMINATION_SIGNALS}
    try:
        for signum in TERMINATION_SIGNALS:
            _ = signal.signal(signum, record)
        yield
    finally:
        for signum, handler in previous.items():
            _ = signal.signal(signum, handler)
    if pending and not unwinding:
        on_signal(pending[0], None)
