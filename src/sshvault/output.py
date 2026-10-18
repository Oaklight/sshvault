"""Console output helpers, with a single global quiet switch."""

from __future__ import annotations

import sys

PROG = "sshvault"

_quiet = False


def set_quiet(value: bool) -> None:
    global _quiet
    _quiet = value


def warn(message: str) -> None:
    print(f"{PROG}: warning: {message}", file=sys.stderr)


def info(message: str) -> None:
    if not _quiet:
        print(message)
