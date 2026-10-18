"""Bitwarden access: session acquisition and a thin, non-leaking ``bw`` wrapper.

The rule throughout this module is that vault contents never leave memory as
text: no item is printed, logged, or interpolated into an exception, because
``bw list items`` returns complete private keys.
"""

from __future__ import annotations

import base64
import json
import os
import shlex
import shutil
import stat
import subprocess
import time
from pathlib import Path

from .settings import EXIT_FATAL, Settings

TYPE_LOGIN = 1


class BwError(Exception):
    """A Bitwarden operation failed."""

    def __init__(self, message: str, code: int = EXIT_FATAL) -> None:
        super().__init__(message)
        self.code = code


def parse_session_env(text: str) -> dict[str, str]:
    """Parse ``export KEY=VALUE`` lines from an unlock helper's env file.

    A literal reader, deliberately: this text is never eval'd or sourced.
    """
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        key, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def bw_status_unlocked(session: str) -> bool:
    env = {**os.environ, "BW_SESSION": session}
    try:
        result = subprocess.run(
            ["bw", "status"], capture_output=True, env=env, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0:
        return False
    try:
        return json.loads(result.stdout).get("status") == "unlocked"
    except (json.JSONDecodeError, AttributeError):
        return False


def validate_session_file(path: Path) -> None:
    """Reject a session file we should not trust."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise BwError(f"cannot stat session file {path}: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise BwError("session file is a symlink, refusing to trust it")
    if not stat.S_ISREG(st.st_mode):
        raise BwError("session file is not a regular file")
    if st.st_uid != os.getuid():
        raise BwError("session file is not owned by us")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise BwError("session file is group/world accessible")
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime and not str(path.resolve()).startswith(
        str(Path(runtime).resolve()) + os.sep
    ):
        raise BwError(f"session file is outside XDG_RUNTIME_DIR: {path}")


def get_session(settings: Settings) -> str:
    """Return a ``BW_SESSION`` that is known to be unlocked."""
    env_session = os.environ.get("BW_SESSION", "")
    if env_session and bw_status_unlocked(env_session):
        return env_session

    if not settings.unlock_cmd:
        raise BwError(
            "Bitwarden is locked and no unlock helper is configured.\n"
            "Unlock it yourself and export BW_SESSION, or pass "
            "--unlock-cmd / set SSHVAULT_UNLOCK_CMD to a command that prints "
            "the path of a shell env file containing BW_SESSION."
        )

    argv = shlex.split(settings.unlock_cmd)
    if not argv:
        raise BwError("unlock command is empty")
    if shutil.which(argv[0]) is None:
        raise BwError(f"unlock helper not found: {argv[0]}")
    try:
        result = subprocess.run(argv, capture_output=True, timeout=300, check=False)
    except subprocess.TimeoutExpired as exc:
        raise BwError("timed out waiting for the unlock helper") from exc
    if result.returncode != 0:
        raise BwError("could not unlock Bitwarden")

    printed = result.stdout.decode("utf-8", "replace").strip()
    if not printed:
        raise BwError("unlock helper printed no session file path")
    session_file = Path(printed.splitlines()[-1].strip())
    validate_session_file(session_file)

    values = parse_session_env(
        session_file.read_text(encoding="utf-8", errors="replace")
    )
    session = values.get("BW_SESSION", "")
    if not session:
        raise BwError("session file contains no BW_SESSION")
    expires = values.get("BW_SESSION_EXPIRES_AT", "")
    if expires.isdigit() and int(expires) <= time.time():
        raise BwError("cached Bitwarden session has expired; re-run the unlock helper")
    if not bw_status_unlocked(session):
        raise BwError("Bitwarden session is not unlocked")
    return session


class Bw:
    """Thin wrapper around the ``bw`` CLI."""

    def __init__(self, session: str) -> None:
        self.session = session
        self._snapshots: dict[str, dict[str, dict]] = {}

    def _run(
        self, args: list[str], stdin_bytes: bytes | None = None, timeout: int = 120
    ) -> bytes:
        env = {**os.environ, "BW_SESSION": self.session}
        try:
            result = subprocess.run(
                ["bw", *args],
                input=stdin_bytes,
                capture_output=True,
                env=env,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BwError(f"bw {args[0]} timed out") from exc
        if result.returncode != 0:
            # bw's own stderr can echo vault contents; report only the operation.
            raise BwError(f"bw {' '.join(args[:2])} failed (exit {result.returncode})")
        return result.stdout

    def snapshot(self, prefix: str) -> dict[str, dict]:
        """Map item name -> {id, notes, raw} for everything under ``prefix``.

        ``bw list items`` hands back full items including private keys, so the
        result is reduced to what callers need and never printed.
        """
        if prefix in self._snapshots:
            return self._snapshots[prefix]
        raw = self._run(["list", "items", "--search", prefix])
        try:
            items = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BwError("could not parse `bw list items` output") from exc
        snapshot = {}
        for item in items:
            name = item.get("name", "")
            if name.startswith(prefix):
                snapshot[name] = {
                    "id": item.get("id", ""),
                    "notes": item.get("notes") or "",
                    "raw": item,
                }
        self._snapshots[prefix] = snapshot
        return snapshot

    def create(self, item_name: str, notes: bytes) -> None:
        """Create a login item. The payload goes on stdin, never in argv."""
        payload = {
            "type": TYPE_LOGIN,
            "name": item_name,
            "notes": notes.decode("utf-8"),
            "login": {"username": None, "password": None, "uris": []},
            "fields": [],
            "favorite": False,
            "reprompt": 0,
            "collectionIds": [],
        }
        encoded = base64.b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        self._run(["create", "item"], stdin_bytes=encoded + b"\n")

    def edit(self, item: dict, notes: bytes) -> None:
        """Update only ``notes``, preserving folder, fields, reprompt and so on."""
        updated = dict(item["raw"])
        updated["notes"] = notes.decode("utf-8")
        encoded = base64.b64encode(
            json.dumps(updated, separators=(",", ":")).encode("utf-8")
        )
        self._run(["edit", "item", item["id"]], stdin_bytes=encoded + b"\n")

    def delete(self, item_id: str) -> None:
        self._run(["delete", "item", item_id])
