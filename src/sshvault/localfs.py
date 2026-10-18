"""Local filesystem: key discovery, key derivation, safe writes and backups."""

from __future__ import annotations

import contextlib
import os
import re
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from .settings import BACKUP_MARKER, Settings

PUB_OK = "ok"
PUB_PASSPHRASE = "passphrase"
PUB_ERROR = "error"

REL_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

PRIVATE_MODE = 0o600
PUBLIC_MODE = 0o644


class UnsafePathError(Exception):
    """Raised when a path would escape the SSH directory."""


def enumerate_private_keys(settings: Settings) -> list[str]:
    """Names of private keys in the keys directory, excluding .pub and backups."""
    keys_dir = settings.keys_dir
    if not keys_dir.is_dir():
        return []
    names = []
    for entry in sorted(keys_dir.iterdir()):
        if not entry.is_file():
            continue
        if entry.name.endswith(".pub") or BACKUP_MARKER in entry.name:
            continue
        names.append(entry.name)
    return names


def derive_public_key(path: Path) -> tuple[str, bytes]:
    """Return (status, data) where status is PUB_OK, PUB_PASSPHRASE or PUB_ERROR.

    ``-P ''`` with an empty stdin and ``SSH_ASKPASS_REQUIRE=never`` makes
    ssh-keygen fail fast on a protected key instead of prompting and hanging.
    """
    env = {**os.environ, "SSH_ASKPASS_REQUIRE": "never"}
    try:
        result = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=env,
            timeout=15,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return PUB_ERROR, b""
    if result.returncode == 0:
        return PUB_OK, result.stdout
    if b"incorrect passphrase" in result.stderr:
        return PUB_PASSPHRASE, b""
    return PUB_ERROR, b""


def key_material(data: bytes) -> bytes:
    """The type and base64 blob of a public key line, ignoring its comment.

    ``ssh-keygen -y`` echoes the comment embedded in the private key, so a
    ``.pub`` whose comment was edited would otherwise look like a key mismatch.
    """
    return b" ".join(data.split()[:2])


def local_key_notes(settings: Settings, name: str) -> tuple[bytes | None, str]:
    """The vault payload a local keypair would produce.

    Returns ``(notes_b64, reason)``; ``notes_b64`` is None when the public key
    is missing and cannot be derived.
    """
    from .payloads import encode_keys

    keys_dir = settings.keys_dir
    private_path = keys_dir / name
    public_path = keys_dir / f"{name}.pub"
    try:
        private_key = private_path.read_bytes()
    except OSError:
        return None, "unreadable"

    if public_path.is_file():
        public_key = public_path.read_bytes()
    else:
        status, derived = derive_public_key(private_path)
        if status != PUB_OK:
            return None, status
        public_key = derived

    try:
        return encode_keys(public_key, private_key), PUB_OK
    except (UnicodeDecodeError, TypeError):
        return None, "not-text"


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Write ``data`` to ``path`` atomically, with an explicit mode and fsync."""
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".sshvault.")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        tmp_name = ""
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp_name:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)


def backup_file(path: Path, hidden: bool = False) -> Path:
    """Copy ``path`` aside, refusing to clobber an existing backup.

    ``hidden`` prefixes the backup name with a dot. Config files usually live in
    a directory the user's main config pulls in with ``Include <dir>/*``, and
    that glob does not match leading dots -- so a hidden backup is never handed
    to ssh's parser. A visible, corrupt backup there can break every connection.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    prefix = "." if hidden else ""
    target = path.with_name(f"{prefix}{path.name}{BACKUP_MARKER}.{stamp}")
    source_mode = stat.S_IMODE(path.stat().st_mode)
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, source_mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(path.read_bytes())
        os.chmod(target, source_mode)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(target)
        raise
    return target


def validate_rel(rel: str, ssh_dir: Path) -> bool:
    """Guard a relative path that is about to be written from the vault."""
    if not rel or rel.startswith(("/", "-")) or ".." in rel:
        return False
    if not REL_RE.match(rel):
        return False
    root = Path(os.path.realpath(ssh_dir))
    real = Path(os.path.realpath(ssh_dir / rel))
    return real == root or root in real.parents


def local_config_files(settings: Settings) -> list[str]:
    """Config files to sync, as paths relative to the SSH dir."""
    files: list[str] = []
    main = settings.ssh_dir / settings.main_config
    if main.is_file():
        files.append(settings.main_config)

    config_dir = settings.config_dir
    if config_dir.is_dir():
        for entry in sorted(config_dir.iterdir()):
            if not entry.is_file() or BACKUP_MARKER in entry.name:
                continue
            files.append(settings.rel_path(entry))
    return files


def config_item_name(settings: Settings, rel: str) -> str:
    """Vault item name for a config path. ``/`` maps to ``__`` on every OS."""
    return settings.config_prefix + rel.replace("/", "__")


def check_rel_representable(settings: Settings, rel: str) -> None:
    """Refuse a path the naming scheme cannot round-trip."""
    if "__" in rel:
        raise UnsafePathError(
            f"path contains '__', which the {settings.config_prefix} naming "
            f"scheme cannot represent: {rel}"
        )
