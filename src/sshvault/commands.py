"""The ``keys`` and ``config`` command implementations."""

from __future__ import annotations

import binascii
import contextlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from .bw import Bw, BwError
from .localfs import (
    PRIVATE_MODE,
    PUB_OK,
    PUB_PASSPHRASE,
    PUBLIC_MODE,
    UnsafePathError,
    atomic_write,
    backup_file,
    check_rel_representable,
    config_item_name,
    derive_public_key,
    enumerate_private_keys,
    key_material,
    local_config_files,
    local_key_notes,
    validate_rel,
)
from .output import info, warn
from .payloads import decode_config, decode_keys, encode_config
from .settings import EXIT_DIFF, EXIT_OK, Settings


def _select(names: list[str], only: list[str] | None) -> list[str]:
    if not only:
        return names
    wanted = set(only)
    return [name for name in names if name in wanted]


# ------------------------------------------------------------------ key commands


def keys_list(bw: Bw, settings: Settings) -> int:
    local = enumerate_private_keys(settings)
    vault = bw.snapshot(settings.keys_prefix)
    for name in sorted(local):
        print(f"{name}\tlocal")
    for item_name in sorted(vault):
        if item_name[len(settings.keys_prefix) :] not in local:
            print(f"{item_name[len(settings.keys_prefix) :]}\tvault-only")
    return EXIT_OK


def keys_push(bw: Bw, settings: Settings, only: list[str] | None, dry_run: bool) -> int:
    vault = bw.snapshot(settings.keys_prefix)
    names = _select(enumerate_private_keys(settings), only)
    if only:
        for name in only:
            if name not in names:
                warn(f"no local private key named {name}")
    status = EXIT_OK
    for name in names:
        notes, reason = local_key_notes(settings, name)
        if notes is None:
            warn(f"skipping {name}: cannot build public key ({reason})")
            status = EXIT_DIFF
            continue
        item_name = settings.keys_prefix + name
        existing = vault.get(item_name)
        if existing is not None and existing["notes"] == notes.decode("utf-8"):
            info(f"unchanged  {item_name}")
            continue
        if dry_run:
            info(f"would {'update' if existing else 'create'}  {item_name}")
            continue
        try:
            if existing is None:
                bw.create(item_name, notes)
                info(f"created  {item_name}")
            else:
                bw.edit(existing, notes)
                info(f"updated  {item_name}")
        except BwError as exc:
            warn(f"failed on {item_name}: {exc}")
            status = EXIT_DIFF
    return status


def keys_pull(bw: Bw, settings: Settings, only: list[str] | None, dry_run: bool) -> int:
    vault = bw.snapshot(settings.keys_prefix)
    names = _select([n[len(settings.keys_prefix) :] for n in vault], only)
    status = EXIT_OK
    keys_dir = settings.keys_dir

    for name in sorted(names):
        item = vault.get(settings.keys_prefix + name)
        if item is None:
            continue
        try:
            fields = decode_keys(item["notes"])
        except (binascii.Error, ValueError, KeyError, TypeError):
            warn(f"skipping {name}: vault payload is not a valid keypair")
            status = EXIT_DIFF
            continue

        private_key = fields.get("private_key", "").encode("utf-8")
        public_key = fields.get("public_key", "").encode("utf-8")
        if not private_key:
            warn(f"refusing {name}: vault holds an empty private key")
            status = EXIT_DIFF
            continue

        targets = [(keys_dir / name, private_key, PRIVATE_MODE)]
        if public_key:
            targets.append((keys_dir / f"{name}.pub", public_key, PUBLIC_MODE))

        if all(
            path.is_file() and path.read_bytes() == data for path, data, _ in targets
        ):
            info(f"unchanged  {name}")
            continue
        if dry_run:
            info(f"would restore  {name}")
            continue

        keys_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            for path, data, mode in targets:
                if path.exists():
                    backup = backup_file(path)
                    info(f"backed up  {name} -> {backup.name}")
                atomic_write(path, data, mode)
        except OSError as exc:
            warn(f"failed to write {name}: {exc.strerror}")
            status = EXIT_DIFF
            continue
        info(f"restored  {name}")
    return status


def keys_check(bw: Bw, settings: Settings) -> int:
    vault = bw.snapshot(settings.keys_prefix)
    names = enumerate_private_keys(settings)
    keys_dir = settings.keys_dir
    problems = 0

    for name in names:
        notes: list[str] = []
        failed = False
        private_path = keys_dir / name
        public_path = keys_dir / f"{name}.pub"

        mode = stat.S_IMODE(private_path.stat().st_mode)
        if mode & 0o077:
            notes.append(f"private key is {mode:04o}, should be {PRIVATE_MODE:04o}")
            failed = True

        if not public_path.is_file():
            notes.append("no .pub alongside it")
            failed = True
        else:
            derived_status, derived = derive_public_key(private_path)
            if derived_status == PUB_OK:
                if key_material(derived) != key_material(public_path.read_bytes()):
                    notes.append(".pub does not match the private key")
                    failed = True
                elif derived != public_path.read_bytes():
                    notes.append("only the .pub comment differs")
            elif derived_status == PUB_PASSPHRASE:
                notes.append("key match unverifiable (passphrase-protected)")
            else:
                notes.append("private key unreadable or corrupt")
                failed = True

        item = vault.get(settings.keys_prefix + name)
        if item is None:
            notes.append("missing from the vault")
            failed = True
        else:
            expected, reason = local_key_notes(settings, name)
            if expected is None:
                notes.append(f"vault comparison skipped ({reason})")
            elif item["notes"] != expected.decode("utf-8"):
                notes.append("vault copy differs")
                failed = True

        if failed:
            problems += 1
        marker = "FAIL" if failed else "ok"
        detail = "; ".join(notes) if notes else "-"
        print(f"{marker:<5} {name:<20} {detail}")

    for item_name in sorted(vault):
        base = item_name[len(settings.keys_prefix) :]
        if base not in names:
            print(f"VAULT {base:<20} no local key")
            problems += 1

    if problems:
        print(f"\n{problems} problem(s) found")
        return EXIT_DIFF
    print(f"\n{len(names)} key(s) checked, no problems")
    return EXIT_OK


def keys_load(settings: Settings, only: list[str] | None, dry_run: bool) -> int:
    if not os.environ.get("SSH_AUTH_SOCK"):
        raise BwError(
            "no ssh-agent is running (SSH_AUTH_SOCK is unset).\n"
            "Start one with `eval $(ssh-agent -s)` and re-run."
        )
    probe = subprocess.run(["ssh-add", "-l"], capture_output=True, check=False)
    if probe.returncode == 2:
        raise BwError("ssh-agent is not reachable (ssh-add could not connect)")

    keys_dir = settings.keys_dir
    names = _select(enumerate_private_keys(settings), only)
    status = EXIT_OK
    for name in names:
        path = keys_dir / name
        if dry_run:
            info(f"would load  {name}")
            continue
        result = subprocess.run(["ssh-add", str(path)], check=False)
        if result.returncode == 0:
            info(f"loaded  {name}")
        else:
            warn(f"failed to load {name}")
            status = EXIT_DIFF
    return status


# --------------------------------------------------------------- config commands


def _config_rows(bw: Bw, settings: Settings) -> list[tuple[str, str, str]]:
    vault = bw.snapshot(settings.config_prefix)
    rows: list[tuple[str, str, str]] = []
    seen = set()

    for rel in local_config_files(settings):
        check_rel_representable(settings, rel)
        item_name = config_item_name(settings, rel)
        seen.add(item_name)
        path = settings.ssh_dir / rel
        item = vault.get(item_name)
        if item is None:
            rows.append(("LOCAL_ONLY", item_name, rel))
            continue
        try:
            remote = decode_config(item["notes"])
        except (binascii.Error, ValueError):
            rows.append(("ERROR", item_name, rel))
            continue
        try:
            local = path.read_bytes()
        except OSError:
            rows.append(("ERROR", item_name, rel))
            continue
        rows.append(("SAME" if remote == local else "DIFF", item_name, rel))

    for item_name in sorted(vault):
        if item_name not in seen:
            rows.append(("BW_ONLY", item_name, "-"))
    return rows


def config_status(bw: Bw, settings: Settings, as_json: bool) -> int:
    rows = _config_rows(bw, settings)
    if as_json:
        print(
            json.dumps(
                [{"status": s, "item": i, "file": f} for s, i, f in rows], indent=2
            )
        )
    else:
        print(f"{'STATUS':<11} {'ITEM':<40} FILE")
        for status, item_name, rel in rows:
            print(f"{status:<11} {item_name:<40} {rel}")
    return EXIT_OK if all(s == "SAME" for s, _, _ in rows) else EXIT_DIFF


def config_push(
    bw: Bw, settings: Settings, only: list[str] | None, dry_run: bool
) -> int:
    vault = bw.snapshot(settings.config_prefix)
    status = EXIT_OK
    for rel in _select(local_config_files(settings), only):
        check_rel_representable(settings, rel)
        item_name = config_item_name(settings, rel)
        notes = encode_config((settings.ssh_dir / rel).read_bytes())
        existing = vault.get(item_name)
        if existing is not None and existing["notes"] == notes.decode("utf-8"):
            info(f"unchanged  {item_name}")
            continue
        if dry_run:
            info(f"would {'update' if existing else 'create'}  {item_name}")
            continue
        try:
            if existing is None:
                bw.create(item_name, notes)
                info(f"created  {item_name}")
            else:
                bw.edit(existing, notes)
                info(f"updated  {item_name}")
        except BwError as exc:
            warn(f"failed on {item_name}: {exc}")
            status = EXIT_DIFF
    return status


def _ssh_config_parses(path: Path) -> bool:
    result = subprocess.run(
        ["ssh", "-G", "-F", str(path), "localhost"],
        capture_output=True,
        timeout=30,
        check=False,
    )
    return result.returncode == 0


class ConfigWriteError(Exception):
    """A config file was refused or could not be written."""


def install_config(
    settings: Settings, rel: str, content: bytes, force: bool, dry_run: bool
) -> str:
    """Install one config file, refusing anything that could break ssh."""
    target = settings.ssh_dir / rel
    real_target = Path(os.path.realpath(target))
    root = Path(os.path.realpath(settings.ssh_dir))
    if root not in real_target.parents:
        raise ConfigWriteError(f"refusing {rel}: resolves outside {settings.ssh_dir}")

    if target.is_file() and target.read_bytes() == content:
        return "unchanged"
    if not content and target.is_file() and target.stat().st_size and not force:
        raise ConfigWriteError(
            f"refusing {rel}: vault content is empty, local file is not"
        )
    if dry_run:
        return "would restore"

    directory = real_target.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target_mode = (
        stat.S_IMODE(real_target.stat().st_mode) if real_target.exists() else 0o600
    )
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".sshvault.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        # Validate before touching anything the user depends on: a malformed
        # config would break SSH access.
        if not _ssh_config_parses(Path(tmp_name)):
            raise ConfigWriteError(f"refusing {rel}: ssh config syntax check failed")
        os.chmod(tmp_name, target_mode)
        # Back up the OLD content, before the replace. Hidden so ssh's
        # `Include <dir>/*` glob does not pick it up.
        backup_name = backup_file(target, hidden=True).name if target.exists() else ""
        os.replace(tmp_name, real_target)
        tmp_name = ""
    finally:
        if tmp_name:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_name)

    return f"restored (backed up -> {backup_name})" if backup_name else "restored"


def config_pull(
    bw: Bw,
    settings: Settings,
    only: list[str] | None,
    dry_run: bool,
    allow_new: bool,
    force: bool,
) -> int:
    vault = bw.snapshot(settings.config_prefix)
    status = EXIT_OK

    for rel in _select(local_config_files(settings), only):
        check_rel_representable(settings, rel)
        item = vault.get(config_item_name(settings, rel))
        if item is None:
            info(f"no Bitwarden item for {rel}")
            continue
        try:
            content = decode_config(item["notes"])
            info(f"{install_config(settings, rel, content, force, dry_run)}  {rel}")
        except (ConfigWriteError, UnsafePathError) as exc:
            warn(str(exc))
            status = EXIT_DIFF
        except (binascii.Error, ValueError):
            warn(f"refusing {rel}: vault payload is not valid base64")
            status = EXIT_DIFF

    if allow_new:
        for item_name in sorted(vault):
            rel = item_name[len(settings.config_prefix) :].replace("__", "/")
            if not validate_rel(rel, settings.ssh_dir):
                warn(f"cannot map {item_name} to a safe path, skipping")
                continue
            if (settings.ssh_dir / rel).exists():
                continue
            try:
                content = decode_config(vault[item_name]["notes"])
                info(f"{install_config(settings, rel, content, force, dry_run)}  {rel}")
            except (ConfigWriteError, UnsafePathError) as exc:
                warn(str(exc))
                status = EXIT_DIFF
    return status
