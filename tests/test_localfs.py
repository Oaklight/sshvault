"""Local filesystem helpers: discovery, safe writes, backups, path guards."""

from __future__ import annotations

import base64
import glob
import json
import stat
import subprocess
from pathlib import Path

import pytest

from sshvault.localfs import (
    PUB_ERROR,
    PUB_OK,
    PUB_PASSPHRASE,
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
from sshvault.settings import Settings


def make_settings(tmp_path: Path) -> Settings:
    return Settings(
        ssh_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        config_dir=tmp_path / "config.d",
    )


def make_keypair(path: Path, passphrase: str = "") -> None:
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", passphrase, "-f", str(path)],
        capture_output=True,
        check=True,
    )


# ------------------------------------------------------------------- discovery


def test_enumerate_private_keys_skips_pub_and_backups(tmp_path):
    s = make_settings(tmp_path)
    s.keys_dir.mkdir()
    for name in ("alpha", "alpha.pub", "alpha.bak.20260101", "beta", "beta.pub"):
        (s.keys_dir / name).write_text("x")
    (s.keys_dir / "adir").mkdir()
    assert enumerate_private_keys(s) == ["alpha", "beta"]


def test_enumerate_private_keys_missing_dir_is_empty(tmp_path):
    assert enumerate_private_keys(make_settings(tmp_path)) == []


def test_local_config_files_skips_backups(tmp_path):
    s = make_settings(tmp_path)
    (s.ssh_dir / "config").write_text("x")
    s.config_dir.mkdir()
    for name in ("cloud", "cloud.bak.20260101", "aur"):
        (s.config_dir / name).write_text("x")
    assert local_config_files(s) == ["config", "config.d/aur", "config.d/cloud"]


def test_local_config_files_tolerates_missing_config(tmp_path):
    assert local_config_files(make_settings(tmp_path)) == []


# ---------------------------------------------------------------------- naming


def test_config_item_name_uses_double_underscore_for_separators(tmp_path):
    s = make_settings(tmp_path)
    assert config_item_name(s, "config") == "SSHConfig__config"
    assert config_item_name(s, "config.d/cloud") == "SSHConfig__config.d__cloud"


def test_config_item_name_respects_a_custom_prefix(tmp_path):
    s = Settings(
        ssh_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        config_dir=tmp_path / "config.d",
        config_prefix="CFG__",
    )
    assert config_item_name(s, "config.d/x") == "CFG__config.d__x"


def test_check_rel_representable_rejects_embedded_double_underscore(tmp_path):
    s = make_settings(tmp_path)
    with pytest.raises(UnsafePathError):
        check_rel_representable(s, "config.d/a__b")
    check_rel_representable(s, "config.d/a-b_c.d")  # single underscores are fine


# -------------------------------------------------------------- path guarding


@pytest.mark.parametrize("rel", ["config", "config.d/cloud", "config.d/anl-bypass"])
def test_validate_rel_accepts_plain_relative_paths(rel, tmp_path):
    assert validate_rel(rel, tmp_path)


@pytest.mark.parametrize(
    "rel",
    [
        "",
        "/etc/passwd",
        "../escape",
        "config.d/../../escape",
        "-flag",
        "a b",
        "a;b",
        "ab\x00",
    ],
)
def test_validate_rel_rejects_unsafe_paths(rel, tmp_path):
    assert not validate_rel(rel, tmp_path)


def test_validate_rel_rejects_symlink_escaping_the_tree(tmp_path):
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    (ssh_dir / "link").symlink_to(outside)
    assert not validate_rel("link/evil", ssh_dir)


# ------------------------------------------------------- writing and backups


def test_atomic_write_sets_mode_and_replaces(tmp_path):
    target = tmp_path / "key"
    atomic_write(target, b"first", 0o600)
    assert target.read_bytes() == b"first"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600

    atomic_write(target, b"second", 0o600)
    assert target.read_bytes() == b"second"


def test_atomic_write_leaves_no_temp_files_behind(tmp_path):
    atomic_write(tmp_path / "key", b"data", 0o600)
    assert [p.name for p in tmp_path.iterdir()] == ["key"]


def test_backup_file_preserves_mode_and_refuses_to_clobber(tmp_path):
    target = tmp_path / "key"
    target.write_bytes(b"original")
    target.chmod(0o600)

    backup = backup_file(target)
    assert backup.read_bytes() == b"original"
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert backup.name.startswith("key.bak.")

    target.write_bytes(b"changed")
    with pytest.raises(FileExistsError):
        backup_file(target)


def test_hidden_backup_stays_out_of_a_star_glob(tmp_path):
    """A main config does `Include <dir>/*`, and `*` skips leading dots.

    A visible backup of a config file would otherwise be handed to ssh's parser.
    `glob.glob` mirrors the glob(3) semantics ssh relies on; pathlib's glob()
    matches dotfiles (Python 3.13+) and is therefore the wrong proxy here.
    """
    target = tmp_path / "cloud"
    target.write_bytes(b"data")
    backup = backup_file(target, hidden=True)
    assert backup.name.startswith(".cloud.bak.")
    assert glob.glob(str(tmp_path / "*")) == [str(target)]


# --------------------------------------------------------- derived key lookup


def test_key_material_ignores_the_comment():
    """Only the type+blob matters; a differing comment is not a key mismatch."""
    assert key_material(b"ssh-ed25519 AAAA one@host\n") == b"ssh-ed25519 AAAA"
    assert key_material(b"ssh-ed25519 AAAA other@host\n") == b"ssh-ed25519 AAAA"
    assert key_material(b"ssh-ed25519 BBBB one@host\n") != key_material(
        b"ssh-ed25519 AAAA one@host\n"
    )


def test_derive_public_key_reports_passphrase_protection(tmp_path):
    key = tmp_path / "protected"
    make_keypair(key, "hunter2")
    status, data = derive_public_key(key)
    assert status == PUB_PASSPHRASE
    assert data == b""


def test_derive_public_key_matches_the_pub_file_for_unprotected_keys(tmp_path):
    key = tmp_path / "plain"
    make_keypair(key, "")
    status, derived = derive_public_key(key)
    assert status == PUB_OK
    assert derived == (tmp_path / "plain.pub").read_bytes()


def test_derive_public_key_reports_corrupt_keys(tmp_path):
    key = tmp_path / "corrupt"
    key.write_bytes(b"not a key\n")
    status, _ = derive_public_key(key)
    assert status == PUB_ERROR


def test_local_key_notes_builds_the_vault_payload(tmp_path):
    s = make_settings(tmp_path)
    s.keys_dir.mkdir()
    make_keypair(s.keys_dir / "k")
    notes, reason = local_key_notes(s, "k")
    assert reason == PUB_OK
    assert notes is not None
    fields = json.loads(base64.b64decode(notes))
    assert [f["name"] for f in fields] == ["public_key", "private_key"]


def test_local_key_notes_uses_the_pub_file_when_present(tmp_path):
    s = make_settings(tmp_path)
    s.keys_dir.mkdir()
    make_keypair(s.keys_dir / "k", "secret")
    notes, reason = local_key_notes(s, "k")
    assert reason == PUB_OK
    assert notes is not None


def test_local_key_notes_without_pub_and_locked_is_not_buildable(tmp_path):
    s = make_settings(tmp_path)
    s.keys_dir.mkdir()
    make_keypair(s.keys_dir / "k", "secret")
    (s.keys_dir / "k.pub").unlink()
    notes, reason = local_key_notes(s, "k")
    assert notes is None
    assert reason == PUB_PASSPHRASE
