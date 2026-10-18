"""Settings resolution: flags beat environment, environment beats defaults."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from sshvault.settings import (
    CONFIG_PREFIX_DEFAULT,
    KEYS_PREFIX_DEFAULT,
    MAIN_CONFIG_DEFAULT,
    Settings,
    resolve_settings,
)


def _args(**overrides) -> argparse.Namespace:
    base = {
        "ssh_dir": None,
        "keys_dir": None,
        "config_dir": None,
        "main_config": None,
        "keys_prefix": None,
        "config_prefix": None,
        "unlock_cmd": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_defaults(monkeypatch):
    for name in (
        "SSHVAULT_SSH_DIR",
        "SSHVAULT_KEYS_DIR",
        "SSHVAULT_CONFIG_DIR",
        "SSHVAULT_MAIN_CONFIG",
        "SSHVAULT_KEYS_PREFIX",
        "SSHVAULT_CONFIG_PREFIX",
        "SSHVAULT_UNLOCK_CMD",
    ):
        monkeypatch.delenv(name, raising=False)
    s = resolve_settings(_args())
    assert s.ssh_dir == Path.home() / ".ssh"
    assert s.keys_dir == Path.home() / ".ssh" / "keys"
    assert s.config_dir == Path.home() / ".ssh" / "config.d"
    assert s.main_config == MAIN_CONFIG_DEFAULT
    assert s.keys_prefix == KEYS_PREFIX_DEFAULT
    assert s.config_prefix == CONFIG_PREFIX_DEFAULT
    assert s.unlock_cmd is None


def test_environment_beats_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("SSHVAULT_SSH_DIR", str(tmp_path / "dotssh"))
    monkeypatch.setenv("SSHVAULT_KEYS_PREFIX", "KEYS__")
    monkeypatch.setenv("SSHVAULT_UNLOCK_CMD", "helper --flag")
    s = resolve_settings(_args())
    assert s.ssh_dir == tmp_path / "dotssh"
    assert s.keys_dir == tmp_path / "dotssh" / "keys"
    assert s.keys_prefix == "KEYS__"
    assert s.unlock_cmd == "helper --flag"


def test_flags_beat_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("SSHVAULT_SSH_DIR", "/from/env")
    s = resolve_settings(_args(ssh_dir=str(tmp_path / "explicit")))
    assert s.ssh_dir == tmp_path / "explicit"


def test_explicit_keys_and_config_dirs_override_the_ssh_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("SSHVAULT_KEYS_DIR", raising=False)
    monkeypatch.delenv("SSHVAULT_CONFIG_DIR", raising=False)
    s = resolve_settings(
        _args(
            ssh_dir=str(tmp_path),
            keys_dir=str(tmp_path / "k"),
            config_dir=str(tmp_path / "c"),
        )
    )
    assert s.keys_dir == tmp_path / "k"
    assert s.config_dir == tmp_path / "c"


def test_tilde_is_expanded(monkeypatch):
    monkeypatch.delenv("SSHVAULT_SSH_DIR", raising=False)
    s = resolve_settings(_args(ssh_dir="~/custom-ssh"))
    assert s.ssh_dir == Path.home() / "custom-ssh"


def test_rel_path_always_uses_forward_slashes(tmp_path):
    s = Settings(
        ssh_dir=tmp_path, keys_dir=tmp_path / "keys", config_dir=tmp_path / "config.d"
    )
    assert s.rel_path(tmp_path / "config.d" / "cloud") == "config.d/cloud"


def test_rel_path_rejects_paths_outside_the_ssh_dir(tmp_path):
    s = Settings(
        ssh_dir=tmp_path / "ssh",
        keys_dir=tmp_path / "ssh" / "keys",
        config_dir=tmp_path / "ssh" / "config.d",
    )
    with pytest.raises(ValueError, match="outside"):
        s.rel_path(Path("/etc/passwd"))
