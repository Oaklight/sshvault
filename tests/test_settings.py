"""Settings resolution: flag beats env, env beats config file, file beats default."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from sshvault.settings import (
    CONFIG_PREFIX_DEFAULT,
    KEYS_PREFIX_DEFAULT,
    MAIN_CONFIG_DEFAULT,
    Settings,
    default_config_file,
    load_config_file,
    parse_config_file,
    resolve_settings,
)

ENV_VARS = (
    "SSHVAULT_SSH_DIR",
    "SSHVAULT_KEYS_DIR",
    "SSHVAULT_CONFIG_DIR",
    "SSHVAULT_MAIN_CONFIG",
    "SSHVAULT_KEYS_PREFIX",
    "SSHVAULT_CONFIG_PREFIX",
    "SSHVAULT_UNLOCK_CMD",
    "SSHVAULT_CONFIG_FILE",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    """Never read the developer's real config file."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _args(**overrides) -> argparse.Namespace:
    base = {
        "config_file": None,
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


def _write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "config"
    path.write_text(body, encoding="utf-8")
    return path


# ------------------------------------------------------------------ parsing


def test_parse_config_file_reads_key_value_pairs():
    text = "ssh_dir = /tmp/ssh\nunlock_cmd=bw-unlock\n"
    assert parse_config_file(text) == {
        "ssh_dir": "/tmp/ssh",
        "unlock_cmd": "bw-unlock",
    }


def test_parse_config_file_ignores_comments_blanks_and_junk():
    text = "\n# a comment\n   \nnot an assignment\n  main_config = config  \n"
    assert parse_config_file(text) == {"main_config": "config"}


def test_parse_config_file_strips_quotes_and_lowercases_keys():
    assert parse_config_file('Unlock_Cmd = "bw -x"\n') == {"unlock_cmd": "bw -x"}


def test_load_config_file_missing_is_not_an_error(tmp_path):
    assert load_config_file(tmp_path / "nope") == {}


def test_load_config_file_warns_about_unknown_keys(tmp_path, capsys):
    path = _write_config(tmp_path, "unlock_cmd=bw\nnot_a_setting=1\n")
    assert load_config_file(path) == {"unlock_cmd": "bw"}
    assert "unknown key" in capsys.readouterr().err


def test_default_config_file_honours_xdg_config_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    assert default_config_file() == tmp_path / "cfg" / "sshvault" / "config"


# ---------------------------------------------------------------- precedence


def test_defaults():
    s = resolve_settings(_args())
    assert s.ssh_dir == Path.home() / ".ssh"
    assert s.keys_dir == Path.home() / ".ssh" / "keys"
    assert s.config_dir == Path.home() / ".ssh" / "config.d"
    assert s.main_config == MAIN_CONFIG_DEFAULT
    assert s.keys_prefix == KEYS_PREFIX_DEFAULT
    assert s.config_prefix == CONFIG_PREFIX_DEFAULT
    assert s.unlock_cmd is None


def test_config_file_beats_defaults(tmp_path):
    path = _write_config(
        tmp_path,
        "ssh_dir = /srv/ssh\nkeys_prefix = KEYS__\nunlock_cmd = bw-unlock-session\n",
    )
    s = resolve_settings(_args(config_file=str(path)))
    assert s.ssh_dir == Path("/srv/ssh")
    assert s.keys_dir == Path("/srv/ssh/keys")  # derived from the file's ssh_dir
    assert s.keys_prefix == "KEYS__"
    assert s.unlock_cmd == "bw-unlock-session"


def test_environment_beats_config_file(monkeypatch, tmp_path):
    path = _write_config(tmp_path, "unlock_cmd=from-file\n")
    monkeypatch.setenv("SSHVAULT_UNLOCK_CMD", "from-env")
    assert resolve_settings(_args(config_file=str(path))).unlock_cmd == "from-env"


def test_flag_beats_environment_and_config_file(monkeypatch, tmp_path):
    path = _write_config(tmp_path, "unlock_cmd=from-file\n")
    monkeypatch.setenv("SSHVAULT_UNLOCK_CMD", "from-env")
    s = resolve_settings(_args(config_file=str(path), unlock_cmd="from-flag"))
    assert s.unlock_cmd == "from-flag"


def test_default_config_file_path_is_used(monkeypatch, tmp_path):
    xdg = tmp_path / "xdg"
    (xdg / "sshvault").mkdir(parents=True)
    (xdg / "sshvault" / "config").write_text("unlock_cmd=bw-unlock-session\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    assert resolve_settings(_args()).unlock_cmd == "bw-unlock-session"


def test_config_file_env_var_selects_the_file(monkeypatch, tmp_path):
    path = _write_config(tmp_path, "unlock_cmd=from-env-file\n")
    monkeypatch.setenv("SSHVAULT_CONFIG_FILE", str(path))
    assert resolve_settings(_args()).unlock_cmd == "from-env-file"


def test_explicit_keys_and_config_dirs_override_the_ssh_dir(tmp_path):
    s = resolve_settings(
        _args(
            ssh_dir=str(tmp_path),
            keys_dir=str(tmp_path / "k"),
            config_dir=str(tmp_path / "c"),
        )
    )
    assert s.keys_dir == tmp_path / "k"
    assert s.config_dir == tmp_path / "c"


def test_tilde_is_expanded():
    s = resolve_settings(_args(ssh_dir="~/custom-ssh"))
    assert s.ssh_dir == Path.home() / "custom-ssh"


# -------------------------------------------------------------- rel_path


def test_rel_path_always_uses_forward_slashes(tmp_path):
    s = Settings(
        ssh_dir=tmp_path,
        keys_dir=tmp_path / "keys",
        config_dir=tmp_path / "config.d",
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
