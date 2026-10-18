"""Session env parsing and session-file trust checks."""

from __future__ import annotations

import os
import stat

import pytest

from sshvault.bw import BwError, parse_session_env, validate_session_file


def test_parse_session_env_reads_exports():
    text = "export BW_SESSION=abc123\nexport BW_SESSION_EXPIRES_AT=1791609674\n"
    assert parse_session_env(text) == {
        "BW_SESSION": "abc123",
        "BW_SESSION_EXPIRES_AT": "1791609674",
    }


def test_parse_session_env_tolerates_quotes_comments_and_blanks():
    text = '\n# comment\nBW_SESSION="quoted"\n\n  export  BW_SESSION_EXPIRES_AT = 42 \n'
    values = parse_session_env(text)
    assert values["BW_SESSION"] == "quoted"
    assert values["BW_SESSION_EXPIRES_AT"] == "42"


def test_parse_session_env_ignores_lines_without_equals():
    assert parse_session_env("not an assignment\n") == {}


def _session_file(tmp_path, mode=0o600, content="export BW_SESSION=x\n"):
    path = tmp_path / "bw-session.env"
    path.write_text(content)
    path.chmod(mode)
    return path


def test_validate_session_file_accepts_private_regular_file(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    path = _session_file(tmp_path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    validate_session_file(path)  # must not raise


def test_validate_session_file_rejects_group_readable(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    path = _session_file(tmp_path, mode=0o644)
    with pytest.raises(BwError, match="group/world"):
        validate_session_file(path)


def test_validate_session_file_rejects_symlink(tmp_path, monkeypatch):
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    real = _session_file(tmp_path)
    link = tmp_path / "link.env"
    link.symlink_to(real)
    with pytest.raises(BwError, match="symlink"):
        validate_session_file(link)


def test_validate_session_file_rejects_path_outside_runtime_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    (tmp_path / "runtime").mkdir()
    outside = tmp_path / "outside.env"
    outside.write_text("export BW_SESSION=x\n")
    outside.chmod(0o600)
    with pytest.raises(BwError, match="outside XDG_RUNTIME_DIR"):
        validate_session_file(outside)
