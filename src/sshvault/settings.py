"""Resolution of where sshvault looks, and what it calls things.

Everything the tool assumes about the filesystem and the vault naming lives
here, so the rest of the code never hardcodes ``~/.ssh`` or an item prefix.
Values resolve in this order: command-line flag, then environment variable,
then the built-in default.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

KEYS_PREFIX_DEFAULT = "SSHKeys__"
CONFIG_PREFIX_DEFAULT = "SSHConfig__"
MAIN_CONFIG_DEFAULT = "config"
BACKUP_MARKER = ".bak"

EXIT_OK = 0
EXIT_DIFF = 1
EXIT_FATAL = 2


@dataclass(frozen=True)
class Settings:
    """Everything filesystem- and naming-related, resolved once per run."""

    ssh_dir: Path
    keys_dir: Path
    config_dir: Path
    main_config: str = MAIN_CONFIG_DEFAULT
    keys_prefix: str = KEYS_PREFIX_DEFAULT
    config_prefix: str = CONFIG_PREFIX_DEFAULT
    unlock_cmd: str | None = None

    def __post_init__(self) -> None:
        # frozen dataclass: normalise through object.__setattr__.
        object.__setattr__(self, "ssh_dir", Path(self.ssh_dir).expanduser())
        object.__setattr__(self, "keys_dir", Path(self.keys_dir).expanduser())
        object.__setattr__(self, "config_dir", Path(self.config_dir).expanduser())

    def rel_path(self, path: Path) -> str:
        """Path relative to the SSH dir, always with forward slashes.

        The vault key must be identical on every OS, so this never uses the
        platform separator.
        """
        try:
            return path.relative_to(self.ssh_dir).as_posix()
        except ValueError as exc:
            raise ValueError(f"{path} is outside {self.ssh_dir}") from exc


def _pick(flag: str | None, env_name: str, default):
    """Flag first, then environment, then default."""
    if flag:
        return flag
    return os.environ.get(env_name) or default


def resolve_settings(args) -> Settings:
    """Build Settings from parsed CLI args, falling back to env and defaults."""
    ssh_dir = Path(
        _pick(
            getattr(args, "ssh_dir", None),
            "SSHVAULT_SSH_DIR",
            Path.home() / ".ssh",
        )
    )
    keys_dir = Path(
        _pick(
            getattr(args, "keys_dir", None),
            "SSHVAULT_KEYS_DIR",
            ssh_dir / "keys",
        )
    )
    config_dir = Path(
        _pick(
            getattr(args, "config_dir", None),
            "SSHVAULT_CONFIG_DIR",
            ssh_dir / "config.d",
        )
    )
    return Settings(
        ssh_dir=ssh_dir,
        keys_dir=keys_dir,
        config_dir=config_dir,
        main_config=_pick(
            getattr(args, "main_config", None),
            "SSHVAULT_MAIN_CONFIG",
            MAIN_CONFIG_DEFAULT,
        ),
        keys_prefix=_pick(
            getattr(args, "keys_prefix", None),
            "SSHVAULT_KEYS_PREFIX",
            KEYS_PREFIX_DEFAULT,
        ),
        config_prefix=_pick(
            getattr(args, "config_prefix", None),
            "SSHVAULT_CONFIG_PREFIX",
            CONFIG_PREFIX_DEFAULT,
        ),
        unlock_cmd=_pick(
            getattr(args, "unlock_cmd", None), "SSHVAULT_UNLOCK_CMD", None
        ),
    )
