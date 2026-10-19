"""Resolution of where sshvault looks, and what it calls things.

Everything the tool assumes about the filesystem and the vault naming lives
here, so the rest of the code never hardcodes ``~/.ssh`` or an item prefix.

Each value resolves in this order:

1. command-line flag
2. environment variable
3. key in the config file
4. built-in default

The config file exists so the tool works without shell configuration: a
``.bashrc`` export is invisible to cron, systemd, and non-bash shells, while a
config file is read no matter how the process was started.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .output import warn

KEYS_PREFIX_DEFAULT = "SSHKeys__"
CONFIG_PREFIX_DEFAULT = "SSHConfig__"
MAIN_CONFIG_DEFAULT = "config"
BACKUP_MARKER = ".bak"

EXIT_OK = 0
EXIT_DIFF = 1
EXIT_FATAL = 2

# Config-file key -> environment variable. Both name the same setting; the
# config file uses the bare snake_case form so it reads like a config file.
CONFIG_KEYS = {
    "ssh_dir": "SSHVAULT_SSH_DIR",
    "keys_dir": "SSHVAULT_KEYS_DIR",
    "config_dir": "SSHVAULT_CONFIG_DIR",
    "main_config": "SSHVAULT_MAIN_CONFIG",
    "keys_prefix": "SSHVAULT_KEYS_PREFIX",
    "config_prefix": "SSHVAULT_CONFIG_PREFIX",
    "unlock_cmd": "SSHVAULT_UNLOCK_CMD",
}


def default_config_file() -> Path:
    """``$XDG_CONFIG_HOME/sshvault/config``, defaulting to ``~/.config``."""
    base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "sshvault" / "config"


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


def parse_config_file(text: str) -> dict[str, str]:
    """Read ``key = value`` lines. Comments start with ``#``.

    A literal reader: the file is data, never evaluated. Keys are lowercased so
    ``Unlock_Cmd`` and ``unlock_cmd`` both work.
    """
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip().lower()] = value
    return values


def load_config_file(path: Path) -> dict[str, str]:
    """Load and validate the config file. A missing file is not an error."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        warn(f"cannot read config file {path}: {exc.strerror}")
        return {}

    values = parse_config_file(text)
    for key in values:
        if key not in CONFIG_KEYS:
            warn(f"unknown key in {path}: {key}")
    return {key: value for key, value in values.items() if key in CONFIG_KEYS}


def _pick(flag: str | None, config_key: str, config: dict[str, str], default):
    """Flag first, then environment, then config file, then default."""
    if flag:
        return flag
    env_value = os.environ.get(CONFIG_KEYS[config_key])
    if env_value:
        return env_value
    if config.get(config_key):
        return config[config_key]
    return default


def resolve_settings(args) -> Settings:
    """Build Settings from CLI args, environment, the config file and defaults."""
    config_file = Path(
        getattr(args, "config_file", None)
        or os.environ.get("SSHVAULT_CONFIG_FILE")
        or default_config_file()
    ).expanduser()
    config = load_config_file(config_file)

    ssh_dir = Path(
        _pick(
            getattr(args, "ssh_dir", None),
            "ssh_dir",
            config,
            Path.home() / ".ssh",
        )
    )
    keys_dir = Path(
        _pick(
            getattr(args, "keys_dir", None),
            "keys_dir",
            config,
            ssh_dir / "keys",
        )
    )
    config_dir = Path(
        _pick(
            getattr(args, "config_dir", None),
            "config_dir",
            config,
            ssh_dir / "config.d",
        )
    )
    return Settings(
        ssh_dir=ssh_dir,
        keys_dir=keys_dir,
        config_dir=config_dir,
        main_config=_pick(
            getattr(args, "main_config", None),
            "main_config",
            config,
            MAIN_CONFIG_DEFAULT,
        ),
        keys_prefix=_pick(
            getattr(args, "keys_prefix", None),
            "keys_prefix",
            config,
            KEYS_PREFIX_DEFAULT,
        ),
        config_prefix=_pick(
            getattr(args, "config_prefix", None),
            "config_prefix",
            config,
            CONFIG_PREFIX_DEFAULT,
        ),
        unlock_cmd=_pick(
            getattr(args, "unlock_cmd", None),
            "unlock_cmd",
            config,
            None,
        ),
    )
