"""Command-line interface."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import os
import resource
import sys
import tempfile
from pathlib import Path

from . import __version__, commands
from .bw import Bw, BwError, get_session
from .localfs import UnsafePathError
from .output import PROG, set_quiet
from .settings import EXIT_FATAL, resolve_settings


class _Lock:
    """Exclusive lock so two runs cannot fight over the vault or the tty."""

    def __enter__(self):
        runtime = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
        path = Path(runtime) / f"{PROG}.lock"
        self._fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX)
        except OSError:
            os.close(self._fd)
            raise
        return self

    def __exit__(self, *_exc):
        fcntl.flock(self._fd, fcntl.LOCK_UN)
        os.close(self._fd)
        return False


def _add_location_options(parser: argparse.ArgumentParser) -> None:
    """Paths and vault naming. Each also has an environment variable."""
    group = parser.add_argument_group("locations and naming")
    group.add_argument(
        "--config-file",
        metavar="PATH",
        help="config file (default: ~/.config/sshvault/config; "
        "env SSHVAULT_CONFIG_FILE)",
    )
    group.add_argument(
        "--ssh-dir",
        metavar="PATH",
        help="SSH directory (default: ~/.ssh; env SSHVAULT_SSH_DIR)",
    )
    group.add_argument(
        "--keys-dir",
        metavar="PATH",
        help="private key directory (default: <ssh-dir>/keys; env SSHVAULT_KEYS_DIR)",
    )
    group.add_argument(
        "--config-dir",
        metavar="PATH",
        help="extra config directory (default: <ssh-dir>/config.d; "
        "env SSHVAULT_CONFIG_DIR)",
    )
    group.add_argument(
        "--main-config",
        metavar="NAME",
        help="main config file name (default: config; env SSHVAULT_MAIN_CONFIG)",
    )
    group.add_argument(
        "--keys-prefix",
        metavar="PREFIX",
        help="vault item prefix for keys (default: SSHKeys__; env SSHVAULT_KEYS_PREFIX)",
    )
    group.add_argument(
        "--config-prefix",
        metavar="PREFIX",
        help="vault item prefix for configs "
        "(default: SSHConfig__; env SSHVAULT_CONFIG_PREFIX)",
    )
    group.add_argument(
        "--unlock-cmd",
        metavar="CMD",
        help="command that unlocks Bitwarden and prints the path of an env file "
        "containing BW_SESSION (env SSHVAULT_UNLOCK_CMD)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Back up and restore SSH keys and config files with Bitwarden.",
        epilog="Exit codes: 0 no drift / all succeeded, 1 drift or partial failure, 2 fatal.",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    parser.add_argument(
        "--allow-root", action="store_true", help="permit running as root"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="suppress progress output"
    )
    _add_location_options(parser)

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="overview of keys and configs")

    keys = sub.add_parser("keys", help="manage SSH keys").add_subparsers(
        dest="subcommand", required=True
    )
    keys.add_parser("list", help="list local and vault keys")
    keys.add_parser("check", help="validate local keypairs and vault parity")
    for name, help_text in (
        ("push", "upload local keys"),
        ("pull", "restore keys locally"),
    ):
        cmd = keys.add_parser(name, help=help_text)
        cmd.add_argument("--dry-run", action="store_true")
        cmd.add_argument("--name", action="append", default=[], metavar="NAME")
    load = keys.add_parser("load", help="add keys to a running ssh-agent")
    load.add_argument("--name", action="append", default=[], metavar="NAME")
    load.add_argument("--dry-run", action="store_true")

    config = sub.add_parser("config", help="manage SSH config files").add_subparsers(
        dest="subcommand", required=True
    )
    cfg_status = config.add_parser("status", help="show config drift")
    cfg_status.add_argument("--json", action="store_true")
    for name, help_text in (
        ("push", "upload local configs"),
        ("pull", "restore configs locally"),
    ):
        cmd = config.add_parser(name, help=help_text)
        cmd.add_argument("--dry-run", action="store_true")
        cmd.add_argument("--file", action="append", default=[], metavar="REL")
        if name == "pull":
            cmd.add_argument("--allow-new", action="store_true")
            cmd.add_argument("--force", action="store_true")
    return parser


def dispatch(args: argparse.Namespace) -> int:
    settings = resolve_settings(args)

    if args.command == "status":
        bw = Bw(get_session(settings))
        print("== keys ==")
        keys_status = commands.keys_check(bw, settings)
        print("\n== config ==")
        config_status = commands.config_status(bw, settings, as_json=False)
        return max(keys_status, config_status)

    bw = Bw(get_session(settings))

    if args.command == "keys":
        if args.subcommand == "list":
            return commands.keys_list(bw, settings)
        if args.subcommand == "check":
            return commands.keys_check(bw, settings)
        if args.subcommand == "push":
            if args.dry_run:
                return commands.keys_push(bw, settings, args.name or None, True)
            with _Lock():
                return commands.keys_push(bw, settings, args.name or None, False)
        if args.subcommand == "pull":
            if args.dry_run:
                return commands.keys_pull(bw, settings, args.name or None, True)
            with _Lock():
                return commands.keys_pull(bw, settings, args.name or None, False)
        if args.subcommand == "load":
            return commands.keys_load(settings, args.name or None, args.dry_run)

    if args.command == "config":
        if args.subcommand == "status":
            return commands.config_status(bw, settings, args.json)
        if args.subcommand == "push":
            if args.dry_run:
                return commands.config_push(bw, settings, args.file or None, True)
            with _Lock():
                return commands.config_push(bw, settings, args.file or None, False)
        if args.subcommand == "pull":
            if args.dry_run:
                return commands.config_pull(
                    bw, settings, args.file or None, True, args.allow_new, args.force
                )
            with _Lock():
                return commands.config_pull(
                    bw, settings, args.file or None, False, args.allow_new, args.force
                )

    raise BwError(f"unhandled command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_quiet(args.quiet)

    os.umask(0o077)
    with contextlib.suppress(ValueError, OSError):
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

    if os.geteuid() == 0 and not args.allow_root:
        print(
            f"{PROG}: refusing to run as root (use --allow-root to override)",
            file=sys.stderr,
        )
        return EXIT_FATAL

    try:
        return dispatch(args)
    except (
        BwError,
        UnsafePathError,
        commands.ConfigWriteError,
        ValueError,
    ) as exc:
        print(f"{PROG}: error: {exc}", file=sys.stderr)
        return getattr(exc, "code", EXIT_FATAL)
    except KeyboardInterrupt:
        print(f"{PROG}: interrupted", file=sys.stderr)
        return EXIT_FATAL


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
