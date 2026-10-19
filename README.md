<h1 align="center">sshvault</h1>

<p align="center">
  <a href="https://pypi.org/project/sshvault/"><img src="https://img.shields.io/pypi/v/sshvault?color=green" alt="PyPI"></a>
  <a href="https://github.com/Oaklight/sshvault/releases/latest"><img src="https://img.shields.io/github/v/release/Oaklight/sshvault?color=green" alt="Release"></a>
  <a href="https://github.com/Oaklight/sshvault/actions/workflows/ci.yml"><img src="https://github.com/Oaklight/sshvault/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT"></a>
</p>

<p align="center">
  <a href="README.md">English</a> | <a href="README_zh.md">中文</a>
</p>

**sshvault** — Back up and restore your SSH keys **and** SSH config files with Bitwarden.

`sshvault` keeps a copy of `~/.ssh/keys/*`, `~/.ssh/config` and `~/.ssh/config.d/*`
in your Bitwarden vault, so a new machine can be brought back to a working state
with one command. It is a small, dependency-free replacement for two previous
tools: `ssh-manager` (keys) and a hand-written config sync script.

```console
$ sshvault status
== keys ==
ok    work-ed25519         -
ok    personal             -
2 key(s) checked, no problems

== config ==
STATUS      ITEM                                     FILE
SAME        SSHConfig__config                        config
SAME        SSHConfig__config.d__cloud               config.d/cloud
```

## Why another one?

- **One tool for keys and configs.** The vault layout is nearly identical for
  both, so there is no reason to run two programs.
- **Secrets never reach `ps`.** Payloads are piped to `bw` on stdin. The
  original `ssh-manager` passed them as argv, where any local user could read
  your private keys out of the process table.
- **Nothing is overwritten silently.** Every restore backs up the old file
  first, skips files that already match, and refuses to write anything it
  cannot verify.
- **Config files are syntax-checked before they land.** A malformed
  `~/.ssh/config` means you cannot log in anywhere; `sshvault` runs
  `ssh -G -F <tmp> localhost` on the candidate file and aborts if it does not
  parse.

## Requirements

- Linux
- [Bitwarden CLI](https://bitwarden.com/help/cli/) (`bw`) on `$PATH`, logged in
- `ssh`, `ssh-keygen` (and `ssh-add` for `keys load`)

## Install

```console
pipx install sshvault
```

or

```console
pip install --user sshvault
```

## Quickstart

```console
# Unlock Bitwarden once; sshvault reuses BW_SESSION.
export BW_SESSION=$(bw unlock --raw)

# See what differs between the vault and this machine.
sshvault status

# Upload local keys and configs.
sshvault keys push
sshvault config push

# On a new machine, pull everything back.
sshvault keys pull
sshvault config pull --allow-new
```

## Commands

```
sshvault status                              overview of keys and configs
sshvault keys list                           local vs vault keys
sshvault keys check                          keypair hygiene and vault parity
sshvault keys push   [--dry-run] [--name N]  upload local keys
sshvault keys pull   [--dry-run] [--name N]  restore keys locally
sshvault keys load   [--dry-run] [--name N]  add keys to a running ssh-agent
sshvault config status [--json]              show config drift
sshvault config push   [--dry-run] [--file REL]
sshvault config pull   [--dry-run] [--file REL] [--allow-new] [--force]
```

Exit codes: `0` no drift / all succeeded, `1` drift or partial failure, `2`
fatal error. `status` is read-only and exit-code friendly, so it works in a
shell prompt or a cron check.

## Vault layout

Two item conventions, both login items (`type: 1`) whose `notes` field holds
base64:

| Item name | `notes` contains |
| --- | --- |
| `SSHKeys__<name>` | base64 of compact JSON `[{"name":"public_key","value":…},{"name":"private_key","value":…}]` |
| `SSHConfig__<path>` | base64 of the raw file, where `<path>` is relative to `~/.ssh` with `/` replaced by `__` |

Both formats are inherited from earlier tools and are preserved byte-for-byte,
so an existing vault keeps working without migration.

## Configuration

Each value resolves in this order: command-line flag, environment variable, key
in the config file, built-in default.

| Flag | Environment | Config key | Default |
| --- | --- | --- | --- |
| `--config-file` | `SSHVAULT_CONFIG_FILE` | — | `~/.config/sshvault/config` |
| `--ssh-dir` | `SSHVAULT_SSH_DIR` | `ssh_dir` | `~/.ssh` |
| `--keys-dir` | `SSHVAULT_KEYS_DIR` | `keys_dir` | `<ssh-dir>/keys` |
| `--config-dir` | `SSHVAULT_CONFIG_DIR` | `config_dir` | `<ssh-dir>/config.d` |
| `--main-config` | `SSHVAULT_MAIN_CONFIG` | `main_config` | `config` |
| `--keys-prefix` | `SSHVAULT_KEYS_PREFIX` | `keys_prefix` | `SSHKeys__` |
| `--config-prefix` | `SSHVAULT_CONFIG_PREFIX` | `config_prefix` | `SSHConfig__` |
| `--unlock-cmd` | `SSHVAULT_UNLOCK_CMD` | `unlock_cmd` | none |

### Config file

`~/.config/sshvault/config` is `key = value` (or `key=value`), one per line, with
`#` comments:

```ini
# Unlock Bitwarden through a helper that prints the env-file path.
unlock_cmd = bw-unlock-session
```

Prefer this over a `.bashrc` export: a shell profile is only read by
interactive shells, so cron, systemd units and non-bash shells never see it,
while the config file is read however the process was started. Environment
variables still override it, and flags override both.

### Unlocking

`sshvault` uses `BW_SESSION` if it is already set and unlocks. Otherwise it runs
the configured unlock helper, which must print the path of a shell env file
containing `BW_SESSION` (and optionally `BW_SESSION_EXPIRES_AT`):

```console
export SSHVAULT_UNLOCK_CMD="my-bw-unlock"   # prints /run/user/1000/bw-session.env
```

The session file is rejected unless it is a regular, non-symlink file owned by
you with mode `0600`.

## Security notes

- Vault payloads are written to `bw` on **stdin**, never argv.
- `bw list items` returns private keys in memory; `sshvault` never prints,
  logs, or interpolates item contents.
- Core dumps are disabled at startup and the tool refuses to run as root
  (override with `--allow-root` if you really mean it).
- Private keys are written `0600`, public keys `0644`, via a temp file in the
  same directory plus an atomic rename.
- Restores back up the previous file first. Backups of config files are
  dot-prefixed on purpose: `~/.ssh/config` normally does
  `Include ~/.ssh/config.d/*`, and that glob skips leading dots, so a corrupt
  backup can never be fed to ssh's parser.

## Limitations

- Linux only. The code uses `fcntl`, `resource.setrlimit` and `os.geteuid`.
- Bitwarden only. The 1Password and S3 backends of `ssh-manager` are not
  implemented.
- `keys load` needs a running `ssh-agent`; if you do not use one, ignore it.

## License

MIT. See [LICENSE](LICENSE).
