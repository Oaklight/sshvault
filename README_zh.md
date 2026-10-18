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

**sshvault** — 用 Bitwarden 备份和恢复你的 SSH 私钥**和** SSH 配置文件。

`sshvault` 把 `~/.ssh/keys/*`、`~/.ssh/config`、`~/.ssh/config.d/*` 备份进
Bitwarden，换机器时一条命令就能恢复。它是两个旧工具的小型零依赖替代品：
`ssh-manager`（管密钥）和一段手写的配置同步脚本。

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

## 为什么再造一个

- **一个工具管两样东西。** 密钥和配置在 vault 里的存法几乎一样，没必要跑两个程序。
- **密钥不会出现在 `ps` 里。** 载荷通过 stdin 传给 `bw`。原来的 `ssh-manager`
  把载荷当命令行参数传，本机任何用户都能从进程表里读到你的私钥。
- **不会静默覆盖。** 每次恢复都先备份旧文件，内容一致就跳过，无法校验的内容一律拒绝写入。
- **配置文件落盘前先做语法检查。** 一个坏掉的 `~/.ssh/config` 意味着哪里都登不上；
  `sshvault` 会先对候选文件跑 `ssh -G -F <tmp> localhost`，解析不过就中止。

## 依赖

- Linux
- [Bitwarden CLI](https://bitwarden.com/help/cli/)（`bw`）在 `$PATH` 中，且已登录
- `ssh`、`ssh-keygen`（`keys load` 另需 `ssh-add`）

## 安装

```console
pipx install sshvault
```

或

```console
pip install --user sshvault
```

## 快速开始

```console
# 解锁一次，sshvault 会复用 BW_SESSION
export BW_SESSION=$(bw unlock --raw)

# 看 vault 和本机有什么差异
sshvault status

# 上传本地密钥和配置
sshvault keys push
sshvault config push

# 在新机器上全部拉回来
sshvault keys pull
sshvault config pull --allow-new
```

## 命令

```
sshvault status                              密钥与配置总览
sshvault keys list                           列出本地与 vault 中的密钥
sshvault keys check                          校验密钥卫生与 vault 一致性
sshvault keys push   [--dry-run] [--name N]  上传本地密钥
sshvault keys pull   [--dry-run] [--name N]  从 vault 恢复密钥
sshvault keys load   [--dry-run] [--name N]  把密钥载入 ssh-agent
sshvault config status [--json]              查看配置漂移
sshvault config push   [--dry-run] [--file REL]
sshvault config pull   [--dry-run] [--file REL] [--allow-new] [--force]
```

退出码：`0` 无漂移/全部成功，`1` 有漂移或部分失败，`2` 致命错误。
`status` 只读且退出码可用，适合放进 shell 提示符或定时检查。

## vault 中的存储格式

两种条目约定，都是登录型条目（`type: 1`），`notes` 字段里放 base64：

| 条目名 | `notes` 内容 |
| --- | --- |
| `SSHKeys__<name>` | 紧凑 JSON `[{"name":"public_key","value":…},{"name":"private_key","value":…}]` 的 base64 |
| `SSHConfig__<path>` | 文件原文的 base64，`<path>` 是相对 `~/.ssh` 的路径，`/` 替换为 `__` |

两种格式都沿用自更早的工具，并保持逐字节兼容，已有 vault 无需迁移。

## 配置项

每个位置都同时提供命令行参数和环境变量，参数优先。

| 参数 | 环境变量 | 默认值 |
| --- | --- | --- |
| `--ssh-dir` | `SSHVAULT_SSH_DIR` | `~/.ssh` |
| `--keys-dir` | `SSHVAULT_KEYS_DIR` | `<ssh-dir>/keys` |
| `--config-dir` | `SSHVAULT_CONFIG_DIR` | `<ssh-dir>/config.d` |
| `--main-config` | `SSHVAULT_MAIN_CONFIG` | `config` |
| `--keys-prefix` | `SSHVAULT_KEYS_PREFIX` | `SSHKeys__` |
| `--config-prefix` | `SSHVAULT_CONFIG_PREFIX` | `SSHConfig__` |
| `--unlock-cmd` | `SSHVAULT_UNLOCK_CMD` | 无 |

### 解锁

如果环境里的 `BW_SESSION` 已解锁就直接用；否则运行配置的解锁助手，后者需要打印一个
包含 `BW_SESSION` 的 env 文件路径（可选 `BW_SESSION_EXPIRES_AT`）：

```console
export SSHVAULT_UNLOCK_CMD="my-bw-unlock"   # 打印 /run/user/1000/bw-session.env
```

会话文件必须是普通文件、非符号链接、属主为你、权限 `0600`，否则拒绝使用。

## 安全说明

- vault 载荷一律走 **stdin** 传给 `bw`，绝不进 argv。
- `bw list items` 会把私钥读进内存；`sshvault` 绝不打印、记录或把条目内容拼进异常。
- 启动时关闭 core dump；默认拒绝以 root 运行（确有需要可加 `--allow-root`）。
- 私钥写 `0600`，公钥写 `0644`，都是同目录临时文件 + 原子 rename。
- 恢复前先备份旧文件。配置文件的备份故意加点号前缀：`~/.ssh/config` 通常有
  `Include ~/.ssh/config.d/*`，而该通配符不匹配点号开头，所以坏备份不会被喂给 ssh 解析。

## 限制

- 仅支持 Linux。代码用了 `fcntl`、`resource.setrlimit`、`os.geteuid`。
- 仅支持 Bitwarden。`ssh-manager` 的 1Password 和 S3 后端没有实现。
- `keys load` 需要运行中的 `ssh-agent`；不用 agent 的话忽略它即可。

## 许可证

MIT，见 [LICENSE](LICENSE)。
