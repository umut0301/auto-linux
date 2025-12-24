# auto-linux

自动化 Linux 管理脚本，提供 WireGuard 服务端/客户端一体化管理与交互式菜单，适合 VPS 快速部署与日常维护。

## 功能概览

- WireGuard 管理
  - 初始化/安装服务端（自动生成密钥与配置）
  - 添加 / 查看 / 删除 客户端
  - 生成客户端配置文件与二维码（PNG 文件）
  - 自动选择可用客户端 IP
  - 修改监听端口、查看状态、配置 NAT 与转发
  - 卸载并清理 WireGuard 配置

## 脚本来源与说明

脚本路径：`auto-linux.sh`

该脚本为交互式 Bash 工具，内置菜单并自动适配主流发行版的包管理命令。

主要功能实现文件和目录（运行脚本后会创建）：

- /etc/wireguard/  — WireGuard 相关配置
- /etc/wireguard/clients/ — 每个客户端的密钥与配置目录

注意：脚本会根据发行版自动安装依赖（`wireguard`/`wireguard-tools`、`qrencode` 等）。

## 使用前提

- 需要 root 权限运行。
- 客户端名只允许 `[A-Za-z0-9._-]` 字符。

## 快速使用（交互式）

1) 在线一键运行（推荐先查看脚本内容再执行）：

- 使用 wget + bash：

```bash
sudo bash <(wget -qO- https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh)
```

- 使用 curl + bash（推荐）：

```bash
curl -fsSL https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh | sudo bash -s --
```

2) 更安全的步骤（先下载、审核、再执行）：

```bash
wget -O auto-linux.sh https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh
less auto-linux.sh       # 推荐人工检查脚本内容
sudo bash auto-linux.sh
```

3) 菜单功能示例：

```bash
# 进入主菜单后可选择：
# 1) 安装/初始化 WireGuard 服务端
# 2) 添加客户端（生成配置 + QR）
# 3) 列出客户端 / 查看配置与二维码 / 删除客户端
# 4) 修改端口 / 配置 NAT / 查看状态 / 卸载
```

## 非交互式 / 自动化 使用

脚本支持直接调用函数方式，但主要以菜单交互为主，自动化场景建议在受控环境中二次封装：

```bash
sudo bash auto-linux.sh
```

可通过环境变量设置服务端 Endpoint（用于客户端配置生成）：

```bash
WG_SERVER_ENDPOINT="1.2.3.4:51820" sudo bash auto-linux.sh wg_add_client alice
```

也可在服务端配置中添加注释（供脚本读取）：

```
# ServerPublicKey: <server_public_key>
# ServerEndpoint: 1.2.3.4:51820
```

## 功能优化重点（开发记录）

- 菜单流程优化：支持编号选择、自动列出现有接口/客户端、默认随机接口/端口/客户端名。
- 配置健壮性：Endpoint/公钥自动推导，接口/客户端名校验，生成配置权限收敛。
- NAT 与转发：自动读取网段并配置 iptables，避免空值导致的错误。
- 清理逻辑：卸载时停止所有 `wg-quick@<iface>` 并清理 `/etc/wireguard`。

## 常见问题与排查

- 404 或无法下载脚本：请确认 raw.githubusercontent.com 的 URL 形式正确，正确示例：
  - https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh
  错误示例（会导致 404）：
  - 包含 refs/heads 的 URL，例如 https://raw.githubusercontent.com/umut0301/auto-linux/refs/heads/main/auto-linux.sh

- 网络或 DNS 问题：某些网络环境（例如部分地区或VPS提供商）可能屏蔽 raw.githubusercontent.com 或 githubusercontent 的访问。可尝试切换到 curl 的 -4 参数或先在本地网络下载后再上传至 VPS。

- 权限问题：脚本需要 root 权限（脚本会检查并提示）。如果脚本提示无法写入 /etc/wireguard，确认是否使用 sudo 或以 root 身份运行。

- qrencode 未安装：二维码生成依赖 `qrencode`，脚本会尝试安装；若失败请手动安装后重新添加客户端。

- Endpoint 或服务器公钥缺失：若客户端配置中的 `Endpoint`/`PublicKey` 为空，请设置 `WG_SERVER_ENDPOINT` 或在服务端配置里添加 `# ServerEndpoint:` 与 `# ServerPublicKey:` 注释（或确保 `PrivateKey` 存在）。

## 安全与建议

- 在线一键运行会在目标机器以 root 权限执行远端脚本。建议下载并人工审查脚本内容后再运行。
- 如果你计划频繁在多个 VPS 上运行，建议在脚本中加入签名/哈希校验（例如 SHA256），在 README 中公布校验值，运行时先校验脚本完整性。

## 我可以为你做的事情

- 如果你希望，我可以：
  - 自动从公网 IP 生成 `ServerEndpoint`（可选参数/环境变量控制）；
  - 添加 `wg syncconf`/`wg-quick` 自动重载；
  - 为 README 增加更多示例与排错流程。
