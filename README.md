# auto-linux

自动化 Linux 管理脚本，当前聚焦 WireGuard 与 x-ui 面板管理，目标是方便 VPS 的快速部署与日常管理。

## 功能概览

- WireGuard
  - 安装/初始化服务端（自动生成密钥与配置文件）
  - 添加 / 查看 / 删除 客户端
  - 生成客户端配置文件与二维码（终端渲染 + PNG 文件）
  - 配置 NAT 与 IP 转发（自动检测公网接口并添加 iptables 规则）
  - 修改监听端口、查看状态、卸载
- x-ui 面板
  - 使用官方脚本进行安装与管理（通过脚本内菜单调用）
- 系统信息与环境检查
  - 发行版信息、内核版本、公网 IP、磁盘占用等
- 交互式菜单
  - 提供交互式菜单，按提示执行对应的安装 / 管理 / 卸载 操作

## 脚本来源与说明

脚本路径：`auto-linux.sh`

该脚本为交互式 Bash 脚本，自动适配主流发行版（Debian/Ubuntu、CentOS/RHEL、Fedora、Arch、openSUSE 等），并封装了常见的包管理命令（apt/dnf/pacman/zypper）。

主要功能实现文件和目录（运行脚本后会创建）：

- /etc/wireguard/  — WireGuard 相关配置
- /etc/wireguard/clients/ — 每个客户端的密钥与配置目录

注意：脚本会在运行时尝试安装 `wireguard`/`wireguard-tools`、`qrencode` 等工具，方便生成二维码与管理。

## 快速使用（交互式）

1) 在线一键运行（推荐先查看脚本内容再执行）：

- 使用 wget + bash：

```bash
bash <(wget -qO- https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh)
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

3) 脚本为交互式菜单，示例操作：

- 安装/初始化 WireGuard 服务端：运行脚本 → 选择 1 → 输入接口名（默认 wg0）、服务器内网 IP（默认 10.0.0.1）与端口（默认 51820）。
- 添加客户端：选择 WireGuard 菜单中的选项 2，输入客户端名，脚本会生成密钥、预共享密钥、客户端配置并生成二维码（如安装了 qrencode）。
- 列出/查看/删除 客户端：使用菜单选项 3/4/5。

## 非交互式 / 自动化 使用

当前脚本以交互式菜单为主；如果你需要通过脚本自动完成某些操作（例如在部署脚本中自动添加客户端），可以：

- 手动下载脚本并从中复制对应函数，比如 `wg_add_client`、`wg_create_server_conf` 等，单独运行这些函数（注意：脚本的 `main` 会在执行时进入菜单循环，若要在脚本内部直接调用函数请在本地修改脚本以支持命令行参数或在交互式环境中以 `source` + 调用函数的方式运行）。

示例（不推荐在未经审查的远程环境中直接运行）：

```bash
# 下载并打开脚本交互式运行（推荐）
wget -O auto-linux.sh https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh
less auto-linux.sh
sudo bash auto-linux.sh

# 或者（高级，需谨慎）：
# 1) 下载并在受控环境中修改脚本以接受命令行参数
# 2) 通过修改后的脚本传参实现自动化
```

## 常见问题与排查

- 404 或无法下载脚本：请确认 raw.githubusercontent.com 的 URL 形式正确，正确示例：
  - https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh
  错误示例（会导致 404）：
  - 包含 refs/heads 的 URL，例如 https://raw.githubusercontent.com/umut0301/auto-linux/refs/heads/main/auto-linux.sh

- 网络或 DNS 问题：某些网络环境（例如部分地区或VPS提供商）可能屏蔽 raw.githubusercontent.com 或 githubusercontent 的访问。可尝试切换到 curl 的 -4 参数或先在本地网络下载后再上传至 VPS。

- 权限问题：脚本需要 root 权限（脚本会检查并提示）。如果脚本提示无法写入 /etc/wireguard，确认是否使用 sudo 或以 root 身份运行。

- qrencode 未安装：二维码显示与生成依赖 `qrencode`，脚本会尝试安装。如果没有生成二维码，可以手动安装 `qrencode` 然后重新添加客户端。

- NAT 与 iptables 部分：脚本尝试自动添加 NAT/转发规则并保存（netfilter-persistent / iptables-save 等）。注意：我在读取仓库中的 `auto-linux.sh` 时，发现 NAT/iptables 配置段的几行在仓库文件展示中出现了截断（包含字符串 "[...]"），这可能是获取时的展示问题或脚本被意外截断。强烈建议你在执行前打开 `auto-linux.sh` 检查第 320-340 行附近的 iptables/nat 相關命令是否完整并正确。

如果需要，我可以帮你修复或补全这部分规则，并将更稳健的 NAT 配置推送到仓库。

## 安全与建议

- 在线一键运行会在目标机器以 root 权限执行远端脚本。建议下载并人工审查脚本内容后再运行。
- 如果你计划频繁在多个 VPS 上运行，建议在脚本中加入签名/哈希校验（例如 SHA256），在 README 中公布校验值，运行时先校验脚本完整性。

## 我可以为你做的事情

- 我已经将 README 更新为更详细的版本，包含使用示例与注意事项。
- 如果你希望，我可以：
  - 修复 `auto-linux.sh` 中被截断或错误的 iptables/NAT 逻辑并提交补丁；
  - 为脚本添加非交互式参数支持（例如通过命令行参数自动初始化服务端或添加客户端）；
  - 在 README 中加入示例输出与更多操作流程截图（需你提供或授权生成）。
