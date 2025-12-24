# Auto-Linux 全能服务器管理脚本 🚀

**Auto-Linux** 是一款专为 Linux VPS 设计的自动化运维脚本。它集成了 **WireGuard 全生命周期管理**、**X-UI 面板管理**、**系统状态监控**以及**专业的网络工具箱**。

脚本采用纯 Shell 编写，结合 ANSI 颜色代码与字符画 UI，提供**极客级**的交互体验。

---

## 🌟 核心功能亮点

### 🛡️ WireGuard 深度管理
- **全生命周期**：一键安装服务端、初始化接口。
- **批量制造**：支持批量添加/删除客户端（自动防冲突、自动分配 IP）。
- **级联清理**：删除接口时自动清理关联的所有客户端文件，不留垃圾。
- **智能配置**：自动识别公网 IP、自动配置 NAT 转发、二维码终端输出。

### ⚡ 网络与安全托管
- **全自动 NAT**：自动识别主网卡并配置 iptables 转发，无需人工干预。
- **端口管家**：自动扫描并放行 X-UI 面板及所有节点的端口。
- **安全加固**：自动识别 SSH 端口防误锁，主动拦截 SMB/NetBIOS 等高危端口。

### 🧰 网络工具箱 (UMUT Pro)
- **极致本地化**：核心流媒体检测（Netflix/Disney+/ChatGPT 等）纯原生代码实现，无远程脚本依赖，秒出结果。
- **智能分区**：自动识别 VPS 地区（HK/JP/US/EU...），智能加载对应地区的流媒体检测项。
- **整合测速**：内置 Ookla Speedtest 官方二进制核心，配合精选三网 5G 节点，测速更稳更准。
- **IP 体检**：集成净化版 IP 质量检测，一键查询欺诈分数与流媒体解锁详情。

### 🎨 终极 UI 体验
- **Dashboard 置顶**：主菜单实时显示 CPU/内存/负载/硬盘及组件运行状态。
- **完美对齐**：采用 ANSI 绝对定位技术，解决中英文混合排版不对齐的痛点。
- **快捷指令**：安装后输入 `ws` 即可随时唤醒脚本。

---

## 📥 安装与使用

### 一键安装
推荐使用 root 用户执行以下命令：

```bash
# 使用 curl (推荐)
curl -fsSL [https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh](https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh) -o auto-linux.sh && chmod +x auto-linux.sh && ./auto-linux.sh

# 或者使用 wget
wget -qO auto-linux.sh [https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh](https://raw.githubusercontent.com/umut0301/auto-linux/main/auto-linux.sh) && chmod +x auto-linux.sh && ./auto-linux.sh
