# auto-linux
自动化 Linux 管理脚本，当前聚焦 WireGuard 与 x-ui 面板管理。

## 功能
- WireGuard：安装/初始化服务端、添加/查看/删除客户端、生成配置与二维码、NAT 与转发、状态查看、卸载
- x-ui 面板：通过官方脚本进行安装/配置/管理
- 系统信息：发行版信息、内核、IP、磁盘占用

## 使用
脚本需以 root 运行：
```bash
sudo bash auto-linux.sh
```

## 说明
- x-ui 功能入口会调用官方脚本：`https://github.com/yonggekkk/x-ui-yg`
