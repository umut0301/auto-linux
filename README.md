# auto-linux
自动化linux管理部署，管理vps

## 使用方式

推荐统一通过 `auto-linux.sh` 进行管理，已解释并整合仓库内的 WireGuard 与 x-ui 脚本入口。

```bash
sudo bash auto-linux.sh
```

也支持命令行子命令：

```bash
sudo bash auto-linux.sh wg install
sudo bash auto-linux.sh wg add-client
sudo bash auto-linux.sh xui
```

> 说明：仓库内其他 `.sh` 脚本为历史版本或专项脚本，功能已由 `auto-linux.sh` 统一覆盖。
