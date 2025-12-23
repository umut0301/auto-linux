#!/usr/bin/env bash
#
# auto-linux.sh
# WireGuard 一键管理脚本
# 说明：自动适配主流发行版，提供交互式菜单，支持安装、配置、添加客户端、生成二维码、查看/删除客户端等功能
# 作者：整合自 repo 脚本（由 ChatGPT 整合与优化）
#
set -euo pipefail
IFS=$'\n\t'

WG_DIR="/etc/wireguard"
WG_CLIENT_DIR="$WG_DIR/clients"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# -----------------------
# 通用工具函数
# -----------------------
log() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "请以 root 身份运行本脚本。"
        exit 1
    fi
}

press_any_key() {
    echo
    read -r -p "按 Enter 键返回..." _dummy
}

# -----------------------
# 发行版检测与包管理抽象
# -----------------------
DISTRO=""
PKG_INSTALL=""
PKG_UPDATE=""
PKG_REMOVE=""

detect_distro_and_pkgmgr() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO="$ID"
    fi

    case "$DISTRO" in
        ubuntu|debian)
            PKG_INSTALL="apt-get install -y"
            PKG_UPDATE="apt-get update -y"
            PKG_REMOVE="apt-get remove -y"
            ;;
        centos|rhel|almalinux|rocky)
            PKG_INSTALL="dnf install -y"
            PKG_UPDATE="dnf makecache"
            PKG_REMOVE="dnf remove -y"
            ;;
        fedora)
            PKG_INSTALL="dnf install -y"
            PKG_UPDATE="dnf makecache"
            PKG_REMOVE="dnf remove -y"
            ;;
        arch)
            PKG_INSTALL="pacman -S --noconfirm"
            PKG_UPDATE="pacman -Sy"
            PKG_REMOVE="pacman -R --noconfirm"
            ;;
        opensuse*|suse)
            PKG_INSTALL="zypper install -y"
            PKG_UPDATE="zypper refresh"
            PKG_REMOVE="zypper remove -y"
            ;;
        *)
            warn "无法识别发行版 ($DISTRO)，将尝试使用 apt/dnf/pacman 等通用命令。"
            PKG_INSTALL="apt-get install -y"
            PKG_UPDATE="apt-get update -y"
            PKG_REMOVE="apt-get remove -y"
            ;;
    esac
}

pkg_update() {
    if [[ -n "${PKG_UPDATE:-}" ]]; then
        eval "$PKG_UPDATE"
    fi
}

pkg_install() {
    local pkgs="$*"
    if [[ -z "$pkgs" ]]; then return; fi
    echo "安装软件包：$pkgs"
    eval "$PKG_INSTALL $pkgs"
}

pkg_exists() {
    local pkg="$1"
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -s "$pkg" >/dev/null 2>&1 && return 0 || return 1
    elif command -v rpm >/dev/null 2>&1; then
        rpm -q "$pkg" >/dev/null 2>&1 && return 0 || return 1
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Qi "$pkg" >/dev/null 2>&1 && return 0 || return 1
    else
        command -v "$pkg" >/dev/null 2>&1 && return 0 || return 1
    fi
}

# -----------------------
# WireGuard 部分
# -----------------------
ensure_wireguard_tools() {
    detect_distro_and_pkgmgr
    pkg_update
    # install common tools
    case "$DISTRO" in
        ubuntu|debian)
            pkg_install wireguard qrencode iptables-persistent net-tools resolvconf
            ;;
        centos|rhel|almalinux|rocky)
            # EPEL may be required on older RHEL/CentOS
            if ! rpm -qa | grep -qi epel; then
                dnf install -y epel-release || true
            fi
            pkg_install wireguard-tools qrencode iptables-services
            ;;
        fedora)
            pkg_install wireguard-tools qrencode
            ;;
        arch)
            pkg_install wireguard-tools qrencode
            ;;
        opensuse*|suse)
            pkg_install wireguard-tools qrencode
            ;;
        *)
            # fallback
            pkg_install wireguard qrencode || true
            ;;
    esac
    mkdir -p "$WG_DIR"
    mkdir -p "$WG_CLIENT_DIR"
    chmod 700 "$WG_DIR"
}

wg_generate_server_keys() {
    local iface="${1:-wg0}"
    ensure_wireguard_tools
    if [[ ! -f "$WG_DIR/server_private.key" ]]; then
        umask 077
        wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
        chmod 600 "$WG_DIR/server_private.key"
    fi
}

wg_create_server_conf() {
    local iface="${1:-wg0}"
    local server_ip="${2:-10.0.0.1}"
    local port="${3:-51820}"
    wg_generate_server_keys "$iface"
    local server_priv
    server_priv=$(cat "$WG_DIR/server_private.key")
    cat > "$WG_DIR/${iface}.conf" <<EOF
[Interface]
Address = ${server_ip}/24
ListenPort = ${port}
PrivateKey = ${server_priv}
SaveConfig = true
EOF
    chmod 600 "$WG_DIR/${iface}.conf"
    log "WireGuard 服务端配置已创建: $WG_DIR/${iface}.conf"
}

wg_next_client_ip() {
    local iface="${1:-wg0}"
    local base
    base=$(grep -m1 '^Address' "$WG_DIR/${iface}.conf" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' | cut -d'/' -f1)
    if [[ -z "$base" ]]; then base="10.0.0.1"; fi
    local prefix
    prefix=$(echo "$base" | awk -F'.' '{print $1"."$2"."$3}')
    for i in $(seq 2 254); do
        candidate="${prefix}.${i}"
        if ! grep -q "$candidate" "$WG_DIR/${iface}.conf"; then
            echo "$candidate"
            return
        fi
    done
    err "没有可用的客户端 IP"
    return 1
}

wg_add_client() {
    local name="$1"; shift
    local iface="${1:-wg0}"
    local ipaddr
    if [[ -z "$name" ]]; then
        read -rp "请输入客户端名称（仅字母数字_-）: " name
        if [[ -z "$name" ]]; then err "客户端名不能为空"; return 1; fi
    fi
    if [[ ! -f "$WG_DIR/${iface}.conf" ]]; then
        err "未找到服务端配置：$WG_DIR/${iface}.conf，请先部署服务端。"
        return 1
    fi
    mkdir -p "$WG_CLIENT_DIR/$name"
    chmod 700 "$WG_CLIENT_DIR/$name"
    ipaddr=$(wg_next_client_ip "$iface")
    # generate keys
    umask 077
    wg genkey | tee "$WG_CLIENT_DIR/$name/private.key" | wg pubkey > "$WG_CLIENT_DIR/$name/public.key"
    wg genpsk > "$WG_CLIENT_DIR/$name/psk"
    local priv pub psk server_pub server_addr server_port dns
    priv=$(cat "$WG_CLIENT_DIR/$name/private.key")
    pub=$(cat "$WG_CLIENT_DIR/$name/public.key")
    psk=$(cat "$WG_CLIENT_DIR/$name/psk")
    server_pub=$(cat "$WG_DIR/server_public.key" 2>/dev/null || true)
    # server endpoint: prefer public IP detection
    server_addr=$(curl -fs4 https://ipv4.icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
    server_port=$(grep -E 'ListenPort' "$WG_DIR/${iface}.conf" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ')
    dns="1.1.1.1"
    cat > "$WG_CLIENT_DIR/$name/$name.conf" <<EOF
[Interface]
PrivateKey = ${priv}
Address = ${ipaddr}/32
DNS = ${dns}

[Peer]
PublicKey = ${server_pub}
PresharedKey = ${psk}
Endpoint = ${server_addr}:${server_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 21
EOF
    # append peer to server config
    cat >> "$WG_DIR/${iface}.conf" <<EOF

# ${name}
[Peer]
PublicKey = ${pub}
PresharedKey = ${psk}
AllowedIPs = ${ipaddr}/32
EOF
    chmod 600 "$WG_CLIENT_DIR/$name/$name.conf"
    # generate qr (png + terminal)
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -o "$WG_CLIENT_DIR/$name/$name.png" -t png < "$WG_CLIENT_DIR/$name/$name.conf" || true
    fi
    log "已添加客户端 ${name}，配置: $WG_CLIENT_DIR/$name/$name.conf"
    # restart service to apply
    systemctl restart "wg-quick@${iface}" 2>/dev/null || wg syncconf "$iface" <(wg-quick strip "$iface") 2>/dev/null || true
}

wg_list_clients() {
    if [[ ! -d "$WG_CLIENT_DIR" ]]; then
        echo "暂无客户端"
        return
    fi
    for d in "$WG_CLIENT_DIR"/*; do
        [[ -d "$d" ]] || continue
        name=$(basename "$d")
        ip=$(grep '^Address' "$d/$name.conf" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' | cut -d'/' -f1)
        echo " - $name ($ip)"
    done
}

wg_show_client() {
    local name="$1"; shift
    if [[ -z "$name" ]]; then
        read -rp "请输入要查看的客户端名: " name
    fi
    local conf="$WG_CLIENT_DIR/$name/$name.conf"
    if [[ ! -f "$conf" ]]; then err "未找到客户端配置: $conf"; return 1; fi
    echo "---- $name 配置 ----"
    cat "$conf"
    echo "二维码（终端渲染）:"
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ansiutf8 < "$conf" || true
    else
        echo "(未安装 qrencode，无法显示二维码)"
    fi
    echo "PNG二维码路径（若生成）: $WG_CLIENT_DIR/$name/$name.png"
}

wg_remove_client() {
    local name="$1"; shift
    if [[ -z "$name" ]]; then
        read -rp "请输入要删除的客户端名: " name
    fi
    local iface="${1:-wg0}"
    local server_conf="$WG_DIR/${iface}.conf"
    if [[ ! -f "$server_conf" ]]; then err "未找到服务器配置 $server_conf"; fi
    local pub
    pub=$(cat "$WG_CLIENT_DIR/$name/public.key" 2>/dev/null || true)
    if [[ -z "$pub" ]]; then
        warn "未找到客户端公钥，仍会尝试删除本地文件"
    else
        # remove peer block by matching public key or comment
        sed -i "/# ${name}/,/\[Peer\]/{/^\s*$/!b};" "$server_conf" 2>/dev/null || true
        # safer remove: remove the comment and following peer (4 lines)
        sed -i "/# ${name}/,+4d" "$server_conf" 2>/dev/null || true
        # also try removing by public key
        sed -i "/${pub}/, +3d" "$server_conf" 2>/dev/null || true
    fi
    rm -rf "$WG_CLIENT_DIR/$name"
    systemctl restart "wg-quick@${iface}" 2>/dev/null || true
    log "客户端 $name 已删除"
}

wg_change_port() {
    local iface="${1:-wg0}"
    local conf="$WG_DIR/${iface}.conf"
    if [[ ! -f "$conf" ]]; then err "未找到 $conf"; return 1; fi
    read -rp "请输入新的监听端口: " newp
    if ! [[ "$newp" =~ ^[0-9]+$ ]] || (( newp < 1 || newp > 65535 )); then err "端口不合法"; return 1; fi
    sed -i "s/^ListenPort.*/ListenPort = ${newp}/" "$conf" || sed -i "s/^ListenPort = .*/ListenPort = ${newp}/" "$conf" || true
    log "端口已修改为 $newp，正在重启服务..."
    systemctl restart "wg-quick@${iface}" 2>/dev/null || true
}

wg_enable_nat_and_forward() {
    local iface="${1:-wg0}"
    # enable ip forward
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || true
    fi
    # configure iptables NAT
    local pub_if
    pub_if=$(ip route | awk '/default/ {print $5; exit}')
    if [[ -z "$pub_if" ]]; then warn "未能自动检测公网接口，请手动配置 NAT"; return; fi
    iptables -t nat -C POSTROUTING -s "$(grep -m1 '^Address' "$WG_DIR/${iface}.conf" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' | cut -d'/' -f1 | awk -F'.' '{print $1"."$2"."$3".0/24"}')" -o "$pub_if" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "$(grep -m1 '^Address' "$WG_DIR/${iface}.conf" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' | cut -d'/' -f1 | awk -F'.' '{print $1"."$2"."$3".0/24"}')" -o "$pub_if" -j MASQUERADE
    # allow forwarding
    iptables -C FORWARD -i "$iface" -o "$pub_if" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$iface" -o "$pub_if" -j ACCEPT
    iptables -C FORWARD -i "$pub_if" -o "$iface" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$pub_if" -o "$iface" -m state --state ESTABLISHED,RELATED -j ACCEPT
    # save rules if possible
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    elif [[ -d /etc/iptables ]]; then
        iptables-save > /etc/iptables/rules.v4 || true
    fi
    log "已配置 NAT 与转发（出口接口: $pub_if）"
}

wg_show_status() {
    local iface="${1:-wg0}"
    if command -v wg >/dev/null 2>&1; then
        wg show "$iface" || true
    else
        warn "wg 工具不可用"
    fi
    systemctl status "wg-quick@${iface}" --no-pager || true
}

wg_uninstall() {
    read -rp "要彻底卸载 WireGuard 吗？这将删除 /etc/wireguard 下的所有文件 (y/N): " yn
    if [[ "$yn" =~ ^[Yy]$ ]]; then
        systemctl stop wg-quick@wg0 2>/dev/null || true
        systemctl disable wg-quick@wg0 2>/dev/null || true
        rm -rf "$WG_DIR"
        log "WireGuard 配置已删除"
        # optionally remove packages
        read -rp "是否卸载软件包 wireguard/qrencode？(y/N): " rem
        if [[ "$rem" =~ ^[Yy]$ ]]; then
            eval "$PKG_REMOVE wireguard wireguard-tools qrencode" || true
            log "WireGuard 软件包已卸载（若可用）"
        fi
    else
        log "取消卸载"
    fi
}

# -----------------------
# 菜单 UI
# -----------------------
show_main_menu() {
    clear
    cat <<'EOF'
============================================
 auto-linux WireGuard 管理脚本
 1) WireGuard 管理
 2) x-ui 面板管理（使用官方脚本）
 3) 系统信息
 0) 退出
============================================
EOF
    read -rp "请选择: " choice
    case "$choice" in
        1) wg_menu ;;
        2) xui_manage; press_any_key ;;
        3) system_info; press_any_key ;;
        0) exit 0 ;;
        *) warn "无效选项"; sleep 1 ;;
    esac
}

wg_menu() {
    while true; do
        clear
        cat <<EOF
==== WireGuard 菜单 ====
1) 安装/初始化 WireGuard 服务端
2) 添加客户端（生成配置 + QR）
3) 列出客户端
4) 查看客户端配置与二维码
5) 删除客户端
6) 修改监听端口
7) 配置 NAT 与转发
8) 查看状态
9) 卸载 WireGuard
0) 返回主菜单
EOF
        read -rp "请选择: " c
        case "$c" in
            1)
                require_root
                read -rp "接口名 [wg0]: " iface; iface=${iface:-wg0}
                read -rp "服务器内网IP [10.0.0.1]: " serverip; serverip=${serverip:-10.0.0.1}
                read -rp "端口 [51820]: " port; port=${port:-51820}
                ensure_wireguard_tools
                wg_create_server_conf "$iface" "$serverip" "$port"
                systemctl enable "wg-quick@${iface}" >/dev/null 2>&1 || true
                systemctl restart "wg-quick@${iface}" >/dev/null 2>&1 || true
                log "WireGuard 服务已安装并启动（接口: $iface）"
                press_any_key
                ;;
            2) require_root; read -rp "客户端名: " name; name=${name:-client}; read -rp "接口名 [wg0]: " iface; iface=${iface:-wg0}; wg_add_client "$name" "$iface"; press_any_key ;;
            3) wg_list_clients; press_any_key ;;
            4) wg_show_client; press_any_key ;;
            5) require_root; read -rp "客户端名: " name; read -rp "接口名 [wg0]: " iface; iface=${iface:-wg0}; wg_remove_client "$name" "$iface"; press_any_key ;;
            6) require_root; read -rp "接口名 [wg0]: " iface; iface=${iface:-wg0}; wg_change_port "$iface"; press_any_key ;;
            7) require_root; read -rp "接口名 [wg0]: " iface; iface=${iface:-wg0}; wg_enable_nat_and_forward "$iface"; press_any_key ;;
            8) wg_show_status; press_any_key ;;
            9) require_root; wg_uninstall; press_any_key ;;
            0) break ;;
            *) warn "无效选项"; sleep 1 ;;
        esac
    done
}

system_info() {
    echo "系统信息："
    lsb_release -a 2>/dev/null || cat /etc/os-release
    echo "内核：$(uname -r)"
    echo "IP：$(hostname -I | tr -s ' ')"
    echo "磁盘："
    df -h | sed -n '1,6p'
}

# -----------------------
# x-ui 面板（调用官方脚本）
# -----------------------
xui_manage() {
    echo "将执行 x-ui 官方管理脚本..."
    bash <(curl -fsSL https://raw.githubusercontent.com/yonggekkk/x-ui-yg/main/install.sh)
}

# -----------------------
# 启动 & 主循环
# -----------------------
main() {
    require_root
    detect_distro_and_pkgmgr
    while true; do
        show_main_menu
    done
}

main "$@"

# End of file
