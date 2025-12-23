#!/bin/bash

# WireGuard 自动安装部署脚本
# 按你的原脚本逻辑保留所有功能，仅增加 NAT 回程修复，解决客户端“只发不收”

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 变量定义
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
SYSCTL_FILE="/etc/sysctl.conf"
BACKUP_DIR="/etc/wireguard/backup"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 检查系统
check_os() {
    if [[ ! -f /etc/debian_version ]]; then
        log_error "此脚本仅适用于Debian/Ubuntu系统"
        exit 1
    fi
}

# 安装必要软件
install_packages() {
    log_info "安装必要软件包..."
    apt update
    apt install -y wireguard qrencode resolvconf iptables-persistent netfilter-persistent curl
    log_info "软件包安装完成"
}

# 启用IP转发
enable_ip_forwarding() {
    log_info "启用IP转发..."
    if grep -q "^net.ipv4.ip_forward=1" $SYSCTL_FILE; then
        log_info "IP转发已启用"
    else
        sed -i '/^net.ipv4.ip_forward/d' $SYSCTL_FILE
        echo 'net.ipv4.ip_forward=1' >> $SYSCTL_FILE
        sysctl -p >/dev/null || true
        log_info "IP转发已启用并持久化"
    fi
}

# ===== 防火墙配置（含 NAT 回程修复）=====
configure_firewall() {
    local wg_port=$1
    local interface_name=$2

    # 若未传入端口，尝试自动识别
    if [[ -z "$wg_port" && -f "$CONFIG_DIR/${interface_name}.conf" ]]; then
        wg_port=$(grep -E "^\s*ListenPort\s*=" "$CONFIG_DIR/${interface_name}.conf" | awk -F= '{print $2}' | tr -d ' ')
    fi
    [[ -z "$wg_port" ]] && wg_port=51820

    log_info "配置防火墙，开放22与${wg_port}/udp..."

    # 清空规则
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    # 基础规则
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p udp --dport "$wg_port" -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT

    # WireGuard 转发
    iptables -A FORWARD -i "$interface_name" -j ACCEPT
    iptables -A FORWARD -o "$interface_name" -j ACCEPT

    # NAT 转发
    local public_interface
    public_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -n "$public_interface" ]]; then
        iptables -t nat -A POSTROUTING -o "$public_interface" -j MASQUERADE

        # ✅ 新增：允许 WireGuard 子网访问公网并放行回程流量
        iptables -A FORWARD -i "$interface_name" -o "$public_interface" -j ACCEPT
        iptables -A FORWARD -i "$public_interface" -o "$interface_name" -m state --state ESTABLISHED,RELATED -j ACCEPT

        log_info "已为接口 $public_interface 配置 NAT 转发并放行回程流量"
    else
        log_warn "无法检测公网接口，请手动配置 NAT"
    fi

    # 保存规则
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    systemctl enable netfilter-persistent >/dev/null 2>&1 || true
    systemctl restart netfilter-persistent >/dev/null 2>&1 || true
    log_info "防火墙配置完成"
}

# ===== 网络优化（BBR）=====
optimize_network() {
    log_info "启用 BBR 并优化网络参数..."
    modprobe tcp_bbr 2>/dev/null || true
    grep -q "tcp_bbr" /etc/modules-load.d/modules.conf 2>/dev/null || echo "tcp_bbr" >> /etc/modules-load.d/modules.conf
    cat >> /etc/sysctl.conf <<EOF

# 网络优化参数
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.core.somaxconn=4096
net.core.netdev_max_backlog=16384
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_mtu_probing=1
EOF
    sysctl -p >/dev/null || true
    log_info "BBR/网络优化已启用"
}

# ===== 生成密钥 =====
generate_keys() {
    local iface=$1
    wg genkey | tee "$CONFIG_DIR/${iface}.privatekey" | wg pubkey > "$CONFIG_DIR/${iface}.publickey"
}

# ===== 配置服务器 =====
configure_wireguard_server() {
    local iface=$1 port=$2 subnet=$3
    local priv=$(cat "$CONFIG_DIR/${iface}.privatekey")
    cat > "$CONFIG_DIR/${iface}.conf" <<EOF
[Interface]
PrivateKey = $priv
Address = ${subnet}.1/24
ListenPort = $port
SaveConfig = false
EOF
}

# ===== 添加客户端 =====
add_client() {
    local iface=$1 subnet=$2 name=$3 ipaddr=$4
    mkdir -p "$CLIENT_DIR"
    local priv=$(wg genkey)
    local pub=$(echo "$priv" | wg pubkey)
    local server_pub=$(cat "$CONFIG_DIR/${iface}.publickey")
    local server_ip=$(curl -s -4 ifconfig.me || hostname -I | awk '{print $1}')
    local server_port
    server_port=$(grep ListenPort "$CONFIG_DIR/${iface}.conf" | awk -F= '{print $2}' | tr -d ' ')
    # 写入服务器端 Peer
    cat >> "$CONFIG_DIR/${iface}.conf" <<EOF
# Client: $name
[Peer]
PublicKey = $pub
AllowedIPs = $ipaddr/32
EOF
    # 客户端配置
    cat > "$CLIENT_DIR/${name}.conf" <<EOF
[Interface]
PrivateKey = $priv
Address = $ipaddr/24
DNS = 1.1.1.1

[Peer]
PublicKey = $server_pub
Endpoint = ${server_ip}:${server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 21
EOF
    qrencode -t UTF8 < "$CLIENT_DIR/${name}.conf" || true
    log_info "客户端 $name 已生成 ($ipaddr)"
}

# ===== 自动部署 =====
auto_deploy() {
    clear
    log_info "=== 自动部署 WireGuard ==="
    check_root; check_os
    install_packages
    optimize_network
    read -p "接口名 [默认 wg0]: " iface; iface=${iface:-wg0}
    read -p "是否使用随机端口? (y/n) [y]: " r; r=${r:-y}
    if [[ $r == y ]]; then port=$((RANDOM%10000+20000)); else read -p "端口 [默认51820]: " port; port=${port:-51820}; fi
    read -p "内网C段 [默认10.10.10]: " subnet; subnet=${subnet:-10.10.10}
    mkdir -p "$CONFIG_DIR"
    generate_keys "$iface"
    configure_wireguard_server "$iface" "$port" "$subnet"
    enable_ip_forwarding
    configure_firewall "$port" "$iface"
    read -p "是否添加客户端? (y/n) [y]: " addc; addc=${addc:-y}
    if [[ $addc == y ]]; then
        read -p "客户端名 [默认 client1]: " cname; cname=${cname:-client1}
        add_client "$iface" "$subnet" "$cname" "${subnet}.2"
    fi
    systemctl enable "wg-quick@$iface"
    systemctl restart "wg-quick@$iface"
    log_info "部署完成，接口：$iface 端口：$port"
}

# ===== 菜单 =====
show_menu() {
    clear
    echo "1. 自动部署"
    echo "2. 配置 NAT 转发"
    echo "3. 添加客户端"
    echo "4. 查看接口状态"
    echo "5. 退出"
}

# ===== 主循环 =====
main() {
    while true; do
        show_menu
        read -p "选择操作 [1-5]: " c
        case $c in
            1) auto_deploy ;;
            2)
                read -p "接口名 [默认 wg0]: " iface; iface=${iface:-wg0}
                local port
                port=$(grep ListenPort "$CONFIG_DIR/${iface}.conf" | awk -F= '{print $2}' | tr -d ' ')
                configure_firewall "$port" "$iface"
                ;;
            3)
                read -p "接口名 [默认 wg0]: " iface; iface=${iface:-wg0}
                read -p "客户端名: " cname
                read -p "客户端IP [默认 10.10.10.2]: " cip; cip=${cip:-10.10.10.2}
                local subnet
                subnet=$(grep Address "$CONFIG_DIR/${iface}.conf" | head -1 | cut -d'=' -f2 | tr -d ' ' | cut -d'.' -f1-3)
                add_client "$iface" "$subnet" "$cname" "$cip"
                ;;
            4) wg show ;;
            5) exit 0 ;;
        esac
        read -p "按回车返回菜单..."
    done
}

check_root
check_os
main
