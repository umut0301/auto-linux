#!/bin/bash

# auto-linux.sh
# 统一入口脚本：WireGuard / x-ui
# 主要功能整合自：
# - wireguard-manager.sh / ws-network-manager.sh（主干功能：WireGuard管理、x-ui部署、BBR、防火墙）
# - wg-1-install.sh（端口修改、配置展示、备份思路）
# - wg-install.sh（NAT回程放行思路）
# - wg-install-初始版本.sh / wg-install-GPT修改版.sh（早期自动化流程参考）
# - wireguard-manager.sh / ws-network-manager.sh（主干功能：WireGuard管理、x-ui部署、BBR、防火墙）

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# 目录与配置
WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/wg0.conf"
CLIENT_DIR="${WG_DIR}/clients"
SYSCTL_FILE="/etc/sysctl.conf"

# 日志函数
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }

# 通用工具
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

press_any_key() {
    echo ""
    read -p "按 Enter 键继续..." _dummy
}

clear_screen() {
    clear
}

show_header() {
    clear_screen
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                     auto-linux 管理工具                   ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

show_wg_header() {
    clear_screen
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           WireGuard 服务端/客户端管理工具                 ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# 发行版检测（来自 wireguard-manager.sh）
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    else
        log_error "无法检测Linux发行版"
        return 1
    fi
    return 0
}

# 获取公网IP（来自 wg-1-install.sh）
get_public_ip() {
    local public_ip
    public_ip=$(curl -s -4 http://ipv4.icanhazip.com || curl -s -4 http://api.ipify.org)
    if [[ -z "$public_ip" ]]; then
        log_warn "无法获取公网IP，请手动设置"
        read -p "请输入服务器公网IP地址: " public_ip
    fi
    echo "$public_ip"
}

# 获取默认出口网卡（来自 wg-install-GPT修改版.sh）
get_default_iface() {
    ip route | grep default | awk '{print $5}' | head -n 1
}

# 随机端口生成（来自 wg-1-install.sh）
random_port() {
    echo $(( ( RANDOM % 10000 ) + 20000 ))
}

# ===== WireGuard 安装与优化 =====
install_wireguard() {
    show_wg_header
    log_info "开始安装WireGuard..."

    if ! detect_distro; then
        press_any_key
        return 1
    fi

    case $DISTRO in
        ubuntu|debian)
            log_info "使用apt安装WireGuard..."
            apt-get update
            apt-get install -y wireguard wireguard-tools qrencode
            ;;
        centos|rhel|fedora)
            log_info "使用yum/dnf安装WireGuard..."
            if command -v dnf &> /dev/null; then
                dnf install -y epel-release
                dnf install -y wireguard-tools qrencode
            else
                yum install -y epel-release
                yum install -y wireguard-tools qrencode
            fi
            ;;
        arch|manjaro)
            log_info "使用pacman安装WireGuard..."
            pacman -S --noconfirm wireguard-tools qrencode
            ;;
        *)
            log_error "不支持的Linux发行版: $DISTRO"
            log_info "请手动安装WireGuard: https://www.wireguard.com/install/"
            press_any_key
            return 1
            ;;
    esac

    # 启用IP转发（来自 wireguard-manager.sh）
    if [ ! -f /etc/sysctl.d/99-wireguard.conf ]; then
        log_info "配置IP转发..."
        echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard.conf
        sysctl -p /etc/sysctl.d/99-wireguard.conf
    fi

    log_success "WireGuard安装完成"

    echo ""
    read -p "是否安装BBR网络优化？(Y/n): " install_bbr_choice
    if [ "$install_bbr_choice" != "n" ] && [ "$install_bbr_choice" != "N" ]; then
        install_bbr
    fi

    if [ ! -f "$WG_CONF" ]; then
        echo ""
        read -p "是否立即配置服务端？(Y/n): " setup_now
        if [ "$setup_now" != "n" ] && [ "$setup_now" != "N" ]; then
            setup_server_first_time
            return 0
        fi
    fi
    press_any_key
}

install_bbr() {
    show_wg_header
    log_info "开始安装和配置BBR网络优化"

    KERNEL_VERSION=$(uname -r | cut -d'.' -f1,2)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d'.' -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d'.' -f2)

    if [ "$KERNEL_MAJOR" -lt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 9 ]); then
        log_warn "当前内核版本 $KERNEL_VERSION 不支持BBR（需要4.9+），跳过安装"
        press_any_key
        return 1
    fi

    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        log_info "BBR已启用，跳过安装"
        press_any_key
        return 0
    fi

    modprobe tcp_bbr 2>/dev/null || log_warn "无法加载tcp_bbr模块，可能需要更新内核"

    BBR_CONF="/etc/sysctl.d/99-bbr.conf"
    cat > "$BBR_CONF" <<'BBR_EOF'
# BBR网络优化配置
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000

net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 524288
net.core.wmem_default = 524288
net.ipv4.udp_mem = 524288 1048576 33554432

net.core.netdev_max_backlog = 10000
net.core.netdev_budget = 600
net.ipv4.udp_rmem_min = 4096
net.ipv4.udp_wmem_min = 4096

net.core.somaxconn = 8192
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

net.core.netdev_budget_usecs = 5000
net.core.netdev_tstamp_prequeue = 1

net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.ipfrag_high_thresh = 4194304
net.ipv4.ipfrag_low_thresh = 3145728
BBR_EOF

    sysctl -p "$BBR_CONF" > /dev/null 2>&1

    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        log_success "BBR网络优化已成功启用"
    else
        log_warn "BBR启用失败，可能需要重启系统或更新内核"
        log_info "配置文件已保存: $BBR_CONF"
    fi

    if [ ! -f /etc/modules-load.d/bbr.conf ]; then
        echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
        log_info "已配置BBR模块开机自动加载"
    fi

    press_any_key
}

# ===== WireGuard 关键配置 =====
generate_keys() {
    local privkey_file=$1
    local pubkey_file=$2

    if [ ! -f "$privkey_file" ]; then
        wg genkey | tee "$privkey_file" | wg pubkey > "$pubkey_file"
        chmod 600 "$privkey_file"
        chmod 644 "$pubkey_file"
        log_info "密钥对已生成: $privkey_file"
    else
        log_warn "密钥文件已存在: $privkey_file"
    fi
}

detect_firewall() {
    local firewall_type="none"

    if systemctl is-active --quiet firewalld 2>/dev/null || systemctl is-enabled --quiet firewalld 2>/dev/null; then
        firewall_type="firewalld"
    elif systemctl is-active --quiet ufw 2>/dev/null || command -v ufw &>/dev/null; then
        firewall_type="ufw"
    elif command -v iptables &>/dev/null && iptables -L -n 2>/dev/null | grep -q "Chain"; then
        firewall_type="iptables"
    elif command -v nft &>/dev/null && nft list ruleset &>/dev/null 2>&1; then
        firewall_type="nftables"
    fi

    echo "$firewall_type"
}

# 来自 wireguard-manager.sh，合并 x-ui 端口自动探测
# 若未安装 x-ui，仅返回空列表
detect_xui_ports() {
    local xui_ports=()

    if [ ! -f /usr/local/x-ui/x-ui ]; then
        echo ""
        return 0
    fi

    if command -v /usr/local/x-ui/x-ui &>/dev/null; then
        local login_port
        login_port=$(/usr/local/x-ui/x-ui setting -show 2>/dev/null | grep -oE 'port:[0-9]+' | cut -d':' -f2)
        if [ -n "$login_port" ]; then
            xui_ports+=("$login_port")
        fi
    fi

    local config_file="/usr/local/x-ui/bin/config.json"
    if [ -f "$config_file" ] && command -v jq &>/dev/null; then
        local node_ports
        node_ports=$(jq -r '.inbounds[]?.port // empty' "$config_file" 2>/dev/null | sort -u)
        if [ -n "$node_ports" ]; then
            while IFS= read -r node_port; do
                if [ -n "$node_port" ] && [[ "$node_port" =~ ^[0-9]+$ ]]; then
                    if [[ ! " ${xui_ports[*]} " =~ " ${node_port} " ]]; then
                        xui_ports+=("$node_port")
                    fi
                fi
            done <<< "$node_ports"
        fi
    fi

    echo "${xui_ports[@]}"
}

configure_firewall() {
    local port=$1
    local firewall_type
    firewall_type=$(detect_firewall)

    local xui_ports
    xui_ports=($(detect_xui_ports))

    if [ "$firewall_type" = "none" ]; then
        log_warn "未检测到防火墙服务，跳过防火墙配置"
        return 0
    fi

    log_info "检测到防火墙类型: $firewall_type"
    log_info "正在配置防火墙规则..."

    case $firewall_type in
        firewalld)
            if ! systemctl is-active --quiet firewalld; then
                log_info "启动firewalld服务..."
                systemctl start firewalld
                systemctl enable firewalld
            fi

            if ! firewall-cmd --permanent --query-service=ssh &>/dev/null; then
                firewall-cmd --permanent --add-service=ssh 2>/dev/null
                log_success "已确保SSH服务(端口22)开放"
            fi

            if ! firewall-cmd --permanent --query-port="${port}/udp" &>/dev/null; then
                firewall-cmd --permanent --add-port="${port}/udp" 2>/dev/null
                log_success "已开放WireGuard端口 $port/udp"
            fi

            if ! firewall-cmd --permanent --query-port="${port}/tcp" &>/dev/null; then
                firewall-cmd --permanent --add-port="${port}/tcp" 2>/dev/null
                log_success "已开放WireGuard端口 $port/tcp"
            fi

            if [ ${#xui_ports[@]} -gt 0 ]; then
                for xui_port in "${xui_ports[@]}"; do
                    firewall-cmd --permanent --add-port="${xui_port}/tcp" 2>/dev/null || true
                    firewall-cmd --permanent --add-port="${xui_port}/udp" 2>/dev/null || true
                done
            fi

            firewall-cmd --reload 2>/dev/null
            ;;
        ufw)
            if ! systemctl is-active --quiet ufw 2>/dev/null; then
                systemctl start ufw 2>/dev/null || ufw --force enable
            fi

            if ! ufw status | grep -q "22/tcp"; then
                ufw allow 22/tcp comment 'SSH' 2>/dev/null
            fi

            if ! ufw status | grep -q "${port}/udp"; then
                ufw allow ${port}/udp comment 'WireGuard' 2>/dev/null
            fi

            if ! ufw status | grep -q "${port}/tcp"; then
                ufw allow ${port}/tcp comment 'WireGuard-TCP' 2>/dev/null
            fi

            if [ ${#xui_ports[@]} -gt 0 ]; then
                for xui_port in "${xui_ports[@]}"; do
                    ufw allow ${xui_port}/tcp comment 'x-ui' 2>/dev/null || true
                    ufw allow ${xui_port}/udp comment 'x-ui' 2>/dev/null || true
                done
            fi

            ufw --force enable 2>/dev/null
            ;;
        iptables)
            if ! iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null; then
                iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
            fi

            if ! iptables -C INPUT -p udp --dport $port -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -p udp --dport $port -j ACCEPT
            fi

            if ! iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -p tcp --dport $port -j ACCEPT
            fi

            if [ ${#xui_ports[@]} -gt 0 ]; then
                for xui_port in "${xui_ports[@]}"; do
                    iptables -I INPUT -p tcp --dport $xui_port -j ACCEPT 2>/dev/null || true
                    iptables -I INPUT -p udp --dport $xui_port -j ACCEPT 2>/dev/null || true
                done
            fi

            if command -v iptables-save &>/dev/null; then
                if [ -d /etc/iptables ]; then
                    iptables-save > /etc/iptables/rules.v4 2>/dev/null
                elif [ -f /etc/iptables.rules ]; then
                    iptables-save > /etc/iptables.rules 2>/dev/null
                fi
            fi
            ;;
        nftables)
            if ! nft list chain inet filter input 2>/dev/null | grep -q "tcp dport 22"; then
                nft insert rule inet filter input position 0 tcp dport 22 accept 2>/dev/null || \
                nft add rule inet filter input tcp dport 22 accept 2>/dev/null
            fi

            if ! nft list chain inet filter input 2>/dev/null | grep -q "udp dport $port"; then
                nft add rule inet filter input udp dport $port accept 2>/dev/null || \
                nft insert rule inet filter input udp dport $port accept 2>/dev/null
            fi

            if ! nft list chain inet filter input 2>/dev/null | grep -q "tcp dport $port"; then
                nft add rule inet filter input tcp dport $port accept 2>/dev/null || \
                nft insert rule inet filter input tcp dport $port accept 2>/dev/null
            fi

            if [ ${#xui_ports[@]} -gt 0 ]; then
                for xui_port in "${xui_ports[@]}"; do
                    nft add rule inet filter input tcp dport $xui_port accept 2>/dev/null || true
                    nft add rule inet filter input udp dport $xui_port accept 2>/dev/null || true
                done
            fi

            if [ -f /etc/nftables.conf ]; then
                nft list ruleset > /etc/nftables.conf 2>/dev/null
            fi
            ;;
    esac

    return 0
}

setup_firewall() {
    show_wg_header
    log_info "配置防火墙规则..."

    local wg_port="51820"
    if [ -f "$WG_CONF" ]; then
        wg_port=$(grep "ListenPort" "$WG_CONF" | cut -d'=' -f2 | tr -d ' ' | head -1)
        if [ -z "$wg_port" ]; then
            wg_port="51820"
        fi
        log_info "从配置文件读取WireGuard端口: $wg_port"
    else
        read -p "请输入WireGuard端口 [默认: 51820]: " input_port
        wg_port=${input_port:-51820}
    fi

    echo ""
    log_warn "重要提示：配置防火墙时，将确保SSH端口22保持开放状态！"
    echo ""
    read -p "确认配置防火墙规则？(Y/n): " confirm
    if [ "$confirm" = "n" ] || [ "$confirm" = "N" ]; then
        log_info "取消配置"
        press_any_key
        return 0
    fi

    configure_firewall "$wg_port"

    echo ""
    log_success "防火墙配置完成"
    log_info "WireGuard端口: $wg_port/udp 和 $wg_port/tcp 已开放"
    log_info "SSH端口: 22/tcp (已确保开放)"
    press_any_key
}

setup_server_first_time() {
    show_wg_header
    log_info "配置WireGuard服务端..."

    mkdir -p "$WG_DIR"

    if [ -f "$WG_CONF" ]; then
        cp "$WG_CONF" "${WG_CONF}.bak.$(date +%Y%m%d_%H%M%S)"
        log_info "已备份原配置文件"
    fi

    SERVER_PRIVKEY="${WG_DIR}/server_private.key"
    SERVER_PUBKEY="${WG_DIR}/server_public.key"
    if [ ! -f "$SERVER_PRIVKEY" ]; then
        generate_keys "$SERVER_PRIVKEY" "$SERVER_PUBKEY"
    else
        log_info "使用现有服务端密钥"
    fi

    echo ""
    read -p "请输入服务端名称 [默认: server]: " SERVER_NAME
    SERVER_NAME=${SERVER_NAME:-server}

    read -p "请输入服务器公网IP或域名 [默认: 自动检测]: " SERVER_IP
    if [ -z "$SERVER_IP" ]; then
        log_info "正在自动检测IP..."
        SERVER_IP=$(get_public_ip)
        log_info "自动检测到IP: $SERVER_IP"
    fi

    echo ""
    read -p "请输入WireGuard监听端口 [默认: 随机生成, 或输入具体端口]: " SERVER_PORT
    if [ -z "$SERVER_PORT" ]; then
        SERVER_PORT=$((RANDOM % 55536 + 10000))
        log_info "随机生成端口: $SERVER_PORT"
    fi

    echo ""
    read -p "请输入VPN内网网段C段 [例如: 10.10.10, 默认: 10.8.0]: " VPN_C_SEGMENT
    if [ -z "$VPN_C_SEGMENT" ]; then
        VPN_C_SEGMENT="10.8.0"
    fi
    VPN_C_SEGMENT=$(echo "$VPN_C_SEGMENT" | sed 's/\.$//')
    VPN_NETWORK="${VPN_C_SEGMENT}.0/24"
    log_info "完整网段: $VPN_NETWORK"

    echo ""
    log_info "正在自动检测默认出口网卡..."
    EXTERNAL_IF=$(get_default_iface)
    if [ -z "$EXTERNAL_IF" ]; then
        EXTERNAL_IF="eth0"
    fi
    log_info "检测到默认出口网卡: $EXTERNAL_IF"
    echo ""
    log_info "可用的网络接口:"
    ip -o link show | awk -F': ' '{print "  " $2}'
    echo ""
    read -p "请输入外网接口名称 [默认: $EXTERNAL_IF]: " input_if
    EXTERNAL_IF=${input_if:-$EXTERNAL_IF}

    cat > "$WG_CONF" <<EOF
[Interface]
Address = $(echo $VPN_NETWORK | cut -d'/' -f1 | cut -d'.' -f1-3).1/24
ListenPort = $SERVER_PORT
PrivateKey = $(cat $SERVER_PRIVKEY)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $EXTERNAL_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $EXTERNAL_IF -j MASQUERADE

EOF

    log_success "服务端配置已创建: $WG_CONF"
    log_info "服务端公钥: $(cat $SERVER_PUBKEY)"

    echo ""
    log_info "正在自动配置防火墙..."
    configure_firewall "$SERVER_PORT"

    systemctl enable wg-quick@wg0 > /dev/null 2>&1
    systemctl start wg-quick@wg0

    if systemctl is-active --quiet wg-quick@wg0; then
        log_success "WireGuard服务端已启动"
    else
        log_error "WireGuard服务端启动失败"
        systemctl status wg-quick@wg0 --no-pager -l
    fi

    EXISTING_CLIENTS=$(grep -c "# Client:" "$WG_CONF" 2>/dev/null || echo "0")
    if ! [[ "$EXISTING_CLIENTS" =~ ^[0-9]+$ ]]; then
        EXISTING_CLIENTS=0
    fi

    if [ "$EXISTING_CLIENTS" -eq 0 ]; then
        echo ""
        read -p "是否立即创建第一个客户端？(Y/n): " create_client
        if [ "$create_client" != "n" ] && [ "$create_client" != "N" ]; then
            add_client_first_time "$SERVER_IP" "$SERVER_PORT" "$VPN_C_SEGMENT"
        fi
    else
        log_info "检测到已有 $EXISTING_CLIENTS 个客户端，跳过自动创建"
    fi

    press_any_key
}

add_client_first_time() {
    local server_ip=$1
    local server_port=$2
    local vpn_c_segment=$3

    show_header
    log_info "创建第一个客户端..."

    echo ""
    read -p "请输入客户端名称 [默认: client1]: " CLIENT_NAME
    CLIENT_NAME=${CLIENT_NAME:-client1}

    if grep -q "# Client: $CLIENT_NAME" "$WG_CONF" 2>/dev/null; then
        log_warn "客户端 $CLIENT_NAME 已存在，使用默认名称 client1"
        CLIENT_NAME="client1"
        counter=1
        while grep -q "# Client: $CLIENT_NAME" "$WG_CONF" 2>/dev/null; do
            counter=$((counter + 1))
            CLIENT_NAME="client${counter}"
        done
        log_info "使用客户端名称: $CLIENT_NAME"
    fi

    mkdir -p "$CLIENT_DIR"
    CLIENT_PRIVKEY="${CLIENT_DIR}/${CLIENT_NAME}_private.key"
    CLIENT_PUBKEY="${CLIENT_DIR}/${CLIENT_NAME}_public.key"
    generate_keys "$CLIENT_PRIVKEY" "$CLIENT_PUBKEY"

    SERVER_PRIVKEY_FILE="${WG_DIR}/server_private.key"
    if [ -f "$SERVER_PRIVKEY_FILE" ]; then
        SERVER_PUBKEY=$(cat "$SERVER_PRIVKEY_FILE" | wg pubkey)
    else
        log_error "无法找到服务端私钥文件"
        return 1
    fi

    CLIENT_IP="${vpn_c_segment}.2"

    cat >> "$WG_CONF" <<EOF

# Client: $CLIENT_NAME
[Peer]
PublicKey = $(cat $CLIENT_PUBKEY)
AllowedIPs = $CLIENT_IP/32
EOF

    CLIENT_CONF="${CLIENT_DIR}/${CLIENT_NAME}.conf"
    cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = $(cat $CLIENT_PRIVKEY)
Address = $CLIENT_IP/24
DNS = 8.8.8.8

[Peer]
PublicKey = $SERVER_PUBKEY
Endpoint = $server_ip:$server_port
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 21
EOF

    log_success "客户端配置已创建: $CLIENT_CONF"

    wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || log_warn "配置重载失败，请手动重启服务"

    if command -v qrencode &> /dev/null; then
        echo ""
        log_info "客户端配置二维码:"
        echo ""
        qrencode -t ansiutf8 < "$CLIENT_CONF"
    else
        log_warn "qrencode未安装，无法生成二维码"
    fi

    log_success "客户端 $CLIENT_NAME 添加成功"
    log_info "客户端IP: $CLIENT_IP"
    log_info "配置文件路径: $CLIENT_CONF"
}

setup_server() {
    show_wg_header
    log_info "配置WireGuard服务端..."

    if ! command -v wg &> /dev/null; then
        log_warn "WireGuard未安装，正在安装..."
        if ! detect_distro; then
            press_any_key
            return 1
        fi
        install_wireguard
        return 0
    fi

    if [ -f "$WG_CONF" ]; then
        log_warn "服务端配置已存在: $WG_CONF"
        read -p "是否要重新配置？(y/N): " confirm
        if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
            log_info "取消配置"
            press_any_key
            return 0
        fi
    fi

    setup_server_first_time
}

add_client() {
    show_wg_header

    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在，请先配置服务端！"
        press_any_key
        return 1
    fi

    echo ""
    read -p "请输入客户端名称 [默认: 自动生成]: " CLIENT_NAME
    if [ -z "$CLIENT_NAME" ]; then
        EXISTING_COUNT=$(grep -c "# Client:" "$WG_CONF" 2>/dev/null || echo "0")
        if ! [[ "$EXISTING_COUNT" =~ ^[0-9]+$ ]]; then
            EXISTING_COUNT=0
        fi
        CLIENT_NAME="client$((EXISTING_COUNT + 1))"
        log_info "自动生成客户端名称: $CLIENT_NAME"
    fi

    if grep -q "# Client: $CLIENT_NAME" "$WG_CONF" 2>/dev/null; then
        log_error "客户端 $CLIENT_NAME 已存在！"
        press_any_key
        return 1
    fi

    mkdir -p "$CLIENT_DIR"
    CLIENT_PRIVKEY="${CLIENT_DIR}/${CLIENT_NAME}_private.key"
    CLIENT_PUBKEY="${CLIENT_DIR}/${CLIENT_NAME}_public.key"
    generate_keys "$CLIENT_PRIVKEY" "$CLIENT_PUBKEY"

    SERVER_ADDRESS=$(grep "Address" "$WG_CONF" | head -1 | cut -d'=' -f2 | tr -d ' ' | cut -d'/' -f1)
    SERVER_PORT=$(grep "ListenPort" "$WG_CONF" | cut -d'=' -f2 | tr -d ' ')
    SERVER_PRIVKEY_FILE="${WG_DIR}/server_private.key"

    if [ -f "$SERVER_PRIVKEY_FILE" ]; then
        SERVER_PUBKEY=$(cat "$SERVER_PRIVKEY_FILE" | wg pubkey)
    else
        log_error "无法找到服务端私钥文件"
        press_any_key
        return 1
    fi

    echo ""
    read -p "请输入服务器公网IP或域名 [默认: 自动检测]: " SERVER_IP
    if [ -z "$SERVER_IP" ]; then
        log_info "正在自动检测IP..."
        SERVER_IP=$(get_public_ip)
        log_info "自动检测到IP: $SERVER_IP"
    fi

    VPN_NET=$(echo $SERVER_ADDRESS | cut -d'.' -f1-3)
    USED_IPS=$(grep "AllowedIPs" "$WG_CONF" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.([0-9]+)' | cut -d'.' -f4 | sort -n)

    CLIENT_IP_NUM=2
    while echo "$USED_IPS" | grep -q "^${CLIENT_IP_NUM}$"; do
        CLIENT_IP_NUM=$((CLIENT_IP_NUM + 1))
        if [ $CLIENT_IP_NUM -gt 254 ]; then
            log_error "IP地址池已满（最多支持253个客户端）"
            press_any_key
            return 1
        fi
    done

    CLIENT_IP="${VPN_NET}.${CLIENT_IP_NUM}"

    cat >> "$WG_CONF" <<EOF

# Client: $CLIENT_NAME
[Peer]
PublicKey = $(cat $CLIENT_PUBKEY)
AllowedIPs = $CLIENT_IP/32
EOF

    CLIENT_CONF="${CLIENT_DIR}/${CLIENT_NAME}.conf"
    cat > "$CLIENT_CONF" <<EOF
[Interface]
PrivateKey = $(cat $CLIENT_PRIVKEY)
Address = $CLIENT_IP/24
DNS = 8.8.8.8

[Peer]
PublicKey = $SERVER_PUBKEY
Endpoint = $SERVER_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 21
EOF

    log_success "客户端配置已创建: $CLIENT_CONF"

    wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || log_warn "配置重载失败，请手动重启服务"

    if command -v qrencode &> /dev/null; then
        echo ""
        log_info "客户端配置二维码:"
        echo ""
        qrencode -t ansiutf8 < "$CLIENT_CONF"
    else
        log_warn "qrencode未安装，无法生成二维码"
    fi

    log_success "客户端 $CLIENT_NAME 添加成功"
    log_info "配置文件路径: $CLIENT_CONF"
    press_any_key
}

remove_client() {
    show_wg_header

    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在"
        press_any_key
        return 1
    fi

    clients=$(grep "# Client:" "$WG_CONF" | cut -d' ' -f3)
    if [ -z "$clients" ]; then
        log_warn "暂无客户端"
        press_any_key
        return 1
    fi

    echo ""
    log_info "已配置的客户端:"
    echo "$clients" | nl -w2 -s'. '
    echo ""
    read -p "请输入要删除的客户端编号或名称: " input

    if [[ "$input" =~ ^[0-9]+$ ]]; then
        CLIENT_NAME=$(echo "$clients" | sed -n "${input}p")
    else
        CLIENT_NAME="$input"
    fi

    if [ -z "$CLIENT_NAME" ]; then
        log_error "无效的客户端"
        press_any_key
        return 1
    fi

    read -p "确认删除客户端 $CLIENT_NAME? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        log_info "取消删除"
        press_any_key
        return 0
    fi

    sed -i "/# Client: $CLIENT_NAME/,/^$/d" "$WG_CONF"

    rm -f "${CLIENT_DIR}/${CLIENT_NAME}"*.key
    rm -f "${CLIENT_DIR}/${CLIENT_NAME}.conf"

    wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || log_warn "配置重载失败，请手动重启服务"

    log_success "客户端 $CLIENT_NAME 已删除"
    press_any_key
}

list_clients() {
    show_wg_header

    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在"
        press_any_key
        return 1
    fi

    echo ""
    log_info "已配置的客户端:"
    clients=$(grep "# Client:" "$WG_CONF" | cut -d' ' -f3)
    if [ -z "$clients" ]; then
        log_warn "  暂无客户端"
        echo ""
        log_info "客户端配置文件位置: ${CLIENT_DIR}/"
        press_any_key
        return 0
    else
        echo "$clients" | nl -w2 -s'. ' | sed 's/^/  /'
    fi

    echo ""
    log_info "当前连接的客户端:"
    if wg show wg0 &>/dev/null; then
        connected=$(wg show wg0 | grep -A 3 "peer:" | grep -E "(peer:|endpoint:|transfer:)" | sed 's/^/  /')
        if [ -z "$connected" ]; then
            log_warn "  暂无客户端连接"
        else
            echo "$connected"
        fi
    else
        log_warn "  WireGuard接口未运行"
    fi

    echo ""
    log_info "客户端配置文件位置: ${CLIENT_DIR}/"

    echo ""
    read -p "是否查看某个客户端的配置文件？(输入客户端编号/名称，或按Enter跳过): " input

    if [ -n "$input" ]; then
        if [[ "$input" =~ ^[0-9]+$ ]]; then
            CLIENT_NAME=$(echo "$clients" | sed -n "${input}p")
        else
            CLIENT_NAME="$input"
        fi

        if [ -z "$CLIENT_NAME" ]; then
            log_error "无效的客户端"
            press_any_key
            return 0
        fi

        if ! echo "$clients" | grep -q "^${CLIENT_NAME}$"; then
            log_error "客户端 $CLIENT_NAME 不存在"
            press_any_key
            return 0
        fi

        CLIENT_CONF="${CLIENT_DIR}/${CLIENT_NAME}.conf"
        if [ -f "$CLIENT_CONF" ]; then
            echo ""
            log_info "客户端 $CLIENT_NAME 的配置文件（完整内容，包含私钥）:"
            echo ""
            echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
            cat "$CLIENT_CONF"
            echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
            echo ""
            log_info "配置文件路径: $CLIENT_CONF"
        else
            log_error "客户端配置文件不存在: $CLIENT_CONF"
        fi
    fi

    press_any_key
}

show_client_qr() {
    show_wg_header

    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在"
        press_any_key
        return 1
    fi

    clients=$(grep "# Client:" "$WG_CONF" | cut -d' ' -f3)
    if [ -z "$clients" ]; then
        log_warn "暂无客户端"
        press_any_key
        return 1
    fi

    echo ""
    log_info "已配置的客户端:"
    echo "$clients" | nl -w2 -s'. '
    echo ""
    read -p "请输入要查看QR码的客户端编号或名称: " input

    if [[ "$input" =~ ^[0-9]+$ ]]; then
        CLIENT_NAME=$(echo "$clients" | sed -n "${input}p")
    else
        CLIENT_NAME="$input"
    fi

    if [ -z "$CLIENT_NAME" ]; then
        log_error "无效的客户端"
        press_any_key
        return 1
    fi

    CLIENT_CONF="${CLIENT_DIR}/${CLIENT_NAME}.conf"
    if [ ! -f "$CLIENT_CONF" ]; then
        log_error "客户端配置文件不存在: $CLIENT_CONF"
        press_any_key
        return 1
    fi

    if command -v qrencode &> /dev/null; then
        echo ""
        log_info "客户端 $CLIENT_NAME 的配置二维码:"
        echo ""
        qrencode -t ansiutf8 < "$CLIENT_CONF"
        echo ""
        log_info "配置文件路径: $CLIENT_CONF"
    else
        log_error "qrencode未安装，无法生成二维码"
        log_info "请先安装qrencode: apt-get install qrencode 或 yum install qrencode"
    fi

    press_any_key
}

start_service() {
    show_wg_header
    log_info "启动WireGuard服务..."

    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在，请先配置服务端！"
        press_any_key
        return 1
    fi

    systemctl start wg-quick@wg0
    sleep 1
    if systemctl is-active --quiet wg-quick@wg0; then
        log_success "WireGuard服务已启动"
    else
        log_error "WireGuard服务启动失败"
        systemctl status wg-quick@wg0 --no-pager -l
    fi
    press_any_key
}

stop_service() {
    show_wg_header
    log_info "停止WireGuard服务..."
    systemctl stop wg-quick@wg0
    sleep 1
    if ! systemctl is-active --quiet wg-quick@wg0; then
        log_success "WireGuard服务已停止"
    else
        log_error "WireGuard服务停止失败"
    fi
    press_any_key
}

restart_service() {
    show_wg_header
    log_info "重启WireGuard服务..."

    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在，请先配置服务端！"
        press_any_key
        return 1
    fi

    systemctl restart wg-quick@wg0
    sleep 1
    if systemctl is-active --quiet wg-quick@wg0; then
        log_success "WireGuard服务已重启"
    else
        log_error "WireGuard服务重启失败"
        systemctl status wg-quick@wg0 --no-pager -l
    fi
    press_any_key
}

show_status() {
    show_wg_header

    echo ""
    log_info "WireGuard服务状态:"
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        log_success "服务运行中"
    else
        log_warn "服务未运行"
    fi

    echo ""
    log_info "WireGuard接口信息:"
    if wg show &>/dev/null; then
        wg show | sed 's/^/  /'
    else
        log_warn "  WireGuard接口未运行"
    fi

    echo ""
    log_info "网络接口状态:"
    if ip addr show wg0 &>/dev/null; then
        ip addr show wg0 | sed 's/^/  /'
    else
        log_warn "  wg0接口未启动"
    fi

    echo ""
    log_info "系统信息:"
    echo "  配置文件: $WG_CONF"
    if [ -f "$WG_CONF" ]; then
        echo "  服务端端口: $(grep 'ListenPort' "$WG_CONF" | cut -d'=' -f2 | tr -d ' ')"
        echo "  客户端数量: $(grep -c '# Client:' "$WG_CONF" || echo '0')"
    fi

    press_any_key
}

show_config_info() {
    local interface_name=$1
    local config_file="${WG_DIR}/${interface_name}.conf"

    if [ ! -f "$config_file" ]; then
        log_error "WireGuard配置不存在: $config_file"
        return 1
    fi

    log_info "=== WireGuard 配置信息 ==="
    echo "接口名称: $interface_name"
    echo "配置文件: $config_file"
    echo "服务器公钥: $(cat ${WG_DIR}/${interface_name}.publickey 2>/dev/null || echo '未找到')"
    echo "服务器私钥: $(cat ${WG_DIR}/${interface_name}.privatekey 2>/dev/null || echo '未找到')"
    echo "监听端口: $(grep "ListenPort" "$config_file" | cut -d'=' -f2 | tr -d ' ')"
    echo "内网网段: $(grep "Address" "$config_file" | head -1 | cut -d'=' -f2 | tr -d ' ' | cut -d'.' -f1-3).0/24"

    log_info "=== 客户端列表 ==="
    if [[ -d "$CLIENT_DIR" ]]; then
        for client_file in "$CLIENT_DIR"/*.conf; do
            if [[ -f "$client_file" ]]; then
                local client_name
                client_name=$(basename "$client_file" .conf)
                local client_ip
                client_ip=$(grep "Address" "$client_file" | cut -d'=' -f2 | tr -d ' ' | cut -d'/' -f1)
                echo "客户端: $client_name, IP: $client_ip"
            fi
        done
    fi
}

modify_wg_port() {
    local interface_name=$1
    local config_file="${WG_DIR}/${interface_name}.conf"

    if [[ ! -f "$config_file" ]]; then
        log_error "WireGuard配置不存在: $config_file"
        return 1
    fi

    log_info "当前端口: $(grep "ListenPort" "$config_file" | cut -d'=' -f2 | tr -d ' ')"
    read -p "请输入新的端口号: " new_port

    if [[ ! $new_port =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1024 ] || [ "$new_port" -gt 65535 ]; then
        log_error "端口号必须在1024-65535之间"
        return 1
    fi

    systemctl stop "wg-quick@${interface_name}" 2>/dev/null || true

    sed -i "s/ListenPort = .*/ListenPort = $new_port/" "$config_file"

    configure_firewall "$new_port"

    systemctl start "wg-quick@${interface_name}" 2>/dev/null || true

    log_info "端口已修改为: $new_port"
    log_info "请更新所有客户端的Endpoint端口"
}

setup_nat() {
    show_wg_header
    log_info "配置NAT转发..."

    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在，请先配置服务端！"
        press_any_key
        return 1
    fi

    log_info "正在自动检测默认出口网卡..."
    EXTERNAL_IF=$(get_default_iface)
    if [ -z "$EXTERNAL_IF" ]; then
        EXTERNAL_IF="eth0"
    fi

    echo ""
    log_info "检测到默认出口网卡: $EXTERNAL_IF"
    echo ""
    log_info "可用的网络接口:"
    ip -o link show | awk -F': ' '{print "  " $2}'
    echo ""
    read -p "请输入外网接口名称 [默认: $EXTERNAL_IF]: " input_if
    EXTERNAL_IF=${input_if:-$EXTERNAL_IF}

    if ! ip link show "$EXTERNAL_IF" &>/dev/null; then
        log_error "接口 $EXTERNAL_IF 不存在！"
        press_any_key
        return 1
    fi

    log_info "更新NAT转发配置..."
    cp "$WG_CONF" "${WG_CONF}.bak.$(date +%Y%m%d_%H%M%S)"

    sed -i "s|PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o .* -j MASQUERADE|PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $EXTERNAL_IF -j MASQUERADE|g" "$WG_CONF"
    sed -i "s|PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o .* -j MASQUERADE|PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $EXTERNAL_IF -j MASQUERADE|g" "$WG_CONF"

    if ! grep -q "PostUp" "$WG_CONF"; then
        sed -i "/^\[Interface\]/a PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $EXTERNAL_IF -j MASQUERADE" "$WG_CONF"
        sed -i "/PostUp =/a PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $EXTERNAL_IF -j MASQUERADE" "$WG_CONF"
    fi

    if [ ! -f /etc/sysctl.d/99-wireguard.conf ]; then
        log_info "配置IP转发..."
        echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard.conf
        sysctl -p /etc/sysctl.d/99-wireguard.conf
    fi

    log_success "NAT转发配置已更新"
    log_info "出口网卡: $EXTERNAL_IF"

    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        echo ""
        read -p "WireGuard服务正在运行，是否重启以应用新配置？(Y/n): " restart
        if [ "$restart" != "n" ] && [ "$restart" != "N" ]; then
            systemctl restart wg-quick@wg0
            if systemctl is-active --quiet wg-quick@wg0; then
                log_success "服务已重启，新配置已生效"
            else
                log_error "服务重启失败"
            fi
        fi
    fi

    press_any_key
}

uninstall_wireguard() {
    show_wg_header
    log_warn "警告：此操作将完全删除WireGuard服务端和所有客户端配置！"
    echo ""
    read -p "确认要完全卸载WireGuard吗？(yes/N): " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "取消卸载"
        press_any_key
        return 0
    fi

    log_info "开始完全卸载WireGuard..."

    for service in $(systemctl list-units --type=service --all 2>/dev/null | grep -o 'wg-quick@[^.]*' | sort -u); do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            systemctl stop "$service" 2>/dev/null
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            systemctl disable "$service" 2>/dev/null
        fi
    done

    for wg_interface in $(ip link show 2>/dev/null | grep -oE 'wg[0-9]+' | sort -u); do
        if ip link show "$wg_interface" &>/dev/null; then
            wg-quick down "$wg_interface" 2>/dev/null || ip link delete "$wg_interface" 2>/dev/null
        fi
    done

    WG_PORT=""
    if [ -f "$WG_CONF" ]; then
        WG_PORT=$(grep "ListenPort" "$WG_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    fi

    if command -v iptables &>/dev/null; then
        while iptables -C FORWARD -i wg+ -j ACCEPT 2>/dev/null; do
            iptables -D FORWARD -i wg+ -j ACCEPT 2>/dev/null
        done
        while iptables -C FORWARD -o wg+ -j ACCEPT 2>/dev/null; do
            iptables -D FORWARD -o wg+ -j ACCEPT 2>/dev/null
        done
    fi

    if [ -n "$WG_PORT" ]; then
        firewall_type=$(detect_firewall)
        case $firewall_type in
            firewalld)
                firewall-cmd --permanent --remove-port="${WG_PORT}/udp" 2>/dev/null || true
                firewall-cmd --permanent --remove-port="${WG_PORT}/tcp" 2>/dev/null || true
                firewall-cmd --reload 2>/dev/null || true
                ;;
            ufw)
                ufw delete allow ${WG_PORT}/udp 2>/dev/null || true
                ufw delete allow ${WG_PORT}/tcp 2>/dev/null || true
                ;;
        esac
    fi

    if [ -d "$WG_DIR" ]; then
        rm -rf "$WG_DIR"
        log_success "已删除目录: $WG_DIR"
    fi

    if [ -f /etc/sysctl.d/99-wireguard.conf ]; then
        rm -f /etc/sysctl.d/99-wireguard.conf
        sysctl -p > /dev/null 2>&1 || true
    fi

    read -p "是否卸载WireGuard软件包？(y/N): " uninstall_pkg
    if [ "$uninstall_pkg" = "y" ] || [ "$uninstall_pkg" = "Y" ]; then
        if detect_distro; then
            case $DISTRO in
                ubuntu|debian)
                    apt-get remove -y wireguard wireguard-tools qrencode 2>/dev/null
                    apt-get autoremove -y 2>/dev/null
                    ;;
                centos|rhel|fedora)
                    if command -v dnf &> /dev/null; then
                        dnf remove -y wireguard-tools qrencode 2>/dev/null
                    else
                        yum remove -y wireguard-tools qrencode 2>/dev/null
                    fi
                    ;;
                arch|manjaro)
                    pacman -R --noconfirm wireguard-tools qrencode 2>/dev/null
                    ;;
            esac
        fi
    fi

    log_success "WireGuard已完全卸载"
    press_any_key
}

# ===== 其他模块 =====
deploy_xui() {
    show_header
    log_info "开始部署 x-ui 面板..."

    if command -v x-ui &>/dev/null || systemctl list-units --all | grep -q x-ui; then
        log_warn "检测到 x-ui 可能已安装"
        read -p "是否继续重新安装？(y/N): " reinstall
        if [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ]; then
            log_info "取消安装"
            press_any_key
            return 0
        fi
    fi

    local install_url="https://raw.githubusercontent.com/yonggekkk/x-ui-yg/main/install.sh"
    echo ""
    log_info "正在下载并执行 x-ui 安装脚本..."
    log_info "安装脚本来源: $install_url"
    echo ""

    if command -v wget &>/dev/null; then
        if bash <(wget -qO- "$install_url"); then
            echo ""
            log_success "x-ui 面板部署完成"
            log_info "请按照安装脚本的提示访问 x-ui 面板"
        else
            echo ""
            log_error "x-ui 面板部署失败"
            log_info "请检查网络连接或手动执行安装脚本"
        fi
    elif command -v curl &>/dev/null; then
        if bash <(curl -fsSL "$install_url"); then
            echo ""
            log_success "x-ui 面板部署完成"
            log_info "请按照安装脚本的提示访问 x-ui 面板"
        else
            echo ""
            log_error "x-ui 面板部署失败"
            log_info "请检查网络连接或手动执行安装脚本"
        fi
    else
        log_error "未找到 wget 或 curl，无法下载 x-ui 安装脚本"
    fi

    press_any_key
}

# ===== CLI 与菜单 =====
show_main_menu() {
    show_header
    echo -e "${BOLD}请选择操作:${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}. 🔐 WireGuard 管理"
    echo -e "  ${GREEN}2${NC}. 🧰 x-ui 面板部署"
    echo -e "  ${RED}0${NC}. 👋 退出"
    echo ""
}

show_wireguard_menu() {
    show_wg_header
    echo -e "${BOLD}请选择操作:${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}. 📦 安装 WireGuard"
    echo -e "  ${GREEN}2${NC}. ⚙️  配置服务端"
    echo -e "  ${GREEN}3${NC}. ➕ 添加客户端"
    echo -e "  ${GREEN}4${NC}. ➖ 删除客户端"
    echo -e "  ${GREEN}5${NC}. 📋 列出客户端"
    echo -e "  ${GREEN}6${NC}. 📱 显示客户端QR码"
    echo -e "  ${GREEN}7${NC}. 🔀 配置NAT转发"
    echo -e "  ${GREEN}8${NC}. 🔥 配置防火墙规则"
    echo -e "  ${GREEN}9${NC}. 🚀 安装BBR网络优化"
    echo -e "  ${GREEN}10${NC}. ▶️  启动服务"
    echo -e "  ${GREEN}11${NC}. ⏹️  停止服务"
    echo -e "  ${GREEN}12${NC}. 🔄 重启服务"
    echo -e "  ${GREEN}13${NC}. 📊 查看状态"
    echo -e "  ${GREEN}14${NC}. 🔧 修改WG端口"
    echo -e "  ${GREEN}15${NC}. 📄 查看配置信息"
    echo -e "  ${RED}16${NC}. 🗑️  完全卸载"
    echo -e "  ${YELLOW}0${NC}. ⬅️  返回上级菜单"
    echo ""
}

wireguard_menu_loop() {
    while true; do
        show_wireguard_menu
        read -p "请输入选项 [0-16]: " choice
        echo ""

        case $choice in
            1) install_wireguard ;;
            2) setup_server ;;
            3) add_client ;;
            4) remove_client ;;
            5) list_clients ;;
            6) show_client_qr ;;
            7) setup_nat ;;
            8) setup_firewall ;;
            9) install_bbr ;;
            10) start_service ;;
            11) stop_service ;;
            12) restart_service ;;
            13) show_status ;;
            14)
                read -p "请输入WireGuard接口名称 [默认: wg0]: " interface_name
                interface_name=${interface_name:-wg0}
                modify_wg_port "$interface_name"
                press_any_key
                ;;
            15)
                read -p "请输入WireGuard接口名称 [默认: wg0]: " interface_name
                interface_name=${interface_name:-wg0}
                show_config_info "$interface_name"
                press_any_key
                ;;
            16) uninstall_wireguard ;;
            0) return 0 ;;
            *)
                log_error "无效选项，请重新选择"
                sleep 1
                ;;
        esac
    done
}

usage() {
    cat <<'USAGE'
使用方法:
  ./auto-linux.sh [module] [command]

模块:
  wg          WireGuard 管理
  xui         x-ui 面板部署

WireGuard 命令:
  install         安装 WireGuard
  setup-server    配置服务端
  add-client      添加客户端
  remove-client   删除客户端
  list-clients    列出客户端
  show-qr         显示客户端二维码
  setup-nat       配置 NAT 转发
  setup-firewall  配置防火墙规则
  install-bbr     安装 BBR 网络优化
  start           启动服务
  stop            停止服务
  restart         重启服务
  status          查看状态
  modify-port     修改端口
  show-config     查看配置信息
  uninstall       完全卸载

示例:
  ./auto-linux.sh wg install
  ./auto-linux.sh wg add-client
  ./auto-linux.sh xui

未提供参数时，将进入交互式菜单。
USAGE
}

main() {
    check_root

    if [ $# -gt 0 ]; then
        case "$1" in
            wg)
                shift
                case "$1" in
                    install) install_wireguard ;;
                    setup-server) setup_server ;;
                    add-client) add_client ;;
                    remove-client) remove_client ;;
                    list-clients) list_clients ;;
                    show-qr) show_client_qr ;;
                    setup-nat) setup_nat ;;
                    setup-firewall) setup_firewall ;;
                    install-bbr) install_bbr ;;
                    start) start_service ;;
                    stop) stop_service ;;
                    restart) restart_service ;;
                    status) show_status ;;
                    modify-port)
                        interface_name=${2:-wg0}
                        modify_wg_port "$interface_name"
                        ;;
                    show-config)
                        interface_name=${2:-wg0}
                        show_config_info "$interface_name"
                        ;;
                    uninstall) uninstall_wireguard ;;
                    help|--help|-h|"") usage ;;
                    *)
                        log_error "未知WireGuard命令: $1"
                        usage
                        exit 1
                        ;;
                esac
                exit 0
                ;;
            xui)
                deploy_xui
                exit 0
                ;;
            help|--help|-h)
                usage
                exit 0
                ;;
            *)
                log_error "未知模块: $1"
                usage
                exit 1
                ;;
        esac
    fi

    while true; do
        show_main_menu
        read -p "请输入选项 [0-2]: " choice
        echo ""

        case $choice in
            1) wireguard_menu_loop ;;
            2) deploy_xui ;;
            0)
                clear_screen
                log_info "感谢使用！再见！"
                exit 0
                ;;
            *)
                log_error "无效选项，请重新选择"
                sleep 1
                ;;
        esac
    done
}

main "$@"
