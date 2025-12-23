#!/bin/bash

# 服务器部署管理脚本
# 支持部署 WireGuard VPN 和 x-ui 面板
# 提供完整的服务管理和配置功能（交互式菜单版）

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# 配置目录
WG_DIR="/etc/wireguard"
WG_CONF="${WG_DIR}/wg0.conf"

# 日志函数（带emoji）
log_info() {
    echo -e "${GREEN}[INFO]${NC} ℹ️  $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} ⚠️  $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} ❌ $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} 🔍 $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} ✅ $1"
}

# 清屏
clear_screen() {
    clear
}

# 显示标题（通用）
show_header() {
    clear_screen
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           ws自动化部署工具                                  ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# 显示WireGuard标题
show_wg_header() {
    clear_screen
    echo -e "${CYAN}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║           WireGuard 服务端/客户端管理工具                ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
}

# 等待用户按键
press_any_key() {
    echo ""
    read -p "按 Enter 键继续..." dummy
}

# 检测Linux发行版
detect_distro() {
    log_info "正在检测Linux发行版..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        log_info "检测到发行版: $DISTRO $VERSION"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        log_info "检测到发行版: RHEL/CentOS"
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
        log_info "检测到发行版: Debian"
    else
        log_error "无法检测Linux发行版"
        return 1
    fi
    
    # 检测架构
    ARCH=$(uname -m)
    log_info "系统架构: $ARCH"
    return 0
}

# 检查是否为root用户
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        log_error "请使用root权限运行此脚本"
        exit 1
    fi
}

# 安装WireGuard
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
    
    # 启用IP转发
    if [ ! -f /etc/sysctl.d/99-wireguard.conf ]; then
        log_info "配置IP转发..."
        echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard.conf
        sysctl -p /etc/sysctl.d/99-wireguard.conf
    fi
    
    log_success "WireGuard安装完成！ 🎉"
    
    # 询问是否安装BBR网络优化
    echo ""
    read -p "是否安装BBR网络优化？(Y/n): " install_bbr
    if [ "$install_bbr" != "n" ] && [ "$install_bbr" != "N" ]; then
        install_bbr
    fi
    
    # 如果是首次安装，询问是否立即配置服务端
    if [ ! -f "$WG_CONF" ]; then
        echo ""
        read -p "是否立即配置服务端？(Y/n): " setup_now
        if [ "$setup_now" != "n" ] && [ "$setup_now" != "N" ]; then
            # 直接调用首次配置，不需要press_any_key，因为setup_server_first_time内部会处理
            setup_server_first_time
            return 0
        fi
    fi
    press_any_key
}

# 安装和配置BBR网络优化
install_bbr() {
    show_wg_header
    log_info "开始安装和配置BBR网络优化 🚀"
    
    # 检查内核版本（BBR需要Linux 4.9+）
    KERNEL_VERSION=$(uname -r | cut -d'.' -f1,2)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d'.' -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d'.' -f2)
    
    if [ "$KERNEL_MAJOR" -lt 4 ] || ([ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 9 ]); then
        log_warn "当前内核版本 $KERNEL_VERSION 不支持BBR（需要4.9+），跳过安装"
        press_any_key
        return 1
    fi
    
    log_info "检测到内核版本: $(uname -r) ✅"
    
    # 检查BBR是否已启用
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        log_info "BBR已启用，跳过安装"
        press_any_key
        return 0
    fi
    
    # 加载BBR模块
    log_info "加载BBR内核模块..."
    modprobe tcp_bbr 2>/dev/null || log_warn "无法加载tcp_bbr模块，可能需要更新内核"
    
    # 配置BBR参数
    log_info "配置BBR网络优化参数..."
    
    # 创建或更新sysctl配置
    BBR_CONF="/etc/sysctl.d/99-bbr.conf"
    cat > "$BBR_CONF" <<EOF
# BBR网络优化配置
# TCP BBR拥塞控制算法
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP优化参数
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000

# UDP优化参数（增强版）
# UDP缓冲区大小（最小值、默认值、最大值）
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 524288
net.core.wmem_default = 524288
# UDP内存限制（最小值、压力值、最大值，单位：页）
net.ipv4.udp_mem = 524288 1048576 33554432

# UDP特定优化
# 减少UDP包丢失（增加接收队列）
net.core.netdev_max_backlog = 10000
net.core.netdev_budget = 600
# UDP接收缓冲区自动调整
net.ipv4.udp_rmem_min = 4096
net.ipv4.udp_wmem_min = 4096

# 网络缓冲区优化
net.core.somaxconn = 8192
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

# 连接跟踪优化（UDP连接）
net.netfilter.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

# 网络接口队列优化（提升UDP性能）
net.core.netdev_budget_usecs = 5000
net.core.netdev_tstamp_prequeue = 1

# IP层优化（影响UDP传输）
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.ipfrag_high_thresh = 4194304
net.ipv4.ipfrag_low_thresh = 3145728
EOF
    
    # 应用配置
    sysctl -p "$BBR_CONF" > /dev/null 2>&1
    
    # 验证BBR是否启用
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q "bbr"; then
        log_success "BBR网络优化已成功启用！ 🎉"
        log_info "TCP拥塞控制算法: $(sysctl -n net.ipv4.tcp_congestion_control)"
        log_info "默认队列规则: $(sysctl -n net.core.default_qdisc)"
    else
        log_warn "BBR启用失败，可能需要重启系统或更新内核"
        log_info "配置文件已保存: $BBR_CONF"
        log_info "重启后BBR将自动启用"
    fi
    
    # 确保BBR模块开机自动加载
    if [ ! -f /etc/modules-load.d/bbr.conf ]; then
        echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
        log_info "已配置BBR模块开机自动加载"
    fi
    
    press_any_key
}

# 生成密钥对
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

# 检测防火墙类型
detect_firewall() {
    local firewall_type="none"
    
    # 检测 firewalld
    if systemctl is-active --quiet firewalld 2>/dev/null || systemctl is-enabled --quiet firewalld 2>/dev/null; then
        firewall_type="firewalld"
    # 检测 ufw
    elif systemctl is-active --quiet ufw 2>/dev/null || command -v ufw &>/dev/null; then
        firewall_type="ufw"
    # 检测 iptables (通过检查是否有规则)
    elif command -v iptables &>/dev/null && iptables -L -n 2>/dev/null | grep -q "Chain"; then
        firewall_type="iptables"
    # 检测 nftables
    elif command -v nft &>/dev/null && nft list ruleset &>/dev/null 2>&1; then
        firewall_type="nftables"
    fi
    
    echo "$firewall_type"
}

# 配置防火墙规则
configure_firewall() {
    local port=$1
    local firewall_type=$(detect_firewall)
    
    if [ "$firewall_type" = "none" ]; then
        log_warn "未检测到防火墙服务，跳过防火墙配置"
        return 0
    fi
    
    log_info "检测到防火墙类型: $firewall_type"
    log_info "正在配置防火墙规则..."
    
    case $firewall_type in
        firewalld)
            # 确保firewalld服务运行
            if ! systemctl is-active --quiet firewalld; then
                log_info "启动firewalld服务..."
                systemctl start firewalld
                systemctl enable firewalld
            fi
            
            # 优先确保SSH端口22开放（关键！必须最先配置）
            if ! firewall-cmd --permanent --query-service=ssh &>/dev/null; then
                firewall-cmd --permanent --add-service=ssh 2>/dev/null
                log_success "已确保SSH服务(端口22)开放（优先级最高）"
            else
                log_info "SSH服务(端口22)已在firewalld中开放"
            fi
            
            # 开放WireGuard端口（UDP和TCP）
            if firewall-cmd --permanent --query-port="${port}/udp" &>/dev/null; then
                log_info "端口 $port/udp 已在firewalld中开放"
            else
                firewall-cmd --permanent --add-port="${port}/udp" 2>/dev/null
                log_success "已开放WireGuard端口 $port/udp 🔓"
            fi
            
            # 同时开放TCP端口（用于备用或特殊场景）
            if firewall-cmd --permanent --query-port="${port}/tcp" &>/dev/null; then
                log_info "端口 $port/tcp 已在firewalld中开放"
            else
                firewall-cmd --permanent --add-port="${port}/tcp" 2>/dev/null
                log_success "已开放WireGuard端口 $port/tcp 🔓"
            fi
            
            # 重新加载firewalld配置
            firewall-cmd --reload 2>/dev/null
            log_success "firewalld配置已重新加载"
            ;;
            
        ufw)
            # 确保ufw服务运行
            if ! systemctl is-active --quiet ufw 2>/dev/null; then
                log_info "启动ufw服务..."
                systemctl start ufw 2>/dev/null || ufw --force enable
            fi
            
            # 优先确保SSH端口22开放（关键！必须最先配置）
            if ! ufw status | grep -q "22/tcp"; then
                ufw allow 22/tcp comment 'SSH' 2>/dev/null
                log_success "已确保SSH端口22开放（优先级最高）"
            else
                log_info "SSH端口22已在ufw中开放"
            fi
            
            # 开放WireGuard端口（UDP和TCP）
            if ufw status | grep -q "${port}/udp"; then
                log_info "端口 $port/udp 已在ufw中开放"
            else
                ufw allow ${port}/udp comment 'WireGuard' 2>/dev/null
                log_success "已开放WireGuard端口 $port/udp 🔓"
            fi
            
            # 同时开放TCP端口（用于备用或特殊场景）
            if ufw status | grep -q "${port}/tcp"; then
                log_info "端口 $port/tcp 已在ufw中开放"
            else
                ufw allow ${port}/tcp comment 'WireGuard-TCP' 2>/dev/null
                log_success "已开放WireGuard端口 $port/tcp 🔓"
            fi
            
            # 确保ufw已启用
            ufw --force enable 2>/dev/null
            log_success "ufw配置已应用"
            ;;
            
        iptables)
            # 优先确保SSH端口22开放（关键！必须最先添加）
            if ! iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null; then
                iptables -I INPUT 1 -p tcp --dport 22 -j ACCEPT
                log_success "已确保SSH端口22在iptables中开放（优先级最高）"
            else
                log_info "SSH端口22已在iptables中开放"
            fi
            
            # 检查并添加WireGuard端口规则（UDP和TCP）
            if ! iptables -C INPUT -p udp --dport $port -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -p udp --dport $port -j ACCEPT
                log_success "已添加iptables规则：开放WireGuard端口 $port/udp 🔓"
            else
                log_info "端口 $port/udp 已在iptables中开放"
            fi
            
            # 同时开放TCP端口（用于备用或特殊场景）
            if ! iptables -C INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -p tcp --dport $port -j ACCEPT
                log_success "已添加iptables规则：开放WireGuard端口 $port/tcp 🔓"
            else
                log_info "端口 $port/tcp 已在iptables中开放"
            fi
            
            # 尝试保存iptables规则（如果可用）
            if command -v iptables-save &>/dev/null; then
                # 尝试保存到常见位置
                if [ -d /etc/iptables ]; then
                    iptables-save > /etc/iptables/rules.v4 2>/dev/null
                elif [ -f /etc/iptables.rules ]; then
                    iptables-save > /etc/iptables.rules 2>/dev/null
                fi
            fi
            log_success "iptables规则已配置"
            ;;
            
        nftables)
            # 优先确保SSH端口22开放（关键！必须最先添加）
            if ! nft list chain inet filter input 2>/dev/null | grep -q "tcp dport 22"; then
                nft insert rule inet filter input position 0 tcp dport 22 accept 2>/dev/null || \
                nft add rule inet filter input tcp dport 22 accept 2>/dev/null
                log_success "已确保SSH端口22在nftables中开放（优先级最高）"
            else
                log_info "SSH端口22已在nftables中开放"
            fi
            
            # 检查并添加WireGuard端口规则（UDP和TCP）
            if ! nft list chain inet filter input 2>/dev/null | grep -q "udp dport $port"; then
                nft add rule inet filter input udp dport $port accept 2>/dev/null || \
                nft insert rule inet filter input udp dport $port accept 2>/dev/null
                log_success "已添加nftables规则：开放WireGuard端口 $port/udp 🔓"
            else
                log_info "端口 $port/udp 已在nftables中开放"
            fi
            
            # 同时开放TCP端口（用于备用或特殊场景）
            if ! nft list chain inet filter input 2>/dev/null | grep -q "tcp dport $port"; then
                nft add rule inet filter input tcp dport $port accept 2>/dev/null || \
                nft insert rule inet filter input tcp dport $port accept 2>/dev/null
                log_success "已添加nftables规则：开放WireGuard端口 $port/tcp 🔓"
            else
                log_info "端口 $port/tcp 已在nftables中开放"
            fi
            
            # 保存nftables规则
            if [ -f /etc/nftables.conf ]; then
                nft list ruleset > /etc/nftables.conf 2>/dev/null
            fi
            log_success "nftables规则已配置"
            ;;
    esac
    
    return 0
}

# 防火墙配置菜单
setup_firewall() {
    show_wg_header
    log_info "配置防火墙规则..."
    
    # 获取WireGuard端口
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
    log_success "防火墙配置完成！ 🔥"
    log_info "WireGuard端口: $wg_port/udp 和 $wg_port/tcp 已开放 🔓"
    log_info "SSH端口: 22/tcp (已确保开放) 🔐"
    press_any_key
}

# 首次配置服务端（完整流程）
setup_server_first_time() {
    show_wg_header
    log_info "配置WireGuard服务端..."
    
    # 创建配置目录
    mkdir -p "$WG_DIR"
    
    # 如果配置文件已存在，备份
    if [ -f "$WG_CONF" ]; then
        cp "$WG_CONF" "${WG_CONF}.bak.$(date +%Y%m%d_%H%M%S)"
        log_info "已备份原配置文件"
    fi
    
    # 生成服务端密钥（如果不存在）
    SERVER_PRIVKEY="${WG_DIR}/server_private.key"
    SERVER_PUBKEY="${WG_DIR}/server_public.key"
    if [ ! -f "$SERVER_PRIVKEY" ]; then
        generate_keys "$SERVER_PRIVKEY" "$SERVER_PUBKEY"
    else
        log_info "使用现有服务端密钥"
    fi
    
    echo ""
    # 获取服务端名称
    read -p "请输入服务端名称 [默认: server]: " SERVER_NAME
    SERVER_NAME=${SERVER_NAME:-server}
    
    # 获取服务器IP
    read -p "请输入服务器公网IP或域名 [默认: 自动检测]: " SERVER_IP
    if [ -z "$SERVER_IP" ]; then
        log_info "正在自动检测IP..."
        SERVER_IP=$(curl -s ifconfig.me || curl -s ip.sb || echo "YOUR_SERVER_IP")
        log_info "自动检测到IP: $SERVER_IP"
    fi
    
    # 获取监听端口（支持随机）
    echo ""
    read -p "请输入WireGuard监听端口 [默认: 随机生成, 或输入具体端口]: " SERVER_PORT
    if [ -z "$SERVER_PORT" ]; then
        # 随机生成端口（10000-65535之间）
        SERVER_PORT=$((RANDOM % 55536 + 10000))
        log_info "随机生成端口: $SERVER_PORT"
    fi
    
    # 获取内网网段（用户只需输入C段）
    echo ""
    read -p "请输入VPN内网网段C段 [例如: 10.10.10, 默认: 10.8.0]: " VPN_C_SEGMENT
    if [ -z "$VPN_C_SEGMENT" ]; then
        VPN_C_SEGMENT="10.8.0"
    fi
    # 确保格式正确（去除末尾的点）
    VPN_C_SEGMENT=$(echo "$VPN_C_SEGMENT" | sed 's/\.$//')
    VPN_NETWORK="${VPN_C_SEGMENT}.0/24"
    log_info "完整网段: $VPN_NETWORK"
    
    # 自动识别外网接口名称
    echo ""
    log_info "正在自动检测默认出口网卡..."
    EXTERNAL_IF=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$EXTERNAL_IF" ]; then
        EXTERNAL_IF=$(ip route | grep "^default" | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
    fi
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
    
    # 生成服务端配置
    cat > "$WG_CONF" <<EOF
[Interface]
Address = $(echo $VPN_NETWORK | cut -d'/' -f1 | cut -d'.' -f1-3).1/24
ListenPort = $SERVER_PORT
PrivateKey = $(cat $SERVER_PRIVKEY)
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $EXTERNAL_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $EXTERNAL_IF -j MASQUERADE

EOF
    
    log_success "服务端配置已创建: $WG_CONF 📝"
    echo ""
    log_info "服务端公钥: $(cat $SERVER_PUBKEY) 🔑"
    echo ""
    
    # 自动配置防火墙
    echo ""
    log_info "正在自动配置防火墙... 🔥"
    configure_firewall "$SERVER_PORT"
    
    # 启用并启动服务
    systemctl enable wg-quick@wg0 > /dev/null 2>&1
    systemctl start wg-quick@wg0
    
    if systemctl is-active --quiet wg-quick@wg0; then
        log_success "WireGuard服务端已启动！ 🚀"
    else
        log_error "WireGuard服务端启动失败"
        systemctl status wg-quick@wg0 --no-pager -l
    fi
    
    # 首次配置完成后，自动创建第一个客户端（仅当没有客户端时）
    EXISTING_CLIENTS=$(grep -c "# Client:" "$WG_CONF" 2>/dev/null || echo "0")
    # 确保EXISTING_CLIENTS是数字
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

# 首次添加客户端（自动分配IP从2开始）
add_client_first_time() {
    local server_ip=$1
    local server_port=$2
    local vpn_c_segment=$3
    
    show_header
    log_info "创建第一个客户端..."
    
    # 获取客户端名称（支持默认）
    echo ""
    read -p "请输入客户端名称 [默认: client1]: " CLIENT_NAME
    CLIENT_NAME=${CLIENT_NAME:-client1}
    
    # 检查客户端是否已存在
    if grep -q "# Client: $CLIENT_NAME" "$WG_CONF" 2>/dev/null; then
        log_warn "客户端 $CLIENT_NAME 已存在，使用默认名称 client1"
        CLIENT_NAME="client1"
        # 如果client1也存在，自动递增
        counter=1
        while grep -q "# Client: $CLIENT_NAME" "$WG_CONF" 2>/dev/null; do
            counter=$((counter + 1))
            CLIENT_NAME="client${counter}"
        done
        log_info "使用客户端名称: $CLIENT_NAME"
    fi
    
    # 生成客户端密钥
    CLIENT_DIR="${WG_DIR}/clients"
    mkdir -p "$CLIENT_DIR"
    CLIENT_PRIVKEY="${CLIENT_DIR}/${CLIENT_NAME}_private.key"
    CLIENT_PUBKEY="${CLIENT_DIR}/${CLIENT_NAME}_public.key"
    generate_keys "$CLIENT_PRIVKEY" "$CLIENT_PUBKEY"
    
    # 获取服务端公钥
    SERVER_PRIVKEY_FILE="${WG_DIR}/server_private.key"
    if [ -f "$SERVER_PRIVKEY_FILE" ]; then
        SERVER_PUBKEY=$(cat "$SERVER_PRIVKEY_FILE" | wg pubkey)
    else
        log_error "无法找到服务端私钥文件"
        return 1
    fi
    
    # 分配客户端IP（从2开始）
    CLIENT_IP="${vpn_c_segment}.2"
    
    # 添加客户端到服务端配置
    cat >> "$WG_CONF" <<EOF

# Client: $CLIENT_NAME
[Peer]
PublicKey = $(cat $CLIENT_PUBKEY)
AllowedIPs = $CLIENT_IP/32
EOF
    
    # 生成客户端配置
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
    
    log_success "客户端配置已创建: $CLIENT_CONF 📝"
    
    # 重新加载配置
    wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || log_warn "配置重载失败，请手动重启服务"
    
    # 自动显示二维码
    if command -v qrencode &> /dev/null; then
        echo ""
        log_info "客户端配置二维码: 📱"
        echo ""
        qrencode -t ansiutf8 < "$CLIENT_CONF"
        echo ""
        log_info "也可以使用以下命令查看二维码:"
        echo "  qrencode -t ansiutf8 < $CLIENT_CONF"
    else
        log_warn "qrencode未安装，无法生成二维码"
        log_info "请安装qrencode以支持二维码显示功能"
    fi
    
    log_success "客户端 $CLIENT_NAME 添加成功！ ✅"
    log_info "客户端IP: $CLIENT_IP 🌐"
    log_info "配置文件路径: $CLIENT_CONF 📁"
}

# 配置服务端（通用函数，用于菜单）
setup_server() {
    show_wg_header
    log_info "配置WireGuard服务端..."
    
    # 检查是否已安装
    if ! command -v wg &> /dev/null; then
        log_warn "WireGuard未安装，正在安装..."
        if ! detect_distro; then
            press_any_key
            return 1
        fi
        install_wireguard
        # 安装完成后会自动进入首次配置流程
        return 0
    fi
    
    # 检查是否已配置
    if [ -f "$WG_CONF" ]; then
        log_warn "服务端配置已存在: $WG_CONF"
        read -p "是否要重新配置？(y/N): " confirm
        if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
            log_info "取消配置"
            press_any_key
            return 0
        fi
    fi
    
    # 如果是首次配置，使用首次配置函数
    if [ ! -f "$WG_CONF" ]; then
        setup_server_first_time
    else
        # 重新配置时也使用首次配置函数（简化流程）
        setup_server_first_time
    fi
}

# 添加客户端
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
        # 自动生成客户端名称
        EXISTING_COUNT=$(grep -c "# Client:" "$WG_CONF" 2>/dev/null || echo "0")
        # 确保EXISTING_COUNT是数字
        if ! [[ "$EXISTING_COUNT" =~ ^[0-9]+$ ]]; then
            EXISTING_COUNT=0
        fi
        CLIENT_NAME="client$((EXISTING_COUNT + 1))"
        log_info "自动生成客户端名称: $CLIENT_NAME"
    fi
    
    # 检查客户端是否已存在
    if grep -q "# Client: $CLIENT_NAME" "$WG_CONF" 2>/dev/null; then
        log_error "客户端 $CLIENT_NAME 已存在！"
        press_any_key
        return 1
    fi
    
    # 生成客户端密钥
    CLIENT_DIR="${WG_DIR}/clients"
    mkdir -p "$CLIENT_DIR"
    CLIENT_PRIVKEY="${CLIENT_DIR}/${CLIENT_NAME}_private.key"
    CLIENT_PUBKEY="${CLIENT_DIR}/${CLIENT_NAME}_public.key"
    generate_keys "$CLIENT_PRIVKEY" "$CLIENT_PUBKEY"
    
    # 获取服务端信息
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
    
    # 获取服务器公网IP
    echo ""
    read -p "请输入服务器公网IP或域名 [默认: 自动检测]: " SERVER_IP
    if [ -z "$SERVER_IP" ]; then
        log_info "正在自动检测IP..."
        SERVER_IP=$(curl -s ifconfig.me || curl -s ip.sb || echo "YOUR_SERVER_IP")
        log_info "自动检测到IP: $SERVER_IP"
    fi
    
    # 分配客户端IP（从2开始顺序分配）
    VPN_NET=$(echo $SERVER_ADDRESS | cut -d'.' -f1-3)
    # 获取已使用的IP地址
    USED_IPS=$(grep "AllowedIPs" "$WG_CONF" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.([0-9]+)' | cut -d'.' -f4 | sort -n)
    
    # 从2开始查找第一个可用的IP
    CLIENT_IP_NUM=2
    while echo "$USED_IPS" | grep -q "^${CLIENT_IP_NUM}$"; do
        CLIENT_IP_NUM=$((CLIENT_IP_NUM + 1))
        # 防止无限循环，最多到254
        if [ $CLIENT_IP_NUM -gt 254 ]; then
            log_error "IP地址池已满（最多支持253个客户端）"
            press_any_key
            return 1
        fi
    done
    
    CLIENT_IP="${VPN_NET}.${CLIENT_IP_NUM}"
    
    # 添加客户端到服务端配置
    cat >> "$WG_CONF" <<EOF

# Client: $CLIENT_NAME
[Peer]
PublicKey = $(cat $CLIENT_PUBKEY)
AllowedIPs = $CLIENT_IP/32
EOF
    
    # 生成客户端配置
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
    
    # 重新加载配置
    wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || log_warn "配置重载失败，请手动重启服务"
    
    # 自动显示二维码
    if command -v qrencode &> /dev/null; then
        echo ""
        log_info "客户端配置二维码:"
        echo ""
        qrencode -t ansiutf8 < "$CLIENT_CONF"
        echo ""
        log_info "也可以使用以下命令查看二维码:"
        echo "  qrencode -t ansiutf8 < $CLIENT_CONF"
    else
        log_warn "qrencode未安装，无法生成二维码"
        log_info "请安装qrencode以支持二维码显示功能"
    fi
    
    log_success "客户端 $CLIENT_NAME 添加成功！"
    log_info "配置文件路径: $CLIENT_CONF"
    press_any_key
}

# 删除客户端
remove_client() {
    show_wg_header
    
    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在"
        press_any_key
        return 1
    fi
    
    # 列出所有客户端
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
    
    # 判断是编号还是名称
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
    
    # 确认删除
    read -p "确认删除客户端 $CLIENT_NAME? (y/N): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        log_info "取消删除"
        press_any_key
        return 0
    fi
    
    # 从配置文件中删除客户端
    sed -i "/# Client: $CLIENT_NAME/,/^$/d" "$WG_CONF"
    
    # 删除客户端密钥和配置
    rm -f "${WG_DIR}/clients/${CLIENT_NAME}"*.key
    rm -f "${WG_DIR}/clients/${CLIENT_NAME}.conf"
    
    # 重新加载配置
    wg syncconf wg0 <(wg-quick strip wg0) 2>/dev/null || log_warn "配置重载失败，请手动重启服务"
    
    log_success "客户端 $CLIENT_NAME 已删除！"
    press_any_key
}

# 列出客户端
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
        log_info "客户端配置文件位置: ${WG_DIR}/clients/"
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
    log_info "客户端配置文件位置: ${WG_DIR}/clients/"
    
    # 询问是否查看客户端配置文件
    echo ""
    read -p "是否查看某个客户端的配置文件？(输入客户端编号/名称，或按Enter跳过): " input
    
    if [ -n "$input" ]; then
        # 判断是编号还是名称
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
        
        # 检查客户端是否存在
        if ! echo "$clients" | grep -q "^${CLIENT_NAME}$"; then
            log_error "客户端 $CLIENT_NAME 不存在"
            press_any_key
            return 0
        fi
        
        # 查看客户端配置文件
        CLIENT_CONF="${WG_DIR}/clients/${CLIENT_NAME}.conf"
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

# 启动服务
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

# 停止服务
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

# 重启服务
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

# 显示客户端QR码
show_client_qr() {
    show_wg_header
    
    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在"
        press_any_key
        return 1
    fi
    
    # 列出所有客户端
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
    
    # 判断是编号还是名称
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
    
    CLIENT_CONF="${WG_DIR}/clients/${CLIENT_NAME}.conf"
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

# 完全卸载WireGuard
uninstall_wireguard() {
    show_wg_header
    log_warn "警告：此操作将完全删除WireGuard服务端和所有客户端配置！"
    log_warn "包括所有配置文件、备份文件、虚拟网卡和残留数据！"
    echo ""
    read -p "确认要完全卸载WireGuard吗？(yes/N): " confirm
    if [ "$confirm" != "yes" ]; then
        log_info "取消卸载"
        press_any_key
        return 0
    fi
    
    log_info "开始完全卸载WireGuard..."
    
    # 停止并禁用所有WireGuard服务
    log_info "停止所有WireGuard服务..."
    for service in $(systemctl list-units --type=service --all 2>/dev/null | grep -o 'wg-quick@[^.]*' | sort -u); do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_info "停止服务: $service"
            systemctl stop "$service" 2>/dev/null
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            log_info "禁用服务: $service"
            systemctl disable "$service" 2>/dev/null
        fi
    done
    
    # 删除所有WireGuard虚拟网卡
    log_info "删除所有WireGuard虚拟网卡..."
    # 方法1: 通过ip link查找wireguard类型接口
    for wg_interface in $(ip link show type wireguard 2>/dev/null | grep -oE 'wg[0-9]+' | sort -u); do
        if ip link show "$wg_interface" &>/dev/null; then
            log_info "删除虚拟网卡: $wg_interface"
            wg-quick down "$wg_interface" 2>/dev/null || ip link delete "$wg_interface" 2>/dev/null
        fi
    done
    # 方法2: 通过ip link查找所有wg开头的接口（兼容性更好）
    for wg_interface in $(ip link show 2>/dev/null | grep -oE 'wg[0-9]+' | sort -u); do
        if ip link show "$wg_interface" &>/dev/null; then
            log_info "删除虚拟网卡: $wg_interface"
            wg-quick down "$wg_interface" 2>/dev/null || ip link delete "$wg_interface" 2>/dev/null
        fi
    done
    
    # 先读取端口信息（在删除配置文件之前）
    WG_PORT=""
    if [ -f "$WG_CONF" ]; then
        WG_PORT=$(grep "ListenPort" "$WG_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    fi
    
    # 清理iptables规则（与WireGuard相关的）
    log_info "清理iptables规则..."
    if command -v iptables &>/dev/null; then
        # 删除所有与wg接口相关的FORWARD规则（循环删除直到没有匹配的规则）
        while iptables -C FORWARD -i wg+ -j ACCEPT 2>/dev/null; do
            iptables -D FORWARD -i wg+ -j ACCEPT 2>/dev/null
        done
        while iptables -C FORWARD -o wg+ -j ACCEPT 2>/dev/null; do
            iptables -D FORWARD -o wg+ -j ACCEPT 2>/dev/null
        done
        # 删除所有与wg接口相关的FORWARD规则（精确匹配）
        for wg_if in wg0 wg1 wg2 wg3 wg4 wg5 wg6 wg7 wg8 wg9; do
            while iptables -C FORWARD -i "$wg_if" -j ACCEPT 2>/dev/null; do
                iptables -D FORWARD -i "$wg_if" -j ACCEPT 2>/dev/null
            done
            while iptables -C FORWARD -o "$wg_if" -j ACCEPT 2>/dev/null; do
                iptables -D FORWARD -o "$wg_if" -j ACCEPT 2>/dev/null
            done
        done
        # 删除NAT规则（MASQUERADE）- 只删除明确与wg接口相关的规则
        # 注意：MASQUERADE规则通常针对外部接口，这里只清理明确相关的
        external_if=$(ip route | grep default | awk '{print $5}' | head -1)
        if [ -n "$external_if" ] && [ -f "$WG_CONF" ]; then
            # 从配置文件中提取PostUp命令中的接口信息
            postup_rule=$(grep "PostUp" "$WG_CONF" 2>/dev/null | grep -oE "POSTROUTING.*-o [^ ]+" | awk '{print $NF}')
            if [ -n "$postup_rule" ]; then
                # 删除匹配的MASQUERADE规则
                while iptables -t nat -C POSTROUTING -o "$postup_rule" -j MASQUERADE 2>/dev/null; do
                    iptables -t nat -D POSTROUTING -o "$postup_rule" -j MASQUERADE 2>/dev/null
                done
            fi
        fi
    fi
    
    # 清理防火墙规则（WireGuard端口）
    if [ -n "$WG_PORT" ]; then
        log_info "清理防火墙规则（端口: $WG_PORT）..."
        firewall_type=$(detect_firewall)
        case $firewall_type in
            firewalld)
                firewall-cmd --permanent --remove-port="${WG_PORT}/udp" 2>/dev/null
                firewall-cmd --permanent --remove-port="${WG_PORT}/tcp" 2>/dev/null
                firewall-cmd --reload 2>/dev/null
                ;;
            ufw)
                ufw delete allow ${WG_PORT}/udp 2>/dev/null
                ufw delete allow ${WG_PORT}/tcp 2>/dev/null
                ;;
        esac
    fi
    
    # 删除整个WireGuard配置目录（包括所有备份文件）
    if [ -d "$WG_DIR" ]; then
        log_info "删除整个WireGuard配置目录（包括所有备份文件）..."
        rm -rf "$WG_DIR"
        log_success "已删除目录: $WG_DIR"
    fi
    
    # 删除sysctl配置
    if [ -f /etc/sysctl.d/99-wireguard.conf ]; then
        log_info "删除IP转发配置..."
        rm -f /etc/sysctl.d/99-wireguard.conf
        sysctl -p > /dev/null 2>&1
    fi
    
    # 询问是否卸载软件包
    read -p "是否卸载WireGuard软件包？(y/N): " uninstall_pkg
    if [ "$uninstall_pkg" = "y" ] || [ "$uninstall_pkg" = "Y" ]; then
        log_info "卸载WireGuard软件包..."
        if ! detect_distro; then
            log_warn "无法检测发行版，跳过软件包卸载"
        else
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
    
    log_success "WireGuard已完全卸载！"
    log_info "所有配置文件、密钥和服务已删除"
    press_any_key
}

# 配置NAT转发
setup_nat() {
    show_wg_header
    log_info "配置NAT转发..."
    
    if [ ! -f "$WG_CONF" ]; then
        log_error "服务端配置文件不存在，请先配置服务端！"
        press_any_key
        return 1
    fi
    
    # 自动识别默认出口网卡
    log_info "正在自动检测默认出口网卡..."
    EXTERNAL_IF=$(ip route | grep default | awk '{print $5}' | head -1)
    if [ -z "$EXTERNAL_IF" ]; then
        EXTERNAL_IF=$(ip route | grep "^default" | head -1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
    fi
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
    
    # 检查接口是否存在
    if ! ip link show "$EXTERNAL_IF" &>/dev/null; then
        log_error "接口 $EXTERNAL_IF 不存在！"
        press_any_key
        return 1
    fi
    
    # 更新配置文件中的NAT规则
    log_info "更新NAT转发配置..."
    
    # 备份原配置
    cp "$WG_CONF" "${WG_CONF}.bak.$(date +%Y%m%d_%H%M%S)"
    
    # 更新PostUp和PostDown规则
    sed -i "s|PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o .* -j MASQUERADE|PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $EXTERNAL_IF -j MASQUERADE|g" "$WG_CONF"
    sed -i "s|PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o .* -j MASQUERADE|PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $EXTERNAL_IF -j MASQUERADE|g" "$WG_CONF"
    
    # 如果配置中没有PostUp/PostDown，添加它们
    if ! grep -q "PostUp" "$WG_CONF"; then
        SERVER_ADDRESS=$(grep "Address" "$WG_CONF" | head -1 | cut -d'=' -f2 | tr -d ' ')
        VPN_NET=$(echo $SERVER_ADDRESS | cut -d'/' -f1 | cut -d'.' -f1-3)
        sed -i "/^\[Interface\]/a PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $EXTERNAL_IF -j MASQUERADE" "$WG_CONF"
        sed -i "/PostUp =/a PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $EXTERNAL_IF -j MASQUERADE" "$WG_CONF"
    fi
    
    # 确保IP转发已启用
    if [ ! -f /etc/sysctl.d/99-wireguard.conf ]; then
        log_info "配置IP转发..."
        echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
        echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard.conf
        sysctl -p /etc/sysctl.d/99-wireguard.conf
    fi
    
    log_success "NAT转发配置已更新！"
    log_info "出口网卡: $EXTERNAL_IF"
    
    # 如果服务正在运行，重启服务以应用新配置
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

# 查看状态
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

# 部署 x-ui 面板
deploy_xui() {
    show_header
    log_info "开始部署 x-ui 面板..."
    
    # 检查是否已安装
    if command -v x-ui &>/dev/null || systemctl list-units --all | grep -q x-ui; then
        log_warn "检测到 x-ui 可能已安装"
        read -p "是否继续重新安装？(y/N): " reinstall
        if [ "$reinstall" != "y" ] && [ "$reinstall" != "Y" ]; then
            log_info "取消安装"
            press_any_key
            return 0
        fi
    fi
    
    echo ""
    log_info "正在下载并执行 x-ui 安装脚本..."
    log_info "安装脚本来源: https://raw.githubusercontent.com/yonggekkk/x-ui-yg/main/install.sh"
    echo ""
    
    # 下载并执行安装脚本
    if bash <(wget -qO- https://raw.githubusercontent.com/yonggekkk/x-ui-yg/main/install.sh); then
        echo ""
        log_success "x-ui 面板部署完成！ 🎉"
        log_info "请按照安装脚本的提示访问 x-ui 面板"
    else
        echo ""
        log_error "x-ui 面板部署失败"
        log_info "请检查网络连接或手动执行安装脚本"
    fi
    
    press_any_key
}

# 显示主菜单（顶级菜单）
show_main_menu() {
    show_header
    
    echo -e "${BOLD}请选择要部署的服务:${NC}"
    echo ""
    echo -e "  ${GREEN}1${NC}. 🔐 部署 WireGuard VPN"
    echo -e "  ${GREEN}2${NC}. 🌐 部署 x-ui 面板"
    echo -e "  ${RED}0${NC}. 👋 退出"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# 显示WireGuard菜单
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
    echo -e "  ${RED}14${NC}. 🗑️  完全卸载"
    echo -e "  ${YELLOW}0${NC}. ⬅️  返回上级菜单"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# WireGuard 子菜单循环
wireguard_menu_loop() {
    while true; do
        show_wireguard_menu
        read -p "请输入选项 [0-14]: " choice
        echo ""
        
        case $choice in
            1)
                install_wireguard
                ;;
            2)
                setup_server
                ;;
            3)
                add_client
                ;;
            4)
                remove_client
                ;;
            5)
                list_clients
                ;;
            6)
                show_client_qr
                ;;
            7)
                setup_nat
                ;;
            8)
                setup_firewall
                ;;
            9)
                install_bbr
                ;;
            10)
                start_service
                ;;
            11)
                stop_service
                ;;
            12)
                restart_service
                ;;
            13)
                show_status
                ;;
            14)
                uninstall_wireguard
                ;;
            0)
                return 0
                ;;
            *)
                log_error "无效选项，请重新选择"
                sleep 1
                ;;
        esac
    done
}

# 主循环
main() {
    check_root
    
    # 如果提供了命令行参数，执行对应操作后退出
    if [ $# -gt 0 ]; then
        case "$1" in
            install)
                install_wireguard
                ;;
            setup-server)
                setup_server
                ;;
            add-client)
                add_client
                ;;
            remove-client)
                remove_client
                ;;
            list-clients)
                list_clients
                ;;
            show-qr)
                show_client_qr
                ;;
            setup-nat)
                setup_nat
                ;;
            setup-firewall)
                setup_firewall
                ;;
            install-bbr)
                install_bbr
                ;;
            uninstall)
                uninstall_wireguard
                ;;
            start)
                start_service
                ;;
            stop)
                stop_service
                ;;
            restart)
                restart_service
                ;;
            status)
                show_status
                ;;
            help|--help|-h)
                echo "WireGuard 管理脚本 - 交互式菜单版"
                echo "直接运行脚本进入交互式菜单，或使用命令参数执行特定操作"
                echo ""
                echo "可用命令:"
                echo "  install          - 安装WireGuard"
                echo "  setup-server     - 配置服务端"
                echo "  add-client       - 添加客户端"
                echo "  remove-client    - 删除客户端"
                echo "  list-clients     - 列出客户端"
                echo "  show-qr          - 显示客户端QR码"
                echo "  setup-nat        - 配置NAT转发"
                echo "  setup-firewall   - 配置防火墙规则"
                echo "  install-bbr      - 安装BBR网络优化"
                echo "  uninstall        - 完全卸载WireGuard"
                echo "  start            - 启动服务"
                echo "  stop             - 停止服务"
                echo "  restart          - 重启服务"
                echo "  status           - 查看状态"
                ;;
            *)
                log_error "未知命令: $1"
                ;;
        esac
        exit 0
    fi
    
    # 交互式顶级菜单循环
    while true; do
        show_main_menu
        read -p "请输入选项 [0-2]: " choice
        echo ""
        
        case $choice in
            1)
                # 进入 WireGuard 子菜单
                wireguard_menu_loop
                ;;
            2)
                # 部署 x-ui 面板
                deploy_xui
                ;;
            0)
                clear_screen
                log_info "感谢使用！再见！ 👋"
                exit 0
                ;;
            *)
                log_error "无效选项，请重新选择"
                sleep 1
                ;;
        esac
    done
}

# 运行主函数
main "$@"
