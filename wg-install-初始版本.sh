#!/bin/bash

# WireGuard 自动安装部署脚本
# 功能：自动安装WireGuard，自定义配置，生成客户端配置

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

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
        log_error "此脚本仅适用于Debian系统"
        exit 1
    fi
}

# 安装WireGuard
install_wireguard() {
    log_info "开始安装WireGuard..."
    
    # 更新软件包列表
    apt update
    
    # 安装WireGuard和必要的工具
    apt install -y wireguard qrencode resolvconf
    
    log_info "WireGuard安装完成"
}

# 生成随机端口
generate_random_port() {
    echo $(( ( RANDOM % 10000 ) + 20000 ))
}

# 生成密钥对
generate_keys() {
    local interface_name=$1
    local config_dir="/etc/wireguard"
    
    log_info "为接口 ${interface_name} 生成密钥对..."
    
    # 生成服务器密钥对
    wg genkey | tee ${config_dir}/${interface_name}.privatekey | wg pubkey > ${config_dir}/${interface_name}.publickey
    chmod 600 ${config_dir}/${interface_name}.privatekey
    
    log_info "密钥对生成完成"
}

# 获取公网IP
get_public_ip() {
    local public_ip=$(curl -s http://ipv4.icanhazip.com)
    if [[ -z "$public_ip" ]]; then
        log_warn "无法获取公网IP，请手动设置"
        read -p "请输入服务器公网IP地址: " public_ip
    fi
    echo "$public_ip"
}

# 配置WireGuard服务器
configure_wireguard_server() {
    local interface_name=$1
    local port=$2
    local subnet=$3
    local config_file="/etc/wireguard/${interface_name}.conf"
    
    log_info "配置WireGuard服务器..."
    
    # 获取密钥
    local private_key=$(cat /etc/wireguard/${interface_name}.privatekey)
    local public_key=$(cat /etc/wireguard/${interface_name}.publickey)
    
    # 获取公网IP
    local public_ip=$(get_public_ip)
    
    # 创建配置文件
    cat > "$config_file" << EOF
[Interface]
PrivateKey = $private_key
Address = ${subnet}.1/24
ListenPort = $port
SaveConfig = false
PostUp = iptables -A FORWARD -i $interface_name -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i $interface_name -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

EOF

    log_info "服务器配置文件已创建: $config_file"
    echo "$public_key" > "/etc/wireguard/${interface_name}_server_public.key"
}

# 添加客户端配置
add_client() {
    local interface_name=$1
    local subnet=$2
    local client_name=$3
    local client_ip=$4
    local config_file="/etc/wireguard/${interface_name}.conf"
    local client_config_dir="/etc/wireguard/clients"
    
    # 创建客户端配置目录
    mkdir -p "$client_config_dir"
    
    log_info "添加客户端: $client_name (IP: $client_ip)"
    
    # 生成客户端密钥对
    local client_private_key=$(wg genkey)
    local client_public_key=$(echo "$client_private_key" | wg pubkey)
    
    # 获取服务器公钥和配置
    local server_public_key=$(cat /etc/wireguard/${interface_name}.publickey)
    local server_public_ip=$(get_public_ip)
    local server_port=$(grep "ListenPort" "$config_file" | cut -d'=' -f2 | tr -d ' ')
    
    # 在服务器配置中添加客户端
    cat >> "$config_file" << EOF
# Client: $client_name
[Peer]
PublicKey = $client_public_key
AllowedIPs = $client_ip/32

EOF

    # 创建客户端配置文件
    local client_config_file="${client_config_dir}/${client_name}.conf"
    cat > "$client_config_file" << EOF
[Interface]
PrivateKey = $client_private_key
Address = $client_ip/24
DNS = 8.8.8.8, 1.1.1.1

[Peer]
PublicKey = $server_public_key
Endpoint = ${server_public_ip}:${server_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # 生成QR码（如果安装了qrencode）
    if command -v qrencode &> /dev/null; then
        qrencode -t UTF8 < "$client_config_file"
        qrencode -t PNG -o "${client_config_dir}/${client_name}.png" < "$client_config_file"
        log_info "客户端QR码已生成: ${client_config_dir}/${client_name}.png"
    fi
    
    # 创建客户端信息文件
    cat > "${client_config_dir}/${client_name}_info.txt" << EOF
客户端名称: $client_name
客户端IP: $client_ip
服务器公网IP: $server_public_ip
服务器端口: $server_port
服务器公钥: $server_public_key
客户端公钥: $client_public_key
客户端私钥: $client_private_key

配置文件路径: $client_config_file
EOF

    log_info "客户端配置完成: $client_config_file"
    log_info "客户端信息文件: ${client_config_dir}/${client_name}_info.txt"
}

# 显示配置信息
show_config_info() {
    local interface_name=$1
    local config_file="/etc/wireguard/${interface_name}.conf"
    
    log_info "=== WireGuard 配置信息 ==="
    echo "接口名称: $interface_name"
    echo "配置文件: $config_file"
    echo "服务器公钥: $(cat /etc/wireguard/${interface_name}.publickey)"
    echo "服务器私钥: $(cat /etc/wireguard/${interface_name}.privatekey)"
    echo "监听端口: $(grep "ListenPort" "$config_file" | cut -d'=' -f2 | tr -d ' ')"
    echo "内网网段: $(grep "Address" "$config_file" | head -1 | cut -d'=' -f2 | tr -d ' ' | cut -d'.' -f1-3).0/24"
    
    # 显示客户端列表
    log_info "=== 客户端列表 ==="
    local client_config_dir="/etc/wireguard/clients"
    if [[ -d "$client_config_dir" ]]; then
        for client_file in "$client_config_dir"/*.conf; do
            if [[ -f "$client_file" ]]; then
                local client_name=$(basename "$client_file" .conf)
                local client_ip=$(grep "Address" "$client_file" | cut -d'=' -f2 | tr -d ' ' | cut -d'/' -f1)
                echo "客户端: $client_name, IP: $client_ip"
            fi
        done
    fi
}

# 启用系统服务
enable_service() {
    local interface_name=$1
    
    log_info "启用WireGuard系统服务..."
    
    # 启用IP转发
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    sysctl -p
    
    # 启用WireGuard服务
    systemctl enable wg-quick@${interface_name}
    systemctl start wg-quick@${interface_name}
    
    log_info "WireGuard服务已启用并启动"
}

# 主函数
main() {
    clear
    log_info "=== WireGuard 自动安装部署脚本 ==="
    
    # 检查权限和系统
    check_root
    check_os
    
    # 安装WireGuard
    install_wireguard
    
    # 获取配置参数
    log_info "请配置WireGuard参数:"
    
    read -p "请输入WireGuard接口名称 [默认: wg0]: " interface_name
    interface_name=${interface_name:-wg0}
    
    read -p "是否使用随机端口? (y/n) [默认: y]: " use_random_port
    use_random_port=${use_random_port:-y}
    
    if [[ $use_random_port == "y" ]]; then
        port=$(generate_random_port)
        log_info "使用随机端口: $port"
    else
        read -p "请输入监听端口 [默认: 51820]: " port
        port=${port:-51820}
    fi
    
    read -p "请输入WireGuard内网网段 [默认: 10.10.10]: " subnet_prefix
    subnet_prefix=${subnet_prefix:-10.10.10}
    
    # 生成密钥对
    generate_keys "$interface_name"
    
    # 配置服务器
    configure_wireguard_server "$interface_name" "$port" "$subnet_prefix"
    
    # 添加客户端
    while true; do
        read -p "是否添加客户端? (y/n) [默认: y]: " add_more_clients
        add_more_clients=${add_more_clients:-y}
        
        if [[ $add_more_clients != "y" ]]; then
            break
        fi
        
        read -p "请输入客户端名称 [默认: client1]: " client_name
        client_name=${client_name:-client1}
        
        # 自动分配IP地址
        client_count=$(find /etc/wireguard/clients -name "*.conf" 2>/dev/null | wc -l)
        client_ip="${subnet_prefix}.$((client_count + 2))"
        
        add_client "$interface_name" "$subnet_prefix" "$client_name" "$client_ip"
    done
    
    # 启用服务
    enable_service "$interface_name"
    
    # 显示配置信息
    show_config_info "$interface_name"
    
    log_info "=== 安装完成 ==="
    log_info "客户端配置文件位置: /etc/wireguard/clients/"
    log_info "管理命令:"
    log_info "启动: systemctl start wg-quick@${interface_name}"
    log_info "停止: systemctl stop wg-quick@${interface_name}"
    log_info "状态: systemctl status wg-quick@${interface_name}"
    log_info "查看接口: wg show ${interface_name}"
}

# 脚本使用说明
usage() {
    echo "使用方法: $0"
    echo "功能: 自动安装和配置WireGuard VPN"
    echo ""
    echo "该脚本将:"
    echo "1. 自动安装WireGuard"
    echo "2. 允许自定义接口名称"
    echo "3. 支持随机或自定义端口"
    echo "4. 允许自定义内网网段"
    echo "5. 自动配置客户端并顺序分配IP"
    echo "6. 配置开机自启"
    echo "7. 显示完整的配置信息"
}

# 执行主函数
if [[ $1 == "-h" ]] || [[ $1 == "--help" ]]; then
    usage
else
    main
fi