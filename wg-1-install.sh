#!/bin/bash

# WireGuard 自动安装部署脚本
# 功能：自动安装WireGuard，配置防火墙，NAT转发，提供管理菜单

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

# 安装必要软件
install_packages() {
    log_info "安装必要软件包..."
    
    apt update
    apt install -y wireguard qrencode resolvconf iptables-persistent netfilter-persistent
    
    log_info "软件包安装完成"
}

# 备份现有配置
backup_config() {
    local interface_name=$1
    
    log_info "备份现有配置..."
    
    mkdir -p "$BACKUP_DIR"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    # 备份iptables规则
    iptables-save > "$BACKUP_DIR/iptables_backup_$timestamp.rules"
    ip6tables-save > "$BACKUP_DIR/ip6tables_backup_$timestamp.rules"
    
    # 备份WireGuard配置
    if [[ -f "$CONFIG_DIR/${interface_name}.conf" ]]; then
        cp "$CONFIG_DIR/${interface_name}.conf" "$BACKUP_DIR/${interface_name}_backup_$timestamp.conf"
    fi
    
    # 备份客户端配置
    if [[ -d "$CLIENT_DIR" ]]; then
        tar -czf "$BACKUP_DIR/clients_backup_$timestamp.tar.gz" -C "$CONFIG_DIR" clients/
    fi
    
    log_info "配置已备份到: $BACKUP_DIR"
}

# 配置防火墙
configure_firewall() {
    local wg_port=$1
    local interface_name=$2
    
    log_info "配置防火墙..."
    
    # 备份当前规则
    iptables-save > /etc/iptables/rules.v4.backup
    ip6tables-save > /etc/iptables/rules.v6.backup
    
    # 清除现有规则
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # 允许回环接口
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # 允许已建立的连接
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # 允许SSH连接
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    
    # 允许WireGuard端口
    iptables -A INPUT -p udp --dport $wg_port -j ACCEPT
    
    # 允许ICMP (ping)
    iptables -A INPUT -p icmp -j ACCEPT
    
    # 允许WireGuard接口的流量
    iptables -A FORWARD -i $interface_name -j ACCEPT
    iptables -A FORWARD -o $interface_name -j ACCEPT
    
    # 配置NAT转发
    local public_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -n "$public_interface" ]]; then
        iptables -t nat -A POSTROUTING -o $public_interface -j MASQUERADE
        log_info "已为接口 $public_interface 配置NAT转发"
    else
        log_warn "无法检测公网接口，请手动配置NAT"
    fi
    
    # 保存iptables规则
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    ip6tables-save > /etc/iptables/rules.v6
    
    # 启用iptables服务
    systemctl enable netfilter-persistent 2>/dev/null || true
    
    log_info "防火墙配置完成"
}

# 启用IP转发
enable_ip_forwarding() {
    log_info "启用IP转发..."
    
    # 检查是否已启用
    if grep -q "^net.ipv4.ip_forward=1" $SYSCTL_FILE; then
        log_info "IP转发已启用"
    else
        # 移除现有的ip_forward设置（如果有）
        sed -i '/^net.ipv4.ip_forward/d' $SYSCTL_FILE
        # 添加新的设置
        echo 'net.ipv4.ip_forward=1' >> $SYSCTL_FILE
        sysctl -p
        log_info "IP转发已启用并持久化"
    fi
}

# 生成随机端口
generate_random_port() {
    echo $(( ( RANDOM % 10000 ) + 20000 ))
}

# 生成密钥对
generate_keys() {
    local interface_name=$1
    
    log_info "为接口 ${interface_name} 生成密钥对..."
    
    # 生成服务器密钥对
    wg genkey | tee $CONFIG_DIR/${interface_name}.privatekey | wg pubkey > $CONFIG_DIR/${interface_name}.publickey
    chmod 600 $CONFIG_DIR/${interface_name}.privatekey
    
    log_info "密钥对生成完成"
}

# 获取公网IP
get_public_ip() {
    local public_ip=$(curl -s -4 http://ipv4.icanhazip.com || curl -s -4 http://api.ipify.org)
    if [[ -z "$public_ip" ]]; then
        log_warn "无法获取公网IP，请手动设置"
        read -p "请输入服务器公网IP地址: " public_ip
    fi
    echo "$public_ip"
}

# 获取公网接口
get_public_interface() {
    local public_interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -z "$public_interface" ]]; then
        log_warn "无法自动检测公网接口"
        read -p "请输入公网接口名称 (如eth0, ens3等): " public_interface
    fi
    echo "$public_interface"
}

# 配置WireGuard服务器
configure_wireguard_server() {
    local interface_name=$1
    local port=$2
    local subnet=$3
    local config_file="$CONFIG_DIR/${interface_name}.conf"
    
    log_info "配置WireGuard服务器..."
    
    # 获取密钥
    local private_key=$(cat $CONFIG_DIR/${interface_name}.privatekey)
    local public_key=$(cat $CONFIG_DIR/${interface_name}.publickey)
    
    # 获取公网IP和接口
    local public_ip=$(get_public_ip)
    local public_interface=$(get_public_interface)
    
    # 创建配置文件
    cat > "$config_file" << EOF
[Interface]
PrivateKey = $private_key
Address = ${subnet}.1/24
ListenPort = $port
SaveConfig = false

EOF

    log_info "服务器配置文件已创建: $config_file"
    echo "$public_key" > "$CONFIG_DIR/${interface_name}_server_public.key"
}

# 添加客户端配置
add_client() {
    local interface_name=$1
    local subnet=$2
    local client_name=$3
    local client_ip=$4
    local config_file="$CONFIG_DIR/${interface_name}.conf"
    
    # 创建客户端配置目录
    mkdir -p "$CLIENT_DIR"
    
    log_info "添加客户端: $client_name (IP: $client_ip)"
    
    # 生成客户端密钥对
    local client_private_key=$(wg genkey)
    local client_public_key=$(echo "$client_private_key" | wg pubkey)
    
    # 获取服务器公钥和配置
    local server_public_key=$(cat $CONFIG_DIR/${interface_name}.publickey)
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
    local client_config_file="$CLIENT_DIR/${client_name}.conf"
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

    # 生成QR码
    if command -v qrencode &> /dev/null; then
        qrencode -t UTF8 < "$client_config_file"
        qrencode -t PNG -o "$CLIENT_DIR/${client_name}.png" < "$client_config_file"
        log_info "客户端QR码已生成: $CLIENT_DIR/${client_name}.png"
    fi
    
    # 创建客户端信息文件
    cat > "$CLIENT_DIR/${client_name}_info.txt" << EOF
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
    log_info "客户端信息文件: $CLIENT_DIR/${client_name}_info.txt"
}

# 显示配置信息
show_config_info() {
    local interface_name=$1
    local config_file="$CONFIG_DIR/${interface_name}.conf"
    
    if [[ ! -f "$config_file" ]]; then
        log_error "WireGuard配置不存在: $config_file"
        return 1
    fi
    
    log_info "=== WireGuard 配置信息 ==="
    echo "接口名称: $interface_name"
    echo "配置文件: $config_file"
    echo "服务器公钥: $(cat $CONFIG_DIR/${interface_name}.publickey 2>/dev/null || echo '未找到')"
    echo "服务器私钥: $(cat $CONFIG_DIR/${interface_name}.privatekey 2>/dev/null || echo '未找到')"
    echo "监听端口: $(grep "ListenPort" "$config_file" | cut -d'=' -f2 | tr -d ' ')"
    echo "内网网段: $(grep "Address" "$config_file" | head -1 | cut -d'=' -f2 | tr -d ' ' | cut -d'.' -f1-3).0/24"
    
    # 显示客户端列表
    log_info "=== 客户端列表 ==="
    if [[ -d "$CLIENT_DIR" ]]; then
        for client_file in "$CLIENT_DIR"/*.conf; do
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
    
    # 停止可能存在的服务
    systemctl stop "wg-quick@${interface_name}" 2>/dev/null || true
    
    # 重新加载systemd
    systemctl daemon-reload
    
    # 启用并启动服务
    systemctl enable "wg-quick@${interface_name}"
    
    # 等待一下再启动
    sleep 2
    
    if systemctl start "wg-quick@${interface_name}"; then
        log_info "WireGuard服务启动成功"
    else
        log_error "WireGuard服务启动失败"
        log_error "请检查配置文件: $CONFIG_DIR/${interface_name}.conf"
        journalctl -u "wg-quick@${interface_name}" -n 20 --no-pager
        return 1
    fi
}

# 修改WG端口
modify_wg_port() {
    local interface_name=$1
    local config_file="$CONFIG_DIR/${interface_name}.conf"
    
    if [[ ! -f "$config_file" ]]; then
        log_error "WireGuard配置不存在: $config_file"
        return 1
    fi
    
    log_info "当前端口: $(grep "ListenPort" "$config_file" | cut -d'=' -f2 | tr -d ' ')"
    read -p "请输入新的端口号: " new_port
    
    # 验证端口号
    if [[ ! $new_port =~ ^[0-9]+$ ]] || [ $new_port -lt 1024 ] || [ $new_port -gt 65535 ]; then
        log_error "端口号必须在1024-65535之间"
        return 1
    fi
    
    # 停止服务
    systemctl stop "wg-quick@${interface_name}"
    
    # 修改配置文件
    sed -i "s/ListenPort = .*/ListenPort = $new_port/" "$config_file"
    
    # 更新防火墙规则
    configure_firewall "$new_port" "$interface_name"
    
    # 重新启动服务
    systemctl start "wg-quick@${interface_name}"
    
    log_info "端口已修改为: $new_port"
    log_info "请更新所有客户端的Endpoint端口"
}

# 完全卸载WireGuard
uninstall_wireguard() {
    clear
    log_warn "=== WireGuard 完全卸载 ==="
    log_warn "此操作将删除所有WireGuard配置和文件！"
    
    read -p "请输入要卸载的WireGuard接口名称 [默认: wg0]: " interface_name
    interface_name=${interface_name:-wg0}
    
    echo
    log_warn "即将执行以下操作："
    echo "1. 停止WireGuard服务"
    echo "2. 禁用WireGuard服务"
    echo "3. 删除配置文件: $CONFIG_DIR/${interface_name}.*"
    echo "4. 删除客户端配置: $CLIENT_DIR/"
    echo "5. 恢复防火墙规则"
    echo "6. 可选：卸载WireGuard软件包"
    echo
    
    read -p "确定要继续吗？(y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        log_info "取消卸载"
        return
    fi
    
    log_info "开始卸载WireGuard..."
    
    # 停止并禁用服务
    systemctl stop "wg-quick@${interface_name}" 2>/dev/null || true
    systemctl disable "wg-quick@${interface_name}" 2>/dev/null || true
    
    # 删除配置文件
    rm -f $CONFIG_DIR/${interface_name}.conf
    rm -f $CONFIG_DIR/${interface_name}.privatekey
    rm -f $CONFIG_DIR/${interface_name}.publickey
    rm -f $CONFIG_DIR/${interface_name}_server_public.key
    
    # 删除客户端配置
    if [[ -d "$CLIENT_DIR" ]]; then
        rm -rf "$CLIENT_DIR"
    fi
    
    # 恢复防火墙规则
    log_info "恢复防火墙规则..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # 如果有备份规则，恢复备份
    if [[ -f /etc/iptables/rules.v4.backup ]]; then
        iptables-restore < /etc/iptables/rules.v4.backup
        iptables-save > /etc/iptables/rules.v4
        log_info "已恢复iptables规则备份"
    fi
    
    if [[ -f /etc/iptables/rules.v6.backup ]]; then
        ip6tables-restore < /etc/iptables/rules.v6.backup
        ip6tables-save > /etc/iptables/rules.v6
        log_info "已恢复ip6tables规则备份"
    fi
    
    read -p "是否要卸载WireGuard软件包？(y/N): " uninstall_pkg
    if [[ $uninstall_pkg =~ ^[Yy]$ ]]; then
        apt remove -y wireguard qrencode
        apt autoremove -y
        log_info "WireGuard软件包已卸载"
    else
        log_info "保留WireGuard软件包"
    fi
    
    log_info "WireGuard卸载完成！"
    log_info "备份文件保存在: $BACKUP_DIR"
}

# 显示菜单
show_menu() {
    clear
    echo -e "${GREEN}=== WireGuard 管理脚本 ===${NC}"
    echo "1. 自动化部署安装"
    echo "2. 修改WG端口"
    echo "3. 添加客户端"
    echo "4. 配置路由转发和NAT转发"
    echo "5. 显示配置信息"
    echo "6. 重启WireGuard服务"
    echo "7. 完全卸载WireGuard"
    echo "8. 退出"
    echo
}

# 自动化部署安装
auto_deploy() {
    clear
    log_info "=== WireGuard 自动化部署 ==="
    
    # 检查权限和系统
    check_root
    check_os
    
    # 安装必要软件
    install_packages
    
    # 获取配置参数
    log_info "请配置WireGuard参数:"
    
    read -p "请输入WireGuard接口名称 [默认: wg0]: " interface_name
    interface_name=${interface_name:-wg0}
    
    # 备份现有配置
    backup_config "$interface_name"
    
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
    
    # 配置防火墙
    configure_firewall "$port" "$interface_name"
    
    # 启用IP转发
    enable_ip_forwarding
    
    # 添加默认客户端
    read -p "是否添加默认客户端? (y/n) [默认: y]: " add_default_client
    add_default_client=${add_default_client:-y}
    
    if [[ $add_default_client == "y" ]]; then
        add_client "$interface_name" "$subnet_prefix" "client1" "${subnet_prefix}.2"
    fi
    
    # 启用服务
    enable_service "$interface_name"
    
    # 显示配置信息
    show_config_info "$interface_name"
    
    log_info "=== 部署完成 ==="
    log_info "客户端配置文件位置: $CLIENT_DIR/"
    log_info "管理命令:"
    log_info "启动: systemctl start wg-quick@${interface_name}"
    log_info "停止: systemctl stop wg-quick@${interface_name}"
    log_info "状态: systemctl status wg-quick@${interface_name}"
    log_info "查看接口: wg show ${interface_name}"
    
    read -p "按回车键返回主菜单..."
}

# 添加客户端功能
add_client_menu() {
    clear
    log_info "=== 添加客户端 ==="
    
    read -p "请输入WireGuard接口名称 [默认: wg0]: " interface_name
    interface_name=${interface_name:-wg0}
    
    local config_file="$CONFIG_DIR/${interface_name}.conf"
    if [[ ! -f "$config_file" ]]; then
        log_error "WireGuard配置不存在: $config_file"
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    read -p "请输入客户端名称: " client_name
    if [[ -z "$client_name" ]]; then
        log_error "客户端名称不能为空"
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    # 获取子网
    local subnet=$(grep "Address" "$config_file" | head -1 | cut -d'=' -f2 | tr -d ' ' | cut -d'.' -f1-3)
    
    # 自动分配IP地址
    local client_count=0
    if [[ -d "$CLIENT_DIR" ]]; then
        client_count=$(find "$CLIENT_DIR" -name "*.conf" | wc -l)
    fi
    local client_ip="${subnet}.$((client_count + 2))"
    
    read -p "请输入客户端IP [默认: $client_ip]: " custom_ip
    client_ip=${custom_ip:-$client_ip}
    
    add_client "$interface_name" "$subnet" "$client_name" "$client_ip"
    
    # 重新加载WG配置
    if systemctl is-active --quiet "wg-quick@${interface_name}"; then
        wg syncconf "$interface_name" <(wg-quick strip "$interface_name")
        log_info "WireGuard配置已重新加载"
    fi
    
    read -p "按回车键返回主菜单..."
}

# 配置路由转发和NAT转发
configure_nat_menu() {
    clear
    log_info "=== 配置路由转发和NAT转发 ==="
    
    read -p "请输入WireGuard接口名称 [默认: wg0]: " interface_name
    interface_name=${interface_name:-wg0}
    
    local config_file="$CONFIG_DIR/${interface_name}.conf"
    if [[ ! -f "$config_file" ]]; then
        log_error "WireGuard配置不存在: $config_file"
        read -p "按回车键返回主菜单..."
        return 1
    fi
    
    local port=$(grep "ListenPort" "$config_file" | cut -d'=' -f2 | tr -d ' ')
    
    # 启用IP转发
    enable_ip_forwarding
    
    # 配置防火墙和NAT
    configure_firewall "$port" "$interface_name"
    
    log_info "路由转发和NAT转发配置完成"
    read -p "按回车键返回主菜单..."
}

# 重启WireGuard服务
restart_wireguard() {
    clear
    log_info "=== 重启WireGuard服务 ==="
    
    read -p "请输入WireGuard接口名称 [默认: wg0]: " interface_name
    interface_name=${interface_name:-wg0}
    
    systemctl restart "wg-quick@${interface_name}"
    systemctl status "wg-quick@${interface_name}" --no-pager
    
    read -p "按回车键返回主菜单..."
}

# 主循环
main() {
    while true; do
        show_menu
        read -p "请选择操作 [1-8]: " choice
        
        case $choice in
            1)
                auto_deploy
                ;;
            2)
                read -p "请输入WireGuard接口名称 [默认: wg0]: " interface_name
                interface_name=${interface_name:-wg0}
                modify_wg_port "$interface_name"
                read -p "按回车键返回主菜单..."
                ;;
            3)
                add_client_menu
                ;;
            4)
                configure_nat_menu
                ;;
            5)
                clear
                read -p "请输入WireGuard接口名称 [默认: wg0]: " interface_name
                interface_name=${interface_name:-wg0}
                show_config_info "$interface_name"
                read -p "按回车键返回主菜单..."
                ;;
            6)
                restart_wireguard
                ;;
            7)
                uninstall_wireguard
                read -p "按回车键返回主菜单..."
                ;;
            8)
                log_info "再见!"
                exit 0
                ;;
            *)
                log_error "无效选择，请重新输入"
                sleep 2
                ;;
        esac
    done
}

# 脚本使用说明
usage() {
    echo "使用方法: $0"
    echo "功能: WireGuard VPN 管理脚本"
    echo ""
    echo "该脚本提供以下功能:"
    echo "1. 自动化部署安装"
    echo "2. 修改WG端口"
    echo "3. 添加客户端"
    echo "4. 配置路由转发和NAT转发"
    echo "5. 显示配置信息"
    echo "6. 重启WireGuard服务"
    echo "7. 完全卸载WireGuard"
}

# 执行主函数
if [[ $1 == "-h" ]] || [[ $1 == "--help" ]]; then
    usage
else
    check_root
    check_os
    main
fi