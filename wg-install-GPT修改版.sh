#!/bin/bash
# WireGuard 一键管理脚本 v2.0
# 适用于 Debian 10/11/12+
# 作者: ChatGPT (GPT-5)
# 日期: 2025-10

WG_DIR="/etc/wireguard"
SYSCTL_FILE="/etc/sysctl.conf"

# 检查 root 权限
[[ $EUID -ne 0 ]] && echo "❌ 请以 root 身份运行。" && exit 1

# 获取默认网卡
get_default_iface() {
    ip route | grep default | awk '{print $5}' | head -n 1
}

# 随机端口生成
random_port() {
    echo $((10000 + RANDOM % 50000))
}

# 启用 NAT 与 IP 转发
enable_nat() {
    local iface=$(get_default_iface)
    sed -i '/net.ipv4.ip_forward/d' $SYSCTL_FILE
    echo "net.ipv4.ip_forward=1" >> $SYSCTL_FILE
    sysctl -p >/dev/null
    iptables -t nat -A POSTROUTING -o $iface -j MASQUERADE
    iptables-save > /etc/iptables.rules
    echo "✅ NAT 与路由转发已启用（出口网卡: $iface）"
}

# 启用 BBR 加速
enable_bbr() {
    modprobe tcp_bbr
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
    sed -i '/net.core.default_qdisc/d' $SYSCTL_FILE
    sed -i '/net.ipv4.tcp_congestion_control/d' $SYSCTL_FILE
    echo "net.core.default_qdisc=fq" >> $SYSCTL_FILE
    echo "net.ipv4.tcp_congestion_control=bbr" >> $SYSCTL_FILE
    sysctl -p >/dev/null
    echo "✅ BBR 加速已启用"
}

# 安装 WireGuard
install_wireguard() {
    apt update && apt install -y wireguard qrencode iptables >/dev/null
    mkdir -p $WG_DIR
}

# 创建服务端配置
create_server_config() {
    WG_IFACE=$1
    WG_NET=$2
    SERVER_IP=$3
    WG_PORT=$4

    cd $WG_DIR
    umask 077
    wg genkey | tee server_private.key | wg pubkey > server_public.key
    SERVER_PRIV=$(cat server_private.key)
    SERVER_PUB=$(cat server_public.key)

    cat > $WG_DIR/${WG_IFACE}.conf <<EOF
[Interface]
Address = ${SERVER_IP}/24
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIV}
MTU = 1420
DNS = 1.1.1.1
EOF

    systemctl enable wg-quick@${WG_IFACE} >/dev/null
    systemctl start wg-quick@${WG_IFACE}
}

# 显示服务端信息
show_server_info() {
    WG_IFACE=$1
    CONF="$WG_DIR/${WG_IFACE}.conf"
    echo "=== 服务端信息 (${WG_IFACE}) ==="
    wg show $WG_IFACE
    echo ""
    echo "--- 配置文件内容 ---"
    cat $CONF
    echo "=============================="
}

# 添加客户端
add_client() {
    CLIENT_NAME=$1
    WG_IFACE=$2
    SERVER_CONF="$WG_DIR/${WG_IFACE}.conf"

    BASE_IP=$(grep Address $SERVER_CONF | awk '{print $3}' | cut -d'.' -f1-3)
    CLIENT_IP="${BASE_IP}.$((2 + $(grep -c '\[Peer\]' $SERVER_CONF)))"

    cd $WG_DIR
    wg genkey | tee ${CLIENT_NAME}_private.key | wg pubkey > ${CLIENT_NAME}_public.key
    CLIENT_PRIV=$(cat ${CLIENT_NAME}_private.key)
    CLIENT_PUB=$(cat ${CLIENT_NAME}_public.key)
    SERVER_PUB=$(cat server_public.key)
    SERVER_IP=$(grep Address $SERVER_CONF | awk '{print $3}' | cut -d'/' -f1)
    SERVER_PORT=$(grep ListenPort $SERVER_CONF | awk '{print $3}')
    SERVER_ADDR=$(hostname -I | awk '{print $1}')

    cat >> $SERVER_CONF <<EOF

[Peer]
# ${CLIENT_NAME}
PublicKey = ${CLIENT_PUB}
AllowedIPs = ${CLIENT_IP}/32
PersistentKeepalive = 21
EOF

    cat > $WG_DIR/${CLIENT_NAME}.conf <<EOF
[Interface]
PrivateKey = ${CLIENT_PRIV}
Address = ${CLIENT_IP}/24
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = ${SERVER_PUB}
Endpoint = ${SERVER_ADDR}:${SERVER_PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 21
EOF

    wg-quick down $WG_IFACE >/dev/null 2>&1
    wg-quick up $WG_IFACE >/dev/null 2>&1
    echo "✅ 客户端 ${CLIENT_NAME} 添加成功。"
}

# 管理客户端菜单
manage_clients() {
    WG_IFACE=$(choose_interface)
    while true; do
        clear
        echo "=== 管理客户端 (${WG_IFACE}) ==="
        echo "1. 添加客户端"
        echo "2. 删除客户端"
        echo "3. 查看客户端配置"
        echo "4. 返回主菜单"
        read -p "请选择操作 [1-4]: " c
        case $c in
            1)
                read -p "输入客户端名称: " CLIENT_NAME
                add_client "$CLIENT_NAME" "$WG_IFACE"
                ;;
            2)
                list_clients
                read -p "输入要删除的客户端名称: " CLIENT_NAME
                delete_client "$CLIENT_NAME" "$WG_IFACE"
                ;;
            3)
                list_clients
                read -p "输入要查看的客户端名称: " CLIENT_NAME
                view_client "$CLIENT_NAME"
                ;;
            4) break ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}

# 列出客户端
list_clients() {
    echo "=== 当前客户端 ==="
    ls $WG_DIR | grep '\.conf' | grep -v 'wg' | sed 's/\.conf//'
}

# 删除客户端
delete_client() {
    CLIENT_NAME=$1
    WG_IFACE=$2
    SERVER_CONF="$WG_DIR/${WG_IFACE}.conf"

    CLIENT_PUB=$(cat $WG_DIR/${CLIENT_NAME}_public.key 2>/dev/null)
    if [ -z "$CLIENT_PUB" ]; then
        echo "未找到客户端公钥，跳过删除。"
        return
    fi

    sed -i "/# ${CLIENT_NAME}/,+3d" "$SERVER_CONF"
    rm -f "$WG_DIR/${CLIENT_NAME}.conf" "$WG_DIR/${CLIENT_NAME}_private.key" "$WG_DIR/${CLIENT_NAME}_public.key"
    wg-quick down $WG_IFACE && wg-quick up $WG_IFACE
    echo "✅ 客户端 ${CLIENT_NAME} 已删除。"
}

# 查看客户端配置 + QR 码
view_client() {
    CLIENT_NAME=$1
    if [ ! -f "$WG_DIR/${CLIENT_NAME}.conf" ]; then
        echo "未找到客户端配置。"
        return
    fi
    echo "=== ${CLIENT_NAME} 配置内容 ==="
    cat "$WG_DIR/${CLIENT_NAME}.conf"
    echo ""
    qrencode -t ansiutf8 < "$WG_DIR/${CLIENT_NAME}.conf"
}

# 选择现有接口
choose_interface() {
    INTERFACES=($(ls /etc/wireguard | grep '\.conf' | sed 's/.conf//'))
    if [ ${#INTERFACES[@]} -eq 0 ]; then
        echo "未找到任何接口，请先执行自动化部署。"
        exit 1
    fi
    echo "当前可用接口："
    i=1
    for iface in "${INTERFACES[@]}"; do
        echo "$i) $iface"
        ((i++))
    done
    read -p "请选择接口编号: " CHOICE
    echo "${INTERFACES[$((CHOICE-1))]}"
}

# 修改端口
change_port() {
    WG_IFACE=$(choose_interface)
    read -p "请输入新的端口号: " NEW_PORT
    sed -i "s/^ListenPort.*/ListenPort = ${NEW_PORT}/" $WG_DIR/${WG_IFACE}.conf
    wg-quick down $WG_IFACE && wg-quick up $WG_IFACE
    echo "✅ 端口修改完成，新端口为 ${NEW_PORT}"
}

# 卸载 WireGuard
uninstall_menu() {
    echo "=== 卸载 WireGuard ==="
    INTERFACES=($(ls /etc/wireguard | grep '\.conf' | sed 's/.conf//'))
    if [ ${#INTERFACES[@]} -eq 0 ]; then
        echo "未检测到接口。"
    else
        echo "当前已存在接口："
        i=1
        for iface in "${INTERFACES[@]}"; do
            echo "$i) $iface"
            ((i++))
        done
        read -p "请选择要删除的接口编号（或输入 all 删除全部）: " CHOICE
        if [[ "$CHOICE" == "all" ]]; then
            for iface in "${INTERFACES[@]}"; do
                systemctl stop wg-quick@$iface
                rm -f $WG_DIR/${iface}.conf
            done
        else
            IDX=$((CHOICE-1))
            systemctl stop wg-quick@${INTERFACES[$IDX]}
            rm -f $WG_DIR/${INTERFACES[$IDX]}.conf
        fi
    fi
    read -p "是否彻底卸载 WireGuard 包？(y/N): " CONFIRM
    if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
        apt purge -y wireguard wireguard-tools qrencode
        apt autoremove -y
        echo "✅ WireGuard 已彻底卸载。"
    else
        echo "接口已清理，保留软件包。"
    fi
}

# 自动化部署安装
auto_deploy() {
    echo "=== 自动化部署 WireGuard ==="
    read -p "请输入 WG 接口名称 (默认 wg0): " WG_IFACE
    WG_IFACE=${WG_IFACE:-wg0}
    read -p "请输入网段 C 段 (例如 10.0.0): " C_SEGMENT
    [[ -z "$C_SEGMENT" ]] && C_SEGMENT="10.66.66"
    WG_NET="${C_SEGMENT}.0/24"
    SERVER_IP="${C_SEGMENT}.1"
    read -p "请输入监听端口 (留空随机): " WG_PORT
    WG_PORT=${WG_PORT:-$(random_port)}

    install_wireguard
    create_server_config "$WG_IFACE" "$WG_NET" "$SERVER_IP" "$WG_PORT"
    enable_nat
    enable_bbr

    read -p "是否添加默认客户端？(y/N): " ADD_CLIENT
    if [[ "$ADD_CLIENT" =~ ^[Yy]$ ]]; then
        read -p "请输入客户端名称 (默认 client1): " CLIENT_NAME
        CLIENT_NAME=${CLIENT_NAME:-client1}
        add_client "$CLIENT_NAME" "$WG_IFACE"
    fi
    show_server_info "$WG_IFACE"
}

# 主菜单
main_menu() {
    clear
    echo "========= WireGuard 管理菜单 ========="
    echo "1. 自动化部署安装"
    echo "2. 修改 WG 端口"
    echo "3. 管理客户端（添加/删除/查看）"
    echo "4. 查看服务端配置"
    echo "5. 路由转发 & NAT 设置"
    echo "6. 卸载 WireGuard"
    echo "====================================="
    read -p "请选择操作 [1-6]: " CHOICE
    case $CHOICE in
        1) auto_deploy ;;
        2) change_port ;;
        3) manage_clients ;;
        4) WG_IFACE=$(choose_interface); show_server_info "$WG_IFACE" ;;
        5) enable_nat ;;
        6) uninstall_menu ;;
        *) echo "无效选项" ;;
    esac
}

main_menu
