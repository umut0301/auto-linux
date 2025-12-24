#!/usr/bin/env bash
#
# auto-linux.sh (v18.0 里程碑版)
# 新增：
# 1. 删除接口时，自动级联删除关联的所有客户端文件 (彻底清理)
# 2. 删除客户端升级为二级菜单 (支持 单个/批量范围/清空接口用户)
#
set -u
IFS=$'\n\t'

# ===========================
# 0. 环境深度预设
# ===========================
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WG_DIR="/etc/wireguard"
WG_CLIENT_DIR="$WG_DIR/clients"
DEFAULT_MTU="1420"
KEEPALIVE="21"

# 颜色
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# ===========================
# 1. 基础工具函数
# ===========================
log() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

require_root() { [[ $EUID -eq 0 ]] || { err "必须使用 root 权限"; exit 1; }; }

press_any_key() {
    echo
    echo -e "${YELLOW}--> 按 Enter 键继续...${NC}"
    read -r _dummy
}

trim() {
    local var="$*"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    echo -n "$var"
}

rand_suffix() { tr -dc 'a-z0-9' </dev/urandom | head -c 6; }
rand_iface() { echo "wg$(tr -dc '0-9' </dev/urandom | head -c 3)"; }
rand_port() { echo "$(( (RANDOM % 10000) + 20000 ))"; }

# 获取下一个顺序客户端名称
get_next_client_name() {
    local i=1
    local name
    while true; do
        printf -v name "client-%03d" "$i"
        if [[ ! -d "$WG_CLIENT_DIR/$name" ]]; then
            echo "$name"
            return
        fi
        ((i++))
    done
}

find_wg_bin() {
    if command -v wg >/dev/null 2>&1; then command -v wg; return; fi
    local paths=("/usr/bin/wg" "/usr/sbin/wg" "/usr/local/bin/wg" "/usr/local/sbin/wg")
    for p in "${paths[@]}"; do
        if [[ -x "$p" ]]; then echo "$p"; return; fi
    done
    find /usr -name "wg" -type f -executable 2>/dev/null | head -n 1
}

get_public_ip() {
    local ip=""
    local sources=("https://api.ipify.org" "https://ip.sb" "https://ifconfig.me" "https://icanhazip.com")
    for url in "${sources[@]}"; do
        ip=$(curl -s4m 3 "$url" | tr -d '\n' | tr -d '\r')
        if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then echo "$ip"; return; fi
    done
    ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7}')
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then echo "$ip"; return; fi
    echo "127.0.0.1"
}

read_input() {
    local prompt="$1"
    local default="$2"
    local var_ref="$3"
    local input
    
    if [[ -n "$default" ]]; then
        read -rp "${prompt} [默认: ${default}]: " input
    else
        read -rp "${prompt}: " input
    fi
    
    [[ -z "$input" ]] && input="$default"
    input=$(trim "$input")
    
    if [[ "$var_ref" == *"ip"* ]] && [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${BLUE}[提示] 自动补全 IP: ${input}.1${NC}"
        input="${input}.1"
    fi
    eval "$var_ref='$input'"
}

# ===========================
# 2. 智能选择系统
# ===========================
select_smart() {
    local title="$1"
    local list_str="$2"
    local ret_var="$3"
    local -a items
    local old_ifs="$IFS"
    IFS=' ' read -r -a items <<< "$list_str"
    IFS="$old_ifs"
    
    if [[ ${#items[@]} -eq 0 ]]; then
        echo " (无数据)"
        eval "$ret_var=''"
        return
    fi
    
    echo -e "${BLUE}--- $title ---${NC}"
    local i=0
    for item in "${items[@]}"; do
        i=$((i+1))
        echo "$i) $item"
    done
    echo "------------------"
    
    local choice
    read -rp "请输入编号或名称: " choice
    choice=$(trim "$choice")
    
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
        if (( choice >= 1 && choice <= ${#items[@]} )); then
            local index=$((choice-1))
            eval "$ret_var='${items[$index]}'"
            return
        fi
    fi
    
    for item in "${items[@]}"; do
        if [[ "$item" == "$choice" ]]; then
            eval "$ret_var='$item'"
            return
        fi
    done
    
    warn "无效的选择"
    eval "$ret_var=''"
}

get_ifaces() {
    ls "$WG_DIR"/*.conf 2>/dev/null | xargs -n 1 basename -s .conf | xargs
}

get_clients() {
    if [[ -d "$WG_CLIENT_DIR" ]]; then
        find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | xargs
    fi
}

# ===========================
# 3. 系统适配与安装
# ===========================
detect_pm() {
    if command -v apt-get >/dev/null 2>&1; then PM="apt";
    elif command -v dnf >/dev/null 2>&1; then PM="dnf";
    elif command -v yum >/dev/null 2>&1; then PM="yum";
    elif command -v pacman >/dev/null 2>&1; then PM="pacman";
    else PM="unknown"; fi
}

pkg_mgr() {
    local action="$1"; shift
    detect_pm
    echo -e "${BLUE}[系统] 执行: $PM $action $*${NC}"
    case "$PM" in
        apt) [[ "$action" == "install" ]] && apt-get install -y "$@" || apt-get remove -y "$@" ;;
        dnf) [[ "$action" == "install" ]] && dnf install -y "$@" || dnf remove -y "$@" ;;
        yum) [[ "$action" == "install" ]] && yum install -y "$@" || yum remove -y "$@" ;;
        pacman) [[ "$action" == "install" ]] && pacman -S --noconfirm "$@" || pacman -R --noconfirm "$@" ;;
    esac
}

check_and_install_dns() {
    detect_pm
    if [[ "$PM" == "apt" ]]; then
        if dpkg -l | grep -q "^ii  resolvconf"; then
            log "检测到 resolvconf 已存在，兼容模式。"
            pkg_mgr install wireguard iptables-persistent qrencode
        else
            log "检测到纯净环境，安装 openresolv..."
            pkg_mgr install wireguard iptables-persistent openresolv qrencode
        fi
    elif [[ "$PM" == "yum" || "$PM" == "dnf" ]]; then
        rpm -qa | grep -qi epel || pkg_mgr install epel-release
        pkg_mgr install wireguard-tools iptables-services qrencode
    else
        pkg_mgr install wireguard-tools qrencode openresolv
    fi
}

install_wg() {
    echo -e "${YELLOW}=== 开始智能安装 ===${NC}"
    detect_pm
    if [[ "$PM" == "apt" ]]; then apt-get update; fi
    check_and_install_dns
    
    local wg_bin=$(find_wg_bin)
    if [[ -z "$wg_bin" ]]; then
        err "安装失败！未找到 wg 命令。"
        press_any_key
        return 1
    else
        log "安装成功: $wg_bin"
    fi
    mkdir -p "$WG_DIR" "$WG_CLIENT_DIR"
    chmod 700 "$WG_DIR"
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
    fi
}

# ===========================
# 4. 防火墙
# ===========================
open_port() {
    local port="$1"; local proto="${2:-udp}"
    port=$(trim "$port")
    echo -e "${BLUE}[防火墙]${NC} 正在配置 $port ($proto)..."
    local configured=false
    
    if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1
        firewall-cmd --permanent --add-masquerade >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
        log "Firewalld: 已放行"
        configured=true
    fi
    if command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1
        log "UFW: 已放行"
        configured=true
    fi
    if command -v iptables >/dev/null; then
        if ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT
            command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1
            command -v service >/dev/null && service iptables save >/dev/null 2>&1
        fi
        if [[ "$configured" == "false" ]]; then log "Iptables: 已放行"; fi
    fi
}

# ===========================
# 5. 核心业务逻辑
# ===========================

# 创建服务端
create_server_logic() {
    install_wg || return 
    
    echo -e "${BLUE}=== 配置 WireGuard 服务端 ===${NC}"
    local iface; local def_iface="wg0"
    read_input "接口名称" "$def_iface" iface
    if [[ ! "$iface" =~ ^[A-Za-z0-9_-]+$ ]]; then err "非法名称"; return; fi
    if [[ ${#iface} -gt 15 ]]; then err "接口名过长"; return; fi
    
    local ip_cidr; local def_ip="10.0.0.1"
    read_input "服务端内网IP (如 10.10.10)" "$def_ip" ip_cidr
    
    local port; local def_port=$(rand_port)
    read_input "监听端口" "$def_port" port
    
    umask 077
    wg genkey | tee "$WG_DIR/${iface}_private.key" | wg pubkey > "$WG_DIR/${iface}_public.key"
    local priv=$(cat "$WG_DIR/${iface}_private.key")
    local eth=$(ip route | awk '/default/ {print $5; exit}')
    
    cat > "$WG_DIR/${iface}.conf" <<EOF
[Interface]
Address = ${ip_cidr}/24
ListenPort = ${port}
PrivateKey = ${priv}
MTU = ${DEFAULT_MTU}
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${eth} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${eth} -j MASQUERADE
EOF
    chmod 600 "$WG_DIR/${iface}.conf"
    open_port "$port" "udp"
    
    systemctl daemon-reload
    systemctl enable "wg-quick@$iface" --now >/dev/null 2>&1
    log "服务端配置完成！"
    
    local yn
    read -rp "是否立即添加一个客户端? (y/n) [y]: " yn
    [[ "${yn:-y}" == "y" ]] && add_client_menu
}

# 核心生成逻辑 (共享)
core_generate_client() {
    local iface="$1"
    local name="$2"
    local manual_ip="${3:-}"
    
    local conf="$WG_DIR/${iface}.conf"
    if [[ ! -f "$conf" ]]; then err "接口配置丢失"; return 1; fi
    
    local new_ip="$manual_ip"
    if [[ -z "$new_ip" ]]; then
        local base_ip=$(grep "^Address" "$conf" | cut -d= -f2 | cut -d/ -f1 | tr -d ' ')
        local prefix="${base_ip%.*}"
        for i in {2..254}; do
            if ! grep -q "${prefix}.${i}" "$conf" "$WG_CLIENT_DIR"/*/*.conf 2>/dev/null; then
                new_ip="${prefix}.${i}"
                break
            fi
        done
        if [[ -z "$new_ip" ]]; then err "IP池已满"; return 1; fi
    fi
    
    mkdir -p "$WG_CLIENT_DIR/$name"
    local c_priv=$(wg genkey); local c_pub=$(echo "$c_priv" | wg pubkey); local c_psk=$(wg genpsk)
    
    local s_pub=""; 
    [[ -f "$WG_DIR/${iface}_public.key" ]] && s_pub=$(cat "$WG_DIR/${iface}_public.key") || s_pub=$(grep "PrivateKey" "$conf" | cut -d= -f2 | tr -d ' ' | wg pubkey)
    local s_port=$(grep "ListenPort" "$conf" | cut -d= -f2 | tr -d ' ')
    local s_ip=$(get_public_ip)
    
    local client_conf="$WG_CLIENT_DIR/$name/$name.conf"
    cat > "$client_conf" <<EOF
[Interface]
PrivateKey = ${c_priv}
Address = ${new_ip}/32
DNS = 8.8.8.8, 1.1.1.1
MTU = ${DEFAULT_MTU}
[Peer]
PublicKey = ${s_pub}
PresharedKey = ${c_psk}
Endpoint = ${s_ip}:${s_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = ${KEEPALIVE}
EOF
    
    wg set "$iface" peer "$c_pub" preshared-key <(echo "$c_psk") allowed-ips "${new_ip}/32"
    if ! grep -q "$c_pub" "$conf"; then
        cat >> "$conf" <<EOF

# Client: ${name}
[Peer]
PublicKey = ${c_pub}
PresharedKey = ${c_psk}
AllowedIPs = ${new_ip}/32
EOF
    fi
    echo "$new_ip"
}

# 单个添加
add_single_client() {
    local iface="$1"
    local name
    local def_name=$(get_next_client_name)
    read_input "客户端名称" "$def_name" name
    
    if [[ ! "$name" =~ ^[A-Za-z0-9_-]+$ ]]; then err "非法名称"; press_any_key; return; fi
    if [[ -d "$WG_CLIENT_DIR/$name" ]]; then warn "用户已存在!"; press_any_key; return; fi
    
    local set_ip=""
    read -rp "指定内网IP (留空自动分配): " set_ip
    set_ip=$(trim "$set_ip")
    if [[ -n "$set_ip" ]]; then
        if [[ ! "$set_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then warn "IP格式错误，将自动分配"; set_ip=""; fi
    fi

    log "正在生成..."
    local res_ip
    res_ip=$(core_generate_client "$iface" "$name" "$set_ip")
    
    if [[ -n "$res_ip" ]]; then
        clear
        echo -e "${GREEN}=== 添加成功 ===${NC}"
        echo "用户: $name"; echo "IP: $res_ip"; echo "保活: ${KEEPALIVE}s"
        local conf="$WG_CLIENT_DIR/$name/$name.conf"
        if command -v qrencode >/dev/null; then echo -e "${BLUE}[二维码]${NC}"; qrencode -t ansiutf8 < "$conf"; fi
        # 保存一次状态
        wg-quick save "$iface" >/dev/null 2>&1
    fi
    press_any_key
}

# 批量添加
add_batch_client() {
    local iface="$1"
    local count
    read -rp "请输入要批量生成的数量 (例如 10): " count
    
    if [[ ! "$count" =~ ^[0-9]+$ ]] || [[ "$count" -le 0 ]]; then
        err "数量无效"
        press_any_key
        return
    fi
    
    log "准备生成 $count 个客户端..."
    local success_count=0
    for ((i=1; i<=count; i++)); do
        local name=$(get_next_client_name)
        log "[$i/$count] 正在生成 $name ..."
        local res_ip=$(core_generate_client "$iface" "$name" "")
        if [[ -n "$res_ip" ]]; then ((success_count++)); else err "生成 $name 失败"; break; fi
    done
    wg-quick save "$iface" >/dev/null 2>&1
    echo -e "${GREEN}=== 批量完成 ===${NC}"
    echo "成功生成: $success_count 个"
    press_any_key
}

add_client_menu() {
    local iface
    local iface_list=$(get_ifaces)
    if [[ -z "$iface_list" ]]; then err "请先安装服务端 (菜单 1)"; press_any_key; return; fi
    select_smart "选择接口" "$iface_list" iface
    if [[ -z "$iface" ]]; then return; fi
    iface=$(trim "$iface")
    
    clear
    echo -e "${BLUE}=== 添加客户端 ($iface) ===${NC}"
    echo "1) 单个添加 (可指定名称/IP)"
    echo "2) 批量添加 (全自动顺序命名)"
    echo "0) 返回"
    local method
    read -rp "请选择: " method
    case "$method" in
        1) add_single_client "$iface" ;;
        2) add_batch_client "$iface" ;;
        *) ;;
    esac
}

view_client_logic() {
    local client_list=$(get_clients)
    local name
    select_smart "选择客户端" "$client_list" name
    [[ -z "$name" ]] && return
    name=$(trim "$name")
    local conf="$WG_CLIENT_DIR/$name/$name.conf"
    [[ ! -f "$conf" ]] && { err "文件不存在"; return; }
    clear
    echo -e "${GREEN}配置 ($name):${NC}"; cat "$conf"; echo
    if command -v qrencode >/dev/null; then echo -e "${GREEN}二维码:${NC}"; qrencode -t ansiutf8 < "$conf"; fi
}

# --- 删除逻辑 ---

# 核心删除执行函数
core_delete_client() {
    local name="$1"
    local conf="$WG_CLIENT_DIR/$name/$name.conf"
    local pub=""
    
    if [[ -f "$conf" ]]; then
        # 强力清洗密钥
        local priv=$(grep -v '^#' "$conf" | grep "PrivateKey" | cut -d= -f2 | tr -d ' \n\r\t')
        if [[ -n "$priv" ]]; then pub=$(echo "$priv" | wg pubkey); fi
    fi
    
    # 移除 Peer
    if [[ -n "$pub" && ${#pub} -eq 44 ]]; then
        local ifaces=$(get_ifaces)
        for iface in $ifaces; do
            wg set "$iface" peer "$pub" remove >/dev/null 2>&1 || true
            wg-quick save "$iface" >/dev/null 2>&1
        done
    fi
    
    rm -rf "$WG_CLIENT_DIR/$name"
    log "已删除: $name"
}

del_single_client() {
    local client_list=$(get_clients)
    local name
    select_smart "删除客户端" "$client_list" name
    [[ -z "$name" ]] && return
    name=$(trim "$name")
    read -rp "确认删除 $name ? (y/n): " yn
    [[ "$yn" != "y" ]] && return
    core_delete_client "$name"
    press_any_key
}

del_batch_client() {
    echo -e "${BLUE}--- 批量删除 ---${NC}"
    echo "说明: 输入起始编号和数量，删除 client-xxx 系列用户"
    local start_num count
    read -rp "起始编号 (如 3): " start_num
    read -rp "删除数量 (如 5): " count
    
    if [[ ! "$start_num" =~ ^[0-9]+$ ]] || [[ ! "$count" =~ ^[0-9]+$ ]]; then err "输入无效"; press_any_key; return; fi
    
    read -rp "即将删除 client-$(printf "%03d" "$start_num") 开始的 $count 个用户，确认? (y/n): " yn
    [[ "$yn" != "y" ]] && return
    
    for ((i=0; i<count; i++)); do
        local num=$((start_num + i))
        local target
        printf -v target "client-%03d" "$num"
        if [[ -d "$WG_CLIENT_DIR/$target" ]]; then
            core_delete_client "$target"
        else
            warn "找不到 $target，跳过"
        fi
    done
    press_any_key
}

del_all_clients_on_iface() {
    local iface_list=$(get_ifaces)
    local iface
    select_smart "清空接口下所有用户" "$iface_list" iface
    [[ -z "$iface" ]] && return
    iface=$(trim "$iface")
    
    warn "警告！这将删除所有连接到 $iface 的用户！"
    read -rp "请输入 'CONFIRM' 以确认清空: " input
    if [[ "$input" != "CONFIRM" ]]; then return; fi
    
    # 获取服务端公钥
    local s_pub=""
    [[ -f "$WG_DIR/${iface}_public.key" ]] && s_pub=$(cat "$WG_DIR/${iface}_public.key")
    
    if [[ -z "$s_pub" ]]; then err "找不到接口公钥，无法匹配用户"; return; fi
    
    log "正在扫描并删除..."
    if [[ -d "$WG_CLIENT_DIR" ]]; then
        # 遍历所有客户端配置，匹配 Peer 公钥
        find "$WG_CLIENT_DIR" -name "*.conf" | while read -r c_conf; do
            if grep -q "$s_pub" "$c_conf"; then
                # 提取用户名 (文件夹名)
                local c_dir=$(dirname "$c_conf")
                local c_name=$(basename "$c_dir")
                core_delete_client "$c_name"
            fi
        done
    fi
    press_any_key
}

del_client_menu() {
    clear
    echo -e "${BLUE}=== 删除客户端 ===${NC}"
    echo "1) 单个删除 (选择列表)"
    echo "2) 批量删除 (指定范围)"
    echo "3) 清空接口用户 (删除某接口下的所有用户)"
    echo "0) 返回"
    local sel
    read -rp "请选择: " sel
    case "$sel" in
        1) del_single_client ;;
        2) del_batch_client ;;
        3) del_all_clients_on_iface ;;
        *) ;;
    esac
}

# 删除服务端接口 (新增：级联删除关联客户端)
del_interface_logic() {
    local iface_list=$(get_ifaces)
    local iface
    select_smart "删除服务端接口 (危险)" "$iface_list" iface
    [[ -z "$iface" ]] && return
    iface=$(trim "$iface")
    
    warn "警告：删除接口 $iface 将同时删除其下所有客户端！"
    read -rp "确认执行? (输入 yes 确认): " confirm
    if [[ "$confirm" == "yes" ]]; then
        # 1. 先级联删除客户端
        log "正在清理关联的客户端..."
        local s_pub=""
        [[ -f "$WG_DIR/${iface}_public.key" ]] && s_pub=$(cat "$WG_DIR/${iface}_public.key")
        
        if [[ -n "$s_pub" && -d "$WG_CLIENT_DIR" ]]; then
            find "$WG_CLIENT_DIR" -name "*.conf" | while read -r c_conf; do
                if grep -q "$s_pub" "$c_conf"; then
                    local c_dir=$(dirname "$c_conf")
                    rm -rf "$c_dir"
                    log "级联删除: $(basename "$c_dir")"
                fi
            done
        fi

        log "正在停止服务..."
        systemctl stop "wg-quick@$iface" 2>/dev/null
        systemctl disable "wg-quick@$iface" 2>/dev/null
        
        log "正在删除配置文件..."
        rm -f "$WG_DIR/${iface}.conf"
        rm -f "$WG_DIR/${iface}_private.key"
        rm -f "$WG_DIR/${iface}_public.key"
        
        log "接口 $iface 已彻底移除。"
    fi
    press_any_key
}

del_menu_entry() {
    echo -e "${BLUE}=== 删除管理 ===${NC}"
    echo "1) 删除 客户端 (二级菜单)"
    echo "2) 删除 接口 (级联删除)"
    echo "0) 返回"
    read -rp "请选择: " sel
    case "$sel" in
        1) del_client_menu ;;
        2) del_interface_logic ;;
        *) ;;
    esac
}

modify_port_logic() {
    local iface_list=$(get_ifaces)
    local iface
    select_smart "修改端口 - 选择接口" "$iface_list" iface
    if [[ -n "$iface" ]]; then
        iface=$(trim "$iface")
        read -rp "新端口: " p
        if [[ "$p" =~ ^[0-9]+$ ]]; then
            log "正在停止服务..."
            systemctl stop "wg-quick@$iface" 2>/dev/null
            wg-quick down "$iface" 2>/dev/null
            
            log "修改配置..."
            sed -i "s/^ListenPort.*/ListenPort = $p/" "$WG_DIR/${iface}.conf"
            
            log "同步客户端配置..."
            if [[ -d "$WG_CLIENT_DIR" ]]; then
                find "$WG_CLIENT_DIR" -name "*.conf" | while read -r client_file; do
                     sed -i "s/\(Endpoint.*:\)[0-9]*$/\1$p/" "$client_file"
                done
            fi

            open_port "$p" "udp"
            
            log "启动服务..."
            systemctl daemon-reload
            if systemctl start "wg-quick@$iface"; then
                 log "成功！端口已更新为 $p"
            else
                 err "启动失败，尝试备用模式..."
                 wg-quick up "$iface" 2>/dev/null && log "备用模式启动成功"
            fi
        else
            err "端口无效"
        fi
    fi
}

show_status_logic() {
    local wg_bin=$(find_wg_bin)
    if [[ -n "$wg_bin" ]]; then "$wg_bin" show; else err "未找到 wg 命令。"; fi
}

uninstall_logic() {
    warn "警告: 删除所有配置！"
    read -rp "输入 'yes' 确认: " confirm
    if [[ "$confirm" == "yes" ]]; then
        log "停止服务..."
        systemctl stop wg-quick@* 2>/dev/null
        systemctl disable wg-quick@* 2>/dev/null
        log "删除文件..."
        rm -rf "$WG_DIR"
        log "卸载软件..."
        detect_pm
        if [[ "$PM" == "apt" ]]; then
            pkg_mgr remove wireguard wireguard-tools qrencode iptables-persistent openresolv resolvconf || true
        elif [[ "$PM" == "yum" || "$PM" == "dnf" ]]; then
            pkg_mgr remove wireguard-tools qrencode iptables-services || true
        else
            pkg_mgr remove wireguard wireguard-tools qrencode || true
        fi
        log "完成"
    fi
}

# ===========================
# 6. 主菜单
# ===========================
menu_main() {
    while true; do
        clear
        echo -e "${BLUE}====================================${NC}"
        echo -e "${BLUE}    WireGuard 管理脚本 (v18.0)      ${NC}"
        echo -e "${BLUE}====================================${NC}"
        echo "1) 安装/配置服务端"
        echo "2) 添加客户端 (批量/单个)"
        echo "3) 列出所有客户端"
        echo "4) 查看配置/二维码"
        echo "5) 删除管理 (客户端/接口)"
        echo "6) 修改端口 (自动同步)"
        echo "7) 运行状态"
        echo "8) 彻底卸载"
        echo "0) 退出"
        echo "------------------------------------"
        read -rp "请选择: " choice
        case "$choice" in
            1) create_server_logic; press_any_key ;;
            2) add_client_menu; press_any_key ;;
            3) list=$(get_clients); if [[ -z "$list" ]]; then echo "(暂无用户)"; else echo "$list" | tr ' ' '\n' | nl; fi; press_any_key ;;
            4) view_client_logic; press_any_key ;;
            5) del_menu_entry; press_any_key ;;
            6) modify_port_logic; press_any_key ;;
            7) show_status_logic; press_any_key ;;
            8) uninstall_logic; press_any_key ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

require_root
menu_main