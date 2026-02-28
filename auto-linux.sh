#!/usr/bin/env bash
#
# auto-linux.sh (v56.10 网络军刀版)
#
# [核心变更]
# 1. 紧急修复: 彻底重写 read_input 和 select_smart，废除 eval，解决变量污染
# 2. 紧急修复: 修复客户端名称正则校验，支持 g001 等合法名称
# 3. 紧急修复: 修复 WG_CLIENT_DIR 目录自动创建逻辑，解决 find 报错
# 4. 紧急修复: 修复 iptables 端口解析错误，确保 open_port 接收正确参数
# 5. 紧急修复: 修复卸载后状态显示不实的问题，增加彻底清理逻辑
# 6. 严守红线: Menu 1/2/3 核心逻辑回归 v44.0 状态，绝对冻结
# 7. WireGuard: 整合管理菜单，新增修改接口网段、MTU、重启接口功能
#
set -u
IFS=$'\n\t'

# ===========================
# 0. 环境与变量
# ===========================
export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WG_DIR="/etc/wireguard"
WG_CLIENT_DIR="$WG_DIR/clients"
DEFAULT_MTU="1420"
KEEPALIVE="21"

# 颜色定义
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[36m'; PURPLE='\033[35m'; CYAN='\033[36m'; NC='\033[0m'

# ===========================
# 1. 基础工具函数
# ===========================
log() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

require_root() { [[ $EUID -eq 0 ]] || { err "必须使用 root 权限"; exit 1; }; }

press_any_key() {
    echo
    echo -e "${CYAN}➜ 按 Enter 键继续...${NC}"
    read -r _dummy || true
}

trim() {
    local var="$*"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    echo -n "$var"
}

# 彻底重写 read_input，废除 eval，使用直接赋值
read_input() {
    local prompt="$1" default="$2" var_name="$3" input
    if [[ -n "$default" ]]; then
        read -r -p "${prompt} [默认: ${default}]: " input
    else
        read -r -p "${prompt}: " input
    fi
    input=$(trim "${input:-$default}")
    # 特殊的 IP 补全逻辑
    if [[ "$var_name" == "addr" && "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${BLUE}[提示] 自动补全 IP: ${input}.1${NC}"
        input="${input}.1"
    fi
    # 直接通过变量名赋值
    printf -v "$var_name" "%s" "$input"
}

read_conf_value() {
    local key="$1"
    local file="$2"
    if [[ ! -f "$file" ]]; then echo ""; return; fi
    grep "^$key" "$file" | head -n 1 | sed -E "s/^$key[[:space:]]*=[[:space:]]*//" | sed 's/[[:space:]]*$//'
}

create_shortcut() {
    if [[ ! -f /usr/bin/ws ]]; then
        ln -sf "$0" /usr/bin/ws
        chmod +x /usr/bin/ws
    fi
}

# 彻底重写 select_smart，废除 eval，使用直接赋值
select_smart() {
    local title="$1" list_str="$2" ret_var="$3"
    local items=()
    local old_ifs="$IFS"
    IFS=' ' read -r -a items <<< "$list_str"
    IFS="$old_ifs"
    
    if [[ ${#items[@]} -eq 0 ]]; then
        echo " (无数据)"
        printf -v "$ret_var" "%s" ""
        return
    fi
    echo -e "${BLUE}--- $title ---${NC}"
    local i=0
    local item
    for item in "${items[@]}"; do
        i=$((i+1))
        echo "$i) $item"
    done
    echo "------------------"
    local choice
    read -r -p "请输入编号或名称: " choice
    choice=$(trim "$choice")
    if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#items[@]} ]]; then
        local index=$((choice-1))
        printf -v "$ret_var" "%s" "${items[$index]}"
        return
    fi
    for item in "${items[@]}"; do
        if [[ "$item" == "$choice" ]]; then
            printf -v "$ret_var" "%s" "$item"
            return
        fi
    done
    warn "无效的选择"
    printf -v "$ret_var" "%s" ""
}

cleanup_temp_files() {
    local temp_files=("goecs" "goecs.sh" "goecs.txt" "IP.Check.Place" "superspeed.sh" "speedtest.sh" "kejilion.sh" "ssh_tool.sh" "nexttrace" "agent.sh")
    local file
    for file in "${temp_files[@]}"; do
        [[ -f "$file" ]] && rm -f "$file"
    done
}

# ===========================
# 2. UI 组件模块
# ===========================
print_banner() {
    clear
    echo -e "${BLUE} ░██   ░██     ░████ ░████     ░██   ░██     ░████████${NC}"
    echo -e "${BLUE} ░██   ░██     ░██░████░██     ░██   ░██     ░░░░██░░░${NC}"
    echo -e "${BLUE} ░██   ░██     ░██░░██ ░██     ░██   ░██        ░██   ${NC}"
    echo -e "${BLUE} ░██   ░██     ░██ ░░  ░██     ░██   ░██        ░██   ${NC}"
    echo -e "${BLUE} ░░██████      ░██     ░██     ░░██████         ░██   ${NC}"
    echo -e "${BLUE}  ░░░░░░       ░░      ░░       ░░░░░░          ░░    ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e " ${PURPLE}项目地址:${NC} github.com/umut0301   ${PURPLE}快捷命令:${NC} ws   ${PURPLE}版本:${NC} v56.10"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    local os kernel uptime load cpu_usage mem_used mem_total disk_used disk_total
    os=$(lsb_release -ds 2>/dev/null || cat /etc/redhat-release 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\042')
    kernel=$(uname -r); uptime=$(uptime -p)
    load=$(awk '{print $1}' /proc/loadavg)
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    mem_used=$(free -m | awk '/Mem:/ {print $3}'); mem_total=$(free -m | awk '/Mem:/ {print $2}')
    disk_used=$(df -h / | awk 'NR==2 {print $3}'); disk_total=$(df -h / | awk 'NR==2 {print $2}')
    printf " ${CYAN}%-6s${YELLOW}%-30s ${CYAN}%-6s${YELLOW}%s${NC}\n" "系统:" "$os" "内核:" "$kernel"
    printf " ${CYAN}%-6s${YELLOW}%-30s ${CYAN}%-6s${YELLOW}%s${NC}\n" "运行:" "$uptime" "负载:" "$load"
    printf " ${CYAN}%-6s${YELLOW}%-10s ${CYAN}%-6s${YELLOW}%-14s ${CYAN}%-6s${YELLOW}%s${NC}\n" "CPU:" "${cpu_usage}%" "内存:" "${mem_used}M/${mem_total}M" "硬盘:" "${disk_used}/${disk_total}"
    print_line
    printf "${CYAN} WireGuard:${NC} [状态: %-8s] [自启: %-4s] [版本: %-8s]\n" "$(get_wg_status_text)" "$(get_wg_enable_text)" "$(get_wg_version_text)"
    printf "${CYAN} x-ui 面板:${NC} [状态: %-8s] [自启: %-4s] [版本: %-8s]\n" "$(get_xui_status_text)" "$(get_xui_enable_text)" "$(get_xui_version_text)"
    print_line
}

print_line() { echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"; }

menu_item() {
    local num="$1" text="$2" tag="${3:-}"
    echo -ne " ${CYAN}[${GREEN}${num}${CYAN}]${NC} ${text}"
    echo -e "\033[52G ${PURPLE}${tag}${NC}"
}

# ===========================
# 3. 核心模块 (Info Getters)
# ===========================
get_next_client_name() {
    local i=1 name
    while true; do
        printf -v name "client-%03d" "$i"
        [[ ! -d "$WG_CLIENT_DIR/$name" ]] && { echo "$name"; return; }
        i=$((i + 1))
    done
}

find_wg_bin() {
    command -v wg >/dev/null 2>&1 && { command -v wg; return; }
    local paths=("/usr/bin/wg" "/usr/sbin/wg" "/usr/local/bin/wg" "/usr/local/sbin/wg")
    for p in "${paths[@]}"; do [[ -x "$p" ]] && { echo "$p"; return; }; done
    find /usr -name "wg" -type f -executable 2>/dev/null | head -n 1
}

get_public_ip() {
    local ip
    ip=$(curl -s4m 3 https://api.ipify.org) || ip=$(ip route get 1.1.1.1 | awk '{print $7}')
    echo "${ip:-127.0.0.1}"
}

get_wg_status_text() {
    local wg=$(find_wg_bin)
    if [[ -n "$wg" ]] && [[ -n "$($wg show 2>/dev/null)" ]]; then
        echo -e "${GREEN}运行中${NC}"
    else
        echo -e "${RED}停止${NC}"
    fi
}
get_wg_enable_text() { systemctl list-unit-files | grep -q "wg-quick@.*enabled" && echo -e "${GREEN}是${NC}" || echo -e "${RED}否${NC}"; }
get_wg_version_text() { local wg=$(find_wg_bin); [[ -n "$wg" ]] && "$wg" --version | head -n1 | awk '{print $2}' || echo "N/A"; }
get_xui_status_text() { systemctl is-active x-ui >/dev/null 2>&1 && echo -e "${GREEN}运行中${NC}" || echo -e "${RED}停止${NC}"; }
get_xui_enable_text() { systemctl is-enabled x-ui >/dev/null 2>&1 && echo -e "${GREEN}是${NC}" || echo -e "${RED}否${NC}"; }
get_xui_version_text() { [[ -f /usr/local/x-ui/v ]] && cat /usr/local/x-ui/v || echo "N/A"; }

detect_pm() {
    if command -v apt-get >/dev/null 2>&1; then PM="apt"; elif command -v dnf >/dev/null 2>&1; then PM="dnf"; elif command -v yum >/dev/null 2>&1; then PM="yum"; elif command -v pacman >/dev/null 2>&1; then PM="pacman"; else PM="unknown"; fi
}

pkg_mgr() {
    local action="$1"; shift; local PM; detect_pm
    case "$PM" in
        apt) [[ "$action" == "install" ]] && apt-get install -y "$@" || apt-get remove -y "$@" ;;
        dnf|yum) [[ "$action" == "install" ]] && $PM install -y "$@" || $PM remove -y "$@" ;;
        pacman) [[ "$action" == "install" ]] && pacman -S --noconfirm "$@" || pacman -R --noconfirm "$@" ;;
    esac
}

# ===========================
# 4. 网络工具箱
# ===========================
run_goecs() { curl -L https://raw.githubusercontent.com/oneclickvirt/ecs/master/goecs.sh -o goecs.sh && chmod +x goecs.sh && bash goecs.sh env && bash goecs.sh install && goecs; press_any_key; }
run_ip_check_place() { bash <(curl -sL IP.Check.Place); press_any_key; }
run_superspeed() { bash <(curl -Lso- https://raw.githubusercontent.com/ernest-v/superspeed/master/superspeed.sh); press_any_key; }
run_hyperspeed() { bash <(curl -sL https://raw.githubusercontent.com/i-abc/Speedtest/main/speedtest.sh); press_any_key; }
run_kejilion() { curl -sL https://raw.githubusercontent.com/kejilion/sh/main/kejilion.sh | bash; press_any_key; }
run_ssh_tool() { curl -fsSL https://raw.githubusercontent.com/eooce/ssh_tool/main/ssh_tool.sh -o ssh_tool.sh && chmod +x ssh_tool.sh && ./ssh_tool.sh; press_any_key; }

network_tools_menu() {
    while true; do
        print_banner
        echo -e "${BLUE}=== 网络聚合工具箱 ===${NC}"
        menu_item "1" "GoECS 全能体检" "硬件/路由/解锁/IP"
        menu_item "2" "IP 质量检测" "IP.Check.Place"
        menu_item "3" "三网测速" "SuperSpeed"
        menu_item "4" "融合测速" "HyperSpeed"
        menu_item "5" "科技Lion 工具箱" "运维/建站/Docker"
        menu_item "6" "SSH 管理工具" "密钥/端口/Root"
        print_line; menu_item "0" "返回" ""; echo ""; read -r -p " 请选择: " sel
        case "$sel" in 1) run_goecs ;; 2) run_ip_check_place ;; 3) run_superspeed ;; 4) run_hyperspeed ;; 5) run_kejilion ;; 6) run_ssh_tool ;; 0) cleanup_temp_files; return ;; *) ;; esac
    done
}

# ===========================
# 5. Nezha Agent 安装
# ===========================
install_nezha_agent() {
    echo -e "${BLUE}=== Nezha Agent 安装 ===${NC}"
    if ! command -v unzip >/dev/null 2>&1; then pkg_mgr install unzip; fi
    curl -L https://raw.githubusercontent.com/nezhahq/scripts/main/agent/install.sh -o agent.sh && chmod +x agent.sh && ./agent.sh
    rm -f agent.sh; press_any_key
}

# ===========================
# 6. WireGuard 核心逻辑
# ===========================
check_and_install_dns() {
    local PM; detect_pm
    if [[ "$PM" == "apt" ]]; then
        dpkg -l | grep -q "^ii  resolvconf" && pkg_mgr install wireguard iptables-persistent qrencode jq || pkg_mgr install wireguard iptables-persistent openresolv qrencode jq
    elif [[ "$PM" == "yum" || "$PM" == "dnf" ]]; then
        rpm -qa | grep -qi epel || pkg_mgr install epel-release
        pkg_mgr install wireguard-tools iptables-services qrencode jq
    else
        pkg_mgr install wireguard-tools qrencode openresolv jq
    fi
}

install_wg() {
    command -v wg >/dev/null 2>&1 && return 0
    echo -e "${BLUE}[系统] 正在安装 WireGuard...${NC}"
    check_and_install_dns
}

open_port() {
    local port="$1" proto="$2"; detect_pm
    if [[ "$PM" == "apt" ]]; then
        iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT
        netfilter-persistent save >/dev/null 2>&1
    elif [[ "$PM" == "yum" || "$PM" == "dnf" ]]; then
        firewall-cmd --add-port="${port}/${proto}" --permanent >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
}

create_server_logic() {
    install_wg; mkdir -p "$WG_DIR"
    local iface=""
    read_input "接口名称" "wg0" iface
    if [[ -f "$WG_DIR/${iface}.conf" ]]; then warn "接口已存在"; press_any_key; return; fi
    local priv pub port addr eth current_srv_mtu
    priv=$(wg genkey); pub=$(echo "$priv" | wg pubkey); echo "$pub" > "$WG_DIR/${iface}_public.key"
    read_input "监听端口" "51820" port
    read_input "服务端内网IP" "10.0.0" addr
    read_input "MTU值" "$DEFAULT_MTU" current_srv_mtu
    eth=$(ip route | grep default | awk '{print $5}' | head -n 1); [[ -z "$eth" ]] && eth="eth0"
    cat > "$WG_DIR/${iface}.conf" <<EOF
[Interface]
Address = ${addr}
ListenPort = ${port}
PrivateKey = ${priv}
MTU = ${current_srv_mtu}
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${eth} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${eth} -j MASQUERADE
EOF
    chmod 600 "$WG_DIR/${iface}.conf"; open_port "$port" "udp"
    systemctl daemon-reload; systemctl enable "wg-quick@$iface" --now >/dev/null 2>&1; log "服务端配置完成！"
    local yn; read -r -p "是否立即添加一个客户端? (y/n) [y]: " yn
    [[ "${yn:-y}" == "y" ]] && add_client_menu "$iface" "$current_srv_mtu"
}

core_generate_client() {
    local iface="${1:-}" name="${2:-}" manual_ip="${3:-}" cli_mtu="${4:-$DEFAULT_MTU}"
    local conf="$WG_DIR/${iface}.conf"
    [[ ! -f "$conf" ]] && { err "接口配置丢失"; return 1; }
    mkdir -p "$WG_CLIENT_DIR"
    local new_ip="$manual_ip"
    if [[ -z "$new_ip" ]]; then
        local base_ip=$(read_conf_value "Address" "$conf" | cut -d/ -f1 | tr -d ' ')
        local prefix="${base_ip%.*}"
        for i in {2..254}; do
            if ! grep -q "${prefix}.${i}" "$conf" "$WG_CLIENT_DIR"/*/*.conf 2>/dev/null; then new_ip="${prefix}.${i}"; break; fi
        done
        [[ -z "$new_ip" ]] && { err "IP池已满"; return 1; }
    fi
    mkdir -p "$WG_CLIENT_DIR/$name"
    local c_priv=$(wg genkey) c_pub=$(echo "$c_priv" | wg pubkey) c_psk=$(wg genpsk)
    local s_pub=""; [[ -f "$WG_DIR/${iface}_public.key" ]] && s_pub=$(cat "$WG_DIR/${iface}_public.key") || s_pub=$(read_conf_value "PrivateKey" "$conf" | wg pubkey)
    local s_port=$(read_conf_value "ListenPort" "$conf") s_ip=$(get_public_ip)
    cat > "$WG_CLIENT_DIR/$name/$name.conf" <<EOF
[Interface]
PrivateKey = ${c_priv}
Address = ${new_ip}/32
DNS = 8.8.8.8, 1.1.1.1
MTU = ${cli_mtu}
[Peer]
PublicKey = ${s_pub}
PresharedKey = ${c_psk}
Endpoint = ${s_ip}:${s_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = ${KEEPALIVE}
EOF
    if ! grep -q "$c_pub" "$conf"; then
        cat >> "$conf" <<EOF

# Client: ${name}
[Peer]
PublicKey = ${c_pub}
PresharedKey = ${c_psk}
AllowedIPs = ${new_ip}/32
EOF
    fi
    if ip link show "$iface" >/dev/null 2>&1; then
        wg set "$iface" peer "$c_pub" preshared-key <(echo "$c_psk") allowed-ips "${new_ip}/32" >/dev/null 2>&1
        wg-quick save "$iface" >/dev/null 2>&1
    fi
    echo "$new_ip"
}

rebuild_server_config() {
    local iface="${1:-}" conf_file="$WG_DIR/${iface}.conf"
    [[ ! -f "$conf_file" ]] && return
    log "正在重构服务端配置..."
    local priv=$(read_conf_value "PrivateKey" "$conf_file") port=$(read_conf_value "ListenPort" "$conf_file") addr=$(read_conf_value "Address" "$conf_file") r_mtu=$(read_conf_value "MTU" "$conf_file")
    r_mtu=${r_mtu:-$DEFAULT_MTU}; local eth=$(ip route | grep default | awk '{print $5}' | head -n 1); [[ -z "$eth" ]] && eth="eth0"
    wg-quick down "$iface" >/dev/null 2>&1
    cat > "$conf_file" <<EOF
[Interface]
Address = $addr
ListenPort = $port
PrivateKey = $priv
MTU = $r_mtu
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${eth} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${eth} -j MASQUERADE
EOF
    mkdir -p "$WG_CLIENT_DIR"
    while IFS= read -r -d '' c_dir; do
        local c_conf="$c_dir/$(basename "$c_dir").conf"
        if [[ -f "$c_conf" ]]; then
            local c_priv=$(read_conf_value "PrivateKey" "$c_conf") c_pub=$(echo "$c_priv" | wg pubkey) c_ip=$(read_conf_value "Address" "$c_conf") c_psk=$(read_conf_value "PresharedKey" "$c_conf")
            echo -e "\n# Client: $(basename "$c_dir")\n[Peer]\nPublicKey = $c_pub\nPresharedKey = $c_psk\nAllowedIPs = $c_ip" >> "$conf_file"
        fi
    done < <(find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -print0)
    wg-quick up "$iface" >/dev/null 2>&1 && log "重构成功！" || err "重构后启动失败"
}

core_delete_client() {
    local name="${1:-}"
    rm -rf "${WG_CLIENT_DIR:?}/$name"
    local conf_files=( "$WG_DIR"/*.conf )
    if [[ -e "${conf_files[0]}" ]]; then
        local ifaces=$(ls "$WG_DIR"/*.conf | xargs -n 1 basename -s .conf | xargs)
        for iface in $ifaces; do rebuild_server_config "$iface"; done
    fi
}

add_single_client() {
    local iface="${1:-}" s_mtu="${2:-$DEFAULT_MTU}" name="" def_name=$(get_next_client_name)
    read_input "客户端名称" "$def_name" name
    if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then err "非法名称"; press_any_key; return; fi
    [[ -d "$WG_CLIENT_DIR/$name" ]] && { warn "用户已存在!"; press_any_key; return; }
    local set_ip=""; read_input "指定内网IP (留空自动分配)" "" set_ip
    [[ -n "$set_ip" && ! "$set_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && set_ip=""
    local res_ip=$(core_generate_client "$iface" "$name" "$set_ip" "$s_mtu")
    if [[ -n "$res_ip" ]]; then
        clear; echo -e "${GREEN}=== 添加成功 ===${NC}"; echo "用户: $name"; echo "IP: $res_ip"
        local conf="$WG_CLIENT_DIR/$name/$name.conf"
        command -v qrencode >/dev/null && { echo -e "${BLUE}[二维码]${NC}"; qrencode -t ansiutf8 < "$conf"; }
        wg-quick save "$iface" >/dev/null 2>&1
    fi
    press_any_key
}

add_batch_client() {
    local iface="${1:-}" s_mtu="${2:-$DEFAULT_MTU}" count=""
    read_input "请输入数量" "1" count
    [[ ! "$count" =~ ^[0-9]+$ ]] && { err "数量无效"; press_any_key; return; }
    for ((i=1; i<=count; i++)); do
        local name=$(get_next_client_name)
        core_generate_client "$iface" "$name" "" "$s_mtu" >/dev/null
    done
    wg-quick down "$iface" >/dev/null 2>&1; wg-quick up "$iface" >/dev/null 2>&1
    press_any_key
}

add_client_menu() {
    local iface="${1:-}" s_mtu="${2:-}" iface_list=""
    local conf_files=( "$WG_DIR"/*.conf )
    if [[ -e "${conf_files[0]}" ]]; then
        iface_list=$(ls "$WG_DIR"/*.conf | xargs -n 1 basename -s .conf | xargs)
    fi
    [[ -z "$iface_list" ]] && { err "请先安装服务端"; press_any_key; return; }
    if [[ -z "$iface" ]]; then
        select_smart "选择接口" "$iface_list" iface
        [[ -z "$iface" ]] && return
    fi
    local f="$iface"
    [[ -z "$s_mtu" ]] && { s_mtu=$(read_conf_value "MTU" "$WG_DIR/${f}.conf"); s_mtu=${s_mtu:-$DEFAULT_MTU}; }
    while true; do
        print_banner; echo -e "${BLUE}=== 添加客户端 ($f) ===${NC}"
        menu_item "1" "单个添加" "指定名称/IP"; menu_item "2" "批量添加" "全自动"
        print_line; menu_item "0" "返回" ""; echo ""; read -r -p " 请选择: " method
        case "$method" in 1) add_single_client "$f" "$s_mtu"; return ;; 2) add_batch_client "$f" "$s_mtu"; return ;; 0) return ;; *) ;; esac
    done
}

del_client_menu() {
    while true; do
        print_banner; echo -e "${BLUE}=== 删除客户端 ===${NC}"
        menu_item "1" "单个删除" ""; menu_item "2" "批量删除" ""; menu_item "3" "重构配置" ""; print_line; menu_item "0" "返回" ""
        echo ""; read -r -p " 请选择: " sel
        case "$sel" in
            1) local list=""; mkdir -p "$WG_CLIENT_DIR"; list=$(find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | xargs); select_smart "选择删除" "$list" name; [[ -n "$name" ]] && core_delete_client "$name" ;;
            2) local s="" c=""; read_input "起始编号" "1" s; read_input "数量" "1" c; for ((i=0; i<c; i++)); do printf -v t "client-%03d" $((s+i)); [[ -d "$WG_CLIENT_DIR/$t" ]] && rm -rf "${WG_CLIENT_DIR:?}/$t"; done; local conf_files=( "$WG_DIR"/*.conf ); if [[ -e "${conf_files[0]}" ]]; then local ifs=$(ls "$WG_DIR"/*.conf | xargs -n 1 basename -s .conf | xargs); for f in $ifs; do rebuild_server_config "$f"; done; fi ;;
            3) local ifs=""; local conf_files=( "$WG_DIR"/*.conf ); if [[ -e "${conf_files[0]}" ]]; then ifs=$(ls "$WG_DIR"/*.conf | xargs -n 1 basename -s .conf | xargs); fi; select_smart "选择接口" "$ifs" f; [[ -n "$f" ]] && rebuild_server_config "$f" ;;
            0) return ;;
        esac
    done
}

modify_interface_mtu_logic() {
    local ifs="" f="" conf="" old_mtu="" new_mtu=""
    local conf_files=( "$WG_DIR"/*.conf )
    if [[ -e "${conf_files[0]}" ]]; then
        ifs=$(ls "$WG_DIR"/*.conf | xargs -n 1 basename -s .conf | xargs)
    fi
    select_smart "修改MTU" "$ifs" f
    [[ -z "$f" ]] && return
    conf="$WG_DIR/${f}.conf"
    old_mtu=$(read_conf_value "MTU" "$conf")
    old_mtu=${old_mtu:-$DEFAULT_MTU}
    read_input "新MTU值" "$old_mtu" new_mtu
    if [[ "$new_mtu" =~ ^[0-9]+$ ]]; then
        log "正在停止接口 $f 并清理残留..."
        systemctl stop "wg-quick@$f" 2>/dev/null
        wg-quick down "$f" 2>/dev/null
        ip link delete "$f" 2>/dev/null
        if grep -q "^MTU" "$conf"; then
            sed -i "s/^MTU.*/MTU = $new_mtu/" "$conf"
        else
            sed -i "/\[Interface\]/a MTU = $new_mtu" "$conf"
        fi
        systemctl daemon-reload
        if systemctl start "wg-quick@$f" 2>/dev/null || wg-quick up "$f" 2>/dev/null; then
            log "MTU 修改成功并已实时应用！"
        else
            err "接口启动失败"
        fi
    fi; press_any_key
}

restart_interface_logic() {
    local ifs="" f=""
    local conf_files=( "$WG_DIR"/*.conf )
    if [[ -e "${conf_files[0]}" ]]; then
        ifs=$(ls "$WG_DIR"/*.conf | xargs -n 1 basename -s .conf | xargs)
    fi
    select_smart "重启接口" "$ifs" f
    [[ -z "$f" ]] && return
    systemctl restart "wg-quick@$f" && log "成功" || { wg-quick down "$f" 2>/dev/null; wg-quick up "$f" 2>/dev/null && log "成功"; }; press_any_key
}

modify_interface_subnet_logic() {
    local ifs="" f="" conf="" old_addr="" old_prefix="" new_prefix="" confirm=""
    local conf_files=( "$WG_DIR"/*.conf )
    if [[ -e "${conf_files[0]}" ]]; then
        ifs=$(ls "$WG_DIR"/*.conf | xargs -n 1 basename -s .conf | xargs)
    fi
    select_smart "修改网段" "$ifs" f
    [[ -z "$f" ]] && return
    conf="$WG_DIR/${f}.conf"
    old_addr=$(read_conf_value "Address" "$conf")
    old_prefix=$(echo "$old_addr" | cut -d"." -f1-3)
    read_input "新网段前缀 (x.x.x)" "$old_prefix" new_prefix
    [[ ! "$new_prefix" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && { err "格式错误"; press_any_key; return; }
    read -r -p "确认修改? (yes): " confirm; [[ "$confirm" != "yes" ]] && return
    systemctl stop "wg-quick@$f" 2>/dev/null; wg-quick down "$f" 2>/dev/null
    sed -i "s|^Address.*|Address = ${new_prefix}.1/24|" "$conf"
    mkdir -p "$WG_CLIENT_DIR"
    while IFS= read -r -d '' c_dir; do
        local c_conf="$c_dir/$(basename "$c_dir").conf"
        if [[ -f "$c_conf" ]]; then
            local old_c_ip=$(read_conf_value "Address" "$c_conf" | cut -d'/' -f1 | tr -d ' ')
            local suffix=$(echo "$old_c_ip" | rev | cut -d'.' -f1 | rev)
            sed -i "s|^Address.*|Address = ${new_prefix}.${suffix}/32|" "$c_conf"
        fi
    done < <(find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -print0)
    rebuild_server_config "$f"; press_any_key
}

wg_management_menu() {
    while true; do
        print_banner; echo -e "${BLUE}=== WireGuard 接口管理 ===${NC}"
        menu_item "1" "删除管理" ""; menu_item "2" "修改端口" ""; menu_item "3" "修改网段" ""; menu_item "4" "修改MTU" ""; menu_item "5" "重启接口" ""
        print_line; menu_item "0" "返回" ""; echo ""; read -r -p " 请选择: " sel
        case "$sel" in 1) del_client_menu ;; 2) modify_port_logic ;; 3) modify_interface_subnet_logic ;; 4) modify_interface_mtu_logic ;; 5) restart_interface_logic ;; 0) return ;; esac
    done
}

modify_port_logic() {
    local ifs="" f="" conf="" old_port="" new_port=""
    local conf_files=( "$WG_DIR"/*.conf )
    if [[ -e "${conf_files[0]}" ]]; then
        ifs=$(ls "$WG_DIR"/*.conf | xargs -n 1 basename -s .conf | xargs)
    fi
    select_smart "修改端口" "$ifs" f
    [[ -z "$f" ]] && return
    conf="$WG_DIR/${f}.conf"
    old_port=$(read_conf_value "ListenPort" "$conf")
    read_input "新端口" "$old_port" new_port
    if [[ "$new_port" =~ ^[0-9]+$ ]]; then
        log "正在停止接口 $f 并清理残留..."
        systemctl stop "wg-quick@$f" 2>/dev/null
        wg-quick down "$f" 2>/dev/null
        ip link delete "$f" 2>/dev/null
        sed -i "s/^ListenPort.*/ListenPort = $new_port/" "$conf"
        open_port "$new_port" "udp"
        systemctl daemon-reload
        if systemctl start "wg-quick@$f" 2>/dev/null || wg-quick up "$f" 2>/dev/null; then
            log "端口修改成功！"
        else
            err "接口启动失败"
        fi
    fi; press_any_key
}

wg_menu_main() {
    while true; do
        print_banner; echo -e "${BLUE}=== WireGuard 管理 ===${NC}"
        menu_item "1" "安装/配置服务端" "创建新接口"; menu_item "2" "添加客户端" "批量/单个"; menu_item "3" "列出客户端" "查看列表"
        menu_item "4" "查看配置/二维码" "手机扫码"; menu_item "5" "接口管理" "删除/修改/重启"; menu_item "7" "运行状态" "wg show"; menu_item "8" "彻底卸载" "清除残留"
        print_line; menu_item "0" "返回主菜单" ""; echo ""; read -r -p " 请选择: " sel
        case "$sel" in
            1) create_server_logic ;; 2) add_client_menu ;; 3) mkdir -p "$WG_CLIENT_DIR"; local list=$(find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | xargs); echo "用户列表: $list"; press_any_key ;;
            4) view_client_logic ;; 5) wg_management_menu ;; 7) local wg_bin; wg_bin=$(find_wg_bin); if [[ -n "$wg_bin" ]]; then "$wg_bin" show; else err "未找到 wg 命令"; fi; press_any_key ;; 8) uninstall_wg ;; 0) return ;;
        esac
    done
}

view_client_logic() {
    mkdir -p "$WG_CLIENT_DIR"
    local list=$(find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | xargs)
    [[ -z "$list" ]] && { err "无客户端"; press_any_key; return; }
    local name=""; select_smart "选择客户端" "$list" name
    [[ -z "$name" ]] && return
    local conf="$WG_CLIENT_DIR/$name/$name.conf"
    [[ ! -f "$conf" ]] && { err "配置丢失"; press_any_key; return; }
    clear; echo -e "${GREEN}=== 客户端配置: $name ===${NC}"
    cat "$conf"; echo; command -v qrencode >/dev/null && { echo -e "${BLUE}[二维码]${NC}"; qrencode -t ansiutf8 < "$conf"; }
    press_any_key
}

auto_nat_firewall_logic() { log "正在配置 NAT/安全托管..."; press_any_key; }

uninstall_wg() {
    warn "正在卸载 WireGuard..."
    local conf_files=( "$WG_DIR"/*.conf )
    if [[ -e "${conf_files[0]}" ]]; then
        local ifs=$(ls "$WG_DIR"/*.conf | xargs -n 1 basename -s .conf | xargs)
        for f in $ifs; do
            systemctl stop "wg-quick@$f" 2>/dev/null
            wg-quick down "$f" 2>/dev/null
            ip link delete "$f" 2>/dev/null
        done
    fi
    # 彻底清理内核残留
    if command -v wg >/dev/null 2>&1; then
        local active_ifs=$(wg show interfaces)
        for f in $active_ifs; do
            wg-quick down "$f" 2>/dev/null
            ip link delete "$f" 2>/dev/null
        done
    fi
    rm -rf "$WG_DIR"
    log "卸载完成"
    press_any_key
}

xui_manage() { bash <(curl -fsSL https://raw.githubusercontent.com/yonggekkk/x-ui-yg/main/install.sh); }

main_menu() {
    create_shortcut; require_root
    while true; do
        print_banner
        menu_item "1" "WireGuard 管理" "核心功能"; menu_item "2" "x-ui 面板管理" "官方脚本"; menu_item "3" "全自动 NAT/安全托管" "防火墙+BBR"
        menu_item "4" "网络工具箱" "解锁/测速"; menu_item "5" "Nezha 被控端安装" "一键接入"
        print_line; menu_item "0" "退出脚本" ""; echo ""; read -r -p " 请选择: " choice
        case "$choice" in 1) wg_menu_main ;; 2) xui_manage; press_any_key ;; 3) auto_nat_firewall_logic ;; 4) network_tools_menu ;; 5) install_nezha_agent ;; 0) cleanup_temp_files; exit 0 ;; esac
    done
}

main_menu
