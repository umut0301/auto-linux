#!/usr/bin/env bash
#
# auto-linux.sh (v56.5 网络军刀版)
#
# [核心变更]
# 1. 新增自动清理机制: 退出或返回主菜单时自动删除工具箱产生的临时文件
# 2. 修复 CYAN 变量未定义导致的 crash 问题
# 3. 深度代码规范化，修复剩余 shellcheck 问题
# 4. Menu 5 (Nezha): 新增 Nezha Agent 一键安装
# 5. 严守红线: Menu 1/2/3 核心逻辑保持 v44.0 状态，绝对冻结
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
    read -r _dummy
}

trim() {
    local var="$*"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    echo -n "$var"
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

# 清理临时文件函数
cleanup_temp_files() {
    # 定义要清理的文件列表 (仅限当前目录)
    local temp_files=(
        "goecs" "goecs.sh" "goecs.txt"
        "IP.Check.Place"
        "superspeed.sh"
        "speedtest.sh"
        "kejilion.sh"
        "ssh_tool.sh"
        "nexttrace"
        "agent.sh"
        "test-auto.py" # 如果有残留
    )

    # 遍历并删除
    for file in "${temp_files[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
        fi
    done
    # 不输出日志，保持静默清理
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
    echo -e " ${PURPLE}项目地址:${NC} github.com/umut0301   ${PURPLE}快捷命令:${NC} ws   ${PURPLE}版本:${NC} v56.5"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

print_line() {
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
}

menu_item() {
    local num="$1"
    local text="$2"
    local tag="${3:-}"
    echo -ne " ${CYAN}[${GREEN}${num}${CYAN}]${NC} ${text}"
    echo -e "\033[52G ${PURPLE}${tag}${NC}"
}

# ===========================
# 3. 核心模块 (Info Getters)
# ===========================
get_next_client_name() {
    local i=1
    local name
    while true; do
        printf -v name "client-%03d" "$i"
        if [[ ! -d "$WG_CLIENT_DIR/$name" ]]; then echo "$name"; return; fi
        i=$((i + 1))
    done
}

find_wg_bin() {
    if command -v wg >/dev/null 2>&1; then command -v wg; return; fi
    local paths=("/usr/bin/wg" "/usr/sbin/wg" "/usr/local/bin/wg" "/usr/local/sbin/wg")
    local p
    for p in "${paths[@]}"; do if [[ -x "$p" ]]; then echo "$p"; return; fi; done
    find /usr -name "wg" -type f -executable 2>/dev/null | head -n 1
}

get_public_ip() {
    local ip
    ip=$(curl -s4m 3 https://api.ipify.org) || ip=$(ip route get 1.1.1.1 | awk '{print $7}')
    echo "${ip:-127.0.0.1}"
}

get_wg_status_text() {
    local wg
    wg=$(find_wg_bin)
    if [[ -n "$wg" ]] && [[ -n "$($wg show 2>/dev/null)" ]]; then echo -e "${GREEN}运行中${NC}"; else echo -e "${RED}停止${NC}"; fi
}
get_wg_enable_text() {
    if systemctl list-unit-files | grep -q "wg-quick@.*enabled"; then echo -e "${GREEN}是${NC}"; else echo -e "${RED}否${NC}"; fi
}
get_wg_version_text() {
    local wg
    wg=$(find_wg_bin)
    if [[ -n "$wg" ]]; then "$wg" --version | head -n1 | awk '{print $2}'; else echo "N/A"; fi
}
get_xui_status_text() { if systemctl is-active x-ui >/dev/null 2>&1; then echo -e "${GREEN}运行中${NC}"; else echo -e "${RED}停止${NC}"; fi; }
get_xui_enable_text() { if systemctl is-enabled x-ui >/dev/null 2>&1; then echo -e "${GREEN}是${NC}"; else echo -e "${RED}否${NC}"; fi; }
get_xui_version_text() { if [[ -f /usr/local/x-ui/v ]]; then cat /usr/local/x-ui/v; else echo "N/A"; fi; }

detect_pm() {
    if command -v apt-get >/dev/null 2>&1; then PM="apt"; elif command -v dnf >/dev/null 2>&1; then PM="dnf"; elif command -v yum >/dev/null 2>&1; then PM="yum"; elif command -v pacman >/dev/null 2>&1; then PM="pacman"; else PM="unknown"; fi
}

pkg_mgr() {
    local action="$1"
    shift
    local PM
    detect_pm
    echo -e "${BLUE}[系统] 执行: $PM $action $*${NC}"
    case "$PM" in
        apt) [[ "$action" == "install" ]] && apt-get install -y "$@" || apt-get remove -y "$@" ;;
        dnf) [[ "$action" == "install" ]] && dnf install -y "$@" || dnf remove -y "$@" ;;
        yum) [[ "$action" == "install" ]] && yum install -y "$@" || yum remove -y "$@" ;;
        pacman) [[ "$action" == "install" ]] && pacman -S --noconfirm "$@" || pacman -R --noconfirm "$@" ;;
    esac
}

# ===========================
# 4. 网络工具箱 (聚合启动器)
# ===========================

# 4-1: GoECS 全能测试
run_goecs() {
    echo -e "${BLUE}>>> 正在启动 GoECS 服务器全能体检...${NC}"
    export noninteractive=true
    curl -L https://raw.githubusercontent.com/oneclickvirt/ecs/master/goecs.sh -o goecs.sh && chmod +x goecs.sh && bash goecs.sh env && bash goecs.sh install && goecs
    press_any_key
}

# 4-2: IP.Check.Place (IP质量)
run_ip_check_place() {
    echo -e "${BLUE}>>> 正在启动 IP.Check.Place...${NC}"
    bash <(curl -sL IP.Check.Place)
    press_any_key
}

# 4-3: SuperSpeed (三网测速)
run_superspeed() {
    echo -e "${BLUE}>>> 正在启动 SuperSpeed 三网测速...${NC}"
    bash <(curl -Lso- https://git.io/superspeed_uxh)
    press_any_key
}

# 4-4: Hyperspeed (i-abc 融合测速)
run_hyperspeed() {
    echo -e "${BLUE}>>> 正在启动 i-abc 融合测速...${NC}"
    bash <(curl -sL https://raw.githubusercontent.com/i-abc/Speedtest/main/speedtest.sh)
    press_any_key
}

# 4-5: Kejilion 工具箱
run_kejilion() {
    echo -e "${BLUE}>>> 正在启动 科技Lion 工具箱...${NC}"
    curl -sL https://raw.githubusercontent.com/kejilion/sh/main/kejilion.sh | bash
    press_any_key
}

# 4-6: SSH 管理工具
run_ssh_tool() {
    echo -e "${BLUE}>>> 正在启动 SSH 管理工具...${NC}"
    curl -fsSL https://raw.githubusercontent.com/eooce/ssh_tool/main/ssh_tool.sh -o ssh_tool.sh && chmod +x ssh_tool.sh && ./ssh_tool.sh
    press_any_key
}

network_tools_menu() {
    while true; do
        print_banner
        echo -e "${BLUE}=== 网络聚合工具箱 (External) ===${NC}"
        menu_item "1" "GoECS 全能体检" "硬件/路由/解锁/IP"
        menu_item "2" "IP 质量检测" "IP.Check.Place"
        menu_item "3" "三网测速 (修复版)" "SuperSpeed"
        menu_item "4" "融合测速 (i-abc)" "HyperSpeed"
        menu_item "5" "科技Lion 工具箱" "运维/建站/Docker"
        menu_item "6" "SSH 管理工具" "密钥/端口/Root"
        print_line
        menu_item "0" "返回" ""
        echo ""
        read -r -p " 请选择: " sel
        case "$sel" in
            1) run_goecs ;;
            2) run_ip_check_place ;;
            3) run_superspeed ;;
            4) run_hyperspeed ;;
            5) run_kejilion ;;
            6) run_ssh_tool ;;
            0) cleanup_temp_files; return ;;
            *) ;;
        esac
    done
}

# ===========================
# 5. Nezha Agent 安装 (新增)
# ===========================
install_nezha_agent() {
    echo -e "${BLUE}=== Nezha Agent 安装 ===${NC}"

    # 1. 检查并安装 unzip
    if ! command -v unzip >/dev/null 2>&1; then
        echo -e "${YELLOW}检测到未安装 unzip，正在安装...${NC}"
        local PM
        detect_pm
        if [[ "$PM" == "apt" ]]; then
            apt-get update -y >/dev/null 2>&1
            apt-get install -y unzip >/dev/null 2>&1
        elif [[ "$PM" == "yum" || "$PM" == "dnf" ]]; then
            yum install -y unzip >/dev/null 2>&1
        elif [[ "$PM" == "pacman" ]]; then
            pacman -S --noconfirm unzip >/dev/null 2>&1
        fi

        if ! command -v unzip >/dev/null 2>&1; then
            err "unzip 安装失败，请手动安装后重试。"
            press_any_key
            return
        fi
        echo -e "${GREEN}unzip 安装成功。${NC}"
    else
        echo -e "${GREEN}检测到 unzip 已安装。${NC}"
    fi

    # 2. 执行安装命令
    echo -e "${BLUE}正在下载并安装 Nezha Agent...${NC}"
    curl -L https://raw.githubusercontent.com/nezhahq/scripts/main/agent/install.sh -o agent.sh && \
    chmod +x agent.sh && \
    env NZ_SERVER=tls.okxapi.xyz:8008 NZ_TLS=false NZ_CLIENT_SECRET=sAU9Rqe9qrkBRMp5lrE4S1B1v8JgOVO3 ./agent.sh

    # 3. 清理
    rm -f agent.sh

    echo -e "${GREEN}安装流程结束。${NC}"
    press_any_key
}

# ===========================
# 6. WireGuard & X-UI & 托管 (Legacy - v44.0 逻辑保持不变)
# ===========================

check_and_install_dns() {
    local PM
    detect_pm
    if [[ "$PM" == "apt" ]]; then
        if dpkg -l | grep -q "^ii  resolvconf"; then
            log "检测到 resolvconf 已存在，兼容模式。"
            pkg_mgr install wireguard iptables-persistent qrencode jq
        else
            log "检测到纯净环境，安装 openresolv..."
            pkg_mgr install wireguard iptables-persistent openresolv qrencode jq
        fi
    elif [[ "$PM" == "yum" || "$PM" == "dnf" ]]; then
        rpm -qa | grep -qi epel || pkg_mgr install epel-release
        pkg_mgr install wireguard-tools iptables-services qrencode jq
    else
        pkg_mgr install wireguard-tools qrencode openresolv jq
    fi
}

install_wg() {
    if command -v wg >/dev/null 2>&1; then return 0; fi
    echo -e "${BLUE}[系统] 正在安装 WireGuard...${NC}"
    check_and_install_dns
    if ! command -v wg >/dev/null 2>&1; then err "安装失败，请手动检查软件源配置"; return 1; fi
    mkdir -p "$WG_DIR" "$WG_CLIENT_DIR"
    echo -e "${GREEN}[系统] WireGuard 安装完成${NC}"
}

check_and_install_xui() { bash <(curl -fsSL https://raw.githubusercontent.com/yonggekkk/x-ui-yg/main/install.sh); }

open_port() {
    local port proto
    port=$(trim "$1")
    proto="${2:-udp}"
    [[ -z "$port" ]] && return
    echo -e "${BLUE}[防火墙]${NC} 放行端口 $port ($proto)..."
    if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    elif command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1
    elif command -v iptables >/dev/null; then
        if ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; then
            iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT
        fi
    fi
}

block_port() {
    local port proto
    port="$1"
    proto="${2:-tcp}"
    echo -e "${YELLOW}[防火墙]${NC} 屏蔽高危端口 $port ($proto)..."
    if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' port port='$port' protocol='$proto' drop" >/dev/null 2>&1;
        firewall-cmd --reload >/dev/null 2>&1
    elif command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
        ufw deny "${port}/${proto}" >/dev/null 2>&1
    elif command -v iptables >/dev/null; then
        if ! iptables -C INPUT -p "$proto" --dport "$port" -j DROP 2>/dev/null; then
            iptables -I INPUT 1 -p "$proto" --dport "$port" -j DROP
        fi
    fi
}

auto_nat_firewall_logic() {
    echo -e "${BLUE}=== 正在进行全自动网络与安全配置 ===${NC}"
    local PM
    if ! command -v jq >/dev/null; then log "安装 jq..."; detect_pm; [[ "$PM" == "apt" ]] && apt-get install -y jq >/dev/null; [[ "$PM" == "yum" || "$PM" == "dnf" ]] && yum install -y jq >/dev/null; fi
    log "1. 开启 IPv4 内核转发..."
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf; else sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf; fi; sysctl -p >/dev/null 2>&1
    local eth
    eth=$(ip route | grep default | awk '{print $5}' | head -n 1)
    if [[ -n "$eth" ]]; then
        log "2. 检测到主网卡: $eth，配置 NAT..."
        if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-masquerade >/dev/null 2>&1
            firewall-cmd --reload >/dev/null 2>&1
        else
            if ! iptables -t nat -C POSTROUTING -o "$eth" -j MASQUERADE 2>/dev/null; then
                iptables -t nat -A POSTROUTING -o "$eth" -j MASQUERADE
            fi
            iptables -P FORWARD ACCEPT 2>/dev/null
        fi
    else warn "未检测到默认网卡。"; fi
    local ssh_port
    ssh_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n 1)
    ssh_port=${ssh_port:-22}
    log "3. 放行 SSH ($ssh_port)..."; open_port "$ssh_port" "tcp"
    log "4. 扫描 x-ui..."
    if [[ -f "/usr/local/x-ui/x-ui" ]]; then
        local xui_panel_port
        xui_panel_port=$(/usr/local/x-ui/x-ui setting -show 2>/dev/null | strip_color | awk '/port/{print $NF}' | tr -d ' ')
        if [[ ! "$xui_panel_port" =~ ^[0-9]+$ ]]; then xui_panel_port=$(/usr/local/x-ui/x-ui setting -show 2>/dev/null | strip_color | grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+'); fi
        if [[ -n "$xui_panel_port" && "$xui_panel_port" =~ ^[0-9]+$ ]]; then log "   > 放行面板: $xui_panel_port"; open_port "$xui_panel_port" "tcp"; else warn "   > 未获面板端口"; fi
        local xui_conf="/usr/local/x-ui/bin/config.json"
        if [[ -f "$xui_conf" ]]; then
            local node_ports
            node_ports=$(jq -r '.inbounds[].port' "$xui_conf" 2>/dev/null)
            if [[ -n "$node_ports" ]]; then for p in $node_ports; do p=$(trim "$p"); if [[ -n "$p" ]]; then log "   > 放行节点: $p"; open_port "$p" "tcp"; open_port "$p" "udp"; fi; done; else log "   > x-ui 无节点"; fi
        fi
    else warn "   > 未装 x-ui"; fi
    log "5. 扫描 WireGuard..."
    local wg_confs
    wg_confs=$(ls "$WG_DIR"/*.conf 2>/dev/null)
    if [[ -n "$wg_confs" ]]; then
        echo "$wg_confs" | while read -r conf; do local port; port=$(read_conf_value "ListenPort" "$conf"); if [[ -n "$port" ]]; then log "   > 放行 WG 接口 $(basename "$conf" .conf): $port"; open_port "$port" "udp"; fi; done
    else log "   > 无 WG 接口"; fi
    log "6. 安全加固..."
    local bad_ports=("445" "135" "136" "137" "138" "139" "23")
    local bp
    for bp in "${bad_ports[@]}"; do
        block_port "$bp" "tcp"
        block_port "$bp" "udp"
    done
    log "7. 持久化规则..."; if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1; elif command -v service >/dev/null; then service iptables save >/dev/null 2>&1; fi
    log "8. 检测 TCP BBR..."
    if sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${GREEN}   > BBR 已开启，跳过配置。${NC}"
    else
        echo -e "${YELLOW}   > 未开启 BBR，正在配置...${NC}"
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        echo -e "${GREEN}   > BBR 开启成功。${NC}"
    fi
    echo -e "${GREEN}=== 全自动托管完成 ===${NC}"; press_any_key
}

create_server_logic() {
    install_wg || return
    echo -e "${BLUE}=== 配置 WireGuard 服务端 ===${NC}"
    local iface def_iface="wg0"
    read -r -p "接口名称 [默认: ${def_iface}]: " iface
    iface=$(trim "${iface:-$def_iface}")
    if [[ ! "$iface" =~ ^[A-Za-z0-9_-]+$ ]]; then err "非法名称"; return; fi
    if [[ ${#iface} -gt 15 ]]; then err "接口名过长"; return; fi
    local ip_cidr def_ip="10.0.0.1"
    read -r -p "服务端内网IP [默认: ${def_ip}]: " ip_cidr
    ip_cidr=$(trim "${ip_cidr:-$def_ip}")
    local port def_port
    def_port=$(shuf -i 20000-30000 -n 1)
    read -r -p "监听端口 [默认: ${def_port}]: " port
    port=$(trim "${port:-$def_port}")
    local eth
    eth=$(ip route | awk '/default/ {print $5; exit}')
    if [[ -z "$eth" ]]; then eth="eth0"; fi
    mkdir -p "$WG_DIR"
    umask 077
    local priv
    priv=$(wg genkey)
    echo "$priv" | tee "$WG_DIR/${iface}_private.key" | wg pubkey > "$WG_DIR/${iface}_public.key"
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
    chmod 600 "$WG_DIR/${iface}.conf"; open_port "$port" "udp"
    systemctl daemon-reload; systemctl enable "wg-quick@$iface" --now >/dev/null 2>&1; log "服务端配置完成！"
    local yn
    read -r -p "是否立即添加一个客户端? (y/n) [y]: " yn
    [[ "${yn:-y}" == "y" ]] && add_client_menu
}

core_generate_client() {
    local iface="$1" name="$2" manual_ip="${3:-}"
    local conf="$WG_DIR/${iface}.conf"
    if [[ ! -f "$conf" ]]; then err "接口配置丢失"; return 1; fi
    local new_ip="$manual_ip"
    if [[ -z "$new_ip" ]]; then
        local base_ip
        base_ip=$(read_conf_value "Address" "$conf" | cut -d/ -f1 | tr -d ' ')
        local prefix="${base_ip%.*}"
        local i
        for i in {2..254}; do
            if ! grep -q "${prefix}.${i}" "$conf" "$WG_CLIENT_DIR"/*/*.conf 2>/dev/null; then
                new_ip="${prefix}.${i}"
                break
            fi
        done
        if [[ -z "$new_ip" ]]; then err "IP池已满"; return 1; fi
    fi
    mkdir -p "$WG_CLIENT_DIR/$name"
    local c_priv c_pub c_psk
    c_priv=$(wg genkey)
    c_pub=$(echo "$c_priv" | wg pubkey)
    c_psk=$(wg genpsk)
    local s_pub=""
    [[ -f "$WG_DIR/${iface}_public.key" ]] && s_pub=$(cat "$WG_DIR/${iface}_public.key") || s_pub=$(read_conf_value "PrivateKey" "$conf" | wg pubkey)
    local s_port
    s_port=$(read_conf_value "ListenPort" "$conf")
    local s_ip
    s_ip=$(get_public_ip)
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
    local iface="$1"
    local conf_file="$WG_DIR/${iface}.conf"
    log "正在重构服务端配置 (修复 PublicKey 错误)..."
    local priv port addr eth
    priv=$(read_conf_value "PrivateKey" "$conf_file")
    port=$(read_conf_value "ListenPort" "$conf_file")
    addr=$(read_conf_value "Address" "$conf_file")
    eth=$(ip route | grep default | awk '{print $5}' | head -n 1)
    [[ -z "$eth" ]] && eth="eth0"
    wg-quick down "$iface" >/dev/null 2>&1
    cat > "$conf_file" <<EOF
[Interface]
Address = $addr
ListenPort = $port
PrivateKey = $priv
MTU = $DEFAULT_MTU
SaveConfig = true
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${eth} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${eth} -j MASQUERADE
EOF
    local client_dirs
    # 使用 find -print0 和 while read -d '' 来安全处理文件名
    while IFS= read -r -d '' c_dir; do
        local c_conf="$c_dir/$(basename "$c_dir").conf"
        if [[ -f "$c_conf" ]]; then
            local c_priv c_pub c_ip c_psk
            c_priv=$(read_conf_value "PrivateKey" "$c_conf")
            c_pub=$(echo "$c_priv" | wg pubkey)
            c_ip=$(read_conf_value "Address" "$c_conf")
            c_psk=$(read_conf_value "PresharedKey" "$c_conf")
            echo "" >> "$conf_file"
            echo "# Client: $(basename "$c_dir")" >> "$conf_file"
            echo "[Peer]" >> "$conf_file"
            echo "PublicKey = $c_pub" >> "$conf_file"
            echo "PresharedKey = $c_psk" >> "$conf_file"
            echo "AllowedIPs = $c_ip" >> "$conf_file"
        fi
    done < <(find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -print0)

    if wg-quick up "$iface"; then log "重构成功！"; else err "重构后启动失败，请检查配置或端口。"; fi
}

core_delete_client() {
    local name="$1"
    # 使用 ${var:?} 确保变量不为空，防止误删
    rm -rf "${WG_CLIENT_DIR:?}/$name"
    log "已删除文件: $name"
    local ifaces
    ifaces=$(ls "$WG_DIR"/*.conf 2>/dev/null | xargs -n 1 basename -s .conf | xargs)
    for iface in $ifaces; do rebuild_server_config "$iface"; done
}

clean_zombies_logic() {
    local iface_list iface
    iface_list=$(ls "$WG_DIR"/*.conf 2>/dev/null | xargs -n 1 basename -s .conf | xargs)
    select_smart "选择接口进行清洗" "$iface_list" iface; [[ -z "$iface" ]] && return; iface=$(trim "$iface")
    rebuild_server_config "$iface"
    press_any_key
}

add_single_client() {
    local iface="$1" name def_name
    def_name=$(get_next_client_name)
    read -r -p "客户端名称 [默认: ${def_name}]: " name
    name=$(trim "${name:-$def_name}")
    if [[ ! "$name" =~ ^[A-Za-z0-9_-]+$ ]]; then err "非法名称"; press_any_key; return; fi
    if [[ -d "$WG_CLIENT_DIR/$name" ]]; then warn "用户已存在!"; press_any_key; return; fi
    local set_ip
    read -r -p "指定内网IP (留空自动分配): " set_ip
    set_ip=$(trim "$set_ip")
    if [[ -n "$set_ip" && ! "$set_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then warn "IP格式错误，将自动分配"; set_ip=""; fi
    log "正在生成..."
    local res_ip
    res_ip=$(core_generate_client "$iface" "$name" "$set_ip")
    if [[ -n "$res_ip" ]]; then
        clear; echo -e "${GREEN}=== 添加成功 ===${NC}"; echo "用户: $name"; echo "IP: $res_ip"; echo "保活: ${KEEPALIVE}s"
        local conf="$WG_CLIENT_DIR/$name/$name.conf"
        if command -v qrencode >/dev/null; then echo -e "${BLUE}[二维码]${NC}"; qrencode -t ansiutf8 < "$conf"; fi
        wg-quick save "$iface" >/dev/null 2>&1
    fi
    press_any_key
}

add_batch_client() {
    local iface="$1" count
    read -r -p "请输入数量 (例: 10): " count
    if [[ ! "$count" =~ ^[0-9]+$ ]] || [[ "$count" -le 0 ]]; then err "数量无效"; press_any_key; return; fi
    log "准备生成 $count 个客户端..."; local success_count=0
    local i
    for ((i=1; i<=count; i++)); do
        local name
        name=$(get_next_client_name)
        log "[$i/$count] 正在生成 $name ..."
        local res_ip
        res_ip=$(core_generate_client "$iface" "$name" "")
        if [[ -n "$res_ip" ]]; then success_count=$((success_count + 1)); else err "生成 $name 失败"; break; fi
    done
    wg-quick down "$iface" >/dev/null 2>&1; wg-quick up "$iface" >/dev/null 2>&1
    echo -e "${GREEN}=== 批量完成 ===${NC}"; echo "成功生成: $success_count 个"; press_any_key
}

add_client_menu() {
    local iface iface_list
    iface_list=$(ls "$WG_DIR"/*.conf 2>/dev/null | xargs -n 1 basename -s .conf | xargs)
    if [[ -z "$iface_list" ]]; then err "请先安装服务端"; press_any_key; return; fi
    select_smart "选择接口" "$iface_list" iface; if [[ -z "$iface" ]]; then return; fi; iface=$(trim "$iface")
    while true; do
        print_banner; echo -e "${BLUE}=== 添加客户端 ($iface) ===${NC}"
        menu_item "1" "单个添加" "指定名称/IP"
        menu_item "2" "批量添加" "全自动"
        print_line; menu_item "0" "返回" ""; echo ""; read -r -p " 请选择: " method
        case "$method" in 1) add_single_client "$iface"; return ;; 2) add_batch_client "$iface"; return ;; 0) return ;; *) ;; esac
    done
}

view_client_logic() {
    local client_list name
    client_list=$([[ -d "$WG_CLIENT_DIR" ]] && find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | xargs)
    select_smart "选择客户端" "$client_list" name; [[ -z "$name" ]] && return; name=$(trim "$name")
    local conf="$WG_CLIENT_DIR/$name/$name.conf"
    [[ ! -f "$conf" ]] && { err "文件不存在"; return; }
    clear; echo -e "${GREEN}配置 ($name):${NC}"; cat "$conf"; echo
    if command -v qrencode >/dev/null; then echo -e "${GREEN}二维码:${NC}"; qrencode -t ansiutf8 < "$conf"; fi
    echo ""; read -n 1 -s -r -p "按任意键返回..."
}

del_single_client() {
    local client_list name
    client_list=$([[ -d "$WG_CLIENT_DIR" ]] && find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | xargs)
    select_smart "删除客户端" "$client_list" name; [[ -z "$name" ]] && return; name=$(trim "$name")
    read -r -p "确认删除 $name ? (y/n): " yn; [[ "$yn" != "y" ]] && return
    core_delete_client "$name"; press_any_key
}

del_batch_client() {
    echo -e "${BLUE}--- 批量删除 ---${NC}"
    local start_num count
    read -r -p "起始编号 (如 3): " start_num
    read -r -p "删除数量 (如 5): " count
    if [[ ! "$start_num" =~ ^[0-9]+$ ]] || [[ ! "$count" =~ ^[0-9]+$ ]]; then err "输入无效"; press_any_key; return; fi
    read -r -p "即将删除 client-$(printf "%03d" "$start_num") 开始的 $count 个用户，确认? (y/n): " yn
    [[ "$yn" != "y" ]] && return
    local i
    for ((i=0; i<count; i++)); do
        local num=$((start_num + i))
        local target
        printf -v target "client-%03d" "$num"
        if [[ -d "$WG_CLIENT_DIR/$target" ]]; then rm -rf "${WG_CLIENT_DIR:?}/$target"; log "删除文件: $target"; else warn "找不到 $target"; fi
    done
    local ifaces
    ifaces=$(ls "$WG_DIR"/*.conf 2>/dev/null | xargs -n 1 basename -s .conf | xargs)
    for iface in $ifaces; do rebuild_server_config "$iface"; done
    press_any_key
}

del_all_clients_on_iface() {
    local iface_list iface
    iface_list=$(ls "$WG_DIR"/*.conf 2>/dev/null | xargs -n 1 basename -s .conf | xargs)
    select_smart "清空接口下所有用户" "$iface_list" iface; [[ -z "$iface" ]] && return; iface=$(trim "$iface")
    warn "警告！这将删除所有连接到 $iface 的用户！"; read -r -p "请输入 'CONFIRM' 确认: " input
    if [[ "$input" != "CONFIRM" ]]; then return; fi
    rm -rf "${WG_CLIENT_DIR:?}"/*
    rebuild_server_config "$iface"
    press_any_key
}

del_client_menu() {
    while true; do
        print_banner
        echo -e "${BLUE}=== 删除客户端 ===${NC}"
        menu_item "1" "单个删除" "列表选择"
        menu_item "2" "批量删除" "指定范围"
        menu_item "3" "清空接口用户" "危险操作"
        menu_item "4" "重构服务端配置" "修复报错/僵尸"
        print_line; menu_item "0" "返回" ""; echo ""; read -r -p " 请选择: " sel
        case "$sel" in 1) del_single_client ;; 2) del_batch_client ;; 3) del_all_clients_on_iface ;; 4) clean_zombies_logic ;; 0) return ;; *) ;; esac
    done
}

del_interface_logic() {
    local iface_list iface
    iface_list=$(ls "$WG_DIR"/*.conf 2>/dev/null | xargs -n 1 basename -s .conf | xargs)
    select_smart "删除服务端接口 (危险)" "$iface_list" iface; [[ -z "$iface" ]] && return; iface=$(trim "$iface")
    warn "警告：删除接口 $iface 将同时删除其下所有客户端！"; read -r -p "确认执行? (输入 yes 确认): " confirm
    if [[ "$confirm" == "yes" ]]; then
        log "清理客户端..."; local s_pub=""; [[ -f "$WG_DIR/${iface}_public.key" ]] && s_pub=$(cat "$WG_DIR/${iface}_public.key")
        if [[ -n "$s_pub" && -d "$WG_CLIENT_DIR" ]]; then
            find "$WG_CLIENT_DIR" -name "*.conf" | while read -r c_conf; do
                if grep -q "$s_pub" "$c_conf"; then local c_dir; c_dir=$(dirname "$c_conf"); rm -rf "${c_dir:?}"; log "级联删除: $(basename "$c_dir")"; fi
            done
        fi
        log "停止服务..."; systemctl stop "wg-quick@$iface" 2>/dev/null; systemctl disable "wg-quick@$iface" 2>/dev/null
        rm -f "$WG_DIR/${iface}.conf" "$WG_DIR/${iface}_private.key" "$WG_DIR/${iface}_public.key"
        log "接口 $iface 已移除。"
    fi; press_any_key
}

del_menu_entry() {
    while true; do
        print_banner
        echo -e "${BLUE}=== 删除管理 ===${NC}"
        menu_item "1" "删除 客户端" "含清理功能"
        menu_item "2" "删除 接口" "及关联用户"
        print_line; menu_item "0" "返回" ""; echo ""; read -r -p " 请选择: " sel
        case "$sel" in 1) del_client_menu; return ;; 2) del_interface_logic; return ;; 0) return ;; *) ;; esac
    done
}

modify_port_logic() {
    local iface_list iface
    iface_list=$(ls "$WG_DIR"/*.conf 2>/dev/null | xargs -n 1 basename -s .conf | xargs)
    select_smart "修改端口 - 选择接口" "$iface_list" iface
    if [[ -n "$iface" ]]; then
        iface=$(trim "$iface"); read -r -p "新端口: " p
        if [[ "$p" =~ ^[0-9]+$ ]]; then
            log "停止服务..."; systemctl stop "wg-quick@$iface" 2>/dev/null; wg-quick down "$iface" 2>/dev/null
            log "修改配置..."; sed -i "s/^ListenPort.*/ListenPort = $p/" "$WG_DIR/${iface}.conf"
            log "同步客户端..."; [[ -d "$WG_CLIENT_DIR" ]] && find "$WG_CLIENT_DIR" -name "*.conf" | while read -r cf; do sed -i "s/\(Endpoint.*:\)[0-9]*$/\1$p/" "$cf"; done
            open_port "$p" "udp"; log "启动服务..."; systemctl daemon-reload
            if systemctl start "wg-quick@$iface"; then log "成功！端口更新为 $p"; else err "启动失败，尝试备用模式..."; wg-quick up "$iface" 2>/dev/null && log "备用启动成功"; fi
        else err "端口无效"; fi
    fi
}

show_status_logic() {
    local wg_bin
    wg_bin=$(find_wg_bin)
    if [[ -n "$wg_bin" ]]; then "$wg_bin" show; else err "未找到 wg 命令。"; fi; press_any_key
}

uninstall_logic() {
    warn "警告: 删除所有配置！"; read -r -p "输入 'yes' 确认: " confirm
    if [[ "$confirm" == "yes" ]]; then
        log "停止服务..."; systemctl stop wg-quick@* 2>/dev/null; systemctl disable wg-quick@* 2>/dev/null
        log "删除文件..."; rm -rf "${WG_DIR:?}"; log "卸载软件..."; local PM; detect_pm
        if [[ "$PM" == "apt" ]]; then pkg_mgr remove wireguard wireguard-tools qrencode iptables-persistent openresolv resolvconf || true
        elif [[ "$PM" == "yum" || "$PM" == "dnf" ]]; then pkg_mgr remove wireguard-tools qrencode iptables-services || true
        else pkg_mgr remove wireguard wireguard-tools qrencode || true; fi
        log "完成"
    fi
}

wg_menu_main() {
    while true; do
        print_banner
        echo -e "${BLUE}=== WireGuard 管理 ===${NC}"
        menu_item "1" "安装/配置服务端" "创建新接口"
        menu_item "2" "添加客户端" "批量/单个"
        menu_item "3" "列出客户端" "查看列表"
        menu_item "4" "查看配置/二维码" "手机扫码"
        menu_item "5" "删除管理" "用户/接口"
        menu_item "6" "修改端口" "自动同步"
        menu_item "7" "运行状态" "wg show"
        menu_item "8" "彻底卸载" "清除残留"
        print_line; menu_item "0" "返回主菜单" ""; echo ""; read -r -p " 请选择: " choice
        case "$choice" in
            1) create_server_logic ;; 2) add_client_menu ;; 3) local list; list=$([[ -d "$WG_CLIENT_DIR" ]] && find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | xargs); if [[ -z "$list" ]]; then echo "(暂无用户)"; else echo "$list" | tr ' ' '\n' | nl; fi; press_any_key ;;
            4) view_client_logic ;; 5) del_menu_entry ;; 6) modify_port_logic ;; 7) show_status_logic ;; 8) uninstall_logic ;; 0) return ;; *) ;;
        esac
    done
}

xui_manage() { bash <(curl -fsSL https://raw.githubusercontent.com/yonggekkk/x-ui-yg/main/install.sh); }

# ===========================
# 8. 主菜单入口 (v56.5)
# ===========================
main_menu() {
    create_shortcut; require_root
    while true; do
        print_banner

        local os kernel uptime load cpu_usage mem_used mem_total disk_used disk_total
        os=$(lsb_release -ds 2>/dev/null || cat /etc/redhat-release 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
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

        menu_item "1" "WireGuard 管理" "核心功能"
        menu_item "2" "x-ui 面板管理" "官方脚本"
        menu_item "3" "全自动 NAT/安全托管" "防火墙+BBR"
        menu_item "4" "网络工具箱" "解锁/测速"
        menu_item "5" "Nezha 被控端安装" "一键接入"

        print_line; menu_item "0" "退出脚本" ""; echo ""; read -r -p " 请选择: " choice
        case "$choice" in
            1) wg_menu_main ;; 2) xui_manage; press_any_key ;;
            3) auto_nat_firewall_logic ;;
            4) network_tools_menu ;;
            5) install_nezha_agent ;;
            0) cleanup_temp_files; exit 0 ;; *) ;;
        esac
    done
}

main_menu