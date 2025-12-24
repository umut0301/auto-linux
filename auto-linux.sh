#!/usr/bin/env bash
#
# auto-linux.sh (v34.0 终极完整版)
# 恢复：完整恢复 v32.0 的所有 WireGuard 核心逻辑 (批量/删除/配置)
# 保持：v32.0 的 UI 风格 (UMUT Logo / 对齐 / 配色)
# 新增：网络工具箱中集成 IP体检(净化) 和 整合测速(官方二进制)
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
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; WHITE='\033[1;37m'; NC='\033[0m'
BOLD='\033[1m'

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

strip_color() { sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g"; }

create_shortcut() {
    if [[ ! -f /usr/bin/ws ]]; then
        ln -sf "$0" /usr/bin/ws
        chmod +x /usr/bin/ws
    fi
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
    echo -e " ${PURPLE}项目地址:${NC} github.com/umut0301   ${PURPLE}快捷命令:${NC} ws   ${PURPLE}版本:${NC} v34.0"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
}

print_line() {
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
}

# 绝对对齐菜单项
menu_item() {
    local num="$1"
    local text="$2"
    local tag="${3:-}"
    # 前半部分
    echo -ne " ${CYAN}[${GREEN}${num}${CYAN}]${NC} ${text}"
    # ANSI 绝对定位到第 42 列打印注释
    echo -e "\033[42G ${PURPLE}${tag}${NC}"
}

# ===========================
# 3. 核心模块 (状态/信息)
# ===========================
rand_suffix() { tr -dc 'a-z0-9' </dev/urandom | head -c 6; }
rand_iface() { echo "wg$(tr -dc '0-9' </dev/urandom | head -c 3)"; }
rand_port() { echo "$(( (RANDOM % 10000) + 20000 ))"; }

get_next_client_name() {
    local i=1
    local name
    while true; do
        printf -v name "client-%03d" "$i"
        if [[ ! -d "$WG_CLIENT_DIR/$name" ]]; then echo "$name"; return; fi
        ((i++))
    done
}

find_wg_bin() {
    if command -v wg >/dev/null 2>&1; then command -v wg; return; fi
    local paths=("/usr/bin/wg" "/usr/sbin/wg" "/usr/local/bin/wg" "/usr/local/sbin/wg")
    for p in "${paths[@]}"; do if [[ -x "$p" ]]; then echo "$p"; return; fi; done
    find /usr -name "wg" -type f -executable 2>/dev/null | head -n 1
}

get_public_ip() {
    local ip
    ip=$(curl -s4m 3 https://api.ipify.org) || ip=$(ip route get 1.1.1.1 | awk '{print $7}')
    echo "${ip:-127.0.0.1}"
}

# 状态检测
get_wg_status_text() {
    if command -v wg >/dev/null 2>&1 && [[ -n $(wg show 2>/dev/null) ]]; then echo -e "${GREEN}运行中${NC}"; else echo -e "${RED}停止${NC}"; fi
}
get_wg_enable_text() {
    if systemctl list-unit-files | grep -q "wg-quick@.*enabled"; then echo -e "${GREEN}是${NC}"; else echo -e "${RED}否${NC}"; fi
}
get_wg_version_text() {
    if command -v wg >/dev/null 2>&1; then wg --version | head -n1 | awk '{print $2}'; else echo "N/A"; fi
}
get_xui_status_text() {
    if systemctl is-active x-ui >/dev/null 2>&1; then echo -e "${GREEN}运行中${NC}"; else echo -e "${RED}停止${NC}"; fi
}
get_xui_enable_text() {
    if systemctl is-enabled x-ui >/dev/null 2>&1; then echo -e "${GREEN}是${NC}"; else echo -e "${RED}否${NC}"; fi
}
get_xui_version_text() {
    if [[ -f /usr/local/x-ui/v ]]; then cat /usr/local/x-ui/v; else echo "N/A"; fi
}

get_virt_type() {
    if command -v systemd-detect-virt >/dev/null 2>&1; then systemd-detect-virt
    elif command -v virt-what >/dev/null 2>&1; then virt-what | head -n 1
    else echo "Unknown"; fi
}

get_ip_info() {
    echo -e "${CYAN}正在获取网络信息...${NC}"
    local v4 v6 v4_loc v6_loc
    v4=$(curl -s4m 3 https://api.ipify.org); [[ -z "$v4" ]] && v4="无 IPv4"
    if [[ "$v4" != "无 IPv4" ]]; then v4_loc=$(curl -s4m 3 "http://ip-api.com/json/$v4?lang=zh-CN" | jq -r '"\(.country) - \(.regionName) - \(.isp)"' 2>/dev/null); else v4_loc="-"; fi
    v6=$(curl -s6m 3 https://api64.ipify.org); [[ -z "$v6" ]] && v6="无 IPv6"
    if [[ "$v6" != "无 IPv6" ]]; then v6_loc=$(curl -s6m 3 "http://ip-api.com/json/$v6?lang=zh-CN" | jq -r '"\(.country) - \(.regionName) - \(.isp)"' 2>/dev/null); else v6_loc="-"; fi
    echo -e " IPv4: ${GREEN}$v4${NC} ($v4_loc)"
    echo -e " IPv6: ${GREEN}$v6${NC} ($v6_loc)"
}

show_full_sys_info() {
    clear; echo -e "${BLUE}=== 系统详细信息 ===${NC}"
    local os=$(lsb_release -ds 2>/dev/null || cat /etc/redhat-release 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
    local kernel=$(uname -r); local virt=$(get_virt_type); local uptime=$(uptime -p)
    local cpu_model=$(grep 'model name' /proc/cpuinfo | head -n1 | cut -d: -f2 | xargs)
    local cpu_cores=$(grep 'processor' /proc/cpuinfo | wc -l)
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    local mem_total=$(free -m | awk '/Mem:/ {print $2}'); local mem_used=$(free -m | awk '/Mem:/ {print $3}')
    local mem_rate=$(awk "BEGIN {printf \"%.1f\", $mem_used / $mem_total * 100}")
    local disk_total=$(df -h / | awk 'NR==2 {print $2}'); local disk_used=$(df -h / | awk 'NR==2 {print $3}')
    local disk_rate=$(df -h / | awk 'NR==2 {print $5}')
    echo -e " 系统: ${CYAN}$os${NC} | 内核: ${CYAN}$kernel${NC} | 架构: ${CYAN}$virt${NC}"
    echo -e " CPU : ${CYAN}$cpu_model${NC} (${cpu_cores}核) | 占用: ${PURPLE}${cpu_usage}%${NC}"
    echo -e " 内存: ${PURPLE}${mem_used}MB / ${mem_total}MB (${mem_rate}%)${NC} | 硬盘: ${PURPLE}${disk_used} / ${disk_total} (${disk_rate})${NC}"
    print_line
    get_ip_info
    press_any_key
}

# ===========================
# 4. 新增功能 (测速 & IP体检)
# ===========================

# --- A. 整合测速 (Ookla C++ Binary) ---
install_speedtest() {
    if [ ! -e "./speedtest-cli" ] && [ ! -e "./speedtest" ]; then
        echo -e "${CYAN}正在下载 Speedtest 官方客户端...${NC}"
        local arch=$(uname -m)
        local url=""
        if [[ $arch == "x86_64" ]]; then
            url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
        elif [[ $arch == "aarch64" ]]; then
            url="https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-aarch64.tgz"
        else
            err "不支持的架构: $arch"; return 1
        fi
        if curl -sL "$url" | tar xz speedtest 2>/dev/null; then
            chmod +x speedtest
        else
            err "下载失败"
            return 1
        fi
    fi
}

run_integrated_speedtest() {
    clear
    echo -e "${BLUE}=== 三网测速整合版 (Ookla Core) ===${NC}"
    install_speedtest
    if [ ! -e "./speedtest" ]; then err "Speedtest 未找到"; press_any_key; return; fi

    echo -e "正在进行测速，请稍候..."
    print_line
    printf "%-10s %-10s %-12s %-12s %-10s\n" "运营商" "位置" "下载(Mbps)" "上传(Mbps)" "延迟(ms)"
    print_line

    # 精选节点 (整合自 cesu1/cesu2)
    local nodes=(
        "3633  电信-上海 ChinaTelecom"
        "29071 电信-成都 ChinaTelecom"
        "27594 电信-广州 ChinaTelecom"
        "24447 联通-上海 ChinaUnicom"
        "4870  联通-长沙 ChinaUnicom"
        "17145 联通-合肥 ChinaUnicom"
        "25637 移动-上海 ChinaMobile"
        "16375 移动-吉林 ChinaMobile"
    )

    for node_info in "${nodes[@]}"; do
        local id=$(echo "$node_info" | awk '{print $1}')
        local name=$(echo "$node_info" | awk '{print $2}')
        
        local result
        result=$(./speedtest --accept-license --accept-gdpr --server "$id" --format=json 2>/dev/null)
        
        if [[ -n "$result" ]] && [[ $(echo "$result" | jq -r '.type' 2>/dev/null) == "result" ]]; then
            local dl=$(echo "$result" | jq -r '.download.bandwidth' | awk '{printf "%.2f", $1/125000}')
            local ul=$(echo "$result" | jq -r '.upload.bandwidth' | awk '{printf "%.2f", $1/125000}')
            local ping=$(echo "$result" | jq -r '.ping.latency' | awk '{printf "%.2f", $1}')
            
            local color=$NC
            [[ "$name" == *"电信"* ]] && color=$GREEN
            [[ "$name" == *"联通"* ]] && color=$PURPLE
            [[ "$name" == *"移动"* ]] && color=$BLUE
            
            printf "${color}%-10s${NC} %-12s %-12s %-12s %-10s\n" "${name%%-*}" "${name##*-}" "$dl" "$ul" "$ping"
        fi
    done
    print_line
    rm -f speedtest speedtest.1 speedtest.md
    press_any_key
}

# --- B. IP 质量体检 (净化版) ---
run_fusion_monster_clean() {
    clear
    echo -e "${BLUE}=== IP 质量体检 (融合怪净化版) ===${NC}"
    echo -e "正在加载检测脚本..."
    print_line
    
    # 管道过滤：去除广告、版本号、项目地址等冗余信息
    bash <(curl -sL https://raw.githubusercontent.com/xykt/IPQuality/main/ip.sh) | \
    grep -vE "版本|项目|频道|官方|感谢|时间|运行|测试|Bitwarden|Email|IP类型" | \
    sed '/^$/d'
    
    print_line
    echo -e "检测完成。"
    press_any_key
}

# ===========================
# 5. 本地化流媒体检测 (v32 逻辑)
# ===========================
check_http_code() {
    local name="$1"; local url="$2"; local expect="$3"
    printf " %-13s: " "$name" 
    local code
    code=$(curl -s4m 5 -o /dev/null -w "%{http_code}" -L "$url" --user-agent "Mozilla/5.0")
    if [[ "$code" == "$expect" ]]; then echo -e "${GREEN}Yes (解锁)${NC}";
    elif [[ "$code" == "403" ]]; then echo -e "${RED}No (403 Forbidden)${NC}";
    elif [[ "$code" == "404" ]]; then echo -e "${RED}No (404 Not Found)${NC}";
    elif [[ "$code" == "000" ]]; then echo -e "${RED}No (Timeout)${NC}";
    else echo -e "${RED}No (Code: $code)${NC}"; fi
}

check_global_tools() {
    echo -e "${BLUE}--- 全球平台 & 工具 ---${NC}"
    printf " %-13s: " "ChatGPT"; local gpt=$(curl -s4m 5 -o /dev/null -w "%{http_code}" -L "https://chat.openai.com/" --user-agent "Mozilla/5.0"); if [[ "$gpt" == "200" ]]; then echo -e "${GREEN}Yes (网页可用)${NC}"; elif [[ "$gpt" == "403" ]]; then echo -e "${RED}No (Web Shield)${NC}"; else echo -e "${RED}No${NC}"; fi
    printf " %-13s: " "Google"; local google=$(curl -s4m 5 "https://www.google.com/ncr" -H "User-Agent: Mozilla/5.0" | grep -o 'id="footer".*</span>' | sed 's/.*location" //;s/<\/span>.*//' | tr -d '>'); if [[ -n "$google" ]]; then echo -e "${GREEN}Yes (Region: $google)${NC}"; else echo -e "${RED}Fail${NC}"; fi
    check_http_code "TikTok" "https://www.tiktok.com/" "200"
    printf " %-13s: " "Steam"; local steam=$(curl -s4m 5 "https://store.steampowered.com/app/10" | grep "priceCurrency"); if [[ -n "$steam" ]]; then local cur=$(echo "$steam" | grep -o 'content="[^"]*"' | cut -d'"' -f2); echo -e "${GREEN}Yes (Cur: $cur)${NC}"; else echo -e "${RED}No${NC}"; fi
}

check_global_media() {
    echo -e "${BLUE}--- 流媒体核心 ---${NC}"
    printf " %-13s: " "Netflix"; local nf=$(curl -4sL "https://www.netflix.com/title/81255309" -w "%{http_code}" -o /dev/null --user-agent "Mozilla/5.0"); if [[ "$nf" == "200" ]]; then echo -e "${GREEN}Yes (Full)${NC}"; elif [[ "$nf" == "404" ]]; then echo -e "${YELLOW}Only Homemade${NC}"; else echo -e "${RED}No${NC}"; fi
    printf " %-13s: " "YouTube"; local yt=$(curl -s4m 5 -L "https://www.youtube.com/red" --user-agent "Mozilla/5.0"); if echo "$yt" | grep -q "Premium is not available"; then echo -e "${YELLOW}Yes (Ads)${NC}"; else echo -e "${GREEN}Yes (Premium)${NC}"; fi
    printf " %-13s: " "Disney+"; local dp=$(curl -s4m 5 -I -L "https://www.disneyplus.com/login" | grep -i "location:" | awk '{print $2}'); if [[ "$dp" == *"begin"* ]]; then echo -e "${GREEN}Yes${NC}"; else echo -e "${RED}No${NC}"; fi
}

check_hk() { echo -e "${BLUE}--- 港区 (HK) ---${NC}"; check_http_code "Viu.com" "https://www.viu.com/ott/hk/" "200"; check_http_code "HBO GO" "https://www.hbogoasia.hk/" "200"; }
check_tw() { echo -e "${BLUE}--- 台区 (TW) ---${NC}"; check_http_code "动画疯" "https://ani.gamer.com.tw/" "200"; check_http_code "KKTV" "https://www.kktv.me/" "200"; }
check_jp() { echo -e "${BLUE}--- 日区 (JP) ---${NC}"; check_http_code "Abema" "https://abema.tv/" "200"; check_http_code "Niconico" "https://www.nicovideo.jp/" "200"; }
check_eu_us() { echo -e "${BLUE}--- 欧美 & 体育 ---${NC}"; check_http_code "HBO Max" "https://www.max.com/" "200"; check_http_code "Hulu" "https://www.hulu.com/welcome" "200"; check_http_code "BBC iPlayer" "https://www.bbc.co.uk/iplayer" "200"; }
check_asia() { echo -e "${BLUE}--- 亚洲综合 ---${NC}"; check_http_code "MeWatch" "https://www.mewatch.sg/" "200"; check_http_code "Viu (SG)" "https://www.viu.com/ott/sg/" "200"; }

media_unlock_main() {
    local region_input="$1"
    local current_region=""
    clear
    check_global_tools
    check_global_media
    if [[ "$region_input" == "auto" ]]; then
        current_region=$(curl -s4m 5 http://ip-api.com/json | jq -r '.countryCode')
        echo -e "识别地区: ${YELLOW}$current_region${NC}"
    else
        current_region="$region_input"
    fi
    case "$current_region" in
        "HK") check_hk ;; "TW") check_tw ;; "JP") check_jp ;; "SG") check_asia ;;
        "US"|"CA"|"GB"|"FR"|"DE"|"AU"|"EU_US") check_eu_us ;; "ASIA") check_asia ;;
        *) check_eu_us ;;
    esac
    press_any_key
}

network_tools_menu() {
    while true; do
        print_banner
        echo -e "${BLUE}=== 网络工具箱 ===${NC}"
        menu_item "1" "IP 质量体检" "融合怪/欺诈分"
        menu_item "2" "流媒体检测 (自动)" "地区智能识别"
        menu_item "3" "流媒体检测 (手动)" "指定地区"
        menu_item "4" "三网测速 (整合版)" "电信/联通/移动"
        print_line
        menu_item "0" "返回" ""
        echo ""
        read -rp " 请选择: " sel
        case "$sel" in
            1) run_fusion_monster_clean ;;
            2) media_unlock_main "auto" ;;
            3) 
                echo -e " 1.HK 2.TW 3.JP 4.EU/US 5.Asia"
                read -rp " Select: " r
                case "$r" in 1) media_unlock_main "HK";; 2) media_unlock_main "TW";; 3) media_unlock_main "JP";; 4) media_unlock_main "EU_US";; 5) media_unlock_main "ASIA";; *) ;; esac
                ;;
            4) run_integrated_speedtest ;;
            0) return ;; *) ;;
        esac
    done
}

# ===========================
# 6. 依赖安装与公共函数 (其他)
# ===========================
read_input() {
    local prompt="$1" default="$2" var_ref="$3" input
    if [[ -n "$default" ]]; then read -rp "${prompt} [默认: ${default}]: " input
    else read -rp "${prompt}: " input; fi
    [[ -z "$input" ]] && input="$default"
    input=$(trim "$input")
    if [[ "$var_ref" == *"ip"* && "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${BLUE}[提示] 自动补全 IP: ${input}.1${NC}"
        input="${input}.1"
    fi
    eval "$var_ref='$input'"
}

select_smart() {
    local title="$1" list_str="$2" ret_var="$3" items old_ifs="$IFS"
    IFS=' ' read -r -a items <<< "$list_str"
    IFS="$old_ifs"
    if [[ ${#items[@]} -eq 0 ]]; then echo " (无数据)"; eval "$ret_var=''"; return; fi
    echo -e "${BLUE}--- $title ---${NC}"
    local i=0
    for item in "${items[@]}"; do i=$((i+1)); echo "$i) $item"; done
    echo "------------------"
    local choice; read -rp "请输入编号或名称: " choice; choice=$(trim "$choice")
    if [[ "$choice" =~ ^[0-9]+$ && choice -ge 1 && choice -le ${#items[@]} ]]; then
        local index=$((choice-1)); eval "$ret_var='${items[$index]}'"
        return
    fi
    for item in "${items[@]}"; do if [[ "$item" == "$choice" ]]; then eval "$ret_var='$item'"; return; fi; done
    warn "无效的选择"; eval "$ret_var=''"
}

get_ifaces() { ls "$WG_DIR"/*.conf 2>/dev/null | xargs -n 1 basename -s .conf | xargs; }
get_clients() { [[ -d "$WG_CLIENT_DIR" ]] && find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | xargs; }

detect_pm() {
    if command -v apt-get >/dev/null 2>&1; then PM="apt"; elif command -v dnf >/dev/null 2>&1; then PM="dnf"; elif command -v yum >/dev/null 2>&1; then PM="yum"; elif command -v pacman >/dev/null 2>&1; then PM="pacman"; else PM="unknown"; fi
}

pkg_mgr() {
    local action="$1"; shift; detect_pm
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

# ----------------
# Firewall & NAT (v32逻辑)
# ----------------
open_port() {
    local port="$1"; local proto="${2:-udp}"; port=$(trim "$port"); [[ -z "$port" ]] && return
    echo -e "${BLUE}[防火墙]${NC} 放行端口 $port ($proto)..."
    if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1
    elif command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1
    elif command -v iptables >/dev/null; then
        if ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; then iptables -I INPUT -p "$proto" --dport "$port" -j ACCEPT; fi
    fi
}

block_port() {
    local port="$1"; local proto="${2:-tcp}"
    echo -e "${YELLOW}[防火墙]${NC} 屏蔽高危端口 $port ($proto)..."
    if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1; firewall-cmd --permanent --add-rich-rule="rule family='ipv4' port port='$port' protocol='$proto' drop" >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1
    elif command -v ufw >/dev/null && systemctl is-active --quiet ufw; then
        ufw deny "${port}/${proto}" >/dev/null 2>&1
    elif command -v iptables >/dev/null; then
        if ! iptables -C INPUT -p "$proto" --dport "$port" -j DROP 2>/dev/null; then iptables -I INPUT 1 -p "$proto" --dport "$port" -j DROP; fi
    fi
}

auto_nat_firewall_logic() {
    echo -e "${BLUE}=== 正在进行全自动网络与安全配置 ===${NC}"
    if ! command -v jq >/dev/null; then log "安装 jq..."; detect_pm; [[ "$PM" == "apt" ]] && apt-get install -y jq >/dev/null; [[ "$PM" == "yum" || "$PM" == "dnf" ]] && yum install -y jq >/dev/null; fi
    log "1. 开启 IPv4 内核转发..."
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf; else sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf; fi; sysctl -p >/dev/null 2>&1
    local eth=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -n "$eth" ]]; then
        log "2. 检测到主网卡: $eth，配置 NAT..."
        if command -v firewall-cmd >/dev/null && systemctl is-active --quiet firewalld; then firewall-cmd --permanent --add-masquerade >/dev/null 2>&1; firewall-cmd --reload >/dev/null 2>&1
        else if ! iptables -t nat -C POSTROUTING -o "$eth" -j MASQUERADE 2>/dev/null; then iptables -t nat -A POSTROUTING -o "$eth" -j MASQUERADE; fi; iptables -P FORWARD ACCEPT 2>/dev/null; fi
    else warn "未检测到默认网卡。"; fi
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -n1); ssh_port=${ssh_port:-22}
    log "3. 放行 SSH ($ssh_port)..."; open_port "$ssh_port" "tcp"
    log "4. 扫描 x-ui..."
    if [[ -f "/usr/local/x-ui/x-ui" ]]; then
        local xui_panel_port=$(/usr/local/x-ui/x-ui setting -show 2>/dev/null | strip_color | awk '/port/{print $NF}' | tr -d ' ')
        if [[ ! "$xui_panel_port" =~ ^[0-9]+$ ]]; then xui_panel_port=$(/usr/local/x-ui/x-ui setting -show 2>/dev/null | strip_color | grep -oE 'port[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+'); fi
        if [[ -n "$xui_panel_port" && "$xui_panel_port" =~ ^[0-9]+$ ]]; then log "   > 放行面板: $xui_panel_port"; open_port "$xui_panel_port" "tcp"; else warn "   > 未获面板端口"; fi
        local xui_conf="/usr/local/x-ui/bin/config.json"
        if [[ -f "$xui_conf" ]]; then
            local node_ports=$(jq -r '.inbounds[].port' "$xui_conf" 2>/dev/null)
            if [[ -n "$node_ports" ]]; then
                for p in $node_ports; do p=$(trim "$p"); if [[ -n "$p" ]]; then log "   > 放行节点: $p"; open_port "$p" "tcp"; open_port "$p" "udp"; fi; done
            else log "   > x-ui 无节点"; fi
        fi
    else warn "   > 未装 x-ui"; fi
    log "5. 扫描 WireGuard..."
    local wg_confs=$(ls "$WG_DIR"/*.conf 2>/dev/null)
    if [[ -n "$wg_confs" ]]; then
        echo "$wg_confs" | while read -r conf; do
            local port=$(grep "^ListenPort" "$conf" | cut -d= -f2 | tr -d ' ')
            if [[ -n "$port" ]]; then log "   > 放行 WG 接口 $(basename "$conf" .conf): $port"; open_port "$port" "udp"; fi
        done
    else log "   > 无 WG 接口"; fi
    log "6. 安全加固..."
    local bad_ports=("445" "135" "136" "137" "138" "139" "23")
    for bp in "${bad_ports[@]}"; do block_port "$bp" "tcp"; block_port "$bp" "udp"; done
    log "7. 持久化规则..."
    if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1
    elif command -v service >/dev/null; then service iptables save >/dev/null 2>&1; fi
    echo -e "${GREEN}=== 完成 ===${NC}"; press_any_key
}

# ===========================
# 6. WireGuard 业务 (完整恢复 v32)
# ===========================
create_server_logic() {
    install_wg || return 
    echo -e "${BLUE}=== 配置 WireGuard 服务端 ===${NC}"
    local iface; local def_iface="wg0"; read_input "接口名称" "$def_iface" iface
    if [[ ! "$iface" =~ ^[A-Za-z0-9_-]+$ ]]; then err "非法名称"; return; fi
    if [[ ${#iface} -gt 15 ]]; then err "接口名过长"; return; fi
    local ip_cidr; local def_ip="10.0.0.1"; read_input "服务端内网IP" "$def_ip" ip_cidr
    local port; local def_port=$(rand_port); read_input "监听端口" "$def_port" port
    umask 077; wg genkey | tee "$WG_DIR/${iface}_private.key" | wg pubkey > "$WG_DIR/${iface}_public.key"
    local priv=$(cat "$WG_DIR/${iface}_private.key"); local eth=$(ip route | awk '/default/ {print $5; exit}')
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
    local yn; read -rp "是否立即添加一个客户端? (y/n) [y]: " yn; [[ "${yn:-y}" == "y" ]] && add_client_menu
}

core_generate_client() {
    local iface="$1" name="$2" manual_ip="${3:-}"
    local conf="$WG_DIR/${iface}.conf"; if [[ ! -f "$conf" ]]; then err "接口配置丢失"; return 1; fi
    local new_ip="$manual_ip"
    if [[ -z "$new_ip" ]]; then
        local base_ip=$(grep "^Address" "$conf" | cut -d= -f2 | cut -d/ -f1 | tr -d ' ')
        local prefix="${base_ip%.*}"
        for i in {2..254}; do
            if ! grep -q "${prefix}.${i}" "$conf" "$WG_CLIENT_DIR"/*/*.conf 2>/dev/null; then new_ip="${prefix}.${i}"; break; fi
        done
        if [[ -z "$new_ip" ]]; then err "IP池已满"; return 1; fi
    fi
    mkdir -p "$WG_CLIENT_DIR/$name"
    local c_priv=$(wg genkey); local c_pub=$(echo "$c_priv" | wg pubkey); local c_psk=$(wg genpsk)
    local s_pub=""; [[ -f "$WG_DIR/${iface}_public.key" ]] && s_pub=$(cat "$WG_DIR/${iface}_public.key") || s_pub=$(grep "PrivateKey" "$conf" | cut -d= -f2 | tr -d ' ' | wg pubkey)
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
    if ! grep -q "$c_pub" "$conf"; then cat >> "$conf" <<EOF

# Client: ${name}
[Peer]
PublicKey = ${c_pub}
PresharedKey = ${c_psk}
AllowedIPs = ${new_ip}/32
EOF
    fi
    echo "$new_ip"
}

add_single_client() {
    local iface="$1" name def_name=$(get_next_client_name)
    read_input "客户端名称" "$def_name" name
    if [[ ! "$name" =~ ^[A-Za-z0-9_-]+$ ]]; then err "非法名称"; press_any_key; return; fi
    if [[ -d "$WG_CLIENT_DIR/$name" ]]; then warn "用户已存在!"; press_any_key; return; fi
    local set_ip=""; read -rp "指定内网IP (留空自动分配): " set_ip; set_ip=$(trim "$set_ip")
    if [[ -n "$set_ip" && ! "$set_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then warn "IP格式错误，将自动分配"; set_ip=""; fi
    log "正在生成..."
    local res_ip=$(core_generate_client "$iface" "$name" "$set_ip")
    if [[ -n "$res_ip" ]]; then
        clear; echo -e "${GREEN}=== 添加成功 ===${NC}"; echo "用户: $name"; echo "IP: $res_ip"; echo "保活: ${KEEPALIVE}s"
        local conf="$WG_CLIENT_DIR/$name/$name.conf"
        if command -v qrencode >/dev/null; then echo -e "${BLUE}[二维码]${NC}"; qrencode -t ansiutf8 < "$conf"; fi
        wg-quick save "$iface" >/dev/null 2>&1
    fi
    press_any_key
}

add_batch_client() {
    local iface="$1" count; read -rp "请输入数量 (例: 10): " count
    if [[ ! "$count" =~ ^[0-9]+$ ]] || [[ "$count" -le 0 ]]; then err "数量无效"; press_any_key; return; fi
    log "准备生成 $count 个客户端..."; local success_count=0
    for ((i=1; i<=count; i++)); do
        local name=$(get_next_client_name); log "[$i/$count] 正在生成 $name ..."
        local res_ip=$(core_generate_client "$iface" "$name" "")
        if [[ -n "$res_ip" ]]; then ((success_count++)); else err "生成 $name 失败"; break; fi
    done
    wg-quick save "$iface" >/dev/null 2>&1
    echo -e "${GREEN}=== 批量完成 ===${NC}"; echo "成功生成: $success_count 个"; press_any_key
}

add_client_menu() {
    local iface iface_list=$(get_ifaces)
    if [[ -z "$iface_list" ]]; then err "请先安装服务端"; press_any_key; return; fi
    select_smart "选择接口" "$iface_list" iface; if [[ -z "$iface" ]]; then return; fi; iface=$(trim "$iface")
    while true; do
        print_banner
        echo -e "${BLUE}=== 添加客户端 ($iface) ===${NC}"
        menu_item "1" "单个添加" "指定名称/IP"
        menu_item "2" "批量添加" "全自动"
        print_line
        menu_item "0" "返回"
        echo ""
        read -rp " 请选择: " method
        case "$method" in 1) add_single_client "$iface"; return ;; 2) add_batch_client "$iface"; return ;; 0) return ;; *) ;; esac
    done
}

view_client_logic() {
    local client_list=$(get_clients) name
    select_smart "选择客户端" "$client_list" name; [[ -z "$name" ]] && return; name=$(trim "$name")
    local conf="$WG_CLIENT_DIR/$name/$name.conf"
    [[ ! -f "$conf" ]] && { err "文件不存在"; return; }
    clear; echo -e "${GREEN}配置 ($name):${NC}"; cat "$conf"; echo
    if command -v qrencode >/dev/null; then echo -e "${GREEN}二维码:${NC}"; qrencode -t ansiutf8 < "$conf"; fi
}

core_delete_client() {
    local name="$1" conf="$WG_CLIENT_DIR/$name/$name.conf" pub=""
    if [[ -f "$conf" ]]; then
        local priv=$(grep -v '^#' "$conf" | grep "PrivateKey" | cut -d= -f2 | tr -d ' \n\r\t')
        if [[ -n "$priv" ]]; then pub=$(echo "$priv" | wg pubkey); fi
    fi
    if [[ -n "$pub" && ${#pub} -eq 44 ]]; then
        local ifaces=$(get_ifaces)
        for iface in $ifaces; do wg set "$iface" peer "$pub" remove >/dev/null 2>&1 || true; wg-quick save "$iface" >/dev/null 2>&1; done
    fi
    rm -rf "$WG_CLIENT_DIR/$name"; log "已删除: $name"
}

del_single_client() {
    local client_list=$(get_clients) name
    select_smart "删除客户端" "$client_list" name; [[ -z "$name" ]] && return; name=$(trim "$name")
    read -rp "确认删除 $name ? (y/n): " yn; [[ "$yn" != "y" ]] && return
    core_delete_client "$name"; press_any_key
}

del_batch_client() {
    echo -e "${BLUE}--- 批量删除 ---${NC}"
    local start_num count; read -rp "起始编号 (如 3): " start_num; read -rp "删除数量 (如 5): " count
    if [[ ! "$start_num" =~ ^[0-9]+$ ]] || [[ ! "$count" =~ ^[0-9]+$ ]]; then err "输入无效"; press_any_key; return; fi
    read -rp "删除 client-$(printf "%03d" "$start_num") 开始的 $count 个用户，确认? (y/n): " yn
    [[ "$yn" != "y" ]] && return
    for ((i=0; i<count; i++)); do
        local num=$((start_num + i)); local target; printf -v target "client-%03d" "$num"
        if [[ -d "$WG_CLIENT_DIR/$target" ]]; then core_delete_client "$target"; else warn "找不到 $target，跳过"; fi
    done; press_any_key
}

del_all_clients_on_iface() {
    local iface_list=$(get_ifaces) iface
    select_smart "清空接口下所有用户" "$iface_list" iface; [[ -z "$iface" ]] && return; iface=$(trim "$iface")
    warn "警告！这将删除所有连接到 $iface 的用户！"; read -rp "请输入 'CONFIRM' 确认: " input
    if [[ "$input" != "CONFIRM" ]]; then return; fi
    local s_pub=""; [[ -f "$WG_DIR/${iface}_public.key" ]] && s_pub=$(cat "$WG_DIR/${iface}_public.key")
    if [[ -z "$s_pub" ]]; then err "找不到接口公钥"; return; fi
    log "正在扫描并删除..."
    if [[ -d "$WG_CLIENT_DIR" ]]; then
        find "$WG_CLIENT_DIR" -name "*.conf" | while read -r c_conf; do
            if grep -q "$s_pub" "$c_conf"; then local c_dir=$(dirname "$c_conf"); core_delete_client "$(basename "$c_dir")"; fi
        done
    fi; press_any_key
}

del_client_menu() {
    while true; do
        print_banner
        echo -e "${BLUE}=== 删除客户端 ===${NC}"
        menu_item "1" "单个删除" "列表选择"
        menu_item "2" "批量删除" "指定范围"
        menu_item "3" "清空接口用户" "危险操作"
        print_line
        menu_item "0" "返回"
        echo ""
        read -rp " 请选择: " sel
        case "$sel" in 1) del_single_client ;; 2) del_batch_client ;; 3) del_all_clients_on_iface ;; 0) return ;; *) ;; esac
    done
}

del_interface_logic() {
    local iface_list=$(get_ifaces) iface
    select_smart "删除服务端接口 (危险)" "$iface_list" iface; [[ -z "$iface" ]] && return; iface=$(trim "$iface")
    warn "警告：删除接口 $iface 将同时删除其下所有客户端！"; read -rp "确认执行? (输入 yes 确认): " confirm
    if [[ "$confirm" == "yes" ]]; then
        log "清理客户端..."; local s_pub=""; [[ -f "$WG_DIR/${iface}_public.key" ]] && s_pub=$(cat "$WG_DIR/${iface}_public.key")
        if [[ -n "$s_pub" && -d "$WG_CLIENT_DIR" ]]; then
            find "$WG_CLIENT_DIR" -name "*.conf" | while read -r c_conf; do
                if grep -q "$s_pub" "$c_conf"; then local c_dir=$(dirname "$c_conf"); rm -rf "$c_dir"; log "级联删除: $(basename "$c_dir")"; fi
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
        menu_item "1" "删除 客户端" "单个/批量"
        menu_item "2" "删除 接口" "及关联用户"
        print_line
        menu_item "0" "返回"
        echo ""
        read -rp " 请选择: " sel
        case "$sel" in 1) del_client_menu; return ;; 2) del_interface_logic; return ;; 0) return ;; *) ;; esac
    done
}

modify_port_logic() {
    local iface_list=$(get_ifaces) iface
    select_smart "修改端口 - 选择接口" "$iface_list" iface
    if [[ -n "$iface" ]]; then
        iface=$(trim "$iface"); read -rp "新端口: " p
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
    local wg_bin=$(find_wg_bin); if [[ -n "$wg_bin" ]]; then "$wg_bin" show; else err "未找到 wg 命令。"; fi; press_any_key
}

uninstall_logic() {
    warn "警告: 删除所有配置！"; read -rp "输入 'yes' 确认: " confirm
    if [[ "$confirm" == "yes" ]]; then
        log "停止服务..."; systemctl stop wg-quick@* 2>/dev/null; systemctl disable wg-quick@* 2>/dev/null
        log "删除文件..."; rm -rf "$WG_DIR"; log "卸载软件..."; detect_pm
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
        print_line
        menu_item "0" "返回主菜单"
        echo ""
        read -rp " 请选择: " choice
        case "$choice" in
            1) create_server_logic ;; 2) add_client_menu ;; 3) list=$(get_clients); if [[ -z "$list" ]]; then echo "(暂无用户)"; else echo "$list" | tr ' ' '\n' | nl; fi; press_any_key ;;
            4) view_client_logic ;; 5) del_menu_entry ;; 6) modify_port_logic ;; 7) show_status_logic ;; 8) uninstall_logic ;;
            0) return ;; *) ;;
        esac
    done
}

xui_manage() { bash <(curl -fsSL https://raw.githubusercontent.com/yonggekkk/x-ui-yg/main/install.sh); }

# ===========================
# 8. 主菜单入口 (v34.0)
# ===========================
main_menu() {
    create_shortcut; require_root
    while true; do
        print_banner
        
        local os=$(lsb_release -ds 2>/dev/null || cat /etc/redhat-release 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
        local kernel=$(uname -r); local uptime=$(uptime -p)
        local load=$(awk '{print $1}' /proc/loadavg)
        local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
        local mem_used=$(free -m | awk '/Mem:/ {print $3}'); local mem_total=$(free -m | awk '/Mem:/ {print $2}')
        local disk_used=$(df -h / | awk 'NR==2 {print $3}'); local disk_total=$(df -h / | awk 'NR==2 {print $2}')
        
        printf " ${CYAN}%-6s${YELLOW}%-30s ${CYAN}%-6s${YELLOW}%s${NC}\n" "系统:" "$os" "内核:" "$kernel"
        printf " ${CYAN}%-6s${YELLOW}%-30s ${CYAN}%-6s${YELLOW}%s${NC}\n" "运行:" "$uptime" "负载:" "$load"
        printf " ${CYAN}%-6s${YELLOW}%-10s ${CYAN}%-6s${YELLOW}%-14s ${CYAN}%-6s${YELLOW}%s${NC}\n" "CPU:" "${cpu_usage}%" "内存:" "${mem_used}M/${mem_total}M" "硬盘:" "${disk_used}/${disk_total}"
        print_line

        printf "${CYAN} WireGuard:${NC} [状态: %-8s] [自启: %-4s] [版本: %-8s]\n" "$(get_wg_status_text)" "$(get_wg_enable_text)" "$(get_wg_version_text)"
        printf "${CYAN} x-ui 面板:${NC} [状态: %-8s] [自启: %-4s] [版本: %-8s]\n" "$(get_xui_status_text)" "$(get_xui_enable_text)" "$(get_xui_version_text)"
        print_line
        
        menu_item "1" "WireGuard 管理" "核心功能"
        menu_item "2" "x-ui 面板管理" "官方脚本"
        menu_item "3" "系统详细信息" "硬件/网络"
        menu_item "4" "全自动 NAT/安全托管" "防火墙"
        menu_item "5" "网络工具箱" "解锁/测速"
        
        print_line
        menu_item "0" "退出脚本"
        echo ""
        
        read -rp " 请选择: " choice
        case "$choice" in
            1) wg_menu_main ;;
            2) xui_manage; press_any_key ;;
            3) show_full_sys_info ;;
            4) auto_nat_firewall_logic ;;
            5) network_tools_menu ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

main_menu
