#!/usr/bin/env bash
#
# auto-linux.sh
# WireGuard 一键管理脚本
# 说明：自动适配主流发行版，提供交互式菜单，支持安装、配置、添加客户端、生成二维码、查看/删除客户端等功能
# 作者：整合自 repo 脚本（由 ChatGPT 整合与优化）
#
set -euo pipefail
IFS=$'\n\t'

WG_DIR="/etc/wireguard"
WG_CLIENT_DIR="$WG_DIR/clients"

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# -----------------------
# 通用工具函数
# -----------------------
log() { echo -e "${GREEN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

valid_name() {
    [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]
}

rand_suffix() {
    tr -dc 'a-z0-9' </dev/urandom | head -c 6
}

rand_iface() {
    echo "wg$(tr -dc '0-9' </dev/urandom | head -c 3)"
}

rand_port() {
    echo "$(( (RANDOM % 20000) + 20000 ))"
}

rand_client_name() {
    echo "client-$(rand_suffix)"
}

normalize_cnet() {
    local cnet="$1"
    if [[ "$cnet" =~ ^([0-9]{1,3}\.){2}[0-9]{1,3}$ ]]; then
        echo "${cnet}.1"
    else
        echo ""
    fi
}

list_wg_ifaces() {
    local ifaces=""
    local -a confs
    confs=("$WG_DIR"/*.conf)
    if [[ -e "${confs[0]}" ]]; then
        local f
        for f in "${confs[@]}"; do
            ifaces+=$(basename "$f" .conf)$'\n'
        done
    fi
    printf '%s\n' "$ifaces" | awk 'NF'
}

list_wg_clients() {
    local names=""
    if [[ -d "$WG_CLIENT_DIR" ]]; then
        local -a dirs
        dirs=("$WG_CLIENT_DIR"/*)
        if [[ -e "${dirs[0]}" ]]; then
            local d
            for d in "${dirs[@]}"; do
                [[ -d "$d" ]] || continue
                names+=$(basename "$d")$'\n'
            done
        fi
    fi
    printf '%s\n' "$names" | awk 'NF' | sort
}

get_iface_port() {
    local iface="$1"
    read_kv "ListenPort" "$WG_DIR/${iface}.conf"
}

get_client_iface() {
    local name="$1"
    local conf="$WG_CLIENT_DIR/$name/$name.conf"
    if [[ -f "$conf" ]]; then
        local iface
        iface=$(read_comment "Interface" "$conf")
        if [[ -n "$iface" ]]; then
            echo "$iface"
            return
        fi
    fi
    local pubkey
    pubkey=$(get_client_pubkey "$name")
    find_iface_by_client_pubkey "$pubkey"
}

print_numbered() {
    awk 'NF {printf "%d) %s\n", NR, $0}'
}

print_to_tty() {
    if [[ -w /dev/tty ]]; then
        cat >/dev/tty
    else
        cat >&2
    fi
}

select_from_list() {
    local label="$1"
    local list="$2"
    local input selected
    local normalized
    normalized=$(printf '%s\n' "$list" | tr -d '\r' | awk '{$1=$1; if (NF) print}')
    if [[ -n "$normalized" ]]; then
        echo "$normalized" | print_numbered | print_to_tty
    fi
    read -rp "${label} (名称或编号): " input
    input=$(printf '%s' "$input" | tr -d '\r' | awk '{$1=$1; print}')
    if [[ -z "$input" ]]; then
        echo ""
        return
    fi
    if [[ "$input" =~ ^[0-9]+$ ]]; then
        selected=$(printf '%s\n' "$normalized" | awk -v n="$input" 'NR==n {print; exit}')
        selected=$(printf '%s' "$selected" | tr -d '\r' | awk '{$1=$1; print}')
        echo "$selected"
        return
    fi
    echo "$input"
}

get_client_pubkey() {
    local name="$1"
    local key_file="$WG_CLIENT_DIR/$name/public.key"
    if [[ -f "$key_file" ]]; then
        cat "$key_file"
        return
    fi
    local conf="$WG_CLIENT_DIR/$name/$name.conf"
    if [[ -f "$conf" ]]; then
        read_comment "ClientPublicKey" "$conf"
    fi
}

find_iface_by_client_pubkey() {
    local pubkey="$1"
    if [[ -z "$pubkey" ]]; then
        return
    fi
    local conf
    for conf in "$WG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        if grep -q "PublicKey = ${pubkey}" "$conf"; then
            basename "$conf" .conf
            return
        fi
    done
}

delete_iface_and_clients() {
    local iface="$1"
    local conf="$WG_DIR/${iface}.conf"
    if [[ -f "$conf" ]]; then
        systemctl stop "wg-quick@${iface}" 2>/dev/null || true
        systemctl disable "wg-quick@${iface}" 2>/dev/null || true
        rm -f "$conf"
    else
        warn "未找到接口配置: $conf，将尝试停止接口"
        systemctl stop "wg-quick@${iface}" 2>/dev/null || true
        systemctl disable "wg-quick@${iface}" 2>/dev/null || true
        ip link delete "$iface" 2>/dev/null || true
    fi
    local removed=0
    if [[ -d "$WG_CLIENT_DIR" ]]; then
        while IFS= read -r -d '' dir; do
            local name conf_path
            name=$(basename "$dir")
            conf_path="$dir/$name.conf"
            if [[ -f "$conf_path" ]] && grep -qx "# Interface: ${iface}" "$conf_path"; then
                rm -rf "$dir"
                ((removed++)) || true
            fi
        done < <(find "$WG_CLIENT_DIR" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
    fi
    if (( removed > 0 )); then
        log "已删除接口 ${iface} 及其客户端 (${removed})"
    else
        warn "已删除接口 ${iface}，未找到标记为该接口的客户端"
    fi
}

read_kv() {
    local key="$1"
    local file="$2"
    awk -F'=' -v k="$key" '
        $1 ~ "^[[:space:]]*"k"[[:space:]]*$" {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
            print $2
            exit
        }
    ' "$file" || true
}

read_comment() {
    local key="$1"
    local file="$2"
    awk -v k="$key" '
        $0 ~ "^# "k":" {
            sub("^# "k":[[:space:]]*", "", $0)
            print $0
            exit
        }
    ' "$file" || true
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "请以 root 身份运行本脚本。"
        exit 1
    fi
}

press_any_key() {
    echo
    read -r -p "按 Enter 键返回..." _dummy
}

prompt_default() {
    local label="$1"
    local default="$2"
    local value
    if [[ -n "$default" ]]; then
        read -rp "${label} [${default}]: " value
        echo "${value:-$default}"
    else
        read -rp "${label}: " value
        echo "$value"
    fi
}

# -----------------------
# 发行版检测与包管理抽象
# -----------------------
DISTRO=""
PKG_INSTALL=""
PKG_UPDATE=""
PKG_REMOVE=""

detect_distro_and_pkgmgr() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        DISTRO="$ID"
    fi

    case "$DISTRO" in
        ubuntu|debian)
            PKG_INSTALL="apt-get install -y"
            PKG_UPDATE="apt-get update -y"
            PKG_REMOVE="apt-get remove -y"
            ;;
        centos|rhel|almalinux|rocky)
            PKG_INSTALL="dnf install -y"
            PKG_UPDATE="dnf makecache"
            PKG_REMOVE="dnf remove -y"
            ;;
        fedora)
            PKG_INSTALL="dnf install -y"
            PKG_UPDATE="dnf makecache"
            PKG_REMOVE="dnf remove -y"
            ;;
        arch)
            PKG_INSTALL="pacman -S --noconfirm"
            PKG_UPDATE="pacman -Sy"
            PKG_REMOVE="pacman -R --noconfirm"
            ;;
        opensuse*|suse)
            PKG_INSTALL="zypper install -y"
            PKG_UPDATE="zypper refresh"
            PKG_REMOVE="zypper remove -y"
            ;;
        *)
            warn "无法识别发行版 ($DISTRO)，将尝试使用 apt/dnf/pacman 等通用命令。"
            PKG_INSTALL="apt-get install -y"
            PKG_UPDATE="apt-get update -y"
            PKG_REMOVE="apt-get remove -y"
            ;;
    esac
}

run_pkg_cmd() {
    local cmd_string="$1"
    shift || true
    local -a cmd
    IFS=' ' read -r -a cmd <<<"$cmd_string"
    "${cmd[@]}" "$@"
}

pkg_update() {
    if [[ -n "${PKG_UPDATE:-}" ]]; then
        run_pkg_cmd "$PKG_UPDATE"
    fi
}

pkg_install() {
    if [[ $# -eq 0 ]]; then return; fi
    echo "安装软件包：$*"
    run_pkg_cmd "$PKG_INSTALL" "$@"
}

pkg_exists() {
    local pkg="$1"
    if command -v dpkg >/dev/null 2>&1; then
        dpkg -s "$pkg" >/dev/null 2>&1 && return 0 || return 1
    elif command -v rpm >/dev/null 2>&1; then
        rpm -q "$pkg" >/dev/null 2>&1 && return 0 || return 1
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Qi "$pkg" >/dev/null 2>&1 && return 0 || return 1
    else
        command -v "$pkg" >/dev/null 2>&1 && return 0 || return 1
    fi
}

# -----------------------
# WireGuard 部分
# -----------------------
ensure_wireguard_tools() {
    detect_distro_and_pkgmgr
    pkg_update
    # install common tools
    case "$DISTRO" in
        ubuntu|debian)
            pkg_install wireguard qrencode iptables-persistent net-tools resolvconf
            ;;
        centos|rhel|almalinux|rocky)
            # EPEL may be required on older RHEL/CentOS
            if ! rpm -qa | grep -qi epel; then
                dnf install -y epel-release || true
            fi
            pkg_install wireguard-tools qrencode iptables-services
            ;;
        fedora)
            pkg_install wireguard-tools qrencode
            ;;
        arch)
            pkg_install wireguard-tools qrencode
            ;;
        opensuse*|suse)
            pkg_install wireguard-tools qrencode
            ;;
        *)
            # fallback
            pkg_install wireguard qrencode || true
            ;;
    esac
    mkdir -p "$WG_DIR"
    mkdir -p "$WG_CLIENT_DIR"
    chmod 700 "$WG_DIR"
}

wg_generate_server_keys() {
    local iface="${1:-wg0}"
    ensure_wireguard_tools
    if [[ ! -f "$WG_DIR/server_private.key" ]]; then
        umask 077
        wg genkey | tee "$WG_DIR/server_private.key" | wg pubkey > "$WG_DIR/server_public.key"
        chmod 600 "$WG_DIR/server_private.key"
    fi
}

wg_create_server_conf() {
    local iface="${1:-wg0}"
    local server_ip="${2:-10.0.0.1}"
    local port="${3:-51820}"
    wg_generate_server_keys "$iface"
    local server_priv
    server_priv=$(cat "$WG_DIR/server_private.key")
    cat > "$WG_DIR/${iface}.conf" <<EOF
[Interface]
Address = ${server_ip}/24
ListenPort = ${port}
PrivateKey = ${server_priv}
SaveConfig = true
EOF
    chmod 600 "$WG_DIR/${iface}.conf"
    log "WireGuard 服务端配置已创建: $WG_DIR/${iface}.conf"
}

wg_next_client_ip() {
    local iface="${1:-wg0}"
    local base
    base=$(read_kv "Address" "$WG_DIR/${iface}.conf")
    base=${base%%/*}
    if [[ -z "$base" ]]; then
        err "无法读取服务器地址，请检查 $WG_DIR/${iface}.conf"
        return 1
    fi
    local prefix="${base%.*}"
    local used_ips=""
    local server_ips
    server_ips=$(awk -F'=' '/^(Address|AllowedIPs)/ {gsub(/[[:space:]]/, "", $2); print $2}' "$WG_DIR/${iface}.conf" 2>/dev/null || true)
    local conf_files=("$WG_CLIENT_DIR"/*/*.conf)
    if [[ -e "${conf_files[0]}" ]]; then
        server_ips+=$'\n'"$(awk -F'=' '/^Address/ {gsub(/[[:space:]]/, "", $2); print $2}' "${conf_files[@]}" 2>/dev/null || true)"
    fi
    used_ips=$(printf '%s\n' "$server_ips" | awk '{gsub(/\/.*/, "", $0); if ($0 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) print $0}')
    for i in $(seq 2 254); do
        candidate="${prefix}.${i}"
        if ! printf '%s\n' "$used_ips" | grep -qx "$candidate"; then
            echo "$candidate"
            return
        fi
    done
    err "没有可用的客户端 IP"
    return 1
}

wg_add_client() {
    local name="$1"; shift
    local iface="${1:-wg0}"
    local ipaddr
    if [[ -z "$name" ]]; then
        read -rp "请输入客户端名称（仅字母数字_-）: " name
        if [[ -z "$name" ]]; then err "客户端名不能为空"; return 1; fi
    fi
    if ! valid_name "$name"; then
        err "客户端名不合法，仅允许 [A-Za-z0-9._-]"
        return 1
    fi
    if [[ ! -f "$WG_DIR/${iface}.conf" ]]; then
        err "未找到服务端配置：$WG_DIR/${iface}.conf，请先部署服务端。"
        return 1
    fi
    mkdir -p "$WG_CLIENT_DIR/$name"
    chmod 700 "$WG_CLIENT_DIR/$name"
    ipaddr=$(wg_next_client_ip "$iface")
    # generate keys
    umask 077
    wg genkey | tee "$WG_CLIENT_DIR/$name/private.key" | wg pubkey > "$WG_CLIENT_DIR/$name/public.key"
    wg genpsk > "$WG_CLIENT_DIR/$name/psk"
    local priv pub psk server_pub server_addr server_port dns
    priv=$(cat "$WG_CLIENT_DIR/$name/private.key")
    pub=$(cat "$WG_CLIENT_DIR/$name/public.key")
    psk=$(cat "$WG_CLIENT_DIR/$name/psk")
    server_pub=$(cat "$WG_DIR/server_public.key" 2>/dev/null || true)
    if [[ -z "$server_pub" ]]; then
        local server_priv
        server_priv=$(read_kv "PrivateKey" "$WG_DIR/${iface}.conf")
        if [[ -n "$server_priv" ]]; then
            server_pub=$(printf '%s' "$server_priv" | wg pubkey)
        fi
    fi
    if [[ -z "$server_pub" && -f "$WG_DIR/server_private.key" ]]; then
        server_pub=$(wg pubkey < "$WG_DIR/server_private.key" 2>/dev/null || true)
    fi
    # server endpoint: prefer env/comment, fallback to public IP detection
    server_port=$(read_kv "ListenPort" "$WG_DIR/${iface}.conf")
    server_port=${server_port:-51820}
    server_addr="${WG_SERVER_ENDPOINT:-$(read_comment "ServerEndpoint" "$WG_DIR/${iface}.conf")}"
    if [[ -z "$server_addr" ]]; then
        server_addr=$(curl -fs4 https://ipv4.icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
    fi
    if [[ -z "$server_pub" ]]; then
        err "无法获取服务端公钥，请确认 $WG_DIR/server_public.key 或配置中的 PrivateKey。"
        return 1
    fi
    if [[ -z "$server_addr" || -z "$server_port" ]]; then
        err "无法确定 Endpoint，请设置 WG_SERVER_ENDPOINT 或在配置中添加 # ServerEndpoint:。"
        return 1
    fi
    local endpoint
    if [[ "$server_addr" =~ :[0-9]{1,5}$ ]]; then
        endpoint="$server_addr"
    else
        endpoint="${server_addr}:${server_port}"
    fi
    dns="1.1.1.1"
    cat > "$WG_CLIENT_DIR/$name/$name.conf" <<EOF
[Interface]
PrivateKey = ${priv}
Address = ${ipaddr}/32
DNS = ${dns}
# ClientPublicKey: ${pub}
# Interface: ${iface}

[Peer]
PublicKey = ${server_pub}
PresharedKey = ${psk}
Endpoint = ${endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 21
EOF
    # append peer to server config
    cat >> "$WG_DIR/${iface}.conf" <<EOF

# ${name}
[Peer]
PublicKey = ${pub}
PresharedKey = ${psk}
AllowedIPs = ${ipaddr}/32
EOF
    chmod 600 "$WG_CLIENT_DIR/$name/$name.conf"
    # generate qr (png + terminal)
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -o "$WG_CLIENT_DIR/$name/$name.png" -t png < "$WG_CLIENT_DIR/$name/$name.conf" || true
    fi
    log "已添加客户端 ${name}，配置: $WG_CLIENT_DIR/$name/$name.conf"
    # restart service to apply
    systemctl restart "wg-quick@${iface}" 2>/dev/null || wg syncconf "$iface" <(wg-quick strip "$iface") 2>/dev/null || true
}

wg_list_clients() {
    if [[ ! -d "$WG_CLIENT_DIR" ]]; then
        echo "暂无客户端"
        return
    fi
    for d in "$WG_CLIENT_DIR"/*; do
        [[ -d "$d" ]] || continue
        name=$(basename "$d")
        ip=$(grep '^Address' "$d/$name.conf" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' | cut -d'/' -f1)
        echo " - $name ($ip)"
    done
}

wg_show_client() {
    local name="${1-}"; shift || true
    if [[ -z "$name" ]]; then
        read -rp "请输入要查看的客户端名: " name
    fi
    if ! valid_name "$name"; then
        err "客户端名不合法，仅允许 [A-Za-z0-9._-]"
        return 1
    fi
    local conf="$WG_CLIENT_DIR/$name/$name.conf"
    if [[ ! -f "$conf" ]]; then err "未找到客户端配置: $conf"; return 1; fi
    echo "---- $name 配置 ----"
    cat "$conf"
    echo "二维码（终端渲染）:"
    if command -v qrencode >/dev/null 2>&1; then
        qrencode -t ansiutf8 < "$conf" || true
    else
        echo "(未安装 qrencode，无法显示二维码)"
    fi
    echo "PNG二维码路径（若生成）: $WG_CLIENT_DIR/$name/$name.png"
}

wg_remove_client() {
    local name="${1-}"; shift || true
    if [[ -z "$name" ]]; then
        read -rp "请输入要删除的客户端名: " name
    fi
    if ! valid_name "$name"; then
        err "客户端名不合法，仅允许 [A-Za-z0-9._-]"
        return 1
    fi
    local iface="${1-}"
    if [[ -z "$iface" ]]; then
        iface=$(get_client_iface "$name")
    fi
    if [[ -z "$iface" ]]; then
        err "无法确定接口，请指定接口名"
        return 1
    fi
    local server_conf="$WG_DIR/${iface}.conf"
    if [[ ! -f "$server_conf" ]]; then err "未找到服务器配置 $server_conf"; fi
    local pub
    pub=$(cat "$WG_CLIENT_DIR/$name/public.key" 2>/dev/null || true)
    if [[ -z "$pub" ]]; then
        warn "未找到客户端公钥，仍会尝试删除本地文件"
    fi
    # remove peer block by matching public key or comment
    local tmpfile
    tmpfile=$(mktemp)
    awk -v pk="$pub" -v cname="$name" '
        function flush() {
            if (inpeer && !skip) print buffer
            inpeer=0; skip=0; buffer=""
        }
        BEGIN {inpeer=0; skip=0; buffer=""}
        /^\[Peer\]/ {flush(); inpeer=1; buffer=$0; next}
        {
            if (inpeer) {
                buffer=buffer ORS $0
                if (pk != "" && index($0, pk)) skip=1
                if ($0 ~ "^# " cname "$") skip=1
            } else {
                print $0
            }
        }
        END {flush()}
    ' "$server_conf" > "$tmpfile"
    mv "$tmpfile" "$server_conf"
    rm -rf "$WG_CLIENT_DIR/$name"
    systemctl restart "wg-quick@${iface}" 2>/dev/null || true
    log "客户端 $name 已删除"
}

wg_change_port() {
    local iface="${1:-wg0}"
    local conf="$WG_DIR/${iface}.conf"
    if [[ ! -f "$conf" ]]; then err "未找到 $conf"; return 1; fi
    read -rp "请输入新的监听端口: " newp
    if ! [[ "$newp" =~ ^[0-9]+$ ]] || (( newp < 1 || newp > 65535 )); then err "端口不合法"; return 1; fi
    sed -i "s/^ListenPort.*/ListenPort = ${newp}/" "$conf" || sed -i "s/^ListenPort = .*/ListenPort = ${newp}/" "$conf" || true
    log "端口已修改为 $newp，正在重启服务..."
    systemctl restart "wg-quick@${iface}" 2>/dev/null || true
}

wg_enable_nat_and_forward() {
    local iface="${1:-wg0}"
    if [[ -z "$iface" ]]; then
        err "接口名不能为空"
        return 1
    fi
    if [[ ! -f "$WG_DIR/${iface}.conf" ]]; then
        err "未找到接口配置: $WG_DIR/${iface}.conf"
        return 1
    fi
    # enable ip forward
    if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || true
    fi
    # configure iptables NAT
    local pub_if
    pub_if=$(ip route | awk '/default/ {print $5; exit}')
    if [[ -z "$pub_if" ]]; then warn "未能自动检测公网接口，请手动配置 NAT"; return; fi
    local base_ip net_cidr
    base_ip=$(read_kv "Address" "$WG_DIR/${iface}.conf")
    base_ip=${base_ip%%/*}
    if [[ -z "$base_ip" ]]; then
        err "未能从配置读取网段"
        return 1
    fi
    net_cidr="${base_ip%.*}.0/24"
    iptables -t nat -C POSTROUTING -s "$net_cidr" -o "$pub_if" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "$net_cidr" -o "$pub_if" -j MASQUERADE
    # allow forwarding
    iptables -C FORWARD -i "$iface" -o "$pub_if" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$iface" -o "$pub_if" -j ACCEPT
    iptables -C FORWARD -i "$pub_if" -o "$iface" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$pub_if" -o "$iface" -m state --state ESTABLISHED,RELATED -j ACCEPT
    # save rules if possible
    if command -v netfilter-persistent >/dev/null 2>&1; then
        netfilter-persistent save >/dev/null 2>&1 || true
    elif [[ -d /etc/iptables ]]; then
        iptables-save > /etc/iptables/rules.v4 || true
    fi
    log "已配置 NAT 与转发（出口接口: $pub_if）"
}

wg_show_status() {
    local iface="${1:-wg0}"
    if command -v wg >/dev/null 2>&1; then
        wg show "$iface" || true
    else
        warn "wg 工具不可用"
    fi
    systemctl status "wg-quick@${iface}" --no-pager || true
}

wg_uninstall() {
    read -rp "要彻底卸载 WireGuard 吗？这将删除 /etc/wireguard 下的所有文件 (y/N): " yn
    if [[ "$yn" =~ ^[Yy]$ ]]; then
        local ifaces
        ifaces=$(list_wg_ifaces)
        if [[ -n "$ifaces" ]]; then
            while IFS= read -r iface; do
                systemctl stop "wg-quick@${iface}" 2>/dev/null || true
                systemctl disable "wg-quick@${iface}" 2>/dev/null || true
            done <<<"$ifaces"
        else
            systemctl stop wg-quick@wg0 2>/dev/null || true
            systemctl disable wg-quick@wg0 2>/dev/null || true
        fi
        rm -rf "$WG_DIR"
        log "WireGuard 配置已删除"
        # optionally remove packages
        read -rp "是否卸载软件包 wireguard/qrencode？(y/N): " rem
        if [[ "$rem" =~ ^[Yy]$ ]]; then
            run_pkg_cmd "$PKG_REMOVE" wireguard wireguard-tools qrencode || true
            log "WireGuard 软件包已卸载（若可用）"
        fi
    else
        log "取消卸载"
    fi
}

# -----------------------
# 菜单 UI
# -----------------------
show_main_menu() {
    clear
    cat <<'EOF'
============================================
 auto-linux WireGuard 管理脚本
 1) WireGuard 管理
 2) x-ui 面板管理（使用官方脚本）
 3) 系统信息
 0) 退出
============================================
EOF
    read -rp "请选择: " choice
    case "$choice" in
        1) wg_menu ;;
        2) xui_manage; press_any_key ;;
        3) system_info; press_any_key ;;
        0) exit 0 ;;
        *) warn "无效选项"; sleep 1 ;;
    esac
}

wg_menu() {
    while true; do
        clear
        cat <<EOF
==== WireGuard 菜单 ====
1) 安装/初始化 WireGuard 服务端
2) 添加客户端（生成配置 + QR）
3) 列出客户端
4) 查看客户端配置与二维码
5) 删除客户端
6) 修改监听端口
7) 配置 NAT 与转发
8) 查看状态
9) 卸载 WireGuard
0) 返回主菜单
EOF
        read -rp "请选择: " c
        case "$c" in
            1)
                require_root
                local iface serverip port cnet cname
                iface=$(prompt_default "接口名(可留空随机)" "$(rand_iface)")
                if ! valid_name "$iface"; then
                    err "接口名不合法，仅允许 [A-Za-z0-9._-]"
                    press_any_key
                    continue
                fi
                cnet=$(prompt_default "服务器内网 C 段(示例 10.0.0)" "10.0.0")
                serverip=$(normalize_cnet "$cnet")
                if [[ -z "$serverip" ]]; then
                    err "网段格式不正确，请输入如 10.0.0"
                    press_any_key
                    continue
                fi
                port=$(prompt_default "端口(可留空随机)" "$(rand_port)")
                if ! [[ "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
                    err "端口不合法"
                    press_any_key
                    continue
                fi
                ensure_wireguard_tools
                wg_create_server_conf "$iface" "$serverip" "$port"
                systemctl enable "wg-quick@${iface}" >/dev/null 2>&1 || true
                systemctl restart "wg-quick@${iface}" >/dev/null 2>&1 || true
                log "WireGuard 服务已安装并启动（接口: $iface）"
                cname=$(prompt_default "初始化客户端名称(可留空随机)" "$(rand_client_name)")
                wg_add_client "$cname" "$iface"
                press_any_key
                ;;
            2)
                require_root
                local ifaces iface name
                ifaces=$(list_wg_ifaces)
                if [[ -n "$ifaces" ]]; then
                    echo "现有接口:"
                    iface=$(select_from_list "接口" "$ifaces")
                else
                    warn "未检测到现有接口，请手动输入"
                    read -rp "接口名: " iface
                fi
                iface=${iface:-wg0}
                if [[ -z "$iface" ]]; then
                    warn "未选择接口"
                    press_any_key
                    continue
                fi
                if ! valid_name "$iface"; then
                    err "接口名不合法，仅允许 [A-Za-z0-9._-]"
                    press_any_key
                    continue
                fi
                name=$(prompt_default "客户端名(可留空随机)" "$(rand_client_name)")
                wg_add_client "$name" "$iface"
                press_any_key
                ;;
            3) wg_list_clients; press_any_key ;;
            4)
                local clients cname
                clients=$(list_wg_clients)
                if [[ -n "$clients" ]]; then
                    echo "现有客户端:"
                else
                    warn "未检测到客户端"
                    press_any_key
                    continue
                fi
                cname=$(select_from_list "客户端" "$clients")
                if [[ -z "$cname" ]]; then
                    warn "未选择客户端"
                    press_any_key
                    continue
                fi
                wg_show_client "$cname"
                press_any_key
                ;;
            5)
                require_root
                local sub
                echo "1) 删除接口（包含其客户端）"
                echo "2) 删除客户端"
                echo "0) 返回"
                read -rp "请选择: " sub
                case "$sub" in
                    1)
                        local ifaces iface
                        ifaces=$(list_wg_ifaces)
                        if [[ -n "$ifaces" ]]; then
                            echo "现有接口:"
                        else
                            warn "未检测到现有接口"
                            press_any_key
                            break
                        fi
                        iface=$(select_from_list "接口" "$ifaces")
                        if [[ -z "$iface" ]]; then
                            warn "未选择接口"
                            break
                        fi
                        delete_iface_and_clients "$iface"
                        ;;
                    2)
                        local clients name ifaces iface
                        clients=$(list_wg_clients)
                        if [[ -n "$clients" ]]; then
                            echo "现有客户端:"
                        else
                            warn "未检测到客户端"
                            press_any_key
                            break
                        fi
                        name=$(select_from_list "客户端" "$clients")
                        if [[ -z "$name" ]]; then
                            warn "未选择客户端"
                            break
                        fi
                        iface=$(get_client_iface "$name")
                        if [[ -z "$iface" ]]; then
                            warn "未能自动识别接口，请手动选择"
                            ifaces=$(list_wg_ifaces)
                            if [[ -n "$ifaces" ]]; then
                                echo "现有接口:"
                            else
                                warn "未检测到现有接口"
                                press_any_key
                                break
                            fi
                            iface=$(select_from_list "接口" "$ifaces")
                            iface=${iface:-wg0}
                        else
                            echo "检测到接口: $iface"
                        fi
                        wg_remove_client "$name" "$iface"
                        ;;
                    0) ;;
                    *) warn "无效选项" ;;
                esac
                press_any_key
                ;;
            6)
                require_root
                local ifaces iface port
                ifaces=$(list_wg_ifaces)
                if [[ -n "$ifaces" ]]; then
                    echo "现有接口:"
                else
                    warn "未检测到现有接口"
                    press_any_key
                    continue
                fi
                iface=$(select_from_list "接口" "$ifaces")
                iface=${iface:-wg0}
                if [[ -z "$iface" ]]; then
                    warn "未选择接口"
                    press_any_key
                    continue
                fi
                port=$(get_iface_port "$iface")
                if [[ -n "$port" ]]; then
                    echo "当前端口: $port"
                fi
                wg_change_port "$iface"
                press_any_key
                ;;
            7)
                require_root
                local ifaces iface
                ifaces=$(list_wg_ifaces)
                if [[ -n "$ifaces" ]]; then
                    echo "现有接口:"
                    iface=$(select_from_list "接口" "$ifaces")
                else
                    warn "未检测到现有接口"
                    press_any_key
                    break
                fi
                if [[ -z "$iface" ]]; then
                    warn "未选择接口"
                    press_any_key
                    break
                fi
                wg_enable_nat_and_forward "$iface"
                press_any_key
                ;;
            8) wg_show_status; press_any_key ;;
            9) require_root; wg_uninstall; press_any_key ;;
            0) break ;;
            *) warn "无效选项"; sleep 1 ;;
        esac
    done
}

system_info() {
    echo "系统信息："
    lsb_release -a 2>/dev/null || cat /etc/os-release
    echo "内核：$(uname -r)"
    echo "IP：$(hostname -I | tr -s ' ')"
    echo "磁盘："
    df -h | sed -n '1,6p'
}

# -----------------------
# x-ui 面板（调用官方脚本）
# -----------------------
xui_manage() {
    echo "将执行 x-ui 官方管理脚本..."
    bash <(curl -fsSL https://raw.githubusercontent.com/yonggekkk/x-ui-yg/main/install.sh)
}

# -----------------------
# 启动 & 主循环
# -----------------------
main() {
    require_root
    detect_distro_and_pkgmgr
    while true; do
        show_main_menu
    done
}

main "$@"

# End of file
