#!/bin/bash
#
# OpenVPN 一键安装脚本 (中文版) - 账号密码认证版
# 基于 https://github.com/Nyr/openvpn-install 修改
#
# 版权所有 (c) 2013 Nyr。根据 MIT 许可证发布。

# 检测使用 dash 而不是 bash 运行脚本的 Debian 用户
if readlink /proc/$$/exe | grep -q "dash"; then
	echo '这个安装程序需要使用 "bash" 运行，而不是 "sh"。'
	exit
fi

# 丢弃标准输入。当从包含换行符的一行命令运行时需要
read -N 999999 -t 0.001

# 检测操作系统
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "这个安装程序似乎运行在不支持的操作系统上。
支持的操作系统有 Ubuntu、Debian、AlmaLinux、Rocky Linux、CentOS 和 Fedora。"
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
	echo "这个安装程序需要 Ubuntu 22.04 或更高版本。
您当前的 Ubuntu 版本太旧且不受支持。"
	exit
fi

if [[ "$os" == "debian" ]]; then
	if grep -q '/sid' /etc/debian_version; then
		echo "这个安装程序不支持 Debian Testing 和 Debian Unstable。"
		exit
	fi
	if [[ "$os_version" -lt 11 ]]; then
		echo "这个安装程序需要 Debian 11 或更高版本。
您当前的 Debian 版本太旧且不受支持。"
		exit
	fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
	os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
	echo "需要 $os_name 9 或更高版本才能使用此安装程序。
您当前的 $os_name 版本太旧且不受支持。"
	exit
fi

# 检测 $PATH 不包含 sbin 目录的环境
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH 不包含 sbin。请尝试使用 "su -" 而不是 "su"。'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "这个安装程序需要使用超级用户权限运行。"
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "系统没有可用的 TUN 设备。
在运行此安装程序之前需要启用 TUN。"
	exit
fi

# 存储脚本所在目录的绝对路径
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# 账号密码认证相关函数
add_user() {
	echo
	echo "请输入新用户的用户名:"
	read -p "用户名: " username
	until [[ -n "$username" ]]; do
		echo "用户名不能为空。"
		read -p "用户名: " username
	done
	
	echo "请输入新用户的密码:"
	read -s -p "密码: " password
	echo
	until [[ -n "$password" ]]; do
		echo "密码不能为空。"
		read -s -p "密码: " password
		echo
	done
	
	# 检查用户是否已存在
	if grep -q "^$username:" /etc/openvpn/server/psw-file; then
		echo "用户 $username 已存在！"
		return 1
	fi
	
	# 添加用户到密码文件
	echo "$username:$(openssl passwd -1 "$password")" >> /etc/openvpn/server/psw-file
	echo "用户 $username 添加成功！"
}

del_user() {
	echo
	echo "当前用户列表:"
	grep -v "^#" /etc/openvpn/server/psw-file | cut -d: -f1 | nl -s ') '
	
	echo "请输入要删除的用户名:"
	read -p "用户名: " username
	until [[ -n "$username" ]]; do
		echo "用户名不能为空。"
		read -p "用户名: " username
	done
	
	# 检查用户是否存在
	if ! grep -q "^$username:" /etc/openvpn/server/psw-file; then
		echo "用户 $username 不存在！"
		return 1
	fi
	
	# 删除用户
	sed -i "/^$username:/d" /etc/openvpn/server/psw-file
	echo "用户 $username 已删除！"
}

# 创建 RouterOS 兼容的客户端配置文件
create_routeros_config() {
	local client_name="$1"
	local config_file="$script_dir/${client_name}-routeros.ovpn"
	
	echo "client
dev tun
proto $protocol
remote $public_ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
auth SHA512
verb 3

<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>

key-direction 1
<tls-auth>
$(cat /etc/openvpn/server/ta.key)
</tls-auth>" > "$config_file"
	
	echo "RouterOS 兼容配置文件已创建: $config_file"
}

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	# 检测一些 Debian 最小化安装，其中既没有安装 wget 也没有安装 curl
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "使用此安装程序需要 Wget。"
		read -n1 -r -p "按任意键安装 Wget 并继续..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo '欢迎使用 OpenVPN 一键安装程序 (账号密码认证版)!'
	# 如果系统有单个 IPv4，则自动选择。否则，询问用户
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "应该使用哪个 IPv4 地址？"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 地址 [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: 无效选择。"
			read -p "IPv4 地址 [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# 如果 $ip 是私有 IP 地址，则服务器必须在 NAT 后面
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "此服务器位于 NAT 后面。公共 IPv4 地址或主机名是什么？"
		# 获取公共 IP 并使用 grep 清理
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "公共 IPv4 地址 / 主机名 [$get_public_ip]: " public_ip
		# 如果 checkip 服务不可用且用户没有提供输入，则再次询问
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "无效输入。"
			read -p "公共 IPv4 地址 / 主机名: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	else
		public_ip="$ip"
	fi
	# 如果系统有单个 IPv6，则自动选择
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# 如果系统有多个 IPv6，则让用户选择一个
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "应该使用哪个 IPv6 地址？"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 地址 [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: 无效选择。"
			read -p "IPv6 地址 [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "OpenVPN 应该使用哪种协议？"
	echo "   1) UDP (推荐)"
	echo "   2) TCP"
	read -p "协议 [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: 无效选择。"
		read -p "协议 [1]: " protocol
	done
	case "$protocol" in
		1|"") 
		protocol=udp
		;;
		2) 
		protocol=tcp
		;;
	esac
	echo
	echo "OpenVPN 应该监听哪个端口？"
	read -p "端口 [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: 无效端口。"
		read -p "端口 [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "为客户端选择 DNS 服务器："
	echo "   1) 默认系统解析器"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) Gcore"
	echo "   7) AdGuard"
	echo "   8) 指定自定义解析器"
	read -p "DNS 服务器 [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-8]$ ]]; do
		echo "$dns: 无效选择。"
		read -p "DNS 服务器 [1]: " dns
	done
	# 如果用户选择了自定义解析器，我们在这里处理
	if [[ "$dns" = "8" ]]; then
		echo
		until [[ -n "$custom_dns" ]]; do
			echo "输入 DNS 服务器（一个或多个 IPv4 地址，用逗号或空格分隔）："
			read -p "DNS 服务器: " dns_input
			# 将逗号分隔转换为空格分隔
			dns_input=$(echo "$dns_input" | tr ',' ' ')
			# 验证并构建自定义 DNS IP 列表
			for dns_ip in $dns_input; do
				if [[ "$dns_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
					if [[ -z "$custom_dns" ]]; then
						custom_dns="$dns_ip"
					else
						custom_dns="$custom_dns $dns_ip"
					fi
				fi
			done
			if [ -z "$custom_dns" ]; then
				echo "无效输入。"
			fi
		done
	fi
	echo
	echo "输入管理员账号:"
	read -p "用户名: " admin_user
	until [[ -n "$admin_user" ]]; do
		echo "用户名不能为空。"
		read -p "用户名: " admin_user
	done
	
	echo "输入管理员密码:"
	read -s -p "密码: " admin_pass
	echo
	until [[ -n "$admin_pass" ]]; do
		echo "密码不能为空。"
		read -s -p "密码: " admin_pass
		echo
	done
	
	echo
	echo "OpenVPN 安装准备开始。"
	# 安装一个防火墙如果 firewalld 或 iptables 不可用
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# 我们不想静默启用 firewalld，所以给出一个微妙的警告
			# 如果用户继续，firewalld 将在安装过程中安装并启用
			echo "将安装 firewalld，这是管理路由表所必需的。"
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables 比 firewalld 侵入性小得多，因此不给出警告
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "按任意键继续..."
	# 如果在容器内运行，禁用 LimitNPROC 以防止冲突
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
		apt-get update
		apt-get install -y --no-install-recommends openvpn openssl ca-certificates $firewall
	elif [[ "$os" = "centos" ]]; then
		dnf install -y epel-release
		dnf install -y openvpn openssl ca-certificates tar $firewall
	else
		# 否则，操作系统必须是 Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# 如果刚刚安装了 firewalld，则启用它
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# 获取 easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.4/EasyRSA-3.2.4.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# 创建 PKI，设置 CA 并创建 TLS 密钥
	./easyrsa --batch init-pki
	./easyrsa --batch build-ca nopass
	# 生成 tls-auth 密钥而不是 tls-crypt
	openvpn --genkey --secret /etc/openvpn/server/ta.key
	# 使用预定义的 ffdhe2048 组创建 DH 参数文件
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# 让 easy-rsa 知道我们的外部 DH 文件（防止警告）
	ln -s /etc/openvpn/server/dh.pem pki/dh.pem
	# 创建服务器证书
	./easyrsa --batch --days=3650 build-server-full server nopass
	
	# 创建密码文件
	mkdir -p /etc/openvpn/server/
	echo "# OpenVPN 用户账号密码文件" > /etc/openvpn/server/psw-file
	echo "$admin_user:$(openssl passwd -1 "$admin_pass")" >> /etc/openvpn/server/psw-file
	chmod 600 /etc/openvpn/server/psw-file
	
	# 移动我们需要的文件
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	# CRL 在每次客户端连接时读取，而 OpenVPN 被降级为 nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# 如果没有目录的 +x 权限，OpenVPN 无法对 CRL 文件运行 stat()
	chmod o+x /etc/openvpn/server/
	# 生成 server.conf - 使用 tls-auth 而不是 tls-crypt
	echo "local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so openvpn
client-cert-not-required
username-as-common-name
auth-user-pass-verify /etc/openvpn/server/checkpsw.sh via-env
script-security 3" > /etc/openvpn/server/server.conf
	# IPv6
	if [[ -z "$ip6" ]]; then
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	else
		echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
		echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
	fi
	echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
	# DNS
	case "$dns" in
		1|"")
			# 定位正确的 resolv.conf
			# 对于运行 systemd-resolved 的系统需要
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# 从 resolv.conf 获取解析器并将其用于 OpenVPN
			grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/server/server.conf
			done
		;;
		2)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf
		;;
		3)
			echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf
		;;
		4)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf
		;;
		5)
			echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf
		;;
		6)
			echo 'push "dhcp-option DNS 95.85.95.85"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2.56.220.2"' >> /etc/openvpn/server/server.conf
		;;
		7)
			echo 'push "dhcp-option DNS 94.140.14.14"' >> /etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >> /etc/openvpn/server/server.conf
		;;
		8)
		for dns_ip in $custom_dns; do
			echo "push \"dhcp-option DNS $dns_ip\"" >> /etc/openvpn/server/server.conf
		done
		;;
	esac
	echo 'push "block-outside-dns"' >> /etc/openvpn/server/server.conf
	echo "keepalive 10 120
user nobody
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >> /etc/openvpn/server/server.conf
	if [[ "$protocol" = "udp" ]]; then
		echo "explicit-exit-notify" >> /etc/openvpn/server/server.conf
	fi
	
	# 创建密码验证脚本
	echo '#!/bin/bash
if [ ! -r /etc/openvpn/server/psw-file ]; then
    echo "无法读取密码文件" >&2
    exit 1
fi

PASSFILE="/etc/openvpn/server/psw-file"
username=$1
password=$2

if [ -z "$username" ] || [ -z "$password" ]; then
    echo "用户名或密码为空" >&2
    exit 1
fi

if ! grep -q "^${username}:" "$PASSFILE"; then
    echo "用户名不存在" >&2
    exit 1
fi

stored_hash=$(grep "^${username}:" "$PASSFILE" | cut -d: -f2)
if [ "$(openssl passwd -1 "$password")" != "$stored_hash" ]; then
    echo "密码错误" >&2
    exit 1
fi

exit 0' > /etc/openvpn/server/checkpsw.sh
	
	chmod +x /etc/openvpn/server/checkpsw.sh
	
	# 为系统启用 net.ipv4.ip_forward
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# 无需等待重启或服务重新启动即可启用
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# 为系统启用 net.ipv6.conf.all.forwarding
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		# 无需等待重启或服务重新启动即可启用
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# 同时使用永久和非永久规则以避免 firewalld 重新加载。
		# 我们不使用 --add-service=openvpn，因为这仅适用于默认端口和协议。
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# 为 VPN 子网设置 NAT
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# 创建一个服务来设置持久的 iptables 规则
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables 在 OVZ 内核中不作为标准提供。所以如果我们是在 OVZ 中，
		# 使用 nf_tables 后端并且 iptables-legacy 可用，则使用 iptables-legacy。
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -w 5 -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -w 5 -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 10.8.0.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/openvpn-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:1194:1194:1194::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/openvpn-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/openvpn-iptables.service
		systemctl enable --now openvpn-iptables.service
	fi
	# 如果启用了 SELinux 并且选择了自定义端口，我们需要这个
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# 如果尚未安装 semanage，则安装
		if ! hash semanage 2>/dev/null; then
				dnf install -y policycoreutils-python-utils
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# 如果服务器位于 NAT 后面，使用正确的 IP 地址
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# 创建 client-common.txt
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
auth SHA512
verb 3" > /etc/openvpn/server/client-common.txt
	
	# 创建标准客户端配置文件
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
auth SHA512
verb 3

<ca>
$(cat /etc/openvpn/server/ca.crt)
</ca>

key-direction 1
<tls-auth>
$(cat /etc/openvpn/server/ta.key)
</tls-auth>" > "$script_dir"/client.ovpn

	# 创建 RouterOS 兼容的客户端配置文件
	create_routeros_config "client"
	
	echo
	echo "完成！"
	echo
	echo "管理员账号已创建: $admin_user"
	echo "标准客户端配置文件位于: $script_dir/client.ovpn"
	echo "RouterOS 兼容配置文件位于: $script_dir/client-routeros.ovpn"
	echo "可以通过再次运行此脚本来添加新用户。"
else
	clear
	echo "OpenVPN 已经安装。"
	echo
	echo "选择一个选项："
	echo "   1) 添加新用户"
	echo "   2) 删除用户"
	echo "   3) 为现有用户生成 RouterOS 兼容配置文件"
	echo "   4) 移除 OpenVPN"
	echo "   5) 退出"
	read -p "选项: " option
	until [[ "$option" =~ ^[1-5]$ ]]; do
		echo "$option: 无效选择。"
		read -p "选项: " option
	done
	case "$option" in
		1)
			add_user
		;;
		2)
			del_user
		;;
		3)
			echo
			echo "为哪个用户生成 RouterOS 兼容配置文件？"
			read -p "用户名: " username
			if grep -q "^$username:" /etc/openvpn/server/psw-file; then
				create_routeros_config "$username"
			else
				echo "用户 $username 不存在！"
			fi
		;;
		4)
			echo
			read -p "确认移除 OpenVPN？[y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: 无效选择。"
				read -p "确认移除 OpenVPN？[y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
					# 同时使用永久和非永久规则以避免 firewalld 重新加载。
					firewall-cmd --remove-port="$port"/"$protocol"
					firewall-cmd --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --permanent --remove-port="$port"/"$protocol"
					firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
					if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now openvpn-iptables.service
					rm -f /etc/systemd/system/openvpn-iptables.service
				fi
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
					semanage port -d -t openvpn_port_t -p "$protocol" "$port"
				fi
				systemctl disable --now openvpn-server@server.service
				rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/99-openvpn-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					rm -rf /etc/openvpn/server
					apt-get remove --purge -y openvpn
				else
					# 否则，操作系统必须是 CentOS 或 Fedora
					dnf remove -y openvpn
					rm -rf /etc/openvpn/server
				fi
				echo
				echo "OpenVPN 已移除！"
			else
				echo
				echo "OpenVPN 移除已取消！"
			fi
			exit
		;;
		5)
			exit
		;;
	esac
fi