#!/bin/bash
#
#

# --- UI Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# --- Helper Functions ---
function header() {
	clear
	echo -e "${GREEN}=================================================${NC}"
	echo -e "${CYAN}   OPENVPN MANAGER v3.3 (Fast & Multi-Link)      ${NC}"
	echo -e "${GREEN}=================================================${NC}"
	echo ""
}

function show_dashboard() {
	echo -e "${PURPLE}--- SERVICE STATUS ---${NC}"
	
	# 1. OpenVPN Status
	if systemctl is-active --quiet openvpn-server@server.service; then
		ovpn_status="${GREEN}ACTIVE${NC}"
		ovpn_port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
		ovpn_proto=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
		
		# Check duplicate-cn status
		if grep -q "^duplicate-cn" /etc/openvpn/server/server.conf; then
			login_mode="${GREEN}Multi-Device${NC}"
		else
			login_mode="${YELLOW}Single-Device${NC}"
		fi
	else
		ovpn_status="${RED}INACTIVE${NC}"
		ovpn_port="N/A"
		ovpn_proto=""
		login_mode="N/A"
	fi
	echo -e "OpenVPN:  $ovpn_status  [Port: $ovpn_port/$ovpn_proto] [Mode: $login_mode]"

	# 2. Squid Status
	if hash squid 2>/dev/null && systemctl is-active --quiet squid; then
		squid_status="${GREEN}ACTIVE${NC}"
		# Extract ports from squid.conf (simple grep)
		squid_ports=$(grep "^http_port" /etc/squid/squid.conf | awk '{print $2}' | tr '\n' ' ')
	elif hash squid 2>/dev/null; then
		squid_status="${RED}STOPPED${NC}"
		squid_ports="N/A"
	else
		squid_status="${YELLOW}NOT INSTALLED${NC}"
		squid_ports=""
	fi
	echo -e "Squid:    $squid_status  [Ports: $squid_ports]"

	# 3. Web Host Status (Apache Port 81)
	web_service="apache2"
	if [[ "$os" == "centos" || "$os" == "fedora" ]]; then web_service="httpd"; fi
	
	if systemctl is-active --quiet $web_service; then
		# Check if our config exists
		if [[ -f /etc/apache2/sites-enabled/ovpn-port81.conf || -f /etc/httpd/conf.d/ovpn-port81.conf ]]; then
			web_status="${GREEN}ACTIVE${NC}"
			web_port="81"
		else
			web_status="${YELLOW}RUNNING (No VPN Config)${NC}"
			web_port="80/443"
		fi
	else
		web_status="${RED}INACTIVE${NC}"
		web_port="N/A"
	fi
	echo -e "Hosting:  $web_status  [Port: $web_port]"
	echo -e "${PURPLE}----------------------${NC}"
	echo ""
}

function toggle_duplicate_cn() {
	echo
	echo -e "${CYAN}Toggling Multi-Login Settings...${NC}"
	
	if grep -q "^duplicate-cn" /etc/openvpn/server/server.conf; then
		# Currently Enabled -> Disable it
		sed -i 's/^duplicate-cn/;duplicate-cn/' /etc/openvpn/server/server.conf
		echo -e "Status changed to: ${YELLOW}Single-Device Only${NC}"
		echo "Users can now only connect from one device at a time."
	else
		# Currently Disabled -> Enable it
		if grep -q "^;duplicate-cn" /etc/openvpn/server/server.conf; then
			sed -i 's/^;duplicate-cn/duplicate-cn/' /etc/openvpn/server/server.conf
		else
			echo "duplicate-cn" >> /etc/openvpn/server/server.conf
		fi
		echo -e "Status changed to: ${GREEN}Multi-Device Allowed${NC}"
		echo "Users can now connect multiple devices simultaneously."
	fi
	
	# Restart OpenVPN
	systemctl restart openvpn-server@server.service
	echo "OpenVPN restarted to apply changes."
	read -n1 -r -p "Press any key to return to menu..."
}

function setup_web_hosting() {
	# Ensure storage directory exists
	mkdir -p /var/www/ovpn-config
	chmod 755 /var/www/ovpn-config
	
	# SECURITY: Create a blank index.html to prevent directory listing of the root folder
	touch /var/www/ovpn-config/index.html

	# Only run firewall checks if port 81 isn't already open (Speeds up the loop)
	# Simple check using netstat or ss to see if 81 is listening isn't enough for firewall,
	# but we can assume if the VHost file exists, we did this already.
	
	config_exists=false
	if [[ -f /etc/apache2/sites-enabled/ovpn-port81.conf || -f /etc/httpd/conf.d/ovpn-port81.conf ]]; then
		config_exists=true
	fi

	if [ "$config_exists" = false ]; then
		echo "Configuring Web Hosting for first time..."

		# 1. Check UFW (Ubuntu Common)
		if hash ufw 2>/dev/null && systemctl is-active --quiet ufw; then
			ufw allow 81/tcp >/dev/null
		fi

		# 2. Check Firewalld (CentOS/RHEL Common)
		if systemctl is-active --quiet firewalld.service; then
			if ! firewall-cmd --zone=public --list-ports | grep -q "81/tcp"; then
				firewall-cmd --zone=public --add-port=81/tcp
				firewall-cmd --permanent --zone=public --add-port=81/tcp
			fi
		else
			# 3. IPTABLES (Fallback)
			if ! iptables -C INPUT -p tcp --dport 81 -j ACCEPT 2>/dev/null; then
				iptables -I INPUT -p tcp --dport 81 -j ACCEPT
			fi
		fi
	fi

	# --- Apache Configuration ---
	if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
		# Install Apache if missing
		if ! hash apache2 2>/dev/null; then
			echo "Installing Apache2..."
			apt-get update
			apt-get install -y apache2
		fi
		
		# Only configure if missing
		if [[ ! -f /etc/apache2/sites-available/ovpn-port81.conf ]]; then
			a2enmod headers > /dev/null 2>&1
			if ! grep -q "Listen 81" /etc/apache2/ports.conf; then
				echo "Listen 81" >> /etc/apache2/ports.conf
			fi
			cat <<EOF > /etc/apache2/sites-available/ovpn-port81.conf
<VirtualHost *:81>
    DocumentRoot /var/www/ovpn-config
    <Directory /var/www/ovpn-config>
        Options +Indexes
        Require all granted
        <FilesMatch "\.(ovpn|zip)$">
            ForceType application/octet-stream
            Header set Content-Disposition attachment
        </FilesMatch>
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/ovpn-error.log
    CustomLog \${APACHE_LOG_DIR}/ovpn-access.log combined
</VirtualHost>
EOF
			ln -s /etc/apache2/sites-available/ovpn-port81.conf /etc/apache2/sites-enabled/
			systemctl restart apache2
		fi
	else
		# CentOS / Fedora / RHEL
		if ! hash httpd 2>/dev/null; then
			echo "Installing Apache (httpd)..."
			dnf install -y httpd
		fi
		
		if [[ ! -f /etc/httpd/conf.d/ovpn-port81.conf ]]; then
			if ! grep -q "Listen 81" /etc/httpd/conf/httpd.conf; then
				echo "Listen 81" >> /etc/httpd/conf/httpd.conf
			fi
			cat <<EOF > /etc/httpd/conf.d/ovpn-port81.conf
<VirtualHost *:81>
    DocumentRoot /var/www/ovpn-config
    <Directory /var/www/ovpn-config>
        Options +Indexes
        Require all granted
        <FilesMatch "\.(ovpn|zip)$">
            ForceType application/octet-stream
            Header set Content-Disposition attachment
        </FilesMatch>
    </Directory>
</VirtualHost>
EOF
			systemctl enable --now httpd
			systemctl restart httpd
		fi
	fi
}

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from a one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OS
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
	echo "This installer seems to be running on an unsupported distribution."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
	echo "Ubuntu 22.04 or higher is required to use this installer."
	exit
fi

if [[ "$os" == "debian" ]]; then
	if grep -q '/sid' /etc/debian_version; then
		echo "Debian Testing and Debian Unstable are unsupported by this installer."
		exit
	fi
	if [[ "$os_version" -lt 11 ]]; then
		echo "Debian 11 or higher is required to use this installer."
		exit
	fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
	os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
	echo "$os_name 9 or higher is required to use this installer."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available."
	exit
fi

# Store the directory where the .ovpn files will be saved (User's Home)
script_dir="$HOME"

# --- Squid Logic ---
function install_squid() {
	header
	echo -e "${CYAN}Installing Smart Squid Proxy (Force-to-VPN)...${NC}"
	
	# 1. Get OpenVPN Info
	ovpn_port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
	ovpn_proto=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)

	# WARNING FOR UDP
	if [[ "$ovpn_proto" == "udp" ]]; then
		echo
		echo -e "${RED}WARNING: Your OpenVPN server is using UDP.${NC}"
		echo -e "${YELLOW}Squid can only tunnel TCP. The 'Smart Proxy' redirection will likely FAIL${NC}"
		echo -e "${YELLOW}because it tries to redirect TCP proxy traffic to a UDP listener.${NC}"
		echo "It is highly recommended to reinstall OpenVPN with TCP protocol for this to work."
		read -p "Do you want to proceed anyway? [y/N]: " proceed_udp
		if [[ ! "$proceed_udp" =~ ^[yY]$ ]]; then
			echo "Aborted."
			return
		fi
	fi

	# 2. Install packages
	if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
		apt-get update
		apt-get install -y squid
		# Debian/Ubuntu uses 'proxy' user for squid usually
		squid_user="proxy"
	else
		dnf install -y squid
		# RHEL/CentOS uses 'squid' user
		squid_user="squid"
	fi

	# Verify Squid User Exists
	if ! id "$squid_user" >/dev/null 2>&1; then
		# Fallback check
		if id "squid" >/dev/null 2>&1; then
			squid_user="squid"
		elif id "proxy" >/dev/null 2>&1; then
			squid_user="proxy"
		fi
	fi

	# 3. Ask for Ports (Multiple allowed)
	echo
	echo "Enter the ports Squid should listen on, separated by spaces."
	read -p "Ports [3128 8080]: " squid_ports_input
	[[ -z "$squid_ports_input" ]] && squid_ports_input="3128 8080"

	# 4. Build Squid Config
	mv /etc/squid/squid.conf /etc/squid/squid.conf.bak 2>/dev/null

	# SMART CONFIG:
	cat <<EOF > /etc/squid/squid.conf
# Access Control
# Allow localhost
acl localhost src 127.0.0.1/32
http_access allow localhost

# Allow All (Secured by IPTABLES Redirection to VPN)
# We must allow 'all' so Squid attempts the connection, allowing iptables to grab it.
acl all src all
http_access allow all

# Ports
EOF

	# Add http_port lines for each port specified
	for port in $squid_ports_input; do
		echo "http_port $port" >> /etc/squid/squid.conf
	done

	# Add remaining config
	cat <<EOF >> /etc/squid/squid.conf

coredump_dir /var/spool/squid
refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0
refresh_pattern .		0	20%	4320
EOF

	# 5. FIX OPENVPN BINDING (CRITICAL FOR REDIRECT TO LOCALHOST)
	# If 'local IP' is set, OpenVPN ignores traffic redirected to 127.0.0.1
	if grep -q "^local " /etc/openvpn/server/server.conf; then
		echo
		echo -e "${YELLOW}Configuring OpenVPN to listen on all interfaces (required for localhost redirect)...${NC}"
		# Comment out the local line
		sed -i 's/^local /;local /' /etc/openvpn/server/server.conf
		# Restart OpenVPN to apply
		systemctl restart openvpn-server@server.service
		echo -e "${GREEN}OpenVPN restarted.${NC}"
	fi

	# 6. Firewall & Redirection Logic
	if systemctl is-active --quiet firewalld.service; then
		# FIREWALLD
		for port in $squid_ports_input; do
			firewall-cmd --zone=public --add-port="$port"/tcp
			firewall-cmd --permanent --zone=public --add-port="$port"/tcp
		done
		
		# Add Direct Rule for Redirection
		firewall-cmd --permanent --direct --add-rule ipv4 nat OUTPUT 0 -p tcp -m owner --uid-owner "$squid_user" -j REDIRECT --to-ports "$ovpn_port"
		firewall-cmd --reload
	else
		# IPTABLES
		# Open Input Ports
		for port in $squid_ports_input; do
			iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
		done
		
		# Add Redirection Rule immediately
		iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner "$squid_user" -j REDIRECT --to-ports "$ovpn_port"

		# Persist in a separate service file
		echo "[Unit]
Description=Squid Smart Proxy Redirection
After=network.target

[Service]
Type=oneshot
ExecStart=$(command -v iptables) -t nat -A OUTPUT -p tcp -m owner --uid-owner $squid_user -j REDIRECT --to-ports $ovpn_port
ExecStop=$(command -v iptables) -t nat -D OUTPUT -p tcp -m owner --uid-owner $squid_user -j REDIRECT --to-ports $ovpn_port
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/squid-redirect.service

		systemctl enable --now squid-redirect.service
	fi

	# Enable and Start Squid
	systemctl enable squid
	systemctl restart squid

	echo
	echo -e "${GREEN}Smart Squid Proxy Installed on ports: $squid_ports_input${NC}"
	echo -e "${YELLOW}Traffic from Squid is now redirected to OpenVPN (Port $ovpn_port).${NC}"
	echo -e "OpenVPN has been configured to listen on ALL interfaces to accept this traffic."
	read -n1 -r -p "Press any key to continue..."
}

function remove_squid() {
	header
	read -p "Confirm Squid removal? [y/N]: " confirm
	if [[ "$confirm" =~ ^[yY]$ ]]; then
		
		# 1. Remove Redirect Rules
		# Detect Squid user again just in case
		if grep -q "proxy" /etc/passwd; then squid_user="proxy"; else squid_user="squid"; fi
		ovpn_port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)

		if systemctl is-active --quiet firewalld.service; then
			firewall-cmd --permanent --direct --remove-rule ipv4 nat OUTPUT 0 -p tcp -m owner --uid-owner "$squid_user" -j REDIRECT --to-ports "$ovpn_port" 2>/dev/null
			firewall-cmd --reload
		else
			# Disable the separate service we created
			if [[ -f /etc/systemd/system/squid-redirect.service ]]; then
				systemctl disable --now squid-redirect.service
				rm -f /etc/systemd/system/squid-redirect.service
				# Also clean up the running rule just in case
				iptables -t nat -D OUTPUT -p tcp -m owner --uid-owner "$squid_user" -j REDIRECT --to-ports "$ovpn_port" 2>/dev/null
			fi
		fi

		# 2. Remove Package
		if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			apt-get remove --purge -y squid
		else
			dnf remove -y squid
		fi
		rm -rf /etc/squid
		echo -e "${GREEN}Squid removed.${NC}"
	else
		echo "Cancelled."
	fi
	read -n1 -r -p "Press any key to continue..."
}


if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	# ... existing code for installation ...
	header
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	
	echo -e "Welcome to the OpenVPN installer!"
	echo -e "I will ask you a few questions to setup the server."
	echo ""

	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "Which protocol should OpenVPN use?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1]: " protocol
	until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
		echo "$protocol: invalid selection."
		read -p "Protocol [1]: " protocol
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
	echo "What port should OpenVPN listen on?"
	read -p "Port [1194]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [1194]: " port
	done
	[[ -z "$port" ]] && port="1194"
	echo
	echo "Select a DNS server for the clients:"
	echo "   1) Default system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) Gcore"
	echo "   7) AdGuard"
	echo "   8) Specify custom resolvers"
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-8]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
	# If the user selected custom resolvers, we deal with that here
	if [[ "$dns" = "8" ]]; then
		echo
		until [[ -n "$custom_dns" ]]; do
			echo "Enter DNS servers (one or more IPv4 addresses, separated by commas or spaces):"
			read -p "DNS servers: " dns_input
			# Convert comma delimited to space delimited
			dns_input=$(echo "$dns_input" | tr ',' ' ')
			# Validate and build custom DNS IP list
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
				echo "Invalid input."
			fi
		done
	fi
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	echo -e "${GREEN}OpenVPN installation is ready to begin.${NC}"
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
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
		# Else, OS must be Fedora
		dnf install -y openvpn openssl ca-certificates tar $firewall
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Get easy-rsa
	easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.4/EasyRSA-3.2.4.tgz'
	mkdir -p /etc/openvpn/server/easy-rsa/
	{ wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
	chown -R root:root /etc/openvpn/server/easy-rsa/
	cd /etc/openvpn/server/easy-rsa/
	# Create the PKI, set up the CA and create TLS key
	./easyrsa --batch init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-tls-crypt-key
	# Create the DH parameters file using the predefined ffdhe2048 group
	echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
	# Make easy-rsa aware of our external DH file (prevents a warning)
	ln -s /etc/openvpn/server/dh.pem pki/dh.pem
	# Create certificates and CRL
	./easyrsa --batch --days=3650 build-server-full server nopass
	./easyrsa --batch --days=3650 build-client-full "$client" nopass
	./easyrsa --batch --days=3650 gen-crl
	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
	cp pki/private/easyrsa-tls.key /etc/openvpn/server/tc.key
	# CRL is read with each client connection, while OpenVPN is dropped to nobody
	chown nobody:"$group_name" /etc/openvpn/server/crl.pem
	# Without +x in the directory, OpenVPN can't run a stat() on the CRL file
	chmod o+x /etc/openvpn/server/
	# Generate server.conf (MODIFIED to listen on 0.0.0.0 by default for future compatibility)
	# We leave the 'local' parameter commented out so it binds to all interfaces.
	# MULTI-LOGIN (duplicate-cn) is ENABLED by default here.
	echo ";local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0
duplicate-cn" > /etc/openvpn/server/server.conf
    
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
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
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
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		# We don't use --add-service=openvpn because that would only work with
		# the default port and protocol.
		firewall-cmd --add-port="$port"/"$protocol"
		firewall-cmd --zone=trusted --add-source=10.8.0.0/24
		firewall-cmd --permanent --add-port="$port"/"$protocol"
		firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
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
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
				dnf install -y policycoreutils-python-utils
		fi
		semanage port -a -t openvpn_port_t -p "$protocol" "$port"
	fi
	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"
	# client-common.txt is created so we have a template to add further users later
	echo "client
dev tun
proto $protocol
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
ignore-unknown-option block-outside-dns
verb 3" > /etc/openvpn/server/client-common.txt
	# Enable and start the OpenVPN service
	systemctl enable --now openvpn-server@server.service
	# Build the $client.ovpn file, stripping comments from easy-rsa in the process
	grep -vh '^#' /etc/openvpn/server/client-common.txt /etc/openvpn/server/easy-rsa/pki/inline/private/"$client".inline > "$script_dir"/"$client".ovpn
	echo
	echo -e "${GREEN}Finished!${NC}"
	echo
	echo -e "The client configuration is available in: ${CYAN}$script_dir/$client.ovpn${NC}"
	echo "You can manage users by typing 'ovpn' command."
else
	# START OF MENU LOOP
	while true; do
		header
		
		# SHOW DASHBOARD
		show_dashboard

		# Check if Squid is installed
		squid_installed=false
		if hash squid 2>/dev/null; then
			squid_installed=true
		fi
		
		echo "Select an option:"
		echo -e "   1) ${GREEN}Add a new VPN client${NC}"
		echo -e "   2) ${YELLOW}Revoke an existing VPN client${NC}"
		echo -e "   3) ${PURPLE}Toggle Multi-Login (Currently: $login_mode)${NC}"
		
		if [ "$squid_installed" = true ]; then
			echo -e "   4) ${RED}Remove Squid Proxy${NC}"
		else
			echo -e "   4) ${CYAN}Install Squid Proxy${NC}"
		fi

		echo -e "   5) ${RED}Remove OpenVPN & Web Host${NC}"
		echo -e "   6) ${CYAN}Exit${NC}"
		
		read -p "Option: " option
		until [[ "$option" =~ ^[1-6]$ ]]; do
			echo "$option: invalid selection."
			read -p "Option: " option
		done
		case "$option" in
			1)
				echo
				echo "Provide a name for the client:"
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
				while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
					echo "$client: invalid name."
					read -p "Name: " unsanitized_client
					client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
				done
				cd /etc/openvpn/server/easy-rsa/
				./easyrsa --batch --days=3650 build-client-full "$client" nopass
				
				# 1. Build the STANDARD .ovpn file (No Proxy)
				grep -vh '^#' /etc/openvpn/server/client-common.txt /etc/openvpn/server/easy-rsa/pki/inline/private/"$client".inline > "$script_dir"/"$client".ovpn
				
				# Default File (Standard)
				# We don't use $file_to_host variable anymore, we copy both explicitly.

				# --- PROXY SUPPORT LOGIC (AUTO-GENERATE SECOND FILE) ---
				if hash squid 2>/dev/null; then
					echo
					echo -e "${CYAN}Squid Proxy is detected.${NC}"
					read -p "Do you want to generate a second config WITH Proxy settings? [y/N]: " gen_proxy_file
					if [[ "$gen_proxy_file" =~ ^[yY]$ ]]; then
						
						# Get public IP for proxy
						proxy_ip=$(grep "remote " /etc/openvpn/server/client-common.txt | awk '{print $2}')
						
						# Ask for Port
						echo
						echo "Enter the Proxy Port you want to use."
						read -p "Port [8080]: " proxy_port
						[[ -z "$proxy_port" ]] && proxy_port="8080"

						# Ask for Custom Header Host (Bug Host)
						echo
						echo "Enter Custom Header Host (e.g. m.youtube.com for spoofing):"
						read -p "Host [m.youtube.com]: " proxy_host
						[[ -z "$proxy_host" ]] && proxy_host="m.youtube.com"
						
						# Create Header String
						proxy_config_string="http-proxy $proxy_ip $proxy_port
http-proxy-option VERSION 1.1
http-proxy-option AGENT OpenVPN
http-proxy-option CUSTOM-HEADER Host $proxy_host
http-proxy-option CUSTOM-HEADER X-Forwarded-For $proxy_host
"
						# Generate the Proxy Config File
						echo "$proxy_config_string" > "$script_dir"/"$client"-Proxy.ovpn
						cat "$script_dir"/"$client".ovpn >> "$script_dir"/"$client"-Proxy.ovpn
						
						echo -e "${GREEN}Generated: $client-Proxy.ovpn${NC}"
					fi
				fi
				# ---------------------------

				# --- APACHE HOSTING LOGIC ---
				setup_web_hosting
				
				# GENERATE RANDOM PATH (SECURITY OBFUSCATION)
				random_path=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
				
				# Create the random directory inside the webroot
				mkdir -p "/var/www/ovpn-config/$random_path"
				
				# Copy Standard File
				cp "$script_dir/$client.ovpn" "/var/www/ovpn-config/$random_path/$client.ovpn"
				
				# Copy Proxy File if exists
				if [[ -f "$script_dir/$client-Proxy.ovpn" ]]; then
					cp "$script_dir/$client-Proxy.ovpn" "/var/www/ovpn-config/$random_path/$client-Proxy.ovpn"
				fi
				
				# Get Public IP
				if [[ -f /etc/openvpn/server/client-common.txt ]]; then
					host_ip=$(grep "remote " /etc/openvpn/server/client-common.txt | awk '{print $2}')
				else
					host_ip=$(wget -4qO- "http://ip1.dynupdate.no-ip.com/")
				fi

				echo
				echo -e "${GREEN}$client added.${NC}"
				echo -e "------------------------------------------------"
				echo -e "Standard Config:"
				echo -e "${YELLOW}http://$host_ip:81/$random_path/$client.ovpn${NC}"
				
				if [[ -f "$script_dir/$client-Proxy.ovpn" ]]; then
					echo -e "------------------------------------------------"
					echo -e "Proxy Config:"
					echo -e "${YELLOW}http://$host_ip:81/$random_path/$client-Proxy.ovpn${NC}"
				fi
				echo -e "------------------------------------------------"
				
				read -n1 -r -p "Press any key to return to menu..."
				;;
			2)
				# This option could be documented a bit better and maybe even be simplified
				# ...but what can I say, I want some sleep too
				number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
				if [[ "$number_of_clients" = 0 ]]; then
					echo
					echo "There are no existing clients!"
					read -n1 -r -p "Press any key to return to menu..."
				else
					echo
					echo "Select the client to revoke:"
					tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
					read -p "Client: " client_number
					until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
						echo "$client_number: invalid selection."
						read -p "Client: " client_number
					done
					client=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
					echo
					echo -e "${YELLOW}WARNING: This will disconnect the user $client immediately.${NC}"
					read -p "Confirm $client revocation? [y/N]: " revoke
					until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
						echo "$revoke: invalid selection."
						read -p "Confirm $client revocation? [y/N]: " revoke
					done
					if [[ "$revoke" =~ ^[yY]$ ]]; then
						cd /etc/openvpn/server/easy-rsa/
						./easyrsa --batch revoke "$client"
						./easyrsa --batch --days=3650 gen-crl
						rm -f /etc/openvpn/server/crl.pem
						rm -f /etc/openvpn/server/easy-rsa/pki/reqs/"$client".req
						rm -f /etc/openvpn/server/easy-rsa/pki/private/"$client".key
						cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
						# CRL is read with each client connection, when OpenVPN is dropped to nobody
						chown nobody:"$group_name" /etc/openvpn/server/crl.pem
						echo
						echo -e "${GREEN}$client revoked!${NC}"
					else
						echo
						echo "$client revocation aborted!"
					fi
					read -n1 -r -p "Press any key to return to menu..."
				fi
				;;
			3)
				toggle_duplicate_cn
				;;
			4)
				if [ "$squid_installed" = true ]; then
					remove_squid
				else
					# Install Squid
					install_squid
				fi
				;;
			5)
				echo
				echo -e "${RED}WARNING: This will remove OpenVPN and all configuration files.${NC}"
				read -p "Confirm OpenVPN removal? [y/N]: " remove
				until [[ "$remove" =~ ^[yYnN]*$ ]]; do
					echo "$remove: invalid selection."
					read -p "Confirm OpenVPN removal? [y/N]: " remove
				done
				if [[ "$remove" =~ ^[yY]$ ]]; then
					port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
					protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
					if systemctl is-active --quiet firewalld.service; then
						ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
						# Using both permanent and not permanent rules to avoid a firewalld reload.
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
						
						# CLEAN APACHE
						rm -f /etc/apache2/sites-enabled/ovpn-port81.conf
						rm -f /etc/apache2/sites-available/ovpn-port81.conf
						systemctl restart apache2
					else
						# Else, OS must be CentOS or Fedora
						dnf remove -y openvpn
						rm -rf /etc/openvpn/server
						
						# CLEAN APACHE
						rm -f /etc/httpd/conf.d/ovpn-port81.conf
						systemctl restart httpd
					fi
					
					# Clean Web Directory
					rm -rf /var/www/ovpn-config

					echo
					echo -e "${GREEN}OpenVPN & Web Hosting Config removed!${NC}"
					# Optional: Remove the ovpn command itself
					rm -f /usr/local/bin/ovpn
					echo "Manager command 'ovpn' removed."
					exit
				else
					echo
					echo "OpenVPN removal aborted!"
				fi
				;;
			6)
				exit 0
				;;
		esac
	done
fi
