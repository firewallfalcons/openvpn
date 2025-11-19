#!/bin/bash
#
# https://github.com/Nyr/openvpn-install
# 
# Modified for 'ovpn' command, Pro UI, Secure Squid + file.io Upload
#

# --- Global Constants ---
LOG_FILE="/root/ovpn-install.log"

# --- UI Colors & Styling ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# --- Helper Functions ---

function log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

function info() {
    echo -e "${BLUE}[i]${NC} $1"
    log "INFO: $1"
}

function success() {
    echo -e "${GREEN}[✓]${NC} $1"
    log "SUCCESS: $1"
}

function warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log "WARNING: $1"
}

function error() {
    echo -e "${RED}[✗]${NC} $1"
    log "ERROR: $1"
}

function critical_error() {
    echo -e "${RED}[✗] FATAL ERROR:${NC} $1"
    echo -e "    Check log file: $LOG_FILE"
    log "FATAL: $1"
    exit 1
}

function header() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "   ___                   _   _ ___  _   _ "
    echo "  / _ \ _ __   ___ _ __ | \ | | _ \| \ | |"
    echo " | | | | '_ \ / _ \ '_ \|  \| | |_) |  \| |"
    echo " | |_| | |_) |  __/ | | | |\  |  __/| |\  |"
    echo "  \___/| .__/ \___|_| |_|_| \_|_|   |_| \_|"
    echo "       |_|   MANAGER v2.6 (Pro Edition)"
    echo -e "${NC}"
    echo "  Secure Squid Proxy | File.io Upload | Multi-Port"
    echo "  ─────────────────────────────────────────────"
    echo ""
}

# --- Initial Checks ---

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
    echo 'This installer needs to be run with "bash", not "sh".'
    exit
fi

# Discard stdin
read -N 999999 -t 0.001

# Create Log File
touch "$LOG_FILE"

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

script_dir="$HOME"

# Detect IP (Used for Squid ACLs later)
if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
    ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
else
    # Fallback simple detection for variable availability if multiple IPs exist but user hasn't selected yet
    # The main install logic will refine this, but we need a value for Squid Option 3
    ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | head -1)
fi

# --- Logic Functions ---

function upload_config() {
    local file_path="$1"
    local file_name
    file_name=$(basename "$file_path")

    echo
    echo -e "${CYAN}>>> Cloud Share${NC}"
    echo "Do you want to upload '$file_name' to file.io?"
    echo -e "${YELLOW}Note: The generated link will expire after 1 download (secure share).${NC}"
    read -p "Upload? [y/N]: " confirm_upload

    if [[ "$confirm_upload" =~ ^[yY]$ ]]; then
        info "Uploading to file.io..."
        
        # Ensure curl
        if ! hash curl 2>/dev/null; then
            if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
                apt-get update >> "$LOG_FILE" 2>&1 && apt-get install -y curl >> "$LOG_FILE" 2>&1
            else
                dnf install -y curl >> "$LOG_FILE" 2>&1
            fi
        fi
        
        # Upload logic
        response=$(curl -s -F "file=@$file_path" https://file.io)
        
        # Parse JSON using grep/cut to avoid jq dependency
        upload_url=$(echo "$response" | grep -o '"link":"[^"]*"' | cut -d'"' -f4)
        
        if [[ -z "$upload_url" || "$upload_url" != http* ]]; then
            error "Upload failed. Response: $response"
        else
            echo
            success "Upload Successful!"
            echo "─────────────────────────────────────────────"
            echo -e "DOWNLOAD LINK: ${YELLOW}${BOLD}$upload_url${NC}"
            echo "─────────────────────────────────────────────"
            echo
        fi
    else
        info "Upload skipped."
    fi
}

function install_squid() {
    header
    info "Preparing Squid Proxy installation..."
    
    info "Installing Squid packages..."
    if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y squid >> "$LOG_FILE" 2>&1
    else
        dnf install -y squid >> "$LOG_FILE" 2>&1
    fi

    echo
    echo -e "${CYAN}>>> Configuration${NC}"
    echo "Enter Squid Listen Ports (space separated)."
    read -p "Ports [3128 8080]: " squid_ports_input
    [[ -z "$squid_ports_input" ]] && squid_ports_input="3128 8080"

    info "Configuring ACLs and Security Rules..."
    mv /etc/squid/squid.conf /etc/squid/squid.conf.bak 2>/dev/null

    # Build Secure Config
    # ALLOW: 127.0.0.0/8 (Localhost) and Current Public IP
    cat <<EOF > /etc/squid/squid.conf
# Define Access Lists
acl all src all
acl CONNECT method CONNECT

# Localhost (127.0.0.1) and Public IP
acl Local_IPs dst 127.0.0.0/8 ::1 $ip

# SECURITY RULES
# 1. Allow tunneling (CONNECT) to Localhost or Public IP on ANY PORT
#    (Allows SSH tunneling, OpenVPN, internal services)
http_access allow CONNECT Local_IPs

# 2. Deny everything else (Stops access to external internet)
http_access deny all

# Squid Listen Ports
EOF

    for port in $squid_ports_input; do
        echo "http_port $port" >> /etc/squid/squid.conf
    done

    # Standard Squid Boilerplate
    cat <<EOF >> /etc/squid/squid.conf

coredump_dir /var/spool/squid
refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0
refresh_pattern .		0	20%	4320
EOF

    info "Updating Firewall..."
    if systemctl is-active --quiet firewalld.service; then
        for port in $squid_ports_input; do
            firewall-cmd --zone=public --add-port="$port"/tcp >> "$LOG_FILE" 2>&1
            firewall-cmd --permanent --zone=public --add-port="$port"/tcp >> "$LOG_FILE" 2>&1
        done
    else
        for port in $squid_ports_input; do
            iptables -I INPUT -p tcp --dport "$port" -j ACCEPT
        done
    fi

    info "Restarting Squid Service..."
    systemctl enable squid >> "$LOG_FILE" 2>&1
    systemctl restart squid >> "$LOG_FILE" 2>&1

    echo
    success "Squid Proxy Installed & Secured."
    echo -e "    Ports: ${YELLOW}$squid_ports_input${NC}"
    echo -e "    Access: ${GREEN}Restricted to Localhost (127.0.0.1) & Server IP ($ip) ONLY${NC}"
    read -n1 -r -p "Press any key to continue..."
}

function remove_squid() {
    header
    warning "You are about to remove Squid Proxy."
    read -p "Confirm removal? [y/N]: " confirm
    if [[ "$confirm" =~ ^[yY]$ ]]; then
        info "Removing Squid packages..."
        if [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
            apt-get remove --purge -y squid >> "$LOG_FILE" 2>&1
        else
            dnf remove -y squid >> "$LOG_FILE" 2>&1
        fi
        rm -rf /etc/squid
        success "Squid removed successfully."
    else
        echo "Cancelled."
    fi
    read -n1 -r -p "Press any key to continue..."
}


# --- Main Install Logic ---

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
    header
    # Detect minimal setups
    if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
        echo "Wget is required to use this installer."
        read -n1 -r -p "Press any key to install Wget and continue..."
        apt-get update
        apt-get install -y wget
    fi
    
    echo -e "Welcome to the OpenVPN installer!"
    echo -e "Please answer a few questions to setup your server."
    echo ""

    # IP Detection (Main)
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
    
    # NAT
    if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
        echo
        echo "This server is behind NAT. What is the public IPv4 address or hostname?"
        get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
        read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
        until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
            echo "Invalid input."
            read -p "Public IPv4 address / hostname: " public_ip
        done
        [[ -z "$public_ip" ]] && public_ip="$get_public_ip"
    fi

    # IPv6
    if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
        ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
    fi
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

    # Protocol
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
        1|"") protocol=udp ;;
        2) protocol=tcp ;;
    esac

    # Port
    echo
    echo "What port should OpenVPN listen on?"
    read -p "Port [1194]: " port
    until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
        echo "$port: invalid port."
        read -p "Port [1194]: " port
    done
    [[ -z "$port" ]] && port="1194"

    # DNS
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
    if [[ "$dns" = "8" ]]; then
        echo
        until [[ -n "$custom_dns" ]]; do
            echo "Enter DNS servers (one or more IPv4 addresses, separated by commas or spaces):"
            read -p "DNS servers: " dns_input
            dns_input=$(echo "$dns_input" | tr ',' ' ')
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
    info "Starting OpenVPN installation..."
    info "Installing dependencies (this may take a minute)..."
    
    # Firewall Install Check
    if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
        if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
            firewall="firewalld"
        elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
            firewall="iptables"
        fi
    fi

    # Install Core Packages (Suppressed Output)
    if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
        apt-get update >> "$LOG_FILE" 2>&1
        apt-get install -y --no-install-recommends openvpn openssl ca-certificates $firewall >> "$LOG_FILE" 2>&1
    elif [[ "$os" = "centos" ]]; then
        dnf install -y epel-release >> "$LOG_FILE" 2>&1
        dnf install -y openvpn openssl ca-certificates tar $firewall >> "$LOG_FILE" 2>&1
    else
        dnf install -y openvpn openssl ca-certificates tar $firewall >> "$LOG_FILE" 2>&1
    fi

    if [[ "$firewall" == "firewalld" ]]; then
        systemctl enable --now firewalld.service >> "$LOG_FILE" 2>&1
    fi

    info "Setting up Easy-RSA..."
    easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.4/EasyRSA-3.2.4.tgz'
    mkdir -p /etc/openvpn/server/easy-rsa/
    { wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url" ; } | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components 1
    chown -R root:root /etc/openvpn/server/easy-rsa/
    cd /etc/openvpn/server/easy-rsa/
    
    # PKI Setup (Suppressed Output)
    info "Generating PKI and Keys..."
    ./easyrsa --batch init-pki >> "$LOG_FILE" 2>&1
    ./easyrsa --batch build-ca nopass >> "$LOG_FILE" 2>&1
    ./easyrsa gen-tls-crypt-key >> "$LOG_FILE" 2>&1
    
    # DH Params
    info "Generating Diffie-Hellman parameters..."
    echo '-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----' > /etc/openvpn/server/dh.pem
    ln -s /etc/openvpn/server/dh.pem pki/dh.pem

    # Certificates
    info "Signing certificates..."
    ./easyrsa --batch --days=3650 build-server-full server nopass >> "$LOG_FILE" 2>&1
    ./easyrsa --batch --days=3650 build-client-full "$client" nopass >> "$LOG_FILE" 2>&1
    ./easyrsa --batch --days=3650 gen-crl >> "$LOG_FILE" 2>&1
    
    # File Operations
    cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server
    cp pki/private/easyrsa-tls.key /etc/openvpn/server/tc.key
    chown nobody:"$group_name" /etc/openvpn/server/crl.pem
    chmod o+x /etc/openvpn/server/

    info "Writing server configuration..."
    echo "local $ip
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

    if [[ -z "$ip6" ]]; then
        echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    else
        echo 'server-ipv6 fddd:1194:1194:1194::/64' >> /etc/openvpn/server/server.conf
        echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >> /etc/openvpn/server/server.conf
    fi
    echo 'ifconfig-pool-persist ipp.txt' >> /etc/openvpn/server/server.conf
    
    # DNS Config
    case "$dns" in
        1|"")
            if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
                resolv_conf="/etc/resolv.conf"
            else
                resolv_conf="/run/systemd/resolve/resolv.conf"
            fi
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
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn-forward.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward
    if [[ -n "$ip6" ]]; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-openvpn-forward.conf
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi

    info "Applying Firewall Rules..."
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port="$port"/"$protocol" >> "$LOG_FILE" 2>&1
        firewall-cmd --zone=trusted --add-source=10.8.0.0/24 >> "$LOG_FILE" 2>&1
        firewall-cmd --permanent --add-port="$port"/"$protocol" >> "$LOG_FILE" 2>&1
        firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24 >> "$LOG_FILE" 2>&1
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip" >> "$LOG_FILE" 2>&1
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip" >> "$LOG_FILE" 2>&1
        if [[ -n "$ip6" ]]; then
            firewall-cmd --zone=trusted --add-source=fddd:1194:1194:1194::/64 >> "$LOG_FILE" 2>&1
            firewall-cmd --permanent --zone=trusted --add-source=fddd:1194:1194:1194::/64 >> "$LOG_FILE" 2>&1
            firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6" >> "$LOG_FILE" 2>&1
            firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6" >> "$LOG_FILE" 2>&1
        fi
    else
        iptables_path=$(command -v iptables)
        ip6tables_path=$(command -v ip6tables)
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
        systemctl enable --now openvpn-iptables.service >> "$LOG_FILE" 2>&1
    fi
    
    if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
        if ! hash semanage 2>/dev/null; then
                dnf install -y policycoreutils-python-utils >> "$LOG_FILE" 2>&1
        fi
        semanage port -a -t openvpn_port_t -p "$protocol" "$port" >> "$LOG_FILE" 2>&1
    fi
    [[ -n "$public_ip" ]] && ip="$public_ip"
    
    # Client Template
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
    
    systemctl enable --now openvpn-server@server.service >> "$LOG_FILE" 2>&1
    grep -vh '^#' /etc/openvpn/server/client-common.txt /etc/openvpn/server/easy-rsa/pki/inline/private/"$client".inline > "$script_dir"/"$client".ovpn
    
    # Ask for upload
    upload_config "$script_dir"/"$client".ovpn

    echo
    success "OpenVPN Setup Complete!"
    echo -e "    Client config: ${CYAN}$script_dir/$client.ovpn${NC}"
    echo "    Run 'ovpn' anytime to manage users."
else
    header
    
    # Check if Squid is installed
    squid_installed=false
    if hash squid 2>/dev/null; then
        squid_installed=true
    fi
    
    echo "Menu Selection:"
    echo -e "   1) ${GREEN}Add a new VPN client${NC}"
    echo -e "   2) ${YELLOW}Revoke an existing VPN client${NC}"
    
    if [ "$squid_installed" = true ]; then
        echo -e "   3) ${RED}Remove Squid Proxy${NC}"
    else
        echo -e "   3) ${CYAN}Install Squid Proxy${NC}"
    fi

    echo -e "   4) ${RED}Remove OpenVPN${NC}"
    echo -e "   5) ${CYAN}Exit${NC}"
    echo
    read -p "Option: " option
    until [[ "$option" =~ ^[1-5]$ ]]; do
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
            
            info "Generating client certificate..."
            ./easyrsa --batch --days=3650 build-client-full "$client" nopass >> "$LOG_FILE" 2>&1
            
            # Build the .ovpn file
            grep -vh '^#' /etc/openvpn/server/client-common.txt /etc/openvpn/server/easy-rsa/pki/inline/private/"$client".inline > "$script_dir"/"$client".ovpn

            # --- PROXY SUPPORT LOGIC (NO AUTH + HEADERS) ---
            if hash squid 2>/dev/null; then
                echo
                echo -e "${CYAN}>>> Proxy Configuration${NC}"
                echo "Squid Proxy is detected."
                read -p "Configure this client to tunnel through Squid? [y/N]: " use_proxy
                if [[ "$use_proxy" =~ ^[yY]$ ]]; then
                    # Check Protocol Warning
                    proto_check=$(grep "proto udp" /etc/openvpn/server/server.conf)
                    if [[ ! -z "$proto_check" ]]; then
                        warning "OpenVPN is using UDP. HTTP Proxies only tunnel TCP."
                        echo "    Connection may fail unless proxy supports UDP (uncommon)."
                        read -p "    Continue anyway? [y/N]: " confirm_proto
                        if [[ ! "$confirm_proto" =~ ^[yY]$ ]]; then
                            use_proxy="n"
                        fi
                    fi

                    if [[ "$use_proxy" =~ ^[yY]$ ]]; then
                        proxy_ip=$(grep "remote " /etc/openvpn/server/client-common.txt | awk '{print $2}')
                        
                        echo "Enter Proxy Port for this client."
                        read -p "Port [8080]: " proxy_port
                        [[ -z "$proxy_port" ]] && proxy_port="8080"

                        echo "Enter Custom Header Host (e.g. m.youtube.com for spoofing):"
                        read -p "Host [m.youtube.com]: " proxy_host
                        [[ -z "$proxy_host" ]] && proxy_host="m.youtube.com"
                        
                        # Add to .ovpn
                        echo "http-proxy $proxy_ip $proxy_port" >> "$script_dir"/"$client".ovpn
                        echo "http-proxy-option VERSION 1.1" >> "$script_dir"/"$client".ovpn
                        echo "http-proxy-option AGENT OpenVPN" >> "$script_dir"/"$client".ovpn
                        echo "http-proxy-option CUSTOM-HEADER Host $proxy_host" >> "$script_dir"/"$client".ovpn
                        echo "http-proxy-option CUSTOM-HEADER X-Forwarded-For $proxy_host" >> "$script_dir"/"$client".ovpn
                        
                        success "Proxy settings injected."
                    fi
                fi
            fi
            # ---------------------------
            
            # Ask for upload
            upload_config "$script_dir"/"$client".ovpn

            echo
            success "Client '$client' added."
            echo -e "    File: ${CYAN}$script_dir/$client.ovpn${NC}"
            exit
        ;;
        2)
            number_of_clients=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
            if [[ "$number_of_clients" = 0 ]]; then
                echo
                echo "There are no existing clients!"
                exit
            fi
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
            warning "This will disconnect user '$client' immediately."
            read -p "Confirm revocation? [y/N]: " revoke
            until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
                echo "$revoke: invalid selection."
                read -p "Confirm revocation? [y/N]: " revoke
            done
            if [[ "$revoke" =~ ^[yY]$ ]]; then
                cd /etc/openvpn/server/easy-rsa/
                ./easyrsa --batch revoke "$client" >> "$LOG_FILE" 2>&1
                ./easyrsa --batch --days=3650 gen-crl >> "$LOG_FILE" 2>&1
                rm -f /etc/openvpn/server/crl.pem
                rm -f /etc/openvpn/server/easy-rsa/pki/reqs/"$client".req
                rm -f /etc/openvpn/server/easy-rsa/pki/private/"$client".key
                cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
                chown nobody:"$group_name" /etc/openvpn/server/crl.pem
                echo
                success "$client revoked!"
            else
                echo
                echo "Revocation cancelled."
            fi
            exit
        ;;
        3)
            if [ "$squid_installed" = true ]; then
                remove_squid
            else
                install_squid
            fi
            exit
        ;;
        4)
            echo
            warning "This will remove OpenVPN, Squid, and all configs."
            read -p "Confirm full removal? [y/N]: " remove
            until [[ "$remove" =~ ^[yYnN]*$ ]]; do
                echo "$remove: invalid selection."
                read -p "Confirm full removal? [y/N]: " remove
            done
            if [[ "$remove" =~ ^[yY]$ ]]; then
                info "Cleaning up Firewall rules..."
                port=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                protocol=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
                if systemctl is-active --quiet firewalld.service; then
                    ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.8.0.0/24 '"'"'!'"'"' -d 10.8.0.0/24' | grep -oE '[^ ]+$')
                    firewall-cmd --remove-port="$port"/"$protocol" >> "$LOG_FILE" 2>&1
                    firewall-cmd --zone=trusted --remove-source=10.8.0.0/24 >> "$LOG_FILE" 2>&1
                    firewall-cmd --permanent --remove-port="$port"/"$protocol" >> "$LOG_FILE" 2>&1
                    firewall-cmd --permanent --zone=trusted --remove-source=10.8.0.0/24 >> "$LOG_FILE" 2>&1
                    firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip" >> "$LOG_FILE" 2>&1
                    firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to "$ip" >> "$LOG_FILE" 2>&1
                    if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
                        ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:1194:1194:1194::/64 '"'"'!'"'"' -d fddd:1194:1194:1194::/64' | grep -oE '[^ ]+$')
                        firewall-cmd --zone=trusted --remove-source=fddd:1194:1194:1194::/64 >> "$LOG_FILE" 2>&1
                        firewall-cmd --permanent --zone=trusted --remove-source=fddd:1194:1194:1194::/64 >> "$LOG_FILE" 2>&1
                        firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6" >> "$LOG_FILE" 2>&1
                        firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:1194:1194:1194::/64 ! -d fddd:1194:1194:1194::/64 -j SNAT --to "$ip6" >> "$LOG_FILE" 2>&1
                    fi
                else
                    systemctl disable --now openvpn-iptables.service >> "$LOG_FILE" 2>&1
                    rm -f /etc/systemd/system/openvpn-iptables.service
                fi
                
                if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
                    semanage port -d -t openvpn_port_t -p "$protocol" "$port" >> "$LOG_FILE" 2>&1
                fi
                
                info "Removing Systemd Services..."
                systemctl disable --now openvpn-server@server.service >> "$LOG_FILE" 2>&1
                rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
                rm -f /etc/sysctl.d/99-openvpn-forward.conf
                
                info "Removing OpenVPN packages..."
                if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
                    rm -rf /etc/openvpn/server
                    apt-get remove --purge -y openvpn >> "$LOG_FILE" 2>&1
                else
                    dnf remove -y openvpn >> "$LOG_FILE" 2>&1
                    rm -rf /etc/openvpn/server
                fi
                
                success "OpenVPN removed!"
                rm -f /usr/local/bin/ovpn
                echo "Manager command 'ovpn' removed."
            else
                echo
                echo "Removal cancelled."
            fi
            exit
        ;;
        5)
            exit
        ;;
    esac
fi
