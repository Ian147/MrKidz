#!/bin/bash
### mrkidz Autoscript ###
apt update
apt upgrade -y
apt install curl -y
apt install wondershaper -y

### Color ###
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
BLUE="\033[0;36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${GREEN}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\033[1;30m"
NC="\033[0m"
# ===================
TIME=$(date '+%d %b %Y')

# Pastikan wget atau curl tersedia untuk mengambil IP
if command -v wget > /dev/null; then
    ipsaya=$(wget -qO- ipinfo.io/ip)
elif command -v curl > /dev/null; then
    ipsaya=$(curl -s ipinfo.io/ip)
else
    ipsaya="UNKNOWN_IP"
fi

CHATID="2118266757"
KEY="6561892159:AAEfW_wh32WA3KzJDVrvFDDbtazjcmA2Cc4"
URL="https://api.telegram.org/bot$KEY/sendMessage"

# Pastikan API Telegram bisa diakses sebelum mengirim pesan
response=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
if [ "$response" -ne 200 ]; then
    echo "Gagal menghubungi API Telegram."
    exit 1
fi

# Kirim pesan ke Telegram
MESSAGE="Server aktif pada $TIME dengan IP: $ipsaya"
response=$(curl -s -X POST "$URL" -d chat_id="$CHATID" -d text="$MESSAGE")

if [[ $response == *"\"ok\":true"* ]]; then
    echo "Pesan berhasil dikirim ke Telegram."
else
    echo "Gagal mengirim pesan ke Telegram. Periksa API KEY dan CHAT ID."
fi

# ===================
clear

# Pastikan curl dan wget tersedia
if ! command -v curl &> /dev/null; then
    apt install curl -y
fi
if ! command -v wget &> /dev/null; then
    apt install wget -y
fi

# Exporing IP Address Information
export IP=$(curl -sS icanhazip.com)

# Clear Data
clear

# Banner
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e "  Welcome To MrKidz Tunneling ${YELLOW}(${NC}${green} Stable Edition ${NC}${YELLOW})${NC}"
echo -e " This Will Quick Setup VPN Server On Your Server"
echo -e "  Author : ${green}╭────────────®MrKidz®────────────╮${NC}${YELLOW}(${NC} ${green} MrKidz Tunneling ${NC}${YELLOW})${NC}"
echo -e " © Recode By My Self Mrkidz Tunneling${YELLOW}(${NC} 2025 ${YELLOW})${NC}"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 2

###### IZIN SC 
ipsaya=$(wget -qO- ipinfo.io/ip)
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //' || echo "UNKNOWN")
date_list=$(date +"%Y-%m-%d" -d "$data_server")
data_ip="https://raw.githubusercontent.com/Ian147/MrKidz/main/ip"

checking_sc() {
    # Pastikan data IP dapat diakses
    if curl --output /dev/null --silent --head --fail "$data_ip"; then
        useexp=$(wget -qO- $data_ip | grep $ipsaya | awk '{print $3}')
    else
        echo "Gagal mengakses data IP dari $data_ip"
        exit 1
    fi

    if [[ $date_list < $useexp ]]; then
        echo -ne
    else
        echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
        echo -e "\033[42m          Mrkidz AUTOSCRIPT          \033[0m"
        echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
        echo -e ""
        echo -e "            ${RED}PERMISSION DENIED !${NC}"
        echo -e "   \033[0;33mYour VPS${NC} $ipsaya \033[0;33mHas been Banned${NC}"
        echo -e "     \033[0;33mBuy access permissions for scripts${NC}"
        echo -e "             \033[0;33mContact Admin :${NC}"
        echo -e "      \033[0;36mTelegram${NC} t.me/IanClay"
        echo -e "      ${GREEN}WhatsApp${NC} wa.me/6285162544391"
        echo -e "\033[1;93m────────────────────────────────────────────\033[0m"
        exit 1
    fi
}
fi
}
# // Checking OS Architecture
if [[ $(uname -m) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported (${green}$(uname -m)${NC})"
else
    echo -e "${ERROR} Unsupported Architecture: ${YELLOW}$(uname -m)${NC}"
    exit 1
fi
# // Checking System
source /etc/os-release
if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported (${green}$PRETTY_NAME${NC})"
else
    echo -e "${ERROR} Your OS Is Not Supported (${YELLOW}$PRETTY_NAME${NC})"
    exit 1
fi

# // IP Address Validating
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# // Validate Successful
echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear

# // Check Root User
if (( EUID != 0 )); then
    echo "You need to run this script as root"
    exit 1
fi

# // Check Virtualization
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

#IZIN SCRIPT
MYIP=$(curl -sS ipv4.icanhazip.com)
echo -e "\e[32mloading...\e[0m"
clear

# Version sc
clear
#########################

# Hapus file hanya jika ada
[ -f /usr/bin/user ] && rm -f /usr/bin/user

# Ambil informasi dari server
username=$(curl -s https://raw.githubusercontent.com/Ian147/MrKidz/main/ip | grep "$MYIP" | awk '{print $2}')
expx=$(curl -s https://raw.githubusercontent.com/Ian147/MrKidz/main/ip | grep "$MYIP" | awk '{print $3}')

# Validasi jika username kosong
if [[ -z "$username" ]]; then
    echo "Gagal mendapatkan username dari server!"
    exit 1
fi

# Simpan ke file
echo "$username" >/usr/bin/user
echo "$expx" >/usr/bin/e

# DETAIL ORDER
username=$(cat /usr/bin/user)
oid=$(cat /usr/bin/ver)
exp=$(cat /usr/bin/e)

# CERTIFICATE STATUS
today=$(date -d "0 days" +"%Y-%m-%d")
d1=$(date -d "$expx" +%s)
d2=$(date -d "$today" +%s)
certifacate=$(((d1 - d2) / 86400))

# Fungsi untuk menghitung selisih hari
datediff() {
    d1=$(date -d "$1" +%s)
    d2=$(date -d "$2" +%s)
    echo -e "$COLOR1 $NC Expiry In   : $(( (d1 - d2) / 86400 )) Days"
}

# Ambil Expiry Date
Exp1=$(curl -s https://raw.githubusercontent.com/Ian147/MrKidz/main/ip | grep "$MYIP" | awk '{print $4}')

# Validasi status akun
Info="(${green}Active${NC})"
Error="(${RED}ExpiRED${NC})"
if [[ "$today" < "$Exp1" ]]; then
    sts="${Info}"
else
    sts="${Error}"
fi

echo -e "\e[32mloading...\e[0m"
clear

# REPO    
REPO="https://raw.githubusercontent.com/Ian147/MrKidz/main/"
####

# Mulai penghitungan waktu
start=$(date +%s)

# Fungsi untuk menghitung durasi instalasi
secs_to_human() {
    elapsed_time=$(( $(date +%s) - start ))
    echo "Installation time : $((elapsed_time / 3600)) hours $(((elapsed_time / 60) % 60)) minutes $((elapsed_time % 60)) seconds"
}

### Status
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function print_install() {
    echo -e "${green} =============================== ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
    echo -e "${green} =============================== ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    echo -e "${green} =============================== ${FONT}"
    echo -e "${GREEN} # $1 berhasil dipasang ${FONT}"
    echo -e "${green} =============================== ${FONT}"
    sleep 2
}

### Cek root
function is_root() {
    if [[ "$EUID" -ne 0 ]]; then
        print_error "The current user is not the root user, please switch to the root user and run the script again"
        exit 1
    fi
    print_ok "Root user detected. Starting installation process..."
}
# Buat direktori Xray
print_install "Membuat direktori Xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data:www-data /var/log/xray
chmod 755 /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log

# Buat direktori /var/lib/kyt jika belum ada
[ ! -d "/var/lib/kyt" ] && mkdir -p /var/lib/kyt

# Hitung penggunaan RAM
mem_used=0
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB})) ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable") ((mem_used-=${b/kB})) ;;
    esac
done < /proc/meminfo

Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
source /etc/os-release
export OS_Name="$PRETTY_NAME"
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# Change Environment System
function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"

    # Cek OS
    source /etc/os-release
    if [[ "$ID" == "ubuntu" ]]; then
        echo "Setup Dependencies for $PRETTY_NAME"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-2.0 -y
        apt-get -y install haproxy=2.0.*
    elif [[ "$ID" == "debian" ]]; then
        echo "Setup Dependencies for $PRETTY_NAME"
        curl -s https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] http://haproxy.debian.net buster-backports-1.8 main" > /etc/apt/sources.list.d/haproxy.list
        sudo apt-get update
        apt-get -y install haproxy=1.8.*
    else
        echo -e "Your OS is not supported ($PRETTY_NAME)"
        exit 1
    fi
} 
### MrKidz Autoscript ###
clear

function nginx_install() {
    # Load OS Information
    source /etc/os-release

    if [[ "$ID" == "ubuntu" ]]; then
        print_install "Setup nginx For OS: $PRETTY_NAME"
        sudo apt-get update -y
        sudo apt-get install nginx -y
    elif [[ "$ID" == "debian" ]]; then
        print_install "Setup nginx For OS: $PRETTY_NAME"
        apt update -y
        apt install nginx -y
    else
        echo -e "Your OS is not supported (${YELLOW}$PRETTY_NAME${FONT})"
        exit 1
    fi
} 
# Update and remove packages
function base_package() {
    clear
    print_install "Updating and Installing Required Packages"

    # Update package list sebelum menginstal paket
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y

    # Install paket dasar
    apt install -y zip pwgen openssl netcat socat cron bash-completion figlet ntpdate sudo

    # Konfigurasi waktu
    systemctl enable chrony
    systemctl restart chrony
    ntpdate pool.ntp.org

    # Hapus paket yang tidak diperlukan
    sudo apt-get remove --purge -y exim4 ufw firewalld

    # Membersihkan sistem
    sudo apt-get clean
    sudo apt-get autoremove -y

    # Instalasi software tambahan
    sudo apt-get install -y --no-install-recommends software-properties-common debconf-utils

    # Konfigurasi iptables agar menyimpan aturan secara otomatis
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # Install paket tambahan dalam beberapa kelompok
    sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config
    sudo apt-get install -y libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev
    sudo apt-get install -y libcurl4-nss-dev flex bison make libnss3-tools libevent-dev
    sudo apt-get install -y bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed
    sudo apt-get install -y dirmngr libxml-parser-perl build-essential gcc g++ python htop
    sudo apt-get install -y lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6
    sudo apt-get install -y util-linux msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent
    sudo apt-get install -y netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 lsb-release
    sudo apt-get install -y gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1
    sudo apt-get install -y dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa

    print_success "Required packages installed successfully"
} 
clear

# Fungsi input domain
function pasang_domain() {
    echo -e ""
    clear
    echo -e "   .----------------------------------."
    echo -e "   |\e[1;32m Please Select a Domain Type Below \e[0m|"
    echo -e "   '----------------------------------'"
    echo -e "     \e[1;32m1)\e[0m Use your own domain"
    echo -e "     \e[1;32m2)\e[0m Use a random domain"
    echo -e "   ------------------------------------"
    
    read -p "   Choose an option (1: Custom Domain, 2: Random Domain, Other: Default Random): " host
    echo ""

    if [[ "$host" == "1" ]]; then
        echo -e "   \e[1;32mPlease Enter Your Subdomain: $NC"
        read -p "   Subdomain: " host1
        
        # Simpan domain ke dalam file konfigurasi
        echo "IP=$host1" > /var/lib/kyt/ipvps.conf
        echo "$host1" > /etc/xray/domain
        echo "$host1" > /root/domain
        echo ""

    else
        print_install "Using Random Subdomain/Domain"
        
        # Download dan install Cloudflare script
        wget -q ${REPO}cobek/cf.sh -O cf.sh
        if [[ -f cf.sh ]]; then
            chmod +x cf.sh && ./cf.sh
            rm -f cf.sh
        else
            echo "Failed to download cf.sh, please check your internet connection."
            exit 1
        fi
    fi
} 
clear

# GANTI PASSWORD DEFAULT
restart_system() {
    USRSC=$(wget -qO- https://raw.githubusercontent.com/Ian147/MrKidz/main/ip | grep $ipsaya | awk '{print $2}')
    EXPSC=$(wget -qO- https://raw.githubusercontent.com/Ian147/MrKidz/main/ip | grep $ipsaya | awk '{print $3}')

    # Dapatkan waktu dan tanggal
    TIME=$(date +"%Y-%m-%d")
    TIMEZONE=$(date +"%H:%M:%S")

    # Ambil domain jika tersedia
    domain=$(cat /etc/xray/domain 2>/dev/null || echo "No Domain Set")

    # Pesan notifikasi
    TEXT="
<code>────────────────────</code>
<b>⚡AUTOSCRIPT PREMIUM V.01 LTS⚡</b>
<code>────────────────────</code>
<code>ID     : </code><code>$USRSC</code>
<code>Domain : </code><code>$domain</code>
<code>Date   : </code><code>$TIME</code>
<code>Time   : </code><code>$TIMEZONE</code>
<code>Ip vps : </code><code>$ipsaya</code>
<code>Exp Sc : </code><code>$EXPSC</code>
<code>────────────────────</code>
<i>Automatic Notification from Github</i>
"'&reply_markup={"inline_keyboard":[[{"text":"ORDER🐳","url":"https://t.me/IanClay"},{"text":"GROUP🐬","url":"https://chat.whatsapp.com/IMwXEDPHxatHBg9bOk7iME"}]]}'
    
    # Kirim notifikasi ke Telegram dengan pengecekan status
    response=$(curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL)
    if [[ $response == *"\"ok\":true"* ]]; then
        echo "Notification sent successfully."
    else
        echo "Failed to send notification to Telegram."
    fi
} 
clear

# Pasang SSL
function pasang_ssl() {
    clear
    print_install "Installing SSL on a domain"

    # Cek apakah domain sudah ada
    if [[ ! -f "/etc/xray/domain" || -z "$(cat /etc/xray/domain)" ]]; then
        echo "Error: No domain found in /etc/xray/domain"
        exit 1
    fi
    domain=$(cat /etc/xray/domain)

    # Hapus sertifikat lama
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt

    # Hentikan Nginx jika berjalan
    if systemctl is-active --quiet nginx; then
        systemctl stop nginx
    fi

    # Hapus folder acme.sh lama dan buat ulang
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh

    # Unduh acme.sh dari sumber resmi
    curl -s https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh

    # Instalasi dan upgrade acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt

    # Proses penerbitan SSL
    /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256
    /root/.acme.sh/acme.sh --install-cert -d "$domain" --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

    # Ubah permission file SSL
    chmod 600 /etc/xray/xray.key

    print_success "SSL installation completed successfully."
} 
function make_folder_xray() {
    # Hapus file database lama jika ada
    for file in /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
                /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db; do
        [[ -f "$file" ]] && rm -rf "$file"
    done

    # Buat direktori yang dibutuhkan
    mkdir -p /etc/{bot,xray,vmess,vless,trojan,shadowsocks,ssh} \
             /usr/bin/xray /var/log/xray /var/www/html \
             /etc/kyt/limit/{vmess,vless,trojan,ssh}/ip \
             /etc/limit/{vmess,vless,trojan,ssh}

    # Pastikan file domain ada
    [[ ! -f /etc/xray/domain ]] && touch /etc/xray/domain

    # Buat file log dan database jika belum ada
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log

    for db in /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db \
              /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db; do
        [[ ! -f "$db" ]] && touch "$db" && echo "& plugin Account" >> "$db"
    done

    # Atur izin direktori log
    chmod 755 /var/log/xray
}
# Instalasi Xray
function install_xray() {
    clear
    print_install "Installing Xray Core Latest Version"

    # Buat folder domain socket jika belum ada
    domainSock_dir="/run/xray"
    [[ ! -d $domainSock_dir ]] && mkdir -p $domainSock_dir
    chown www-data:www-data $domainSock_dir

    # Ambil versi terbaru Xray
    latest_version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name 2>/dev/null || echo "1.8.1")
    latest_version="${latest_version#v}"  # Hapus 'v' jika ada

    # Unduh dan pasang Xray
    curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/install-xray.sh
    if [[ -f /tmp/install-xray.sh ]]; then
        bash /tmp/install-xray.sh install -u www-data --version $latest_version
        rm -f /tmp/install-xray.sh
    else
        echo "Failed to download Xray installation script."
        exit 1
    fi

    # Unduh konfigurasi Xray
    wget -O /etc/xray/config.json "${REPO}kucik/config.json"
    if [[ ! -s /etc/xray/config.json ]]; then
        echo "Failed to download Xray config.json"
        exit 1
    fi

    wget -O /etc/systemd/system/runn.service "${REPO}kucik/runn.service"
    if [[ ! -s /etc/systemd/system/runn.service ]]; then
        echo "Failed to download runn.service"
        exit 1
    fi

    # Pastikan domain dan IP sudah ada
    domain=$(cat /etc/xray/domain 2>/dev/null || echo "No Domain Set")
    IPVS=$(cat /etc/xray/ipvps 2>/dev/null || echo "No IP Found")

    print_success "Xray Core version $latest_version installed successfully."
}

---

## **Script yang Sudah Diperbaiki**
```bash
#!/bin/bash

# Settings UP Nginx and HAProxy
clear

# Simpan informasi kota dan ISP
curl -s ipinfo.io/city > /etc/xray/city
curl -s ipinfo.io/org | cut -d " " -f 2-10 > /etc/xray/isp

print_install "Installing Package Configuration"

# Unduh konfigurasi HAProxy dan Nginx
wget -O /etc/haproxy/haproxy.cfg "${REPO}kucik/haproxy.cfg"
if [[ ! -s /etc/haproxy/haproxy.cfg ]]; then
  echo "Failed to download haproxy.cfg"
  exit 1
fi

wget -O /etc/nginx/conf.d/xray.conf "${REPO}kucik/xray.conf"
if [[ ! -s /etc/nginx/conf.d/xray.conf ]]; then
  echo "Failed to download xray.conf"
  exit 1
fi

curl -s ${REPO}kucik/nginx.conf -o /etc/nginx/nginx.conf
if [[ ! -s /etc/nginx/nginx.conf ]]; then
  echo "Failed to download nginx.conf"
  exit 1
fi

# Pastikan domain ada sebelum mengganti konfigurasi
if [[ -z "$domain" ]]; then
  echo "Error: Domain is not set!"
  exit 1
fi

sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf

# Gabungkan sertifikat SSL untuk HAProxy
cat /etc/xray/xray.crt /etc/xray/xray.key > /etc/haproxy/hap.pem

# Set Permission jika file service ada
[[ -f /etc/systemd/system/runn.service ]] && chmod +x /etc/systemd/system/runn.service

# Buat file service Xray
cat <<EOF > /etc/systemd/system/xray.service
[Unit]
Description=Xray Service
Documentation=https://github.com
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
EOF
function ssh(){
    clear
    print_install "Setting SSH Password"

    # Unduh konfigurasi password dan pastikan file valid
    wget -O /etc/pam.d/common-password "${REPO}caw/password"
    if [[ ! -s /etc/pam.d/common-password ]]; then
        echo "Failed to download common-password"
        exit 1
    fi
    chmod 644 /etc/pam.d/common-password  # Tidak perlu eksekusi (+x)

    # Konfigurasi keyboard hanya jika belum ada
    if [[ ! -f /etc/default/keyboard ]]; then
        echo "Setting up keyboard configuration..."
        debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
        debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
        dpkg-reconfigure -f noninteractive keyboard-configuration
    else
        echo "Keyboard configuration already exists, skipping..."
    fi
}
# Pindah ke root directory
cd

# Membuat file service systemd untuk rc.local
cat > /etc/systemd/system/rc-local.service <<-EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

# Membuat file /etc/rc.local
cat > /etc/rc.local <<-EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
EOF

# Berikan izin eksekusi
chmod +x /etc/rc.local

# Reload systemd dan aktifkan rc-local
systemctl daemon-reload
systemctl enable rc-local
systemctl start rc-local

# Ubah izin akses
chmod +x /etc/rc.local

# Nonaktifkan IPv6 secara permanen
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

# Atur zona waktu ke Asia/Jakarta
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# Nonaktifkan pengaturan lingkungan SSH
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
print_success "SSH Password"

function ins_badvpn(){
    clear
    print_install "Setting IP Service Limit "

    # Unduh script limit.sh dan jalankan
    wget -O /tmp/limit.sh https://raw.githubusercontent.com/deyank00/deyankvps/main/limit/limit.sh
    chmod +x /tmp/limit.sh && /tmp/limit.sh

    # Unduh file quota
    wget -q -O /usr/local/sbin/quota "${REPO}limit/quota"
    chmod +x /usr/local/sbin/quota
    sed -i 's/\r//' /usr/local/sbin/quota

    # Unduh dan atur limit IP SSH
    wget -q -O /usr/bin/limit-ip "${REPO}limit/limit-ip"
    chmod +x /usr/bin/limit-ip
    sed -i 's/\r//' /usr/bin/limit-ip

    wget -q -O /usr/bin/limit-ip-ssh "${REPO}limit/limit-ip-ssh"
    chmod +x /usr/bin/limit-ip-ssh
    sed -i 's/\r//' /usr/bin/limit-ip-ssh

    # Buat service limit IP
    for service in sship vmip vlip trip; do
        cat > /etc/systemd/system/$service.service <<EOF
[Unit]
Description=Limit IP $service
After=network.target

[Service]
ExecStart=/usr/bin/limit-ip $service
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now $service
    done

    # Buat service limit kuota
    for service in qmv qmvl qmtr; do
        cat > /etc/systemd/system/$service.service <<EOF
[Unit]
Description=Limit Quota $service
After=network.target

[Service]
ExecStart=/usr/local/sbin/quota ${service#qm}
Restart=always

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now $service
    done

    # Instalasi BadVPN
    wget -O /usr/bin/badvpn "${REPO}tangkal/badvpn"
    if [[ ! -s /usr/bin/badvpn ]]; then
        echo "Failed to download badvpn"
        exit 1
    fi
    chmod +x /usr/bin/badvpn

    # Unduh dan aktifkan service BadVPN
    for i in {1..3}; do
        wget -q -O /etc/systemd/system/badvpn$i.service "${REPO}tangkal/badvpn$i.service"
        systemctl enable --now badvpn$i
    done

    print_success "IP Service Limit"
}
function ssh_slow(){
    clear
    print_install "Installing the SlowDNS Server module"

    wget -q -O /tmp/nameserver "${REPO}linak/nameserver"
    if [[ ! -s /tmp/nameserver ]]; then
        echo "Failed to download SlowDNS nameserver"
        exit 1
    fi
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log

    print_success "SlowDNS"
}

function ins_SSHD(){
    clear
    print_install "Installing SSHD"

    wget -q -O /etc/ssh/sshd_config "${REPO}caw/sshd"
    if [[ ! -s /etc/ssh/sshd_config ]]; then
        echo "Failed to download SSHD configuration"
        exit 1
    fi
    chmod 600 /etc/ssh/sshd_config
    systemctl restart ssh
    systemctl status ssh --no-pager

    print_success "SSHD"
}

function ins_dropbear(){
    clear
    print_install "Installing Dropbear"

    apt-get install dropbear -y > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}caw/dropbear.conf"
    if [[ ! -s /etc/default/dropbear ]]; then
        echo "Failed to download Dropbear configuration"
        exit 1
    fi
    chmod 600 /etc/default/dropbear
    systemctl restart dropbear
    systemctl status dropbear --no-pager

    print_success "Dropbear"
}

function ins_vnstat(){
    clear
    print_install "Installing Vnstat"

    apt -y install vnstat libsqlite3-dev
    systemctl enable vnstat
    systemctl restart vnstat
    systemctl status vnstat --no-pager

    print_success "Vnstat"
}

function ins_openvpn(){
    clear
    print_install "Installing OpenVPN"

    wget -O /tmp/openvpn-install.sh "${REPO}caw/openvpn"
    if [[ ! -s /tmp/openvpn-install.sh ]]; then
        echo "Failed to download OpenVPN installer"
        exit 1
    fi
    chmod +x /tmp/openvpn-install.sh
    /tmp/openvpn-install.sh
    systemctl restart openvpn
    systemctl status openvpn --no-pager

    print_success "OpenVPN"
}
function ins_backup(){
    clear
    print_install "Installing Backup Server"

    # Install Rclone
    apt install rclone -y
    printf "q\n" | rclone config

    # Unduh konfigurasi Rclone
    wget -O /root/.config/rclone/rclone.conf "${REPO}bantur/rclone.conf"
    if [[ ! -s /root/.config/rclone/rclone.conf ]]; then
        echo "Failed to download rclone configuration"
        exit 1
    fi

    # Instal Wondershaper
    cd /tmp
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper
    sudo make install
    cd ..
    rm -rf wondershaper

    # Kosongkan file /home/limit
    echo > /home/limit

    # Instalasi msmtp untuk pengiriman email
    apt install msmtp-mta ca-certificates bsd-mailx -y
    cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user YOUR_EMAIL@gmail.com
from YOUR_EMAIL@gmail.com
password YOUR_SECURE_APP_PASSWORD
logfile ~/.msmtp.log
EOF

    # Berikan izin aman untuk file konfigurasi
    chmod 600 /etc/msmtprc
    chown -R www-data:www-data /etc/msmtprc

    # Unduh dan jalankan ipserver script jika berhasil diunduh
    wget -q -O /etc/ipserver "${REPO}bantur/ipserver"
    if [[ ! -s /etc/ipserver ]]; then
        echo "Failed to download ipserver script"
        exit 1
    fi
    bash /etc/ipserver

    print_success "Backup Server"
}
function ins_swab(){
    clear
    print_install "Installing 1G Swap"

    # Install gotop
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb

    if [[ ! -s /tmp/gotop.deb ]]; then
        echo "Failed to download gotop"
        exit 1
    fi

    dpkg -i /tmp/gotop.deb >/dev/null 2>&1

    # Cek apakah swap sudah ada
    if ! swapon --show | grep -q "/swapfile"; then
        echo "Creating swap file..."
        dd if=/dev/zero of=/swapfile bs=1024 count=1048576
        mkswap /swapfile
        chown root:root /swapfile
        chmod 0600 /swapfile >/dev/null 2>&1
        swapon /swapfile >/dev/null 2>&1
        echo "/swapfile      swap swap   defaults    0 0" >> /etc/fstab
    else
        echo "Swap already exists, skipping creation."
    fi

    # Pastikan chronyd berjalan
    systemctl enable --now chronyd

    # Unduh dan jalankan BBR script
    wget -O /tmp/bbr.sh "${REPO}cobek/bbr.sh"
    if [[ ! -s /tmp/bbr.sh ]]; then
        echo "Failed to download bbr.sh"
        exit 1
    fi
    chmod +x /tmp/bbr.sh
    /tmp/bbr.sh

    print_success "Swap 1G"
}
function ins_Fail2ban(){
    clear
    print_install "Installing Fail2Ban"

    # Instal Fail2Ban jika belum terinstal
    if ! dpkg -l | grep -qw fail2ban; then
        apt -y install fail2ban
    fi

    systemctl enable --now fail2ban
    systemctl restart fail2ban
    systemctl status fail2ban --no-pager

    # Instal DDOS Flate
    if [ -d "/usr/local/ddos" ]; then
        echo "Existing DDOS Flate installation found. Removing..."
        rm -rf /usr/local/ddos
    fi
    mkdir -p /usr/local/ddos

    print_success "Fail2Ban & DDOS Flate Installed"
}
function set_banner(){
    clear
    print_install "Setting up SSH & Dropbear Banner"

    # Konfigurasi Banner untuk SSH
    if ! grep -q "^Banner /etc/kyt.txt" /etc/ssh/sshd_config; then
        echo "Banner /etc/kyt.txt" >> /etc/ssh/sshd_config
    fi

    # Konfigurasi Banner untuk Dropbear
    if ! grep -q "^DROPBEAR_BANNER=" /etc/default/dropbear; then
        echo 'DROPBEAR_BANNER="/etc/kyt.txt"' >> /etc/default/dropbear
    else
        sed -i 's@^DROPBEAR_BANNER=.*@DROPBEAR_BANNER="/etc/kyt.txt"@' /etc/default/dropbear
    fi

    # Unduh file banner
    wget -O /etc/kyt.txt "${REPO}bantur/issue.net"
    if [[ ! -s /etc/kyt.txt ]]; then
        echo "Failed to download SSH banner"
        exit 1
    fi

    # Restart layanan untuk menerapkan perubahan
    systemctl restart ssh
    systemctl restart dropbear

    print_success "SSH & Dropbear Banner Set"
}
function ins_epro(){
    clear
    print_install "Installing WebSocket Proxy"

    # Unduh file yang diperlukan dengan validasi
    wget -O /usr/bin/ws "${REPO}kijuk/ws"
    if [[ ! -s /usr/bin/ws ]]; then
        echo "Failed to download ws"
        exit 1
    fi

    wget -O /usr/bin/tun.conf "${REPO}kijuk/tun.conf"
    if [[ ! -s /usr/bin/tun.conf ]]; then
        echo "Failed to download tun.conf"
        exit 1
    fi

    wget -O /etc/systemd/system/ws.service "${REPO}kijuk/ws.service"
    if [[ ! -s /etc/systemd/system/ws.service ]]; then
        echo "Failed to download ws.service"
        exit 1
    fi

    # Atur izin file
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf

    # Konfigurasi sistemd
    systemctl daemon-reload
    systemctl enable --now ws
    systemctl restart ws

    # Unduh data geolocation untuk Xray
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    if [[ ! -s /usr/local/share/xray/geosite.dat ]]; then
        echo "Failed to download geosite.dat"
        exit 1
    fi

    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    if [[ ! -s /usr/local/share/xray/geoip.dat ]]; then
        echo "Failed to download geoip.dat"
        exit 1
    fi

    # Unduh dan berikan izin eksekusi untuk ftvpn
    wget -O /usr/sbin/ftvpn "${REPO}kijuk/ftvpn"
    if [[ ! -s /usr/sbin/ftvpn ]]; then
        echo "Failed to download ftvpn"
        exit 1
    fi
    chmod +x /usr/sbin/ftvpn

    # Konfigurasi firewall untuk memblokir BitTorrent dan P2P
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

    # Simpan aturan firewall
    iptables-save > /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    print_success "WebSocket Proxy Installed"
}
# Bersihkan paket yang tidak diperlukan
function clean_system(){
    cd
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    print_success "System Cleanup"
}

# Restart semua layanan
function ins_restart(){
    clear
    print_install "Restarting All Services"

    # Restart layanan dengan systemctl
    systemctl restart nginx openvpn ssh dropbear fail2ban vnstat haproxy cron netfilter-persistent ws xray

    # Pastikan layanan aktif secara otomatis saat booting
    systemctl enable nginx xray rc-local dropbear openvpn cron haproxy netfilter-persistent ws fail2ban

    # Hapus riwayat shell untuk keamanan
    history -c
    if ! grep -q "unset HISTFILE" /etc/profile; then
        echo "unset HISTFILE" >> /etc/profile
    fi

    # Hapus file yang tidak diperlukan
    rm -f /root/openvpn /root/key.pem /root/cert.pem

    print_success "All Services Restarted"
}
# Instal Menu
function menu(){
    clear
    print_install "Installing the Menu Packet"
    
    # Unduh menu.zip dan validasi
    wget -q ${REPO}kikitolan/menu.zip
    if [[ ! -f menu.zip ]]; then
        echo "Failed to download menu.zip"
        exit 1
    fi

    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
}

# Instal SSH UDP
function ins_udp() {
    clear
    print_install "INSTALL SSH UDP"
    wget -q https://udp.bagusvpn.me/udp-custom.sh && chmod +x udp-custom.sh && ./udp-custom.sh
}

# Membuat Default Menu 
function profile(){
    clear
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

    cat >/etc/cron.d/xp_all <<-END
        SHELL=/bin/sh
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
        2 0 * * * root /usr/local/sbin/xp
    END

    cat >/etc/cron.d/logclean <<-END
        SHELL=/bin/sh
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
        */10 * * * * root /usr/local/sbin/clearlog
    END

    chmod 644 /root/.profile

    cat >/etc/cron.d/daily_reboot <<-END
        SHELL=/bin/sh
        PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
        0 5 * * * root /sbin/reboot
    END

    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    service cron restart

    cat >/home/daily_reboot <<-END
        5
    END

    cat >/etc/cron.d/limitssh-ip <<-END
    SHELL=/bin/sh
    PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
    */1 * * * * root /usr/local/sbin/limitssh-ip
    END

    # Konfigurasi rc.local
    cat >/etc/systemd/system/rc-local.service <<EOF
    [Unit]
    Description=/etc/rc.local
    ConditionPathExists=/etc/rc.local
    [Service]
    Type=forking
    ExecStart=/etc/rc.local start
    TimeoutSec=0
    StandardOutput=tty
    RemainAfterExit=yes
    SysVStartPriority=99
    [Install]
    WantedBy=multi-user.target
    EOF

    echo "/bin/false" >> /etc/shells
    echo "/usr/sbin/nologin" >> /etc/shells

    cat >/etc/rc.local <<EOF
    #!/bin/sh -e
    # rc.local
    # By default this script does nothing.
    iptables -I INPUT -p udp --dport 5300 -j ACCEPT
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
    systemctl restart netfilter-persistent
    exit 0
    EOF

    chmod +x /etc/rc.local

    # Menentukan waktu AM/PM
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
    print_success "Menu Packet"
}

# Restart layanan after install
function enable_services(){
    clear
    print_install "Enable Service"
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable --now rc-local
    systemctl enable --now cron
    systemctl enable --now netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    print_success "Enable Service"
    clear
}
# Fungsi untuk memeriksa status setelah setiap perintah
function check_status() {
    if [[ $? -ne 0 ]]; then
        echo "Error: $1 failed!"
        exit 1
    fi
}

# Fungsi untuk instalasi dan konfigurasi
function instal(){
    clear
    checking_sc
    first_setup
    nginx_install
    check_status "Nginx installation"
    base_package
    check_status "Base package installation"
    make_folder_xray
    check_status "Xray folder creation"
    pasang_domain
    check_status "Domain installation"
    password_default
    check_status "Setting default password"
    pasang_ssl
    check_status "SSL installation"
    install_xray
    check_status "Xray installation"
    ssh
    check_status "SSH configuration"
    ins_badvpn
    check_status "BadVPN installation"
    ssh_slow
    check_status "SlowDNS installation"
    ins_SSHD
    check_status "SSHD installation"
    ins_dropbear
    check_status "Dropbear installation"
    ins_vnstat
    check_status "Vnstat installation"
    ins_openvpn
    check_status "OpenVPN installation"
    ins_backup
    check_status "Backup installation"
    ins_swab
    check_status "Swap installation"
    ins_Fail2ban
    check_status "Fail2ban installation"
    ins_epro
    check_status "WebSocket Proxy installation"
    ins_restart
    check_status "Services restart"
    menu
    check_status "Menu installation"
    ins_udp
    check_status "UDP installation"
    profile
    check_status "Profile creation"
    enable_services
    check_status "Enable services"
    restart_system
    check_status "System reboot"
}

# Menjalankan instalasi
instal

# Membersihkan file yang tidak diperlukan
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
echo -e "${green} Script Successfully Installed"

# Informasi port
echo -e "\033[0;32m ┌──────────────────────────────────────────┐\033[0m"
echo -e "\033[0;32m │\033[0m            \033[0;36mPORT SERVICE INFO\033[0m             \033[0;32m|\033[0m"
echo -e "\033[0;32m └──────────────────────────────────────────┘\033[0m"
echo -e "\033[0;32m┌─────────────────────────────────────────────┐"
echo -e "\033[0;32m│       >>> Service & Port                    │"
echo -e "\033[0;32m│   - Open SSH                : 443, 80, 22   │"
echo -e "\033[0;32m│   - Dropbear                : 443, 109, 143 │"
echo -e "\033[0;32m│   - Dropbear Websocket      : 443, 109      │"
echo -e "\033[0;32m│   - SSH Websocket SSL       : 443           │"
echo -e "\033[0;32m│   - SSH Websocket           : 80            │"
echo -e "\033[0;32m│   - OpenVPN SSL             : 443           │"
echo -e "\033[0;32m│   - OpenVPN Websocket SSL   : 443           │"
echo -e "\033[0;32m│   - OpenVPN TCP             : 443, 1194     │"
echo -e "\033[0;32m│   - OpenVPN UDP             : 2200          │"
echo -e "\033[0;32m│   - Nginx Webserver         : 443, 80, 81   │"
echo -e "\033[0;32m│   - Haproxy Loadbalancer    : 443, 80       │"
echo -e "\033[0;32m│   - XRAY Vmess TLS          : 443           │"
echo -e "\033[0;32m│   - XRAY Vmess gRPC         : 443           │"
echo -e "\033[0;32m│   - XRAY Vmess None TLS     : 80            │"
echo -e "\033[0;32m│   - XRAY Vless TLS          : 443           │"
echo -e "\033[0;32m│   - XRAY Vless gRPC         : 443           │"
echo -e "\033[0;32m│   - XRAY Vless None TLS     : 80            │"
echo -e "\033[0;32m│   - Trojan gRPC             : 443           │"
echo -e "\033[0;32m│   - Trojan WS               : 443           │"
echo -e "\033[0;32m│   - Shadowsocks WS          : 443           │"
echo -e "\033[0;32m│   - BadVPN 1                : 7100          │"
echo -e "\033[0;32m│   - BadVPN 2                : 7200          │"
echo -e "\033[0;32m│   - BadVPN 3                : 7300          │"
echo -e "\033[0;32m└─────────────────────────────────────────────┘"
echo ""

# Menunggu reboot
read -p "$( echo -e "Press ${YELLOW}[ ${NC}${YELLOW}Enter${NC} ${YELLOW}]${NC} For Reboot") "
reboot
