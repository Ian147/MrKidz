# Vps Indo Install Ini Duluan
wget https://raw.githubusercontent.com/Ian147/MrKidz/main/repoindo.sh && chmod +x repoindo.sh && ./repoindo.sh




# Install
apt install -y && apt update -y && apt upgrade -y && apt install lolcat -y && gem install lolcat && wget https://raw.githubusercontent.com/Ian147/MrKidz/main/v3.sh && chmod +x v3.sh && ./v3.sh


# Fix Haproxy

curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    wget -O /etc/haproxy/haproxy.cfg "https://raw.githubusercontent.com/Ian147/MrKidz/main/kucik/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "https://raw.githubusercontent.com/Ian147/MrKidz/main/kucik/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/sub domain kamu/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/sub domain kamu/g" /etc/nginx/conf.d/xray.conf
    curl https://raw.githubusercontent.com/Ian147/MrKidz/main/kucik/nginx.conf > /etc/nginx/nginx.conf
    
cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
