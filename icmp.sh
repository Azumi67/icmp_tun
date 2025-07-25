apt update -y
apt install wget -y
echo -e "${GREEN}Downloading logo ...${RESET}"
wget -O /etc/logo2.sh https://github.com/Azumi67/UDP2RAW_FEC/raw/main/logo2.sh
chmod +x /etc/logo2.sh
if [ -f "udp_tun.py" ]; then
    echo -e "${YELLOW}Removing existing icmp ...${RESET}"
    rm icmp.py
fi
echo -e "${YELLOW}Downloading icmp.py...${RESET}"
wget https://github.com/Azumi67/icmp_tun/releases/download/V1.0/icmp.py
echo -e "${GREEN}Launching udp_tun.py...${RESET}"
python3 icmp.py
