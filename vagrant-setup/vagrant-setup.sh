rm -f /etc/apt/sources.list
apt-get clean && apt-get update --fix-missing && apt-get upgrade -y && apt-get autoremove
apt-get --fix-broken install
apt-get install -y libssl-dev debootstrap iwatch inetsim tcpdump gdb hexedit ghidra upx-ucl xorg
groupadd -f students
mkdir -p /bin/cyberwal-lab
mv server_ssl /bin/cyberwal-lab/server_ssl
mv server.crt /bin/cyberwal-lab/server.crt
mv server.key /bin/cyberwal-lab/server.key
mv ssl_server.service /lib/systemd/system/ssl_server.service

systemctl enable ssl_server.service
systemctl restart ssl_server.service