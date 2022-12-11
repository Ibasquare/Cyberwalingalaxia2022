rm -f /etc/apt/sources.list
apt-get clean && apt-get update --fix-missing && apt-get upgrade -y && apt-get autoremove
apt-get --fix-broken install
apt-get install -y libssl-dev debootstrap iwatch inetsim tcpdump gdb hexedit ghidra upx-ucl xorg
groupadd -f students