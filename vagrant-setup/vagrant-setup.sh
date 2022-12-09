apt-get clean && apt-get update && apt-get upgrade -y
apt-get --fix-missing --fix-broken install
apt-get install -y libssl-dev debootstrap iwatch inetsim tcpdump gdb hexedit ghidra upx-ucl xorg