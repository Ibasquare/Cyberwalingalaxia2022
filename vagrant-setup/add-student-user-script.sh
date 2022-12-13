#!/bin/bash
# Purpose - Script to add a user to Linux system including passsword
# Author - Vivek Gite <www.cyberciti.biz> under GPL v2.0+
# ------------------------------------------------------------------
# Am i Root user?
if [ $(id -u) -eq 0 ]; then
	read -p "Enter username : " username
	read -s -p "Enter password : " password
	egrep "^$username" /etc/passwd >/dev/null
	if [ $? -eq 0 ]; then
		echo ""
		echo ""
		echo "User $username exists!"
		echo ""
		exit 1
	else
		pass=$(perl -e 'print crypt($ARGV[0], "password")' $password 2> /dev/null)
		useradd -m -p "$pass" "$username" -s "/bin/bash" -m --home "/var/$username" >/dev/null

		if [ $? -ne 0 ]; then
			echo ""
			echo ""
			echo "Failed to add user $username!"
			exit $?
		fi

		usermod -aG sudo "$username" >/dev/null

		if [ $? -ne 0 ]; then
			echo ""
			echo ""
			echo "Failed to add user $username to sudoers!"
			exit $?
		fi

		usermod -aG students "$username" >/dev/null

		if [ $? -ne 0 ]; then
			echo ""
			echo ""
			echo "Failed to add user $username to sudoers!"
			exit $?
		fi

		cp "~/archive.zip" "/var/$username/"
		cp "/etc/inetsim/inetsim.conf" "/var/$username/"
	fi

	echo ""
	echo ""
	echo "You have successfully created a new account."
	echo "You can now connect to your vm using the following command:"
	echo "ssh -XY $username@frodo.run.montefiore.uliege.be -p $1"
	echo ""
	echo ""
else
	echo "Only root may add a user to the system."
	exit 2
fi
