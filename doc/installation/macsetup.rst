#####################################################
Setting Up a VM on a recent Mac (with M1 or M2 chips)
#####################################################
#####################################################

.. danger:: Perform these steps only if you do not have the Kali reference machine installed or if you have a recent Macbook with an M1 or M2 chip. Otherwise use `VirtualBox <vmsetup.html>`_ instead. Note that we propose two solutions:
  
  1. Connect to a remote VM already configured (**recommended**).
  2. If the previous approach does not work, you can use qemu as emulator to run Kali (**but it is slow**).


.. _target connect to a remote VM:

Connect to a remote VM (Kali) already setup
*******************************************

We have made Kali Linux VMs available in a private network. In order to use them, it is necessary to connect to the private Wi-Fi first. The SSID is either ``Cyberwal1`` or ``Cyberwal2``. Once connected, open a terminal and connect via ssh with the following command::

  ssh student@192.168.1.4

The password is ``cyberwal``. Once logged in, you are asked to create a new user. Enter your username and a password. Once the user has been created, the ssh session will end and you will be asked to log in again with the following command::

  ssh -XY your_username@192.168.1.4 -p PORT_NUMBER

Once logged in, you automatically have a workspace dedicated to your user in ``/var/<your_username>``.

.. danger:: In order to use the ``-XY`` argument, make sure you have installed `XQuartz <https://www.xquartz.org>`_.

Using Qemu as emulator (SLOW)
*****************************

As mentioned, this approach allows to run Kali x86 (64bits) on your Mac but since it relied on a emulator, it will be quite **slow**... 

.. warning:: Use Qemu only if you cannot have access to the private network (cfr. part above).


Download the Kali VM image
==========================

Then download the reference Kali Linux image from `this link <https://www.kali.org/get-kali/#kali-virtual-machines>`_.
The image contains Kali Linux 64bits. The default user of the VM image is ``kali``. The password for the user is also ``kali``.

Installing the VM on Mac (M1 chip)
==================================

If you have a Mac with a modern chip, VirtualBox will not work as the underlying architecture is different (arm vs x86_64). To overcome this problem you will have to use another hypervisor/emulator which is `qemu <https://www.qemu.org>`_.

First, you must install ``brew`` and ``qemu``. Open a terminal and run the following command::

  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Once ``brew`` is installed, run the following command in the same terminal::

  brew install qemu

Go to the folder which contains the "kali.vdi.zip" and run the following commands::

  unzip kali.vdi.zip
  qemu-img convert -f vdi -O qcow2 kali.vdi kali.qcow2

.. warning:: You can delete the .vdi file but be careful do not to delete the .qcow2 image!

Finally, run the following command::

  qemu-system-x86_64 kali.qcow2 -m 4G -netdev user,id=mynet0,hostfwd=tcp::6543-:22 -device e1000,netdev=mynet0

You have to wait a few seconds/minutes before the machine boots completely. Once fully booted, you must enter your credentials. Once you have logged on to the system, you need to run the following commands::

  sudo setxkbmap be
  sudo service ssh start

If you don't see any errors, everything is working on your side and you can move on to the next step.

.. note:: Each time you will reboot the VM, you need to add your credentials and run the *dhclient* command to activate the network interface. You can investigate yourself to create a cronjob/crontab.

Connect to the VM by ssh
========================

Then open a terminal and enter the following commands::

  $ ssh kali@127.0.0.1 -p 6543

The VM will ask your password. In that case, use the "kali" credentials. Note that if you are using Windows, you can use PowerShell or CommandPrompt or `putty <https://www.putty.org>`_.

Update package information
==========================

Finally, enter the following command on your terminal app after connecting to the VM by ssh::

  $ sudo apt update
