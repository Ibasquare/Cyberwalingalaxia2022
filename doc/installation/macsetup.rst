Setting Up a VM on a recent Mac (m1 chips)
==========================================

.. danger:: Perform these steps only if you have a recent Macbook with a m1 chip. Otherwise use `VirtualBox <vmsetup.html>`_ instead.

Download the reference VM image
-------------------------------

Download the reference VM image from `here <https://people.montefiore.uliege.be/gain/courses/info0940/vm/Ubuntu.vdi.zip>`_.
We use this image for the course. TAs will not be able to support if you use other VM images prepared by yourself.
The image contains Ubuntu 16.04 LTS 32 bit. We use the 32 bit image in order to avoid compatibility issue in the submission platform.
The default user of the VM image is ``student``. The password for the user is also ``student``.

Installing the VM on Mac (m1 chip)
----------------------------------

If you have a Mac with a modern chip, VirtualBox will not work as the underlying architecture is different (arm vs x86_64). To overcome this problem you will have to use another hypervisor/emulator which is `qemu <https://www.qemu.org>`_.

First, you must install ``brew`` and ``qemu``. Open a terminal and run the following command::

  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

Once ``brew`` is installed, run the following command in the same terminal::

  brew install qemu

Go to the folder which contains the "Ubuntu.vdi.zip" and run the following commands::

  unzip Ubuntu.vdi.zip
  qemu-img convert -f vdi -O qcow2 Ubuntu.vdi Ubuntu.qcow2

.. warning:: You can delete the .vdi file but be careful do not to delete the .qcow2 image!

Finally, run the following command::

  qemu-system-x86_64 Ubuntu.qcow2 -m 4G -netdev user,id=mynet0,hostfwd=tcp::6543-:22 -device e1000,netdev=mynet0

You have to wait a few seconds/minutes before the machine boots completely. Once fully booted, you must enter your credentials. Once you have logged on to the system, you need to run the following commands::

  ip addr show
  sudo dhclient -v ens3
  sudo apt update

If you don't see any errors, everything is working on your side and you can move on to the next step.

.. note:: Each time you will reboot the VM, you need to add your credentials and run the *dhclient* command to activate the network interface. You can investigate yourself to create a cronjob/crontab.

Connect to the VM by ssh
------------------------

Then open a terminal and enter the following commands::

  $ ssh student@127.0.0.1 -p 6543

The VM will ask your password. In that case, use the "student" credentials. Note that if you are using Windows, you can use PowerShell or CommandPrompt or `putty <https://www.putty.org>`_.

Update package information
--------------------------

Finally, enter the following command on your terminal app after connecting to the VM by ssh::

  $ sudo apt update

In a nutshell, this command updates the package lists for upgrades for packages that need upgrading, as well as new packages that have just come to the repositories. Note that, ``apt update`` does not actually install new versions of software.

After running this command, you can install apps/utilities via the ``apt install`` command::

  $ sudo apt install gcc make bison flex libncurses-dev openssh-server git curl wget

.. danger:: NEVER upgrade ubuntu 16 to ubuntu 18! Otherwise you will have some troubles with the submission platform.
