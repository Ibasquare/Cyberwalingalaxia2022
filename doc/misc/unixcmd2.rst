UNIX Commands (2)
=================

OS Information
--------------

Show OS kernel version.::

  $ uname -a

Show CPU information::

  $ cat /proc/cpuinfo

Show OS processes 1::

  $ top

Show OS processes 2::

  $ ps aux

Show network interface information::

  $ ip addr

Show memory utilization::

  $ free

Text processing
---------------

Print lines including PATTERN::

  $ (do output) | grep PATTERN

grep example: showing CPU model name, and removing other info from /proc/cpuinfo::

  $ cat /proc/cpuinfo | grep "model name"

Advanced grep example: printing only the first line using awk. awk is a text processing language. awk is complicated but quite useful. Please look into it if you are interested in.::

  $ cat /proc/cpuinfo | grep "model name" | awk 'NR==1'

File search
-----------

Print lines FROM FILES UNDER CURRENT DIRECTORY including PATTERN::

  $ grep PATTERN -r ./

Find a file named FILE_NAME under current directory.::

  $ find ./ -name FILE_NAME -ls
