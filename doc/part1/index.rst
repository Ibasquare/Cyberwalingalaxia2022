.. CyberwalinGalaxia documentation master file, created by
   sphinx-quickstart on Fri Jun 10 23:25:15 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

###############################
Part 1 -- Basic Static Analysis
###############################
###############################

Lab material
************

In this lab, you will explore many binary reverse engineering techniques. In this first part, you will use basic static analysis techniques on a set of binaries whose source code you do not have in order to achieve a basic understanding of their logic. 

.. note:: The material for all lab parts can be downloaded as a `zip archive <https://dox.uliege.be/index.php/s/ETLfkuFShPvPrAJ/download>`_. This zip archive contains one folder per part of the lab. Each folder contains the files for the corresponding part.

Lab tools
*********

All tools listed below are readily available in the reference virtual machine (Kali 2022.4). If you are using something else, please make sure to use UPX version 3.96 (https://github.com/upx/upx/releases/tag/v3.96).

* ``md5sum`` can be used to compute the MD5 signature of a given file. This is useful to check files against databases of known malware signatures. Never run a binary whose signature is in such a database.
* ``file`` can be used to determine whether a binary is statically or dynamically linked and whether the binary is stripped or not. A stripped binary does not contain any symbolic information (e.g. function names) which makes it more difficult to analyze.
* ``ldd`` can provide a list of the dynamically linked libraries used by the binary
* ``strings`` can provide a list of all printable strings found in a binary. By default, it only prints strings of length greater than 3 to restrict the output's length but this minimum string length can be configured through the ``-n`` flag.
* ``nm`` provides the list of symbols found within a binary if it contains any. It will only be of use if the binary is not stripped.
* ``objdump`` allows to interpret the binary's contents. A particularly useful flag is ``-S`` which allows to have a quick look at the disassembled code (i.e. the machine code is translated in human-readable assembly language). More advanced tools will be presented in Part 3, but it may still be of interest to have a quick look at the assembly. In particular, looking at which functions are called (only possible for non-stripped binaries) can shed some light on the inner workings of a binary without delving too deep into the assembly code.
* ``upx`` is a packer. Its main purpose is not obfuscation but it can be used to make static binary analysis more difficult by hiding a binary's real code. It modifies a binary by storing its code within a string in another which starts with a small bootstrap code that retrieves the real code from the string, stores it in memory and executes it. 
	- ``upx <filename>`` modifies the file so that it is packed.
	- ``upx -d <filename>`` can be used to retrieve the original binary from a packed binary.
	
Malware signature database
**************************

You have been provided with the following database of MD5 signatures of malicious files. Check every binary you get your hands on against it. 

* c26866ad6efeff7ad2f555ac42cb1d4f
* 641931f6ed670acf54ce5d1af07c58ba
* 51039fa833ea00f5a4c75ab4ca0db2ae

A first mystery file
********************

Analyze the ``mystery1`` binary with your tools.

* Check the file against your malware signature database. If it is not found in there, you may run it.
* Is this a stripped binary?
* What are the dynamically linked library it uses?
* Find the secret passphrase. Use all tools at your disposal.

A second mystery file
*********************

Analyze the ``mystery2`` binary with your tools.

* Check the file against your malware signature database. If it is not found in there, you may run it.
* Is this a stripped binary?
* What are the dynamically linked library it uses?
* Find the secret passphrase. Use all tools at your disposal.

Malware analysis
****************

Dynamic analysis techniques have shown that the ``malware`` binary file displays suspicious behavior on the network. Never run it.

* Check the file against your malware signature database. Can you find it in there?
* Is this a stripped binary?
* Does it rely on any dynamic libraries?
* Is there anything weird about the results of the analysis of this binary file? Explain a likely cause of your observations.
* Deal with issue mentioned above. Is anything different now about your analysis? Can you find a new use to your signature database? 
* Can you observe anything that would suggest malicious network communication? Explain.


