.. CyberwalinGalaxia documentation master file, created by
   sphinx-quickstart on Fri Jun 10 23:25:15 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

==============================
Part 1: Basic Dynamic Analysis
==============================

In the previous section, you studied some basic techniques of static binary analysis that allow you to characterize parts of an executable file without actually executing it. As such, these techniques most often involve analyzing the binary code to trace the data and control flows of the executable. Unfortunately, you have seen in the previous section that these techniques can be easily mitigated through obfuscation techniques and that basic tools often fail to provide valuable insights into the fundamental patterns within the binary file. In addition, the compilation of higher-level source code may result in very complex binary file that may be very hard to interpret by such basic tools.

In this section, you will learn how to complement these techniques with basic dynamic analysis techniques. These techniques will allow you to perform an actual characterization of the binary file of interest at runtime without risking corruption of your testbed. As such, the lab will consist of using state-of-the-art sandboxing tools to ensure the binary file is executed in a controlled environment. These sandboxing tools will allow you to both secure the dynamic analysis of an unknown binary file by preventing the execution of malicious/unwanted instructions on your actual setup and will also prevent any bias in the results that you obtain. Then, you will apply basic dynamic analysis techniques to further characterize the binary file studied at the end of the previous section.

----------
SandBoxing
----------

In cybersecurity, a sandbox is a controlled, isolated environment that mimics a given target environment. Such tools allows one to execute programs on a mock environment, minimizing the risk of
compromising live systems, while still providing similar runtime features as a target environment.

There exists many tool that can be used for sandboxing ranging from virtualization and containerization techniques to simpler isolation mechanisms such as linux namespaces, chroot jails, etc. In this lab, we will focus on two main aspects of sandboxing: network sandboxing and file system sandboxing.

~~~~~~~~~~~~~~~~~~
Network Sandboxing
~~~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~~~~~~~
File System Sandboxing
~~~~~~~~~~~~~~~~~~~~~~



.. toctree::
   :maxdepth: 2

