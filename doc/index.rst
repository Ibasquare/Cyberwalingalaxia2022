.. CyberwalinGalaxia documentation master file, created by
   sphinx-quickstart on Fri Jun 10 23:25:15 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

|

.. image:: images/main_page.png
   :width: 600
   :align: center

|

Welcome to ULiege's Malware Reverse Engineering Lab, which focuses on
fundamentals of malware reverse engineering.

This site contains the tutorial that will help you understand the
important concepts related to Malware Reverse Engineering discussed
during the theoretical part given by Prof. Laurent Mathy.

This lab work is presented as a hands-on tutorial and participants are
encouraged to follow along and work through the different exercises.
Feel free to ask questions or request clarifications at any point
during the workshop.

.. warning:: 
   **DISCLAIMER**: This tutorial is intended for academic purposes only, and the methods suggested in further sections should be used with particular care when handling real suspicious/malicious programs. In particular, not all security policies are enforced by all techniques, and many simplifications have been made to meet the timing requirements of this lab. 
   
   The binary files that you will study in this lab are **harmless** and only mimic some of the behavior that real malware can exhibit.

Requirements
************

There are only two hard requirements in order to follow along with the workshop:

* 3 hours of your time
* An interest in binary analysis and/or reverse engineering
* A Linux machine with administrative privileges with the following software/package: ``md5sum``, ``gdb``, ``ghidra``, ``inetsim``, ``file``, ``ldd``, ``strace``, ``xxd``, ``hexedit``, and ``gcc``.

.. note:: The material for all lab parts can be downloaded as a `zip archive <https://dox.uliege.be/index.php/s/Tk9ywgpdjziBGYJ/download>`_. This zip archive contains one folder per part of the lab. Each folder contains the files for the corresponding part.

Tutorial
********

.. toctree::
   :maxdepth: 2

   installation/index
   part1/index
   part2/index
   part3/index
   part4/index
   contact/index

.. Indices and tables
.. ==================

.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`
