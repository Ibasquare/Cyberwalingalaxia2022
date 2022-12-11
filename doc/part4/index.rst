.. CyberwalinGalaxia documentation master file, created by
   sphinx-quickstart on Fri Jun 10 23:25:15 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

###################################
Part 4 -- Advanced Dynamic Analysis
###################################

In this section, you will play with advanced dynamic techniques in order to analyse and update the behavior of a binary. For this part, we will take the previous sample that we used in part 2. As we have noticed earlier, the ``malware`` binary created some undesirable files on the disk by receiving specific commands from a remote server. Now, we will try to intercept these commands and understand their behavior.

In order to perform theses tasks, we will rely on a debugger (in our case, the Gnu Project Debugger ``gdb``). Unlike static analysis, we will execute the binary file by debugging it. The file is not actually malicious (the commands are harmless).

.. danger:: If you do not have access to Internet, make sure to run **inetsim** first (configured as local DNS - see Part 2) and run the binary with the ``--locahost`` argument.

The Gnu Project Debugger
************************

The Gnu Project Debugger can be used to study the behavior of a running program by examining its content (e.g., stack, variables, registers, ...) . It is also able to disassemble some code, i.e., showing the assembly code corresponding to the instructions.

You should be familiar with the use of gdb, but we will briefly review the most important commands you can use in this section. Note that you can also install `gdb gef <https://hugsy.github.io/gef/>`_ or `gdb pwndbg <hhttps://github.com/pwndbg/pwndbg>`_ to have gdb plug-in that makes debugging with gdb more intuitive (and fun?).

After running your program with ``gdb program`` where program is an executable program, you can use the following commands::

   run                   # run the program
   disassemble method    # disassembles a specified function or a function fragment
   break line_nb|method  # insert breakpoint at line_nb (can be a method)
   info functions        # list all functions
   info registers        # list all registers
   stepi (si)            # single step execution (line by line)
   next                  # continue to the next source line in the current (innermost) stack frame
   continue              # continue execution until the next breakpoint.
   x[/n] addr            # examine the memory (addr), where n is the number of words
   x/s addr              # examine the memory (addr) as a string
   p $pc                 # display the value of pc (you can display any registers)
   set $pc = addr        # set the value of pc to a specific address

If you need, you can use the `help` command to list all possible commands. There exists also various cheat-sheets available online such as `gdb_cheatsheet1 <https://gist.github.com/rkubik/b96c23bd8ed58333de37f2b8cd052c30>`_ or `gdb_cheatsheet2 <https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf>`_  

Objectives
**********

The study of the malicious sample may be divided in the following parts:

1. The first part consists of executing the ``malware`` binary file with gdb in order to intercept and see the content of the various messages exchanged with the remote server. What is the content of these messages? In addition, what is the remote address of the server?

2. After intercepting these messages, you notice that these commands are being executed on your machine. Try to intercept all the different commands (received by the remote server) by preventing them from being executed. How did you do this with gdb?

3. For this part, your task is to prevent the execution of remote commands by logging them instead. For this task, you **must not** use gdb or modify the binary file. To get a bit of help, it would be interesting to have a look at `LD_PRELOAD <https://man7.org/linux/man-pages/man8/ld.so.8.html>`_.

4. For this last part, the idea is to modify the binary in order to run it without executing any commands received remotely (when this one is executed without gdb). You can use tools like ``ghidra`` or ``hexedit`` to modify the content of the binary. Make sure you make a **backup** of your sample before modifying it. Is it possible to log (display) the commands? If so, how do you do it?

Good Luck.