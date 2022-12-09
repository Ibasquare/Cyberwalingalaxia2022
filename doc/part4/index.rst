.. CyberwalinGalaxia documentation master file, created by
   sphinx-quickstart on Fri Jun 10 23:25:15 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

###################################
Part 4 -- Advanced Dynamic Analysis
###################################

In this section, you will play with advanced dynamic techniques in order to analyse and update the behavior of a binary. For this part, we will take the previous sample that we used in part 2. As we have noticed earlier, the TODO_NAME binary created some undesirable files on the disk by receiving specific commands from a remote server. Now, we will try to intercept these commands and understand their behavior without executing them.

In order to perform theses tasks, we will rely on a debugger (in our case, the Gnu Project Debugger `GDB`). Unlike static analysis, we will execute the binary file by debugging it. The file is not actually malicious (the commands are harmless).

------------------------
The Gnu Project Debugger
------------------------

The Gnu Project Debugger (GDB) can be used to study the behavior of a running program by examining its content (e.g., stack, variables, registers, ...) . It is also able to disassemble some code, i.e., showing the assembly code corresponding to the instructions.

Using GDB must be quite familiar to you nevertheless, we will give a very brief reminder with the most important commands that you may use for this part. Note that you can also install `GDB gef <https://hugsy.github.io/gef/>`_ or `GDB pwndbg <hhttps://github.com/pwndbg/pwndbg>`_ to have GDB plug-in that makes debugging with GDB more intuitive (and fun?).

After running your program with ``gdb program`` where program is an executable program, you can use the following commands::

   run                   # run the program
   disassemble method    # disassembles a specified function or a function fragment
   break line_nb         # insert breakpoint at line_nb (can be a method)
   step                  # continue running your program until control reaches a different source line
   next                  # continue to the next source line in the current (innermost) stack frame
   continue              # continue execution until the next breakpoint.
   x[/n] addr            # examine the memory, where n is the number of words and
                         # when addr is the address where you want GDB to begin displaying memory.
   p $pc                 # display the value of pc
   set $pc = addr        # set the value of pc to a specific address

If you need, you can use the `help` command to list all possible commands. There exists also various cheat-sheets available online such as `GDB_cheatsheet1 <https://gist.github.com/rkubik/b96c23bd8ed58333de37f2b8cd052c30>`_ or `GDB_cheatsheet2 <https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf>`_  

----------
Objectives
----------

The study of the malicious sample may be divided in the following parts:

1. The first part is to run the TODO_NAME binary file with gdb in order to intercept and see the content of the different messages exchanged with the remote server. What is the content of these messages? In addition, what is the remote address of the server?

2. After intercepting these messages, you notice that these commands are executed on your machine. Try to intercept all the different commands by preventing their execution on your machine. How did you do that with gdb?

3. For this part, the idea is to modify the binary in order to be able to display the commands without executing them when this last one is executed without gdb. You can use tools like ``ghidra`` or ``hexedit`` to modify the content of the binary. Make sure to do a **backup** of your sample before modifying it.

4. For this last part, take the previous backup of the binary (it must be unmodified). Your task is to avoid the execution of the remote commands by displaying them instead. For this task, you **must not use** gdb or modify the binary file. To get a bit of help, it would be interesting to have a look at `LD_PRELOAD < https://man7.org/linux/man-pages/man8/ld.so.8.html>`_.


Good Luck.