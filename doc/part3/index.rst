.. CyberwalinGalaxia documentation master file, created by
   sphinx-quickstart on Fri Jun 10 23:25:15 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.


##################################
Part 3 -- Advanced Static Analysis
##################################
##################################

  
Ghidra: a static binary analysis tool
-------------------------------------

Ghidra is a tool for static binary analysis. It offers a user-friendly graphical interface, disassembly and decompilation functionalities as well as analysis tools for understandings the disassembled and decompiled code. It builds lists of functions, symbols, and can also help navigate in-between disassembled and decompiled code to understand better to which high-level instructions a set of assembly instructions can be mapped to.

To start with Ghidra, create a project and simply drag & drop the binary files that you want to analyze in the main project window.

A simple start: the empty program
---------------------------------

Compile the libc.c file with gcc::
	
	gcc libc.c -o libc
	
The libc.c file contains the simple program that can be written in the C language. It does nothing and returns 0. Its code is displayed below.

.. literalinclude:: libc.c

The nolibc.c contains equivalent code. Its only difference is that it does not rely on glibc for defining the main() function as the program's entry point. It can thus be compiled without it. Its code is displayed below.

.. literalinclude:: nolibc.c

It can be compiled without glibc with the command::

	gcc nolibc.c -o nolibc
	
Which of these 2 binaries will get the smallest binary size? Why? Check your theory with objdump and/or Ghidra. Could the nolibc binary be adapted to print "Hello world". Could it do it the standard way using printf?

Binary analysis with Ghidra
---------------------------

Have a look at funcs.c. Its code is displayed below.

.. literalinclude:: funcs.c

Compile it with gcc.::

	gcc funcs.c -o func1

You can now drag the func1 binary in you Ghidra project window to explore and analyze the result is contents. Have a look at the main function. 

* What do the function calls look like? How are arguments passed and how is the return value obtained?
* Where are the local variables stored? In particular, where is the array stored and in which form? How does that look in the decompiled code?
* Is there anything surprising about the arguments passed to the functions in the decompiled code? If one of the values passed to the function seems odd, can you explain why it makes sense and how it will be equivalent to the source code?

Have a look at the sum3 function.

* Can you identify the assembly structure corresponding to the for loop? How is its logic implemented?
* In the decompiled code, what does the access to the array's values look like? Why is it not more natural? Which information is the decompiler missing to write more readable code?
* How does the function return a value? What is the return convention?

Have a look at the sum and rec_sum functions. The rec_sum function is equivalent to the sum function but computes the sum of the array's elements recursively.

* What does the array look like in each case (both in assembly and decompiled code)?
* In rec_sum, can you identify the structure corresponding to the if statement in the assembly code? How is its logic implemented?
* In each case, is it obvious from the decompiled code that you are iterating over an array? Explain.

Compiler optimizations
----------------------

We are now going to study the impact of compiler optimization on the readability of disassembled and decompiled code. Recompile funcs.c with optimizations using the following command.::

	gcc funcs.c -O3 -o func2
	
Drag the resulting binary into Ghidra for analysis and comparison with its unoptimized counterpart.

* Have a look at the main() function. What do you observe? Could the compiler have generated the same instructions for the main function if the array was passed as user input? Why (not)?
* Compare the sum3() and sum() functions. In the unoptimized binary, they were very similar. What technique was applied to sum3() that could not be applied to sum()? Explain.
* Compare sum_rec() with sum() and its unoptimized version. What is the most notable thing about the optimization(s) that were applied?
* Compare sum() and sum_rec()'s optimized and unoptimized versions in terms of readability? What is the impact of optimizations on the ease to perform binary analysis? 
