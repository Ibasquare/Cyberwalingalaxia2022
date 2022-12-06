# Material for cyberwalingalaxia2022.

## Roadmap:
### Part 1: Basic Static Binary Analysis (~40min)
In this part, the student will staticly study a binary file that has networking (ssl?) and i/o capabilities that has been compiled in 3 different ways:
1. Normal way
2. Stripped
3. Obfuscated/Packed -> UPX

Then, the students will analyze the binary files obtained these ways using several tools:
1. **file** to see that the binary file is using shared/static libraries.
2. **string** to check strings that are used in the binary files.
2. **nm** to mine the elf file.
2. **objdump** to mine the elf file.
3. **ldd** to mine the shared libraries required by the binary files.

### Part 2: Basic Dynamic Binary Analysis (~1hour)
In this part, the student will analyze some of the basic operations that malicious binary files may attempt to perform:
1. Network functionalities -> Download malicious payloads through a socket on a web server. 
2. I/Os functionalities -> File operation on controlled environment (file system isolation?).

To do so, they will mainly use two tools:
1. INetSim/BurpSuite (cfr. https://infosecaddicts.com/set-up-a-malware-analysis-lab-with-inetsim-and-burpsuite/)
2. IWatch (cfr. https://iwatch.sourceforge.net/index.html)

### Part 3: Advanced Static Binary Analysis (~40min)
In this part, the student will re-analyze the files of **Part 1** and will compare with the results obtained in **Part 1**. Then, the students will investigate stack analysis techniques (e.g. using **-fno-stack-protector** disabling) and advanced binary analysis (e.g. using **radare2**). Decompilation? 

### Part 4: Advanced Dynamic Binary Analysis (~40min)
In this part, the student will use dynamic reverse-engineering techniques to understand the instruction executed by the binary file studied in **Part 1** (e.g. using the debugging tool **gdb**, **gef** or **gdb-pwn2**).

## Build the Tutorial (html)
### Requirements:

```
apt-get install python3-sphinx (brew install sphinx-doc for MacOS)
pip install furo
```
### Execution:
```
cd doc
make hmtl
open _build/html/index.html 
```
