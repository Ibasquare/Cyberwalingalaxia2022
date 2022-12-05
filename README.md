#Material for cyberwalingalaxia2022.

##Agenda:
# Part 1: Basic Static Binary Analysis (~40min)
In this part, the student will study the following binary file:
``` c
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv){
	
	if(argc < 2)
		return 0;
	
	char* a = "alb";
	char* b = "inos";
	char* c = "atros";
	
	char secret_key [255];
	
	strcpy(secret_key, a);
	strcat(secret_key, c);
	
	if(!strcmp(secret_key, argv[1]))
		printf("Congrats, you found the secret key\n");
	else
		printf("Better luck next time...\n");
	
	return 0;
}
```
The idea is that they will compile this file in 3 ways:
1. Normal way
2. Stripped
3. Obfuscated/Packed -> UPX

Then, the students will analyze the binary files obtained these ways using several tools:
1. **file** to see that the binary file is using shared/static libraries.
2. **string** to check strings that are used in the binary files.
2. **nm** to mine the elf file.
2. **objdump** to mine the elf file.
3. **ldd** to mine the shared libraries required by the binary files.

## Part 1.2: Dynamic Binary Analysis

##Requirements:

```
apt-get install python3-sphinx (brew install sphinx-doc for MacOS)
pip install furo
```
