#include <stdio.h>
#include <string.h>

int main(int argc, char** argv){
	
	if(argc < 2){
		
		printf("Format: %s <password>\n", argv[0]);
		return 0;
	}
	
	const char* a = "alba";
	const char* b = "nian";
	const char* c = "tros";
	
	char secret_key [255];
	
	strcpy(secret_key, a);
	strcat(secret_key, c);
	
	if(!strcmp(secret_key, argv[1]))
		printf("Congrats, you found the secret key!\n");
	else
		printf("Better luck next time...\n");
	
	return 0;
}
