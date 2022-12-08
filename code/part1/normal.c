#include <stdio.h>
#include <string.h>

void caesar_decrypt(char* word, int shift){
	
	int N = strlen(word);
	for(int i = 0; i < N; i++){
	
		word[i] = 'a' + (word[i] - 'a' + shift) % 26;
	}
}

int main(int argc, char** argv){
	
	if(argc < 2){
		
		printf("Format: %s <password>\n", argv[0]);
		return 0;
	}
	
	const char* a = "zxbpxo";
	const int N = 7;
	
	char password [N];
	strcpy(password, a);
	caesar_decrypt(password, 3);
	
	if(!strcmp(password, argv[1]))
		printf("Congrats, you found the secret key!\n");
	else
		printf("Better luck next time...\n");
	
	return 0;
}


