#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

int main(){
	FILE* fp1 = fopen("five-hundred.bin", "rb");
	FILE* fp2 = fopen("thousand.bin", "rb");
	uint32_t n1, n2;
        size_t byte1 = fread(&n1, sizeof(uint32_t), 1, fp1);
	size_t byte2 = fread(&n2, sizeof(uint32_t), 1, fp2);
	n1 = ntohl(n1);
	n2 = ntohl(n2);
	printf("%d(%x) + %d(%x) = %d(%x)",n1,n1,n2,n2,n1+n2,n1+n2);
	fclose(fp1);
    	fclose(fp2);
	return 0;
}
