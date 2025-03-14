#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "randombytes.h"
#include "cpucycles.h"

#define TEST_LOOP 100
extern int ntruplus864_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int ntruplus864_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int ntruplus864_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// 16진법으로 바이트 배열을 출력하는 함수
void print_hex_to_file(FILE *fp, const char *label, const unsigned char *data, size_t len);
void print_hex_to_file(FILE *fp, const char *label, const unsigned char *data, size_t len) {
    fprintf(fp, "%s: ", label);
    for (size_t i = 0; i < len; i++) {
        fprintf(fp, "%02X", data[i]);
    }
    fprintf(fp, "\n");
}
void print_hex(const char *label, const unsigned char *data, size_t len);
void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0) {  // 보기 좋게 16바이트마다 줄바꿈
            printf("\n");
        }
    }
    printf("\n");
}

static void TEST_CCA_KEM()
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	unsigned char ss[CRYPTO_BYTES];
	unsigned char dss[CRYPTO_BYTES];

	int cnt = 0;

	printf("============ CCA_KEM ENCAP DECAP TEST ============\n");

	//Generate public and secret key
	ntruplus864_ref_keypair(pk, sk);

	//Encrypt and Decrypt message
	for(int j = 0; j < TEST_LOOP; j++)
	{
		ntruplus864_ref_enc(ct, ss, pk);
		ntruplus864_ref_dec(dss, ct, sk);

		if(memcmp(ss, dss, 32) != 0)
		{
			printf("ss[%d]  : ", j);
			for(int i=0; i<32; i++) printf("%02X", ss[i]);
			printf("\n");
		
			printf("dss[%d] : ", j);
			for(int i=0; i<32; i++) printf("%02X", dss[i]);
			printf("\n");
		
			cnt++;
		}
	}
	printf("count: %d\n", cnt);
	printf("==================================================\n\n");

}

static void TEST_CCA_KEM_CLOCK()
{
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
	unsigned char ss[CRYPTO_BYTES];
	unsigned char dss[CRYPTO_BYTES];

    unsigned long long kcycles, ecycles, dcycles;
    unsigned long long cycles1, cycles2;

	printf("========= CCA KEM ENCAP DECAP SPEED TEST =========\n");

	kcycles=0;
	for (int i = 0; i < TEST_LOOP; i++)
	{
		cycles1 = cpucycles();
		ntruplus864_ref_keypair(pk, sk);
        cycles2 = cpucycles();
        kcycles += cycles2-cycles1;
	}
    printf("  KEYGEN runs in ................. %8lld cycles", kcycles/TEST_LOOP);
    printf("\n"); 

	ecycles=0;
	dcycles=0;
	for (int i = 0; i < TEST_LOOP; i++)
	{
		cycles1 = cpucycles();
		ntruplus864_ref_enc(ct, ss, pk);
        cycles2 = cpucycles();
        ecycles += cycles2-cycles1;

		cycles1 = cpucycles(); 
		ntruplus864_ref_dec(dss, ct, sk);
		cycles2 = cpucycles();
        dcycles += cycles2-cycles1;
	}

    printf("  ENCAP  runs in ................. %8lld cycles", ecycles/TEST_LOOP);
    printf("\n"); 

    printf("  DECAP  runs in ................. %8lld cycles", dcycles/TEST_LOOP);
    printf("\n"); 

	printf("==================================================\n");
}

int main(void)
{
	printf("PUBLICKEYBYTES : %d\n", CRYPTO_PUBLICKEYBYTES);
	printf("SECRETKEYBYTES : %d\n", CRYPTO_SECRETKEYBYTES);
	printf("CIPHERTEXTBYTES : %d\n", CRYPTO_CIPHERTEXTBYTES);

    unsigned char pk[CRYPTO_PUBLICKEYBYTES];  // 공개 키 저장
    unsigned char sk[CRYPTO_SECRETKEYBYTES];  // 비밀 키 저장

    // 파일 열기 (쓰기 모드, 기존 파일 덮어쓰기)
    FILE *file = fopen("mykeys.txt", "w");
    if (file == NULL) {
        printf("Error: Could not open file for writing\n");
        return 1;
    }

    // 10번 키 생성 및 출력
    for (int i = 0; i < 10; i++) {
        // 키 생성
        if (ntruplus864_ref_keypair(pk, sk) != 0) {
            printf("Key generation failed!\n");
            fclose(file);
            return 1;
        }

        // 공개 키와 비밀 키를 파일에 16진법으로 출력
        fprintf(file, "Key Pair %d\n", i + 1);
        print_hex_to_file(file, "Public Key (pk)", pk, CRYPTO_PUBLICKEYBYTES);
        print_hex_to_file(file, "Secret Key (sk)", sk, CRYPTO_SECRETKEYBYTES);
        fprintf(file, "\n");  // 각 키 쌍 사이에 공백 줄 추가
    }

    // 파일 닫기
    fclose(file);
    printf("Keys have been written to mykeys.txt\n");

	TEST_CCA_KEM();
	TEST_CCA_KEM_CLOCK();

	return 0;	
}