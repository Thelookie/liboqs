#include <stdio.h>
#include <time.h>

#include "../include/randombytes.h"
#include "cpucycles.h"
#include "fft.h"
#include "ntt.h"
#include "params.h"
#include "polyfix.h"
#include "polymat.h"
#include "polyvec.h"
#include "sign.h"
#include "consts.h"
#include "speed_print.h"

#define NTESTS 10000

uint64_t t[NTESTS];

int main() {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES], byte;
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES];
    uint8_t msg[SEEDBYTES * 2];
    size_t siglen;
    int i = 0;
    clock_t srt, ed;
    clock_t overhead;
    polyvecm mat[K];
    polyvecl matl[K] = {0};
    polyfixvecl y1;
    polyfixveck y2;
    polyvecl vecl;
    polyvecm s1;
    polyveck s2;
    poly *a = &mat[0].vec[0];
    poly *b = &mat[0].vec[1];
    poly *c = &mat[0].vec[2];
    poly_complex_fp32_16 fft_in;

    randombytes(msg, SEEDBYTES);
    overhead = clock();
    cpucycles();
    overhead = clock() - overhead;

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polymatkm_expand(mat, msg);
    }
    print_results("polymatkm_expand:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polymatkl_double(matl);
    }
    print_results("\npolymatkl_double:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyfixveclk_sample_hyperball(&y1, &y2, &byte, msg, i);
    }
    print_results("\npolyfixveclk_sample_hyperball:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyvecmk_uniform_eta(&s1, &s2, msg, i);
    }
    print_results("\npolyvecmk_uniform_eta:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        fft_init_and_bitrev(&fft_in, &s2.vec[i % K]);
        fft(&fft_in);
    }
    print_results("\nfft_bitrev + fft:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        ntt_avx(&a->vec[0], qdata.vec);
    }
    print_results("\nntt:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polymatkm_pointwise_montgomery(&s2, mat, &s1);
    }
    print_results("\npolymatkm_pointwise_montgomery:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyfixvecl_round(&vecl, &y1);
        polyfixveck_round(&s2, &y2);
    }
    print_results("\npolyfixvecl_round + polyfixveck_round:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyvecl_cneg(&vecl, i&1);
        polyveck_cneg(&s2, i&1);
    }
    print_results("\npolyvecl_cneg + polyveck_cneg:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyvecl_sqnorm2(&vecl);
        polyveck_sqnorm2(&s2);
    }
    print_results("\npolyvecl_sqnorm2 + polyveck_sqnorm2:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyveck_caddDQ2ALPHA(&s2);
        polyveck_csubDQ2ALPHA(&s2);
    }
    print_results("\npolyveck_caddDQ2ALPHA + polyveck_csubDQ2ALPHA:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyveck_poly_fromcrt(&s2, &s2, a);
    }
    print_results("\npolyveck_poly_fromcrt:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyveck_mul_alpha(&s2, &s2);
    }
    print_results("\npolyveck_mul_alpha:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyveck_highbits_hint(&s2, &s2);
    }
    print_results("\npolyveck_highbits_hint:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyveck_freeze2q(&s2);
    }
    print_results("\npolyveck_freeze2q:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        polyveck_reduce2q(&s2);
    }
    print_results("\npolyveck_reduce2q:", t, NTESTS);

    for (i = 0; i < NTESTS; ++i) {
        t[i] = cpucycles();
        poly_lsb(a, b);
    }
    print_results("\npoly_lsb:", t, NTESTS);

    srt = clock();
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        crypto_sign_keypair(pk, sk);
    }
    ed = clock();
    print_results("\ncrypto_sign_keypair: ", t, NTESTS);
    printf("time elapsed: %.8fms\n\n", (double)(ed - srt - overhead * NTESTS) *
                                           1000 / CLOCKS_PER_SEC / NTESTS);

    srt = clock();
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        crypto_sign_signature(sig, &siglen, sig, SEEDBYTES, sk);
    }
    ed = clock();
    print_results("crypto_sign_signature: ", t, NTESTS);
    printf("time elapsed: %.8fms\n\n", (double)(ed - srt - overhead * NTESTS) *
                                           1000 / CLOCKS_PER_SEC / NTESTS);
    
    

    srt = clock();
    size_t cnt = 0;
    while ((double)(clock() - srt) / CLOCKS_PER_SEC < 10) {
        crypto_sign_signature(sig, &siglen, sig, SEEDBYTES, sk);
        cnt += 1;
    }
    ed = clock();
    printf("crypto_sign_signature: %lu iterations ", cnt);
    printf("time elapsed: %.8fms\n\n", (double)(ed - srt - overhead * cnt) *
                                           1000 / CLOCKS_PER_SEC / cnt);



    crypto_sign_signature(sig, &siglen, msg, SEEDBYTES, sk);
    srt = clock();
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        crypto_sign_verify(sig, siglen, msg, SEEDBYTES, pk);
    }
    ed = clock();
    print_results("crypto_sign_verify: ", t, NTESTS);
    printf("time elapsed: %.8fms\n\n", (double)(ed - srt - overhead * NTESTS) *
                                           1000 / CLOCKS_PER_SEC / NTESTS);
    return 0;
}
