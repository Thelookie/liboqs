// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <oqs/kem_smaugt.h>

#if defined(OQS_ENABLE_KEM_smaugt_256)

OQS_KEM *OQS_KEM_smaugt_256_new(void) {

    OQS_KEM *kem = malloc(sizeof(OQS_KEM));
    if (kem == NULL) {
        return NULL;
    }
    kem->method_name = OQS_KEM_alg_smaugt_256;
    kem->alg_version = "v1";

    kem->claimed_nist_level = 1;
    kem->ind_cca = true;

    kem->length_public_key = OQS_KEM_smaugt_256_length_public_key;
    kem->length_secret_key = OQS_KEM_smaugt_256_length_secret_key;
    kem->length_ciphertext = OQS_KEM_smaugt_256_length_ciphertext;
    kem->length_shared_secret = OQS_KEM_smaugt_256_length_shared_secret;

    kem->keypair = OQS_KEM_smaugt_256_keypair;
    kem->encaps = OQS_KEM_smaugt_256_encaps;
    kem->decaps = OQS_KEM_smaugt_256_decaps;

    return kem;
}

extern int cryptolab_smaug5_ref_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int cryptolab_smaug5_ref_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int cryptolab_smaug5_ref_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#if defined(OQS_ENABLE_KEM_smaugt_256_avx2)
extern int cryptolab_smaug5_avx2_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
extern int cryptolab_smaug5_avx2_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int cryptolab_smaug5_avx2_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

OQS_API OQS_STATUS OQS_KEM_smaugt_256_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_smaugt_256_avx2)
    return (OQS_STATUS) cryptolab_smaug5_avx2_crypto_kem_keypair(public_key, secret_key);
#else
    return (OQS_STATUS) cryptolab_smaug5_ref_crypto_kem_keypair(public_key, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_smaugt_256_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
#if defined(OQS_ENABLE_KEM_smaugt_256_avx2)
    return (OQS_STATUS) cryptolab_smaug5_avx2_crypto_kem_enc(ciphertext, shared_secret, public_key);
#else
    return (OQS_STATUS) cryptolab_smaug5_ref_crypto_kem_enc(ciphertext, shared_secret, public_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_smaugt_256_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_smaugt_256_avx2)
    return (OQS_STATUS) cryptolab_smaug5_avx2_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#else
    return (OQS_STATUS) cryptolab_smaug5_ref_crypto_kem_dec(shared_secret, ciphertext, secret_key);
#endif
}


#endif
