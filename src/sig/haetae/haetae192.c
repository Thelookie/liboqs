// SPDX-License-Identifier: MIT

#include <stdlib.h>
#include <oqs/sig_haetae.h>

#if defined(OQS_ENABLE_SIG_haetae192)

extern int cryptolab_haetae3_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int cryptolab_haetae3_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int cryptolab_haetae3_ref_verify(const uint8_t *m, size_t mlen, const uint8_t *sig, size_t siglen, const uint8_t *pk);

#if defined(OQS_ENABLE_SIG_haetae192_avx)
extern int cryptolab_haetae3_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int cryptolab_haetae3_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
extern int cryptolab_haetae3_ref_verify(const uint8_t *m, size_t mlen, const uint8_t *sig, size_t siglen, const uint8_t *pk);
#endif

OQS_SIG *OQS_SIG_haetae192_new(void) {

    OQS_SIG *sig = malloc(sizeof(OQS_SIG));
    if (sig == NULL) {
        return NULL;
    }
    sig->method_name = OQS_SIG_alg_haetae192;
    sig->alg_version = "v1";

    sig->claimed_nist_level = 2;
    sig->euf_cma = true;

    sig->length_public_key = OQS_SIG_haetae192_length_public_key;
    sig->length_secret_key = OQS_SIG_haetae192_length_secret_key;
    sig->length_signature = OQS_SIG_haetae192_length_signature;

    sig->keypair = OQS_SIG_haetae192_keypair;
    sig->sign = OQS_SIG_haetae192_sign;
    sig->verify = OQS_SIG_haetae192_verify;

    return sig;
}

OQS_API OQS_STATUS OQS_SIG_haetae192_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_ENABLE_SIG_haetae192_avx)
    return (OQS_STATUS) cryptolab_haetae3_avx2_keypair(public_key, secret_key);
#else
    return (OQS_STATUS) cryptolab_haetae3_ref_keypair(public_key, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_SIG_haetae192_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_SIG_haetae192_avx)
    return (OQS_STATUS) cryptolab_haetae3_avx2_signature(signature, signature_len, message, message_len, secret_key);
#else
    return (OQS_STATUS) cryptolab_haetae3_ref_signature(signature, signature_len, message, message_len, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_SIG_haetae192_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key) {
#if defined(OQS_ENABLE_SIG_haetae192_avx)
    return (OQS_STATUS) cryptolab_haetae3_avx2_verify(signature, signature_len, message, message_len, public_key);
#else
    return (OQS_STATUS) cryptolab_haetae3_ref_verify(signature, signature_len,message, message_len, public_key);
#endif
}

#endif
