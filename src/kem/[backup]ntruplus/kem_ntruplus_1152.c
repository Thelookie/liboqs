// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/kem_ntruplus.h>

#if defined(OQS_ENABLE_KEM_ntruplus_1152)

OQS_KEM *OQS_KEM_ntruplus_1152_new(void) {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_ntruplus_1152;
	kem->alg_version = "v2";

	kem->claimed_nist_level = 1;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_ntruplus_1152_length_public_key;
	kem->length_secret_key = OQS_KEM_ntruplus_1152_length_secret_key;
	kem->length_ciphertext = OQS_KEM_ntruplus_1152_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_ntruplus_1152_length_shared_secret;

	kem->keypair = OQS_KEM_ntruplus_1152_keypair;
	kem->encaps = OQS_KEM_ntruplus_1152_encaps;
	kem->decaps = OQS_KEM_ntruplus_1152_decaps;

	return kem;
}

extern int ntruplus1152_ref_keypair(uint8_t *pk, uint8_t *sk);
extern int ntruplus1152_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int ntruplus1152_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#if defined(OQS_ENABLE_KEM_ntruplus_1152_avx2)
extern int ntruplus1152_avx2_keypair(uint8_t *pk, uint8_t *sk);
extern int ntruplus1152_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int ntruplus1152_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif


OQS_API OQS_STATUS OQS_KEM_ntruplus_1152_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_ntruplus_1152_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) ntruplus1152_avx2_keypair(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) ntruplus1152_ref_keypair(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) ntruplus1152_ref_keypair(public_key, secret_key);
#endif /* OQS_LIBJADE_BUILD */
}

OQS_API OQS_STATUS OQS_KEM_ntruplus_1152_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
#if defined(OQS_ENABLE_KEM_ntruplus_1152_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) ntruplus1152_avx2_enc(ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) ntruplus1152_ref_enc(ciphertext, shared_secret, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) ntruplus1152_ref_enc(ciphertext, shared_secret, public_key);
#endif /* OQS_LIBJADE_BUILD */
}

OQS_API OQS_STATUS OQS_KEM_ntruplus_1152_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
#if defined(OQS_ENABLE_KEM_ntruplus_1152_avx2)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) ntruplus1152_avx2_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) ntruplus1152_ref_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) ntruplus1152_ref_dec(shared_secret, ciphertext, secret_key);
#endif /* OQS_LIBJADE_BUILD */
}

#endif
