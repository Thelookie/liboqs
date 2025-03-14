// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/kem_ntruplus.h>
#include "ntruplus864/api.h"

#if defined(OQS_ENABLE_KEM_ntruplus_864)

OQS_KEM *OQS_KEM_ntruplus_864_new(void) {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_ntruplus_864;
	kem->alg_version = "v2";

	kem->claimed_nist_level = 1;
	kem->ind_cca = true;

	kem->length_public_key = CRYPTO_PUBLICKEYBYTES;
	kem->length_secret_key = CRYPTO_SECRETKEYBYTES;
	kem->length_ciphertext = CRYPTO_CIPHERTEXTBYTES;
	kem->length_shared_secret = CRYPTO_BYTES;

	kem->keypair = crypto_kem_keypair;
	kem->encaps = crypto_kem_enc;
	kem->decaps = crypto_kem_dec;

	return kem;
}

//extern int ntruplus864_ref_keypair(uint8_t *pk, uint8_t *sk);
//extern int ntruplus864_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
//extern int ntruplus864_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#if defined(OQS_ENABLE_KEM_ntruplus_864_avx2)
extern int ntruplus864_avx2_keypair(uint8_t *pk, uint8_t *sk);
extern int ntruplus864_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int ntruplus864_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif


// OQS_API OQS_STATUS OQS_KEM_ntruplus_864_keypair(uint8_t *public_key, uint8_t *secret_key) {
// #if defined(OQS_ENABLE_KEM_ntruplus_864_avx2)
// #if defined(OQS_DIST_BUILD)
// 	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
// #endif /* OQS_DIST_BUILD */
// 		return (OQS_STATUS) ntruplus864_avx2_keypair(public_key, secret_key);
// #if defined(OQS_DIST_BUILD)
// 	} else {
// 		return (OQS_STATUS) ntruplus864_ref_keypair(public_key, secret_key);
// 	}
// #endif /* OQS_DIST_BUILD */
// #else
// 	return (OQS_STATUS) ntruplus864_ref_keypair(public_key, secret_key);
// #endif /* OQS_LIBJADE_BUILD */
// }

// OQS_API OQS_STATUS OQS_KEM_ntruplus_864_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
// #if defined(OQS_ENABLE_KEM_ntruplus_864_avx2)
// #if defined(OQS_DIST_BUILD)
// 	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
// #endif /* OQS_DIST_BUILD */
// 		return (OQS_STATUS) ntruplus864_avx2_enc(ciphertext, shared_secret, public_key);
// #if defined(OQS_DIST_BUILD)
// 	} else {
// 		return (OQS_STATUS) ntruplus864_ref_enc(ciphertext, shared_secret, public_key);
// 	}
// #endif /* OQS_DIST_BUILD */
// #else
// 	return (OQS_STATUS) ntruplus864_ref_enc(ciphertext, shared_secret, public_key);
// #endif /* OQS_LIBJADE_BUILD */
// }

// OQS_API OQS_STATUS OQS_KEM_ntruplus_864_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
// #if defined(OQS_ENABLE_KEM_ntruplus_864_avx2)
// #if defined(OQS_DIST_BUILD)
// 	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
// #endif /* OQS_DIST_BUILD */
// 		return (OQS_STATUS) ntruplus864_avx2_dec(shared_secret, ciphertext, secret_key);
// #if defined(OQS_DIST_BUILD)
// 	} else {
// 		return (OQS_STATUS) ntruplus864_ref_dec(shared_secret, ciphertext, secret_key);
// 	}
// #endif /* OQS_DIST_BUILD */
// #else
// 	return (OQS_STATUS) ntruplus864_ref_dec(shared_secret, ciphertext, secret_key);
// #endif /* OQS_LIBJADE_BUILD */
// }

#endif
