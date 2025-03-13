// SPDX-License-Identifier: MIT

#ifndef OQS_KEM_PALOMA_H
#define OQS_KEM_PALOMA_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_KEM_paloma_128)
#define OQS_KEM_paloma_128_length_public_key 319488
#define OQS_KEM_paloma_128_length_secret_key 94528
#define OQS_KEM_paloma_128_length_ciphertext 136
#define OQS_KEM_paloma_128_length_shared_secret 32
OQS_KEM *OQS_KEM_paloma_128_new(void);
OQS_API OQS_STATUS OQS_KEM_paloma_128_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_paloma_128_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_paloma_128_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_paloma_192)
#define OQS_KEM_paloma_192_length_public_key 812032
#define OQS_KEM_paloma_192_length_secret_key 357568
#define OQS_KEM_paloma_192_length_ciphertext 240
#define OQS_KEM_paloma_192_length_shared_secret 32
OQS_KEM *OQS_KEM_paloma_192_new(void);
OQS_API OQS_STATUS OQS_KEM_paloma_192_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_paloma_192_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_paloma_192_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_paloma_256)
#define OQS_KEM_paloma_256_length_public_key 1025024
#define OQS_KEM_paloma_256_length_secret_key 359616
#define OQS_KEM_paloma_256_length_ciphertext 240
#define OQS_KEM_paloma_256_length_shared_secret 32
OQS_KEM *OQS_KEM_paloma_256_new(void);
OQS_API OQS_STATUS OQS_KEM_paloma_256_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_paloma_256_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_paloma_256_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#endif
