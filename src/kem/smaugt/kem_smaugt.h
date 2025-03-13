// SPDX-License-Identifier: MIT

#ifndef OQS_KEM_SMAUGT_H
#define OQS_KEM_SMAUGT_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_KEM_smaugt_128)
#define OQS_KEM_smaugt_128_length_public_key 672
#define OQS_KEM_smaugt_128_length_secret_key 832
#define OQS_KEM_smaugt_128_length_ciphertext 672
#define OQS_KEM_smaugt_128_length_shared_secret 32
OQS_KEM *OQS_KEM_smaugt_128_new(void);
OQS_API OQS_STATUS OQS_KEM_smaugt_128_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_128_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_128_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_smaugt_192)
#define OQS_KEM_smaugt_192_length_public_key 1088
#define OQS_KEM_smaugt_192_length_secret_key 1312
#define OQS_KEM_smaugt_192_length_ciphertext 992
#define OQS_KEM_smaugt_192_length_shared_secret 32
OQS_KEM *OQS_KEM_smaugt_192_new(void);
OQS_API OQS_STATUS OQS_KEM_smaugt_192_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_192_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_192_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#if defined(OQS_ENABLE_KEM_smaugt_256)
#define OQS_KEM_smaugt_256_length_public_key 1440
#define OQS_KEM_smaugt_256_length_secret_key 1792
#define OQS_KEM_smaugt_256_length_ciphertext 1376
#define OQS_KEM_smaugt_256_length_shared_secret 32
OQS_KEM *OQS_KEM_smaugt_256_new(void);
OQS_API OQS_STATUS OQS_KEM_smaugt_256_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_256_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_smaugt_256_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);
#endif

#endif
