// SPDX-License-Identifier: MIT

#ifndef OQS_SIG_HAETAE_H
#define OQS_SIG_HAETAE_H

#include <oqs/oqs.h>

#if defined(OQS_ENABLE_SIG_haetae128)
#define OQS_SIG_haetae128_length_public_key 992  // SEEDBYTES + 2 * POLYQ_PACKEDBYTES
#define OQS_SIG_haetae128_length_secret_key 1408 // public_key + 3 * POLYETA_PACKEDBYTES + 2 * POLY2ETA_PACKEDBYTES + SEEDBYTES
#define OQS_SIG_haetae128_length_signature 1474  // CRYPTO_BYTES

OQS_SIG *OQS_SIG_haetae128_new(void);
OQS_API OQS_STATUS OQS_SIG_haetae128_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae128_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae128_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_haetae192)
#define OQS_SIG_haetae192_length_public_key 1472 // SEEDBYTES + 3 * POLYQ_PACKEDBYTES
#define OQS_SIG_haetae192_length_secret_key 2112 // public_key + 5 * POLYETA_PACKEDBYTES + 3 * POLY2ETA_PACKEDBYTES + SEEDBYTES
#define OQS_SIG_haetae192_length_signature 2349  // CRYPTO_BYTES

OQS_SIG *OQS_SIG_haetae192_new(void);
OQS_API OQS_STATUS OQS_SIG_haetae192_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae192_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae192_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#if defined(OQS_ENABLE_SIG_haetae256)
#define OQS_SIG_haetae256_length_public_key 2080 // SEEDBYTES + 4 * POLYQ_PACKEDBYTES
#define OQS_SIG_haetae256_length_secret_key 2752 // public_key + 6 * POLYETA_PACKEDBYTES + 4 * POLY2ETA_PACKEDBYTES + SEEDBYTES
#define OQS_SIG_haetae256_length_signature 2948  // CRYPTO_BYTES

OQS_SIG *OQS_SIG_haetae256_new(void);
OQS_API OQS_STATUS OQS_SIG_haetae256_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae256_sign(uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);
OQS_API OQS_STATUS OQS_SIG_haetae256_verify(const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);
#endif

#endif
