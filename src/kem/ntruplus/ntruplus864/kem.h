#ifndef KEM_H
#define KEM_H

#include "params.h"
#include "config.h"

#define crypto_kem_keypair NTRUPLUS_NAMESPACE(keypair)
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

#define crypto_kem_enc NTRUPLUS_NAMESPACE(enc)
int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk);

#define crypto_kem_dec NTRUPLUS_NAMESPACE(dec)
int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk);

#endif