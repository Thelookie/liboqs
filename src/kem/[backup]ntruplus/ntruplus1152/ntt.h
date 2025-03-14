#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "params.h"
#include "config.h"
#define zetas NTRUPLUS_NAMESPACE(zetas)
extern const int16_t zetas[384];

#define ntt NTRUPLUS_NAMESPACE(ntt)
void ntt(int16_t r[NTRUPLUS_N], const int16_t a[NTRUPLUS_N]);
#define invntt NTRUPLUS_NAMESPACE(invntt)
void invntt(int16_t r[NTRUPLUS_N], const int16_t a[NTRUPLUS_N]);
#define basemul NTRUPLUS_NAMESPACE(basemul)
void basemul(int16_t r[3], const int16_t a[3], const int16_t b[3], int16_t zeta);
#define baseinv NTRUPLUS_NAMESPACE(baseinv)
int  baseinv(int16_t r[3], const int16_t a[3], int16_t zeta);

#endif