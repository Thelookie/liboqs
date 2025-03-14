#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "params.h"
#include "config.h"

/*
 * Elements of R_q = Z_q[X]/(X^n - X^n/2 + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*xoeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
  int16_t coeffs[NTRUPLUS_N];
} poly;

#define poly_tobytes NTRUPLUS_NAMESPACE(poly_tobytes)
void poly_tobytes(uint8_t r[NTRUPLUS_POLYBYTES], const poly *a);
#define poly_frombytes NTRUPLUS_NAMESPACE(poly_frombytes)
void poly_frombytes(poly *r, const uint8_t a[NTRUPLUS_POLYBYTES]);
#define poly_ntt NTRUPLUS_NAMESPACE(poly_ntt)
void poly_ntt(poly *r, const poly *a);
#define poly_invntt NTRUPLUS_NAMESPACE(poly_invntt)
void poly_invntt(poly *r, const poly *a);
#define poly_add NTRUPLUS_NAMESPACE(poly_add)
void poly_add(poly *r, const poly *a, const poly *b);
#define poly_sub NTRUPLUS_NAMESPACE(poly_sub)
void poly_sub(poly *c, const poly *a, const poly *b);
#define poly_triple NTRUPLUS_NAMESPACE(poly_triple)
void poly_triple(poly *r);
#define poly_basemul NTRUPLUS_NAMESPACE(poly_basemul)
void poly_basemul(poly *r, const poly *a, const poly *b);
#define poly_baseinv NTRUPLUS_NAMESPACE(poly_baseinv)
int poly_baseinv(poly *r, const poly *a);
#define poly_crepmod3 NTRUPLUS_NAMESPACE(poly_crepmod3)
void poly_crepmod3(poly *b, const poly *a);
#define poly_reduce NTRUPLUS_NAMESPACE(poly_reduce)
void poly_reduce(poly *a);
#define poly_freeze NTRUPLUS_NAMESPACE(poly_freeze)
void poly_freeze(poly *a);
#define poly_cbd1 NTRUPLUS_NAMESPACE(poly_cbd1)
void poly_cbd1(poly *r, const uint8_t buf[NTRUPLUS_N/4]);
#define poly_sotp NTRUPLUS_NAMESPACE(poly_sotp)
void poly_sotp(poly *e, const unsigned char *msg, const unsigned char *buf);
#define poly_sotp_inv NTRUPLUS_NAMESPACE(poly_sotp_inv)
int poly_sotp_inv(unsigned char *msg, const poly *e, const unsigned char *buf);

#endif