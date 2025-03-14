#include "sha2.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "randombytes.h"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <errno.h>
#ifdef __linux__
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#else
#include <unistd.h>
#endif
#endif



//////////combined common functions/////////////////

static uint32_t load_bigendian(const uint8_t *x)
{
  return
      (uint32_t) (x[3]) \
  | (((uint32_t) (x[2])) << 8) \
  | (((uint32_t) (x[1])) << 16) \
  | (((uint32_t) (x[0])) << 24)
  ;
}

static void store_bigendian(uint8_t *x,uint32_t u)
{
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}

#define SHR(x,c) ((x) >> (c))
#define ROTR(x,c) (((x) >> (c)) | ((x) << (32 - (c))))

#define Ch(x,y,z) ((x & y) ^ (~x & z))
#define Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x,18) ^ SHR(x, 3))
#define sigma1(x) (ROTR(x,17) ^ ROTR(x,19) ^ SHR(x,10))

#define M(w0,w14,w9,w1) w0 = sigma1(w14) + w9 + sigma0(w1) + w0;

#define EXPAND \
  M(w0 ,w14,w9 ,w1 ) \
  M(w1 ,w15,w10,w2 ) \
  M(w2 ,w0 ,w11,w3 ) \
  M(w3 ,w1 ,w12,w4 ) \
  M(w4 ,w2 ,w13,w5 ) \
  M(w5 ,w3 ,w14,w6 ) \
  M(w6 ,w4 ,w15,w7 ) \
  M(w7 ,w5 ,w0 ,w8 ) \
  M(w8 ,w6 ,w1 ,w9 ) \
  M(w9 ,w7 ,w2 ,w10) \
  M(w10,w8 ,w3 ,w11) \
  M(w11,w9 ,w4 ,w12) \
  M(w12,w10,w5 ,w13) \
  M(w13,w11,w6 ,w14) \
  M(w14,w12,w7 ,w15) \
  M(w15,w13,w8 ,w0 )

#define F(w,k) \
  T1 = h + Sigma1(e) + Ch(e,f,g) + k + w; \
  T2 = Sigma0(a) + Maj(a,b,c); \
  h = g; \
  g = f; \
  f = e; \
  e = d + T1; \
  d = c; \
  c = b; \
  b = a; \
  a = T1 + T2;

static int crypto_hashblocks_sha256(uint8_t *statebytes,const uint8_t *in,size_t inlen)
{
  uint32_t state[8];
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
  uint32_t e;
  uint32_t f;
  uint32_t g;
  uint32_t h;
  uint32_t T1;
  uint32_t T2;

  a = load_bigendian(statebytes +  0); state[0] = a;
  b = load_bigendian(statebytes +  4); state[1] = b;
  c = load_bigendian(statebytes +  8); state[2] = c;
  d = load_bigendian(statebytes + 12); state[3] = d;
  e = load_bigendian(statebytes + 16); state[4] = e;
  f = load_bigendian(statebytes + 20); state[5] = f;
  g = load_bigendian(statebytes + 24); state[6] = g;
  h = load_bigendian(statebytes + 28); state[7] = h;

  while (inlen >= 64) {
    uint32_t w0  = load_bigendian(in +  0);
    uint32_t w1  = load_bigendian(in +  4);
    uint32_t w2  = load_bigendian(in +  8);
    uint32_t w3  = load_bigendian(in + 12);
    uint32_t w4  = load_bigendian(in + 16);
    uint32_t w5  = load_bigendian(in + 20);
    uint32_t w6  = load_bigendian(in + 24);
    uint32_t w7  = load_bigendian(in + 28);
    uint32_t w8  = load_bigendian(in + 32);
    uint32_t w9  = load_bigendian(in + 36);
    uint32_t w10 = load_bigendian(in + 40);
    uint32_t w11 = load_bigendian(in + 44);
    uint32_t w12 = load_bigendian(in + 48);
    uint32_t w13 = load_bigendian(in + 52);
    uint32_t w14 = load_bigendian(in + 56);
    uint32_t w15 = load_bigendian(in + 60);

    F(w0 ,0x428a2f98)
    F(w1 ,0x71374491)
    F(w2 ,0xb5c0fbcf)
    F(w3 ,0xe9b5dba5)
    F(w4 ,0x3956c25b)
    F(w5 ,0x59f111f1)
    F(w6 ,0x923f82a4)
    F(w7 ,0xab1c5ed5)
    F(w8 ,0xd807aa98)
    F(w9 ,0x12835b01)
    F(w10,0x243185be)
    F(w11,0x550c7dc3)
    F(w12,0x72be5d74)
    F(w13,0x80deb1fe)
    F(w14,0x9bdc06a7)
    F(w15,0xc19bf174)

    EXPAND

    F(w0 ,0xe49b69c1)
    F(w1 ,0xefbe4786)
    F(w2 ,0x0fc19dc6)
    F(w3 ,0x240ca1cc)
    F(w4 ,0x2de92c6f)
    F(w5 ,0x4a7484aa)
    F(w6 ,0x5cb0a9dc)
    F(w7 ,0x76f988da)
    F(w8 ,0x983e5152)
    F(w9 ,0xa831c66d)
    F(w10,0xb00327c8)
    F(w11,0xbf597fc7)
    F(w12,0xc6e00bf3)
    F(w13,0xd5a79147)
    F(w14,0x06ca6351)
    F(w15,0x14292967)

    EXPAND

    F(w0 ,0x27b70a85)
    F(w1 ,0x2e1b2138)
    F(w2 ,0x4d2c6dfc)
    F(w3 ,0x53380d13)
    F(w4 ,0x650a7354)
    F(w5 ,0x766a0abb)
    F(w6 ,0x81c2c92e)
    F(w7 ,0x92722c85)
    F(w8 ,0xa2bfe8a1)
    F(w9 ,0xa81a664b)
    F(w10,0xc24b8b70)
    F(w11,0xc76c51a3)
    F(w12,0xd192e819)
    F(w13,0xd6990624)
    F(w14,0xf40e3585)
    F(w15,0x106aa070)

    EXPAND

    F(w0 ,0x19a4c116)
    F(w1 ,0x1e376c08)
    F(w2 ,0x2748774c)
    F(w3 ,0x34b0bcb5)
    F(w4 ,0x391c0cb3)
    F(w5 ,0x4ed8aa4a)
    F(w6 ,0x5b9cca4f)
    F(w7 ,0x682e6ff3)
    F(w8 ,0x748f82ee)
    F(w9 ,0x78a5636f)
    F(w10,0x84c87814)
    F(w11,0x8cc70208)
    F(w12,0x90befffa)
    F(w13,0xa4506ceb)
    F(w14,0xbef9a3f7)
    F(w15,0xc67178f2)

    a += state[0];
    b += state[1];
    c += state[2];
    d += state[3];
    e += state[4];
    f += state[5];
    g += state[6];
    h += state[7];

    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
    state[4] = e;
    state[5] = f;
    state[6] = g;
    state[7] = h;

    in += 64;
    inlen -= 64;
  }

  store_bigendian(statebytes +  0,state[0]);
  store_bigendian(statebytes +  4,state[1]);
  store_bigendian(statebytes +  8,state[2]);
  store_bigendian(statebytes + 12,state[3]);
  store_bigendian(statebytes + 16,state[4]);
  store_bigendian(statebytes + 20,state[5]);
  store_bigendian(statebytes + 24,state[6]);
  store_bigendian(statebytes + 28,state[7]);

  return inlen;
}

#define blocks crypto_hashblocks_sha256

static const uint8_t iv[32] = {
  0x6a,0x09,0xe6,0x67,
  0xbb,0x67,0xae,0x85,
  0x3c,0x6e,0xf3,0x72,
  0xa5,0x4f,0xf5,0x3a,
  0x51,0x0e,0x52,0x7f,
  0x9b,0x05,0x68,0x8c,
  0x1f,0x83,0xd9,0xab,
  0x5b,0xe0,0xcd,0x19,
} ;

void sha256(uint8_t out[32],const uint8_t *in,size_t inlen)
{
  uint8_t h[32];
  uint8_t padded[128];
  unsigned int i;
  uint64_t bits = inlen << 3;

  for (i = 0;i < 32;++i) h[i] = iv[i];

  blocks(h,in,inlen);
  in += inlen;
  inlen &= 63;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 56) {
    for (i = inlen + 1;i < 56;++i) padded[i] = 0;
    padded[56] = bits >> 56;
    padded[57] = bits >> 48;
    padded[58] = bits >> 40;
    padded[59] = bits >> 32;
    padded[60] = bits >> 24;
    padded[61] = bits >> 16;
    padded[62] = bits >> 8;
    padded[63] = bits;
    blocks(h,padded,64);
  } else {
    for (i = inlen + 1;i < 120;++i) padded[i] = 0;
    padded[120] = bits >> 56;
    padded[121] = bits >> 48;
    padded[122] = bits >> 40;
    padded[123] = bits >> 32;
    padded[124] = bits >> 24;
    padded[125] = bits >> 16;
    padded[126] = bits >> 8;
    padded[127] = bits;
    blocks(h,padded,128);
  }

  for (i = 0;i < 32;++i) out[i] = h[i];
}


/////sha512//////////////

static uint64_t load_bigendian64(const uint8_t *x)
{
  return
      (uint64_t) (x[7]) \
  | (((uint64_t) (x[6])) << 8) \
  | (((uint64_t) (x[5])) << 16) \
  | (((uint64_t) (x[4])) << 24) \
  | (((uint64_t) (x[3])) << 32) \
  | (((uint64_t) (x[2])) << 40) \
  | (((uint64_t) (x[1])) << 48) \
  | (((uint64_t) (x[0])) << 56)
  ;
}

static void store_bigendian64(uint8_t *x,uint64_t u)
{
  x[7] = u; u >>= 8;
  x[6] = u; u >>= 8;
  x[5] = u; u >>= 8;
  x[4] = u; u >>= 8;
  x[3] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[0] = u;
}

#define SHR64(x,c) ((x) >> (c))
#define ROTR64(x,c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch64(x,y,z) ((x & y) ^ (~x & z))
#define Maj64(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define Sigma064(x) (ROTR64(x,28) ^ ROTR64(x,34) ^ ROTR64(x,39))
#define Sigma164(x) (ROTR64(x,14) ^ ROTR64(x,18) ^ ROTR64(x,41))
#define sigma064(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ SHR64(x,7))
#define sigma164(x) (ROTR64(x,19) ^ ROTR64(x,61) ^ SHR64(x,6))

#define M64(w0,w14,w9,w1) w0 = sigma164(w14) + w9 + sigma064(w1) + w0;

#define EXPAND64 \
  M64(w0 ,w14,w9 ,w1 ) \
  M64(w1 ,w15,w10,w2 ) \
  M64(w2 ,w0 ,w11,w3 ) \
  M64(w3 ,w1 ,w12,w4 ) \
  M64(w4 ,w2 ,w13,w5 ) \
  M64(w5 ,w3 ,w14,w6 ) \
  M64(w6 ,w4 ,w15,w7 ) \
  M64(w7 ,w5 ,w0 ,w8 ) \
  M64(w8 ,w6 ,w1 ,w9 ) \
  M64(w9 ,w7 ,w2 ,w10) \
  M64(w10,w8 ,w3 ,w11) \
  M64(w11,w9 ,w4 ,w12) \
  M64(w12,w10,w5 ,w13) \
  M64(w13,w11,w6 ,w14) \
  M64(w14,w12,w7 ,w15) \
  M64(w15,w13,w8 ,w0 )

#define F64(w,k) \
  T1 = h + Sigma164(e) + Ch64(e,f,g) + k + w; \
  T2 = Sigma064(a) + Maj64(a,b,c); \
  h = g; \
  g = f; \
  f = e; \
  e = d + T1; \
  d = c; \
  c = b; \
  b = a; \
  a = T1 + T2;

static int crypto_hashblocks_sha512(uint8_t *statebytes,const uint8_t *in,size_t inlen)
{
  uint64_t state[8];
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
  uint64_t e;
  uint64_t f;
  uint64_t g;
  uint64_t h;
  uint64_t T1;
  uint64_t T2;

  a = load_bigendian64(statebytes +  0); state[0] = a;
  b = load_bigendian64(statebytes +  8); state[1] = b;
  c = load_bigendian64(statebytes + 16); state[2] = c;
  d = load_bigendian64(statebytes + 24); state[3] = d;
  e = load_bigendian64(statebytes + 32); state[4] = e;
  f = load_bigendian64(statebytes + 40); state[5] = f;
  g = load_bigendian64(statebytes + 48); state[6] = g;
  h = load_bigendian64(statebytes + 56); state[7] = h;

  while (inlen >= 128) {
    uint64_t w0  = load_bigendian64(in +   0);
    uint64_t w1  = load_bigendian64(in +   8);
    uint64_t w2  = load_bigendian64(in +  16);
    uint64_t w3  = load_bigendian64(in +  24);
    uint64_t w4  = load_bigendian64(in +  32);
    uint64_t w5  = load_bigendian64(in +  40);
    uint64_t w6  = load_bigendian64(in +  48);
    uint64_t w7  = load_bigendian64(in +  56);
    uint64_t w8  = load_bigendian64(in +  64);
    uint64_t w9  = load_bigendian64(in +  72);
    uint64_t w10 = load_bigendian64(in +  80);
    uint64_t w11 = load_bigendian64(in +  88);
    uint64_t w12 = load_bigendian64(in +  96);
    uint64_t w13 = load_bigendian64(in + 104);
    uint64_t w14 = load_bigendian64(in + 112);
    uint64_t w15 = load_bigendian64(in + 120);

    F64(w0 ,0x428a2f98d728ae22ULL)
    F64(w1 ,0x7137449123ef65cdULL)
    F64(w2 ,0xb5c0fbcfec4d3b2fULL)
    F64(w3 ,0xe9b5dba58189dbbcULL)
    F64(w4 ,0x3956c25bf348b538ULL)
    F64(w5 ,0x59f111f1b605d019ULL)
    F64(w6 ,0x923f82a4af194f9bULL)
    F64(w7 ,0xab1c5ed5da6d8118ULL)
    F64(w8 ,0xd807aa98a3030242ULL)
    F64(w9 ,0x12835b0145706fbeULL)
    F64(w10,0x243185be4ee4b28cULL)
    F64(w11,0x550c7dc3d5ffb4e2ULL)
    F64(w12,0x72be5d74f27b896fULL)
    F64(w13,0x80deb1fe3b1696b1ULL)
    F64(w14,0x9bdc06a725c71235ULL)
    F64(w15,0xc19bf174cf692694ULL)

    EXPAND64

    F64(w0 ,0xe49b69c19ef14ad2ULL)
    F64(w1 ,0xefbe4786384f25e3ULL)
    F64(w2 ,0x0fc19dc68b8cd5b5ULL)
    F64(w3 ,0x240ca1cc77ac9c65ULL)
    F64(w4 ,0x2de92c6f592b0275ULL)
    F64(w5 ,0x4a7484aa6ea6e483ULL)
    F64(w6 ,0x5cb0a9dcbd41fbd4ULL)
    F64(w7 ,0x76f988da831153b5ULL)
    F64(w8 ,0x983e5152ee66dfabULL)
    F64(w9 ,0xa831c66d2db43210ULL)
    F64(w10,0xb00327c898fb213fULL)
    F64(w11,0xbf597fc7beef0ee4ULL)
    F64(w12,0xc6e00bf33da88fc2ULL)
    F64(w13,0xd5a79147930aa725ULL)
    F64(w14,0x06ca6351e003826fULL)
    F64(w15,0x142929670a0e6e70ULL)

    EXPAND64

    F64(w0 ,0x27b70a8546d22ffcULL)
    F64(w1 ,0x2e1b21385c26c926ULL)
    F64(w2 ,0x4d2c6dfc5ac42aedULL)
    F64(w3 ,0x53380d139d95b3dfULL)
    F64(w4 ,0x650a73548baf63deULL)
    F64(w5 ,0x766a0abb3c77b2a8ULL)
    F64(w6 ,0x81c2c92e47edaee6ULL)
    F64(w7 ,0x92722c851482353bULL)
    F64(w8 ,0xa2bfe8a14cf10364ULL)
    F64(w9 ,0xa81a664bbc423001ULL)
    F64(w10,0xc24b8b70d0f89791ULL)
    F64(w11,0xc76c51a30654be30ULL)
    F64(w12,0xd192e819d6ef5218ULL)
    F64(w13,0xd69906245565a910ULL)
    F64(w14,0xf40e35855771202aULL)
    F64(w15,0x106aa07032bbd1b8ULL)

    EXPAND64

    F64(w0 ,0x19a4c116b8d2d0c8ULL)
    F64(w1 ,0x1e376c085141ab53ULL)
    F64(w2 ,0x2748774cdf8eeb99ULL)
    F64(w3 ,0x34b0bcb5e19b48a8ULL)
    F64(w4 ,0x391c0cb3c5c95a63ULL)
    F64(w5 ,0x4ed8aa4ae3418acbULL)
    F64(w6 ,0x5b9cca4f7763e373ULL)
    F64(w7 ,0x682e6ff3d6b2b8a3ULL)
    F64(w8 ,0x748f82ee5defb2fcULL)
    F64(w9 ,0x78a5636f43172f60ULL)
    F64(w10,0x84c87814a1f0ab72ULL)
    F64(w11,0x8cc702081a6439ecULL)
    F64(w12,0x90befffa23631e28ULL)
    F64(w13,0xa4506cebde82bde9ULL)
    F64(w14,0xbef9a3f7b2c67915ULL)
    F64(w15,0xc67178f2e372532bULL)

    EXPAND64

    F64(w0 ,0xca273eceea26619cULL)
    F64(w1 ,0xd186b8c721c0c207ULL)
    F64(w2 ,0xeada7dd6cde0eb1eULL)
    F64(w3 ,0xf57d4f7fee6ed178ULL)
    F64(w4 ,0x06f067aa72176fbaULL)
    F64(w5 ,0x0a637dc5a2c898a6ULL)
    F64(w6 ,0x113f9804bef90daeULL)
    F64(w7 ,0x1b710b35131c471bULL)
    F64(w8 ,0x28db77f523047d84ULL)
    F64(w9 ,0x32caab7b40c72493ULL)
    F64(w10,0x3c9ebe0a15c9bebcULL)
    F64(w11,0x431d67c49c100d4cULL)
    F64(w12,0x4cc5d4becb3e42b6ULL)
    F64(w13,0x597f299cfc657e2aULL)
    F64(w14,0x5fcb6fab3ad6faecULL)
    F64(w15,0x6c44198c4a475817ULL)

    a += state[0];
    b += state[1];
    c += state[2];
    d += state[3];
    e += state[4];
    f += state[5];
    g += state[6];
    h += state[7];

    state[0] = a;
    state[1] = b;
    state[2] = c;
    state[3] = d;
    state[4] = e;
    state[5] = f;
    state[6] = g;
    state[7] = h;

    in += 128;
    inlen -= 128;
  }

  store_bigendian64(statebytes +  0,state[0]);
  store_bigendian64(statebytes +  8,state[1]);
  store_bigendian64(statebytes + 16,state[2]);
  store_bigendian64(statebytes + 24,state[3]);
  store_bigendian64(statebytes + 32,state[4]);
  store_bigendian64(statebytes + 40,state[5]);
  store_bigendian64(statebytes + 48,state[6]);
  store_bigendian64(statebytes + 56,state[7]);

  return inlen;
}

#define blocks64 crypto_hashblocks_sha512

static const uint8_t iv64[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
} ;

void sha512(uint8_t out[64],const uint8_t *in,size_t inlen)
{
  uint8_t h[64];
  uint8_t padded[256];
  unsigned int i;
  uint64_t bytes = inlen;

  for (i = 0;i < 64;++i) h[i] = iv64[i];

  blocks64(h,in,inlen);
  in += inlen;
  inlen &= 127;
  in -= inlen;

  for (i = 0;i < inlen;++i) padded[i] = in[i];
  padded[inlen] = 0x80;

  if (inlen < 112) {
    for (i = inlen + 1;i < 119;++i) padded[i] = 0;
    padded[119] = bytes >> 61;
    padded[120] = bytes >> 53;
    padded[121] = bytes >> 45;
    padded[122] = bytes >> 37;
    padded[123] = bytes >> 29;
    padded[124] = bytes >> 21;
    padded[125] = bytes >> 13;
    padded[126] = bytes >> 5;
    padded[127] = bytes << 3;
    blocks64(h,padded,128);
  } else {
    for (i = inlen + 1;i < 247;++i) padded[i] = 0;
    padded[247] = bytes >> 61;
    padded[248] = bytes >> 53;
    padded[249] = bytes >> 45;
    padded[250] = bytes >> 37;
    padded[251] = bytes >> 29;
    padded[252] = bytes >> 21;
    padded[253] = bytes >> 13;
    padded[254] = bytes >> 5;
    padded[255] = bytes << 3;
    blocks64(h,padded,256);
  }

  for (i = 0;i < 64;++i) out[i] = h[i];
}

//////////// Randombytes//////////
/*
#ifdef _WIN32
void randombytes(uint8_t *out, size_t outlen) {
  HCRYPTPROV ctx;
  size_t len;

  if(!CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    abort();

  while(outlen > 0) {
    len = (outlen > 1048576) ? 1048576 : outlen;
    if(!CryptGenRandom(ctx, len, (BYTE *)out))
      abort();

    out += len;
    outlen -= len;
  }

  if(!CryptReleaseContext(ctx, 0))
    abort();
}
#elif defined(__linux__) && defined(SYS_getrandom)
void randombytes(uint8_t *out, size_t outlen) {
  ssize_t ret;

  while(outlen > 0) {
    ret = syscall(SYS_getrandom, out, outlen, 0);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}
#else
void randombytes(uint8_t *out, size_t outlen) {
  static int fd = -1;
  ssize_t ret;

  while(fd == -1) {
    fd = open("/dev/urandom", O_RDONLY);
    if(fd == -1 && errno == EINTR)
      continue;
    else if(fd == -1)
      abort();
  }

  while(outlen > 0) {
    ret = read(fd, out, outlen);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      abort();

    out += ret;
    outlen -= ret;
  }
}
#endif
*/