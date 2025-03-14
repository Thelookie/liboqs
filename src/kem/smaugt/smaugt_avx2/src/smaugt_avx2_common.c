/**
 * Implementation of the fisp202 API using the XKCP low interface based on
 * xkcp_sha3.c from OQS library (https://github.com/open-quantum-safe)
 * The high level keccak_absorb, squeezeblocks, etc. are based on fips202.c
 * from PQClean (https://github.com/PQClean/PQClean/tree/master/common)
 *
 * SPDX-License-Identifier: MIT
 */

#include "fips202.h"
#include "fips202x4.h"
#include "keccak/KeccakP-1600-SnP.h"
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>


/*************************************************
 * Name:        keccak_init
 *
 * Description: Initializes the Keccak state.
 *
 * Arguments:   - uint64_t *s: pointer to Keccak state
 **************************************************/
void keccak_init(uint64_t *s) {
    KeccakP1600_Initialize_avx2(s);
    s[25] = 0;
}

/*************************************************
 * Name:        keccak_absorb
 *
 * Description: Absorb step of Keccak; incremental.
 *
 * Arguments:   - uint64_t *s: pointer to Keccak state (s[25]: position)
 *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const uint8_t *m: pointer to input to be absorbed into s
 *              - size_t mlen: length of input m bytes
 *
 * Returns new position pos in current block
 **************************************************/
void keccak_absorb(uint64_t *s, uint32_t r, const uint8_t *m,
                          size_t mlen) {
    uint64_t c;

    if (s[25] && mlen + s[25] >= r) {
        c = r - s[25];
        KeccakP1600_AddBytes_avx2(s, m, (unsigned int)s[25], (unsigned int)c);
        KeccakP1600_Permute_24rounds_avx2(s);
        mlen -= c;
        m += c;
        s[25] = 0;
    }

#ifdef KeccakF1600_FastLoop_supported
    if (mlen >= r) {
        c = KeccakF1600_FastLoop_Absorb_avx2(s, r / 8, m, mlen);
        mlen -= c;
        m += c;
    }
#else
    while (mlen >= r) {
        KeccakP1600_AddBytes_avx2(s, m, 0, r);
        KeccakP1600_Permute_24rounds_avx2(s);
        mlen -= r;
        m += r;
    }
#endif

    KeccakP1600_AddBytes_avx2(s, m, (unsigned int)s[25], (unsigned int)mlen);
    s[25] += mlen;
}

/*************************************************
 * Name:        keccak_finalize
 *
 * Description: Finalizes Keccak absorb phase, prepares for squeezing
 *
 * Arguments:   - uint64_t *s: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 *              - uint8_t p: domain-separation byte for different
 *                                 Keccak-derived functions
 **************************************************/
void keccak_finalize(uint64_t *s, uint32_t r, uint8_t p) {
    /* After keccak_absorb, we are guaranteed that s[25] < r,
       so we can always use one more byte for p in the current state. */
    KeccakP1600_AddByte_avx2(s, p, (unsigned int)s[25]);
    KeccakP1600_AddByte_avx2(s, 0x80, (unsigned int)(r - 1));
    s[25] = 0;
}

/*************************************************
 * Name:        keccak_squeeze
 *
 * Description: Incremental Keccak squeeze; can be called on byte-level
 *
 * Arguments:   - uint8_t *h: pointer to output bytes
 *              - size_t outlen: number of bytes to be squeezed
 *              - uint64_t *s: pointer to input/output incremental state
 *                First 25 values represent Keccak state.
 *                26th value represents either the number of absorbed bytes
 *                that have not been permuted, or not-yet-squeezed bytes.
 *              - uint32_t r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
void keccak_squeeze(uint8_t *h, size_t outlen, uint64_t *s, uint32_t r) {
    while (outlen > s[25]) {
        KeccakP1600_ExtractBytes_avx2(s, h, (unsigned int)(r - s[25]),
                                      (unsigned int)s[25]);
        KeccakP1600_Permute_24rounds_avx2(s);
        h += s[25];
        outlen -= s[25];
        s[25] = r;
    }
    KeccakP1600_ExtractBytes_avx2(s, h, (unsigned int)(r - s[25]),
                                  (unsigned int)outlen);
    s[25] -= outlen;
}

/* shake128 */
void shake128_init(keccak_state *state) { keccak_init(state->s); }

void shake128_absorb(keccak_state *state, const uint8_t *input, size_t inlen) {
    keccak_absorb(state->s, SHAKE128_RATE, input, inlen);
}

void shake128_finalize(keccak_state *state) {
    keccak_finalize(state->s, SHAKE128_RATE, 0x1F);
}

void shake128_squeeze(uint8_t *output, size_t outlen, keccak_state *state) {
    keccak_squeeze(output, outlen, state->s, SHAKE128_RATE);
}

void shake128(uint8_t *output, size_t outlen, const uint8_t *input,
              size_t inlen) {
    keccak_state state;
    shake128_init(&state);
    shake128_absorb(&state, input, inlen);
    shake128_finalize(&state);
    shake128_squeeze(output, outlen, &state);
}

/* shake256 */
void shake256_init(keccak_state *state) { keccak_init(state->s); }

void shake256_absorb(keccak_state *state, const uint8_t *input, size_t inlen) {
    keccak_absorb(state->s, SHAKE256_RATE, input, inlen);
}

void shake256_finalize(keccak_state *state) {
    keccak_finalize(state->s, SHAKE256_RATE, 0x1F);
}

void shake256_squeeze(uint8_t *output, size_t outlen, keccak_state *state) {
    keccak_squeeze(output, outlen, state->s, SHAKE256_RATE);
}

void shake256(uint8_t *output, size_t outlen, const uint8_t *input,
              size_t inlen) {
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, input, inlen);
    shake256_finalize(&state);
    shake256_squeeze(output, outlen, &state);
}

/* sha3-256 */
void sha3_256_init(keccak_state *state) { keccak_init(state->s); }

void sha3_256_absorb(keccak_state *state, const uint8_t *input, size_t inlen) {
    keccak_absorb(state->s, SHA3_256_RATE, input, inlen);
}

void sha3_256_finalize(uint8_t *output, keccak_state *state) {
    keccak_finalize(state->s, SHA3_256_RATE, 0x06);
    keccak_squeeze(output, 32, state->s, SHA3_256_RATE);
}

void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen) {
    keccak_state state;
    sha3_256_init(&state);
    sha3_256_absorb(&state, input, inlen);
    sha3_256_finalize(output, &state);
}

/* sha3-512 */
void sha3_512_init(keccak_state *state) { keccak_init(state->s); }

void sha3_512_absorb(keccak_state *state, const uint8_t *input, size_t inlen) {
    keccak_absorb(state->s, SHA3_512_RATE, input, inlen);
}

void sha3_512_finalize(uint8_t *output, keccak_state *state) {
    keccak_finalize(state->s, SHA3_512_RATE, 0x06);
    keccak_squeeze(output, 64, state->s, SHA3_512_RATE);
}

void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen) {
    keccak_state state;
    sha3_512_init(&state);
    sha3_512_absorb(&state, input, inlen);
    sha3_512_finalize(output, &state);
}


#define KeccakF1600_StatePermute4x                                             \
    FIPS202X4_NAMESPACE(KeccakP1600times4_PermuteAll_24rounds)
extern void KeccakF1600_StatePermute4x(__m256i *s);

void keccakx4_absorb_once(__m256i s[25], unsigned int r,
                                 const uint8_t *in0, const uint8_t *in1,
                                 const uint8_t *in2, const uint8_t *in3,
                                 size_t inlen, uint8_t p) {
    size_t i;
    uint64_t pos = 0;
    __m256i t, idx;

    for (i = 0; i < 25; ++i)
        s[i] = _mm256_setzero_si256();

    idx = _mm256_set_epi64x((long long)in3, (long long)in2, (long long)in1,
                            (long long)in0);
    while (inlen >= r) {
        for (i = 0; i < r / 8; ++i) {
            t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
            s[i] = _mm256_xor_si256(s[i], t);
            pos += 8;
        }
        inlen -= r;

        KeccakF1600_StatePermute4x(s);
    }

    for (i = 0; i < inlen / 8; ++i) {
        t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
        s[i] = _mm256_xor_si256(s[i], t);
        pos += 8;
    }
    inlen -= 8 * i;

    if (inlen) {
        t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
        idx = _mm256_set1_epi64x((1ULL << (8 * inlen)) - 1);
        t = _mm256_and_si256(t, idx);
        s[i] = _mm256_xor_si256(s[i], t);
    }

    t = _mm256_set1_epi64x((uint64_t)p << 8 * inlen);
    s[i] = _mm256_xor_si256(s[i], t);
    t = _mm256_set1_epi64x(1ULL << 63);
    s[r / 8 - 1] = _mm256_xor_si256(s[r / 8 - 1], t);
}

void keccakx4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                   uint8_t *out3, size_t nblocks,
                                   unsigned int r, __m256i s[25]) {
    unsigned int i;
    __m128d t;

    while (nblocks > 0) {
        KeccakF1600_StatePermute4x(s);
        for (i = 0; i < r / 8; ++i) {
            t = _mm_castsi128_pd(_mm256_castsi256_si128(s[i]));
            _mm_storel_pd((__attribute__((__may_alias__)) double *)&out0[8 * i],
                          t);
            _mm_storeh_pd((__attribute__((__may_alias__)) double *)&out1[8 * i],
                          t);
            t = _mm_castsi128_pd(_mm256_extracti128_si256(s[i], 1));
            _mm_storel_pd((__attribute__((__may_alias__)) double *)&out2[8 * i],
                          t);
            _mm_storeh_pd((__attribute__((__may_alias__)) double *)&out3[8 * i],
                          t);
        }

        out0 += r;
        out1 += r;
        out2 += r;
        out3 += r;
        --nblocks;
    }
}

void shake128x4_absorb_once(keccakx4_state *state, const uint8_t *in0,
                            const uint8_t *in1, const uint8_t *in2,
                            const uint8_t *in3, size_t inlen) {
    keccakx4_absorb_once(state->s, SHAKE128_RATE, in0, in1, in2, in3, inlen,
                         0x1F);
}

void shake128x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                              uint8_t *out3, size_t nblocks,
                              keccakx4_state *state) {
    keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks, SHAKE128_RATE,
                           state->s);
}

void shake256x4_absorb_once(keccakx4_state *state, const uint8_t *in0,
                            const uint8_t *in1, const uint8_t *in2,
                            const uint8_t *in3, size_t inlen) {
    keccakx4_absorb_once(state->s, SHAKE256_RATE, in0, in1, in2, in3, inlen,
                         0x1F);
}

void shake256x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                              uint8_t *out3, size_t nblocks,
                              keccakx4_state *state) {
    keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks, SHAKE256_RATE,
                           state->s);
}

void shake128x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
                size_t outlen, const uint8_t *in0, const uint8_t *in1,
                const uint8_t *in2, const uint8_t *in3, size_t inlen) {
    unsigned int i;
    size_t nblocks = outlen / SHAKE128_RATE;
    uint8_t t[4][SHAKE128_RATE];
    keccakx4_state state;

    shake128x4_absorb_once(&state, in0, in1, in2, in3, inlen);
    shake128x4_squeezeblocks(out0, out1, out2, out3, nblocks, &state);

    out0 += nblocks * SHAKE128_RATE;
    out1 += nblocks * SHAKE128_RATE;
    out2 += nblocks * SHAKE128_RATE;
    out3 += nblocks * SHAKE128_RATE;
    outlen -= nblocks * SHAKE128_RATE;

    if (outlen) {
        shake128x4_squeezeblocks(t[0], t[1], t[2], t[3], 1, &state);
        for (i = 0; i < outlen; ++i) {
            out0[i] = t[0][i];
            out1[i] = t[1][i];
            out2[i] = t[2][i];
            out3[i] = t[3][i];
        }
    }
}

void shake256x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
                size_t outlen, const uint8_t *in0, const uint8_t *in1,
                const uint8_t *in2, const uint8_t *in3, size_t inlen) {
    unsigned int i;
    size_t nblocks = outlen / SHAKE256_RATE;
    uint8_t t[4][SHAKE256_RATE];
    keccakx4_state state;

    shake256x4_absorb_once(&state, in0, in1, in2, in3, inlen);
    shake256x4_squeezeblocks(out0, out1, out2, out3, nblocks, &state);

    out0 += nblocks * SHAKE256_RATE;
    out1 += nblocks * SHAKE256_RATE;
    out2 += nblocks * SHAKE256_RATE;
    out3 += nblocks * SHAKE256_RATE;
    outlen -= nblocks * SHAKE256_RATE;

    if (outlen) {
        shake256x4_squeezeblocks(t[0], t[1], t[2], t[3], 1, &state);
        for (i = 0; i < outlen; ++i) {
            out0[i] = t[0][i];
            out1[i] = t[1][i];
            out2[i] = t[2][i];
            out3[i] = t[3][i];
        }
    }
}

