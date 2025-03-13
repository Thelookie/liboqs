/*
 * Copyright (c) 2024 FDL(Future cryptography Design Lab.) Kookmin University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
    This file is for matrix computation
*/

#ifndef MAT_MUL_H
#define MAT_MUL_H

#include "paloma_data.h"
#include "utility.h"
#include "gf2m.h"
#include "paloma_param.h"

/* *************************************** */
#ifdef __cplusplus
extern "C" {
#endif
/* *************************************** */

/* Inlining Macro */
#ifdef INLINE
/* do nothing */
#elif defined(_MSC_VER)
#define INLINE __forceinline
#elif __has_attribute(always_inline)
#define INLINE inline __attribute__((always_inline))
#elif defined(__GNUC__)
#define INLINE inline __attribute__((always_inline))
#elif defined(__cplusplus)
#define INLINE inline
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define INLINE inline
#else
#define INLINE 
#endif

#define matXvec PALOMA_NAMESPACE(matXvec)
void matXvec(OUT Word* out_vec, IN const Word* in_mat, IN const Word* in_vec, 
             IN int rownum, IN int colnum);

#define gen_identity_mat PALOMA_NAMESPACE(gen_identity_mat)
void gen_identity_mat(OUT Word* I_Mat, IN int row);

#define gaussian_row PALOMA_NAMESPACE(gaussian_row)
int gaussian_row(OUT Word* systematic_mat, IN const Word* in_mat);

/* *************************************** */
#ifdef __cplusplus
}
#endif
/* *************************************** */

#endif