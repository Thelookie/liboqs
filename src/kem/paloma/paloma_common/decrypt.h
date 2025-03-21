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
    This file is for decryption
*/

#ifndef DECRYPT_H_
#define DECRYPT_H_

#include "paloma_data.h"
#include "utility.h"
#include "decoding.h"
#include "mat_mul.h"
#include "paloma_param.h"

/* *************************************** */
#ifdef __cplusplus
extern "C" {
#endif
/* *************************************** */

#define decrypt PALOMA_NAMESPACE(decrypt)
void decrypt(
        OUT Word* e_hat, 
        IN const SecretKey* sk, 
        IN const Word* s_hat, 
        IN const gf2m_tab* gf2m_tables);

/* *************************************** */
#ifdef __cplusplus
}
#endif
/* *************************************** */

#endif