/*
 * Copyright (c) 2016 NSR (National Security Research Institute)
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

#ifndef _REF_LSH512_H_
#define _REF_LSH512_H_

#include "lsh.h"
#include "paloma_param.h"

#ifdef __cplusplus
extern "C" {
#endif

#define lsh512_init PALOMA_NAMESPACE(lsh512_init)
/**
 * LSH512 ΄ ΄λΆ λ₯ μ΄κΈ°€.
 *
 * @param [in] ctx ΄ ΄λΆ  κ΅¬μ‘°μ²
 * @param [in] algtype LSH κ³ λ¦¬μ¦ λͺμΈ
 *
 * @return LSH_SUCCESS ΄λΆ  μ΄κΈ° ±κ³
 * @return LSH_ERR_NULL_PTR ctx hashval΄ NULLΈ κ²½μ° 
 * @return LSH_ERR_INVALID_STATE ΄ ΄λΆ κ°μ €λ₯κ  κ²½μ°
 * @return LSH_ERR_INVALID_DATABITLEN ΄   ₯ °΄° κΈΈμ΄κ° 8 λ°°μκ°  κ²½μ°
 */
lsh_err lsh512_init(struct LSH512_Context * ctx, const lsh_type algtype);

#define lsh512_update PALOMA_NAMESPACE(lsh512_update)
/**
 * LSH512 ΄ ΄λΆ λ₯ °΄Έ€.
 *
 * @param [in/out] ctx ΄ ΄λΆ  κ΅¬μ‘°μ²
 * @param [in] data ΄λ₯ κ³μ°  °΄°
 * @param [in] databitlen °΄° κΈΈμ΄ (λΉνΈ¨)
 *
 * @return LSH_SUCCESS °΄Έ ±κ³
 * @return LSH_ERR_NULL_PTR ctx hashval΄ NULLΈ κ²½μ° 
 * @return LSH_ERR_INVALID_STATE ΄ ΄λΆ κ°μ €λ₯κ  κ²½μ°
 * @return LSH_ERR_INVALID_DATABITLEN ΄   ₯ °΄° κΈΈμ΄κ° 8 λ°°μκ°  κ²½μ°
 */
lsh_err lsh512_update(struct LSH512_Context * ctx, const lsh_u8 * data, size_t databitlen);

#define lsh512_final PALOMA_NAMESPACE(lsh512_final)
/**
 * LSH512 ΄λ₯ κ³μ°€.
 *
 * @param [in] ctx ΄ ΄λΆ  κ΅¬μ‘°μ²
 * @param [out] hashval ΄κ° ₯  λ²νΌ, alignmentκ° λ§μΌ€.
 *
 * @return LSH_SUCCESS ΄ κ³μ° ±κ³
 * @return LSH_ERR_NULL_PTR ctx hashval΄ NULLΈ κ²½μ°
 * @return LSH_ERR_INVALID_STATE ΄ ΄λΆ κ°μ €λ₯κ  κ²½μ°
 */
lsh_err lsh512_final(struct LSH512_Context * ctx, lsh_u8 * hashval);

#define lsh512_digest PALOMA_NAMESPACE(lsh512_digest)
/**
 * LSH512 ΄λ₯ κ³μ°€.
 *
 * @param [in] algtype κ³ λ¦¬μ¦ λͺμΈ
 * @param [in] data °΄°
 * @param [in] databitlen °΄° κΈΈμ΄ (λΉνΈ¨)
 * @param [out] hashval ΄κ° ₯  λ²νΌ, alignmentκ° λ§μΌ€.
 *
 * @return LSH_SUCCESS ΄ κ³μ° ±κ³
 */
lsh_err lsh512_digest(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval);

#ifdef __cplusplus
}
#endif

#endif
