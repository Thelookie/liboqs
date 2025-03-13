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
 * LSH512 •´‹œ ‚´ë¶ ƒƒœë¥ ì´ˆê¸°™”•œ‹¤.
 *
 * @param [in] ctx •´‹œ ‚´ë¶ ƒƒœ êµ¬ì¡°ì²
 * @param [in] algtype LSH •Œê³ ë¦¬ì¦ ëª…ì„¸
 *
 * @return LSH_SUCCESS ‚´ë¶ ƒƒœ ì´ˆê¸°™” „±ê³
 * @return LSH_ERR_NULL_PTR ctx‚˜ hashval´ NULL¸ ê²½ìš° 
 * @return LSH_ERR_INVALID_STATE •´‹œ ‚´ë¶ ƒƒœê°’ì— ˜¤ë¥˜ê ˆŠ” ê²½ìš°
 * @return LSH_ERR_INVALID_DATABITLEN ´ „— … ¥œ °´„°˜ ê¸¸ì´ê° 8˜ ë°°ìˆ˜ê° •„‹Œ ê²½ìš°
 */
lsh_err lsh512_init(struct LSH512_Context * ctx, const lsh_type algtype);

#define lsh512_update PALOMA_NAMESPACE(lsh512_update)
/**
 * LSH512 •´‹œ ‚´ë¶ ƒƒœë¥ —…°´Š¸•œ‹¤.
 *
 * @param [in/out] ctx •´‹œ ‚´ë¶ ƒƒœ êµ¬ì¡°ì²
 * @param [in] data •´‹œë¥ ê³„ì‚°•  °´„°
 * @param [in] databitlen °´„° ê¸¸ì´ (ë¹„íŠ¸‹¨œ„)
 *
 * @return LSH_SUCCESS —…°´Š¸ „±ê³
 * @return LSH_ERR_NULL_PTR ctx‚˜ hashval´ NULL¸ ê²½ìš° 
 * @return LSH_ERR_INVALID_STATE •´‹œ ‚´ë¶ ƒƒœê°’ì— ˜¤ë¥˜ê ˆŠ” ê²½ìš°
 * @return LSH_ERR_INVALID_DATABITLEN ´ „— … ¥œ °´„°˜ ê¸¸ì´ê° 8˜ ë°°ìˆ˜ê° •„‹Œ ê²½ìš°
 */
lsh_err lsh512_update(struct LSH512_Context * ctx, const lsh_u8 * data, size_t databitlen);

#define lsh512_final PALOMA_NAMESPACE(lsh512_final)
/**
 * LSH512 •´‹œë¥ ê³„ì‚°•œ‹¤.
 *
 * @param [in] ctx •´‹œ ‚´ë¶ ƒƒœ êµ¬ì¡°ì²
 * @param [out] hashval •´‹œê° ¥  ë²„í¼, alignmentê° ë§ì•„•¼•œ‹¤.
 *
 * @return LSH_SUCCESS •´‹œ ê³„ì‚° „±ê³
 * @return LSH_ERR_NULL_PTR ctx‚˜ hashval´ NULL¸ ê²½ìš°
 * @return LSH_ERR_INVALID_STATE •´‹œ ‚´ë¶ ƒƒœê°’ì— ˜¤ë¥˜ê ˆŠ” ê²½ìš°
 */
lsh_err lsh512_final(struct LSH512_Context * ctx, lsh_u8 * hashval);

#define lsh512_digest PALOMA_NAMESPACE(lsh512_digest)
/**
 * LSH512 •´‹œë¥ ê³„ì‚°•œ‹¤.
 *
 * @param [in] algtype •Œê³ ë¦¬ì¦ ëª…ì„¸
 * @param [in] data °´„°
 * @param [in] databitlen °´„° ê¸¸ì´ (ë¹„íŠ¸‹¨œ„)
 * @param [out] hashval •´‹œê° ¥  ë²„í¼, alignmentê° ë§ì•„•¼•œ‹¤.
 *
 * @return LSH_SUCCESS •´‹œ ê³„ì‚° „±ê³
 */
lsh_err lsh512_digest(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval);

#ifdef __cplusplus
}
#endif

#endif
