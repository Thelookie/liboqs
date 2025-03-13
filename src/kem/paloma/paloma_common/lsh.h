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

#ifndef _SIMD_LSH_H_
#define _SIMD_LSH_H_

#include "lsh_def.h"
#include "paloma_param.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * LSH256 ‚´ë¶ ƒƒœë¥ ¥•˜ê¸ œ„•œ êµ¬ì¡°ì²
 */
struct LSH256_Context{
	lsh_type algtype;
	lsh_uint remain_databitlen;
	lsh_u32 cv_l[8];
	lsh_u32 cv_r[8];
	lsh_u8 last_block[LSH256_MSG_BLK_BYTE_LEN];
};

/**
 * LSH512 ‚´ë¶ ƒƒœë¥ ¥•˜ê¸ œ„•œ êµ¬ì¡°ì²
 */
struct LSH512_Context{
	lsh_type algtype;
	lsh_uint remain_databitlen;
	lsh_u64 cv_l[8];
	lsh_u64 cv_r[8];
	lsh_u8 last_block[LSH512_MSG_BLK_BYTE_LEN];
};

/**
 * LSH ‚´ë¶ ƒƒœë¥ ¥•˜ê¸ œ„•œ œ ‹ˆ˜¨
 */
union LSH_Context{
	struct LSH256_Context ctx256;
	struct LSH512_Context ctx512;
	lsh_type algtype;
};

#define lsh_init PALOMA_NAMESPACE(lsh_init)
/**
 * LSH •´‹œ ‚´ë¶ ƒƒœë¥ ì´ˆê¸°™”•œ‹¤.
 *
 * @param [in] ctx •´‹œ ‚´ë¶ ƒƒœ êµ¬ì¡°ì²
 * @param [in] algtype LSH •Œê³ ë¦¬ì¦ ëª…ì„¸
 *
 * @return LSH_SUCCESS ‚´ë¶ ƒƒœ ì´ˆê¸°™” „±ê³
 * @return LSH_ERR_NULL_PTR ctx‚˜ hashval´ NULL¸ ê²½ìš° 
 * @return LSH_ERR_INVALID_STATE •´‹œ ‚´ë¶ ƒƒœê°’ì— ˜¤ë¥˜ê ˆŠ” ê²½ìš°
 * @return LSH_ERR_INVALID_DATABITLEN ´ „— … ¥œ °´„°˜ ê¸¸ì´ê° 8˜ ë°°ìˆ˜ê° •„‹Œ ê²½ìš°
 */
lsh_err lsh_init(union LSH_Context * ctx, const lsh_type algtype);

#define lsh_update PALOMA_NAMESPACE(lsh_update)
/**
 * LSH •´‹œ ‚´ë¶ ƒƒœë¥ —…°´Š¸•œ‹¤.
 *
 * @param [inout] ctx •´‹œ ‚´ë¶ ƒƒœ êµ¬ì¡°ì²
 * @param [in] data •´‹œë¥ ê³„ì‚°•  °´„°
 * @param [in] databitlen °´„° ê¸¸ì´ (ë¹„íŠ¸‹¨œ„)
 *
 * @return LSH_SUCCESS —…°´Š¸ „±ê³
 * @return LSH_ERR_NULL_PTR ctx‚˜ hashval´ NULL¸ ê²½ìš° 
 * @return LSH_ERR_INVALID_STATE •´‹œ ‚´ë¶ ƒƒœê°’ì— ˜¤ë¥˜ê ˆŠ” ê²½ìš°
 * @return LSH_ERR_INVALID_DATABITLEN ´ „— … ¥œ °´„°˜ ê¸¸ì´ê° 8˜ ë°°ìˆ˜ê° •„‹Œ ê²½ìš°
 */
lsh_err lsh_update(union LSH_Context * ctx, const lsh_u8 * data, size_t databitlen);

#define lsh_final PALOMA_NAMESPACE(lsh_final)
/**
 * LSH •´‹œë¥ ê³„ì‚°•œ‹¤.
 *
 * @param [in] ctx •´‹œ ‚´ë¶ ƒƒœ êµ¬ì¡°ì²
 * @param [out] hashval •´‹œê° ¥  ë²„í¼, alignmentê° ë§ì•„•¼•œ‹¤.
 *
 * @return LSH_SUCCESS •´‹œ ê³„ì‚° „±ê³
 * @return LSH_ERR_NULL_PTR ctx‚˜ hashval´ NULL¸ ê²½ìš°
 * @return LSH_ERR_INVALID_STATE •´‹œ ‚´ë¶ ƒƒœê°’ì— ˜¤ë¥˜ê ˆŠ” ê²½ìš°
 */
lsh_err lsh_final(union LSH_Context * ctx, lsh_u8 * hashval);

#define lsh_digest PALOMA_NAMESPACE(lsh_digest)
/**
 * LSH •´‹œë¥ ê³„ì‚°•œ‹¤.
 *
 * @param [in] algtype LSH •Œê³ ë¦¬ì¦ ëª…ì„¸
 * @param [in] data °´„°
 * @param [in] databitlen °´„° ê¸¸ì´ (ë¹„íŠ¸‹¨œ„)
 * @param [out] hashval •´‹œê° ¥  ë²„í¼, alignmentê° ë§ì•„•¼•œ‹¤.
 *
 * @return LSH_SUCCESS •´‹œ ê³„ì‚° „±ê³
 */
lsh_err lsh_digest(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval);

#ifdef __cplusplus
}
#endif

#endif
