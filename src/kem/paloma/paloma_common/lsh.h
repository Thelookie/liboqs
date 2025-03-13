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
 * LSH256 ��� ����� ����� ���� 구조�
 */
struct LSH256_Context{
	lsh_type algtype;
	lsh_uint remain_databitlen;
	lsh_u32 cv_l[8];
	lsh_u32 cv_r[8];
	lsh_u8 last_block[LSH256_MSG_BLK_BYTE_LEN];
};

/**
 * LSH512 ��� ����� ����� ���� 구조�
 */
struct LSH512_Context{
	lsh_type algtype;
	lsh_uint remain_databitlen;
	lsh_u64 cv_l[8];
	lsh_u64 cv_r[8];
	lsh_u8 last_block[LSH512_MSG_BLK_BYTE_LEN];
};

/**
 * LSH ��� ����� ����� ���� ������
 */
union LSH_Context{
	struct LSH256_Context ctx256;
	struct LSH512_Context ctx512;
	lsh_type algtype;
};

#define lsh_init PALOMA_NAMESPACE(lsh_init)
/**
 * LSH ���� ��� ����� 초기������.
 *
 * @param [in] ctx ���� ��� ���� 구조�
 * @param [in] algtype LSH ��고리� 명세
 *
 * @return LSH_SUCCESS ��� ���� 초기�� ���
 * @return LSH_ERR_NULL_PTR ctx�� hashval�� NULL�� 경우 
 * @return LSH_ERR_INVALID_STATE ���� ��� ����값에 ��류� ���� 경우
 * @return LSH_ERR_INVALID_DATABITLEN ������ ������ �������� 길이� 8�� 배수� ���� 경우
 */
lsh_err lsh_init(union LSH_Context * ctx, const lsh_type algtype);

#define lsh_update PALOMA_NAMESPACE(lsh_update)
/**
 * LSH ���� ��� ����� ������������.
 *
 * @param [inout] ctx ���� ��� ���� 구조�
 * @param [in] data ����� 계산�� ������
 * @param [in] databitlen ������ 길이 (비트����)
 *
 * @return LSH_SUCCESS �������� ���
 * @return LSH_ERR_NULL_PTR ctx�� hashval�� NULL�� 경우 
 * @return LSH_ERR_INVALID_STATE ���� ��� ����값에 ��류� ���� 경우
 * @return LSH_ERR_INVALID_DATABITLEN ������ ������ �������� 길이� 8�� 배수� ���� 경우
 */
lsh_err lsh_update(union LSH_Context * ctx, const lsh_u8 * data, size_t databitlen);

#define lsh_final PALOMA_NAMESPACE(lsh_final)
/**
 * LSH ����� 계산����.
 *
 * @param [in] ctx ���� ��� ���� 구조�
 * @param [out] hashval ����� ���� 버퍼, alignment� 맞아������.
 *
 * @return LSH_SUCCESS ���� 계산 ���
 * @return LSH_ERR_NULL_PTR ctx�� hashval�� NULL�� 경우
 * @return LSH_ERR_INVALID_STATE ���� ��� ����값에 ��류� ���� 경우
 */
lsh_err lsh_final(union LSH_Context * ctx, lsh_u8 * hashval);

#define lsh_digest PALOMA_NAMESPACE(lsh_digest)
/**
 * LSH ����� 계산����.
 *
 * @param [in] algtype LSH ��고리� 명세
 * @param [in] data ������
 * @param [in] databitlen ������ 길이 (비트����)
 * @param [out] hashval ����� ���� 버퍼, alignment� 맞아������.
 *
 * @return LSH_SUCCESS ���� 계산 ���
 */
lsh_err lsh_digest(const lsh_type algtype, const lsh_u8 * data, size_t databitlen, lsh_u8 * hashval);

#ifdef __cplusplus
}
#endif

#endif
