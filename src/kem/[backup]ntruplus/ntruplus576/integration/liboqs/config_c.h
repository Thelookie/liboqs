/*
 * Copyright (c) 2024-2025 The ntruplus-native project authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLK_INTEGRATION_LIBOQS_CONFIG_C_H
#define MLK_INTEGRATION_LIBOQS_CONFIG_C_H

/******************************************************************************
 * Name:        ntruplus_K
 *
 * Description: Determines the security level for ML-KEM
 *              - ntruplus_K=2 corresponds to ML-KEM-512
 *              - ntruplus_K=3 corresponds to ML-KEM-768
 *              - ntruplus_K=4 corresponds to ML-KEM-1024
 *
 *              This can also be set using CFLAGS.
 *
 *****************************************************************************/
#ifndef ntruplus_K
#define ntruplus_K 3 /* Change this for different security strengths */
#endif

/******************************************************************************
 * Name:        MLK_NAMESPACE_PREFIX
 *
 * Description: The prefix to use to namespace global symbols from ntruplus/.
 *
 *              In a multi-level build (that is, if either
 *              - MLK_MULTILEVEL_BUILD_WITH_SHARED, or
 *              - MLK_MULTILEVEL_BUILD_NO_SHARED,
 *              are set, level-dependent symbols will additionally be prefixed
 *              with the security level.
 *
 *              This can also be set using CFLAGS.
 *
 *****************************************************************************/
#if ntruplus_K == 2
#define MLK_NAMESPACE_PREFIX PQCP_ntruplus_NATIVE_ntruplus512_C
#elif ntruplus_K == 3
#define MLK_NAMESPACE_PREFIX PQCP_ntruplus_NATIVE_ntruplus768_C
#elif ntruplus_K == 4
#define MLK_NAMESPACE_PREFIX PQCP_ntruplus_NATIVE_ntruplus1024_C
#endif

/******************************************************************************
 * Name:        MLK_FIPS202_CUSTOM_HEADER
 *
 * Description: Custom header to use for FIPS-202
 *
 *              This should only be set if you intend to use a custom
 *              FIPS-202 implementation, different from the one shipped
 *              with ntruplus-native.
 *
 *              If set, it must be the name of a file serving as the
 *              replacement for ntruplus/fips202/fips202.h, and exposing
 *              the same API (see FIPS202.md).
 *
 *****************************************************************************/
#define MLK_FIPS202_CUSTOM_HEADER "../integration/liboqs/fips202_glue.h"

/******************************************************************************
 * Name:        MLK_FIPS202X4_CUSTOM_HEADER
 *
 * Description: Custom header to use for FIPS-202-X4
 *
 *              This should only be set if you intend to use a custom
 *              FIPS-202 implementation, different from the one shipped
 *              with ntruplus-native.
 *
 *              If set, it must be the name of a file serving as the
 *              replacement for ntruplus/fips202/fips202x4.h, and exposing
 *              the same API (see FIPS202.md).
 *
 *****************************************************************************/
#define MLK_FIPS202X4_CUSTOM_HEADER "../integration/liboqs/fips202x4_glue.h"

/******************************************************************************
 * Name:        MLK_USE_ZEROIZE_NATIVE
 *
 * Description: In compliance with FIPS 203 Section 3.3, ntruplus-native zeroizes
 *              intermediate stack buffers before returning from function calls.
 *
 *              Set this option and define `mlk_zeroize_native` if you want to
 *              use a custom method to zeroize intermediate stack buffers.
 *              The default implementation uses SecureZeroMemory on Windows
 *              and a memset + compiler barrier otherwise. If neither of those
 *              is available on the target platform, compilation will fail,
 *              and you will need to use MLK_USE_ZEROIZE_NATIVE to provide
 *              a custom implementation of `mlk_zeroize_native()`.
 *
 *              WARNING:
 *              The explicit stack zeroization conducted by ntruplus-native
 *              reduces the likelihood of data leaking on the stack, but
 *              does not eliminate it! The C standard makes no guarantee about
 *              where a compiler allocates structures and whether/where it makes
 *              copies of them. Also, in addition to entire structures, there
 *              may also be potentially exploitable leakage of individual values
 *              on the stack.
 *
 *              If you need bullet-proof zeroization of the stack, you need to
 *              consider additional measures instead of of what this feature
 *              provides. In this case, you can set mlk_zeroize_native to a
 *              no-op.
 *
 *****************************************************************************/
/* #define MLK_USE_ZEROIZE_NATIVE
   #if !defined(__ASSEMBLER__)
   #include <stdint.h>
   #include "sys.h"
   static MLK_INLINE void mlk_zeroize_native(void *ptr, size_t len)
   {
       ... your implementation ...
   }
   #endif
*/

/******************************************************************************
 * Name:        MLK_NO_ASM
 *
 * Description: If this option is set, ntruplus-native will be built without
 *              use of native code or inline assembly.
 *
 *              By default, inline assembly is used to implement value barriers.
 *              Without inline assembly, ntruplus-native will use a global volatile
 *              'opt blocker' instead; see verify.h.
 *
 *              Inline assembly is also used to implement a secure zeroization
 *              function on non-Windows platforms. If this option is set and
 *              the target platform is not Windows, you MUST set
 *              MLK_USE_ZEROIZE_NATIVE and provide a custom zeroization
 *              function.
 *
 *              If this option is set, MLK_USE_NATIVE_BACKEND_FIPS202 and
 *              and MLK_USE_NATIVE_BACKEND_ARITH will be ignored, and no native
 *              backends will be used.
 *
 *****************************************************************************/
/* #define MLK_NO_ASM */

/******************************************************************************
 * Name:        MLK_KEYGEN_PCT
 *
 * Description: Compliance with [FIPS 140-3
 *IG](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf)
 *              requires a Pairwise Consistency Test (PCT) to be carried out
 *              on a freshly generated keypair before it can be exported.
 *
 *              Set this option if such a check should be implemented.
 *              In this case, crypto_kem_keypair_derand and crypto_kem_keypair
 *              will return a non-zero error code if the PCT failed.
 *
 *              NOTE: This feature will drastically lower the performance of
 *              key generation.
 *
 *****************************************************************************/
/* #define MLK_KEYGEN_PCT */

/******************************************************************************
 * Name:        MLK_KEYGEN_PCT_BREAKAGE_TEST
 *
 * Description: If this option is set, the user must provide a runtime
 *              function `static inline int mlk_break_pct() { ... }` to
 *              indicate whether the PCT should be made fail.
 *
 *              This option only has an effect if MLK_KEYGEN_PCT is set.
 *
 *****************************************************************************/
/* #define MLK_KEYGEN_PCT_BREAKAGE_TEST
   #if !defined(__ASSEMBLER__)
   #include "sys.h"
   static MLK_INLINE int mlk_break_pct(void)
   {
       ... return 0/1 depending on whether PCT should be broken ...
   }
   #endif
*/

/* Enable valgrind-based assertions in ntruplus-native through macro
 * from libOQS. */
#if !defined(__ASSEMBLER__)
#include <oqs/common.h>
#if defined(OQS_ENABLE_TEST_CONSTANT_TIME)
#define MLK_CT_TESTING_ENABLED
#endif
#endif /* !__ASSEMBLER__ */

#endif /* MLK_INTEGRATION_LIBOQS_CONFIG_C_H */
