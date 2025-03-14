# SPDX-License-Identifier: MIT

# Initialize object list

set(_SMAUGT_OBJS "")
#set(_SMAUGT_LIBS "")

set(SMAUGT_COMMON
smaugt_ref/src/cbd.c
smaugt_ref/src/ciphertext.c
smaugt_ref/src/dg.c
smaugt_ref/src/fips202.c
smaugt_ref/src/hash.c
smaugt_ref/src/hwt.c
smaugt_ref/src/indcpa.c
smaugt_ref/src/io.c
smaugt_ref/src/kem.c
smaugt_ref/src/key.c
smaugt_ref/src/pack.c
smaugt_ref/src/poly.c
smaugt_ref/src/randombytes.c
smaugt_ref/src/toomcook.c
smaugt_ref/src/verify.c
)

add_library(smaugt_common_ref SHARED ${SMAUGT_COMMON})
target_include_directories(smaugt_common_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/include)
if(OQS_ENABLE_KEM_smaugt_128)
    target_compile_options(smaugt_common_ref PUBLIC -DSMAUG_MODE=1 -Wl,--allow-multiple-definition)
elseif(OQS_ENABLE_KEM_smaugt_192)
    target_compile_options(smaugt_common_ref PUBLIC -DSMAUG_MODE=3 -Wl,--allow-multiple-definition)
elseif(OQS_ENABLE_KEM_smaugt_256)
    target_compile_options(smaugt_common_ref PUBLIC -DSMAUG_MODE=5 -Wl,--allow-multiple-definition)
endif()


# smaugt_128 configuration
if(OQS_ENABLE_KEM_smaugt_128)
    add_library(smaugt_128_ref SHARED kem_smaugt_128.c)
    target_include_directories(smaugt_128_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/include)
    target_compile_options(smaugt_128_ref PUBLIC -DSMAUG_MODE=1 -Wl,--allow-multiple-definition)
    target_link_libraries(smaugt_128_ref PRIVATE smaugt_common_ref)
    #list(APPEND _SMAUGT_LIBS smaugt_128_ref)
    set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_128_ref>)
endif()

# smaugt_192 configuration
if(OQS_ENABLE_KEM_smaugt_192)
    add_library(smaugt_192_ref SHARED kem_smaugt_192.c)
    target_include_directories(smaugt_192_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/include)
    target_compile_options(smaugt_192_ref PUBLIC -DSMAUG_MODE=3 -Wl,--allow-multiple-definition)
    target_link_libraries(smaugt_192_ref PRIVATE smaugt_common_ref)
    #list(APPEND _SMAUGT_LIBS smaugt_192_ref)
    set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_192_ref>)
endif()

# smaugt_256 configuration
if(OQS_ENABLE_KEM_smaugt_256)
    add_library(smaugt_256_ref SHARED kem_smaugt_256.c)
    target_include_directories(smaugt_256_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/include)
    target_compile_options(smaugt_256_ref PUBLIC -DSMAUG_MODE=5 -Wl,--allow-multiple-definition)
    target_link_libraries(smaugt_256_ref PRIVATE smaugt_common_ref)
    #list(APPEND _SMAUGT_LIBS smaugt_256_ref)
    set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_256_ref>)
endif()


if(OQS_ENABLE_KEM_smaugt_128_avx2)
    # Add library for smaugt_128_avx2
add_library(smaugt_128_avx2 OBJECT 
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/cbd.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/ciphertext.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/dg.c
            #${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/fips202.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/hash.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/hwt.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/indcpa.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/io.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/kem.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/key.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/pack.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/poly.c
          #  ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/randombytes.c
          #  ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/rng.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/verify.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/mul/basemul.S
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/mul/consts10753.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/mul/consts7681.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/mul/invntt.S
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/mul/ntt.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/mul/ntt.S
           # ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/keccak/KeccakP-1600-AVX2.S
           # ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/src/keccak/KeccakP-1600-times4-SIMD256.c
            )
        target_include_directories(smaugt_128_avx2 PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/include 
        ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/include/keccak 
        ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug1_avx2/include/mul)
        target_include_directories(smaugt_128_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
        target_compile_options(smaugt_128_avx2 PRIVATE -mavx2  -mbmi2  -mpopcnt)
        target_compile_options(smaugt_128_avx2 PUBLIC -DSMAUG_MODE=1)
        set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_128_avx2>)
endif()

if(OQS_ENABLE_KEM_smaugt_192_avx2)
    # Add library for smaugt_192_avx2
add_library(smaugt_192_avx2 OBJECT 
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/cbd.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/ciphertext.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/dg.c
            #${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/fips202.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/hash.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/hwt.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/indcpa.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/io.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/kem.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/key.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/pack.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/poly.c
            #${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/randombytes.c
           # ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/rng.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/verify.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/mul/basemul.S
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/mul/consts10753.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/mul/consts7681.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/mul/invntt.S
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/mul/ntt.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/mul/ntt.S
           # ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/keccak/KeccakP-1600-AVX2.S
           # ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/keccak/KeccakP-1600-times4-SIMD256.c
            )
        target_include_directories(smaugt_192_avx2 PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/include 
        ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/include/keccak 
        ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/include/mul)
        target_include_directories(smaugt_192_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
        target_compile_options(smaugt_192_avx2 PRIVATE -mavx2  -mbmi2  -mpopcnt)
        target_compile_options(smaugt_192_avx2 PUBLIC -DSMAUG_MODE=3)
        set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_192_avx2>)
endif()

if(OQS_ENABLE_KEM_smaugt_256_avx2)
    # Add library for smaugt_256_avx2
add_library(smaugt_256_avx2 OBJECT 
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/cbd.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/ciphertext.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/dg.c
            #${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/fips202.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/hash.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/hwt.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/indcpa.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/io.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/kem.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/key.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/pack.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/poly.c
            #${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/randombytes.c
          #  ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug3_avx2/src/rng.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/verify.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/mul/basemul.S
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/mul/consts10753.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/mul/consts7681.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/mul/invntt.S
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/mul/ntt.c
            ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/mul/ntt.S
            #${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/keccak/KeccakP-1600-AVX2.S
            #${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/src/keccak/KeccakP-1600-times4-SIMD256.c
            )
        target_include_directories(smaugt_256_avx2 PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/include 
        ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/include/keccak 
        ${CMAKE_CURRENT_LIST_DIR}/cryptolab_smaug5_avx2/include/mul)
        target_include_directories(smaugt_256_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
        target_compile_options(smaugt_256_avx2 PRIVATE -mavx2  -mbmi2  -mpopcnt)
        target_compile_options(smaugt_256_avx2 PUBLIC -DSMAUG_MODE=5)
        set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_256_avx2>)
endif()

# Set the object list as a parent scope variable
set(SMAUGT_OBJS ${_SMAUGT_OBJS} PARENT_SCOPE)
#set(SMAUGT_LIBS ${_SMAUGT_LIBS} PARENT_SCOPE)
