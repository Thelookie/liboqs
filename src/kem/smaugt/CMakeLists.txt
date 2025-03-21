# SPDX-License-Identifier: MIT

# Initialize object list
set(_SMAUGT_OBJS "")
set(_SMAUGT_COMMON_OBJS "")
set(_SMAUGT_AVX2_COMMON_OBJS "")

#common objects
add_library(smaugt_common OBJECT smaugt_ref/src/smaugt_common.c)
target_include_directories(smaugt_common PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/include)
if(OQS_ENABLE_KEM_smaugt128)
    target_compile_options(smaugt_common PUBLIC -DSMAUG_MODE=1)
elseif(OQS_ENABLE_KEM_smaugt192)
    target_compile_options(smaugt_common PUBLIC -DSMAUG_MODE=3)
elseif(OQS_ENABLE_KEM_smaugt256)
    target_compile_options(smaugt_common PUBLIC -DSMAUG_MODE=5)
endif()
set(_SMAUGT_COMMON_OBJS ${_SMAUGT_COMMON_OBJS} $<TARGET_OBJECTS:smaugt_common>)

# smaugt_128 configuration
if(OQS_ENABLE_KEM_smaugt_128)
    file(GLOB SMAUGT_128_SRCS "smaugt_ref/src/*.c")
    list(REMOVE_ITEM SMAUGT_128_SRCS "${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/src/smaugt_common.c")
    add_library(smaugt_128_ref OBJECT kem_smaugt_128.c ${SMAUGT_128_SRCS})
    target_include_directories(smaugt_128_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/include
    ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    target_compile_options(smaugt_128_ref PUBLIC -DSMAUG_MODE=1)
    set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_128_ref>)
endif()

# smaugt_192 configuration
if(OQS_ENABLE_KEM_smaugt_192)
    file(GLOB SMAUGT_192_SRCS "smaugt_ref/src/*.c")
    list(REMOVE_ITEM SMAUGT_192_SRCS "${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/src/smaugt_common.c")
    add_library(smaugt_192_ref OBJECT kem_smaugt_192.c ${SMAUGT_192_SRCS})
    target_include_directories(smaugt_192_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/include ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    target_compile_options(smaugt_192_ref PUBLIC -DSMAUG_MODE=3)
    set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_192_ref>)
endif()

# smaugt_256 configuration
if(OQS_ENABLE_KEM_smaugt_256)
    file(GLOB SMAUGT_256_SRCS "smaugt_ref/src/*.c")
    list(REMOVE_ITEM SMAUGT_256_SRCS "${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/src/smaugt_common.c")
    add_library(smaugt_256_ref OBJECT kem_smaugt_256.c ${SMAUGT_256_SRCS})
    target_include_directories(smaugt_256_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_ref/include ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    target_compile_options(smaugt_256_ref PUBLIC -DSMAUG_MODE=5)
    set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_256_ref>)
endif()


set(SRCS
smaugt_avx2/src/ciphertext.c
smaugt_avx2/src/dg.c
smaugt_avx2/src/hash.c
smaugt_avx2/src/hwt.c
smaugt_avx2/src/indcpa.c
smaugt_avx2/src/io.c
smaugt_avx2/src/kem.c
smaugt_avx2/src/key.c
smaugt_avx2/src/pack.c
smaugt_avx2/src/poly.c
smaugt_avx2/src/verify.c
smaugt_avx2/src/cbd.c
smaugt_avx2/src/mul/ntt.c
smaugt_avx2/src/mul/ntt.S
smaugt_avx2/src/mul/invntt.S
smaugt_avx2/src/mul/basemul.S
smaugt_avx2/src/mul/consts7681.c
smaugt_avx2/src/mul/consts10753.c
)


if(OQS_ENABLE_KEM_smaugt_128_avx2 OR OQS_ENABLE_KEM_smaugt_192_avx2 OR OQS_ENABLE_KEM_smaugt_256_avx2)
    add_library(smaugt_avx2_common OBJECT 
        smaugt_avx2/smaugt_avx2_common/keccak/KeccakP-1600-times4-SIMD256.c
        smaugt_avx2/src/smaugt_avx2_common.c)
        target_include_directories(smaugt_avx2_common PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include ${PROJECT_SOURCE_DIR}/src/common/sha3/xkcp_low/KeccakP-1600/avx2)
        target_compile_options(smaugt_avx2_common PRIVATE  -mavx2  -mbmi2  -mpopcnt )
    if(OQS_ENABLE_KEM_smaugt_128_avx2)
        target_compile_options(smaugt_avx2_common PUBLIC -mavx2 -mbmi2 -mpopcnt -DSMAUG_MODE=1)
    elseif(OQS_ENABLE_KEM_smaugt_192_avx2)
        target_compile_options(smaugt_avx2_common PUBLIC -mavx2 -mbmi2 -mpopcnt -DSMAUG_MODE=3)
    elseif(OQS_ENABLE_KEM_smaugt_256_avx2)
        target_compile_options(smaugt_avx2_common PUBLIC -mavx2 -mbmi2 -mpopcnt -DSMAUG_MODE=5)
    endif()
    set(_SMAUGT_AVX2_COMMON_OBJS ${_SMAUGT_AVX2_COMMON_OBJS} $<TARGET_OBJECTS:smaugt_avx2_common>)
    set(SMAUGT_AVX2_COMMON_OBJS ${_SMAUGT_AVX2_COMMON_OBJS} PARENT_SCOPE)
endif()

if(OQS_ENABLE_KEM_smaugt_128_avx2)
    # Add library for smaugt_128_avx2
    add_library(smaugt_128_avx2 OBJECT ${SRCS})
    # Include directories
    target_include_directories(smaugt_128_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include/keccak ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include/mul ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)

    target_compile_options(smaugt_128_avx2 PRIVATE  -mavx2  -mbmi2  -mpopcnt )
    target_compile_options(smaugt_128_avx2 PUBLIC -DSMAUG_MODE=1)
    set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_128_avx2>)
endif()

if(OQS_ENABLE_KEM_smaugt_192_avx2)
   # Add library for smaugt_192_avx2
    add_library(smaugt_192_avx2 OBJECT ${SRCS})
    # Include directories
    target_include_directories(smaugt_192_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include/keccak ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include/mul ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)

    target_compile_options(smaugt_192_avx2 PRIVATE  -mavx2  -mbmi2  -mpopcnt )
    target_compile_options(smaugt_192_avx2 PUBLIC -DSMAUG_MODE=3)
    set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_192_avx2>)
endif()

if(OQS_ENABLE_KEM_smaugt_256_avx2)
    # Add library for smaugt_256_avx2
    add_library(smaugt_256_avx2 OBJECT ${SRCS})
    target_include_directories(smaugt_256_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include/keccak ${CMAKE_CURRENT_LIST_DIR}/smaugt_avx2/include/mul ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    target_compile_options(smaugt_256_avx2 PRIVATE  -mavx2  -mbmi2  -mpopcnt )
    target_compile_options(smaugt_256_avx2 PUBLIC -DSMAUG_MODE=5)
    set(_SMAUGT_OBJS ${_SMAUGT_OBJS} $<TARGET_OBJECTS:smaugt_256_avx2>)
endif()

# Set the object list as a parent scope variable
set(SMAUGT_OBJS ${_SMAUGT_OBJS} PARENT_SCOPE)
set(SMAUGT_COMMON_OBJS ${_SMAUGT_COMMON_OBJS} PARENT_SCOPE)
