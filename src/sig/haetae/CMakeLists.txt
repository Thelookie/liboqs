# SPDX-License-Identifier: MIT

# Initialize object list
set(_HAETAE_OBJS "")

# haetae128 configuration
if(OQS_ENABLE_SIG_haetae128)
    file(GLOB HAETAE_128_SRCS "haetae_ref/src/*.c")
    add_library(haetae_128_ref OBJECT haetae128.c ${HAETAE_128_SRCS})
    target_include_directories(haetae_128_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/haetae_ref/include)
    target_compile_options(haetae_128_ref PUBLIC -DHAETAE_MODE=2)
    set(_HAETAE_OBJS ${_HAETAE_OBJS} $<TARGET_OBJECTS:haetae_128_ref>)
endif()

# haetae192 configuration
if(OQS_ENABLE_SIG_haetae192)
    file(GLOB HAETAE_192_SRCS "haetae_ref/src/*.c")
    add_library(haetae_192_ref OBJECT haetae192.c ${HAETAE_192_SRCS})
    target_include_directories(haetae_192_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/haetae_ref/include)
    target_compile_options(haetae_192_ref PUBLIC -DHAETAE_MODE=3)
    set(_HAETAE_OBJS ${_HAETAE_OBJS} $<TARGET_OBJECTS:haetae_192_ref>)
endif()

# haetae256 configuration
if(OQS_ENABLE_SIG_haetae256)
    file(GLOB HAETAE_256_SRCS "haetae_ref/src/*.c")
    add_library(haetae_256_ref OBJECT haetae256.c ${HAETAE_256_SRCS})
    target_include_directories(haetae_256_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/haetae_ref/include)
    target_compile_options(haetae_256_ref PUBLIC -DHAETAE_MODE=5)
    set(_HAETAE_OBJS ${_HAETAE_OBJS} $<TARGET_OBJECTS:haetae_256_ref>)
endif()

# haetae128 AVX2 configuration
if(OQS_ENABLE_SIG_haetae128_avx2)
    file(GLOB HAETAE_128_AVX2_SRCS "haetae_avx2/src/*.c" "haetae_avx2/src/*.S")
    add_library(haetae_128_avx2 OBJECT ${HAETAE_128_AVX2_SRCS})
    target_include_directories(haetae_128_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/haetae_avx2/include)
    target_compile_options(haetae_128_avx2 PRIVATE -mavx2 -mbmi2 -mpopcnt)
    target_compile_options(haetae_128_avx2 PUBLIC -DHAETAE_MODE=2)
    set(_HAETAE_OBJS ${_HAETAE_OBJS} $<TARGET_OBJECTS:haetae_128_avx2>)
endif()

# haetae192 AVX2 configuration
if(OQS_ENABLE_SIG_haetae192_avx2)
    file(GLOB HAETAE_192_AVX2_SRCS "haetae_avx2/src/*.c" "haetae_avx2/src/*.S")
    add_library(haetae_192_avx2 OBJECT ${HAETAE_192_AVX2_SRCS})
    target_include_directories(haetae_192_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/haetae_avx2/include)
    target_compile_options(haetae_192_avx2 PRIVATE -mavx2 -mbmi2 -mpopcnt)
    target_compile_options(haetae_192_avx2 PUBLIC -DHAETAE_MODE=3)
    set(_HAETAE_OBJS ${_HAETAE_OBJS} $<TARGET_OBJECTS:haetae_192_avx2>)
endif()

# haetae256 AVX2 configuration
if(OQS_ENABLE_SIG_haetae256_avx2)
    file(GLOB HAETAE_256_AVX2_SRCS "haetae_avx2/src/*.c" "haetae_avx2/src/*.S")
    add_library(haetae_256_avx2 OBJECT ${HAETAE_256_AVX2_SRCS})
    target_include_directories(haetae_256_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/haetae_avx2/include)
    target_compile_options(haetae_256_avx2 PRIVATE -mavx2 -mbmi2 -mpopcnt)
    target_compile_options(haetae_256_avx2 PUBLIC -DHAETAE_MODE=5)
    set(_HAETAE_OBJS ${_HAETAE_OBJS} $<TARGET_OBJECTS:haetae_256_avx2>)
endif()

# Set the object list as a parent scope variable
set(HAETAE_OBJS ${_HAETAE_OBJS} PARENT_SCOPE)
