# SPDX-License-Identifier: MIT

# Initialize object list
set(_PALOMA_OBJS "")

# Common source files
set(COMMON_SRC_FILES
    paloma_common/utility.c
    paloma_common/gf2m.c
    paloma_common/gf2m_poly.c
    paloma_common/mat_mul.c
    paloma_common/lsh.c
    paloma_common/lsh512.c
    paloma_common/paloma_api.c
    paloma_common/genkeypair.c
    paloma_common/encrypt.c
    paloma_common/encap.c
    paloma_common/decrypt.c
    paloma_common/decoding.c
    paloma_common/decap.c
    paloma_common/gf2m_tab.c
)

# paloma_128 configuration
if(OQS_ENABLE_KEM_paloma_128)
    add_library(paloma_128 OBJECT kem_paloma_128.c ${COMMON_SRC_FILES})
    target_include_directories(paloma_128 PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/paloma_common
        ${CMAKE_CURRENT_LIST_DIR}/paloma_128
        ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims
    )
    target_compile_options(paloma_128 PUBLIC -DPALOMA_SECURITY_LEVEL=128)
    set(_PALOMA_OBJS ${_PALOMA_OBJS} $<TARGET_OBJECTS:paloma_128>)
endif()

# paloma_192 configuration
if(OQS_ENABLE_KEM_paloma_192)
    add_library(paloma_192 OBJECT kem_paloma_192.c ${COMMON_SRC_FILES})
    target_include_directories(paloma_192 PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/paloma_common
        ${CMAKE_CURRENT_LIST_DIR}/paloma_192
        ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims
    )
    target_compile_options(paloma_192 PUBLIC -DPALOMA_SECURITY_LEVEL=192)
    set(_PALOMA_OBJS ${_PALOMA_OBJS} $<TARGET_OBJECTS:paloma_192>)
endif()

# paloma_256 configuration
if(OQS_ENABLE_KEM_paloma_256)
    add_library(paloma_256 OBJECT kem_paloma_256.c ${COMMON_SRC_FILES})
    target_include_directories(paloma_256 PRIVATE 
        ${CMAKE_CURRENT_LIST_DIR}/paloma_common
        ${CMAKE_CURRENT_LIST_DIR}/paloma_256
        ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims
    )
    target_compile_options(paloma_256 PUBLIC -DPALOMA_SECURITY_LEVEL=256)
    set(_PALOMA_OBJS ${_PALOMA_OBJS} $<TARGET_OBJECTS:paloma_256>)
endif()

# Set the object list as a parent scope variable
set(PALOMA_OBJS ${_PALOMA_OBJS} PARENT_SCOPE)
