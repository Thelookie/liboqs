set(_NTRU_PLUS_OBJS "")


set(_NTRU_PLUS_COMMON_OBJS $<TARGET_OBJECTS:ntruplus_common>)
add_library(ntruplus_common OBJECT ntruplus_common.c)
message(STATUS "NTRUPLUS_COMMON_OBJS = ${_NTRUPLUS_COMMON_OBJS}")
set(NTRUPLUS_COMMON_OBJS ${_NTRU_PLUS_COMMON_OBJS} PARENT_SCOPE)


if(OQS_ENABLE_KEM_ntruplus_576)
    add_library(ntruplus_576_ref OBJECT kem_ntruplus_576.c ntruplus576/kem.c ntruplus576/poly.c ntruplus576/ntt.c ntruplus576/aes256ctr.c ntruplus576/symmetric.c ntruplus576/reduce.c ntruplus576/verify.c)
    target_include_directories(ntruplus_576_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ntruplus576)
    target_include_directories(ntruplus_576_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    target_compile_options(ntruplus_576_ref PUBLIC -DNTRUPLUS_MODE=576)
    set(_NTRU_PLUS_OBJS ${_NTRU_PLUS_OBJS} $<TARGET_OBJECTS:ntruplus_576_ref>)
endif()



if(OQS_ENABLE_KEM_ntruplus_576_avx2)
     add_library(ntruplus_576_avx2 OBJECT kem_ntruplus_576.c ntruplus576_avx2/asm/add.s ntruplus576_avx2/asm/baseinv.s ntruplus576_avx2/asm/basemul.s ntruplus576_avx2/asm/cbd.s ntruplus576_avx2/asm/invntt.s ntruplus576_avx2/asm/ntt.s ntruplus576_avx2/asm/pack.s ntruplus576_avx2/asm/reduce.s ntruplus576_avx2/aes256ctr.c ntruplus576_avx2/consts.c ntruplus576_avx2/kem.c ntruplus576_avx2/poly.c ntruplus576_avx2/symmetric.c ntruplus576_avx2/verify.c ntruplus576_avx2/cpucycles.c ntruplus576_avx2/randombytes.c)
     target_include_directories(ntruplus_576_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ntruplus576_avx2)
     target_include_directories(ntruplus_576_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
     
     #Openssl options
     #target_include_directories(ntruplus_576_avx2 PRIVATE C:/msys64/mingw64/include) 
     #target_link_directories(ntruplus_576_avx2 PRIVATE C:/msys64/mingw64/lib)

     target_compile_options(ntruplus_576_avx2 PRIVATE -mavx2 -mbmi2 -mpopcnt -maes)
     target_compile_options(ntruplus_576_avx2 PUBLIC -DNTRUPLUS_MODE=576)
     set(_NTRU_PLUS_OBJS ${_NTRU_PLUS_OBJS} $<TARGET_OBJECTS:ntruplus_576_avx2>)
 endif()

if(OQS_ENABLE_KEM_ntruplus_768)
    add_library(ntruplus_768_ref OBJECT kem_ntruplus_768.c ntruplus768/kem.c ntruplus768/poly.c ntruplus768/ntt.c ntruplus768/aes256ctr.c ntruplus768/symmetric.c ntruplus768/reduce.c ntruplus768/verify.c)
    target_include_directories(ntruplus_768_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
    
    # Ensure the ntruplus768 randombytes.c is used

    target_compile_options(ntruplus_768_ref PUBLIC -DNTRUPLUS_MODE=768)

    # Ensure ntruplus768 directory is prioritized
    target_include_directories(ntruplus_768_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ntruplus768)
    target_include_directories(ntruplus_768_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)

    target_compile_options(ntruplus_768_ref PUBLIC -DNTRUPLUS_MODE=768)

    if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_definitions(ntruplus_768_ref PRIVATE old_gas_syntax)
    endif()

    set(_NTRU_PLUS_OBJS ${_NTRU_PLUS_OBJS} $<TARGET_OBJECTS:ntruplus_768_ref>)
endif()

if(OQS_ENABLE_KEM_ntruplus_864)
    add_library(ntruplus_864_ref OBJECT kem_ntruplus_864.c ntruplus864/kem.c ntruplus864/poly.c ntruplus864/ntt.c ntruplus864/aes256ctr.c ntruplus864/symmetric.c ntruplus864/reduce.c ntruplus864/verify.c)
    target_compile_options(ntruplus_864_ref PUBLIC -DNTRUPLUS_MODE=864)
    
    # ¿ì¼±¼øÀ§¸¦ ¸í½ÃÀûÀ¸·Î ³ôÀÌ±â À§ÇØ BEFORE ¿É¼Ç »ç¿ë
    target_include_directories(ntruplus_864_ref BEFORE PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ntruplus864)
    target_include_directories(ntruplus_864_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)

    if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_definitions(ntruplus_864_ref PRIVATE old_gas_syntax)
    endif()

    set(_NTRU_PLUS_OBJS ${_NTRU_PLUS_OBJS} $<TARGET_OBJECTS:ntruplus_864_ref>)
endif()


 if(OQS_ENABLE_KEM_ntruplus_768_avx2)
     add_library(ntruplus_768_avx2 OBJECT kem_ntruplus_768.c ntruplus768_avx2/asm/add.s ntruplus768_avx2/asm/baseinv.s ntruplus768_avx2/asm/basemul.s ntruplus768_avx2/asm/cbd.s ntruplus768_avx2/asm/invntt.s ntruplus768_avx2/asm/ntt.s ntruplus768_avx2/asm/pack.s ntruplus768_avx2/asm/reduce.s ntruplus768_avx2/aes256ctr.c ntruplus768_avx2/consts.c ntruplus768_avx2/kem.c ntruplus768_avx2/poly.c ntruplus768_avx2/symmetric.c ntruplus768_avx2/verify.c ntruplus768_avx2/cpucycles.c ntruplus768_avx2/randombytes.c)
     target_include_directories(ntruplus_768_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ntruplus768_avx2)
     target_include_directories(ntruplus_768_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
     # OpenSSL Çì´õ °æ·Î ¼³Á¤
     target_include_directories(ntruplus_768_avx2 PRIVATE C:/msys64/mingw64/include)  # OpenSSL Çì´õ °æ·Î Ãß°¡
     # OpenSSL ¶óÀÌºê·¯¸® °æ·Î ¼³Á¤ (ÇÊ¿ä ½Ã ¸µÅ© ´Ü°è¿¡¼­ »ç¿ë)
     target_link_directories(ntruplus_768_avx2 PRIVATE C:/msys64/mingw64/lib)  # OpenSSL ¶óÀÌºê·¯¸® °æ·Î Ãß°¡

     target_compile_options(ntruplus_768_avx2 PRIVATE -mavx2 -mbmi2 -mpopcnt -maes)
     target_compile_options(ntruplus_768_avx2 PUBLIC -DNTRUPLUS_MODE=768)
     if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
         target_compile_definitions(ntruplus_768_avx2 PRIVATE old_gas_syntax)
     endif()
     set(_NTRU_PLUS_OBJS ${_NTRU_PLUS_OBJS} $<TARGET_OBJECTS:ntruplus_768_avx2>)
 endif()


 if(OQS_ENABLE_KEM_ntruplus_864_avx2)
     add_library(ntruplus_864_avx2 OBJECT kem_ntruplus_864.c ntruplus864_avx2/asm/add.s ntruplus864_avx2/asm/baseinv.s ntruplus864_avx2/asm/basemul.s ntruplus864_avx2/asm/cbd.s ntruplus864_avx2/asm/invntt.s ntruplus864_avx2/asm/ntt.s ntruplus864_avx2/asm/pack.s ntruplus864_avx2/asm/reduce.s ntruplus864_avx2/aes256ctr.c ntruplus864_avx2/consts.c ntruplus864_avx2/kem.c ntruplus864_avx2/poly.c ntruplus864_avx2/symmetric.c ntruplus864_avx2/verify.c ntruplus864_avx2/cpucycles.c ntruplus864_avx2/randombytes.c)
     target_include_directories(ntruplus_864_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ntruplus864_avx2)
     target_include_directories(ntruplus_864_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
     # OpenSSL Çì´õ °æ·Î ¼³Á¤
     target_include_directories(ntruplus_864_avx2 PRIVATE C:/msys64/mingw64/include)  # OpenSSL Çì´õ °æ·Î Ãß°¡
     # OpenSSL ¶óÀÌºê·¯¸® °æ·Î ¼³Á¤ (ÇÊ¿ä ½Ã ¸µÅ© ´Ü°è¿¡¼­ »ç¿ë)
     target_link_directories(ntruplus_864_avx2 PRIVATE C:/msys64/mingw64/lib)  # OpenSSL ¶óÀÌºê·¯¸® °æ·Î Ãß°¡

    target_compile_options(ntruplus_864_avx2 PRIVATE -mavx2 -mbmi2 -mpopcnt -maes)
     target_compile_options(ntruplus_864_avx2 PUBLIC -DNTRUPLUS_MODE=864)
     if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
         target_compile_definitions(ntruplus_864_avx2 PRIVATE old_gas_syntax)
     endif()
     set(_NTRU_PLUS_OBJS ${_NTRU_PLUS_OBJS} $<TARGET_OBJECTS:ntruplus_864_avx2>)
 endif()

if(OQS_ENABLE_KEM_ntruplus_1152)
    add_library(ntruplus_1152_ref OBJECT kem_ntruplus_1152.c ntruplus1152/kem.c ntruplus1152/poly.c ntruplus1152/ntt.c ntruplus1152/aes256ctr.c  ntruplus1152/symmetric.c ntruplus1152/reduce.c ntruplus1152/verify.c)
    target_compile_options(ntruplus_1152_ref PUBLIC -DNTRUPLUS_MODE=1152)
    target_include_directories(ntruplus_1152_ref PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ntruplus1152)
    target_include_directories(ntruplus_1152_ref PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)

    target_compile_options(ntruplus_1152_ref PUBLIC -DNTRUPLUS_MODE=1152)
    if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_definitions(ntruplus_1152_ref PRIVATE old_gas_syntax)
    endif()
    set(_NTRU_PLUS_OBJS ${_NTRU_PLUS_OBJS} $<TARGET_OBJECTS:ntruplus_1152_ref>)
endif()

 if(OQS_ENABLE_KEM_ntruplus_1152_avx2)
     add_library(ntruplus_1152_avx2 OBJECT kem_ntruplus_1152.c ntruplus1152_avx2/asm/add.s ntruplus1152_avx2/asm/baseinv.s ntruplus1152_avx2/asm/basemul.s ntruplus1152_avx2/asm/cbd.s ntruplus1152_avx2/asm/invntt.s ntruplus1152_avx2/asm/ntt.s ntruplus1152_avx2/asm/pack.s ntruplus1152_avx2/asm/reduce.s ntruplus1152_avx2/aes256ctr.c ntruplus1152_avx2/consts.c ntruplus1152_avx2/kem.c ntruplus1152_avx2/poly.c ntruplus1152_avx2/symmetric.c ntruplus1152_avx2/verify.c ntruplus1152_avx2/cpucycles.c ntruplus1152_avx2/randombytes.c)
     target_include_directories(ntruplus_1152_avx2 PRIVATE ${CMAKE_CURRENT_LIST_DIR}/ntruplus1152_avx2)
     target_include_directories(ntruplus_1152_avx2 PRIVATE ${PROJECT_SOURCE_DIR}/src/common/pqclean_shims)
     # OpenSSL Çì´õ °æ·Î ¼³Á¤
     target_include_directories(ntruplus_1152_avx2 PRIVATE C:/msys64/mingw64/include)  # OpenSSL Çì´õ °æ·Î Ãß°¡

     # OpenSSL ¶óÀÌºê·¯¸® °æ·Î ¼³Á¤ (ÇÊ¿ä ½Ã ¸µÅ© ´Ü°è¿¡¼­ »ç¿ë)
     target_link_directories(ntruplus_1152_avx2 PRIVATE C:/msys64/mingw64/lib)  # OpenSSL ¶óÀÌºê·¯¸® °æ·Î Ãß°¡

     target_compile_options(ntruplus_1152_avx2 PRIVATE -mavx2 -mbmi2 -mpopcnt -maes)
     target_compile_options(ntruplus_1152_avx2 PUBLIC -DNTRUPLUS_MODE=1152)
     if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
         target_compile_definitions(ntruplus_1152_avx2 PRIVATE old_gas_syntax)
     endif()
     set(_NTRU_PLUS_OBJS ${_NTRU_PLUS_OBJS} $<TARGET_OBJECTS:ntruplus_1152_avx2>)
 endif()



set(NTRUPLUS_OBJS ${_NTRU_PLUS_OBJS} PARENT_SCOPE)
