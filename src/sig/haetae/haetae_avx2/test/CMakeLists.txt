# shake only

add_executable(${LIB_NAME2}-main main.c ${CMAKE_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${LIB_NAME2}-main ${LIB_NAME2_TEST})

add_executable(${LIB_NAME3}-main main.c ${CMAKE_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${LIB_NAME3}-main ${LIB_NAME3_TEST})

add_executable(${LIB_NAME5}-main main.c ${CMAKE_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${LIB_NAME5}-main ${LIB_NAME5_TEST})

# shake + aes

add_executable(${LIB_NAME2_AES}-main main.c ${CMAKE_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${LIB_NAME2_AES}-main ${LIB_NAME2_AES_TEST})

add_executable(${LIB_NAME3_AES}-main main.c ${CMAKE_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${LIB_NAME3_AES}-main ${LIB_NAME3_AES_TEST})

add_executable(${LIB_NAME5_AES}-main main.c ${CMAKE_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${LIB_NAME5_AES}-main ${LIB_NAME5_AES_TEST})
