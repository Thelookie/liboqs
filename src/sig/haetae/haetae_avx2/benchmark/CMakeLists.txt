set(BENCH_NAME2 ${PROJECT_NAME}2-benchmark)
add_executable(${BENCH_NAME2} speed.c cpucycles.c speed_print.c ${PROJECT_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${BENCH_NAME2} ${LIB_NAME2} OpenSSL::Crypto)

set(BENCH_NAME3 ${PROJECT_NAME}3-benchmark)
add_executable(${BENCH_NAME3} speed.c cpucycles.c speed_print.c ${PROJECT_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${BENCH_NAME3} ${LIB_NAME3} OpenSSL::Crypto)

set(BENCH_NAME5 ${PROJECT_NAME}5-benchmark)
add_executable(${BENCH_NAME5} speed.c cpucycles.c speed_print.c ${PROJECT_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${BENCH_NAME5} ${LIB_NAME5} OpenSSL::Crypto)

set(BENCH_NAME2AES ${PROJECT_NAME}2_AES-benchmark)
add_executable(${BENCH_NAME2AES} speed.c cpucycles.c speed_print.c ${PROJECT_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${BENCH_NAME2AES} ${LIB_NAME2_AES} OpenSSL::Crypto)

set(BENCH_NAME3AES ${PROJECT_NAME}3_AES-benchmark)
add_executable(${BENCH_NAME3AES} speed.c cpucycles.c speed_print.c ${PROJECT_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${BENCH_NAME3AES} ${LIB_NAME3_AES} OpenSSL::Crypto)

set(BENCH_NAME5AES ${PROJECT_NAME}5_AES-benchmark)
add_executable(${BENCH_NAME5AES} speed.c cpucycles.c speed_print.c ${PROJECT_SOURCE_DIR}/src/randombytes.c)
target_link_libraries(${BENCH_NAME5AES} ${LIB_NAME5_AES} OpenSSL::Crypto)
