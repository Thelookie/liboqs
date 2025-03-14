#ifndef CONFIG_H
#define CONFIG_H

//#define NTRUPLUS_MODE 2
//#define NTRUPLUS_USE_AES
//#define NTRUPLUS_RANDOMIZED_SIGNING
//#define USE_RDPMC
//#define DBENCH

#ifndef NTRUPLUS_MODE
#define NTRUPLUS_MODE 576
#endif

#if NTRUPLUS_MODE == 576
#define CRYPTO_ALGNAME "NTRU+KEM576"
#define NTRUPLUS_NAMESPACETOP ntruplus576_ref
#define NTRUPLUS_NAMESPACE(s) ntruplus576_ref_##s
#elif NTRUPLUS_MODE == 768
#define CRYPTO_ALGNAME "NTRU+KEM768"
#define NTRUPLUS_NAMESPACETOP ntruplus768_ref
#define NTRUPLUS_NAMESPACE(s) ntruplus768_ref_##s
#elif NTRUPLUS_MODE == 864
#define CRYPTO_ALGNAME "NTRU+KEM864"
#define NTRUPLUS_NAMESPACETOP ntruplus864_ref
#define NTRUPLUS_NAMESPACE(s) ntruplus864_ref_##s
#elif NTRUPLUS_MODE == 1152
#define CRYPTO_ALGNAME "NTRU+KEM1152"
#define NTRUPLUS_NAMESPACETOP ntruplus1152_ref
#define NTRUPLUS_NAMESPACE(s) ntruplus1152_ref_##s
#endif
#endif