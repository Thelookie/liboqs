#ifndef CONFIG_H
#define CONFIG_H

#if HAETAE_MODE == 2
#define CRYPTO_ALGNAME "HAETAE2"
#define HAETAE_NAMESPACETOP haetae2
#define HAETAE_NAMESPACE(s) cryptolab_haetae2_avx2_##s
#elif HAETAE_MODE == 3
#define CRYPTO_ALGNAME "HAETAE3"
#define HAETAE_NAMESPACETOP haetae3
#define HAETAE_NAMESPACE(s) cryptolab_haetae3_avx2_##s
#elif HAETAE_MODE == 5
#define CRYPTO_ALGNAME "HAETAE5"
#define HAETAE_NAMESPACETOP haetae5
#define HAETAE_NAMESPACE(s) cryptolab_haetae5_avx2_##s
#endif
#endif