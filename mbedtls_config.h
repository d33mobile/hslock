#ifndef _MBEDTLS_CONFIG_H
#define _MBEDTLS_CONFIG_H

#if LIB_PICO_SHA256
// Enable hardware acceleration
#define MBEDTLS_SHA256_ALT
#else
#define MBEDTLS_SHA256_C
#endif

#define MBEDTLS_SHA1_C
#define MBEDTLS_MD_C

// H6: authenticated-encrypted backups (AES-256-GCM payload, PBKDF2-HMAC-SHA256
// key derivation from an operator passphrase). GCM_C pulls in the cipher layer
// (mbedtls_gcm_setkey -> mbedtls_cipher_setup), which needs CIPHER_C + AES_C;
// PKCS5_C provides mbedtls_pkcs5_pbkdf2_hmac_ext and needs MD_C (above) and the
// already-enabled SHA-256. Verify the resulting firmware image size on device.
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C
#define MBEDTLS_PKCS5_C

#endif