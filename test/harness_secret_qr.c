/*
 * Host harness: secret -> base32 -> otpauth URI -> QR code.
 * Mirrors the flow in serial/commands_keys.c (cmd_get_key_secret) using the
 * real shared/random, libs/base32 and libs/qrcodegen sources, with a
 * deterministic host RNG so the result is reproducible.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "random.h"    /* shared/random.h -> generate_secret */
#include "base32.h"    /* libs/base32 */
#include "qrcodegen.h" /* libs/qrcodegen/c */

#define KEY_SECRET_LEN 20

/* Deterministic stand-in for the RP2040 hardware RNG (LCG). */
static uint64_t g_seed = 0x123456789abcdef0ULL;
uint64_t        get_rand_64(void) {
    g_seed = g_seed * 6364136223846793005ULL + 1442695040888963407ULL;
    return g_seed;
}

int main(void) {
    uint8_t secret[KEY_SECRET_LEN];
    generate_secret(secret);

    char b32[BASE32_ENCODED_LEN(KEY_SECRET_LEN)];
    base32_encode(secret, KEY_SECRET_LEN, b32);

    /* 20 bytes -> ceil(160/5) = 32 base32 chars, no padding. */
    assert(strlen(b32) == 32);
    for (size_t i = 0; b32[i]; i++) {
        assert(strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", b32[i]) != NULL);
    }

    char uri[256];
    snprintf(uri, sizeof uri, "otpauth://totp/hslock:admin?secret=%s&issuer=hslock", b32);

    static uint8_t qr[qrcodegen_BUFFER_LEN_MAX];
    static uint8_t tmp[qrcodegen_BUFFER_LEN_MAX];
    bool ok = qrcodegen_encodeText(uri, tmp, qr, qrcodegen_Ecc_MEDIUM, qrcodegen_VERSION_MIN,
                                   qrcodegen_VERSION_MAX, qrcodegen_Mask_AUTO, true);
    assert(ok);

    int size = qrcodegen_getSize(qr);
    assert(size > 0 && size <= 177);

    printf("secret_b32=%s\nqr_size=%d\nOK\n", b32, size);
    return 0;
}
