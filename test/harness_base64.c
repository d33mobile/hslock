/*
 * Host harness: libs/base64 encode + decode roundtrip.
 * Exercises empty input and every input-length residue mod 3 (0/1/2) so that
 * both the full-triple loop and the two tail branches of base64_encode, plus
 * the padding branches of base64_decode, are covered. Asserts roundtrip
 * identity: decode(encode(x)) == x for all cases.
 */

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "base64.h"

static void roundtrip(const unsigned char *in, size_t in_len) {
    char encoded[BASE64_ENCODED_LEN(64)];
    assert(BASE64_ENCODED_LEN(in_len) <= sizeof encoded);

    base64_encode(in, in_len, encoded);

    size_t enc_len = strlen(encoded);
    /* Encoded length is always a multiple of 4 (with padding). */
    assert(enc_len % 4 == 0);
    assert(enc_len == (in_len + 2) / 3 * 4);

    unsigned char decoded[64];
    int           dec_len = base64_decode(encoded, enc_len, decoded);

    assert(dec_len == (int)in_len);
    assert(memcmp(in, decoded, in_len) == 0);
}

int main(void) {
    /* Empty input: encoder emits just a null terminator, decoder returns 0. */
    roundtrip((const unsigned char *)"", 0);

    /* Lengths covering every residue mod 3. */
    const char *samples[] = {
        "f",           /* 1  -> "==" padding branch (single tail byte)   */
        "fo",          /* 2  -> "="  padding branch (two tail bytes)     */
        "foo",         /* 3  -> exact triple, no padding                 */
        "foob",        /* 4                                              */
        "fooba",       /* 5                                              */
        "foobar",      /* 6                                              */
        "hello world", /* 11                                             */
    };
    for (size_t i = 0; i < sizeof samples / sizeof samples[0]; i++) {
        roundtrip((const unsigned char *)samples[i], strlen(samples[i]));
    }

    /* Binary payload including a NUL and high bytes. */
    const unsigned char bin[] = {0x00, 0xff, 0x10, 0x80, 0x7f, 0x01, 0xab, 0xcd};
    roundtrip(bin, sizeof bin);

    /* Invalid inputs: bad length and out-of-alphabet char must be rejected. */
    unsigned char scratch[64];
    assert(base64_decode("abc", 3, scratch) == -1);  /* length not multiple of 4 */
    assert(base64_decode("ab*d", 4, scratch) == -1); /* '*' not in alphabet       */

    printf("base64 roundtrip OK\n");
    return 0;
}
