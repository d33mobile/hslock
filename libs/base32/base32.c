#include "base32.h"

static const char B32_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void base32_encode(const uint8_t *in, size_t in_len, char *out) {
    uint32_t buffer    = 0;
    int      bits_left = 0;
    size_t out_len   = 0;

    for (size_t i = 0; i < in_len; i++) {
        buffer = (buffer << 8) | in[i];
        bits_left += 8;
        while (bits_left >= 5) {
            bits_left -= 5;
            out[out_len++] = B32_CHARS[(buffer >> bits_left) & 0x1F];
        }
    }

    if (bits_left > 0) {
        out[out_len++] = B32_CHARS[(buffer << (5 - bits_left)) & 0x1F];
    }

    out[out_len] = '\0';
}
