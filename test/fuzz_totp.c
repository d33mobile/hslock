/*
 * libFuzzer harness: shared/totp.c (RFC 6238 TOTP), in isolation.
 *
 * The console fuzzer can only reach totp_verify()'s REJECT tail: a random code
 * practically never equals the valid TOTP for the (RNG-generated) stored
 * secret, so `return true` and the whole T-1/T/T+1 match logic stay dark. This
 * harness drives totp.c directly. It interprets the fuzz bytes as a (time,
 * secret) pair and then, every run, deterministically exercises BOTH paths of
 * totp_verify:
 *
 *   - unix_time == 0            -> the "RTC not set" reject branch
 *   - a valid code at T-1/T/T+1 -> the window loop's ACCEPT branch (return true)
 *   - an impossible 7-digit code -> the full loop with no match (reject tail)
 *
 * totp.c is the untouched first-party source, built against the REAL mbedtls
 * (system libmbedcrypto) so HMAC-SHA1 computes genuine codes; the compile-only
 * stub in stub/mbedtls/md.h cannot. clock_get_unix_time() is injected here so
 * the verify time is controllable and deterministic.
 *
 * The valid-code checks double as a differential oracle: a valid in-window code
 * that fails to verify would abort() the run and surface a totp.c regression.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "totp.h"

/* Injectable clock: totp_verify() reads the current time through this. */
static uint32_t g_unix_time;

uint32_t clock_get_unix_time(void) {
    return g_unix_time;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* First up to 4 bytes -> a big-endian time base; the rest -> the secret. */
    uint32_t t   = 0;
    size_t   off = 0;
    for (int i = 0; i < 4 && off < size; i++)
        t = (t << 8) | data[off++];

    uint8_t secret[64];
    size_t  secret_len = size - off;
    if (secret_len > sizeof secret)
        secret_len = sizeof secret;
    if (secret_len)
        memcpy(secret, data + off, secret_len);

    /* RTC-not-set: unix_time == 0 must reject regardless of the code. */
    g_unix_time = 0;
    (void)totp_verify(secret, secret_len, 0);

    /* RTC set: force a non-zero time so the step arithmetic and window run. */
    g_unix_time   = t | 1u;
    uint64_t step = (uint64_t)g_unix_time / TOTP_STEP_SECONDS;

    /* A correct code for each in-window step (T-1, T, T+1) must verify true,
     * exercising the loop's match/accept branch at every window offset. */
    for (int delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta++) {
        uint32_t good = totp_at(secret, secret_len, step + (uint64_t)delta);
        if (!totp_verify(secret, secret_len, good))
            abort(); /* in-window valid code failing to verify == totp.c bug */
    }

    /* An impossible 7-digit code (totp_at always yields < 1e6) drives the full
     * window loop with no match -> the reject tail (return false). */
    if (totp_verify(secret, secret_len, 1000000u))
        abort(); /* out-of-range code accepted == totp.c bug */

    return 0;
}
