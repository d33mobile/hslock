/*
 * libFuzzer harness: network/ntp.c NTP response parser (ntp_recv_cb), driven
 * directly on the REMOTE untrusted-input surface.
 *
 * ntp_recv_cb is the udp_recv() callback lwIP invokes with a UDP datagram from
 * whatever host answered on port 123 -- i.e. an NTP server OR an on-path
 * attacker spoofing one. It is the only place firmware-external network bytes
 * reach the time logic, so a parser bug here is a remote issue: the 48-byte
 * body's transmit-timestamp (bytes 40..43) becomes the RTC. This harness feeds
 * fuzzer bytes straight into that callback via a host pbuf.
 *
 * ntp_recv_cb is static, so we #include the real ntp.c into this TU (the
 * standard static-function fuzzing pattern). That also puts ntp.c's file-static
 * state (synced / last_sync_unix / last_sync_monotonic_us / ntp_state) in scope,
 * which we reset for determinism and preset to deterministically drive BOTH
 * rollback_check() arms every run. Every lwip/pico/hardware symbol ntp.c pulls
 * in is stubbed below (the non-parse ntp_sync/dns paths only need to LINK -- the
 * harness never calls them); the injectable time_us_64() makes rollback_check
 * deterministic.
 *
 * The two valid-time sub-cases double as a differential oracle: a timestamp at
 * or above the rollback floor that fails to apply, or one below it that applies,
 * would be an ntp.c regression (they do not abort -- ntp_recv_cb is void -- but
 * the coverage/state asserts here would).
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* --- host stubs for every non-parse symbol ntp.c references --------------- */
/* Declarations come from -idirafter stub (the lwip, pico and hardware dirs); these
 * are the definitions so the whole ntp.c TU links. Only time_us_64() and
 * clock_set_from_unix_time() matter to the parse path; the rest are no-ops that
 * exist purely because ntp_sync()/dns_found_cb() are compiled (not called). */

#include "lwip/arch.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "pico/time.h"

/* Injectable monotonic clock: rollback_check()/apply_time() read time through
 * this, so the floor computation is deterministic per run. */
static uint64_t g_time_us = 0;

uint64_t time_us_64(void) {
    return g_time_us;
}

/* Records the last timestamp apply_time() pushed to the RTC, for the oracle. */
static uint32_t g_applied_unix;
static int      g_applied_called;

void clock_set_from_unix_time(uint32_t unix_time) {
    g_applied_unix   = unix_time;
    g_applied_called = 1;
}

/* pbuf: the fuzz bytes ride in via p->payload; the parse copies buf[0..47]. */
u16_t pbuf_copy_partial(const struct pbuf *p, void *dataptr, u16_t len, u16_t offset) {
    if (offset >= p->len)
        return 0;
    u16_t avail = (u16_t)(p->len - offset);
    u16_t n     = len < avail ? len : avail;
    memcpy(dataptr, (const uint8_t *)p->payload + offset, n);
    return n;
}

u8_t pbuf_free(struct pbuf *p) {
    (void)p;
    return 1;
}

/* Never called (dns_found_cb is only compiled, not invoked); link-only. */
struct pbuf *pbuf_alloc(pbuf_kind_t layer, u16_t length, pbuf_kind_t type) {
    (void)layer;
    (void)length;
    (void)type;
    return NULL;
}

struct udp_pcb *udp_new_ip_type(u8_t type) {
    (void)type;
    return NULL;
}
void udp_remove(struct udp_pcb *pcb) {
    (void)pcb;
}
void udp_recv(struct udp_pcb *pcb, udp_recv_fn recv, void *recv_arg) {
    (void)pcb;
    (void)recv;
    (void)recv_arg;
}
err_t udp_sendto(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst_ip, u16_t dst_port) {
    (void)pcb;
    (void)p;
    (void)dst_ip;
    (void)dst_port;
    return ERR_OK;
}

err_t dns_gethostbyname(const char *hostname, ip_addr_t *addr, dns_found_callback found,
                        void *callback_arg) {
    (void)hostname;
    (void)addr;
    (void)found;
    (void)callback_arg;
    return ERR_INPROGRESS;
}

void cyw43_arch_lwip_begin(void) {
}
void cyw43_arch_lwip_end(void) {
}
void cyw43_arch_poll(void) {
}

void sleep_ms(uint32_t ms) {
    (void)ms;
}
void sleep_us(uint64_t us) {
    (void)us;
}
absolute_time_t make_timeout_time_ms(uint32_t ms) {
    (void)ms;
    return 0;
}
bool time_reached(absolute_time_t t) {
    (void)t;
    return true;
}

void rtc_init(void) {
}
void buzzer_play_ntp_sync_error(void) {
}

/* --- the target, static functions and file-static state now in scope ------ */
#include "../network/ntp.c"

/* --- helpers -------------------------------------------------------------- */

/* Reset ntp.c's file-static state so each scenario starts from a known point. */
static void reset_ntp_state(void) {
    synced                 = false;
    last_sync_unix         = 0;
    last_sync_monotonic_us = 0;
    ntp_state              = NTP_STATE_IDLE;
    g_applied_called       = 0;
    g_applied_unix         = 0;
}

/* Drive ntp_recv_cb with a datagram: p->len == len selects the parse/too-short
 * branch, and the first min(len,64) bytes become the packet body. payload is a
 * zero-padded 64-byte scratch so the fixed 48-byte read is always in-bounds
 * (confirming the p->len<48 guard makes the copy safe). */
static void feed(const uint8_t *bytes, size_t len) {
    uint8_t payload[64];
    memset(payload, 0, sizeof payload);
    size_t plen = len < sizeof payload ? len : sizeof payload;
    if (plen)
        memcpy(payload, bytes, plen);

    struct pbuf p = {
        .next    = NULL,
        .payload = payload,
        .len     = (u16_t)len,
        .tot_len = (u16_t)len,
    };
    ntp_recv_cb(NULL, NULL, &p, NULL, 123);
}

/* Build a 48-byte NTP response whose transmit timestamp decodes to unix_time. */
static void make_ntp_packet(uint8_t pkt[48], uint32_t unix_time) {
    memset(pkt, 0, 48);
    pkt[0]                      = 0x1C; /* LI=0, VN=3, Mode=4 (server) */
    uint32_t seconds_since_1900 = unix_time + NTP_DELTA;
    pkt[40]                     = (uint8_t)(seconds_since_1900 >> 24);
    pkt[41]                     = (uint8_t)(seconds_since_1900 >> 16);
    pkt[42]                     = (uint8_t)(seconds_since_1900 >> 8);
    pkt[43]                     = (uint8_t)(seconds_since_1900);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;
    /* Silence ntp.c's printf() so it does not throttle the fuzzer. */
    if (!freopen("/dev/null", "w", stdout)) {
        perror("freopen stdout");
        return -1;
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* (1) Fuzzer-driven call from the pre-sync state: size<48 exercises the
     * too-short reject; size>=48 runs the full parse, with the fuzzer choosing
     * bytes 40..43 (the timestamp) and !synced -> rollback_check returns true
     * -> apply_time. Wrap arithmetic in `seconds - NTP_DELTA` is exercised for
     * every fuzzer-chosen timestamp (defined for unsigned, not UB). */
    reset_ntp_state();
    g_time_us = 0;
    feed(data, size);

    /* (2) Deterministic synced scenario driving BOTH rollback_check arms, so
     * the reject/accept branches register every run regardless of fuzz input.
     * floor = last_sync_unix + elapsed_s - NTP_ROLLBACK_EPSILON_S. */
    reset_ntp_state();
    synced                 = true;
    last_sync_unix         = 1700000000u;
    last_sync_monotonic_us = 0;
    g_time_us              = 0;                                       /* elapsed_s == 0 */
    uint32_t floor         = last_sync_unix - NTP_ROLLBACK_EPSILON_S; /* 1699999940 */

    uint8_t pkt[48];

    /* Below the floor: rollback rejected, RTC untouched, state == FAILED. */
    make_ntp_packet(pkt, floor - 100u);
    feed(pkt, 48);
    assert(g_applied_called == 0);
    assert(ntp_state == NTP_STATE_FAILED);

    /* State unchanged by the reject (apply_time never ran), so the floor still
     * holds. At/above the floor: accepted, RTC set to exactly that time. */
    make_ntp_packet(pkt, floor + 100u);
    feed(pkt, 48);
    assert(g_applied_called == 1);
    assert(g_applied_unix == floor + 100u);
    assert(ntp_state == NTP_STATE_SUCCESS);
    assert(synced && last_sync_unix == floor + 100u);

    /* (3) Cheap host-safe coverage of the non-parse API that needs no live
     * lwip: the trivial getters, ntp_init (rtc_init stub), and ntp_task's
     * due-for-resync arm -- with udp_new_ip_type() stubbed to NULL, the resync
     * ntp_sync() takes its pcb-creation-fail return and ntp_task buzzes. The
     * dns-resolve/udp-send success path (dns_found_cb + the rest of ntp_sync)
     * stays dark: it needs a real lwip stack and is HW-only. */
    ntp_init();
    (void)ntp_is_synced();
    (void)ntp_last_sync_time();
    synced                 = true;
    last_sync_monotonic_us = 0;
    g_time_us              = (uint64_t)(NTP_RESYNC_INTERVAL_S + 1) * 1000000ULL;
    ntp_task();

    return 0;
}
