/*
 * libFuzzer harness: the serial-console command interface, end to end.
 *
 * This drives the REAL firmware input path exactly as it runs on the RP2040:
 *
 *   fuzz bytes -> getchar_timeout_us() -> console_task() char accumulator
 *              -> process_line() tokeniser -> commands_dispatch()
 *              -> real cmd_* handlers -> storage.c / backup.c on real littlefs
 *
 * console.c, commands.c and every cmd_* handler are the untouched first-party
 * sources; only the hardware/network leaves (buzzer, latch, led, light,
 * wifi, ntp, USB, flash, RNG, clock) are stubbed. Storage is backed by a
 * RAM-mapped XIP window (the same trick as test/harness_storage.c), so key
 * add/get/delete/list, wifi set/get and the base64 backup import/export code
 * all execute for real against a genuine littlefs.
 *
 * Per input we reset all persistent state (flash window, admin flag, console
 * input buffer) so a given input reproduces deterministically.
 */

#define _POSIX_C_SOURCE 200809L

#include <setjmp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "hardware/flash.h" /* XIP_BASE, FLASH_SECTOR_SIZE */
#include "pico/stdlib.h"    /* PICO_FLASH_SIZE_BYTES, PICO_OK, PICO_ERROR_TIMEOUT */
#include "pico/unique_id.h"

#include "console.h"
#include "storage/storage.h"

/* admin_mode is a non-static extern in commands.c; reset it every run. */
extern bool admin_mode;

/* --- storage layout, mirrored from storage.c ------------------------------ */

#define STORAGE_SIZE_BYTES   (256 * 1024)
#define STORAGE_FLASH_OFFSET (PICO_FLASH_SIZE_BYTES - STORAGE_SIZE_BYTES)
#define STORAGE_WINDOW_BASE  ((uintptr_t)(XIP_BASE + STORAGE_FLASH_OFFSET))

static uint8_t *flash_ptr(uint32_t flash_offs) {
    return (uint8_t *)(uintptr_t)(XIP_BASE + flash_offs);
}

/* --- RAM-backed flash primitives storage.c drives ------------------------- */

void flash_range_program(uint32_t flash_offs, const uint8_t *data, size_t count) {
    uint8_t *dst = flash_ptr(flash_offs);
    for (size_t i = 0; i < count; i++)
        dst[i] &= data[i]; /* NOR: programming can only clear bits */
}

void flash_range_erase(uint32_t flash_offs, size_t count) {
    memset(flash_ptr(flash_offs), 0xFF, count); /* erased NOR reads as 0xFF */
}

int flash_safe_execute(void (*func)(void *), void *param, uint32_t timeout_ms) {
    (void)timeout_ms;
    func(param);
    return PICO_OK;
}

/* --- fuzz input source + USB connection state ----------------------------- */

static const uint8_t *g_data;
static size_t         g_size;
static size_t         g_pos;
static bool           g_connected;

bool stdio_usb_connected(void) {
    return g_connected;
}

int getchar_timeout_us(uint32_t timeout_us) {
    (void)timeout_us;
    if (g_pos >= g_size)
        return PICO_ERROR_TIMEOUT;
    return g_data[g_pos++];
}

/* --- hardware / network leaves: no-op stubs ------------------------------- */

void buzzer_play_command_ack(void) {
}
void buzzer_play_auth_error(void) {
}
void buzzer_beep_short(void) {
}

void latch_open(void) {
}
void light_on(void) {
}
void light_off(void) {
}
void led_on(void) {
}
void led_off(void) {
}

void sleep_ms(uint32_t ms) {
    (void)ms; /* cmd_test would sleep 1s on hardware; skip it */
}

/* --- injectable clock / ntp / wifi environment -----------------------------
 * The console command logic branches on RTC state (clock_get_unix_time()==0 →
 * boot-bypass window), boot uptime (time_us_64() vs BOOT_BYPASS_WINDOW_US),
 * NTP sync state and wifi-connect success. A single hardcoded environment
 * leaves those branches unreachable. Instead the stubs read a per-run config
 * (g_env); LLVMFuzzerTestOneInput replays each input under EVERY config in
 * ENVS[] (see below), so one corpus entry drives all sides of these gates.
 * ENVS[0] keeps the original {clock=1700000000, time>=WINDOW} environment so
 * the precomputed TOTP seeds (code 218873, built for that clock) still reach
 * the login accept/reject tails. */
typedef struct {
    uint32_t clock_unix;   /* clock_get_unix_time(): 0 == RTC not set */
    uint64_t time_us;      /* time_us_64(): boot uptime, vs BOOT_BYPASS_WINDOW_US */
    bool     ntp_sync_ok;  /* ntp_sync() result */
    bool     wifi_conn_ok; /* wifi_connect() result */
    bool     ntp_synced;   /* ntp_is_synced() */
    uint32_t ntp_last;     /* ntp_last_sync_time() */
} fuzz_env_t;

static fuzz_env_t g_env = {1700000000u, 1234567890ULL, false, false, false, 0};

uint64_t time_us_64(void) {
    return g_env.time_us;
}

uint32_t clock_get_unix_time(void) {
    return g_env.clock_unix;
}

bool ntp_is_synced(void) {
    return g_env.ntp_synced;
}
uint32_t ntp_last_sync_time(void) {
    return g_env.ntp_last;
}
bool ntp_sync(void) {
    return g_env.ntp_sync_ok;
}

bool wifi_connect(const char *ssid, const char *password) {
    (void)ssid;
    (void)password;
    return g_env.wifi_conn_ok;
}

void pico_get_unique_board_id(pico_unique_board_id_t *id_out) {
    for (int i = 0; i < PICO_UNIQUE_BOARD_ID_SIZE_BYTES; i++)
        id_out->id[i] = (uint8_t)(0xA0 + i);
}

/* Deterministic RNG so add-key secret generation is reproducible. The state is
 * reset to a fixed seed at the start of every run (see LLVMFuzzerTestOneInput),
 * so the FIRST add-key in a run always generates the SAME secret regardless of
 * how many keys earlier corpus entries generated. That determinism lets a seed
 * carry the precomputed valid TOTP code and reach cmd_login's admin-success
 * tail (the RNG_SEED / login-accept path). */
#define RNG_SEED 0x9E3779B97F4A7C15ULL
static uint64_t g_rng_state = RNG_SEED;

uint64_t get_rand_64(void) {
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 7;
    g_rng_state ^= g_rng_state << 17;
    return g_rng_state;
}

/* cmd_reboot calls watchdog_reboot() then spins in an infinite tight loop.
 * On hardware the watchdog fires; on the host we longjmp back out so the run
 * ends instead of hanging the fuzzer. */
static jmp_buf g_reboot_jmp;

void watchdog_reboot(uint32_t pc, uint32_t sp, uint32_t delay_ms) {
    (void)pc;
    (void)sp;
    (void)delay_ms;
    longjmp(g_reboot_jmp, 1);
}

/* --- per-run reset -------------------------------------------------------- */

static void flash_ram_reset(void) {
    memset((void *)STORAGE_WINDOW_BASE, 0xFF, STORAGE_SIZE_BYTES);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    /* Map the XIP storage window into host RAM at its true address, once. */
    void *base = mmap((void *)STORAGE_WINDOW_BASE, STORAGE_SIZE_BYTES, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (base == MAP_FAILED || (uintptr_t)base != STORAGE_WINDOW_BASE) {
        perror("mmap XIP window");
        return -1;
    }

    /* Silence all console output for throughput; keep stderr for sanitizers. */
    if (!freopen("/dev/null", "w", stdout)) {
        perror("freopen stdout");
        return -1;
    }

    /* console_init() is a near-no-op (USB stdio is brought up in CMakeLists on
     * hardware); call it once so it is exercised by the coverage build. */
    console_init();
    return 0;
}

/* Clock / ntp / wifi environments each corpus input is replayed under. Every
 * input runs once per entry, so a single seed reaches all sides of the
 * RTC-bypass window, the NTP-synced and wifi-connect branches, etc.
 *   [0] RTC set, uptime past bypass window, all HW ops fail — the ORIGINAL
 *       environment; the precomputed-TOTP login seeds (clock==1700000000) hit
 *       their accept/reject tails only here.
 *   [1] RTC not set, WITHIN the bypass window  -> cmd_login "try again" error.
 *   [2] RTC not set, PAST the bypass window     -> cmd_login RTC-open mode.
 *   [3] RTC set, everything succeeds            -> ntp synced/last-sync,
 *       sync-ntp ok, set-wifi connect ok + ntp ok.
 *   [4] RTC set, wifi connect ok but ntp fails  -> set-wifi "ntp sync failed". */
static const fuzz_env_t ENVS[] = {
    {1700000000u, 1234567890ULL, false, false, false, 0},
    {0u, 1000ULL, false, false, false, 0},
    {0u, 400000000ULL, false, false, false, 0},
    {1700000000u, 1234567890ULL, true, true, true, 1700000000u},
    {1700000000u, 1234567890ULL, false, true, false, 0},
};
#define NUM_ENVS (sizeof(ENVS) / sizeof(ENVS[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    for (size_t e = 0; e < NUM_ENVS; e++) {
        g_env = ENVS[e];

        /* Reset persistent state so this input reproduces deterministically
         * under each environment (independent of the previous env's run). */
        flash_ram_reset();
        if (!storage_init())
            continue; /* format/mount failure is not an input-driven bug */
        admin_mode  = false;
        g_rng_state = RNG_SEED; /* first add-key of each run => fixed secret */

        g_data      = data;
        g_size      = size;
        g_pos       = 0;
        g_connected = true;

        if (setjmp(g_reboot_jmp) == 0) {
            /* First call connects (prints banner, consumes no byte); subsequent
             * calls each read at most one byte. Drive until input is drained. */
            console_task(); /* connect */
            while (g_pos < g_size)
                console_task();
            /* One more poll with the input drained but still connected: getchar
             * returns PICO_ERROR_TIMEOUT, exercising the idle-poll early return
             * (the common case on hardware, where most polls have no byte). */
            console_task();
        }

        /* Simulate USB disconnect: clears admin + zeroes the console input_len,
         * so no console state leaks into the next run. */
        g_connected = false;
        console_task();

        /* A second poll while still disconnected: was_connected is now false, so
         * both the just-disconnected block and the connect block are skipped and
         * console_task falls through to the `if (!connected) return;` guard —
         * the only path that reaches it (a disconnected idle poll). */
        console_task();
    }

    return 0;
}
