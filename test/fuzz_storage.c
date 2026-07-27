/*
 * libFuzzer harness: storage/storage.c CRUD API, driven directly.
 *
 * The console and backup fuzzers only ever reach storage.c on a FRESH,
 * just-formatted littlefs, and only through the callers that exist in the
 * firmware (which always list with max_count == BACKUP_MAX_KEYS and only ever
 * touch storage AFTER a successful storage_init). That leaves a cluster of
 * storage.c branches host-reachable but never hit by those two fuzzers:
 *
 *   - the pre-mount `if (!mounted) return false` guard-true arm of every public
 *     op (mounted is a process-static that the other fuzzers set true on their
 *     first storage_init and never clear);
 *   - the storage_init mount-SUCCEEDS-first-try path (201 false) + the
 *     ensure_dirs dir-ALREADY-exists path (184 false / return true, 187) — the
 *     other fuzzers reset flash to 0xFF every run, so mount always fails and
 *     /keys never pre-exists;
 *   - storage_key_list's max_count > KEY_MAX_COUNT clamp (327) and its
 *     count == max_count truncation exit (337 false) — no firmware caller
 *     passes a max other than BACKUP_MAX_KEYS, and >256 keys can't exist;
 *   - storage_wifi_clear (no firmware caller at all).
 *
 * This harness drives storage.c's public API straight, on the same RAM-mapped
 * XIP window trick as fuzz_backup.c. A fixed scripted sequence (independent of
 * the fuzz bytes) exercises every host-reachable branch each run; the fuzz
 * bytes only vary key ids / names / wifi strings so mutation still explores the
 * record encoder + littlefs. Genuine flash-I/O error arms (program/erase/read
 * failure, format failure, opencfg failure, checksum bit-rot) are NOT reachable
 * here — the 256KB host RAM window never fails an I/O — and are documented as
 * HW-only residuals in the plan.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "hardware/flash.h"
#include "pico/stdlib.h"

#include "storage/storage.h"

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
    memset(flash_ptr(flash_offs), 0xFF, count);
}

int flash_safe_execute(void (*func)(void *), void *param, uint32_t timeout_ms) {
    (void)timeout_ms;
    func(param);
    return PICO_OK;
}

/* --- per-run reset -------------------------------------------------------- */

static void flash_ram_reset(void) {
    memset((void *)STORAGE_WINDOW_BASE, 0xFF, STORAGE_SIZE_BYTES);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    void *base = mmap((void *)STORAGE_WINDOW_BASE, STORAGE_SIZE_BYTES, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (base == MAP_FAILED || (uintptr_t)base != STORAGE_WINDOW_BASE) {
        perror("mmap XIP window");
        return -1;
    }

    if (!freopen("/dev/null", "w", stdout)) {
        perror("freopen stdout");
        return -1;
    }

    /* Pre-mount guard arm of every public op: `mounted` is still false here,
     * before any storage_init, so each op takes its `if (!mounted) return`. */
    key_record_t  k = {0};
    wifi_config_t w = {0};
    storage_key_exists(1);
    storage_key_get(1, &k);
    storage_key_save(&k);
    storage_key_delete(1);
    storage_key_list(&k, 1);
    storage_wifi_get(&w);
    storage_wifi_set(&w);
    storage_wifi_clear();
    return 0;
}

static key_record_t make_key(uint16_t id, const char *name, bool enabled, bool admin,
                             uint32_t created, uint8_t seed) {
    key_record_t k = {0};
    k.id           = id;
    k.is_enabled   = enabled;
    k.is_admin     = admin;
    k.created_at   = created;
    snprintf(k.name, sizeof k.name, "%s", name);
    for (int i = 0; i < KEY_SECRET_LEN; i++)
        k.secret[i] = (uint8_t)(seed + i);
    return k;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    flash_ram_reset();

    /* First init: mount fails on 0xFF flash -> format -> mount -> mkdir /keys. */
    if (!storage_init())
        return 0;

    /* Second init on the now-valid fs: mount SUCCEEDS first try (201 false) and
     * ensure_dirs finds /keys already present (184 false -> 187 return true). */
    if (!storage_init())
        return 0;

    /* Fuzz-byte-driven variety: ids/name kept in range, rest is scripted. */
    uint16_t id0 = (uint16_t)((size > 0 ? data[0] : 0x11) % KEY_MAX_COUNT);
    uint16_t id1 = (uint16_t)((size > 1 ? data[1] : 0x22) % KEY_MAX_COUNT);
    if (id1 == id0)
        id1 = (uint16_t)((id1 + 1) % KEY_MAX_COUNT);
    char   name[KEY_NAME_MAX];
    size_t nlen = size > sizeof(name) - 1 ? sizeof(name) - 1 : size;
    for (size_t i = 0; i < nlen; i++)
        name[i] = (data[i] >= 32 && data[i] < 127) ? (char)data[i] : '_';
    name[nlen] = '\0';

    key_record_t got;

    /* create then update the same id (both storage_key_save arms) */
    key_record_t k0 = make_key(id0, name, true, true, 1700000000u, 0x10);
    storage_key_save(&k0);
    storage_key_exists(id0);
    storage_key_get(id0, &got);
    key_record_t k0b = make_key(id0, "updated", false, false, 1700000123u, 0x20);
    storage_key_save(&k0b);
    storage_key_get(id0, &got);

    /* a second key so list has >1 entry */
    key_record_t k1 = make_key(id1, "second", true, false, 1700000200u, 0x30);
    storage_key_save(&k1);

    /* get / delete of a definitely-nonexistent id */
    storage_key_get(60000, &got);
    storage_key_delete(60000);

    /* list: truncation exit (max_count 1 with >1 keys, 337 false) ... */
    key_record_t list[KEY_MAX_COUNT];
    storage_key_list(list, 1);
    /* ... and the max_count > KEY_MAX_COUNT clamp (327). */
    storage_key_list(list, KEY_MAX_COUNT + 100);

    /* wifi: get-when-unset fails, then set/get/clear/clear-when-gone */
    wifi_config_t w = {0};
    storage_wifi_get(&w);
    snprintf(w.ssid, sizeof w.ssid, "ssid-%s", name);
    snprintf(w.password, sizeof w.password, "pw-%u", (unsigned)id0);
    storage_wifi_set(&w);
    storage_wifi_get(&w);
    storage_wifi_clear();
    storage_wifi_clear();

    /* tidy up so the fs never approaches capacity across replays */
    storage_key_delete(id0);
    storage_key_delete(id1);
    return 0;
}
