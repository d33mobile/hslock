/*
 * libFuzzer harness: the binary backup deserialiser, in isolation.
 *
 * cmd_import_keys() reaches backup_import() only after the console tokeniser,
 * a successful login, admin mode AND a base64 decode — so line-fuzzing almost
 * never gets a well-formed header past validation, and the write path
 * (checksum-verified magic/version/count, delete-existing, per-key
 * storage_key_save) stays unexercised. This harness feeds the fuzz bytes
 * STRAIGHT into backup_import(buf, size) on a fresh RAM-backed littlefs,
 * bypassing console + login + admin + base64 entirely. It is the strongest
 * test of the untrusted-blob parser: magic, version, key_count bound, the
 * truncation check, the CRC32, and the record-write loop.
 *
 * Storage is the same RAM-mapped XIP window trick as fuzz_console.c: the last
 * 256KB of the Pico's flash is mmap'd into host RAM at its true XIP address,
 * so storage.c / backup.c drive a genuine littlefs. State is reset per input.
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

#include "storage/backup.h"
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
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    flash_ram_reset();
    if (!storage_init())
        return 0; /* mount/format failure is not an input-driven bug */

    /* The whole point: the raw fuzz bytes ARE the untrusted backup blob. */
    backup_import(data, size);

    return 0;
}
