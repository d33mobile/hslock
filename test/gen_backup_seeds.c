/*
 * Generator for the curated backup_import() seed corpus.
 *
 * backup_import() gates an untrusted blob through a fixed sequence of
 * validation branches (size, magic, version, key_count bound, truncation,
 * whole-backup CRC) before the delete-existing / per-key write loop. libFuzzer
 * mutating random bytes almost never assembles a header that passes each gate,
 * so the deep branches stay unexercised. This host helper hand-crafts ONE blob
 * per branch and, crucially, computes the valid cases' CRC with the firmware's
 * OWN checksum routine (lfs_crc over the packed backup_key_t records, seed
 * 0xFFFFFFFF, no final xor -- identical to storage/backup.c:backup_checksum),
 * so the "valid" blobs genuinely pass validation and drive the write path.
 *
 * Build + run via `make -C test gen-backup-seeds`; it writes the blobs into
 * fuzz_backup_corpus/ (argv[1], default that dir). The emitted files are the
 * committed seed corpus -- this .c is their regenerable source of truth.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lfs_util.h"        /* lfs_crc -- the firmware's CRC-32 */
#include "storage/backup.h"  /* backup_header_t, backup_key_t, magic/version */
#include "storage/storage.h" /* KEY_MAX_COUNT, KEY_NAME_MAX, KEY_SECRET_LEN */

/* Mirror storage/backup.c:backup_checksum EXACTLY (seed 0xFFFFFFFF, no xorout). */
static uint32_t backup_checksum(const backup_key_t *keys, uint32_t count) {
    uint32_t crc = 0xFFFFFFFF;
    crc          = lfs_crc(crc, keys, count * sizeof(backup_key_t));
    return crc;
}

static const char *g_dir;

static void emit(const char *name, const void *data, size_t len) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror(path);
        exit(1);
    }
    if (len && fwrite(data, 1, len, f) != len) {
        perror("fwrite");
        exit(1);
    }
    fclose(f);
    printf("  wrote %-18s %4zu bytes\n", name, len);
}

/* Fill one backup_key_t record with recognisable, distinct content. */
static backup_key_t make_key(uint16_t id, const char *name, uint8_t secret_base, int is_enabled,
                             int is_admin, uint32_t created_at) {
    backup_key_t k;
    memset(&k, 0, sizeof(k));
    k.id = id;
    strncpy(k.name, name, sizeof(k.name)); /* zero-padded, may be non-terminated at max */
    for (int i = 0; i < KEY_SECRET_LEN; i++)
        k.secret[i] = (uint8_t)(secret_base + i);
    k.is_enabled = (bool)is_enabled;
    k.is_admin   = (bool)is_admin;
    k.created_at = created_at;
    return k;
}

/* Serialise header + keys into buf, filling in the correct CRC. Returns length. */
static size_t build(uint8_t *buf, uint32_t magic, uint32_t version, uint32_t key_count,
                    const backup_key_t *keys, uint32_t nkeys, int corrupt_crc) {
    backup_header_t hdr;
    hdr.magic     = magic;
    hdr.version   = version;
    hdr.key_count = key_count;
    hdr.checksum  = backup_checksum(keys, nkeys);
    if (corrupt_crc)
        hdr.checksum ^= 0xA5A5A5A5u; /* deliberately wrong */
    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + sizeof(hdr), keys, nkeys * sizeof(backup_key_t));
    return sizeof(hdr) + nkeys * sizeof(backup_key_t);
}

int main(int argc, char **argv) {
    g_dir = (argc > 1) ? argv[1] : "fuzz_backup_corpus";

    /* Big enough for KEY_MAX_COUNT records. */
    static uint8_t buf[sizeof(backup_header_t) + (KEY_MAX_COUNT + 4) * sizeof(backup_key_t)];
    size_t         n;

    /* --- pre-CRC validation gates (empty key set, so CRC is that of 0 bytes) --- */

    /* 1. empty: size < header -> "buffer too small" (backup.c:90 true). */
    emit("empty", buf, 0);

    /* 2. short_header: 8 bytes, still < sizeof(header)=16 -> same 90 branch, nonzero. */
    n = build(buf, BACKUP_MAGIC, BACKUP_VERSION, 0, NULL, 0, 0);
    emit("short_header", buf, 8);

    /* 3. bad_magic: full header, wrong magic -> "bad magic" (backup.c:97 true). */
    n = build(buf, 0xDEADBEEFu, BACKUP_VERSION, 0, NULL, 0, 0);
    emit("bad_magic", buf, n);

    /* 4. bad_version: magic OK, version 2 -> "unsupported version" (backup.c:101 true). */
    n = build(buf, BACKUP_MAGIC, BACKUP_VERSION + 1, 0, NULL, 0, 0);
    emit("bad_version", buf, n);

    /* 5. count_over_max: key_count = KEY_MAX_COUNT+1 -> "too many keys" (backup.c:106
     *    true). Checked before truncation, so a bare header is enough. */
    n = build(buf, BACKUP_MAGIC, BACKUP_VERSION, KEY_MAX_COUNT + 1, NULL, 0, 0);
    emit("count_over_max", buf, n);

    /* 6. body_truncated: claims 3 keys but supplies only the header -> size < expected
     *    "truncated data" (backup.c:112 true). */
    n = build(buf, BACKUP_MAGIC, BACKUP_VERSION, 3, NULL, 0, 0);
    emit("body_truncated", buf, sizeof(backup_header_t));

    /* --- CRC gate --- */

    /* 7. crc_mismatch: one full key record but a deliberately wrong checksum ->
     *    "backup checksum mismatch" (backup.c:121 true). */
    {
        backup_key_t k = make_key(7, "crc", 0x10, 1, 0, 0x11223344u);
        n              = build(buf, BACKUP_MAGIC, BACKUP_VERSION, 1, &k, 1, /*corrupt_crc=*/1);
        emit("crc_mismatch", buf, n);
    }

    /* --- valid blobs that reach the write loop (backup.c:134) + to_key_record --- */

    /* 8. valid_0keys: valid header, zero keys -> success, write loop skipped. */
    n = build(buf, BACKUP_MAGIC, BACKUP_VERSION, 0, NULL, 0, 0);
    emit("valid_0keys", buf, n);

    /* 9. valid_1key: single enabled admin key -> success + to_key_record once. */
    {
        backup_key_t k = make_key(1, "solo", 0x20, /*enabled=*/1, /*admin=*/1, 0x50000001u);
        n              = build(buf, BACKUP_MAGIC, BACKUP_VERSION, 1, &k, 1, 0);
        emit("valid_1key", buf, n);
    }

    /* 10. valid_flags: four keys spanning every (is_enabled, is_admin) combination,
     *     so to_key_record copies both booleans in both states. */
    {
        backup_key_t ks[4];
        ks[0] = make_key(10, "off_user", 0x30, 0, 0, 0x60000000u);
        ks[1] = make_key(11, "off_admin", 0x40, 0, 1, 0x60000001u);
        ks[2] = make_key(12, "on_user", 0x50, 1, 0, 0x60000002u);
        ks[3] = make_key(13, "on_admin", 0x60, 1, 1, 0x60000003u);
        n     = build(buf, BACKUP_MAGIC, BACKUP_VERSION, 4, ks, 4, 0);
        emit("valid_flags", buf, n);
    }

    /* 11. valid_countmax: key_count == KEY_MAX_COUNT (the upper boundary that PASSES
     *     the >MAX check) with a correct CRC -> a full 256-iteration write loop that
     *     SUCCEEDS. littlefs stores the ~60-byte records inline, so all 256 keys fit
     *     in the 256KB volume (verified: no storage_key_save failure); this is the
     *     max-capacity round-trip regression. The write-loop failure branch
     *     (backup.c:136) is therefore NOT reachable from any accepted blob -- it
     *     needs a genuine flash/storage I/O error, not attacker-controlled bytes. */
    {
        static backup_key_t ks[KEY_MAX_COUNT];
        for (int i = 0; i < KEY_MAX_COUNT; i++) {
            char nm[KEY_NAME_MAX];
            snprintf(nm, sizeof(nm), "k%03d", i);
            ks[i] = make_key((uint16_t)i, nm, (uint8_t)i, i & 1, (i & 2) >> 1,
                             0x70000000u + (uint32_t)i);
        }
        n = build(buf, BACKUP_MAGIC, BACKUP_VERSION, KEY_MAX_COUNT, ks, KEY_MAX_COUNT, 0);
        emit("valid_countmax", buf, n);
    }

    printf("gen_backup_seeds: wrote curated corpus into %s\n", g_dir);
    return 0;
}
