/*
 * Host harness: storage/storage.c + storage/backup.c on a RAM-backed LittleFS.
 *
 * The firmware's block device reads flash by dereferencing an absolute XIP
 * address (XIP_BASE + STORAGE_FLASH_OFFSET + ...) and writes it through
 * flash_range_program/erase (offset-from-flash-base). Both refer to the same
 * XIP window. We reproduce that window in host RAM with a single MAP_FIXED
 * anonymous mapping placed exactly at (void*)(XIP_BASE + STORAGE_FLASH_OFFSET):
 *   - storage.c's flash_read() dereferences (const void*)(uint32_t addr); the
 *     address lands inside the mapping, so reads hit our RAM.
 *   - the flash_range_program()/erase() shims below write the same window
 *     with NOR-flash semantics (erase -> 0xFF, program -> bitwise AND).
 *   - flash_safe_execute() simply calls the callback (no cores to pause).
 * This leaves the firmware source untouched: storage.c + backup.c + the real
 * littlefs lfs.c/lfs_util.c run natively against the RAM window, so their CRUD
 * / wifi / backup logic gets genuinely exercised.
 */

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

#include "hardware/flash.h" /* XIP_BASE, FLASH_SECTOR_SIZE */
#include "pico/stdlib.h"    /* PICO_FLASH_SIZE_BYTES, PICO_OK */

#include "backup.h"
#include "lfs_util.h" /* lfs_crc: matches backup.c's ciphertext checksum hint */
#include "storage.h"

/* backup.c pulls its salt/iv from get_rand_64(); the harness supplies a
 * deterministic definition (real hardware uses the ROSC RNG). Values need not
 * be cryptographically strong here - only distinct enough for GCM correctness. */
uint64_t get_rand_64(void) {
    static uint64_t s = 0x9E3779B97F4A7C15ull;
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}

/* Test passphrase used for every export/import roundtrip below. */
static const char *const PASS = "correct horse battery staple";

/* Per-key admin-confirm callbacks driving backup_import's is_admin backstop. */
static bool confirm_yes(uint16_t id, const char *name, void *ctx) {
    (void)id;
    (void)name;
    (void)ctx;
    return true;
}
static bool confirm_no(uint16_t id, const char *name, void *ctx) {
    (void)id;
    (void)name;
    (void)ctx;
    return false;
}

/* Forge a VALID v2 blob (correct PBKDF2 key + GCM tag) from arbitrary record
 * bytes - the model of a passphrase holder crafting a malicious payload. Mirrors
 * backup_export's crypto so backup_import accepts it, letting the tests inject a
 * chosen-secret admin record / a non-bool flag byte. Returns total blob length. */
static int forge_blob(const char *passphrase, const backup_key_t *recs, uint32_t count,
                      uint8_t *out) {
    backup_header_t hdr = {0};
    hdr.magic           = BACKUP_MAGIC;
    hdr.version         = BACKUP_VERSION;
    hdr.key_count       = count;
    for (int i = 0; i < BACKUP_SALT_LEN; i++)
        hdr.salt[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < BACKUP_IV_LEN; i++)
        hdr.iv[i] = (uint8_t)(0x50 + i);

    uint8_t key[BACKUP_KEY_LEN];
    assert(mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)passphrase,
                                         strlen(passphrase), hdr.salt, BACKUP_SALT_LEN,
                                         BACKUP_PBKDF2_ITERS, BACKUP_KEY_LEN, key) == 0);

    size_t   cipher_len = (size_t)count * sizeof(backup_key_t);
    uint8_t *ct         = out + sizeof(backup_header_t);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    assert(mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, BACKUP_KEY_LEN * 8) == 0);
    assert(mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, cipher_len, hdr.iv, BACKUP_IV_LEN,
                                     (const unsigned char *)&hdr, BACKUP_AAD_LEN,
                                     (const unsigned char *)recs, ct, BACKUP_TAG_LEN,
                                     hdr.tag) == 0);
    mbedtls_gcm_free(&gcm);

    hdr.checksum = lfs_crc(0xFFFFFFFF, ct, cipher_len);
    memcpy(out, &hdr, sizeof(hdr));
    return (int)(sizeof(backup_header_t) + cipher_len);
}

/* Must match storage.c's private layout constants. */
#define STORAGE_SIZE_BYTES   (256 * 1024)
#define STORAGE_FLASH_OFFSET (PICO_FLASH_SIZE_BYTES - STORAGE_SIZE_BYTES)
#define STORAGE_WINDOW_BASE  ((uintptr_t)(XIP_BASE + STORAGE_FLASH_OFFSET))

/* Absolute host pointer for a flash-base-relative offset. */
static uint8_t *flash_ptr(uint32_t flash_offs) {
    return (uint8_t *)(uintptr_t)(XIP_BASE + flash_offs);
}

/* --- RAM-backed flash primitives storage.c drives ------------------------- */

/* M13 witness: while a delete is in progress, record the longest run of zero
 * bytes seen in any single program buffer. storage_key_delete's zero-overwrite
 * commits the record's inline data as zeros, so a run >= KEY_SECRET_LEN proves
 * the secret field was scrubbed before removal; a plain lfs_remove (no fix)
 * only programs a small delete tag and never produces such a run. */
static volatile int    g_delete_active    = 0;
static volatile size_t g_del_max_zero_run = 0;

void flash_range_program(uint32_t flash_offs, const uint8_t *data, size_t count) {
    uint8_t *dst = flash_ptr(flash_offs);
    if (g_delete_active) {
        size_t run = 0;
        for (size_t i = 0; i < count; i++) {
            run = (data[i] == 0) ? run + 1 : 0;
            if (run > g_del_max_zero_run)
                g_del_max_zero_run = run;
        }
    }
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

/* Map the XIP storage window into host RAM at its true address. */
static void flash_ram_map(void) {
    void *base = mmap((void *)STORAGE_WINDOW_BASE, STORAGE_SIZE_BYTES, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (base == MAP_FAILED) {
        perror("mmap XIP window");
        assert(0);
    }
    assert((uintptr_t)base == STORAGE_WINDOW_BASE);
    memset(base, 0xFF, STORAGE_SIZE_BYTES); /* fresh, fully-erased flash */
}

/* Scan the whole storage window for `pat` — used to prove a secret is NOT
 * sitting in cleartext anywhere in flash. */
static bool window_contains(const uint8_t *pat, size_t n) {
    const uint8_t *w = flash_ptr(STORAGE_FLASH_OFFSET);
    for (size_t i = 0; i + n <= STORAGE_SIZE_BYTES; i++)
        if (memcmp(w + i, pat, n) == 0)
            return true;
    return false;
}

/* --- helpers -------------------------------------------------------------- */

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

static bool keys_equal(const key_record_t *a, const key_record_t *b) {
    return a->id == b->id && a->is_enabled == b->is_enabled && a->is_admin == b->is_admin &&
           a->created_at == b->created_at && memcmp(a->name, b->name, sizeof a->name) == 0 &&
           memcmp(a->secret, b->secret, sizeof a->secret) == 0;
}

int main(void) {
    /* --- before mount: every op must refuse -------------------------------- */
    key_record_t tmp;
    assert(storage_key_exists(1) == false);
    assert(storage_key_get(1, &tmp) == false);
    assert(storage_key_save(&tmp) == false);
    assert(storage_key_delete(1) == false);
    assert(storage_key_list(&tmp, 1) == -1);
    wifi_config_t wtmp;
    assert(storage_wifi_get(&wtmp) == false);
    assert(storage_wifi_set(&wtmp) == false);
    assert(storage_wifi_clear() == false);

    /* --- init on fresh 0xFF flash: mount fails; explicit format recovers --- */
    // storage_init() no longer auto-formats a corrupt/blank device (recovery is
    // now operator-driven via the "format-storage" console command). On fresh
    // 0xFF flash the mount fails and init reports failure; storage_format() is
    // the explicit recovery path that formats and re-mounts.
    flash_ram_map();
    assert(storage_is_mounted() == false);
    assert(storage_init() == false);
    assert(storage_is_mounted() == false);
    assert(storage_format() == true);
    assert(storage_is_mounted() == true);

    /* --- key save/get roundtrip ------------------------------------------- */
    key_record_t k1 = make_key(1, "alice", true, true, 1700000000u, 0x10);
    assert(storage_key_save(&k1) == true);
    assert(storage_key_exists(1) == true);
    assert(storage_key_exists(2) == false);

    key_record_t got;
    assert(storage_key_get(1, &got) == true);
    assert(got.is_checksum_valid == true);
    assert(keys_equal(&k1, &got));

    /* get of a nonexistent key fails */
    assert(storage_key_get(99, &got) == false);

    /* --- update existing key ---------------------------------------------- */
    key_record_t k1b = make_key(1, "alice2", false, false, 1700000123u, 0x20);
    assert(storage_key_save(&k1b) == true);
    assert(storage_key_get(1, &got) == true);
    assert(keys_equal(&k1b, &got));

    /* --- multiple keys + list --------------------------------------------- */
    key_record_t k2 = make_key(2, "bob", true, false, 1700000200u, 0x30);
    key_record_t k3 = make_key(3, "carol", true, true, 1700000300u, 0x40);
    assert(storage_key_save(&k2) == true);
    assert(storage_key_save(&k3) == true);

    key_record_t list[16];
    int          n = storage_key_list(list, 16);
    assert(n == 3);

    /* list truncation: max_count clamps to KEY_MAX_COUNT and to what fits */
    int n1 = storage_key_list(list, 1);
    assert(n1 == 1);
    int nbig = storage_key_list(list, KEY_MAX_COUNT + 100);
    assert(nbig == 3);

    /* --- out-of-range id rejected (L7) ------------------------------------ */
    /* storage_key_save must refuse ids above KEY_ID_MAX so an unmanageable
     * (get/delete/unset-admin gate on id > KEY_ID_MAX) key can never persist. */
    key_record_t kbad = make_key(KEY_ID_MAX + 1, "evil", true, true, 1700000400u, 0x50);
    assert(storage_key_save(&kbad) == false);
    assert(storage_key_exists(KEY_ID_MAX + 1) == false);
    assert(storage_key_list(list, 16) == 3); /* still only the 3 valid keys */

    /* --- delete + get-after-delete ---------------------------------------- */
    assert(storage_key_delete(2) == true);
    assert(storage_key_exists(2) == false);
    assert(storage_key_get(2, &got) == false);
    assert(storage_key_delete(2) == false); /* already gone */
    assert(storage_key_list(list, 16) == 2);

    /* --- wifi set/get/clear ----------------------------------------------- */
    wifi_config_t wcfg = {0};
    snprintf(wcfg.ssid, sizeof wcfg.ssid, "hackerspace");
    snprintf(wcfg.password, sizeof wcfg.password, "s3cr3t-pass");
    assert(storage_wifi_set(&wcfg) == true);

    wifi_config_t wgot = {0};
    assert(storage_wifi_get(&wgot) == true);
    assert(strcmp(wgot.ssid, wcfg.ssid) == 0);
    assert(strcmp(wgot.password, wcfg.password) == 0);

    /* L8: storage_wifi_get must NUL-terminate both fields on read, even when the
     * flash bytes carry no terminator. Plant a config whose ssid/password fill
     * the whole field with non-NUL bytes (storage_wifi_set is a raw writer that
     * does NOT zero-pad, unlike cmd_set_wifi), then get: the last byte of each
     * field must be forced to '\0' so downstream printf("%s")/connect can't
     * over-read the password into the SSID. */
    wifi_config_t wfull;
    memset(wfull.ssid, 'S', sizeof wfull.ssid);
    memset(wfull.password, 'P', sizeof wfull.password);
    assert(storage_wifi_set(&wfull) == true);
    wifi_config_t wterm;
    memset(&wterm, 'X', sizeof wterm); /* poison so we see the terminator set */
    assert(storage_wifi_get(&wterm) == true);
    assert(wterm.ssid[WIFI_SSID_MAX - 1] == '\0');
    assert(wterm.password[WIFI_PASSWORD_MAX - 1] == '\0');
    assert(strlen(wterm.ssid) == WIFI_SSID_MAX - 1);         /* no over-read */
    assert(strlen(wterm.password) == WIFI_PASSWORD_MAX - 1); /* no over-read */

    assert(storage_wifi_clear() == true);
    assert(storage_wifi_get(&wgot) == false); /* gone */
    assert(storage_wifi_clear() == false);    /* already gone */

    /* --- H6: encrypt-then-MAC backup export -> import roundtrip ----------- */
    /* Current store holds id=1 (non-admin) and id=3 (ADMIN). */
    static uint8_t backup[sizeof(backup_header_t) + BACKUP_MAX_KEYS * sizeof(backup_key_t)];
    int            blen = backup_export(backup, sizeof backup, PASS);
    assert(blen > 0);
    assert((size_t)blen == sizeof(backup_header_t) + 2 * sizeof(backup_key_t));

    /* the header is cleartext + well-formed; the payload is ciphertext, so it
     * must NOT contain the raw seeds in the clear. */
    {
        const backup_header_t *h = (const backup_header_t *)backup;
        assert(h->magic == BACKUP_MAGIC && h->version == BACKUP_VERSION && h->key_count == 2);
        /* k3's secret starts at byte 0x40 (make_key seed); it must not appear
         * verbatim anywhere in the ciphertext. */
        uint8_t needle[KEY_SECRET_LEN];
        for (int i = 0; i < KEY_SECRET_LEN; i++)
            needle[i] = (uint8_t)(0x40 + i);
        bool leaked = false;
        for (size_t off = sizeof(backup_header_t); off + KEY_SECRET_LEN <= (size_t)blen; off++)
            if (memcmp(backup + off, needle, KEY_SECRET_LEN) == 0)
                leaked = true;
        assert(!leaked);
    }

    /* buffer too small -> -1; missing passphrase -> -1 */
    assert(backup_export(backup, sizeof(backup_header_t), PASS) == -1);
    assert(backup_export(backup, sizeof backup, NULL) == -1);
    assert(backup_export(backup, sizeof backup, "") == -1);
    /* re-export a good blob for the tests below */
    blen = backup_export(backup, sizeof backup, PASS);
    assert(blen > 0);

    /* Snapshot expected keys, then wipe the store. */
    key_record_t expect[8];
    int          expect_n = storage_key_list(expect, 8);
    assert(expect_n == 2);
    for (int i = 0; i < expect_n; i++)
        assert(storage_key_delete(expect[i].id) == true);
    assert(storage_key_list(list, 16) == 0);

    /* Import with the right passphrase restores everything (the admin key id=3
     * is confirmed via confirm_yes). */
    assert(backup_import(backup, (size_t)blen, PASS, confirm_yes, NULL) == true);
    int restored_n = storage_key_list(list, 16);
    assert(restored_n == expect_n);
    for (int i = 0; i < expect_n; i++) {
        key_record_t r;
        assert(storage_key_get(expect[i].id, &r) == true);
        assert(keys_equal(&expect[i], &r));
    }

    /* --- wrong passphrase -> rejected, store untouched -------------------- */
    assert(backup_import(backup, (size_t)blen, "wrong passphrase", confirm_yes, NULL) == false);
    assert(backup_import(backup, (size_t)blen, NULL, confirm_yes, NULL) == false);
    assert(storage_key_list(list, 16) == expect_n);

    /* --- malformed / tampered blobs all rejected before any parse --------- */
    /* too small */
    assert(backup_import(backup, sizeof(backup_header_t) - 1, PASS, confirm_yes, NULL) == false);
    /* bad magic (pre-decrypt header check) */
    {
        uint8_t bad[sizeof backup];
        memcpy(bad, backup, (size_t)blen);
        ((backup_header_t *)bad)->magic = 0xDEADBEEFu;
        assert(backup_import(bad, (size_t)blen, PASS, confirm_yes, NULL) == false);
    }
    /* bad version */
    {
        uint8_t bad[sizeof backup];
        memcpy(bad, backup, (size_t)blen);
        ((backup_header_t *)bad)->version = BACKUP_VERSION + 1;
        assert(backup_import(bad, (size_t)blen, PASS, confirm_yes, NULL) == false);
    }
    /* key_count too large */
    {
        uint8_t bad[sizeof backup];
        memcpy(bad, backup, (size_t)blen);
        ((backup_header_t *)bad)->key_count = KEY_MAX_COUNT + 1;
        assert(backup_import(bad, (size_t)blen, PASS, confirm_yes, NULL) == false);
    }
    /* truncated body (header claims more keys than bytes provided) */
    {
        uint8_t bad[sizeof backup];
        memcpy(bad, backup, (size_t)blen);
        ((backup_header_t *)bad)->key_count = 200;
        assert(backup_import(bad, (size_t)blen, PASS, confirm_yes, NULL) == false);
    }
    /* GCM tag tampered (CRC still valid) -> MAC failure */
    {
        uint8_t bad[sizeof backup];
        memcpy(bad, backup, (size_t)blen);
        ((backup_header_t *)bad)->tag[0] ^= 0xFF;
        assert(backup_import(bad, (size_t)blen, PASS, confirm_yes, NULL) == false);
    }
    /* ciphertext byte flipped -> MAC failure */
    {
        uint8_t bad[sizeof backup];
        memcpy(bad, backup, (size_t)blen);
        bad[sizeof(backup_header_t)] ^= 0xFF;
        assert(backup_import(bad, (size_t)blen, PASS, confirm_yes, NULL) == false);
    }
    /* AAD tampered: key_count altered within range (2 -> 1) -> MAC failure */
    {
        uint8_t bad[sizeof backup];
        memcpy(bad, backup, (size_t)blen);
        ((backup_header_t *)bad)->key_count = 1;
        assert(backup_import(bad, (size_t)blen, PASS, confirm_yes, NULL) == false);
    }

    /* The store still holds the good import after all rejected attempts. */
    assert(storage_key_list(list, 16) == expect_n);

    /* --- M3: empty / admin-less imports rejected before wiping keys ------- */
    /* Regression for the fail-open wipe. A key_count==0 blob (refused before
     * any crypto), and a well-formed AUTHENTICATED blob carrying no enabled+admin
     * record, both let the unconditional delete loop strand the device with no
     * admin key (any_admin == false -> cmd_login hands out admin to any
     * credentials). Both must be refused BEFORE any key is touched; a blob with
     * >= 1 enabled admin still imports. Under H6 the payload is GCM-encrypted, so
     * the non-empty cases are built with forge_blob (a valid PBKDF2 key + tag). */
    assert(storage_key_list(list, 16) == expect_n); /* keys 1 & 3 present */

    /* (a) zero-key blob: refused before crypto, existing keys untouched. */
    {
        uint8_t         empty[sizeof(backup_header_t)];
        backup_header_t eh = {0};
        eh.magic           = BACKUP_MAGIC;
        eh.version         = BACKUP_VERSION;
        eh.key_count       = 0;
        memcpy(empty, &eh, sizeof eh);
        assert(backup_import(empty, sizeof empty, PASS, confirm_yes, NULL) == false);
        assert(storage_key_list(list, 16) == expect_n);
    }

    /* (b) one enabled-but-non-admin key: authenticated, yet refused before the
     * delete loop because the payload has no enabled admin. */
    {
        backup_key_t bk = {0};
        bk.id           = 50;
        snprintf(bk.name, sizeof bk.name, "user");
        memset(bk.secret, 0x11, sizeof bk.secret);
        bk.is_enabled = true;
        bk.is_admin   = false;
        bk.created_at = 1700009000u;

        static uint8_t blob[sizeof(backup_header_t) + sizeof(backup_key_t)];
        int            n = forge_blob(PASS, &bk, 1, blob);
        assert(backup_import(blob, (size_t)n, PASS, confirm_yes, NULL) == false);
        assert(storage_key_list(list, 16) == expect_n); /* untouched */

        /* (c) same record, now enabled + admin -> import succeeds, replaces store. */
        bk.is_admin = true;
        n           = forge_blob(PASS, &bk, 1, blob);
        assert(backup_import(blob, (size_t)n, PASS, confirm_yes, NULL) == true);
        assert(storage_key_list(list, 16) == 1);
        key_record_t g;
        assert(storage_key_get(50, &g) == true);
        assert(g.is_admin == true && g.is_enabled == true);
        assert(storage_key_delete(50) == true);
    }
    assert(storage_key_list(list, 16) == 0); /* store empty for the UBSan block */

    /* --- an exported empty store is itself a zero-key blob whose import is
     * refused by M3 (not a silent wipe of the target device). H6 pre-dated M3
     * and expected this to roundtrip; M3 makes the empty import fail-closed. */
    {
        int elen = backup_export(backup, sizeof backup, PASS);
        assert((size_t)elen == sizeof(backup_header_t));
        assert(backup_import(backup, (size_t)elen, PASS, confirm_yes, NULL) == false);
        assert(storage_key_list(list, 16) == 0);
    }

    /* --- is_admin backstop: an authenticated admin record still needs per-key
     * operator confirmation. Forge a VALID blob (correct passphrase, real GCM
     * tag) carrying a chosen-secret admin record - the exact H6 escalation. --- */
    {
        backup_key_t evil = {0};
        evil.id           = 7;
        snprintf(evil.name, sizeof evil.name, "pwned");
        for (int i = 0; i < KEY_SECRET_LEN; i++)
            evil.secret[i] = (uint8_t)i;
        evil.is_enabled = true;
        evil.is_admin   = true;
        evil.created_at = 42;

        uint8_t craft[sizeof backup];
        int     clen = forge_blob(PASS, &evil, 1, craft);

        /* denied by the operator -> rejected, store untouched */
        assert(backup_import(craft, (size_t)clen, PASS, confirm_no, NULL) == false);
        assert(storage_key_list(list, 16) == 0);
        /* NULL callback denies all admin records */
        assert(backup_import(craft, (size_t)clen, PASS, NULL, NULL) == false);
        assert(storage_key_list(list, 16) == 0);
        /* confirmed -> imported as admin */
        assert(backup_import(craft, (size_t)clen, PASS, confirm_yes, NULL) == true);
        key_record_t g;
        assert(storage_key_get(7, &g) == true);
        assert(g.is_admin == true);
        assert(storage_key_delete(7) == true);
    }

    /* --- UBSan regression: non-bool flag byte in an authenticated payload --- */
    /* to_key_record() must not load is_enabled/is_admin straight into a `bool`:
     * a passphrase holder can forge a validly-encrypted record with any byte in
     * those fields, and loading a bool whose representation is not 0/1 is UB
     * (caught by -fsanitize=undefined). Forge a valid 1-key blob with a non-bool
     * admin byte; import (confirmed) must succeed and read back canonicalised. */
    {
        backup_key_t bk = {0};
        bk.id           = 9;
        snprintf(bk.name, sizeof bk.name, "ub");
        for (int i = 0; i < KEY_SECRET_LEN; i++)
            bk.secret[i] = (uint8_t)(0x40 + i);
        *(uint8_t *)&bk.is_enabled = 1;
        *(uint8_t *)&bk.is_admin   = 67; /* non-bool byte */
        bk.created_at              = 1234;

        uint8_t craft[sizeof backup];
        int     clen = forge_blob(PASS, &bk, 1, craft);

        assert(backup_import(craft, (size_t)clen, PASS, confirm_yes, NULL) == true);
        key_record_t g;
        assert(storage_key_get(9, &g) == true);
        assert(g.is_admin == true);   /* canonicalised: exactly 1, not 67 */
        assert(g.is_enabled == true); /* untouched flag survives */
        assert(storage_key_delete(9) == true);
    }

    /* --- M13: delete-key zero-overwrites the record before unlinking ------- */
    /* storage_key_delete must overwrite the record's bytes with zeros and
     * lfs_file_sync BEFORE lfs_remove, so the NEWEST inline value of the revoked
     * key is zeros, not its secret.
     *
     * Note on what CANNOT be asserted: littlefs is an append-only log. The
     * zero-overwrite commits a NEW inline copy; the ORIGINAL secret bytes stay
     * physically in the metadata block pair until it is compacted and the stale
     * sector erased — so a raw window scan still finds the plaintext seed right
     * after delete (verified: window_contains stays true). Only storage_format()
     * guarantees erasure. Asserting the seed is physically gone would therefore
     * be false; we instead witness the fix directly: during the delete, the
     * flash-program shim records the longest zero run it programs, and the
     * zero-overwrite of the KEY_SECRET_LEN-byte secret field (in fact the whole
     * record) produces a run >= KEY_SECRET_LEN. A plain lfs_remove (no fix) only
     * programs a small delete tag and never does (measured: 2 bytes vs 48). */
    {
        uint8_t del_seed[KEY_SECRET_LEN];
        for (int i = 0; i < KEY_SECRET_LEN; i++)
            del_seed[i] = (uint8_t)(0x3C ^ (i * 5 + 1));
        key_record_t vk = make_key(42, "victim", true, false, 1700111111u, 0);
        memcpy(vk.secret, del_seed, sizeof del_seed);
        assert(storage_key_save(&vk) == true);
        assert(window_contains(del_seed, sizeof del_seed) == true); /* seed on flash */

        g_del_max_zero_run = 0;
        g_delete_active    = 1;
        assert(storage_key_delete(42) == true);
        g_delete_active = 0;

        /* the record's inline data was scrubbed to zeros before removal */
        assert(g_del_max_zero_run >= (size_t)KEY_SECRET_LEN);
        /* the current filesystem value is gone (remove committed) */
        assert(storage_key_exists(42) == false);
        assert(storage_key_get(42, &tmp) == false);
    }

    printf("storage OK\n");
    return 0;
}
