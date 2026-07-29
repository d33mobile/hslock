#include "backup.h"
#include "storage.h"
#include "shared/wipe.h"
#include "lfs_util.h"
#include "pico/rand.h"

#include <mbedtls/version.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/md.h>

#include <stddef.h>
#include <string.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// Scratch plaintext buffer (the serialised records, in the clear). Kept in BSS
// rather than on the stack: BACKUP_MAX_KEYS records is several KiB and this is
// core-0-only console work.
// ---------------------------------------------------------------------------

#define BACKUP_PLAIN_MAX (BACKUP_MAX_KEYS * sizeof(backup_key_t))

static uint8_t plain_scratch[BACKUP_PLAIN_MAX];

// ---------------------------------------------------------------------------
// Checksum helper (paste-corruption hint over the ciphertext only)
// ---------------------------------------------------------------------------

static uint32_t backup_checksum(const uint8_t *ciphertext, size_t len) {
    return lfs_crc(0xFFFFFFFF, ciphertext, len);
}

// ---------------------------------------------------------------------------
// Fill n random bytes from the platform CSPRNG.
// ---------------------------------------------------------------------------

static void fill_random(uint8_t *out, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint64_t r     = get_rand_64();
        size_t   chunk = (n - i < sizeof(r)) ? (n - i) : sizeof(r);
        memcpy(out + i, &r, chunk);
        i += chunk;
    }
}

// ---------------------------------------------------------------------------
// Derive the 32-byte AEAD key from passphrase + salt (PBKDF2-HMAC-SHA256).
// Returns 0 on success.
// ---------------------------------------------------------------------------

static int derive_key(const char *passphrase, const uint8_t *salt, uint8_t key[BACKUP_KEY_LEN]) {
    if (passphrase == NULL || passphrase[0] == '\0')
        return -1;
    // PBKDF2-HMAC-SHA256. mbedtls_pkcs5_pbkdf2_hmac_ext exists only in 3.6+ (the
    // context-based form it replaces is deprecated there); pre-3.6 (some CI hosts
    // / pico-sdk snapshots) has only the context form. Pick per version so the
    // build is warning-clean on both.
#if defined(MBEDTLS_VERSION_NUMBER) && MBEDTLS_VERSION_NUMBER >= 0x03060000
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)passphrase,
                                         strlen(passphrase), salt, BACKUP_SALT_LEN,
                                         BACKUP_PBKDF2_ITERS, BACKUP_KEY_LEN, key);
#else
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL)
        return -1;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int rc = mbedtls_md_setup(&ctx, md, 1 /* HMAC */);
    if (rc == 0)
        rc = mbedtls_pkcs5_pbkdf2_hmac(&ctx, (const unsigned char *)passphrase, strlen(passphrase),
                                       salt, BACKUP_SALT_LEN, BACKUP_PBKDF2_ITERS, BACKUP_KEY_LEN,
                                       key);
    mbedtls_md_free(&ctx);
    return rc;
#endif
}

// ---------------------------------------------------------------------------
// logic model → backup key
// ---------------------------------------------------------------------------

// Fill via an out-pointer rather than returning by value so the secret never
// lives in a transient helper-frame copy that would outlast this call.
static void to_backup_key(const key_record_t *k, backup_key_t *b) {
    b->id         = k->id;
    b->is_enabled = k->is_enabled;
    b->is_admin   = k->is_admin;
    b->created_at = k->created_at;
    memcpy(b->name, k->name, sizeof(b->name));
    memcpy(b->secret, k->secret, sizeof(b->secret));
}

// ---------------------------------------------------------------------------
// backup key → logic model
// ---------------------------------------------------------------------------

static void to_key_record(const backup_key_t *b, key_record_t *k) {
    k->id = b->id;
    // The decrypted payload is still untrusted structurally (a passphrase holder
    // may craft arbitrary bytes): read the flag bytes raw and canonicalise.
    // Loading a `bool` whose object representation is not 0/1 is UB.
    uint8_t enabled_raw, admin_raw;
    memcpy(&enabled_raw, &b->is_enabled, sizeof(enabled_raw));
    memcpy(&admin_raw, &b->is_admin, sizeof(admin_raw));
    k->is_enabled        = (enabled_raw != 0);
    k->is_admin          = (admin_raw != 0);
    k->created_at        = b->created_at;
    k->is_checksum_valid = true;
    memcpy(k->name, b->name, sizeof(k->name));
    k->name[KEY_NAME_MAX - 1] = '\0';
    memcpy(k->secret, b->secret, sizeof(k->secret));
}

// ---------------------------------------------------------------------------
// Export: serialise, encrypt-then-MAC (AES-256-GCM), emit v2 blob.
// ---------------------------------------------------------------------------

int backup_export(uint8_t *buf, size_t buf_size, const char *passphrase) {
    static key_record_t records[BACKUP_MAX_KEYS];
    int                 count = storage_key_list(records, BACKUP_MAX_KEYS);
    if (count < 0)
        return -1;

    // Serialise the valid records into the plaintext scratch.
    backup_key_t *plain              = (backup_key_t *)plain_scratch;
    int           exported_key_count = 0;
    for (int i = 0; i < count; i++) {
        if (!records[i].is_checksum_valid) {
            printf("[backup] export: key %u has invalid checksum, skipping\r\n", records[i].id);
            continue;
        }
        to_backup_key(&records[i], &plain[exported_key_count++]);
    }

    // The resident copy of the key database (seeds included) is now serialised
    // into the scratch; scrub it from BSS. `plain_scratch` is scrubbed below.
    secure_wipe(records, sizeof(records));

    size_t cipher_len = (size_t)exported_key_count * sizeof(backup_key_t);
    size_t needed     = sizeof(backup_header_t) + cipher_len;
    if (buf_size < needed) {
        secure_wipe(plain_scratch, sizeof(plain_scratch));
        return -1;
    }

    backup_header_t hdr = {
        .magic     = BACKUP_MAGIC,
        .version   = BACKUP_VERSION,
        .key_count = (uint32_t)exported_key_count,
    };
    fill_random(hdr.salt, BACKUP_SALT_LEN);
    fill_random(hdr.iv, BACKUP_IV_LEN);

    uint8_t key[BACKUP_KEY_LEN];
    if (derive_key(passphrase, hdr.salt, key) != 0) {
        secure_wipe(plain_scratch, sizeof(plain_scratch));
        return -1;
    }

    uint8_t *ciphertext = buf + sizeof(backup_header_t);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, BACKUP_KEY_LEN * 8);
    if (rc == 0) {
        // AAD = header prefix up to (excluding) the tag; authenticates
        // magic/version/key_count/salt/iv so none can be altered undetected.
        rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, cipher_len, hdr.iv, BACKUP_IV_LEN,
                                       (const unsigned char *)&hdr, BACKUP_AAD_LEN, plain_scratch,
                                       ciphertext, BACKUP_TAG_LEN, hdr.tag);
    }
    mbedtls_gcm_free(&gcm);

    // Scrub key material and the cleartext scratch.
    secure_wipe(key, sizeof(key));
    secure_wipe(plain_scratch, sizeof(plain_scratch));

    if (rc != 0) {
        printf("[backup] export: encryption failed (%d)\r\n", rc);
        return -1;
    }

    hdr.checksum = backup_checksum(ciphertext, cipher_len);
    memcpy(buf, &hdr, sizeof(hdr));

    return (int)needed;
}

// ---------------------------------------------------------------------------
// Import: authenticate, decrypt, THEN parse. Never touch storage until the tag
// verifies and every admin record is operator-confirmed.
// ---------------------------------------------------------------------------

bool backup_import(const uint8_t *buf, size_t size, const char *passphrase,
                   backup_admin_confirm_fn confirm_admin, void *confirm_ctx) {
    if (size < sizeof(backup_header_t)) {
        printf("[backup] import: buffer too small\r\n");
        return false;
    }

    backup_header_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));

    if (hdr.magic != BACKUP_MAGIC) {
        printf("[backup] import: bad magic\r\n");
        return false;
    }
    if (hdr.version != BACKUP_VERSION) {
        printf("[backup] import: unsupported version %u\r\n", hdr.version);
        return false;
    }
    if (hdr.key_count > BACKUP_MAX_KEYS) {
        printf("[backup] import: too many keys (%u > %d)\r\n", hdr.key_count, BACKUP_MAX_KEYS);
        return false;
    }

    // M3: an empty backup (key_count == 0) would clear every gate yet the delete
    // loop below runs unconditionally - importing it would wipe every key and
    // strand the device with no admin (any_admin == false -> fail-open bootstrap
    // login). Refuse before touching storage or crypto.
    if (hdr.key_count < 1) {
        printf("[backup] import: empty backup refused\r\n");
        return false;
    }

    size_t cipher_len = (size_t)hdr.key_count * sizeof(backup_key_t);
    if (size < sizeof(backup_header_t) + cipher_len) {
        printf("[backup] import: truncated data\r\n");
        return false;
    }

    const uint8_t *ciphertext = buf + sizeof(backup_header_t);

    // CRC is only a paste-corruption hint; the GCM tag is the trust boundary.
    if (backup_checksum(ciphertext, cipher_len) != hdr.checksum)
        printf("[backup] import: checksum mismatch (possible paste corruption)\r\n");

    uint8_t key[BACKUP_KEY_LEN];
    if (derive_key(passphrase, hdr.salt, key) != 0) {
        printf("[backup] import: missing/invalid passphrase\r\n");
        return false;
    }

    backup_key_t *plain = (backup_key_t *)plain_scratch;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, BACKUP_KEY_LEN * 8);
    if (rc == 0) {
        rc = mbedtls_gcm_auth_decrypt(&gcm, cipher_len, hdr.iv, BACKUP_IV_LEN,
                                      (const unsigned char *)&hdr, BACKUP_AAD_LEN, hdr.tag,
                                      BACKUP_TAG_LEN, ciphertext, plain_scratch);
    }
    mbedtls_gcm_free(&gcm);
    secure_wipe(key, sizeof(key));

    // MAC failure (tamper / wrong passphrase) -> reject BEFORE any parsing.
    if (rc != 0) {
        secure_wipe(plain_scratch, sizeof(plain_scratch));
        printf("[backup] import: authentication failed - rejected\r\n");
        return false;
    }

    // Payload is now authentic. Validate structure before touching storage.
    for (uint32_t i = 0; i < hdr.key_count; i++) {
        bool terminated = false;
        for (int j = 0; j < KEY_NAME_MAX; j++) {
            if (plain[i].name[j] == '\0') {
                terminated = true;
                break;
            }
        }
        if (!terminated) {
            printf("[backup] import: key %u has unterminated name\r\n", plain[i].id);
            secure_wipe(plain_scratch, sizeof(plain_scratch));
            return false;
        }
        if (plain[i].id > KEY_ID_MAX) {
            printf("[backup] import: key %u has invalid id (max %u)\r\n", plain[i].id, KEY_ID_MAX);
            secure_wipe(plain_scratch, sizeof(plain_scratch));
            return false;
        }
    }

    // M3: require at least one enabled + admin record before wiping anything.
    // cmd_login treats a store with no enabled admin key (any_admin == false) as
    // unprovisioned and hands out admin access to any credentials. An import that
    // leaves the device admin-less therefore opens a permanent credential-free
    // backdoor. Scan the authenticated+validated records - canonicalising the
    // untrusted flag bytes the same way to_key_record() does - and reject,
    // touching nothing, if none qualifies.
    bool has_admin = false;
    for (uint32_t i = 0; i < hdr.key_count; i++) {
        uint8_t enabled_raw, admin_raw;
        memcpy(&enabled_raw, &plain[i].is_enabled, sizeof(enabled_raw));
        memcpy(&admin_raw, &plain[i].is_admin, sizeof(admin_raw));
        if (enabled_raw != 0 && admin_raw != 0) {
            has_admin = true;
            break;
        }
    }
    if (!has_admin) {
        printf("[backup] import: no enabled admin key in backup - refused\r\n");
        secure_wipe(plain_scratch, sizeof(plain_scratch));
        return false;
    }

    // Defense-in-depth: even authenticated, an is_admin record is confirmed
    // per-key before any destructive write. A denied record aborts the whole
    // import (existing keys untouched). A NULL callback denies all admin keys.
    for (uint32_t i = 0; i < hdr.key_count; i++) {
        uint8_t admin_raw;
        memcpy(&admin_raw, &plain[i].is_admin, sizeof(admin_raw));
        if (admin_raw != 0) {
            plain[i].name[KEY_NAME_MAX - 1] = '\0';
            bool confirmed =
                confirm_admin && confirm_admin(plain[i].id, plain[i].name, confirm_ctx);
            if (!confirmed) {
                printf("[backup] import: admin key %u not confirmed - aborting\r\n", plain[i].id);
                secure_wipe(plain_scratch, sizeof(plain_scratch));
                return false;
            }
        }
    }

    // Authenticated + validated + confirmed: replace the key set.
    static key_record_t existing[BACKUP_MAX_KEYS];
    int                 existing_count = storage_key_list(existing, BACKUP_MAX_KEYS);
    for (int i = 0; i < existing_count; i++)
        storage_key_delete(existing[i].id);
    // Only the ids were needed; scrub the resident seeds from BSS.
    secure_wipe(existing, sizeof(existing));

    bool ok = true;
    for (uint32_t i = 0; i < hdr.key_count; i++) {
        key_record_t rec;
        to_key_record(&plain[i], &rec);
        bool saved = storage_key_save(&rec);
        secure_wipe(&rec, sizeof(rec));
        if (!saved) {
            printf("[backup] import: failed to write key %u\r\n", plain[i].id);
            ok = false;
            break;
        }
    }

    secure_wipe(plain_scratch, sizeof(plain_scratch));

    if (ok)
        printf("[backup] import: wrote %u keys\r\n", hdr.key_count);
    return ok;
}
