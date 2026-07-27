#include "backup.h"
#include "storage.h"
#include "lfs_util.h"

#include <string.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// Checksum helper
// ---------------------------------------------------------------------------

static uint32_t backup_checksum(const backup_key_t *keys, uint32_t count) {
    uint32_t crc = 0xFFFFFFFF;
    crc          = lfs_crc(crc, keys, count * sizeof(backup_key_t));
    return crc;
}

// ---------------------------------------------------------------------------
// logic model → backup key (fresh checksum)
// ---------------------------------------------------------------------------

static backup_key_t to_backup_key(const key_record_t *k) {
    backup_key_t b;
    b.id         = k->id;
    b.is_enabled = k->is_enabled;
    b.is_admin   = k->is_admin;
    b.created_at = k->created_at;
    memcpy(b.name, k->name, sizeof(b.name));
    memcpy(b.secret, k->secret, sizeof(b.secret));
    return b;
}

// ---------------------------------------------------------------------------
// backup key → logic model
// ---------------------------------------------------------------------------

static key_record_t to_key_record(const backup_key_t *b) {
    key_record_t k;
    k.id = b->id;
    // The backup blob is untrusted input: its is_enabled/is_admin bytes may hold
    // any value, so read them as raw bytes and canonicalise. Loading a `bool`
    // whose object representation is not 0/1 is undefined behaviour.
    uint8_t enabled_raw, admin_raw;
    memcpy(&enabled_raw, &b->is_enabled, sizeof(enabled_raw));
    memcpy(&admin_raw, &b->is_admin, sizeof(admin_raw));
    k.is_enabled        = (enabled_raw != 0);
    k.is_admin          = (admin_raw != 0);
    k.created_at        = b->created_at;
    k.is_checksum_valid = true;
    memcpy(k.name, b->name, sizeof(k.name));
    memcpy(k.secret, b->secret, sizeof(k.secret));
    return k;
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

int backup_export(uint8_t *buf, size_t buf_size) {
    static key_record_t records[BACKUP_MAX_KEYS];
    int                 count = storage_key_list(records, BACKUP_MAX_KEYS);
    if (count < 0)
        return -1;

    size_t needed = sizeof(backup_header_t) + count * sizeof(backup_key_t);
    if (buf_size < needed)
        return -1;

    // Populate backup keys
    backup_key_t *keys               = (backup_key_t *)(buf + sizeof(backup_header_t));
    int           exported_key_count = 0;
    for (int i = 0; i < count; i++) {
        if (!records[i].is_checksum_valid) {
            printf("[backup] export: key %u has invalid checksum, skipping\r\n", records[i].id);
            continue;
        }
        keys[exported_key_count++] = to_backup_key(&records[i]);
    }

    backup_header_t hdr = {
        .magic     = BACKUP_MAGIC,
        .version   = BACKUP_VERSION,
        .key_count = (uint32_t)exported_key_count,
        .checksum  = backup_checksum(keys, (uint32_t)exported_key_count),
    };
    memcpy(buf, &hdr, sizeof(hdr));

    return (int)(sizeof(backup_header_t) + exported_key_count * sizeof(backup_key_t));
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

bool backup_import(const uint8_t *buf, size_t size) {
    if (size < sizeof(backup_header_t)) {
        printf("[backup] import: buffer too small\r\n");
        return false;
    }

    const backup_header_t *hdr = (const backup_header_t *)buf;

    if (hdr->magic != BACKUP_MAGIC) {
        printf("[backup] import: bad magic\r\n");
        return false;
    }
    if (hdr->version != BACKUP_VERSION) {
        printf("[backup] import: unsupported version %u\r\n", hdr->version);
        return false;
    }

    if (hdr->key_count > KEY_MAX_COUNT) {
        printf("[backup] import: too many keys (%u > %d)\r\n", hdr->key_count, KEY_MAX_COUNT);
        return false;
    }

    size_t expected = sizeof(backup_header_t) + hdr->key_count * sizeof(backup_key_t);
    if (size < expected) {
        printf("[backup] import: truncated data\r\n");
        return false;
    }

    const backup_key_t *keys = (const backup_key_t *)(buf + sizeof(backup_header_t));

    // Verify whole-backup checksum
    uint32_t expected_crc = backup_checksum(keys, hdr->key_count);
    if (hdr->checksum != expected_crc) {
        printf("[backup] import: backup checksum mismatch\r\n");
        return false;
    }

    // Checksum valid - delete existing keys
    static key_record_t existing[BACKUP_MAX_KEYS];
    int                 existing_count = storage_key_list(existing, BACKUP_MAX_KEYS);
    for (int i = 0; i < existing_count; i++) {
        storage_key_delete(existing[i].id);
    }

    // Write new keys
    for (uint32_t i = 0; i < hdr->key_count; i++) {
        key_record_t rec = to_key_record(&keys[i]);
        if (!storage_key_save(&rec)) {
            printf("[backup] import: failed to write key %u\r\n", keys[i].id);
            return false;
        }
    }

    printf("[backup] import: wrote %u keys\r\n", hdr->key_count);
    return true;
}