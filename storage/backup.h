#ifndef BACKUP_H
#define BACKUP_H

#include "storage.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// ---------------------------------------------------------------------------
// Binary format (base64-encoded for serial transport)
// ---------------------------------------------------------------------------
//
// A backup's whole purpose is to live off-device (an operator's laptop, a repo,
// a chat log), so the raw HMAC seeds it carries must be useless to anyone who
// obtains the blob, and a tampered blob must never be trusted. The payload is
// therefore encrypted-then-MAC'd under a key derived from an operator
// passphrase (a backup is portable, so the key cannot be device-bound):
//
//   PBKDF2-HMAC-SHA256(passphrase, salt) -> 32-byte key
//   AES-256-GCM(key, iv) over the serialised key records
//
// With GCM the authentication tag IS the MAC of ciphertext + associated data,
// so this is encrypt-then-MAC by construction. Import derives the same key from
// the blob's salt, GCM-verifies the tag over the header (as AAD) and the
// ciphertext, and REJECTS before any record is parsed if verification fails.
// A wrong passphrase and any tamper (of header, ciphertext or tag) all fail the
// tag check. The CRC-32 is retained only as a paste-corruption hint; it is NOT
// a trust boundary.

#define BACKUP_MAGIC    0x4C4C5348U // "HSLL"
#define BACKUP_VERSION  2
#define BACKUP_MAX_KEYS KEY_MAX_COUNT

#define BACKUP_SALT_LEN     16
#define BACKUP_IV_LEN       12
#define BACKUP_TAG_LEN      16
#define BACKUP_KEY_LEN      32
#define BACKUP_PBKDF2_ITERS 100000u

// Header is cleartext; `salt`, `iv`, `key_count`, `magic` and `version` are fed
// to GCM as associated data so they are authenticated by `tag`. `checksum` is a
// non-cryptographic paste-corruption hint over the ciphertext and is NOT part
// of the AAD. The ciphertext (key_count * sizeof(backup_key_t) bytes) follows.
typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint32_t version;
    uint32_t key_count;
    uint8_t  salt[BACKUP_SALT_LEN];
    uint8_t  iv[BACKUP_IV_LEN];
    uint8_t  tag[BACKUP_TAG_LEN];
    uint32_t checksum; // CRC-32 of ciphertext: paste-corruption hint ONLY
} backup_header_t;

// Bytes of the header that are authenticated as GCM associated data: everything
// up to (not including) the tag itself.
#define BACKUP_AAD_LEN offsetof(backup_header_t, tag)

typedef struct __attribute__((packed)) {
    uint16_t id;
    char     name[KEY_NAME_MAX];
    uint8_t  secret[KEY_SECRET_LEN];
    bool     is_enabled;
    bool     is_admin;
    uint32_t created_at;
} backup_key_t;

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

// Per-key operator confirmation for admin records. Even with a valid MAC, an
// imported record that would grant admin is confirmed one-by-one (import is the
// only path that can set is_admin without set-key-admin). Return true to import
// the record as admin. Returning NULL for the callback denies all admin records.
typedef bool (*backup_admin_confirm_fn)(uint16_t id, const char *name, void *ctx);

// Encrypt-then-MAC all keys into buf under `passphrase`. Returns byte count
// written, -1 on error (buffer too small, no passphrase, crypto/storage error).
int backup_export(uint8_t *buf, size_t buf_size, const char *passphrase);

// Decrypt + authenticate buf under `passphrase`, then overwrite all keys.
// Verifies the GCM tag BEFORE parsing any record; returns false (touching
// nothing) on any authentication failure, wrong passphrase, or malformed blob.
// Each is_admin record is gated through `confirm_admin`; a denied admin record
// aborts the whole import before existing keys are touched. Returns false on
// error.
bool backup_import(const uint8_t *buf, size_t size, const char *passphrase,
                   backup_admin_confirm_fn confirm_admin, void *confirm_ctx);

#endif
