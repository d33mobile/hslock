#include "commands_handlers.h"
#include "hardware/buzzer.h"
#include "storage/backup.h"
#include "shared/wipe.h"
#include "libs/base64/base64.h"
#include "pico/stdlib.h"
#include "pico/time.h"
#include <stdio.h>
#include <string.h>

#define BACKUP_PASSPHRASE_MAX 64

// ---------------------------------------------------------------------------
// Read one line from the console into buf (NUL-terminated, CR/LF stripped).
// Returns the length, or -1 on timeout with nothing entered.
// ---------------------------------------------------------------------------

static int read_line(char *buf, size_t cap, uint32_t timeout_ms) {
    size_t          len      = 0;
    absolute_time_t deadline = make_timeout_time_ms(timeout_ms);
    while (!time_reached(deadline)) {
        int c = getchar_timeout_us(10000);
        if (c == PICO_ERROR_TIMEOUT)
            continue;
        if (c == '\r')
            continue;
        if (c == '\n')
            break;
        if (len < cap - 1)
            buf[len++] = (char)c;
    }
    buf[len] = '\0';
    return (len == 0 && time_reached(deadline)) ? -1 : (int)len;
}

// ---------------------------------------------------------------------------
// Per-key admin confirmation prompt (backup_admin_confirm_fn).
// ---------------------------------------------------------------------------

static bool confirm_admin_prompt(uint16_t id, const char *name, void *ctx) {
    (void)ctx;
    printf("[import] key %u \"%s\" grants ADMIN. import as admin? type yes:\r\n", id, name);
    char answer[8];
    read_line(answer, sizeof(answer), 30000);
    return strcmp(answer, "yes") == 0;
}

// ---------------------------------------------------------------------------
// Emit an encrypted backup of the current key set under `passphrase`.
// ---------------------------------------------------------------------------

static void emit_backup(const char *passphrase) {
    static uint8_t export_buf[sizeof(backup_header_t) + BACKUP_MAX_KEYS * sizeof(backup_key_t)];
    static char    b64_buf[BASE64_ENCODED_LEN(sizeof(export_buf))];

    int len = backup_export(export_buf, sizeof(export_buf), passphrase);
    if (len < 0) {
        printf("error: export failed\r\n");
        secure_wipe(export_buf, sizeof(export_buf));
        return;
    }

    base64_encode(export_buf, (size_t)len, b64_buf);
    printf("--- BEGIN HSLOCK BACKUP ---\r\n");
    printf("%s\r\n", b64_buf);
    printf("--- END HSLOCK BACKUP ---\r\n");

    // The blob and its base64 encoding both carry the seeds; scrub them from BSS.
    secure_wipe(export_buf, sizeof(export_buf));
    secure_wipe(b64_buf, sizeof(b64_buf));
}

void cmd_export_keys(int argc, char **argv) {
    (void)argc;
    (void)argv;

    printf("enter backup passphrase (encrypts the blob):\r\n");
    char passphrase[BACKUP_PASSPHRASE_MAX];
    if (read_line(passphrase, sizeof(passphrase), 60000) <= 0 || passphrase[0] == '\0') {
        printf("error: no passphrase entered\r\n");
        secure_wipe(passphrase, sizeof(passphrase));
        buzzer_play_command_ack();
        return;
    }

    emit_backup(passphrase);
    secure_wipe(passphrase, sizeof(passphrase));

    buzzer_play_command_ack();
}

void cmd_import_keys(int argc, char **argv) {
    (void)argc;
    (void)argv;

    // M3: importing overwrites every key (delete-all then rewrite) and is as
    // destructive as format-storage, yet ran with no confirmation. Gate it
    // behind an explicit CONFIRM (admin-only command, so a literal token is
    // sufficient) - mirrors cmd_format_storage's prompt.
    printf("*** WARNING: import overwrites ALL current keys ***\r\n");
    printf("type CONFIRM to proceed: ");
    fflush(stdout);

    char            confirm[10]      = {0};
    int             confirm_len      = 0;
    absolute_time_t confirm_deadline = make_timeout_time_ms(15000);

    while (!time_reached(confirm_deadline) && confirm_len < 7) {
        int c = getchar_timeout_us(0);
        if (c == PICO_ERROR_TIMEOUT) {
            sleep_ms(10);
            continue;
        }
        if (c == '\r' || c == '\n') {
            printf("\r\n");
            break;
        }
        putchar(c);
        fflush(stdout);
        confirm[confirm_len++] = (char)c;
    }

    if (strncmp(confirm, "CONFIRM", 7) != 0) {
        printf("error: aborted\r\n");
        buzzer_play_command_ack();
        return;
    }

    printf("enter backup passphrase (decrypts the blob):\r\n");
    char passphrase[BACKUP_PASSPHRASE_MAX];
    if (read_line(passphrase, sizeof(passphrase), 60000) <= 0 || passphrase[0] == '\0') {
        printf("error: no passphrase entered\r\n");
        secure_wipe(passphrase, sizeof(passphrase));
        buzzer_play_command_ack();
        return;
    }

    // Safety backup of the current key set (encrypted under the same passphrase)
    // before anything is overwritten.
    printf("backing up current keys...\r\n");
    emit_backup(passphrase);

    printf("paste import data, then send empty line:\r\n");

    // Read base64 directly from serial into a large static buffer
    static char b64_buf[BASE64_ENCODED_LEN(sizeof(backup_header_t) +
                                           BACKUP_MAX_KEYS * sizeof(backup_key_t))];
    int         b64_len  = 0;
    bool        overflow = false;
    char        line[256];
    int         line_len = 0;

    absolute_time_t deadline = make_timeout_time_ms(60000); // 60s to paste

    while (!time_reached(deadline)) {
        int c = getchar_timeout_us(10000);
        if (c == PICO_ERROR_TIMEOUT)
            continue;
        if (c == '\r')
            continue;

        if (c == '\n') {
            if (line_len == 0)
                break; // empty line = done
            // M5: an over-long paste must ABORT the import, not be silently
            // dropped - a truncated blob decoded into import_buf is meaningless
            // and previously masked the length that overflows the decode buffer.
            if (b64_len + line_len < (int)sizeof(b64_buf)) {
                memcpy(b64_buf + b64_len, line, line_len);
                b64_len += line_len;
            } else {
                overflow = true;
            }
            line_len = 0;
        } else {
            if (line_len < (int)sizeof(line) - 1) {
                line[line_len++] = (char)c;
            }
        }
    }

    if (overflow) {
        printf("error: import data too large\r\n");
        secure_wipe(passphrase, sizeof(passphrase));
        secure_wipe(b64_buf, sizeof(b64_buf));
        secure_wipe(line, sizeof(line));
        buzzer_play_command_ack();
        return;
    }

    if (b64_len == 0) {
        printf("error: no data received\r\n");
        secure_wipe(passphrase, sizeof(passphrase));
        secure_wipe(b64_buf, sizeof(b64_buf));
        secure_wipe(line, sizeof(line));
        buzzer_play_command_ack();
        return;
    }

    static uint8_t import_buf[sizeof(backup_header_t) + BACKUP_MAX_KEYS * sizeof(backup_key_t)];

    // M5: reject up front any blob whose decoded length cannot fit import_buf,
    // before feeding it to the decoder. base64_decode is also capacity-bounded
    // (defence in depth), but rejecting here gives the operator a clear error.
    if (BASE64_DECODED_LEN((size_t)b64_len) > sizeof(import_buf)) {
        printf("error: import data too large\r\n");
        secure_wipe(passphrase, sizeof(passphrase));
        secure_wipe(b64_buf, sizeof(b64_buf));
        secure_wipe(line, sizeof(line));
        buzzer_play_command_ack();
        return;
    }

    int len = base64_decode(b64_buf, (size_t)b64_len, import_buf, sizeof(import_buf));
    if (len < 0) {
        printf("error: invalid base64\r\n");
        secure_wipe(passphrase, sizeof(passphrase));
        secure_wipe(b64_buf, sizeof(b64_buf));
        secure_wipe(line, sizeof(line));
        secure_wipe(import_buf, sizeof(import_buf));
        buzzer_play_command_ack();
        return;
    }

    printf("importing...\r\n");
    if (backup_import(import_buf, (size_t)len, passphrase, confirm_admin_prompt, NULL)) {
        printf("import ok\r\n");
    } else {
        printf("error: import failed\r\n");
    }

    // The passphrase, the pasted blob and its decoded form all carry secrets; scrub them.
    secure_wipe(passphrase, sizeof(passphrase));
    secure_wipe(b64_buf, sizeof(b64_buf));
    secure_wipe(line, sizeof(line));
    secure_wipe(import_buf, sizeof(import_buf));

    buzzer_play_command_ack();
}
