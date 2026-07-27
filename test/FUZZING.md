# Fuzzing the hslock parse/logic surface

Five libFuzzer harnesses exercise every host-reachable byte of hslock's
untrusted-input parse/logic surface. HW-I/O wrappers (`hardware/*`, real
network I/O, `main.c`) are out of scope: they are not fuzzable on the host.

## The five fuzzers

| harness | entry point | what it drives |
|---|---|---|
| `fuzz_console.c`  | serial console byte stream | `console_process` → tokeniser → command dispatch → every handler in `commands*.c`, on a RAM-backed littlefs. Replays each input under 5 injectable clock/NTP/WiFi environments. |
| `fuzz_backup.c`   | raw backup blob            | `backup_import` (+ `to_key_record`) directly — header/version/count/CRC validation and the key-write loop. |
| `fuzz_totp.c`     | (big-endian time, secret)  | `totp_verify` directly against the **real** mbedtls HMAC-SHA1 with an injectable fixed clock: reject, T-1/T/T+1 accept window, full-loop reject. |
| `fuzz_storage.c`  | scripted CRUD ids/names    | `storage.c` public API (init/save/get/list/delete, wifi set/get/clear) on the RAM-mapped XIP window. |
| `fuzz_ntp.c`      | 48-byte NTP datagram body  | `ntp_recv_cb` directly — the **remote** untrusted surface (an NTP server or on-path spoofer): the too-short guard, the fixed 48-byte copy/parse, the big-endian transmit-timestamp decode, and both `rollback_check` arms via a deterministic preset + injectable clock. Includes `network/ntp.c` to reach the static callback. |

All five build with **clang libFuzzer + ASan + UBSan**
(`-fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all`) and link the
real `libmbedcrypto`, so **`libmbedtls-dev` and clang (with the sanitizer/fuzzer
runtime) are required**. If plain `clang` is unavailable use
`make -C test fuzz FUZZ_CC=clang-19`.

## Running

```sh
make -C test fuzz            # build all five fuzzer binaries
make -C test fuzz-run        # run fuzz_console from its committed corpus
make -C test fuzz-backup-run # "  fuzz_backup
make -C test fuzz-totp-run   # "  fuzz_totp
make -C test fuzz-storage-run# "  fuzz_storage
make -C test fuzz-ntp-run    # "  fuzz_ntp
make -C test fuzz-cov        # gcc --coverage replay of the committed corpora,
                             #   prints the surface coverage table below
make -C test asan            # the (clang-independent) ASan+UBSan unit gate
```

`fuzz-cov` is a deterministic gcc `--coverage -DFUZZ_REPLAY` build: it replays
the **committed** corpora (`fuzz_corpus`, `fuzz_backup_corpus`,
`fuzz_totp_corpus`, `fuzz_storage_corpus`, `fuzz_ntp_corpus`) through
`LLVMFuzzerTestOneInput`, merges the lcov trace, and restricts it to the 10
surface files. The table is
reproducible from the committed corpus alone — coverage-growth units are not
committed (they add libFuzzer feature buckets but no new surface edges).

## Final coverage (committed corpora)

```
                             |Lines       |Functions  |Branches
Filename                     |Rate     Num|Rate    Num|Rate     Num
===================================================================
network/ntp.c                |55.7%     97|88.9%     9|43.3%     30
serial/commands.c            | 100%     39| 100%     4| 100%     22
serial/commands_backup.c     |87.5%     24| 100%     2|83.3%      6
serial/commands_keys.c       |93.1%    216| 100%    10|88.7%    106
serial/commands_network.c    |93.9%     33| 100%     2|85.7%     14
serial/commands_system.c     |98.2%    113| 100%     6|93.2%     44
serial/console.c             | 100%     59| 100%     4| 100%     46
shared/totp.c                | 100%     25| 100%     2| 100%      6
storage/backup.c             |92.0%     75| 100%     5|84.6%     26
storage/storage.c            |93.2%    146| 100%    20|79.6%     54
===================================================================
                       Total:|90.2%    827|98.4%    64|85.9%    354
```

**Surface total: 90.2% lines (746/827), 98.4% functions (63/64),
85.9% branches (304/354).** This is a documented plateau: 240s
coverage-guided campaigns on all five fuzzers reproduce exactly these numbers.

`network/ntp.c`'s residual is HW-only: the sole uncovered function
`dns_found_cb` (and the matching tail of `ntp_sync`) is the DNS-resolve +
`udp_sendto` request path, which needs a live lwIP stack — the parse/rollback
surface reachable from a received datagram is fully driven.

## Bugs found and fixed

Two real firmware bugs surfaced during the campaigns; both are fixed and carry
a regression seed.

1. **`storage.c` lookahead_size 56-byte global-buffer-overflow.** littlefs was
   configured with a lookahead buffer smaller than `lookahead_size` demanded,
   so the mount walk wrote past the static buffer. Fixed by sizing the buffer to
   `lookahead_size`. (Found before the console/backup campaigns; regressed by
   the storage/console harnesses that mount on every run.)

2. **`backup.c` non-bool load UB (`to_key_record`).** A crafted backup blob
   whose `is_enabled`/`is_admin` bytes are neither 0 nor 1 but whose whole-payload
   CRC matches passes `backup_import` validation and reached a load of a `bool`
   member from an invalid (e.g. `67`) representation — UB on the serial
   `import-keys` path (reachable on real HW: user pastes a base64 backup).
   UBSan flagged `backup.c:40: load of value 67 … not valid for type 'bool'`.
   Fixed by reading the two flag bytes via `memcpy` into `uint8_t` and
   canonicalising `!= 0`; no `bool` is ever loaded from a non-0/1 byte.
   Regression seed: `fuzz_backup_corpus/nonbool_flags` (257B, CRC-irreducible).

No other crash/hang/ASan/UBSan finding across the campaigns.

## Residual uncovered lines/branches — all genuinely HW-unreachable

Every remaining gap is a flash/littlefs I/O error arm, a corrupt-checksum
display that needs sub-littlefs bit-rot, the post-watchdog reboot spin-loop, or
an export-fail arm that no caller can trigger. None is a reachable-but-unseeded
residual.

### serial/commands.c — none (100%).
The dispatch arg-count usage-error arm (`user_args < min_args || user_args > max_args`)
and `cmd_help`'s admin-visible path are driven from the committed corpus by the
`argerr_toofew` / `argerr_toomany` / `argerr_status` / `help_admin` console seeds.

### serial/console.c — none (100%).
### shared/totp.c — none (100%).

### serial/commands_backup.c (lines 14-16, branch 13)
- `cmd_export_keys` export-failed arm. The only caller passes a full
  `export_buf`, so `backup_export` never returns `<0` here (same root as
  backup.c:60/56). Needs a storage read failure.

### serial/commands_keys.c
- **19-20** (br 18): `cmd_list_keys` `storage_key_list < 0` — storage read failure.
- **111-113** (br 110), **br 44, br 75**: `!is_checksum_valid` corrupt-key display in
  get-key-secret / get-key / list-keys. `storage_key_save` always writes a fresh
  valid checksum, so a mismatch needs flash bit-rot under littlefs's own block CRC.
- **135-137** (br 134): QR-generation-failed arm. The fixed-format otpauth URI is
  always well-formed within qrcodegen capacity, so `qrcodegen_encodeText` never
  returns false.
- **187, 221, 253, 285, 309, 341, 373** (br 184/218/250/282/306/338/370):
  `storage_key_save`/`storage_key_delete` failure else-branches across the 9
  handlers. All keys fit inline on the 256KB host window; a save/delete never
  fails — needs a real flash error.

### serial/commands_network.c (lines 42-43, branches 40-41)
- `set-wifi` `storage_wifi_set` returns false → "FAILED". The 256KB host window
  never fails a wifi write; needs a real littlefs write failure.

### serial/commands_system.c (lines 66, 203, branches 65/125/174)
- **66 (br 65)**, **br 125-disjunct, br 174-disjunct**: `!is_checksum_valid` corrupt-key
  counting / any-admin / login disjuncts — flash-bit-rot-only (as above).
- **203**: `while (true) tight_loop_contents()` after `watchdog_reboot` — the
  harness longjmps out of `watchdog_reboot` before the spin; unreachable on host.

### storage/backup.c (lines 63, 67, 74-75, 143-144, branches 62/66/73/142)
- **62/63** (`buf_size < needed` in `backup_export`) and **73/74-75** (skip of an
  on-flash invalid-checksum key): export-only arms; `cmd_export_keys` always
  passes a full buffer and `storage_key_save` never writes an invalid checksum.
- **66/67**: same export invalid-checksum skip disjunct.
- **142/143-144**: `storage_key_save` fails in the import write loop. All 256 MAX
  keys fit the littlefs inline, so no accepted blob makes a save fail — needs a
  genuine flash error.

### storage/storage.c (11 branches — flash/littlefs never fails on the RAM window)
- **127, 134**: `flash_prog` / `flash_erase` → `LFS_ERR_IO`.
- **204-205**: `lfs_format` fails; **208-209**: remount-after-format fails;
  **212-214**: `ensure_dirs` / `lfs_mkdir` fails.
- **246-247**: `storage_wifi_set` `opencfg` fails; **307-308**: `storage_key_save`
  `opencfg` fails.
- **286-287**: `storage_key_get` short read (`n != sizeof`); **291-292**: key_get
  app-checksum mismatch display (sub-littlefs bit-rot only).
- **331-332**: `lfs_dir_open(/keys)` fails; **341-342**: per-entry
  `storage_key_get` fails in the list loop → `continue`.
