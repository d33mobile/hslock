# Host test suite for hslock.
#
# The firmware is cross-compiled for the RP2040 and cannot run natively, but
# the hardware-independent logic can be built as a native Linux ELF and tested.
# This Makefile builds each harness against the REAL first-party sources plus
# cheap host stubs (test/stub/), and runs them under three modes:
#
#   make asan      ASan + UBSan, aborts on any error (CI gate)
#   make valgrind  plain build under valgrind, fails on error/leak
#   make coverage  --coverage build of the harness-exercised modules, run,
#                  lcov + genhtml report (branch coverage) into coverage/html/
#   make clean
#
# Invoke from the repo root as `make -C test <target>`.

# Repo layout, relative to this Makefile (test/).
ROOT      := ..
BUILD     := build
COV_DIR   := coverage

# Absolute repo root, used to filter coverage to first-party sources WITHOUT
# assuming the checkout dir is literally named "hslock". Coverage is built with
# -fprofile-abs-path, so the .info tracefiles carry absolute source paths;
# extracting "$(REPO_ROOT)/*" keeps first-party files regardless of dir name.
# Prefer git's toplevel; fall back to the parent dir for non-git checkouts.
REPO_ROOT := $(or $(shell git -C $(CURDIR) rev-parse --show-toplevel 2>/dev/null),$(abspath $(ROOT)))

# Real first-party / third-party sources exercised by the harnesses.
SHARED    := $(ROOT)/shared
BASE32    := $(ROOT)/libs/base32
BASE64    := $(ROOT)/libs/base64
QRCODEGEN := $(ROOT)/libs/qrcodegen/c

# Include roots. `-I..` resolves module-qualified includes ("hardware/buzzer.h",
# "storage/storage.h", ...); the per-module dirs resolve bare includes
# ("buzzer.h", "base32.h", ...); `-Istub` supplies host shims for Pico-SDK
# headers; `-I$(ROOT)/libs/littlefs` supplies the real lfs_util.h (lfs_crc).
INCLUDES  := -Istub -I$(ROOT) \
             -I$(ROOT)/hardware -I$(ROOT)/network -I$(ROOT)/serial \
             -I$(ROOT)/storage -I$(SHARED) -I$(BASE32) -I$(BASE64) \
             -I$(QRCODEGEN) -I$(ROOT)/libs/littlefs

# Per-harness source lists (harness + its real dependencies).
SECRET_QR_SRCS := harness_secret_qr.c $(SHARED)/random.c $(BASE32)/base32.c \
                  $(QRCODEGEN)/qrcodegen.c
BASE64_SRCS    := harness_base64.c $(BASE64)/base64.c

# TOTP harness needs the REAL HMAC-SHA1, so it builds against the system mbedtls
# (libmbedtls-dev) rather than the compile-only stub/mbedtls/md.h. `-idirafter
# stub` keeps the hardware/rtc.h stub reachable while letting the real
# <mbedtls/md.h> (a system dir) win the search for totp.c's HMAC include.
# CI: the test job must apt-install `libmbedtls-dev` for this to build.
TOTP_SRCS     := harness_totp.c $(SHARED)/totp.c
TOTP_INCLUDES := -I$(ROOT) -I$(ROOT)/hardware -I$(SHARED) -idirafter stub
TOTP_LIBS     := -lmbedcrypto

# Storage harness: storage.c + backup.c + the REAL littlefs (lfs.c/lfs_util.c),
# run against a RAM-backed XIP window the harness maps in (see harness_storage.c).
# LFS_NO_MALLOC/LFS_NO_DEBUG mirror the firmware's CMakeLists so lfs.h/lfs_util.h
# match. The shared INCLUDES already resolve stub/, storage/ and libs/littlefs/.
STORAGE_SRCS := harness_storage.c $(ROOT)/storage/storage.c $(ROOT)/storage/backup.c \
                $(ROOT)/libs/littlefs/lfs.c $(ROOT)/libs/littlefs/lfs_util.c
STORAGE_DEFS := -DLFS_NO_MALLOC -DLFS_NO_DEBUG
# backup.c now encrypt-then-MACs the blob (AES-256-GCM + PBKDF2) via mbedtls, so
# the storage harness links the REAL system mbedtls (libmbedtls-dev). `-idirafter
# stub` keeps the pico/hardware/lwip shims reachable while letting the real
# <mbedtls/gcm.h,pkcs5.h,md.h> (system dirs) win over the compile-only
# stub/mbedtls/md.h (which lacks GCM/PKCS5 and SHA-256).
STORAGE_INCLUDES := -I$(ROOT) -I$(ROOT)/hardware -I$(ROOT)/network -I$(ROOT)/serial \
                    -I$(ROOT)/storage -I$(SHARED) -I$(BASE32) -I$(BASE64) \
                    -I$(QRCODEGEN) -I$(ROOT)/libs/littlefs -idirafter stub
STORAGE_LIBS := -lmbedcrypto

# Commands harness: links serial/commands.c (the dispatcher) against SPY handler
# stubs + a stub buzzer, all inside harness_commands.c. No real key/system/
# network/backup handlers are pulled in - the harness drives commands_dispatch()
# and asserts routing / admin gating / argc validation / unknown handling. The
# shared INCLUDES resolve stub/pico + hardware/buzzer.h.
COMMANDS_SRCS := harness_commands.c $(ROOT)/serial/commands.c

# Whole-codebase coverage: EVERY first-party .c, so the report lists the whole
# firmware (the harness-exercised modules at their real %, the rest at an honest
# 0%). These are compiled instrumented but NOT linked or run - a .gcno alone is
# enough for a file to appear in the report. The terse host stubs under stub/
# stand in for the pico-sdk / cyw43 / lwip / mbedtls headers they pull.
WHOLE_SRCS := $(ROOT)/hardware/buzzer.c $(ROOT)/hardware/clock.c \
              $(ROOT)/hardware/keypad.c $(ROOT)/hardware/latch.c \
              $(ROOT)/hardware/led.c $(ROOT)/hardware/light.c $(ROOT)/main.c \
              $(ROOT)/network/ntp.c $(ROOT)/network/wifi.c \
              $(ROOT)/serial/commands.c $(ROOT)/serial/commands_backup.c \
              $(ROOT)/serial/commands_keys.c $(ROOT)/serial/commands_network.c \
              $(ROOT)/serial/commands_system.c $(ROOT)/serial/console.c \
              $(ROOT)/shared/random.c $(ROOT)/shared/totp.c \
              $(ROOT)/storage/backup.c $(ROOT)/storage/storage.c

# LittleFS build knobs, mirrored from the top-level CMakeLists so storage.c and
# backup.c see the same lfs.h / lfs_util.h configuration the firmware does.
WHOLE_DEFS := -DLFS_NO_MALLOC -DLFS_NO_DEBUG

# Same include roots as INCLUDES but with stub as `-idirafter` so the REAL system
# mbedtls headers win: backup.c (AES-GCM/PKCS5) and totp.c (HMAC-SHA1) are
# compiled compile-only here and the stub/mbedtls/md.h lacks GCM/PKCS5/SHA-256.
# Everything else (pico/hardware/lwip) has no system header, so stub still wins.
WHOLE_INCLUDES := -I$(ROOT) -I$(ROOT)/hardware -I$(ROOT)/network -I$(ROOT)/serial \
                  -I$(ROOT)/storage -I$(SHARED) -I$(BASE32) -I$(BASE64) \
                  -I$(QRCODEGEN) -I$(ROOT)/libs/littlefs -idirafter stub

CC       := gcc
CSTD     := -std=c11
WARN     := -Wall -Wextra

ASAN_FLAGS := -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all
VG_FLAGS   := -g -O0
COV_FLAGS  := -g -O0 --coverage -fprofile-abs-path

# lcov 2.x: enable branch coverage everywhere; tolerate the benign
# inconsistencies host coverage of firmware naturally produces.
#
# The valid --ignore-errors category set differs per sub-tool and per lcov
# build: Ubuntu 24.04's lcov 2.0 genhtml rejects 'gcov'/'graph'/'range'
# (there is no gcov phase in genhtml), while lcov/geninfo accept 'gcov' but
# reject 'range'. So keep two lists: the capture/combine list (lcov+geninfo)
# may carry 'gcov'; the genhtml list must not. Every category below exists in
# lcov 2.0.0, so this is robust across lcov 1.x/2.x on Debian and Ubuntu.
LCOV_RC        := --rc branch_coverage=1
LCOV_IGNORE    := --ignore-errors unused,empty,mismatch,inconsistent,source,gcov,negative
GENHTML_IGNORE := --ignore-errors unused,empty,mismatch,inconsistent,source,negative
LCOV           := lcov $(LCOV_RC) $(LCOV_IGNORE)

.PHONY: all asan valgrind coverage fuzz fuzz-run fuzz-backup-run fuzz-totp-run fuzz-storage-run fuzz-ntp-run fuzz-cov gen-backup-seeds clean check-submodules

all: asan

# Fail early with a clear message if the git submodules aren't checked out
# (fresh clones have empty libs/qrcodegen and libs/littlefs).
check-submodules:
	@test -f $(QRCODEGEN)/qrcodegen.c && test -f $(ROOT)/libs/littlefs/lfs_util.h || { \
	    echo "ERROR: git submodules not initialized (libs/qrcodegen and/or libs/littlefs are empty)." >&2; \
	    echo "       run: git submodule update --init --recursive" >&2; \
	    exit 1; }

# --- ASan + UBSan -----------------------------------------------------------
asan: check-submodules $(BUILD)/asan_secret_qr $(BUILD)/asan_base64 $(BUILD)/asan_totp \
      $(BUILD)/asan_storage $(BUILD)/asan_commands
	@echo "== running asan/ubsan harnesses =="
	$(BUILD)/asan_secret_qr
	$(BUILD)/asan_base64
	$(BUILD)/asan_totp
	$(BUILD)/asan_storage
	$(BUILD)/asan_commands
	@echo "== asan OK =="

$(BUILD)/asan_secret_qr: $(SECRET_QR_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(ASAN_FLAGS) $(INCLUDES) $(SECRET_QR_SRCS) -o $@

$(BUILD)/asan_base64: $(BASE64_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(ASAN_FLAGS) $(INCLUDES) $(BASE64_SRCS) -o $@

$(BUILD)/asan_totp: $(TOTP_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(ASAN_FLAGS) $(TOTP_INCLUDES) $(TOTP_SRCS) $(TOTP_LIBS) -o $@

$(BUILD)/asan_storage: $(STORAGE_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(ASAN_FLAGS) $(STORAGE_DEFS) $(STORAGE_INCLUDES) $(STORAGE_SRCS) $(STORAGE_LIBS) -o $@

$(BUILD)/asan_commands: $(COMMANDS_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(ASAN_FLAGS) $(INCLUDES) $(COMMANDS_SRCS) -o $@

# --- Valgrind ---------------------------------------------------------------
valgrind: check-submodules $(BUILD)/vg_secret_qr $(BUILD)/vg_base64 $(BUILD)/vg_totp \
          $(BUILD)/vg_storage $(BUILD)/vg_commands
	@echo "== running harnesses under valgrind =="
	valgrind --error-exitcode=99 --leak-check=full -q $(BUILD)/vg_secret_qr
	valgrind --error-exitcode=99 --leak-check=full -q $(BUILD)/vg_base64
	valgrind --error-exitcode=99 --leak-check=full -q $(BUILD)/vg_totp
	valgrind --error-exitcode=99 --leak-check=full -q $(BUILD)/vg_storage
	valgrind --error-exitcode=99 --leak-check=full -q $(BUILD)/vg_commands
	@echo "== valgrind OK =="

$(BUILD)/vg_secret_qr: $(SECRET_QR_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(VG_FLAGS) $(INCLUDES) $(SECRET_QR_SRCS) -o $@

$(BUILD)/vg_base64: $(BASE64_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(VG_FLAGS) $(INCLUDES) $(BASE64_SRCS) -o $@

$(BUILD)/vg_totp: $(TOTP_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(VG_FLAGS) $(TOTP_INCLUDES) $(TOTP_SRCS) $(TOTP_LIBS) -o $@

$(BUILD)/vg_storage: $(STORAGE_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(VG_FLAGS) $(STORAGE_DEFS) $(STORAGE_INCLUDES) $(STORAGE_SRCS) $(STORAGE_LIBS) -o $@

$(BUILD)/vg_commands: $(COMMANDS_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(VG_FLAGS) $(INCLUDES) $(COMMANDS_SRCS) -o $@

# --- Coverage (lcov/genhtml HTML report for the WHOLE first-party codebase) --
# Build & run the real harnesses with --coverage (producing .gcda), AND compile
# every first-party .c instrumented but unlinked (compile-only, producing .gcno
# only). A --initial capture turns the whole .gcno set into a 0% baseline; the
# run capture carries the executed lines; merging the two yields a report that
# spans the whole firmware - the harness-exercised modules (base32/base64/
# random/...) at their real %, every other first-party file at an honest 0%.
# Everything outside the first-party tree (vendored libs, the harnesses, /usr)
# is filtered out.
coverage: check-submodules | $(COV_DIR)/obj
	@echo "== coverage: building + running harnesses =="
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(INCLUDES) $(SECRET_QR_SRCS) \
	    -o $(COV_DIR)/obj/cov_secret_qr
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(INCLUDES) $(BASE64_SRCS) \
	    -o $(COV_DIR)/obj/cov_base64
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(TOTP_INCLUDES) $(TOTP_SRCS) $(TOTP_LIBS) \
	    -o $(COV_DIR)/obj/cov_totp
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(STORAGE_DEFS) $(STORAGE_INCLUDES) $(STORAGE_SRCS) \
	    $(STORAGE_LIBS) -o $(COV_DIR)/obj/cov_storage
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(INCLUDES) $(COMMANDS_SRCS) \
	    -o $(COV_DIR)/obj/cov_commands
	@echo "== coverage: running instrumented harnesses =="
	$(COV_DIR)/obj/cov_secret_qr
	$(COV_DIR)/obj/cov_base64
	$(COV_DIR)/obj/cov_totp
	$(COV_DIR)/obj/cov_storage
	$(COV_DIR)/obj/cov_commands
	@echo "== coverage: compiling whole first-party codebase (compile-only) =="
	@for src in $(WHOLE_SRCS); do \
	    obj=$(COV_DIR)/obj/whole_$$(echo $$src | tr '/.' '__').o; \
	    echo "  CC $$src"; \
	    $(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(WHOLE_DEFS) $(WHOLE_INCLUDES) \
	        -c $$src -o $$obj || exit 1; \
	done
	@echo "== coverage: capturing baseline (all .gcno at 0%) + run data =="
	$(LCOV) --capture --initial --directory $(COV_DIR)/obj \
	    --output-file $(COV_DIR)/baseline.info
	$(LCOV) --capture --directory $(COV_DIR)/obj \
	    --output-file $(COV_DIR)/run.info
	$(LCOV) --add-tracefile $(COV_DIR)/baseline.info \
	    --add-tracefile $(COV_DIR)/run.info \
	    --output-file $(COV_DIR)/merged.info
	@echo "== coverage: filtering to first-party sources =="
	$(LCOV) --extract $(COV_DIR)/merged.info '$(REPO_ROOT)/*' \
	    --output-file $(COV_DIR)/first.info
	$(LCOV) --remove $(COV_DIR)/first.info \
	    '*/libs/qrcodegen/*' '*/libs/littlefs/*' '*/test/*' '/usr/*' \
	    --output-file $(COV_DIR)/coverage.info
	@echo "== coverage: generating HTML report =="
	genhtml $(LCOV_RC) $(GENHTML_IGNORE) --branch-coverage \
	    --legend --title "hslock host coverage" \
	    --output-directory $(COV_DIR)/html $(COV_DIR)/coverage.info
	@echo "== coverage summary =="
	$(LCOV) --summary $(COV_DIR)/coverage.info
	@echo "== coverage OK: report at $(COV_DIR)/html/index.html =="

# --- libFuzzer console harness ----------------------------------------------
# End-to-end fuzzing of the serial-console command interface: fuzz bytes flow
# through the REAL console_task() char accumulator -> process_line() tokeniser
# -> commands_dispatch() -> real cmd_* handlers -> storage.c/backup.c on a
# genuine littlefs backed by a RAM-mapped XIP window. Only hardware/network
# leaves are stubbed. See test/fuzz_console.c for the driver.
#
# libFuzzer + ASan + UBSan REQUIRE clang (with the sanitizer/fuzzer runtime),
# so this target is kept separate from the gcc-based asan/valgrind/coverage
# gates and never runs as part of `all`. Override the compiler with
# `make -C test fuzz FUZZ_CC=clang-19` if plain `clang` is unavailable.
FUZZ_CC        ?= clang
FUZZ_BIN       := $(BUILD)/fuzz_console
FUZZ_TIME      ?= 60
FUZZ_CORPUS    := fuzz_corpus
FUZZ_DICT      := fuzz_console.dict
FUZZ_FLAGS     := -std=c11 -g -O1 -fsanitize=fuzzer,address,undefined \
                  -fno-sanitize-recover=all
FUZZ_INCLUDES  := -I$(ROOT) -I$(ROOT)/hardware -I$(ROOT)/network -I$(ROOT)/serial \
                  -I$(ROOT)/storage -I$(SHARED) -I$(BASE32) -I$(BASE64) \
                  -I$(QRCODEGEN) -I$(ROOT)/libs/littlefs -idirafter stub
FUZZ_SRCS      := fuzz_console.c \
                  $(ROOT)/serial/console.c $(ROOT)/serial/commands.c \
                  $(ROOT)/serial/commands_system.c $(ROOT)/serial/commands_keys.c \
                  $(ROOT)/serial/commands_network.c $(ROOT)/serial/commands_backup.c \
                  $(ROOT)/storage/storage.c $(ROOT)/storage/backup.c \
                  $(SHARED)/totp.c $(SHARED)/random.c \
                  $(BASE32)/base32.c $(BASE64)/base64.c $(QRCODEGEN)/qrcodegen.c \
                  $(ROOT)/libs/littlefs/lfs.c $(ROOT)/libs/littlefs/lfs_util.c
FUZZ_DEFS      := -DLFS_NO_MALLOC -DLFS_NO_DEBUG
FUZZ_LIBS      := -lmbedcrypto

# Direct backup_import() deserialiser harness: fuzz bytes go straight into the
# untrusted-blob parser on a fresh RAM-backed littlefs, bypassing console +
# login + admin + base64. See test/fuzz_backup.c. Only storage.c/backup.c and
# the real littlefs are linked (no console/totp/qr surface).
FUZZ_BACKUP_BIN    := $(BUILD)/fuzz_backup
FUZZ_BACKUP_CORPUS := fuzz_backup_corpus
FUZZ_BACKUP_SRCS   := fuzz_backup.c \
                      $(ROOT)/storage/storage.c $(ROOT)/storage/backup.c \
                      $(ROOT)/libs/littlefs/lfs.c $(ROOT)/libs/littlefs/lfs_util.c

# Direct totp_verify() harness: fuzz bytes are interpreted as a (time, secret)
# pair and totp.c is driven directly, so the ACCEPT branch of totp_verify (a
# valid in-window code -> return true) runs every replay — unreachable via the
# console fuzzer, whose RNG-generated secret makes a random code never match.
# Built against the REAL mbedtls (system libmbedcrypto), like the asan_totp
# harness; -idirafter stub keeps the <mbedtls/md.h> system header winning.
FUZZ_TOTP_BIN      := $(BUILD)/fuzz_totp
FUZZ_TOTP_CORPUS   := fuzz_totp_corpus
FUZZ_TOTP_SRCS     := fuzz_totp.c $(SHARED)/totp.c
FUZZ_TOTP_INCLUDES := -I$(ROOT) -I$(ROOT)/hardware -I$(SHARED) -idirafter stub
FUZZ_TOTP_LIBS     := -lmbedcrypto

# Direct storage.c CRUD harness: fuzz bytes vary key ids/names/wifi while a
# fixed scripted sequence drives storage.c's public API on a fresh RAM-backed
# littlefs. Reaches the storage branches the console/backup fuzzers structurally
# can't: the pre-mount `!mounted` guards, the mount-succeeds-first-try +
# dir-already-exists init paths, storage_key_list's clamp/truncation exits, and
# storage_wifi_clear (no firmware caller). See test/fuzz_storage.c.
FUZZ_STORAGE_BIN    := $(BUILD)/fuzz_storage
FUZZ_STORAGE_CORPUS := fuzz_storage_corpus
FUZZ_STORAGE_SRCS   := fuzz_storage.c \
                       $(ROOT)/storage/storage.c \
                       $(ROOT)/libs/littlefs/lfs.c $(ROOT)/libs/littlefs/lfs_util.c

# Direct NTP response-parser harness: fuzz bytes become a 48-byte UDP datagram
# body fed straight into ntp_recv_cb() -- the REMOTE untrusted-input surface (an
# NTP server or on-path spoofer). ntp_recv_cb is static, so fuzz_ntp.c #includes
# the real network/ntp.c (all lwip/pico/hardware symbols stubbed inside the
# harness); network/ntp.c is a prerequisite, not a compiled source. See
# test/fuzz_ntp.c.
FUZZ_NTP_BIN    := $(BUILD)/fuzz_ntp
FUZZ_NTP_CORPUS := fuzz_ntp_corpus
FUZZ_NTP_SRCS   := fuzz_ntp.c

# Build all fuzzers.
fuzz: check-submodules $(FUZZ_BIN) $(FUZZ_BACKUP_BIN) $(FUZZ_TOTP_BIN) $(FUZZ_STORAGE_BIN) \
      $(FUZZ_NTP_BIN)

$(FUZZ_BIN): $(FUZZ_SRCS) | $(BUILD)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) $(FUZZ_INCLUDES) $(FUZZ_SRCS) $(FUZZ_LIBS) -o $@

$(FUZZ_BACKUP_BIN): $(FUZZ_BACKUP_SRCS) | $(BUILD)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) $(FUZZ_INCLUDES) $(FUZZ_BACKUP_SRCS) -o $@

$(FUZZ_TOTP_BIN): $(FUZZ_TOTP_SRCS) | $(BUILD)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_TOTP_INCLUDES) $(FUZZ_TOTP_SRCS) $(FUZZ_TOTP_LIBS) -o $@

$(FUZZ_STORAGE_BIN): $(FUZZ_STORAGE_SRCS) | $(BUILD)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_DEFS) $(FUZZ_INCLUDES) $(FUZZ_STORAGE_SRCS) -o $@

$(FUZZ_NTP_BIN): $(FUZZ_NTP_SRCS) $(ROOT)/network/ntp.c | $(BUILD)
	$(FUZZ_CC) $(FUZZ_FLAGS) $(FUZZ_INCLUDES) $(FUZZ_NTP_SRCS) -o $@

# Build + run short bounded campaigns from the seed corpora. The console run is
# fed the keyword dictionary so mutation can splice real commands together.
# Bump FUZZ_TIME for a longer soak: `make -C test fuzz-run FUZZ_TIME=600`.
fuzz-run: $(FUZZ_BIN)
	@echo "== fuzzing serial console for $(FUZZ_TIME)s =="
	$(FUZZ_BIN) -max_total_time=$(FUZZ_TIME) -print_final_stats=1 \
	    -dict=$(FUZZ_DICT) $(FUZZ_CORPUS)

fuzz-backup-run: $(FUZZ_BACKUP_BIN)
	@echo "== fuzzing backup_import for $(FUZZ_TIME)s =="
	$(FUZZ_BACKUP_BIN) -max_total_time=$(FUZZ_TIME) -print_final_stats=1 \
	    $(FUZZ_BACKUP_CORPUS)

fuzz-totp-run: $(FUZZ_TOTP_BIN)
	@echo "== fuzzing totp_verify for $(FUZZ_TIME)s =="
	$(FUZZ_TOTP_BIN) -max_total_time=$(FUZZ_TIME) -print_final_stats=1 \
	    $(FUZZ_TOTP_CORPUS)

fuzz-storage-run: $(FUZZ_STORAGE_BIN)
	@echo "== fuzzing storage CRUD for $(FUZZ_TIME)s =="
	$(FUZZ_STORAGE_BIN) -max_total_time=$(FUZZ_TIME) -print_final_stats=1 \
	    $(FUZZ_STORAGE_CORPUS)

fuzz-ntp-run: $(FUZZ_NTP_BIN)
	@echo "== fuzzing ntp_recv_cb for $(FUZZ_TIME)s =="
	$(FUZZ_NTP_BIN) -max_total_time=$(FUZZ_TIME) -print_final_stats=1 \
	    $(FUZZ_NTP_CORPUS)

# --- Curated backup_import() seed generator ---------------------------------
# Regenerates the committed fuzz_backup_corpus/ blobs: one per backup_import
# validation/write branch, with the VALID cases carrying a real CRC computed by
# the firmware's own lfs_crc (linked from libs/littlefs/lfs_util.c). Run after
# changing the wire format or the curated set. See test/gen_backup_seeds.c.
GEN_BACKUP_BIN  := $(BUILD)/gen_backup_seeds
GEN_BACKUP_SRCS := gen_backup_seeds.c $(ROOT)/libs/littlefs/lfs_util.c

$(GEN_BACKUP_BIN): $(GEN_BACKUP_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) -g -O1 $(WHOLE_DEFS) $(INCLUDES) $(GEN_BACKUP_SRCS) -o $@

gen-backup-seeds: $(GEN_BACKUP_BIN)
	@echo "== regenerating curated backup_import seed corpus =="
	$(GEN_BACKUP_BIN) $(FUZZ_BACKUP_CORPUS)

# --- Fuzzer coverage of the parse/logic surface ----------------------------
# REPEATABLE measurement of how much of the fuzzable surface the committed
# corpora exercise. Each fuzzer's sources are rebuilt with gcc --coverage and
# -DFUZZ_REPLAY (no libFuzzer runtime) and linked with the plain replay main
# (fuzz_replay.c), producing cov_console / cov_backup. Each replays its corpus
# once per file, then lcov captures + merges both runs and restricts the report
# to the nine surface files. cov_console and cov_backup share storage.c/backup.c
# sources; because their .gcno/.gcda are prefixed with the output basename they
# do not collide, and capturing the whole obj dir merges the two runs' hits per
# source file (the union coverage we want). Output: a per-file + per-function
# summary to stdout and to $(FUZZ_COV_OUT) (gitignored under coverage/).
FUZZ_COV_OBJ := $(COV_DIR)/fuzzobj
FUZZ_COV_OUT := $(COV_DIR)/fuzz-surface.txt

# The fuzzable parse/logic surface (HW-I/O wrappers are out of scope).
SURFACE_SRCS := serial/commands.c serial/commands_system.c serial/commands_keys.c \
                serial/commands_network.c serial/commands_backup.c serial/console.c \
                storage/storage.c storage/backup.c shared/totp.c network/ntp.c
SURFACE_ABS  := $(addprefix $(REPO_ROOT)/,$(SURFACE_SRCS))

# Same lcov config as `coverage`, plus function coverage so the per-function
# summary and the uncovered-function list are populated.
FCOV_LCOV := lcov $(LCOV_RC) --rc function_coverage=1 $(LCOV_IGNORE)

fuzz-cov: check-submodules | $(FUZZ_COV_OBJ)
	@echo "== fuzz-cov: building replay binaries (gcc --coverage) =="
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(FUZZ_DEFS) -DFUZZ_REPLAY $(FUZZ_INCLUDES) \
	    $(FUZZ_SRCS) fuzz_replay.c $(FUZZ_LIBS) -o $(FUZZ_COV_OBJ)/cov_console
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(FUZZ_DEFS) -DFUZZ_REPLAY $(FUZZ_INCLUDES) \
	    $(FUZZ_BACKUP_SRCS) fuzz_replay.c -o $(FUZZ_COV_OBJ)/cov_backup
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) -DFUZZ_REPLAY $(FUZZ_TOTP_INCLUDES) \
	    $(FUZZ_TOTP_SRCS) fuzz_replay.c $(FUZZ_TOTP_LIBS) -o $(FUZZ_COV_OBJ)/cov_totp
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(FUZZ_DEFS) -DFUZZ_REPLAY $(FUZZ_INCLUDES) \
	    $(FUZZ_STORAGE_SRCS) fuzz_replay.c -o $(FUZZ_COV_OBJ)/cov_storage
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) -DFUZZ_REPLAY $(FUZZ_INCLUDES) \
	    $(FUZZ_NTP_SRCS) fuzz_replay.c -o $(FUZZ_COV_OBJ)/cov_ntp
	@echo "== fuzz-cov: replaying corpora =="
	$(FUZZ_COV_OBJ)/cov_console $(FUZZ_CORPUS)
	$(FUZZ_COV_OBJ)/cov_backup $(FUZZ_BACKUP_CORPUS)
	$(FUZZ_COV_OBJ)/cov_totp $(FUZZ_TOTP_CORPUS)
	$(FUZZ_COV_OBJ)/cov_storage $(FUZZ_STORAGE_CORPUS)
	$(FUZZ_COV_OBJ)/cov_ntp $(FUZZ_NTP_CORPUS)
	@echo "== fuzz-cov: capturing + merging coverage =="
	$(FCOV_LCOV) --capture --initial --directory $(FUZZ_COV_OBJ) \
	    --output-file $(COV_DIR)/fuzz-base.info
	$(FCOV_LCOV) --capture --directory $(FUZZ_COV_OBJ) \
	    --output-file $(COV_DIR)/fuzz-run.info
	$(FCOV_LCOV) --add-tracefile $(COV_DIR)/fuzz-base.info \
	    --add-tracefile $(COV_DIR)/fuzz-run.info \
	    --output-file $(COV_DIR)/fuzz-merged.info
	@echo "== fuzz-cov: extracting the surface files =="
	$(FCOV_LCOV) --extract $(COV_DIR)/fuzz-merged.info $(SURFACE_ABS) \
	    --output-file $(COV_DIR)/fuzz-surface.info
	@echo "== fuzz-cov: surface summary (also written to $(FUZZ_COV_OUT)) =="
	@{ \
	  echo "hslock fuzzer coverage of the parse/logic surface"; \
	  echo "corpora: $(FUZZ_CORPUS) (console) + $(FUZZ_BACKUP_CORPUS) (backup)"; \
	  echo; \
	  $(FCOV_LCOV) --list $(COV_DIR)/fuzz-surface.info; \
	  echo; \
	  echo "Uncovered functions across the surface:"; \
	  awk -F'[:,]' '\
	    /^SF:/   { sf=$$2; sub(/.*\/(serial|storage|shared|network)\//,"",sf) } \
	    /^FNA:/  { if ($$3==0) print "  " sf "  " $$4 } \
	    /^FNDA:/ { if ($$2==0) print "  " sf "  " $$3 }' \
	    $(COV_DIR)/fuzz-surface.info | sort || true; \
	} | tee $(FUZZ_COV_OUT)
	@echo "== fuzz-cov OK: $(FUZZ_COV_OUT) =="

$(FUZZ_COV_OBJ):
	mkdir -p $(FUZZ_COV_OBJ)

$(BUILD):
	mkdir -p $(BUILD)

$(COV_DIR)/obj:
	mkdir -p $(COV_DIR)/obj

clean:
	rm -rf $(BUILD) $(COV_DIR) *.gcno *.gcda
