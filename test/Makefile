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

.PHONY: all asan valgrind coverage clean

all: asan

# --- ASan + UBSan -----------------------------------------------------------
asan: $(BUILD)/asan_secret_qr $(BUILD)/asan_base64
	@echo "== running asan/ubsan harnesses =="
	$(BUILD)/asan_secret_qr
	$(BUILD)/asan_base64
	@echo "== asan OK =="

$(BUILD)/asan_secret_qr: $(SECRET_QR_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(ASAN_FLAGS) $(INCLUDES) $(SECRET_QR_SRCS) -o $@

$(BUILD)/asan_base64: $(BASE64_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(ASAN_FLAGS) $(INCLUDES) $(BASE64_SRCS) -o $@

# --- Valgrind ---------------------------------------------------------------
valgrind: $(BUILD)/vg_secret_qr $(BUILD)/vg_base64
	@echo "== running harnesses under valgrind =="
	valgrind --error-exitcode=99 --leak-check=full -q $(BUILD)/vg_secret_qr
	valgrind --error-exitcode=99 --leak-check=full -q $(BUILD)/vg_base64
	@echo "== valgrind OK =="

$(BUILD)/vg_secret_qr: $(SECRET_QR_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(VG_FLAGS) $(INCLUDES) $(SECRET_QR_SRCS) -o $@

$(BUILD)/vg_base64: $(BASE64_SRCS) | $(BUILD)
	$(CC) $(CSTD) $(WARN) $(VG_FLAGS) $(INCLUDES) $(BASE64_SRCS) -o $@

# --- Coverage (lcov/genhtml HTML report for the harness-exercised modules) --
# Build & run the real harnesses with --coverage (producing .gcda), capture
# the run data, filter to first-party sources (dropping the vendored libs and
# the test harnesses themselves), and render coverage/html/ with branches.
# The report covers exactly the modules the harnesses exercise (base32.c,
# base64.c, random.c); HW-only firmware is not built host-side and is absent.
coverage: | $(COV_DIR)/obj
	@echo "== coverage: building + running harnesses =="
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(INCLUDES) $(SECRET_QR_SRCS) \
	    -o $(COV_DIR)/obj/cov_secret_qr
	$(CC) $(CSTD) $(WARN) $(COV_FLAGS) $(INCLUDES) $(BASE64_SRCS) \
	    -o $(COV_DIR)/obj/cov_base64
	@echo "== coverage: running instrumented harnesses =="
	$(COV_DIR)/obj/cov_secret_qr
	$(COV_DIR)/obj/cov_base64
	@echo "== coverage: capturing run data =="
	$(LCOV) --capture --directory $(COV_DIR)/obj \
	    --output-file $(COV_DIR)/run.info
	@echo "== coverage: filtering to first-party sources =="
	$(LCOV) --extract $(COV_DIR)/run.info '$(REPO_ROOT)/*' \
	    --output-file $(COV_DIR)/first.info
	$(LCOV) --remove $(COV_DIR)/first.info \
	    '*/libs/qrcodegen/*' '*/libs/littlefs/*' '*/test/*' '/usr/*' \
	    --output-file $(COV_DIR)/coverage.info
	@echo "== coverage: generating HTML report =="
	genhtml $(LCOV_RC) $(GENHTML_IGNORE) --branch-coverage \
	    --legend --title "hslock host coverage" \
	    --output-directory $(COV_DIR)/html $(COV_DIR)/coverage.info
	@echo "== coverage OK: report at $(COV_DIR)/html/index.html =="

$(BUILD):
	mkdir -p $(BUILD)

$(COV_DIR)/obj:
	mkdir -p $(COV_DIR)/obj

clean:
	rm -rf $(BUILD) $(COV_DIR) *.gcno *.gcda
