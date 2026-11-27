# Linux-native CBMUsbDisk tool
# Crypto: pure-C clean-room cipher by default; PE harness via --pe-crypto
# Container/pacing: native C

CC = gcc
# Phase 0 / H1: exploitation mitigations plus a stricter warning set.
# -Werror is applied only to format-security: the remaining warnings stay
# informative so a new source file cannot silently break the build.
CFLAGS = -m32 -O2 -g -Wall -Wextra -Wformat=2 -Werror=format-security \
         -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wvla \
         -fstack-protector-strong -fstack-clash-protection -D_FORTIFY_SOURCE=2
LDFLAGS = -m32 -Wl,-z,relro,-z,now

# Phase 0 / H2-H3: sanitizer and coverage-guided fuzzing.
# These rebuild in place, run every binary, then restore the normal build.
SAN_FLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer
FUZZ_SECONDS ?= 60
# Local `make ci` uses a short fuzz smoke; Actions uses the 60s default.
CI_FUZZ_SECONDS ?= 5
FUZZ_CC = clang
FUZZ_CFLAGS = -m32 -O1 -g -Wall -Wextra -fsanitize=fuzzer,address \
              -fno-omit-frame-pointer -I.
FUZZ_BINS = fuzz_tea fuzz_container fuzz_decode fuzz_layout fuzz_scan

TARGET = cbm-tool
CLI = pe-call
TESTS = test_tea test_tea_native test_cbm test_paced test_usb_mass test_layout test_nand test_cbm_file test_cbm_inspect test_pelib test_cdb_shim test_cbm_decode test_cbm_diff test_cbm_fuzz test_cbm_scan test_cbm_scan_report test_entropy_map test_png_write test_cbm_doctor test_cbm_tui test_vault test_trust test_json_cli.sh test_challenge.sh test_mesh_scan test_exfat_carver
# Python MCP test is a source file: keep it out of TESTS so `clean` cannot rm it.
MCP_TESTS = test_mcp_server.py

# PE path is supplied at runtime through CBM_PE_PATH; no build-time default.

all: $(TARGET) $(CLI) $(TESTS) test_recon

$(TARGET): main.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h cdb_shim.c cdb_shim.h cbm_container.c cbm_file.c cbm_fuzz.c cbm_fuzz.h cbm_diff.c cbm_diff.h cbm_decode.c cbm_decode.h cbm_inspect.c paced_write.c usb_mass.c cbm_layout.c nand_info.c cbm_scan.c cbm_scan.h cbm_scan_report.c cbm_scan_report.h png_write.c png_write.h entropy_map.c entropy_map.h cbm_doctor.c cbm_doctor.h cbm_tui.c cbm_tui.h cli_json.c cli_json.h recon.c recon.h vault.c vault.h trust.c trust.h
	$(CC) $(CFLAGS) -o $@ main.c tea_crypto.c tea_native.c pelib.c cdb_shim.c cbm_container.c cbm_file.c cbm_fuzz.c cbm_diff.c cbm_decode.c cbm_inspect.c paced_write.c usb_mass.c cbm_layout.c nand_info.c cbm_scan.c cbm_scan_report.c png_write.c entropy_map.c cbm_doctor.c cbm_tui.c cli_json.c recon.c vault.c trust.c $(LDFLAGS) -lz

test_tea: test_tea.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_tea.c tea_crypto.c tea_native.c pelib.c $(LDFLAGS)

test_tea_native: test_tea_native.c tea_native.c tea_crypto.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -I. -o $@ test_tea_native.c tea_native.c tea_crypto.c pelib.c $(LDFLAGS)

test_cbm: test_cbm.c cbm_container.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_cbm.c cbm_container.c tea_crypto.c tea_native.c pelib.c $(LDFLAGS)

# Wave 5Q: derived vault format. Prints its own summary line, so it stays
# outside the frozen `Results:` count sums (same convention as test_recon).
test_vault: test_vault.c vault.c vault.h cbm_container.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h cbm_file.c cbm_file.h paced_write.c cli_json.c cli_json.h
	$(CC) $(CFLAGS) -o $@ test_vault.c vault.c cbm_container.c tea_crypto.c tea_native.c pelib.c cbm_file.c paced_write.c cli_json.c $(LDFLAGS)

# Wave 5P: BadUSB trust scanner. Also prints its own summary line, so it stays
# outside the frozen `Results:` count sums.
test_trust: test_trust.c trust.c trust.h cli_json.c cli_json.h cbm_file.c cbm_file.h paced_write.c paced_write.h
	$(CC) $(CFLAGS) -o $@ test_trust.c trust.c cli_json.c cbm_file.c paced_write.c $(LDFLAGS)

test_paced: test_paced.c paced_write.c
	$(CC) $(CFLAGS) -o $@ test_paced.c paced_write.c $(LDFLAGS)

test_usb_mass: test_usb_mass.c usb_mass.c
	$(CC) $(CFLAGS) -o $@ test_usb_mass.c usb_mass.c $(LDFLAGS)

test_layout: test_layout.c cbm_layout.c
	$(CC) $(CFLAGS) -o $@ test_layout.c cbm_layout.c $(LDFLAGS)

test_nand: test_nand.c nand_info.c
	$(CC) $(CFLAGS) -o $@ test_nand.c nand_info.c $(LDFLAGS)

test_cbm_file: test_cbm_file.c cbm_file.c paced_write.c
	$(CC) $(CFLAGS) -o $@ test_cbm_file.c cbm_file.c paced_write.c $(LDFLAGS)

test_cbm_inspect: test_cbm_inspect.c cbm_inspect.c
	$(CC) $(CFLAGS) -o $@ test_cbm_inspect.c cbm_inspect.c $(LDFLAGS)

test_cbm_decode: test_cbm_decode.c cbm_decode.c
	$(CC) $(CFLAGS) -o $@ test_cbm_decode.c cbm_decode.c $(LDFLAGS)

test_cbm_diff: test_cbm_diff.c cbm_diff.c cbm_diff.h cbm_decode.c cbm_decode.h
	$(CC) $(CFLAGS) -o $@ test_cbm_diff.c cbm_diff.c cbm_decode.c $(LDFLAGS)

test_cbm_fuzz: test_cbm_fuzz.c cbm_fuzz.c cbm_fuzz.h cbm_container.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h cbm_file.c paced_write.c
	$(CC) $(CFLAGS) -o $@ test_cbm_fuzz.c cbm_fuzz.c cbm_container.c tea_crypto.c tea_native.c pelib.c cbm_file.c paced_write.c $(LDFLAGS)

test_pelib: test_pelib.c pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_pelib.c pelib.c $(LDFLAGS)

# Wave 5M: read-only PE recon. Not in TESTS: its own summary line stays
# outside the frozen `Results:` count sums (see scripts/check-counts.sh).
test_recon: test_recon.c recon.c recon.h
	$(CC) $(CFLAGS) -o $@ test_recon.c recon.c $(LDFLAGS)

# Wave 5E: synthetic-PE DeviceIoControl capture (no device, no vendor PE)
test_cdb_shim: test_cdb_shim.c cdb_shim.c cdb_shim.h pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_cdb_shim.c cdb_shim.c pelib.c $(LDFLAGS)

test_cbm_scan: test_cbm_scan.c cbm_scan.c cbm_scan.h cbm_fuzz.c cbm_fuzz.h cbm_container.c cbm_decode.c cbm_decode.h cbm_file.c paced_write.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_cbm_scan.c cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c cbm_file.c paced_write.c tea_crypto.c tea_native.c pelib.c $(LDFLAGS)

test_cbm_scan_report: test_cbm_scan_report.c cbm_scan_report.c cbm_scan_report.h cbm_scan.c cbm_scan.h cbm_fuzz.c cbm_fuzz.h cbm_container.c cbm_decode.c cbm_decode.h cbm_file.c paced_write.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_cbm_scan_report.c cbm_scan_report.c cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c cbm_file.c paced_write.c tea_crypto.c tea_native.c pelib.c $(LDFLAGS)

test_entropy_map: test_entropy_map.c entropy_map.c entropy_map.h cbm_decode.c cbm_decode.h cbm_file.c cbm_file.h cbm_layout.c cbm_layout.h paced_write.c
	$(CC) $(CFLAGS) -o $@ test_entropy_map.c entropy_map.c cbm_decode.c cbm_file.c cbm_layout.c paced_write.c $(LDFLAGS)

test_png_write: test_png_write.c png_write.c png_write.h
	$(CC) $(CFLAGS) -o $@ test_png_write.c png_write.c $(LDFLAGS) -lz

# Wave 5D: doctor repair (links file/layout/scan-report for the shared alias guard)
test_cbm_doctor: test_cbm_doctor.c cbm_doctor.c cbm_doctor.h cbm_layout.c cbm_layout.h cbm_file.c cbm_file.h cbm_scan_report.c cbm_scan_report.h cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c paced_write.c tea_crypto.c tea_native.c pelib.c cli_json.c cli_json.h
	$(CC) $(CFLAGS) -o $@ test_cbm_doctor.c cbm_doctor.c cbm_layout.c cbm_file.c cbm_scan_report.c cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c paced_write.c tea_crypto.c tea_native.c pelib.c cli_json.c $(LDFLAGS)

# Wave 5D: TUI render is pure (no device/file I/O linkage required)
test_cbm_tui: test_cbm_tui.c cbm_tui.c cbm_tui.h
	$(CC) $(CFLAGS) -o $@ test_cbm_tui.c cbm_tui.c $(LDFLAGS)

pe-call: pe-call.c pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ pe-call.c pelib.c $(LDFLAGS)

test_mesh_scan: test_mesh_scan.c mesh_scan.c mesh_scan.h cbm_scan.c cbm_scan.h cbm_fuzz.c cbm_fuzz.h cbm_container.c cbm_decode.c cbm_decode.h cbm_file.c paced_write.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h cli_json.c cli_json.h
	$(CC) $(CFLAGS) -o $@ test_mesh_scan.c mesh_scan.c cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c cbm_file.c paced_write.c tea_crypto.c tea_native.c pelib.c cli_json.c $(LDFLAGS)

test_exfat_carver: test_exfat_carver.c exfat_carver.c exfat_carver.h cbm_file.c cbm_file.h cbm_layout.c cbm_layout.h cli_json.c cli_json.h paced_write.c paced_write.h
	$(CC) $(CFLAGS) -o $@ test_exfat_carver.c exfat_carver.c cbm_file.c cbm_layout.c cli_json.c paced_write.c $(LDFLAGS)

test: $(TESTS) $(TARGET) test_recon
	@mkdir -p /tmp/opencode
	./test_tea && ./test_tea_native && ./test_cbm && ./test_paced && ./test_usb_mass && ./test_layout && ./test_nand && ./test_cbm_file && ./test_cbm_inspect && ./test_pelib && ./test_cdb_shim && ./test_cbm_decode && sh ./test_backend_cli.sh && ./test_cbm_diff && ./test_cbm_fuzz && ./test_cbm_scan && ./test_cbm_scan_report && ./test_entropy_map && ./test_png_write && ./test_cbm_doctor && ./test_cbm_tui && ./test_vault && ./test_trust && sh ./test_json_cli.sh && python3 $(MCP_TESTS) && python3 test_fwemu.py && ./test_recon && sh ./test_challenge.sh && ./test_mesh_scan && ./test_exfat_carver

test-mcp: $(TARGET)
	python3 $(MCP_TESTS)

# Wave 5L: synthetic firmware model, stdlib Python only (no emulator/device)
test-fwemu:
	python3 test_fwemu.py

# Wave 5M: recon suite on its own; CBM_PE_PATH is optional (PE cases skip).
test-recon: test_recon
	./test_recon

# CLI-level backend selection: no device access; fixtures go under /tmp/opencode.
test-cli: $(TARGET)
	sh ./test_backend_cli.sh

# H2: rebuild every binary with ASan+UBSan, run the whole suite, then restore
# the normal build. The trap guarantees restoration even on a failing test.
ASAN_CFLAGS = $(CFLAGS) $(SAN_FLAGS) -O1
ASAN_LDFLAGS = $(LDFLAGS) $(SAN_FLAGS)

asan:
	@set -e; \
	trap '$(MAKE) clean >/dev/null 2>&1 || true; $(MAKE) CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" all >/dev/null 2>&1 || true' EXIT; \
	$(MAKE) clean; \
	ASAN_OPTIONS=detect_leaks=1 $(MAKE) CFLAGS="$(ASAN_CFLAGS)" LDFLAGS="$(ASAN_LDFLAGS)" test

# H3: five libFuzzer harnesses. clang is required because gcc has no libFuzzer.
fuzz_tea: fuzz/fuzz_tea.c tea_native.c tea_native.h
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ fuzz/fuzz_tea.c tea_native.c

fuzz_container: fuzz/fuzz_container.c cbm_container.c tea_crypto.c tea_native.c pelib.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ fuzz/fuzz_container.c cbm_container.c tea_crypto.c tea_native.c pelib.c

fuzz_decode: fuzz/fuzz_decode.c cbm_decode.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ fuzz/fuzz_decode.c cbm_decode.c

fuzz_layout: fuzz/fuzz_layout.c cbm_layout.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ fuzz/fuzz_layout.c cbm_layout.c

fuzz_scan: fuzz/fuzz_scan.c cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c cbm_file.c paced_write.c tea_crypto.c tea_native.c pelib.c
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ fuzz/fuzz_scan.c cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c cbm_file.c paced_write.c tea_crypto.c tea_native.c pelib.c

fuzz: $(FUZZ_BINS)
	@set -e; \
	mkdir -p /tmp/opencode/fuzz-artifacts; \
	for b in $(FUZZ_BINS); do \
	  echo "== $$b ($(FUZZ_SECONDS)s) =="; \
	  ASAN_OPTIONS=detect_leaks=0 ./$$b -max_total_time=$(FUZZ_SECONDS) \
	    -artifact_prefix=/tmp/opencode/fuzz-artifacts/$$b- \
	    -print_final_stats=1 > /tmp/opencode/fuzz-$$b.log 2>&1 || \
	    { tail -30 /tmp/opencode/fuzz-$$b.log; exit 1; }; \
	  tail -3 /tmp/opencode/fuzz-$$b.log; \
	done

# Phase 0 exit gate: local mirror of the Actions jobs. No device, no PE, no
# network. All logs land under /tmp/opencode for provenance. Rejection-test
# fixtures contain /dev/sd* strings; the audit below checks actual opens and
# block ioctls in tests instead of forbidding the strings themselves.
ci:
	@set -e; \
	$(MAKE) clean >/dev/null; \
	$(MAKE) all > /tmp/opencode/ci-build.log 2>&1; \
	if grep -n 'warning:' /tmp/opencode/ci-build.log; then \
	  echo 'ci: compiler warning detected'; exit 1; \
	fi; \
	echo 'ci: build OK (0 warnings)'; \
	$(MAKE) test > /tmp/opencode/ci-test.log 2>&1; \
	awk '/^Results:/ {p+=$$2; f+=$$4; s+=$$6; n++} END {printf "ci suite: %d Results lines, %d passed, %d failed, %d skipped\n", n, p, f, s}' /tmp/opencode/ci-test.log; \
	echo 'ci: suite OK'; \
	$(MAKE) asan > /tmp/opencode/ci-asan.log 2>&1; \
	echo 'ci: asan OK'; \
	$(MAKE) fuzz FUZZ_SECONDS=$(CI_FUZZ_SECONDS) > /tmp/opencode/ci-fuzz.log 2>&1; \
	echo 'ci: fuzz smoke OK'; \
	shellcheck test_backend_cli.sh scripts/check-counts.sh; \
	echo 'ci: shellcheck OK'; \
	gitleaks detect --source . --no-git --redact > /tmp/opencode/ci-gitleaks.log 2>&1; \
	echo 'ci: gitleaks OK'; \
	sh scripts/check-counts.sh --self-test > /tmp/opencode/ci-counts-selftest.log 2>&1; \
	echo 'ci: count verifier self-test OK'; \
	if grep -rnE '(open|fopen|openat)\([^;]*"/dev/' --include='*.c' --include='*.h' .; then \
	  echo 'ci: literal device open in source'; exit 1; \
	fi; \
	if grep -rnE 'ioctl\([^;]*BLKGETSIZE64' --include='test_*.c' --include='*.sh' .; then \
	  echo 'ci: block ioctl in test'; exit 1; \
	fi; \
	echo 'ci: device-open audit OK'; \
	echo 'ci: PASS'

clean:
	rm -f $(TARGET) $(CLI) $(filter-out %.sh,$(TESTS)) test_recon $(FUZZ_BINS) *.o

.PHONY: all test test-mcp test-fwemu test-recon test-cli asan fuzz $(FUZZ_BINS) ci clean
