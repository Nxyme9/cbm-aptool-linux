# Linux-native CBMUsbDisk tool
# Crypto: pure-C clean-room cipher by default; PE harness via --pe-crypto
# Container/pacing: native C

CC = gcc
CFLAGS = -m32 -Wall -Wextra -O2 -g
LDFLAGS = -m32

TARGET = cbm-tool
CLI = pe-call
TESTS = test_tea test_tea_native test_cbm test_paced test_usb_mass test_layout test_nand test_cbm_file test_cbm_inspect test_pelib test_cbm_decode test_cbm_diff test_cbm_fuzz test_cbm_scan test_cbm_scan_report test_entropy_map test_png_write test_cbm_doctor test_cbm_tui

# PE path is supplied at runtime through CBM_PE_PATH; no build-time default.

all: $(TARGET) $(CLI) $(TESTS)

$(TARGET): main.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h cbm_container.c cbm_file.c cbm_fuzz.c cbm_fuzz.h cbm_diff.c cbm_diff.h cbm_decode.c cbm_decode.h cbm_inspect.c paced_write.c usb_mass.c cbm_layout.c nand_info.c cbm_scan.c cbm_scan.h cbm_scan_report.c cbm_scan_report.h png_write.c png_write.h entropy_map.c entropy_map.h cbm_doctor.c cbm_doctor.h cbm_tui.c cbm_tui.h
	$(CC) $(CFLAGS) -o $@ main.c tea_crypto.c tea_native.c pelib.c cbm_container.c cbm_file.c cbm_fuzz.c cbm_diff.c cbm_decode.c cbm_inspect.c paced_write.c usb_mass.c cbm_layout.c nand_info.c cbm_scan.c cbm_scan_report.c png_write.c entropy_map.c cbm_doctor.c cbm_tui.c $(LDFLAGS) -lz

test_tea: test_tea.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_tea.c tea_crypto.c tea_native.c pelib.c $(LDFLAGS)

test_tea_native: test_tea_native.c tea_native.c tea_crypto.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -I. -o $@ test_tea_native.c tea_native.c tea_crypto.c pelib.c $(LDFLAGS)

test_cbm: test_cbm.c cbm_container.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_cbm.c cbm_container.c tea_crypto.c tea_native.c pelib.c $(LDFLAGS)

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

test_cbm_scan: test_cbm_scan.c cbm_scan.c cbm_scan.h cbm_fuzz.c cbm_fuzz.h cbm_container.c cbm_decode.c cbm_decode.h cbm_file.c paced_write.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_cbm_scan.c cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c cbm_file.c paced_write.c tea_crypto.c tea_native.c pelib.c $(LDFLAGS)

test_cbm_scan_report: test_cbm_scan_report.c cbm_scan_report.c cbm_scan_report.h cbm_scan.c cbm_scan.h cbm_fuzz.c cbm_fuzz.h cbm_container.c cbm_decode.c cbm_decode.h cbm_file.c paced_write.c tea_crypto.c tea_native.c cbm_backend.h pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ test_cbm_scan_report.c cbm_scan_report.c cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c cbm_file.c paced_write.c tea_crypto.c tea_native.c pelib.c $(LDFLAGS)

test_entropy_map: test_entropy_map.c entropy_map.c entropy_map.h cbm_decode.c cbm_decode.h cbm_file.c cbm_file.h cbm_layout.c cbm_layout.h paced_write.c
	$(CC) $(CFLAGS) -o $@ test_entropy_map.c entropy_map.c cbm_decode.c cbm_file.c cbm_layout.c paced_write.c $(LDFLAGS)

test_png_write: test_png_write.c png_write.c png_write.h
	$(CC) $(CFLAGS) -o $@ test_png_write.c png_write.c $(LDFLAGS) -lz

# Wave 5D: doctor repair (links file/layout/scan-report for the shared alias guard)
test_cbm_doctor: test_cbm_doctor.c cbm_doctor.c cbm_doctor.h cbm_layout.c cbm_layout.h cbm_file.c cbm_file.h cbm_scan_report.c cbm_scan_report.h cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c paced_write.c tea_crypto.c tea_native.c pelib.c
	$(CC) $(CFLAGS) -o $@ test_cbm_doctor.c cbm_doctor.c cbm_layout.c cbm_file.c cbm_scan_report.c cbm_scan.c cbm_fuzz.c cbm_container.c cbm_decode.c paced_write.c tea_crypto.c tea_native.c pelib.c $(LDFLAGS)

# Wave 5D: TUI render is pure (no device/file I/O linkage required)
test_cbm_tui: test_cbm_tui.c cbm_tui.c cbm_tui.h
	$(CC) $(CFLAGS) -o $@ test_cbm_tui.c cbm_tui.c $(LDFLAGS)

pe-call: pe-call.c pelib.c pelib.h
	$(CC) $(CFLAGS) -o $@ pe-call.c pelib.c $(LDFLAGS)

test: $(TESTS) $(TARGET)
	./test_tea && ./test_tea_native && ./test_cbm && ./test_paced && ./test_usb_mass && ./test_layout && ./test_nand && ./test_cbm_file && ./test_cbm_inspect && ./test_pelib && ./test_cbm_decode && sh ./test_backend_cli.sh && ./test_cbm_diff && ./test_cbm_fuzz && ./test_cbm_scan && ./test_cbm_scan_report && ./test_entropy_map && ./test_png_write && ./test_cbm_doctor && ./test_cbm_tui

# CLI-level backend selection: no device access; fixtures go under /tmp/opencode.
test-cli: $(TARGET)
	sh ./test_backend_cli.sh

clean:
	rm -f $(TARGET) $(CLI) $(TESTS) *.o

.PHONY: all test test-cli clean
