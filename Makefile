# Linux-native CBMUsbDisk tool
# Crypto: mmap-at-ImageBase PE harness (32-bit x86, runs natively on x86-64 Linux)
# Container/pacing: native C

CC = gcc
CFLAGS = -m32 -Wall -Wextra -O2 -g
LDFLAGS = -m32

TARGET = cbm-tool
TESTS = test_tea test_tea_native test_cbm test_paced test_usb_mass test_layout test_nand test_cbm_file test_cbm_inspect

# PE path overridable via CBM_PE_PATH env var; defaults to the APTool location.
PE ?= /tmp/opencode/ap.exe

all: $(TARGET) $(TESTS)

$(TARGET): main.c tea_crypto.c cbm_container.c cbm_file.c cbm_inspect.c paced_write.c usb_mass.c cbm_layout.c nand_info.c
	$(CC) $(CFLAGS) -o $@ main.c tea_crypto.c cbm_container.c cbm_file.c cbm_inspect.c paced_write.c usb_mass.c cbm_layout.c nand_info.c $(LDFLAGS)

test_tea: test_tea.c tea_crypto.c
	$(CC) $(CFLAGS) -o $@ test_tea.c tea_crypto.c $(LDFLAGS)

test_tea_native: test_tea_native.c tea_native.c
	$(CC) $(CFLAGS) -I. -o $@ test_tea_native.c tea_native.c $(LDFLAGS)

test_cbm: test_cbm.c cbm_container.c tea_crypto.c
	$(CC) $(CFLAGS) -o $@ test_cbm.c cbm_container.c tea_crypto.c $(LDFLAGS)

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

test: $(TESTS)
	./test_tea && ./test_tea_native && ./test_cbm && ./test_paced && ./test_usb_mass && ./test_layout && ./test_nand && ./test_cbm_file && ./test_cbm_inspect

clean:
	rm -f $(TARGET) $(TESTS) *.o

.PHONY: all test clean
