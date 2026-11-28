# Pico inspector (Wave 5O)

A standalone, read-only CBM container inspector for an RP2040 board. The
embedded codec is a POSIX-free subset of the same clean-room cipher used by the
host tool: the recovered tables, the three-core transform and the key schedule
are identical to `tea_native.c`, with the PE loader, `mmap`, `stdio` device I/O
and host-only helpers removed.

## Verified on-host (no SDK, no board)

    sh pico/test.sh

`pico/test.sh` compiles the exact firmware sources (`tea_core.c`,
`inspector.c`) with plain `cc` into `/tmp/opencode/test_pico_host` and runs
`pico/test_host.c`. It reports:

    test_pico_host: 18 passed, 0 failed

The check set covers:

- four encryption vectors and four decryption vectors (zeros, 0..15 bytes,
  ASCII string, 0xff pattern);
- a 23-byte roundtrip that proves the trailing partial block is untouched;
- fail-closed rejection of short/long keys and a null buffer;
- the byte-0 encrypted flag, Shannon entropy of a constant and a maximal
  alphabet, printable-string counting and hexdump rendering;
- `pico_inspect()` report fields.

Reference vectors are frozen in `pico/test_vectors.h`. They were measured from
`tea_native_encrypt()` on this tree with `TEA_NATIVE_KEY` (generator kept
outside the repo under `/tmp/opencode/gen_vectors.c`); the portable subset must
match them byte-for-byte. Values:

| input | first bytes of ciphertext |
| --- | --- |
| 8 zero bytes | `e6 62 54 b5 da 09 fb 31` |
| bytes 0x00..0x0f | `3d d2 4f 1e 5c 7d 94 0e f6 90 cf cc 84 dd ff 02` |
| 24 ASCII bytes | `69 bd 21 39 9d 08 b9 9a 9e c5 95 36 a9 21 62 86 8d fe be fa 02 fe ed 34` |
| 32 x 0xff | `bb 2d 47 d8 e7 e6 89 cc` repeated four times |

`test_pico_host` prints its own summary line and is deliberately outside the
frozen `Results:` count sums (same convention as `test_vault`). It does not
change the documented 194/188 pass counts.

## Building the firmware (gated)

The Pico SDK is **not** vendored or downloaded. Provide it yourself:

    export PICO_SDK_PATH=/path/to/pico-sdk
    sh pico/test.sh

When the SDK is present, `pico/test.sh` configures and builds
`/tmp/opencode/pico-build` via `pico/CMakeLists.txt`, producing
`cbm_pico_inspector.uf2`. When it is absent the script prints:

    SKIP pico firmware build: PICO_SDK_PATH unset or SDK missing

This environment has no SDK (`PICO_SDK_PATH` unset) and no confirmed board, so
the firmware image has **not** been compiled or flashed here. Source and host
vectors are committed; the hardware build is an explicit, documented gate, not
a claimed closure.

## Operating the board

The firmware accepts exactly 85688 container bytes over USB serial, then
decrypts in RAM and prints the header, body length, Shannon entropy, printable
string count, hex-line count and the first plaintext block. Two buttons:

- **GPIO 5** — print a bounded plaintext hex dump of the first 256 bytes;
- **GPIO 6** — full-body encrypt/decrypt roundtrip check.

Short or oversized streams fail closed. The board never opens, mounts or
writes to any storage device; the plaintext dump goes to USB serial, and an
operator who wants a file captures the serial output on the host. No vendor
binary or device CDB is involved.

## Honest gaps

1. **USB mass-storage host input is not implemented.** The current firmware
   takes the container over USB serial, not from a thumb drive. Closure gate:
   a board with a USB host-capable wiring plus a TinyUSB hostMSC/SD-card reader
   whose read path is validated against a synthetic container on real
   hardware.
2. **Firmware build and flash are unverified here.** Gate: install the Pico
   SDK, set `PICO_SDK_PATH`, build with `sh pico/test.sh`, flash a board and
   run the two button checks on a synthetic container.
3. **No on-device timing or power measurement.** Gate: logic analyser / power
   meter on real hardware; not claimed by the host vector test.
4. **Partial-block behaviour is host-proven, not board-proven.** The 23-byte
   vector confirms the trailing 7 bytes are preserved by the codec; the board
   only ever sees exact 85688-byte containers, so this is a codec statement,
   not a firmware statement.

The host-side hostMSC read path in `usb_mass.c` remains Linux-native and is
unrelated to the RP2040 firmware; no code is shared across that boundary.
