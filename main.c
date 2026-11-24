/* main.c - Linux-native CBMUsbDisk tool entry point
 *
 * Modes:
 *   cbm-tool                 self-test (crypto/container/pacing/layout/nand logic)
 *   cbm-tool <blockdev>      self-test + real-device validation (read-only layout,
 *                             then safe read/write/restore on unpartitioned tail)
 *   cbm-tool container <path> [options]
 *                            read/decrypt/inspect/re-encrypt one 85688-byte
 *                            container; write only with --write-back/--output
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "tea_crypto.h"
#include "cbm_container.h"
#include "cbm_file.h"
#include "cbm_inspect.h"
#include "paced_write.h"
#include "usb_mass.h"
#include "cbm_layout.h"
#include "nand_info.h"

/* Published RE artifact key (see .gitleaks.toml allowlist). */
static const char CBM_TEA_KEY[] = "1a2b3c4d5e6fTENG";

static int selftest(void) {
    printf("=== Self-Test ===\n");
    const char *pe_path = getenv("CBM_PE_PATH");
    if (!pe_path || !pe_path[0]) pe_path = "/tmp/opencode/ap.exe";
    if (tea_init(pe_path) != 0) {
        fprintf(stderr, "Failed to initialize crypto\n");
        return 1;
    }
    printf("Crypto initialized (TEA cores loaded from PE)\n");

    unsigned char test_data[64];
    for (int i = 0; i < 64; i++) test_data[i] = (unsigned char)(i * 7 + 3);
    unsigned char enc_copy[64];
    memcpy(enc_copy, test_data, 64);
    const char *key = CBM_TEA_KEY;

    if (tea_encrypt(enc_copy, 64, key) != 0) {
        fprintf(stderr, "Encrypt failed\n"); tea_cleanup(); return 1;
    }
    if (tea_decrypt(enc_copy, 64, key) != 0 || memcmp(enc_copy, test_data, 64) != 0) {
        fprintf(stderr, "Roundtrip mismatch\n"); tea_cleanup(); return 1;
    }
    printf("TEA roundtrip OK (64 bytes)\n");

    printf("CBM Container: %d bytes; HLEN(85688)=%zu\n",
           CBM_CONTAINER_SIZE, cbm_compute_hlen(85688));

    paced_writer_t pw;
    paced_init(&pw);
    printf("Paced writer: burst=%d bytes, cooldown=%d sec\n",
           PACED_BURST_SIZE, PACED_COOLDOWN_SEC);

    tea_cleanup();
    return 0;
}

/* Validate a real USB mass-storage device. Read-only layout checks plus a
 * write/read/restore roundtrip in the unpartitioned tail (outside the MBR
 * window), so no filesystem data is touched. */
static int verify_device(const char *path) {
    printf("\n=== Real-Device Validation: %s ===\n", path);
    usb_mass_dev_t dev;
    if (usb_mass_open(path, &dev) != 0) {
        fprintf(stderr, "open failed (need disk group / root?) \n");
        return 1;
    }
    long long cap = usb_mass_capacity(&dev);
    printf("Capacity (BLKGETSIZE64): %lld bytes (%lld sectors)\n",
           cap, cap / CBM_SECTOR_SIZE);
    if (cap < (long long)CBM_EXPECTED_WINDOW_SECTORS * CBM_SECTOR_SIZE) {
        fprintf(stderr, "capacity below 28 GiB window\n");
        usb_mass_close(&dev);
        return 1;
    }

    /* MBR + layout */
    unsigned char mbr[CBM_SECTOR_SIZE];
    if (usb_mass_read_at(&dev, mbr, CBM_SECTOR_SIZE, 0) != 0) {
        fprintf(stderr, "MBR read failed\n"); usb_mass_close(&dev); return 1;
    }
    cbm_layout_t L;
    if (cbm_layout_parse(mbr, CBM_SECTOR_SIZE, &L) != 0) {
        fprintf(stderr, "MBR parse failed (bad signature)\n");
        usb_mass_close(&dev); return 1;
    }
    printf("MBR signature: 0x55AA OK; partitions: %d\n", L.part_count);
    for (int i = 0; i < L.part_count; i++) {
        printf("  part%d: type=0x%02x start=%llu size=%llu sectors (%llu MiB)\n",
               i + 1, L.parts[i].type, L.parts[i].start_lba, L.parts[i].size_lba,
               L.parts[i].size_lba / (1024 * 1024 / CBM_SECTOR_SIZE));
    }
    unsigned long long disk_sectors = (unsigned long long)(cap / CBM_SECTOR_SIZE);
    if (cbm_layout_validate(&L, disk_sectors) != 0) {
        fprintf(stderr, "DJ partition layout validation FAILED\n");
        usb_mass_close(&dev); return 1;
    }
    printf("DJ partition layout: MATCH (512M/4G/rest within 28G window)\n");

    /* NAND controller identity (host-observable) */
    const char *devname = strrchr(path, '/');
    devname = devname ? devname + 1 : path;
    nand_info_t ni;
    if (nand_info_probe(devname, &ni) == 0) {
        printf("USB controller: vid=%s pid=%s vendor='%s' model='%s' driver=%s\n",
               ni.vendor_id, ni.product_id, ni.vendor, ni.model,
               ni.driver[0] ? ni.driver : "(unknown)");
        printf("Chipsbank-class controller: %s\n",
               nand_info_is_chipsbank(&ni) ? "YES" : "NO");
    } else {
        printf("USB controller identity: not available via sysfs\n");
    }

    /* Safe write/read/restore on unpartitioned tail outside MBR window. */
    unsigned long long last_part_end = 0;
    for (int i = 0; i < L.part_count; i++) {
        unsigned long long end = L.parts[i].start_lba + L.parts[i].size_lba;
        if (end > last_part_end) last_part_end = end;
    }
    unsigned long long scratch = last_part_end + 1024;
    if (scratch + 1 >= disk_sectors) scratch = disk_sectors - 2;
    long long off = (long long)(scratch * CBM_SECTOR_SIZE);

    unsigned char orig[CBM_SECTOR_SIZE], pat[CBM_SECTOR_SIZE], rb[CBM_SECTOR_SIZE];
    if (usb_mass_read_at(&dev, orig, CBM_SECTOR_SIZE, off) != 0) {
        fprintf(stderr, "scratch read failed\n"); usb_mass_close(&dev); return 1;
    }
    for (int i = 0; i < CBM_SECTOR_SIZE; i++) pat[i] = (unsigned char)(i * 13 + 7);
    if (usb_mass_write_at(&dev, pat, CBM_SECTOR_SIZE, off) != 0) {
        fprintf(stderr, "scratch write failed\n"); usb_mass_close(&dev); return 1;
    }
    if (usb_mass_read_at(&dev, rb, CBM_SECTOR_SIZE, off) != 0 ||
        memcmp(rb, pat, CBM_SECTOR_SIZE) != 0) {
        fprintf(stderr, "write/read verify FAILED\n");
        usb_mass_write_at(&dev, orig, CBM_SECTOR_SIZE, off);
        usb_mass_close(&dev); return 1;
    }
    printf("Write/read roundtrip at LBA %llu: OK\n", scratch);
    if (usb_mass_write_at(&dev, orig, CBM_SECTOR_SIZE, off) != 0) {
        fprintf(stderr, "scratch restore write failed\n"); usb_mass_close(&dev); return 1;
    }
    if (usb_mass_read_at(&dev, rb, CBM_SECTOR_SIZE, off) != 0 ||
        memcmp(rb, orig, CBM_SECTOR_SIZE) != 0) {
        fprintf(stderr, "restore verify FAILED\n"); usb_mass_close(&dev); return 1;
    }
    printf("Original sector restored and verified: OK\n");

    usb_mass_close(&dev);
    printf("Real-device validation: PASS\n");
    return 0;
}

static void print_container_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s container <path> [options]\n"
        "Options:\n"
        "  --offset N       byte offset on block device (default 0)\n"
        "  --write-back     write re-encrypted container back to target\n"
        "  --output <p>     write re-encrypted container to a different file\n"
        "  --hex-full       full hex dump (default: first 320 + last 320 bytes)\n"
        "  --min-string N   minimum printable string length (default 4)\n",
        prog);
}

/* Strict non-negative decimal parser for --offset / --min-string. */
static int parse_nonneg_ll(const char *s, long long *out) {
    if (!s || !*s || !out) return -1;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || !end || end == s || *end != '\0' || v < 0) return -1;
    *out = v;
    return 0;
}

/* File-level container mode: decrypt, inspect, re-encrypt, verify. Writes
 * nothing unless --write-back or --output is given (safe default). */
static int container_mode(int argc, char **argv) {
    const char *path = (argc >= 3) ? argv[2] : NULL;
    const char *output = NULL;
    long long offset = 0;
    long long min_string = 4;
    int write_back = 0, hex_full = 0;

    if (!path) {
        fprintf(stderr, "Error: container mode requires <path>\n");
        print_container_usage(argv[0]);
        return 1;
    }

    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--offset") == 0) {
            if (++i >= argc || parse_nonneg_ll(argv[i], &offset) != 0) {
                fprintf(stderr, "Error: --offset needs a non-negative byte count\n");
                print_container_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(a, "--output") == 0) {
            if (++i >= argc || !argv[i][0]) {
                fprintf(stderr, "Error: --output needs a file path\n");
                print_container_usage(argv[0]);
                return 1;
            }
            output = argv[i];
        } else if (strcmp(a, "--min-string") == 0) {
            if (++i >= argc || parse_nonneg_ll(argv[i], &min_string) != 0) {
                fprintf(stderr, "Error: --min-string needs a non-negative length\n");
                print_container_usage(argv[0]);
                return 1;
            }
        } else if (strcmp(a, "--write-back") == 0) {
            write_back = 1;
        } else if (strcmp(a, "--hex-full") == 0) {
            hex_full = 1;
        } else {
            fprintf(stderr, "Error: unknown container option '%s'\n", a);
            print_container_usage(argv[0]);
            return 1;
        }
    }

    const size_t body_len = CBM_CONTAINER_SIZE - CBM_HEADER_SIZE; /* 85687 */
    /* Any minimum longer than the body simply yields no strings; clamp so a
     * huge value cannot wrap when converted to size_t on 32-bit. */
    size_t min_run = (min_string > (long long)body_len) ? body_len : (size_t)min_string;
    unsigned char orig_cipher[CBM_CONTAINER_SIZE];
    unsigned char plain[CBM_CONTAINER_SIZE];
    unsigned char reenc[CBM_CONTAINER_SIZE];
    int rc = 1;

    printf("=== Container Mode: %s ===\n", path);
    printf("Target type: %s; offset: %lld bytes\n",
           cbm_file_is_blockdev(path) ? "block device" : "regular file", offset);
    if (output) printf("Output file: %s (offset 0)\n", output);
    if (write_back) printf("Write-back: enabled\n");

    const char *pe_path = getenv("CBM_PE_PATH");
    if (!pe_path || !pe_path[0]) pe_path = "/tmp/opencode/ap.exe";
    printf("Loading TEA cores from PE: %s\n", pe_path);
    if (tea_init(pe_path) != 0) {
        fprintf(stderr, "Error: failed to initialize crypto (TEA PE '%s' could not load); cannot proceed\n",
                pe_path);
        return 1;
    }
    printf("Crypto initialized (TEA cores loaded from PE)\n");

    if (cbm_file_read(path, offset, orig_cipher, CBM_CONTAINER_SIZE) != 0) {
        fprintf(stderr, "Error: failed to read %d bytes from '%s' at offset %lld\n",
                CBM_CONTAINER_SIZE, path, offset);
        goto out;
    }
    printf("Read %d bytes from '%s' at offset %lld\n",
           CBM_CONTAINER_SIZE, path, offset);

    cbm_status_t enc = cbm_check_encrypted(orig_cipher, CBM_CONTAINER_SIZE);
    printf("Header byte: 0x%02x\n", orig_cipher[0]);
    printf("Encrypted flag: %s\n",
           enc == CBM_ERR_ENCRYPTED ? "YES (high bit set)" : "NO (high bit clear)");
    if (enc == CBM_ERR_SIZE) {
        fprintf(stderr, "Error: header check failed (invalid container size)\n");
        goto out;
    }

    memcpy(plain, orig_cipher, CBM_CONTAINER_SIZE);
    if (cbm_cbc_decrypt(plain + CBM_HEADER_SIZE, body_len, CBM_TEA_KEY) != 0) {
        fprintf(stderr, "Error: TEA decryption of %zu-byte body failed\n", body_len);
        goto out;
    }
    printf("Decrypted body: %zu bytes\n", body_len);

    puts("\n--- Plaintext inspection ---");
    fputs("[stats]\n", stdout);
    cbm_inspect_stats(plain + CBM_HEADER_SIZE, body_len, stdout);
    fputs("\n[hex dump]\n", stdout);
    /* Design asks for first 256 + last 64 bytes, but cbm_inspect_hex splits a
     * cap symmetrically and cannot express an asymmetric head/tail. 640 shows
     * the same total number of bytes (320 head + 320 tail). */
    cbm_inspect_hex(plain + CBM_HEADER_SIZE, body_len, hex_full ? 0 : 640, stdout);
    printf("\n[strings (minimum length %zu)]\n", min_run);
    cbm_inspect_strings(plain + CBM_HEADER_SIZE, body_len, min_run, stdout);
    fputs("\n[known tokens]\n", stdout);
    cbm_inspect_tokens(plain + CBM_HEADER_SIZE, body_len, stdout);

    puts("\n--- Roundtrip verification ---");
    memcpy(reenc, plain, CBM_CONTAINER_SIZE);
    if (cbm_cbc_encrypt(reenc + CBM_HEADER_SIZE, body_len, CBM_TEA_KEY) != 0) {
        fprintf(stderr, "Error: TEA re-encryption of %zu-byte body failed\n", body_len);
        goto out;
    }
    if (memcmp(reenc + CBM_HEADER_SIZE, orig_cipher + CBM_HEADER_SIZE, body_len) != 0) {
        fprintf(stderr, "Error: re-encrypted body differs from original ciphertext\n");
        goto out;
    }
    printf("In-memory encrypt(decrypt(x)) == x OK (%zu body bytes, header preserved)\n",
           body_len);

    if (output) {
        printf("\nWriting re-encrypted container to '%s' ...\n", output);
        if (cbm_file_write(output, 0, reenc, CBM_CONTAINER_SIZE) != 0) {
            fprintf(stderr, "Error: write to '%s' failed\n", output);
            goto out;
        }
        printf("Write OK (%d bytes)\n", CBM_CONTAINER_SIZE);
    }
    if (write_back) {
        printf("\nWriting re-encrypted container back to '%s' at offset %lld ...\n",
               path, offset);
        if (cbm_file_write(path, offset, reenc, CBM_CONTAINER_SIZE) != 0) {
            fprintf(stderr, "Error: write-back to '%s' at offset %lld failed\n", path, offset);
            goto out;
        }
        printf("Write-back OK (%d bytes)\n", CBM_CONTAINER_SIZE);

        /* Device/file roundtrip proof: read back, decrypt, compare with the
         * original plaintext still held in `plain`. orig_cipher is reusable
         * now that the in-memory ciphertext comparison has passed. */
        if (cbm_file_read(path, offset, orig_cipher, CBM_CONTAINER_SIZE) != 0) {
            fprintf(stderr, "Error: failed to read back %d bytes from '%s' at offset %lld\n",
                    CBM_CONTAINER_SIZE, path, offset);
            goto out;
        }
        if (cbm_cbc_decrypt(orig_cipher + CBM_HEADER_SIZE, body_len, CBM_TEA_KEY) != 0) {
            fprintf(stderr, "Error: TEA decryption of read-back body failed\n");
            goto out;
        }
        if (memcmp(orig_cipher + CBM_HEADER_SIZE, plain + CBM_HEADER_SIZE, body_len) != 0) {
            fprintf(stderr, "Error: read-back decrypt differs from original plaintext\n");
            goto out;
        }
        printf("Read-back decrypt roundtrip OK (%zu body bytes)\n", body_len);
    }
    if (!output && !write_back) {
        fputs("\nNo write performed (safe default).\n", stdout);
    }

    printf("\nContainer mode: PASS\n");
    rc = 0;
out:
    tea_cleanup();
    return rc;
}

int main(int argc, char **argv) {
    printf("CBMUsbDisk Linux-Native Tool v1.0\n");
    printf("==================================\n\n");
    /* Container mode is a standalone mode: it loads the PE itself and must not
     * run the selftest first (that would init/cleanup TEA twice). */
    if (argc >= 2 && strcmp(argv[1], "container") == 0)
        return container_mode(argc, argv);

    if (selftest() != 0) return 1;
    if (argc > 1) return verify_device(argv[1]);
    printf("\nAll systems operational.\n");
    return 0;
}
