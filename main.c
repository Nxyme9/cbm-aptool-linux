/* main.c - Linux-native CBMUsbDisk tool entry point
 *
 * Modes:
 *   cbm-tool                 self-test (crypto/container/pacing/layout/nand logic)
 *   cbm-tool <blockdev>      self-test + real-device validation (read-only layout,
 *                             then safe read/write/restore on unpartitioned tail)
 *   cbm-tool container <path> [options]
 *                            read/decrypt/inspect/re-encrypt one 85688-byte
 *                            container; write only with --write-back/--output
 *   cbm-tool diff <a.plain> <b.plain> [--context N]
 *                            byte diff + entropy delta + heatmap, offline
 *   cbm-tool fuzz <container> --mutate N --rounds N --seed N [--out <dir>]
 *                            deterministic offline mutation corpus
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "tea_crypto.h"
#include "cbm_backend.h"
#include "tea_native.h"
#include "cbm_container.h"
#include "cbm_file.h"
#include "cbm_inspect.h"
#include "paced_write.h"
#include "usb_mass.h"
#include "cbm_layout.h"
#include "nand_info.h"
#include "cbm_diff.h"
#include "cbm_decode.h"
#include "cbm_fuzz.h"

/* Published RE artifact key (see .gitleaks.toml allowlist). */
static const char CBM_TEA_KEY[] = "1a2b3c4d5e6fTENG";

/* Parse crypto backend flags once, before either mode branches. Recognised
 * flags are stripped from argv so container mode never treats them as unknown
 * options; the choice is stored for tea_init() via cbm_backend_set(). */
static int parse_backend_flags(int argc, char **argv) {
    int backend = CBM_BACKEND_NATIVE; /* native is the no-PE default */
    int out = 1;                      /* preserve argv[0] */
    for (int i = 1; i < argc; i++) {
        int parsed;
        if (cbm_backend_from_arg(argv[i], &parsed) == 0)
            backend = parsed;         /* last flag wins */
        else
            argv[out++] = argv[i];
    }
    argv[out] = NULL;
    cbm_backend_set(backend);
    return out;
}

static void print_backend(void) {
    if (cbm_backend_get() == CBM_BACKEND_PE)
        printf("Crypto backend: PE harness (cross-check)\n");
    else
        printf("Crypto backend: native (clean-room)\n");
}

/* PE mode only: report whether the clean-room cipher matches the vendor
 * oracle. Runs BEFORE tea_init() because the selfcheck maps and unmaps the PE
 * at 0x400000 itself and would otherwise clobber the live backend mapping. */
static void print_pe_selfcheck(const char *pe_path) {
    if (cbm_backend_get() != CBM_BACKEND_PE || access(pe_path, F_OK) != 0)
        return; /* a missing PE is reported by tea_init() as a hard error */
    printf("PE self-check: %s\n",
           tea_native_selfcheck(pe_path) == 0
               ? "PASS (native byte-identical to PE)"
               : "FAIL (native differs from PE)");
}

static int selftest(void) {
    printf("=== Self-Test ===\n");
    print_backend();
    const char *pe_path = getenv("CBM_PE_PATH");
    if (!pe_path || !pe_path[0]) pe_path = "/tmp/opencode/ap.exe";
    print_pe_selfcheck(pe_path);
    if (tea_init(pe_path) != 0) {
        if (cbm_backend_get() == CBM_BACKEND_PE)
            fprintf(stderr, "Failed to initialize crypto: PE harness '%s' could not load\n",
                    pe_path);
        else
            fprintf(stderr, "Failed to initialize crypto: native backend unavailable\n");
        return 1;
    }
    printf("Crypto initialized\n");

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
        "  --min-string N   minimum printable string length (default 4)\n"
        "  --dump-plain <p> write decrypted body (85687 bytes) to file <p>\n"
        "  --inject <p>     replace decrypted body with exact-size file <p> before re-encrypt\n",
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
    const char *dump_plain = NULL;
    const char *inject = NULL;
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
        } else if (strcmp(a, "--dump-plain") == 0) {
            if (++i >= argc || !argv[i][0]) {
                fprintf(stderr, "Error: --dump-plain needs a file path\n");
                print_container_usage(argv[0]);
                return 1;
            }
            dump_plain = argv[i];
        } else if (strcmp(a, "--inject") == 0) {
            if (++i >= argc || !argv[i][0]) {
                fprintf(stderr, "Error: --inject needs a file path\n");
                print_container_usage(argv[0]);
                return 1;
            }
            inject = argv[i];
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
    print_backend();
    printf("Target type: %s; offset: %lld bytes\n",
           cbm_file_is_blockdev(path) ? "block device" : "regular file", offset);
    if (output) printf("Output file: %s (offset 0)\n", output);
    if (write_back) printf("Write-back: enabled\n");
    if (dump_plain) printf("Dump plaintext: %s\n", dump_plain);
    if (inject) printf("Inject plaintext: %s\n", inject);

    const char *pe_path = getenv("CBM_PE_PATH");
    if (!pe_path || !pe_path[0]) pe_path = "/tmp/opencode/ap.exe";
    if (cbm_backend_get() == CBM_BACKEND_PE)
        printf("Loading TEA cores from PE: %s\n", pe_path);
    print_pe_selfcheck(pe_path);
    if (tea_init(pe_path) != 0) {
        if (cbm_backend_get() == CBM_BACKEND_PE)
            fprintf(stderr, "Error: failed to initialize crypto (TEA PE '%s' could not load); cannot proceed\n",
                    pe_path);
        else
            fprintf(stderr, "Error: failed to initialize crypto (native backend); cannot proceed\n");
        return 1;
    }
    printf("Crypto initialized\n");

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

    if (inject) {
        FILE *inf = fopen(inject, "rb");
        if (!inf) {
            fprintf(stderr, "Error: cannot open inject file '%s': %s\n", inject, strerror(errno));
            goto out;
        }
        if (fseeko(inf, 0, SEEK_END) != 0) {
            fprintf(stderr, "Error: cannot seek inject file '%s'\n", inject);
            fclose(inf);
            goto out;
        }
        long long inject_size = ftello(inf);
        if (inject_size < 0 || inject_size != (long long)body_len) {
            fprintf(stderr, "Error: inject file '%s' must be exactly %zu bytes (got %lld)\n",
                    inject, body_len, inject_size);
            fclose(inf);
            goto out;
        }
        if (fseeko(inf, 0, SEEK_SET) != 0) {
            fprintf(stderr, "Error: cannot rewind inject file '%s'\n", inject);
            fclose(inf);
            goto out;
        }
        size_t got = fread(plain + CBM_HEADER_SIZE, 1, body_len, inf);
        int inject_err = ferror(inf);
        if (fclose(inf) != 0) inject_err = 1;
        if (inject_err || got != body_len) {
            fprintf(stderr, "Error: failed to read %zu bytes from inject file '%s'\n", body_len, inject);
            goto out;
        }
        printf("Injected %zu bytes from '%s' into plaintext body\n", body_len, inject);
    }

    if (dump_plain) {
        if (cbm_file_is_blockdev(dump_plain)) {
            fprintf(stderr, "Error: --dump-plain must not target a block device\n");
            goto out;
        }
        FILE * outf = fopen(dump_plain, "wb");
        if (!outf) {
            fprintf(stderr, "Error: cannot open dump file '%s': %s\n", dump_plain, strerror(errno));
            goto out;
        }
        size_t put = fwrite(plain + CBM_HEADER_SIZE, 1, body_len, outf);
        int dump_err = (put != body_len || fflush(outf) != 0);
        if (fclose(outf) != 0) dump_err = 1;
        if (dump_err) {
            fprintf(stderr, "Error: failed to write %zu bytes to dump file '%s'\n", body_len, dump_plain);
            goto out;
        }
        printf("Dumped %zu bytes of plaintext to '%s'\n", body_len, dump_plain);
    }

    puts("\n--- Plaintext inspection ---");
    fputs("[stats]\n", stdout);
    cbm_inspect_stats(plain + CBM_HEADER_SIZE, body_len, stdout);
    fputs("\n[hex dump]\n", stdout);
    /* Design asks for first 256 + last 64 bytes (= 320 total), but
     * cbm_inspect_hex splits a cap symmetrically and cannot express an
     * asymmetric head/tail. Using 640 (= 320 head + 320 tail) shows a
     * symmetric window with double the design's byte count. */
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
    if (!inject) {
        if (memcmp(reenc + CBM_HEADER_SIZE, orig_cipher + CBM_HEADER_SIZE, body_len) != 0) {
            fprintf(stderr, "Error: re-encrypted body differs from original ciphertext\n");
            goto out;
        }
        printf("In-memory encrypt(decrypt(x)) == x OK (%zu body bytes, header preserved)\n",
               body_len);
    } else {
        /* For an injected body, equality to the original ciphertext is not
         * expected; prove the re-encryption is reversible instead. */
        unsigned char check[CBM_CONTAINER_SIZE];
        memcpy(check, reenc, CBM_CONTAINER_SIZE);
        if (cbm_cbc_decrypt(check + CBM_HEADER_SIZE, body_len, CBM_TEA_KEY) != 0) {
            fprintf(stderr, "Error: TEA decryption of re-encrypted body failed\n");
            goto out;
        }
        if (memcmp(check + CBM_HEADER_SIZE, plain + CBM_HEADER_SIZE, body_len) != 0) {
            fprintf(stderr, "Error: re-encrypted body is not reversible to injected plaintext\n");
            goto out;
        }
        printf("In-memory re-encryption of modified body OK (%zu body bytes, reversible, header preserved)\n",
               body_len);
    }

    if (output) {
        if (cbm_file_is_blockdev(output)) {
            fprintf(stderr, "Error: --output must not target a block device (use --write-back for in-place device writes)\n");
            goto out;
        }
        printf("\nWriting re-encrypted container to '%s' ...\n", output);
        if (cbm_file_write(output, 0, reenc, CBM_CONTAINER_SIZE) != 0) {
            fprintf(stderr, "Error: write to '%s' failed\n", output);
            goto out;
        }
        /* Read-back verification for --output (same proof as --write-back). */
        unsigned char verify_buf[CBM_CONTAINER_SIZE];
        if (cbm_file_read(output, 0, verify_buf, CBM_CONTAINER_SIZE) != 0) {
            fprintf(stderr, "Error: failed to read back '%s' for verification\n", output);
            goto out;
        }
        if (memcmp(verify_buf, reenc, CBM_CONTAINER_SIZE) != 0) {
            fprintf(stderr, "Error: read-back of '%s' differs from written data\n", output);
            goto out;
        }
        printf("Write + read-back verify OK (%d bytes)\n", CBM_CONTAINER_SIZE);
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

    printf("\nContainer mode: crypto roundtrip OK (no container authenticity claim)\n");
    rc = 0;
out:
    tea_cleanup();
    return rc;
}


/* ---- offline body diff mode -------------------------------------------- */

static void print_diff_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s diff <a.plain> <b.plain> [--context N]\n"
        "  --context N   merge spans separated by <= N bytes (default 3)\n",
        prog);
}

/* Whole-file read for plain bodies; no device path handling, exact allocation. */
static int read_plain_file(const char *path, unsigned char **buf, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseeko(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    off_t end = ftello(f);
    if (end < 0 || (unsigned long long)end > (unsigned long long)SIZE_MAX ||
        fseeko(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    unsigned char *data = (unsigned char *)malloc((size_t)end ? (size_t)end : 1u);
    if (!data) { fclose(f); return -1; }
    size_t got = end ? fread(data, 1, (size_t)end, f) : 0;
    int bad = ferror(f) || got != (size_t)end;
    fclose(f);
    if (bad) { free(data); return -1; }
    *buf = data;
    *len = (size_t)end;
    return 0;
}

/* Integer fixed-point text with a literal '.' is locale-independent. Values
 * come only from cbm_decode_entropy; no entropy math is duplicated here. */
static void print_body_entropy(const char *label, double value) {
    unsigned scaled = (unsigned)(value * 1000000.0 + 0.5);
    printf("%s %u.%06u\n", label, scaled / 1000000u, scaled % 1000000u);
}

static int diff_mode(int argc, char **argv) {
    const char *a_path = (argc >= 3) ? argv[2] : NULL;
    const char *b_path = (argc >= 4) ? argv[3] : NULL;
    long long ctx = 3;

    if (!a_path || !b_path) {
        fprintf(stderr, "Error: diff requires two plain body files\n");
        print_diff_usage(argv[0]);
        return 2;
    }
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--context") == 0) {
            if (++i >= argc || parse_nonneg_ll(argv[i], &ctx) != 0 ||
                (unsigned long long)ctx > (unsigned long long)SIZE_MAX) {
                fprintf(stderr, "Error: --context needs a non-negative integer\n");
                print_diff_usage(argv[0]);
                return 2;
            }
        } else {
            fprintf(stderr, "Error: unknown diff option '%s'\n", argv[i]);
            print_diff_usage(argv[0]);
            return 2;
        }
    }

    unsigned char *a = NULL, *b = NULL;
    size_t alen = 0, blen = 0;
    if (read_plain_file(a_path, &a, &alen) != 0) {
        fprintf(stderr, "Error: cannot read plain body '%s'\n", a_path);
        free(a);
        return 1;
    }
    if (read_plain_file(b_path, &b, &blen) != 0) {
        fprintf(stderr, "Error: cannot read plain body '%s'\n", b_path);
        free(a); free(b);
        return 1;
    }

    printf("=== Diff Mode: %s vs %s ===\n", a_path, b_path);
    printf("body sizes: a=%zu b=%zu context=%lld\n", alen, blen, ctx);
    puts("--- Body entropy (bits/byte) ---");
    print_body_entropy("entropy_body_a", cbm_decode_entropy(a, alen));
    print_body_entropy("entropy_body_b", cbm_decode_entropy(b, blen));
    puts("--- Changed ranges / heatmap ---");
    cbm_diff_print(a, alen, b, blen, (size_t)ctx, stdout);
    free(a); free(b);
    return 0;
}

/* ---- deterministic offline fuzz mode ----------------------------------- */

static void print_fuzz_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s fuzz <container> --mutate N --rounds N --seed N [--out <dir>]\n"
        "  --out <dir>   existing directory for round-NNN.cbm and manifest.txt\n"
        "                (required: fuzz never writes outside --out)\n",
        prog);
}

/* Strict non-negative integer bounded to unsigned (the fuzz API's type). */
static int parse_unsigned_arg(const char *s, unsigned long *out) {
    if (!s || !*s || !out) return -1;
    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (errno != 0 || !end || end == s || *end != '\0' || v > UINT_MAX) return -1;
    *out = v;
    return 0;
}

static int fuzz_mode(int argc, char **argv) {
    const char *path = (argc >= 3) ? argv[2] : NULL;
    const char *out = NULL;
    unsigned long mutate = 0, rounds = 0, seed = 0;
    int have_mutate = 0, have_rounds = 0, have_seed = 0;

    if (!path) {
        fprintf(stderr, "Error: fuzz requires a container path\n");
        print_fuzz_usage(argv[0]);
        return 2;
    }
    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--mutate") == 0 || strcmp(a, "--rounds") == 0 ||
            strcmp(a, "--seed") == 0) {
            unsigned long *slot = (strcmp(a, "--mutate") == 0) ? &mutate
                                : (strcmp(a, "--rounds") == 0) ? &rounds : &seed;
            if (++i >= argc || parse_unsigned_arg(argv[i], slot) != 0) {
                fprintf(stderr, "Error: %s needs a non-negative integer\n", a);
                print_fuzz_usage(argv[0]);
                return 2;
            }
            if (slot == &mutate) have_mutate = 1;
            else if (slot == &rounds) have_rounds = 1;
            else have_seed = 1;
        } else if (strcmp(a, "--out") == 0) {
            if (++i >= argc || !argv[i][0]) {
                fprintf(stderr, "Error: --out needs a directory path\n");
                print_fuzz_usage(argv[0]);
                return 2;
            }
            out = argv[i];
        } else {
            fprintf(stderr, "Error: unknown fuzz option '%s'\n", a);
            print_fuzz_usage(argv[0]);
            return 2;
        }
    }
    if (!have_mutate || !have_rounds || !have_seed || !out) {
        fprintf(stderr, "Error: fuzz requires --mutate, --rounds, --seed and --out\n");
        print_fuzz_usage(argv[0]);
        return 2;
    }

    const char *pe_path = getenv("CBM_PE_PATH");
    if (!pe_path || !pe_path[0]) pe_path = "/tmp/opencode/ap.exe";
    printf("=== Fuzz Mode: %s ===\n", path);
    print_backend();
    if (cbm_backend_get() == CBM_BACKEND_PE)
        printf("Loading TEA cores from PE: %s\n", pe_path);
    print_pe_selfcheck(pe_path);
    if (tea_init(pe_path) != 0) {
        fprintf(stderr, "Error: failed to initialize crypto backend\n");
        return 1;
    }
    printf("Crypto initialized\n");

    char err[256];
    err[0] = '\0';
    if (cbm_fuzz_run(path, out, (unsigned)mutate, (unsigned)rounds,
                     seed, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err[0] ? err : "fuzz run failed");
        tea_cleanup();
        return 1;
    }
    printf("Fuzz corpus: seed %lu, %u rounds x %u mutations -> '%s'\n",
           seed, (unsigned)rounds, (unsigned)mutate, out);
    printf("Fuzz mode: corpus verified (decrypt -> mutate -> encrypt -> decrypt)\n");
    tea_cleanup();
    return 0;
}

int main(int argc, char **argv) {
    argc = parse_backend_flags(argc, argv);
    printf("CBMUsbDisk Linux-Native Tool v1.0\n");
    printf("==================================\n\n");
    /* Container/fuzz modes load the crypto backend themselves and must not run
     * the selftest first (that would init/cleanup TEA twice). diff is pure
     * byte analysis and needs no crypto at all. All three subcommands are
     * dispatched before the device path so nothing can be mistaken for a
     * block-device argument. */
    if (argc >= 2 && strcmp(argv[1], "container") == 0)
        return container_mode(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "diff") == 0)
        return diff_mode(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "fuzz") == 0)
        return fuzz_mode(argc, argv);

    if (selftest() != 0) return 1;
    if (argc > 1) return verify_device(argv[1]);
    printf("\nAll systems operational.\n");
    return 0;
}
