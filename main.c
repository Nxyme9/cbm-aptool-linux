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
 *   cbm-tool scan <device> [--start LBA] [--end LBA] [--chunk MiB]
 *                            [--carve <dir>] [--json <report>]
 *                            read-only forensic candidate scan; optional
 *                            carved containers and deterministic JSON report
 *   cbm-tool heatmap <device|image> [--block MiB] [--width N]
 *                            [--out <png>] [--json <path>]
 *                            read-only block-entropy PNG + JSON sidecar;
 *                            writes nothing without --out/--json
 *   cbm-tool doctor <device|image> [--repair-mbr --yes --backup <file>]
 *                            [--window-gib 26|27|28]
 *                            default READ-ONLY diagnosis; repair only with
 *                            all three flags plus a verified backup
 *   cbm-tool tui <device|image>
 *                            strictly read-only ANSI live view; q/ESC quits,
 *                            never opens the target for writing
 *   cbm-tool cdb-capture <pe-path> --out <capture-file> [--export <name>]
 *                            [--arg0 N] [--arg1 N] [--arg2 N]
 *                            shimmed PE import capture; writes only --out
 *   cbm-tool recon <pe> [--top N] [--all] [--json]
 *                            read-only heuristic ranking of candidate
 *                            block-cipher functions in a vendor PE
 *   cbm-tool trust <device|observation.json> --baseline <json> [--json]
 *                            read-only host-observable fingerprint compare;
 *                            fails closed without a baseline, never opens
 *                            the device for I/O, never claims firmware
 *   cbm-tool telemetry --listen :PORT [--device PATH] [--state-file PATH]
 *                            read-only Prometheus exporter; loopback by default
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <termios.h>
#include <linux/fs.h>

#include "tea_crypto.h"
#include "cbm_backend.h"
#include "tea_native.h"
#include "cbm_container.h"
#include "vault.h"
#include "trust.h"
#include "telemetry.h"
#include "cbm_file.h"
#include "cbm_inspect.h"
#include "paced_write.h"
#include "usb_mass.h"
#include "cbm_layout.h"
#include "nand_info.h"
#include "cbm_diff.h"
#include "cbm_decode.h"
#include "cbm_fuzz.h"
#include "cbm_scan.h"
#include "cbm_scan_report.h"
#include "entropy_map.h"
#include "png_write.h"
#include "cbm_doctor.h"
#include "cbm_tui.h"
#include "cli_json.h"
#include "cdb_shim.h"
#include "recon.h"

/* Published RE artifact key (see .gitleaks.toml allowlist). */
static const char CBM_TEA_KEY[] = "1a2b3c4d5e6fTENG";

/* Strip bare --json before mode argument parsing. scan/heatmap keep the old
 * sidecar spelling: --json followed by a non-flag token is still a path, while
 * a final --json or one followed by another flag is the compact stdout form.
 * container/diff/fuzz/doctor have no sidecar, so --json is always bare.
 * Returns the updated argc and sets *json when a bare --json was removed. */
static int strip_json_flags(int argc, char **argv, int *json) {
    int sidecar = 0;
    if (argc >= 2)
        sidecar = (strcmp(argv[1], "scan") == 0 || strcmp(argv[1], "heatmap") == 0);
    *json = 0;
    for (int i = 2; i < argc;) {
        if (strcmp(argv[i], "--json") != 0) { i++; continue; }
        if (sidecar && i + 1 < argc && argv[i + 1][0] != '-') {
            i += 2; /* --json <path> sidecar: leave both tokens to the mode */
            continue;
        }
        *json = 1;
        for (int k = i; k + 1 < argc; k++) argv[k] = argv[k + 1];
        argv[--argc] = NULL;
    }
    return argc;
}

/* JSON mode runs the unchanged mode function with stdout pointed at a scratch
 * file (so human prose is suppressed without touching dozens of print sites)
 * and stderr pointed at a second scratch file. On success the one object the
 * mode emitted is copied to the real stdout; on failure that partial object is
 * discarded and a single error object is built from the captured human error.
 * stderr is always replayed byte-for-byte. Nothing here changes a mode's
 * return code or writes to the target. */
typedef struct {
    FILE *json_buf;
    FILE *err_buf;
    FILE *prose_sink;
    int saved_out;
    int saved_err;
} cbm_json_capture_t;

static void json_capture_restore(cbm_json_capture_t *c) {
    (void)fflush(stdout);
    (void)fflush(stderr);
    if (c->saved_out >= 0) {
        (void)dup2(c->saved_out, STDOUT_FILENO);
        (void)close(c->saved_out);
        c->saved_out = -1;
    }
    if (c->saved_err >= 0) {
        (void)dup2(c->saved_err, STDERR_FILENO);
        (void)close(c->saved_err);
        c->saved_err = -1;
    }
}

static int json_capture_start(cbm_json_capture_t *c) {
    c->json_buf = NULL;
    c->err_buf = NULL;
    c->prose_sink = NULL;
    c->saved_out = -1;
    c->saved_err = -1;
    c->json_buf = tmpfile();
    c->err_buf = tmpfile();
    c->prose_sink = tmpfile();
    if (!c->json_buf || !c->err_buf || !c->prose_sink) goto fail;
    (void)fflush(stdout);
    (void)fflush(stderr);
    c->saved_out = dup(STDOUT_FILENO);
    c->saved_err = dup(STDERR_FILENO);
    if (c->saved_out < 0 || c->saved_err < 0 ||
        dup2(fileno(c->prose_sink), STDOUT_FILENO) < 0 ||
        dup2(fileno(c->err_buf), STDERR_FILENO) < 0)
        goto fail;
    return 0;
fail:
    json_capture_restore(c);
    if (c->json_buf) (void)fclose(c->json_buf);
    if (c->err_buf) (void)fclose(c->err_buf);
    if (c->prose_sink) (void)fclose(c->prose_sink);
    c->json_buf = NULL;
    c->err_buf = NULL;
    c->prose_sink = NULL;
    return -1;
}

static void json_capture_copy(FILE *src, FILE *dst) {
    char buf[4096];
    size_t n;
    rewind(src);
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
        if (fwrite(buf, 1, n, dst) != n) break;
}

/* Flatten captured human errors into one escaped JSON string. */
static void json_capture_message(FILE *src, char *dst, size_t len) {
    size_t n = 0;
    if (!dst || !len) return;
    rewind(src);
    int ch;
    while (n + 1u < len && (ch = fgetc(src)) != EOF) {
        if (ch == '\n' || ch == '\r' || ch == '\t') ch = ' ';
        dst[n++] = (char)ch;
    }
    dst[n] = '\0';
    while (n > 0u && dst[n - 1u] == ' ') dst[--n] = '\0';
}

static void json_capture_finish(cbm_json_capture_t *c, int rc,
                                const char *command) {
    json_capture_restore(c);
    json_capture_copy(c->err_buf, stderr);
    (void)fflush(stderr);
    if (rc == 0) {
        json_capture_copy(c->json_buf, stdout);
    } else {
        char msg[1024];
        json_capture_message(c->err_buf, msg, sizeof(msg));
        cbm_json_error(stdout, command, msg[0] ? msg : "command failed");
    }
    (void)fflush(stdout);
    (void)fclose(c->json_buf);
    (void)fclose(c->err_buf);
    (void)fclose(c->prose_sink);
}

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

/* PE is an explicit opt-in: the only path comes from CBM_PE_PATH; there is no
 * compiled-in vendor default. Native mode never needs this value. */
static const char *pe_path_from_env(void) {
    const char *p = getenv("CBM_PE_PATH");
    return (p && *p) ? p : NULL;
}

/* PE mode only: report whether the clean-room cipher matches the vendor
 * oracle. Runs BEFORE tea_init() because the selfcheck maps and unmaps the PE
 * at 0x400000 itself and would otherwise clobber the live backend mapping. */
static void print_pe_selfcheck(const char *pe_path) {
    if (!pe_path || cbm_backend_get() != CBM_BACKEND_PE ||
        access(pe_path, F_OK) != 0)
        return; /* a missing PE is reported by tea_init() as a hard error */
    printf("PE self-check: %s\n",
           tea_native_selfcheck(pe_path) == 0
               ? "PASS (native byte-identical to PE)"
               : "FAIL (native differs from PE)");
}

static int selftest(void) {
    printf("=== Self-Test ===\n");
    print_backend();
    const char *pe_path = pe_path_from_env();
    if (cbm_backend_get() == CBM_BACKEND_PE && !pe_path) {
        fprintf(stderr, "Error: --pe-crypto requires CBM_PE_PATH (no vendor binary default)\n");
        return 1;
    }
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
    if (scratch + 1 >= disk_sectors) {
        fprintf(stderr, "no unpartitioned tail after last partition "
                        "(last part ends at LBA %llu, disk has %llu sectors)\n",
                last_part_end, disk_sectors);
        usb_mass_close(&dev); return 1;
    }
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
        if (usb_mass_write_at(&dev, orig, CBM_SECTOR_SIZE, off) != 0)
            fprintf(stderr, "write/read verify FAILED; restore write also FAILED "
                            "(test pattern may remain at LBA %llu)\n", scratch);
        else
            fprintf(stderr, "write/read verify FAILED\n");
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
static int container_mode(int argc, char **argv, FILE *json_out) {
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

    const char *pe_path = pe_path_from_env();
    if (cbm_backend_get() == CBM_BACKEND_PE && !pe_path) {
        fprintf(stderr, "Error: --pe-crypto requires CBM_PE_PATH (no vendor binary default)\n");
        return 1;
    }
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
    if (json_out) {
        cbm_json_t j;
        cbm_json_object_begin(&j, json_out, "container", "ok");
        cbm_json_field_string(&j, "path", path);
        cbm_json_field_string(&j, "backend", cbm_backend_get() == CBM_BACKEND_PE
                              ? "pe" : "native");
        cbm_json_field_u64(&j, "header_byte", orig_cipher[0]);
        cbm_json_field_bool(&j, "encrypted", enc == CBM_ERR_ENCRYPTED);
        cbm_json_field_u64(&j, "body_len", (unsigned long long)body_len);
        cbm_json_field_fixed6(&j, "entropy_body",
                              cbm_decode_entropy(plain + CBM_HEADER_SIZE, body_len));
        cbm_json_field_bool(&j, "roundtrip_ok", 1);
        cbm_json_end(&j);
    }
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

static int diff_mode(int argc, char **argv, FILE *json_out) {
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
    if (json_out) {
        /* With context 0 at most one range per two common-prefix bytes plus
         * the trailing length range: one allocation is an exact upper bound. */
        size_t common = alen < blen ? alen : blen;
        size_t rcap = common / 2u + 2u;
        cbm_diff_range_t *ranges = NULL;
        size_t nr = 0;
        if (rcap <= SIZE_MAX / sizeof(*ranges)) {
            ranges = (cbm_diff_range_t *)malloc(rcap * sizeof(*ranges));
            if (ranges)
                nr = cbm_diff_ranges(a, alen, b, blen, (size_t)ctx, ranges, rcap);
        }
        cbm_json_t j;
        cbm_json_object_begin(&j, json_out, "diff", "ok");
        cbm_json_field_string(&j, "a", a_path);
        cbm_json_field_string(&j, "b", b_path);
        cbm_json_field_u64(&j, "body_len_a", (unsigned long long)alen);
        cbm_json_field_u64(&j, "body_len_b", (unsigned long long)blen);
        cbm_json_field_u64(&j, "context", (unsigned long long)ctx);
        cbm_json_field_fixed6(&j, "entropy_body_a", cbm_decode_entropy(a, alen));
        cbm_json_field_fixed6(&j, "entropy_body_b", cbm_decode_entropy(b, blen));
        cbm_json_field_u64(&j, "changed_ranges", (unsigned long long)nr);
        cbm_json_field_u64(&j, "changed_bytes",
                           (unsigned long long)cbm_diff_changed_bytes(a, alen, b, blen));
        cbm_json_end(&j);
        free(ranges);
    }
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

/* Strict non-negative decimal LBA / MiB parser (64-bit, no sign, no suffix). */
static int parse_nonneg_ull(const char *s, unsigned long long *out) {
    if (!s || !*s || !out || s[0] == '-') return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || !end || end == s || *end != '\0') return -1;
    *out = v;
    return 0;
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

static int fuzz_mode(int argc, char **argv, FILE *json_out) {
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

    const char *pe_path = pe_path_from_env();
    if (cbm_backend_get() == CBM_BACKEND_PE && !pe_path) {
        fprintf(stderr, "Error: --pe-crypto requires CBM_PE_PATH (no vendor binary default)\n");
        return 1;
    }
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
    if (json_out) {
        cbm_json_t j;
        cbm_json_object_begin(&j, json_out, "fuzz", "ok");
        cbm_json_field_string(&j, "path", path);
        cbm_json_field_u64(&j, "seed", (unsigned long long)seed);
        cbm_json_field_u64(&j, "rounds", (unsigned long long)rounds);
        cbm_json_field_u64(&j, "mutations", (unsigned long long)mutate);
        cbm_json_field_string(&j, "out", out);
        cbm_json_field_bool(&j, "corpus_verified", 1);
        cbm_json_end(&j);
    }
    tea_cleanup();
    return 0;
}

/* ---- read-only forensic scan mode -------------------------------------- */

static void print_scan_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s scan <device|image> [--start LBA] [--end LBA] [--chunk MiB]\n"
        "                            [--carve <dir>] [--json <report>] [--all-hits]\n"
        "  --start LBA   first INCLUSIVE 512-byte LBA (default 0)\n"
        "  --end LBA     last INCLUSIVE 512-byte LBA (default: last LBA)\n"
        "  --chunk MiB   read chunk size, minimum 1 (default 8)\n"
        "  --carve <dir> write hit-NNN-<offset>.cbm (85688 bytes per hit)\n"
        "  --json <rpt>  write a deterministic JSON report\n"
        "  --all-hits    keep every candidate, including close distinct containers\n"
        "Scan is READ-ONLY: --carve/--json write only to the explicit local paths.\n"
        "Hits are CANDIDATES, not confirmed containers; magic is UNVERIFIED and\n"
        "advisory, detection uses the structural probe. Exit: 0 ok, 1 runtime\n"
        "error, 2 usage error.\n",
        prog);
}

/* Last LBA of the image. Regular files use stat; block devices use a strictly
 * O_RDONLY BLKGETSIZE64 capacity query. Deliberately does NOT use
 * usb_mass_open (which opens O_RDWR): scan mode must never hold a write-capable
 * descriptor on the device, even for a capacity probe. */
static int image_last_lba(const char *path, unsigned long long *last_lba) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    unsigned long long bytes;
    if (S_ISBLK(st.st_mode)) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) return -1;
        int ok = (ioctl(fd, BLKGETSIZE64, &bytes) == 0 && bytes > 0);
        close(fd);
        if (!ok) return -1;
    } else if (S_ISREG(st.st_mode)) {
        bytes = (unsigned long long)st.st_size;
    } else {
        return -1;
    }
    *last_lba = bytes ? (bytes - 1ULL) / (unsigned long long)CBM_SECTOR_SIZE : 0ULL;
    return 0;
}

/* Full-device, read-only scan. --carve and --json are the only writes and
 * are pre-flighted against the source inode before any output is opened. */
static int scan_mode(int argc, char **argv, FILE *json_out) {
    const char *path = (argc >= 3) ? argv[2] : NULL;
    const char *carve = NULL, *json = NULL;
    unsigned long long start_lba = 0ULL, end_lba = 0ULL, chunk_mib = 8ULL;
    int have_end = 0, all_hits = 0;

    if (!path || !path[0] || strcmp(path, "--all-hits") == 0) {
        /* A bare "scan --all-hits" has no image; do not treat the flag as a
         * device path and report a runtime open error instead of usage. */
        fprintf(stderr, "Error: scan requires a device or image path\n");
        print_scan_usage(argv[0]);
        return 2;
    }
    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--start") == 0 || strcmp(a, "--end") == 0) {
            unsigned long long *slot = (a[2] == 's') ? &start_lba : &end_lba;
            if (++i >= argc || parse_nonneg_ull(argv[i], slot) != 0) {
                fprintf(stderr, "Error: %s needs a non-negative LBA\n", a);
                print_scan_usage(argv[0]);
                return 2;
            }
            if (slot == &end_lba) have_end = 1;
        } else if (strcmp(a, "--chunk") == 0) {
            if (++i >= argc || parse_nonneg_ull(argv[i], &chunk_mib) != 0 ||
                chunk_mib < 1ULL) {
                fprintf(stderr, "Error: --chunk needs a positive integer (MiB)\n");
                print_scan_usage(argv[0]);
                return 2;
            }
        } else if (strcmp(a, "--all-hits") == 0) {
            all_hits = 1;
        } else if (strcmp(a, "--carve") == 0 || strcmp(a, "--json") == 0) {
            if (++i >= argc || !argv[i][0]) {
                fprintf(stderr, "Error: %s needs a local path\n", a);
                print_scan_usage(argv[0]);
                return 2;
            }
            if (a[2] == 'c') carve = argv[i];
            else json = argv[i];
        } else {
            fprintf(stderr, "Error: unknown scan option '%s'\n", a);
            print_scan_usage(argv[0]);
            return 2;
        }
    }
    if (!have_end && image_last_lba(path, &end_lba) != 0) {
        fprintf(stderr, "Error: cannot determine image size for '%s'\n", path);
        return 1;
    }
    if (start_lba > end_lba) {
        fprintf(stderr, "Error: --start LBA is after --end LBA\n");
        print_scan_usage(argv[0]);
        return 2;
    }
    const unsigned long long max_lba =
        (ULLONG_MAX - (unsigned long long)(CBM_SECTOR_SIZE - 1)) /
        (unsigned long long)CBM_SECTOR_SIZE;
    if (start_lba > max_lba || end_lba > max_lba) {
        fprintf(stderr, "Error: LBA exceeds the addressable byte range\n");
        return 2;
    }
    if (chunk_mib > (unsigned long long)(SIZE_MAX / 1048576ULL)) {
        fprintf(stderr, "Error: --chunk too large for this build\n");
        return 2;
    }
    const size_t chunk_bytes = (size_t)(chunk_mib * 1048576ULL);
    if (chunk_bytes <= 2u * CBM_CONTAINER_SIZE +
                       (size_t)CBM_SECTOR_SIZE) {
        fprintf(stderr, "Error: --chunk must exceed the scanner overlap (2 containers + 1 LBA)\n");
        return 2;
    }

    char err[256];
    err[0] = '\0';
    /* Refuse aliases before opening any output; no source write path exists. */
    if (json && cbm_scan_report_check_output(json, path, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err);
        return 2;
    }
    if (carve && cbm_scan_report_check_output(carve, path, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err);
        return 2;
    }

    const unsigned long long start_byte =
        start_lba * (unsigned long long)CBM_SECTOR_SIZE;
    const unsigned long long end_byte =
        end_lba * (unsigned long long)CBM_SECTOR_SIZE +
        (unsigned long long)(CBM_SECTOR_SIZE - 1);

    const char *pe_path = pe_path_from_env();
    if (cbm_backend_get() == CBM_BACKEND_PE && !pe_path) {
        fprintf(stderr, "Error: --pe-crypto requires CBM_PE_PATH (no vendor binary default)\n");
        return 1;
    }
    printf("=== Scan Mode: %s ===\n", path);
    print_backend();
    if (cbm_backend_get() == CBM_BACKEND_PE)
        printf("Loading TEA cores from PE: %s\n", pe_path);
    printf("Range: LBA %llu-%llu (bytes %llu-%llu)\n",
           start_lba, end_lba, start_byte, end_byte);
    printf("Chunk: %llu MiB (%zu bytes)\n", chunk_mib, chunk_bytes);
    puts("Detection: structural probe only; magic UNVERIFIED/advisory");
    if (all_hits) puts("Hits: exhaustive (--all-hits; candidates only)");
    if (tea_init(pe_path) != 0) {
        fprintf(stderr, "Error: failed to initialize crypto backend\n");
        return 1;
    }

    cbm_scan_hit_t *hits = NULL;
    size_t n = 0;
    int rc = 1;
    if (cbm_scan_image_ex(path, start_byte, end_byte, chunk_bytes, NULL, 0,
                          all_hits ? 0 : 1, &hits, &n, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err[0] ? err : "scan failed");
        goto out;
    }
    printf("Candidates: %zu\n", n);
    puts("offset header entropy sha256 token_count [offset:token]...");
    cbm_scan_print(stdout, hits, n);
    if (json) {
        if (cbm_scan_write_json(json, hits, n, err, sizeof(err)) != 0) {
            fprintf(stderr, "Error: %s\n", err[0] ? err : "JSON write failed");
            goto out;
        }
        printf("JSON report: %s\n", json);
    }
    if (carve) {
        if (cbm_scan_carve(carve, path, hits, n, err, sizeof(err)) != 0) {
            fprintf(stderr, "Error: %s\n", err[0] ? err : "carve failed");
            goto out;
        }
        printf("Carved %zu candidate container(s) into '%s'\n", n, carve);
    }
    if (!json && !carve) puts("No report written (read-only default).");
    puts("Scan complete: candidates only, not confirmed containers.");
    if (json_out) {
        cbm_json_t jb;
        cbm_json_object_begin(&jb, json_out, "scan", "ok");
        cbm_json_field_string(&jb, "path", path);
        cbm_json_field_u64(&jb, "start_lba", start_lba);
        cbm_json_field_u64(&jb, "end_lba", end_lba);
        cbm_json_field_u64(&jb, "candidates", (unsigned long long)n);
        cbm_json_field_bool(&jb, "all_hits", all_hits);
        cbm_json_array_begin(&jb, "hits");
        for (size_t i = 0; i < n; i++) {
            const cbm_scan_hit_t *h = &hits[i];
            char sha[65];
            for (size_t k = 0; k < 32u; k++)
                snprintf(sha + k * 2u, 3u, "%02x", (unsigned)h->sha256[k]);
            size_t nt = h->token_count > 8u ? 8u : h->token_count;
            cbm_json_element_object(&jb);
            cbm_json_field_u64(&jb, "offset", h->offset);
            cbm_json_field_u64(&jb, "header", h->header);
            cbm_json_field_fixed6(&jb, "entropy", h->entropy);
            cbm_json_field_string(&jb, "sha256", sha);
            cbm_json_array_begin(&jb, "tokens");
            for (size_t k = 0; k < nt; k++) {
                cbm_json_element_object(&jb);
                cbm_json_field_u64(&jb, "offset", h->token_offsets[k]);
                cbm_json_field_string(&jb, "text", h->tokens[k]);
                cbm_json_object_end(&jb);
            }
            cbm_json_array_end(&jb);
            cbm_json_object_end(&jb);
        }
        cbm_json_array_end(&jb);
        cbm_json_end(&jb);
    }
    rc = 0;
out:
    cbm_scan_free_hits(hits);
    tea_cleanup();
    return rc;
}

/* ---- read-only whole-image entropy heatmap ------------------------------ */

static void print_heatmap_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s heatmap <device|image> [--block MiB] [--width N]\n"
        "                              [--out <png>] [--json <path>]\n"
        "  --block MiB   block size in MiB (default 1, minimum 1)\n"
        "  --width N     image width in pixels (default 1024, 16..8192)\n"
        "  --out <png>   write an 8-bit RGB PNG (only write target)\n"
        "  --json <path> write a deterministic JSON sidecar (only write target)\n"
        "READ-ONLY: without --out/--json nothing is written. Output paths that\n"
        "resolve to the source are refused. Regions are INFERRED from the MBR,\n"
        "not verified. Image height = clamp(ceil(samples/width), 1,\n"
        "max(1, 1048576/width)); pixels capped at 1048576 (1 Mi). Sample cap:\n"
        "64 Mi samples. Exit: 0 ok, 1 runtime error, 2 usage error.\n",
        prog);
}

/* Fixed-point entropy text: literal '.', never %.6f and never locale-based. */
static void heatmap_fixed(char *dst, size_t dstlen, double v) {
    if (!(v > 0.0)) v = 0.0;
    if (v > 8.0) v = 8.0;
    unsigned long long scaled = (unsigned long long)(v * 1000000.0 + 0.5);
    snprintf(dst, dstlen, "%u.%06u", (unsigned)(scaled / 1000000ULL),
             (unsigned)(scaled % 1000000ULL));
}

/* Full-image read-only heatmap. The source is opened only by cbm_file_read
 * (and the strictly O_RDONLY capacity probe in image_last_lba). --out and
 * --json are the only write targets, pre-flighted against the source inode
 * with the shared scan-report guard before either file is opened. */
static int heatmap_mode(int argc, char **argv, FILE *json_out) {
    const char *path = (argc >= 3) ? argv[2] : NULL;
    const char *png_path = NULL, *json_path = NULL;
    unsigned long long block_mib = 1ULL;
    unsigned long width_arg = 1024UL;
    char err[256] = {0};

    if (!path || !path[0]) {
        fprintf(stderr, "Error: heatmap requires a device or image path\n");
        print_heatmap_usage(argv[0]);
        return 2;
    }
    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--block") == 0) {
            if (++i >= argc || parse_nonneg_ull(argv[i], &block_mib) != 0 ||
                block_mib < 1ULL) {
                fprintf(stderr, "Error: --block needs a positive integer (MiB)\n");
                print_heatmap_usage(argv[0]);
                return 2;
            }
        } else if (strcmp(a, "--width") == 0) {
            unsigned long w = 0UL;
            if (++i >= argc || parse_unsigned_arg(argv[i], &w) != 0 ||
                w < 16UL || w > 8192UL) {
                fprintf(stderr, "Error: --width needs an integer in 16..8192\n");
                print_heatmap_usage(argv[0]);
                return 2;
            }
            width_arg = w;
        } else if (strcmp(a, "--out") == 0 || strcmp(a, "--json") == 0) {
            if (++i >= argc || !argv[i][0]) {
                fprintf(stderr, "Error: %s needs a local path\n", a);
                print_heatmap_usage(argv[0]);
                return 2;
            }
            if (a[2] == 'o') png_path = argv[i];
            else json_path = argv[i];
        } else {
            fprintf(stderr, "Error: unknown heatmap option '%s'\n", a);
            print_heatmap_usage(argv[0]);
            return 2;
        }
    }
    if (block_mib > (unsigned long long)(SIZE_MAX / 1048576ULL)) {
        fprintf(stderr, "Error: --block too large for this build\n");
        print_heatmap_usage(argv[0]);
        return 2;
    }
    const size_t block_bytes = (size_t)(block_mib * 1048576ULL);

    unsigned long long last_lba = 0ULL;
    if (image_last_lba(path, &last_lba) != 0) {
        fprintf(stderr, "Error: cannot determine image size for '%s'\n", path);
        return 1;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "Error: cannot stat image '%s'\n", path);
        return 1;
    }
    unsigned long long end_byte;
    if (S_ISREG(st.st_mode)) {
        /* Exclusive byte end: regular images may end mid-sector (or be empty),
         * and cbm_file_read requires the exact requested byte count. */
        if (st.st_size < 0) {
            fprintf(stderr, "Error: image has a negative size '%s'\n", path);
            return 1;
        }
        end_byte = (unsigned long long)st.st_size;
    } else {
        /* Block devices keep whole-sector LBA semantics and the old guard. */
        const unsigned long long sectors = last_lba + 1ULL;
        if (sectors > ULLONG_MAX / (unsigned long long)CBM_SECTOR_SIZE) {
            fprintf(stderr, "Error: image byte range overflows\n");
            return 2;
        }
        end_byte = sectors * (unsigned long long)CBM_SECTOR_SIZE;
    }

    /* Reuse the scan CLI guard: no inode/realpath logic is duplicated here. */
    if (png_path &&
        cbm_scan_report_check_output(png_path, path, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err);
        return 2;
    }
    if (json_path &&
        cbm_scan_report_check_output(json_path, path, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err);
        return 2;
    }

    unsigned char mbr[CBM_SECTOR_SIZE];
    const unsigned char *mbr_ptr = NULL;
    size_t mbr_len = 0;
    int mbr_ok = (cbm_file_read(path, 0LL, mbr, (size_t)CBM_SECTOR_SIZE) == 0);
    if (mbr_ok) {
        mbr_ptr = mbr;
        mbr_len = (size_t)CBM_SECTOR_SIZE;
    }

    cbm_entropy_sample_t *samples = NULL;
    size_t nsamples = 0;
    if (cbm_entropy_map(path, 0ULL, end_byte, block_bytes, &samples, &nsamples,
                        err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err[0] ? err : "entropy map failed");
        return 1;
    }

    /* Row-major grid: sample i -> pixel (i/width, i%width). Height is capped
     * so width*height never exceeds CBM_HEATMAP_MAX_PIXELS (1 Mi pixels). */
    const size_t width = (size_t)width_arg;
    const size_t max_height = (size_t)CBM_HEATMAP_MAX_PIXELS / width;
    const size_t height_cap = max_height ? max_height : 1u;
    size_t height = 1u;
    if (nsamples > 0u) {
        size_t rows = (nsamples + width - 1u) / width;
        if (rows < 1u) rows = 1u;
        height = rows > height_cap ? height_cap : rows;
    }
    const size_t npixels = width * height;
    if (npixels == 0u || npixels > (size_t)CBM_HEATMAP_MAX_PIXELS) {
        fprintf(stderr, "Error: heatmap pixel count is out of range\n");
        free(samples);
        return 1;
    }
    const size_t rgb_len = npixels * 3u;
    cbm_heatmap_pixel_t *pixels = (cbm_heatmap_pixel_t *)calloc(
        npixels, sizeof(*pixels));
    unsigned char *rgb = (unsigned char *)malloc(rgb_len);
    if (!pixels || !rgb) {
        fprintf(stderr, "Error: out of memory for the heatmap image\n");
        free(rgb);
        free(pixels);
        free(samples);
        return 1;
    }
    if (cbm_entropy_downsample(samples, nsamples, width, height,
                               pixels, npixels) != npixels) {
        fprintf(stderr, "Error: downsample did not fill the pixel grid\n");
        free(rgb);
        free(pixels);
        free(samples);
        return 1;
    }
    for (size_t i = 0; i < npixels; i++) {
        rgb[i * 3u] = pixels[i].r;
        rgb[i * 3u + 1u] = pixels[i].g;
        rgb[i * 3u + 2u] = pixels[i].b;
    }

    cbm_entropy_region_t regions[8];
    const size_t nregions = cbm_entropy_regions(samples, nsamples, mbr_ptr,
                                                mbr_len, regions, 8u);

    double emin = 0.0, emax = 0.0, esum = 0.0;
    if (nsamples > 0u) {
        emin = samples[0].entropy;
        emax = samples[0].entropy;
        for (size_t i = 0; i < nsamples; i++) {
            if (samples[i].entropy < emin) emin = samples[i].entropy;
            if (samples[i].entropy > emax) emax = samples[i].entropy;
            esum += samples[i].entropy;
        }
    }
    char fmin[32], fmean[32], fmax[32];
    heatmap_fixed(fmin, sizeof(fmin), emin);
    heatmap_fixed(fmean, sizeof(fmean), nsamples ? esum / (double)nsamples : 0.0);
    heatmap_fixed(fmax, sizeof(fmax), emax);

    printf("=== Heatmap Mode: %s ===\n", path);
    printf("Range: bytes 0-%llu\n", end_byte ? end_byte - 1ULL : 0ULL);
    printf("Block: %llu MiB (%zu bytes)\n", block_mib, block_bytes);
    printf("Samples: %zu (cap %llu)\n", nsamples, CBM_ENTROPY_MAX_SAMPLES);
    printf("Image: %zu x %zu (max %u pixels)\n", width, height,
           (unsigned)CBM_HEATMAP_MAX_PIXELS);
    printf("Entropy: min %s mean %s max %s\n", fmin, fmean, fmax);
    if (!mbr_ok) puts("MBR: unreadable; regions are TAIL only (INFERRED)");
    printf("Regions: %zu (INFERRED from MBR, not verified)\n", nregions);
    for (size_t i = 0; i < nregions; i++) {
        char rmin[32], rmean[32], rmax[32];
        heatmap_fixed(rmin, sizeof(rmin), regions[i].min);
        heatmap_fixed(rmean, sizeof(rmean), regions[i].mean);
        heatmap_fixed(rmax, sizeof(rmax), regions[i].max);
        printf("  REGION %s inferred=%s offset=%llu length=%llu samples=%zu "
               "min=%s mean=%s max=%s\n",
               regions[i].name, regions[i].inferred ? "yes" : "no",
               regions[i].offset, regions[i].length, regions[i].samples,
               rmin, rmean, rmax);
    }

    int rc = 1;
    if (png_path) {
        if (png_write_rgb(png_path, rgb, width, height, err, sizeof(err)) != 0) {
            fprintf(stderr, "Error: %s\n", err[0] ? err : "PNG write failed");
            goto out;
        }
        printf("PNG: %s\n", png_path);
    }
    if (json_path) {
        if (cbm_entropy_json(json_path, samples, nsamples, regions, nregions,
                             width, height, err, sizeof(err)) != 0) {
            fprintf(stderr, "Error: %s\n", err[0] ? err : "JSON write failed");
            goto out;
        }
        printf("JSON: %s\n", json_path);
    }
    if (!png_path && !json_path) puts("No output written (read-only default).");
    if (json_out) {
        cbm_json_t jb;
        cbm_json_object_begin(&jb, json_out, "heatmap", "ok");
        cbm_json_field_string(&jb, "path", path);
        cbm_json_field_u64(&jb, "block_bytes", (unsigned long long)block_bytes);
        cbm_json_field_u64(&jb, "samples", (unsigned long long)nsamples);
        cbm_json_field_u64(&jb, "width", (unsigned long long)width);
        cbm_json_field_u64(&jb, "height", (unsigned long long)height);
        cbm_json_object_start(&jb, "entropy");
        cbm_json_field_fixed6(&jb, "min", emin);
        cbm_json_field_fixed6(&jb, "mean", nsamples ? esum / (double)nsamples : 0.0);
        cbm_json_field_fixed6(&jb, "max", emax);
        cbm_json_object_end(&jb);
        cbm_json_array_begin(&jb, "regions");
        for (size_t i = 0; i < nregions; i++) {
            const cbm_entropy_region_t *r = &regions[i];
            cbm_json_element_object(&jb);
            cbm_json_field_string(&jb, "name", r->name);
            cbm_json_field_u64(&jb, "offset", r->offset);
            cbm_json_field_u64(&jb, "length", r->length);
            cbm_json_field_u64(&jb, "samples", (unsigned long long)r->samples);
            cbm_json_field_fixed6(&jb, "min", r->min);
            cbm_json_field_fixed6(&jb, "mean", r->mean);
            cbm_json_field_fixed6(&jb, "max", r->max);
            cbm_json_field_bool(&jb, "inferred", r->inferred);
            cbm_json_object_end(&jb);
        }
        cbm_json_array_end(&jb);
        cbm_json_end(&jb);
    }
    rc = 0;
out:
    free(rgb);
    free(pixels);
    free(samples);
    return rc;
}

/* ---- strictly read-only ANSI live TUI ---------------------------------- */
static void print_tui_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s tui <device|image>\n"
            "  read-only ANSI live view; q/ESC quits. No target writes.\n"
            "  Exit: 0 ok, 1 runtime error, 2 usage error.\n",
            prog);
}

/* The frame comes only from cbm_tui_render (pure) fed by cbm_doctor_report
 * (read-only). This function never calls usb_mass_open or any write path, so
 * even a device target is opened for reads only. */
static int tui_mode(int argc, char **argv) {
    const char *path = (argc >= 3) ? argv[2] : NULL;
    if (!path || !path[0]) {
        fprintf(stderr, "Error: tui requires a device or image path\n");
        print_tui_usage(argv[0]);
        return 2;
    }
    for (int i = 3; i < argc; i++) {
        fprintf(stderr, "Error: unknown tui option '%s'\n", argv[i]);
        print_tui_usage(argv[0]);
        return 2;
    }

    char err[256] = {0};
    cbm_doctor_report_t r;
    if (cbm_doctor_report(path, 26ULL, &r, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err);
        return 1;
    }

    /* Window is derived from the measured size: the largest supported window
     * that fits, else 26 (which naturally reports window_consistent=no). */
    const unsigned long long gib = 1024ULL * 1024ULL * 1024ULL;
    unsigned long long window = 26ULL;
    if (r.size_bytes >= 28ULL * gib) window = 28ULL;
    else if (r.size_bytes >= 27ULL * gib) window = 27ULL;
    if (window != 26ULL && cbm_doctor_report(path, window, &r, err, sizeof(err)) != 0) {
        fprintf(stderr, "Error: %s\n", err);
        return 1;
    }

    /* Display the ACTUAL first sector, never the nominal candidate. A MBR
     * that does not parse shows zero partition rows and mbr_status=INVALID. */
    unsigned char mbr[CBM_SECTOR_SIZE];
    if (cbm_file_read(path, 0, mbr, sizeof(mbr)) != 0) {
        fprintf(stderr, "Error: cannot read first sector for TUI\n");
        return 1;
    }
    cbm_layout_t actual;
    int parsed = (cbm_layout_parse(mbr, sizeof(mbr), &actual) == 0);

    cbm_tui_state_t st;
    memset(&st, 0, sizeof(st));
    snprintf(st.target, sizeof(st.target), "%s", path);
    st.size_bytes = r.size_bytes;
    st.window_gib = window;
    st.is_blockdev = cbm_file_is_blockdev(path);
    snprintf(st.mbr_status, sizeof(st.mbr_status), "%s", parsed ? "VALID" : "INVALID");
    snprintf(st.dj_status, sizeof(st.dj_status), "%s", r.dj_ok ? "VALID" : "INVALID");
    if (parsed) {
        static const char *names[4] = {"DJ_BOOT", "DJ_OS", "DJ_DATA", "PART3"};
        int n = actual.part_count > 4 ? 4 : actual.part_count;
        for (int i = 0; i < n; i++) {
            snprintf(st.parts[i].name, sizeof(st.parts[i].name), "%s", names[i]);
            st.parts[i].start_lba = actual.parts[i].start_lba;
            st.parts[i].sectors = actual.parts[i].size_lba;
            st.parts[i].type = actual.parts[i].type;
            st.parts[i].inferred = 0; /* read from the device's real MBR */
        }
        st.part_count = n;
    }
    snprintf(st.backend, sizeof(st.backend), "%s",
             cbm_backend_get() == CBM_BACKEND_PE ? "pe" : "native");
    memcpy(st.hex, mbr, sizeof(st.hex));
    st.hex_len = sizeof(st.hex);
    st.hex_scroll = 0;
    /* scan_hits/last_hit_offset/entropy stay zero: the renderer prints n/a
     * because this mode does not run a scan or an entropy sampler. */

    size_t w = 80, h = 24;
    struct winsize ws;
    if (isatty(STDIN_FILENO) &&
        ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col && ws.ws_row) {
        w = ws.ws_col;
        h = ws.ws_row;
    }
    st.term_width = w;
    st.term_height = h;

    int tty = isatty(STDIN_FILENO);
    struct termios saved, raw;
    if (tty) {
        if (tcgetattr(STDIN_FILENO, &saved) != 0) return 1;
        raw = saved;
        cfmakeraw(&raw);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) return 1;
    }

    int rc = 1;
    for (;;) {
        char *frame = cbm_tui_render(&st, w, h);
        if (!frame) {
            fprintf(stderr, "Error: out of memory rendering TUI frame\n");
            goto done;
        }
        fputs(frame, stdout);
        fflush(stdout);
        free(frame);
        if (!tty) {
            /* Canonical / piped input: never block waiting for a key. */
            fd_set rd;
            struct timeval tv;
            FD_ZERO(&rd);
            FD_SET(STDIN_FILENO, &rd);
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            if (select(STDIN_FILENO + 1, &rd, NULL, NULL, &tv) <= 0) {
                rc = 0;
                break;
            }
        }
        int key = getchar();
        if (key == EOF || key == 'q' || key == '\033') {
            rc = 0;
            break;
        }
        if (key == 'n' || key == 'p')
            st.hex_scroll = cbm_tui_hex_scroll(key, st.hex_scroll, st.hex_len);
    }
done:
    if (tty) (void)tcsetattr(STDIN_FILENO, TCSANOW, &saved); /* always restore */
    return rc;
}

/* ---- wave 5E / G1-a: deterministic PE import capture ------------------- */

static void print_cdb_capture_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s cdb-capture <pe-path> --out <capture-file> [--export <name>]\n"
        "                        [--arg0 N] [--arg1 N] [--arg2 N]\n"
        "  --out <file>    required capture file; devices/directories are refused\n"
        "  --export <name> optional PE export called with three uint32 words\n"
        "  Exit: 0 ok, 1 runtime error, 2 usage error.\n",
        prog);
}

static int cdb_capture_mode(int argc, char **argv, FILE *json_out) {
    const char *path = (argc >= 3) ? argv[2] : NULL;
    const char *out = NULL;
    const char *export = NULL;
    uint32_t args[3] = {0u, 0u, 0u};
    pe_image_t *img = NULL;
    uint32_t rva = 0;
    size_t events = 0;
    int rc = 0, called = 0;

    /* No implicit PE path: <pe-path> is mandatory and is never read from
     * CBM_PE_PATH. A missing file is a usage error naming this argument. */
    if (!path || !*path || path[0] == '-') {
        fprintf(stderr, "Error: cdb-capture requires <pe-path>\n");
        print_cdb_capture_usage(argv[0]);
        return 2;
    }
    if (access(path, F_OK) != 0) {
        fprintf(stderr, "Error: cdb-capture <pe-path> cannot access '%s'\n", path);
        print_cdb_capture_usage(argv[0]);
        return 2;
    }
    for (int i = 3; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--out") == 0 || strcmp(a, "--export") == 0) {
            if (++i >= argc || !argv[i][0]) {
                fprintf(stderr, "Error: %s needs a non-empty path\n", a);
                print_cdb_capture_usage(argv[0]);
                return 2;
            }
            if (strcmp(a, "--out") == 0) out = argv[i];
            else export = argv[i];
        } else if (strcmp(a, "--arg0") == 0 || strcmp(a, "--arg1") == 0 ||
                   strcmp(a, "--arg2") == 0) {
            unsigned long slot;
            int idx = (a[6] == '0') ? 0 : (a[6] == '1') ? 1 : 2;
            if (++i >= argc || parse_unsigned_arg(argv[i], &slot) != 0) {
                fprintf(stderr, "Error: %s needs a non-negative integer\n", a);
                print_cdb_capture_usage(argv[0]);
                return 2;
            }
            args[idx] = (uint32_t)slot;
        } else {
            fprintf(stderr, "Error: unknown cdb-capture option '%s'\n", a);
            print_cdb_capture_usage(argv[0]);
            return 2;
        }
    }
    if (!out || (export && !*export)) {
        fprintf(stderr, "Error: cdb-capture requires --out <capture-file>\n");
        print_cdb_capture_usage(argv[0]);
        return 2;
    }
    if (cdb_capture_open(out) != 0) return 1;
    if (pe_load(&img, path, cdb_shim_hooks()) != 0 || !img) {
        fprintf(stderr, "Error: cdb-capture cannot load PE '%s'\n", path);
        cdb_capture_close();
        return 1;
    }
    if (export) {
        if (pe_export(img, export, &rva) != 0) {
            fprintf(stderr, "Error: cdb-capture --export '%s' not found in '%s'\n",
                    export, path);
            rc = 1;                  /* still close and publish the empty capture */
        } else if (pe_call_void(img, rva, args, sizeof args) != 0) {
            fprintf(stderr, "Error: cdb-capture --export '%s' call failed\n", export);
            rc = 1;
        } else {
            called = 1;
        }
    }
    events = cdb_capture_count();
    pe_unload(img);
    cdb_capture_close();              /* flush the header + every record */

    if (json_out && rc == 0) {
        cbm_json_t j;
        cbm_json_object_begin(&j, json_out, "cdb-capture", "ok");
        cbm_json_field_string(&j, "path", path);
        cbm_json_field_string(&j, "capture", out);
        cbm_json_field_string(&j, "export", export ? export : "");
        cbm_json_field_bool(&j, "called", called);
        cbm_json_field_u64(&j, "events", (unsigned long long)events);
        cbm_json_end(&j);
    } else if (!json_out) {
        printf("CDB capture: %s\n", out);
        printf("Events: %lu\n", (unsigned long)events);
        printf("Export: %s (%s)\n", export ? export : "(none)",
               called ? "called" : "not called");
    }
    return rc;
}

/* ---- wave 5M: read-only block-cipher candidate recon ------------------- */

static void print_recon_usage(FILE *err, const char *prog) {
    fprintf(err,
        "Usage: %s recon <pe> [--top N] [--all] [--json]\n"
        "  --top N   print only the N highest-scoring candidates (default 20)\n"
        "  --all     print every stored candidate (max %u)\n"
        "  --json    emit one compact cbm/1 document on stdout\n"
        "  Read-only: the PE is opened for reading only; nothing is written.\n"
        "  Exit: 0 ok, 2 usage or input error.\n",
        prog, RECON_MAX_CANDIDATES);
}

static void recon_append_flag(char *dst, size_t cap, size_t *pos, const char *s) {
    size_t room = cap > *pos ? cap - *pos : 0u;
    size_t n;
    if (room <= 1u) return;
    n = strlen(s);
    if (n > room - 1u) n = room - 1u;
    memcpy(dst + *pos, s, n);
    *pos += n;
    dst[*pos] = '\0';
}

static void recon_flags(char *dst, size_t cap, const recon_candidate_t *c) {
    size_t pos = 0u;
    dst[0] = '\0';
    if (c->delta_tea) recon_append_flag(dst, cap, &pos, "TEA-delta");
    if (c->delta_alt) recon_append_flag(dst, cap, &pos, "ALT-delta");
    if (c->calls_delta) recon_append_flag(dst, cap, &pos, "calls-delta");
    if (c->repeated_call) recon_append_flag(dst, cap, &pos, "repeat-call");
    if (pos == 0u) recon_append_flag(dst, cap, &pos, "-");
}

int recon_cli_ex(int argc, char **argv, FILE *out, FILE *err, FILE *json) {
    const char *path = (argc >= 3) ? argv[2] : NULL;
    unsigned long top = 20u;
    int all = 0;
    recon_report_t report;
    uint32_t shown = 0u, i;
    int arg_i;

    if (!out) out = stdout;
    if (!err) err = stderr;
    if (!path || !*path || path[0] == '-') {
        fprintf(err, "Error: recon requires <pe> path\n");
        print_recon_usage(err, argv[0] ? argv[0] : "cbm-tool");
        return 2;
    }
    for (arg_i = 3; arg_i < argc; arg_i++) {
        const char *a = argv[arg_i];
        if (strcmp(a, "--all") == 0) all = 1;
        else if (strcmp(a, "--json") == 0) continue; /* stripped by main when present */
        else if (strcmp(a, "--top") == 0) {
            char *end = NULL;
            if (++arg_i >= argc) {
                fprintf(err, "Error: --top needs a non-negative integer\n");
                print_recon_usage(err, argv[0]);
                return 2;
            }
            errno = 0;
            top = strtoul(argv[arg_i], &end, 10);
            if (errno != 0 || !end || end == argv[arg_i] || *end != '\0') {
                fprintf(err, "Error: --top needs a non-negative integer\n");
                print_recon_usage(err, argv[0]);
                return 2;
            }
        } else {
            fprintf(err, "Error: unknown recon option '%s'\n", a);
            print_recon_usage(err, argv[0]);
            return 2;
        }
    }
    memset(&report, 0, sizeof(report));
    if (recon_file(path, &report) != 0) {
        fprintf(err, "Error: %s\n", report.error[0] ? report.error : "recon failed");
        return 2;
    }
    shown = all ? report.stored
                : (top < (unsigned long)report.stored
                       ? (uint32_t)top : report.stored);

    fprintf(out, "RECON: %s\n", path);
    fprintf(out, "ImageBase: 0x%08" PRIX32 "  SizeOfImage: 0x%08" PRIX32
                 "  Sections: %u\n",
            report.image_base, report.size_of_image, (unsigned)report.sections);
    fprintf(out, "Functions scanned: %" PRIu32 "\n", report.functions_scanned);
    fprintf(out, "Candidates: %" PRIu32 " (stored %" PRIu32 ")\n",
            report.total_candidates, report.stored);
    fprintf(out, "VA RVA score size bx dx shf flags\n");
    for (i = 0u; i < shown; i++) {
        const recon_candidate_t *c = &report.candidates[i];
        char flags[64];
        recon_flags(flags, sizeof(flags), c);
        fprintf(out, "%08" PRIX32 " %08" PRIX32 " %5" PRIu32 " %6" PRIu32
                     " %3" PRIu32 " %3" PRIu32 " %3" PRIu32 " %s\n",
                c->va, c->rva, c->score, c->size,
                c->byte_xor, c->dword_xor, c->shifts, flags);
    }
    if (json) {
        cbm_json_t j;
        cbm_json_object_begin(&j, json, "recon", "ok");
        cbm_json_field_string(&j, "path", path);
        cbm_json_field_u64(&j, "image_base", (unsigned long long)report.image_base);
        cbm_json_field_u64(&j, "size_of_image", (unsigned long long)report.size_of_image);
        cbm_json_field_u64(&j, "sections", (unsigned long long)report.sections);
        cbm_json_field_u64(&j, "functions_scanned",
                           (unsigned long long)report.functions_scanned);
        cbm_json_array_begin(&j, "candidates");
        for (i = 0u; i < shown; i++) {
            const recon_candidate_t *c = &report.candidates[i];
            cbm_json_element_object(&j);
            cbm_json_field_u64(&j, "va", (unsigned long long)c->va);
            cbm_json_field_u64(&j, "rva", (unsigned long long)c->rva);
            cbm_json_field_u64(&j, "score", (unsigned long long)c->score);
            cbm_json_field_u64(&j, "size", (unsigned long long)c->size);
            cbm_json_field_u64(&j, "byte_xor", (unsigned long long)c->byte_xor);
            cbm_json_field_u64(&j, "dword_xor", (unsigned long long)c->dword_xor);
            cbm_json_field_u64(&j, "shifts", (unsigned long long)c->shifts);
            cbm_json_field_bool(&j, "calls_delta", c->calls_delta);
            cbm_json_field_bool(&j, "repeated_call", c->repeated_call);
            cbm_json_object_end(&j);
        }
        cbm_json_array_end(&j);
        cbm_json_end(&j);
    }
    return 0;
}

int main(int argc, char **argv) {
    argc = parse_backend_flags(argc, argv);
    const char *command = (argc >= 2) ? argv[1] : NULL;
    int json = 0;
    argc = strip_json_flags(argc, argv, &json);
    cbm_json_capture_t cap;
    FILE *json_out = NULL;
    if (json && json_capture_start(&cap) != 0) json = 0; /* fall back to prose */
    if (json) json_out = cap.json_buf;
    int rc = 0;

    if (!json && !(command && strcmp(command, "telemetry") == 0)) {
        printf("CBMUsbDisk Linux-Native Tool v1.0\n");
        printf("==================================\n\n");
    }
    /* --all-hits is scan-only. Reject it before dispatch so no other mode and
     * no bare invocation can mistake it for a device path or ignore it. */
    if (argc >= 2 && strcmp(argv[1], "scan") != 0) {
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--all-hits") == 0) {
                fprintf(stderr, "Error: --all-hits is only valid with scan\n");
                rc = 2;
                goto done;
            }
        }
    }
    /* Container/vault/trust/fuzz/scan modes load the crypto backend themselves
     * and must not run the selftest first (that would init/cleanup TEA twice).
     * diff and heatmap are pure byte analysis and need no crypto at all.
     * doctor/tui are read-only diagnostics except the explicitly authorised
     * repair path. recon is a pure read-only PE analysis and needs no crypto
     * backend. trust is a read-only descriptor comparison and never opens the
     * device for I/O. telemetry is a read-only Prometheus exporter that binds
     * loopback by default and never opens a device for writing. All twelve
     * subcommands are dispatched before the device path so nothing can be
     * mistaken for a block-device argument. */
    if (argc >= 2 && strcmp(argv[1], "vault") == 0)
        rc = vault_cli_ex(argc, argv, stdout, stderr, json_out);
    else if (argc >= 2 && strcmp(argv[1], "trust") == 0)
        rc = trust_cli_ex(argc, argv, stdout, stderr, json_out);
    else if (argc >= 2 && strcmp(argv[1], "container") == 0)
        rc = container_mode(argc, argv, json_out);
    else if (argc >= 2 && strcmp(argv[1], "diff") == 0)
        rc = diff_mode(argc, argv, json_out);
    else if (argc >= 2 && strcmp(argv[1], "fuzz") == 0)
        rc = fuzz_mode(argc, argv, json_out);
    else if (argc >= 2 && strcmp(argv[1], "scan") == 0)
        rc = scan_mode(argc, argv, json_out);
    else if (argc >= 2 && strcmp(argv[1], "heatmap") == 0)
        rc = heatmap_mode(argc, argv, json_out);
    else if (argc >= 2 && strcmp(argv[1], "doctor") == 0)
        rc = cbm_doctor_cli_ex(argc, argv, stdout, stderr, json_out);
    else if (argc >= 2 && strcmp(argv[1], "tui") == 0)
        rc = tui_mode(argc, argv);
    else if (argc >= 2 && strcmp(argv[1], "cdb-capture") == 0)
        rc = cdb_capture_mode(argc, argv, json_out);
    else if (argc >= 2 && strcmp(argv[1], "recon") == 0)
        rc = recon_cli_ex(argc, argv, stdout, stderr, json_out);
    else if (argc >= 2 && strcmp(argv[1], "telemetry") == 0)
        rc = telemetry_cli_ex(argc, argv, stdout, stderr, json_out);
    else if (argc > 1)
        rc = verify_device(argv[1]);
    else if (selftest() != 0)
        rc = 1;
    else
        printf("\nAll systems operational.\n");

done:
    if (json) json_capture_finish(&cap, rc, command);
    return rc;
}
