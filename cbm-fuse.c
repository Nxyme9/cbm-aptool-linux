/* cbm-fuse.c - read-only FUSE3 view of existing CBM RE artifacts (Wave 5J)
 *
 * Usage:
 *   cbm-fuse <container|image> <mountpoint> [--container-offset N]
 *            [--window-gib 26|27|28] [--allow-device] [fuse options...]
 *
 * The mount exposes only regular, read-only virtual files. Every byte comes
 * from existing helpers: cbm_file_read for source bytes, cbm_cbc_decrypt for
 * the TEA body, the inspect and decode helpers for text, cbm_doctor_cli_ex for
 * the layout report, and cbm_entropy_map + png_write_rgb for the optional PNG.
 * No write/create/unlink/rename/chmod/truncate/setattr callback is registered,
 * and open() rejects any write-mode descriptor with EROFS. Nothing here opens
 * a device for writing, and no vendor PE is loaded (the native TEA backend is
 * used). A block-device source requires the explicit --allow-device opt-in.
 *
 * heatmap.png is compiled in only when CBM_FUSE_WITH_HEATMAP is defined to 1
 * by the build command (the 5F PNG builder sources are present then). See
 * docs/fuse-view.md for the exact build command and provenance table.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cbm_container.h"
#include "cbm_decode.h"
#include "cbm_doctor.h"
#include "cbm_file.h"
#include "cbm_inspect.h"
#include "cli_json.h"
#include "entropy_map.h"
#include "png_write.h"
#include "tea_crypto.h"

#if defined(CBM_FUSE_WITH_HEATMAP) && CBM_FUSE_WITH_HEATMAP
#define FV_HEATMAP 1
#else
#define FV_HEATMAP 0
#endif

#define FV_BODY_LEN (CBM_CONTAINER_SIZE - CBM_HEADER_SIZE)
#define FV_MIN_STRING 4u
#define FV_HEATMAP_BLOCK_BYTES ((unsigned long long)1024ULL * 1024ULL)
#define FV_HEATMAP_WIDTH ((unsigned long long)1024ULL)
#define FV_FUSE_ARGV_MAX 64

static const char FV_TEA_KEY[] = "1a2b3c4d5e6fTENG";

typedef enum {
    FV_LAYOUT = 0,
    FV_CONTAINER,
    FV_PLAIN,
    FV_STRINGS,
    FV_ENTROPY,
    FV_REPORT,
    FV_HEATMAP_FILE,
    FV_NFILES
} fv_file_index_t;

typedef struct {
    const char *name;
    unsigned char *data;
    size_t size;
    int present;
} fv_file_t;

typedef struct {
    char *source;
    long long offset;
    unsigned long long window_gib;
    unsigned char container[CBM_CONTAINER_SIZE];
    unsigned char body[FV_BODY_LEN];
    cbm_doctor_report_t doctor;
    fv_file_t files[FV_NFILES];
    unsigned long long heatmap_samples;
    unsigned long long heatmap_height;
    pthread_mutex_t lock;
    int lock_init;
    int heatmap_tried;
    int destroyed;
} fv_state_t;

static void fv_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s <container|image> <mountpoint> [--container-offset N] "
            "[--window-gib 26|27|28]\n"
            "       [--allow-device] [fuse options...]\n"
            "Read-only. A block-device source needs --allow-device. "
            "Device writes and MBR repair are out of scope.\n",
            prog);
}

static void fv_fixed6(char *dst, size_t dstlen, double v) {
    if (!(v > 0.0)) v = 0.0;
    if (v > 8.0) v = 8.0;
    unsigned long long scaled = (unsigned long long)(v * 1000000.0 + 0.5);
    snprintf(dst, dstlen, "%u.%06u", (unsigned)(scaled / 1000000ULL),
             (unsigned)(scaled % 1000000ULL));
}

static void fv_cleanup(fv_state_t *st) {
    if (!st) return;
    for (size_t i = 0; i < FV_NFILES; i++) {
        free(st->files[i].data);
        st->files[i].data = NULL;
        st->files[i].size = 0;
        st->files[i].present = 0;
    }
    free(st->source);
    st->source = NULL;
    if (st->lock_init) {
        (void)pthread_mutex_destroy(&st->lock);
        st->lock_init = 0;
    }
    tea_cleanup();
    memset(st, 0, sizeof(*st));
}

/* Take ownership of an open_memstream buffer after a successful write.
 * open_memstream may reallocate the buffer and updates both the caller's
 * pointer and length on flush/close; both must be read back through the
 * pointers, not the values captured when the stream was created. */
static int fv_take_stream(FILE *s, char **bufp, size_t *lenp, fv_file_t *out) {
    if (fflush(s) != 0 || ferror(s)) {
        (void)fclose(s);
        free(*bufp);
        *bufp = NULL;
        return -1;
    }
    if (fclose(s) != 0) {
        free(*bufp);
        *bufp = NULL;
        return -1;
    }
    out->data = (unsigned char *)*bufp;
    out->size = *lenp;
    out->present = 1;
    return 0;
}

static int fv_set_raw(fv_file_t *out, const unsigned char *data, size_t len) {
    if (len > 0 && !data) return -1;
    unsigned char *copy = (unsigned char *)malloc(len ? len : 1u);
    if (!copy) return -1;
    if (len) memcpy(copy, data, len);
    out->data = copy;
    out->size = len;
    out->present = 1;
    return 0;
}

static int fv_source_size(const char *path, unsigned long long *out) {
    struct stat s;
    if (stat(path, &s) != 0) return -1;
    if (S_ISREG(s.st_mode)) {
        if (s.st_size < 0) return -1;
        *out = (unsigned long long)s.st_size;
        return 0;
    }
    if (S_ISBLK(s.st_mode)) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        unsigned long long bytes = 0ULL;
        int rc = ioctl(fd, BLKGETSIZE64, &bytes);
        int saved = errno;
        (void)close(fd);
        if (rc != 0) {
            errno = saved;
            return -1;
        }
        *out = bytes;
        return 0;
    }
    errno = EINVAL;
    return -1;
}

static void fv_heatmap_shape(unsigned long long size,
                             unsigned long long *samples,
                             unsigned long long *height) {
    unsigned long long n = size ? (size + FV_HEATMAP_BLOCK_BYTES - 1ULL) /
                                      FV_HEATMAP_BLOCK_BYTES : 0ULL;
    unsigned long long max_h = (unsigned long long)CBM_HEATMAP_MAX_PIXELS /
                               FV_HEATMAP_WIDTH;
    if (max_h < 1ULL) max_h = 1ULL;
    unsigned long long h = 1ULL;
    if (n) {
        unsigned long long rows = (n + FV_HEATMAP_WIDTH - 1ULL) / FV_HEATMAP_WIDTH;
        h = rows > max_h ? max_h : rows;
    }
    *samples = n;
    *height = h;
}

#if FV_HEATMAP
/* Build the 5F PNG from the source with the same helpers the heatmap CLI
 * uses. png_write_rgb takes a path, so the image is encoded through a memfd
 * exposed at /proc/self/fd/N: no on-disk artifact and no source write. */
static int fv_make_heatmap(fv_state_t *st) {
    unsigned long long size = 0ULL;
    if (fv_source_size(st->source, &size) != 0) {
        fprintf(stderr, "cbm-fuse: cannot size source for heatmap: %s\n",
                strerror(errno));
        return -1;
    }
    if (size > (unsigned long long)CBM_ENTROPY_MAX_SAMPLES *
                   FV_HEATMAP_BLOCK_BYTES) {
        fprintf(stderr, "cbm-fuse: heatmap source exceeds the sample cap\n");
        return -1;
    }
    const size_t block = (size_t)FV_HEATMAP_BLOCK_BYTES;
    cbm_entropy_sample_t *samples = NULL;
    size_t nsamples = 0;
    char err[256] = {0};
    if (cbm_entropy_map(st->source, 0ULL, size, block, &samples, &nsamples,
                        err, sizeof(err)) != 0) {
        fprintf(stderr, "cbm-fuse: %s\n", err[0] ? err : "entropy map failed");
        return -1;
    }

    size_t width = (size_t)FV_HEATMAP_WIDTH;
    size_t max_height = (size_t)CBM_HEATMAP_MAX_PIXELS / width;
    size_t height_cap = max_height ? max_height : 1u;
    size_t height = 1u;
    if (nsamples) {
        size_t rows = (nsamples + width - 1u) / width;
        height = rows > height_cap ? height_cap : rows;
    }
    size_t npixels = width * height;
    if (npixels == 0u || npixels > (size_t)CBM_HEATMAP_MAX_PIXELS) {
        fprintf(stderr, "cbm-fuse: heatmap pixel count out of range\n");
        free(samples);
        return -1;
    }
    cbm_heatmap_pixel_t *pixels = (cbm_heatmap_pixel_t *)calloc(
        npixels, sizeof(*pixels));
    unsigned char *rgb = (unsigned char *)malloc(npixels * 3u);
    if (!pixels || !rgb) {
        fprintf(stderr, "cbm-fuse: out of memory for heatmap image\n");
        free(rgb);
        free(pixels);
        free(samples);
        return -1;
    }
    int rc = -1;
    if (cbm_entropy_downsample(samples, nsamples, width, height,
                               pixels, npixels) != npixels) {
        fprintf(stderr, "cbm-fuse: downsample did not fill the grid\n");
        goto out;
    }
    for (size_t i = 0; i < npixels; i++) {
        rgb[i * 3u] = pixels[i].r;
        rgb[i * 3u + 1u] = pixels[i].g;
        rgb[i * 3u + 2u] = pixels[i].b;
    }

    int fd = memfd_create("cbm-fuse-heatmap", MFD_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "cbm-fuse: memfd_create failed: %s\n", strerror(errno));
        goto out;
    }
    char fdpath[64];
    (void)snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", fd);
    if (png_write_rgb(fdpath, rgb, width, height, err, sizeof(err)) != 0) {
        fprintf(stderr, "cbm-fuse: %s\n", err[0] ? err : "PNG write failed");
        (void)close(fd);
        goto out;
    }
    off_t end = lseek(fd, 0, SEEK_END);
    if (end <= 0 || lseek(fd, 0, SEEK_SET) < 0 ||
        (unsigned long long)end > (unsigned long long)SIZE_MAX) {
        fprintf(stderr, "cbm-fuse: cannot size generated PNG\n");
        (void)close(fd);
        goto out;
    }
    unsigned char *png = (unsigned char *)malloc((size_t)end);
    if (!png) {
        (void)close(fd);
        goto out;
    }
    size_t got = 0;
    while (got < (size_t)end) {
        ssize_t nread = read(fd, png + got, (size_t)end - got);
        if (nread <= 0) break;
        got += (size_t)nread;
    }
    (void)close(fd);
    if (got != (size_t)end) {
        fprintf(stderr, "cbm-fuse: short read of generated PNG\n");
        free(png);
        goto out;
    }
    rc = fv_set_raw(&st->files[FV_HEATMAP_FILE], png, got);
    free(png);
out:
    free(rgb);
    free(pixels);
    free(samples);
    return rc;
}
#endif /* FV_HEATMAP */

static int fv_ensure_heatmap(fv_state_t *st) {
#if FV_HEATMAP
    if (st->files[FV_HEATMAP_FILE].present) return 0;
    (void)pthread_mutex_lock(&st->lock);
    if (!st->heatmap_tried) {
        st->heatmap_tried = 1;
        if (fv_make_heatmap(st) != 0)
            fprintf(stderr, "cbm-fuse: heatmap.png unavailable on this source\n");
    }
    int ok = st->files[FV_HEATMAP_FILE].present;
    (void)pthread_mutex_unlock(&st->lock);
    return ok ? 0 : -1;
#else
    (void)st;
    return -1;
#endif
}

static fv_file_t *fv_lookup(fv_state_t *st, const char *path) {
    if (!path || path[0] != '/' || path[1] == '\0') return NULL;
    const char *name = path + 1;
    if (strchr(name, '/') != NULL) return NULL;
    for (size_t i = 0; i < FV_NFILES; i++) {
        if (strcmp(name, st->files[i].name) != 0) continue;
        if (i == FV_HEATMAP_FILE && fv_ensure_heatmap(st) != 0) return NULL;
        return st->files[i].present ? &st->files[i] : NULL;
    }
    return NULL;
}

static int fv_getattr(const char *path, struct stat *stbuf,
                      struct fuse_file_info *fi) {
    (void)fi;
    fv_state_t *st = (fv_state_t *)fuse_get_context()->private_data;
    memset(stbuf, 0, sizeof(*stbuf));
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0555;
        stbuf->st_nlink = 2;
        return 0;
    }
    fv_file_t *f = fv_lookup(st, path);
    if (!f) return -ENOENT;
    stbuf->st_mode = S_IFREG | 0444;
    stbuf->st_nlink = 1;
    stbuf->st_size = (off_t)f->size;
    return 0;
}

static int fv_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi,
                      enum fuse_readdir_flags flags) {
    (void)offset;
    (void)fi;
    (void)flags;
    fv_state_t *st = (fv_state_t *)fuse_get_context()->private_data;
    if (strcmp(path, "/") != 0) return -ENOTDIR;
    (void)filler(buf, ".", NULL, 0, FUSE_FILL_DIR_PLUS);
    (void)filler(buf, "..", NULL, 0, FUSE_FILL_DIR_PLUS);
    for (size_t i = 0; i < FV_NFILES; i++) {
        if (i == FV_HEATMAP_FILE && fv_ensure_heatmap(st) != 0) continue;
        if (!st->files[i].present) continue;
        (void)filler(buf, st->files[i].name, NULL, 0, FUSE_FILL_DIR_PLUS);
    }
    return 0;
}

static int fv_open(const char *path, struct fuse_file_info *fi) {
    /* No write callback exists; reject write modes at open for EROFS. */
    if ((fi->flags & O_ACCMODE) != O_RDONLY ||
        (fi->flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0)
        return -EROFS;
    fv_state_t *st = (fv_state_t *)fuse_get_context()->private_data;
    return fv_lookup(st, path) ? 0 : -ENOENT;
}

static int fv_read(const char *path, char *buf, size_t size, off_t offset,
                   struct fuse_file_info *fi) {
    (void)fi;
    fv_state_t *st = (fv_state_t *)fuse_get_context()->private_data;
    fv_file_t *f = fv_lookup(st, path);
    if (!f) return -ENOENT;
    if (offset < 0 || (unsigned long long)offset >= (unsigned long long)f->size)
        return 0;
    size_t avail = f->size - (size_t)offset;
    size_t n = size < avail ? size : avail;
    memcpy(buf, f->data + (size_t)offset, n);
    return (int)n;
}

static void fv_destroy(void *private_data) {
    fv_state_t *st = (fv_state_t *)private_data;
    if (!st || st->destroyed) return;
    st->destroyed = 1;
    fv_cleanup(st);
}

static const struct fuse_operations fv_ops = {
    .getattr = fv_getattr,
    .readdir = fv_readdir,
    .open = fv_open,
    .read = fv_read,
    .destroy = fv_destroy,
};

static int fv_parse_u64(const char *s, unsigned long long *out) {
    if (!s || !*s) return -1;
    char *end = NULL;
    errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || !end || end == s || *end != '\0') return -1;
    *out = v;
    return 0;
}

static int fv_parse_offset(const char *s, long long *out) {
    if (!s || !*s) return -1;
    char *end = NULL;
    errno = 0;
    long long v = strtoll(s, &end, 10);
    if (errno != 0 || !end || end == s || *end != '\0' || v < 0) return -1;
    *out = v;
    return 0;
}

static int fv_mountpoint_empty(const char *path) {
    struct stat s;
    if (stat(path, &s) != 0 || !S_ISDIR(s.st_mode)) return 0;
    DIR *d = opendir(path);
    if (!d) return 0;
    int empty = 1;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (!e) break;
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0) {
            empty = 0;
            break;
        }
    }
    int rc = empty && errno == 0;
    (void)closedir(d);
    return rc;
}

static int fv_prepare(fv_state_t *st) {
    static const char *names[FV_NFILES] = {
        "layout.txt", "container.bin", "container.plain", "strings.txt",
        "entropy.txt", "report.json", "heatmap.png"
    };
    for (size_t i = 0; i < FV_NFILES; i++) st->files[i].name = names[i];
    st->files[FV_HEATMAP_FILE].present = 0; /* enabled only by the build flag */

    if (tea_init(NULL) != 0) {
        fprintf(stderr, "cbm-fuse: native TEA init failed\n");
        return -1;
    }
    if (cbm_file_read(st->source, st->offset, st->container,
                      CBM_CONTAINER_SIZE) != 0) {
        fprintf(stderr, "cbm-fuse: cannot read %d bytes from '%s' at offset %lld\n",
                CBM_CONTAINER_SIZE, st->source, st->offset);
        return -1;
    }
    memcpy(st->body, st->container + CBM_HEADER_SIZE, FV_BODY_LEN);
    if (cbm_cbc_decrypt(st->body, FV_BODY_LEN, FV_TEA_KEY) != 0) {
        fprintf(stderr, "cbm-fuse: TEA decryption failed\n");
        return -1;
    }
    /* Prove encrypt(decrypt(x)) == x on the same invariant container_mode
     * checks. The decrypted plaintext must be copied into the re-encryption
     * buffer; copying the original ciphertext would encrypt it a second time. */
    unsigned char reenc[CBM_CONTAINER_SIZE];
    memcpy(reenc, st->container, CBM_CONTAINER_SIZE);
    memcpy(reenc + CBM_HEADER_SIZE, st->body, FV_BODY_LEN);
    if (cbm_cbc_encrypt(reenc + CBM_HEADER_SIZE, FV_BODY_LEN, FV_TEA_KEY) != 0 ||
        memcmp(reenc + CBM_HEADER_SIZE, st->container + CBM_HEADER_SIZE,
               FV_BODY_LEN) != 0) {
        fprintf(stderr, "cbm-fuse: crypto roundtrip failed\n");
        return -1;
    }

    char err[512] = {0};
    if (cbm_doctor_report(st->source, st->window_gib, &st->doctor,
                          err, sizeof(err)) != 0) {
        fprintf(stderr, "cbm-fuse: %s\n", err[0] ? err : "layout report failed");
        return -1;
    }

    if (fv_set_raw(&st->files[FV_CONTAINER], st->container,
                   CBM_CONTAINER_SIZE) != 0 ||
        fv_set_raw(&st->files[FV_PLAIN], st->body, FV_BODY_LEN) != 0)
        return -1;

    /* layout.txt is the unmodified doctor prose report (including the
     * explicit dry-run line). */
    char *prose = NULL;
    size_t prose_len = 0;
    FILE *s = open_memstream(&prose, &prose_len);
    if (!s) return -1;
    char win[32];
    (void)snprintf(win, sizeof(win), "%llu", st->window_gib);
    /* main.c prints this banner once before dispatching doctor; reproduce it
     * so layout.txt is byte-for-byte the CLI prose report. */
    (void)fputs("CBMUsbDisk Linux-Native Tool v1.0\n"
                "==================================\n\n", s);
    char *dav[] = {"cbm-fuse", "doctor", st->source, "--window-gib", win, NULL};
    if (cbm_doctor_cli_ex(5, dav, s, stderr, NULL) != 0) {
        (void)fclose(s);
        free(prose);
        fprintf(stderr, "cbm-fuse: doctor report failed\n");
        return -1;
    }
    if (fv_take_stream(s, &prose, &prose_len, &st->files[FV_LAYOUT]) != 0)
        return -1;

    char *text = NULL;
    size_t text_len = 0;
    s = open_memstream(&text, &text_len);
    if (!s) return -1;
    cbm_inspect_strings(st->body, FV_BODY_LEN, FV_MIN_STRING, s);
    if (fv_take_stream(s, &text, &text_len, &st->files[FV_STRINGS]) != 0)
        return -1;

    text = NULL;
    text_len = 0;
    s = open_memstream(&text, &text_len);
    if (!s) return -1;
    char fixed[32];
    fv_fixed6(fixed, sizeof(fixed), cbm_decode_entropy(st->body, FV_BODY_LEN));
    (void)fprintf(s, "entropy_body %s\n", fixed);
    cbm_decode_profile(st->body, FV_BODY_LEN, s);
    if (fv_take_stream(s, &text, &text_len, &st->files[FV_ENTROPY]) != 0)
        return -1;

    unsigned long long source_size = 0ULL;
    if (fv_source_size(st->source, &source_size) != 0) {
        fprintf(stderr, "cbm-fuse: cannot stat source: %s\n", strerror(errno));
        return -1;
    }
    fv_heatmap_shape(source_size, &st->heatmap_samples, &st->heatmap_height);

    text = NULL;
    text_len = 0;
    s = open_memstream(&text, &text_len);
    if (!s) return -1;
    cbm_json_t j;
    cbm_json_object_begin(&j, s, "fuse", "ok");
    cbm_json_field_string(&j, "path", st->source);
    cbm_json_field_u64(&j, "container_offset", (unsigned long long)st->offset);
    cbm_json_field_u64(&j, "window_gib", st->window_gib);
    cbm_json_object_start(&j, "container");
    cbm_json_field_string(&j, "path", st->source);
    cbm_json_field_string(&j, "backend", "native");
    cbm_json_field_u64(&j, "header_byte", st->container[0]);
    cbm_json_field_bool(&j, "encrypted",
                        cbm_check_encrypted(st->container,
                                            CBM_CONTAINER_SIZE) == CBM_ERR_ENCRYPTED);
    cbm_json_field_u64(&j, "body_len", FV_BODY_LEN);
    cbm_json_field_fixed6(&j, "entropy_body",
                          cbm_decode_entropy(st->body, FV_BODY_LEN));
    cbm_json_field_bool(&j, "roundtrip_ok", 1);
    cbm_json_object_end(&j);
    cbm_json_object_start(&j, "doctor");
    cbm_json_field_string(&j, "path", st->source);
    cbm_json_field_u64(&j, "window_gib", st->window_gib);
    cbm_json_field_bool(&j, "mbr_valid", st->doctor.mbr_ok);
    cbm_json_field_bool(&j, "dj_ok", st->doctor.dj_ok);
    cbm_json_field_bool(&j, "window_consistent", st->doctor.window_consistent);
    cbm_json_array_begin(&j, "partitions");
    unsigned char mbr[CBM_SECTOR_SIZE];
    cbm_layout_t layout;
    if (cbm_file_read(st->source, 0, mbr, sizeof(mbr)) == 0 &&
        cbm_layout_parse(mbr, sizeof(mbr), &layout) == 0) {
        static const char *part_names[4] = {
            "DJ_BOOT", "DJ_OS", "DJ_DATA", "PART3"
        };
        for (int i = 0; i < layout.part_count && i < 4; i++) {
            cbm_json_element_object(&j);
            cbm_json_field_string(&j, "name", part_names[i]);
            cbm_json_field_u64(&j, "start_lba", layout.parts[i].start_lba);
            cbm_json_field_u64(&j, "sectors", layout.parts[i].size_lba);
            cbm_json_field_u64(&j, "type", layout.parts[i].type);
            cbm_json_field_bool(&j, "inferred", 0);
            cbm_json_object_end(&j);
        }
    }
    cbm_json_array_end(&j);
    cbm_json_field_bool(&j, "repair_performed", 0);
    cbm_json_field_bool(&j, "dry_run", 1);
    cbm_json_object_end(&j);
#if FV_HEATMAP
    cbm_json_object_start(&j, "heatmap");
    cbm_json_field_u64(&j, "block_bytes", FV_HEATMAP_BLOCK_BYTES);
    cbm_json_field_u64(&j, "samples", st->heatmap_samples);
    cbm_json_field_u64(&j, "width", FV_HEATMAP_WIDTH);
    cbm_json_field_u64(&j, "height", st->heatmap_height);
    cbm_json_object_end(&j);
#endif
    cbm_json_array_begin(&j, "files");
    for (size_t i = 0; i < FV_NFILES; i++) {
        int listed = st->files[i].present;
        if (i == FV_REPORT || i == FV_HEATMAP_FILE) listed = 1;
        if (!listed) continue;
        cbm_json_element_object(&j);
        cbm_json_field_string(&j, "name", st->files[i].name);
        cbm_json_field_u64(&j, "size", i == FV_HEATMAP_FILE ? 0ULL
                                        : (unsigned long long)st->files[i].size);
        cbm_json_object_end(&j);
    }
    cbm_json_array_end(&j);
    cbm_json_end(&j);
    if (fv_take_stream(s, &text, &text_len, &st->files[FV_REPORT]) != 0)
        return -1;

    /* heatmap.png stays absent until fv_ensure_heatmap builds it on demand. */
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fv_usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        fv_usage(argv[0]);
        return 0;
    }

    fv_state_t st;
    memset(&st, 0, sizeof(st));
    st.window_gib = 26ULL;
    char *fargv[FV_FUSE_ARGV_MAX];
    int fac = 0;
    fargv[fac++] = argv[0];
    const char *source = NULL, *mount = NULL;
    int allow_device = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--container-offset") == 0) {
            if (++i >= argc || fv_parse_offset(argv[i], &st.offset) != 0) {
                fprintf(stderr, "cbm-fuse: --container-offset needs a non-negative integer\n");
                fv_usage(argv[0]);
                return 2;
            }
        } else if (strcmp(a, "--window-gib") == 0) {
            if (++i >= argc || fv_parse_u64(argv[i], &st.window_gib) != 0 ||
                (st.window_gib != 26ULL && st.window_gib != 27ULL &&
                 st.window_gib != 28ULL)) {
                fprintf(stderr, "cbm-fuse: --window-gib must be 26, 27 or 28\n");
                fv_usage(argv[0]);
                return 2;
            }
        } else if (strcmp(a, "--allow-device") == 0) {
            allow_device = 1;
        } else if (a[0] == '-') {
            if (fac >= FV_FUSE_ARGV_MAX - 1) {
                fprintf(stderr, "cbm-fuse: too many FUSE options\n");
                return 2;
            }
            fargv[fac++] = argv[i];
        } else if (!source) {
            source = a;
        } else if (!mount) {
            mount = a;
        } else {
            fprintf(stderr, "cbm-fuse: unexpected argument '%s'\n", a);
            fv_usage(argv[0]);
            return 2;
        }
    }
    if (!source || !mount) {
        fv_usage(argv[0]);
        return 2;
    }
    if (!fv_mountpoint_empty(mount)) {
        fprintf(stderr, "cbm-fuse: mountpoint must be an existing empty directory: %s\n",
                mount);
        return 2;
    }
    struct stat sbuf;
    if (stat(source, &sbuf) != 0) {
        fprintf(stderr, "cbm-fuse: cannot stat source '%s': %s\n",
                source, strerror(errno));
        return 1;
    }
    if (!S_ISREG(sbuf.st_mode) && !S_ISBLK(sbuf.st_mode)) {
        fprintf(stderr, "cbm-fuse: source must be a regular file or block device\n");
        return 2;
    }
    if (cbm_file_is_blockdev(source) && !allow_device) {
        fprintf(stderr, "cbm-fuse: block-device source refused without --allow-device\n");
        return 2;
    }
    st.source = strdup(source);
    if (!st.source) {
        fprintf(stderr, "cbm-fuse: out of memory\n");
        return 1;
    }
    if (pthread_mutex_init(&st.lock, NULL) != 0) {
        fprintf(stderr, "cbm-fuse: mutex init failed\n");
        free(st.source);
        return 1;
    }
    st.lock_init = 1;
    if (fv_prepare(&st) != 0) {
        fv_cleanup(&st);
        return 1;
    }
    fargv[fac++] = (char *)mount;
    fargv[fac] = NULL;

    /* A shell that launches this daemon in the background starts it with
     * SIGINT ignored, and libfuse deliberately leaves ignored signals alone.
     * Restore the default so fuse_main installs its clean-unmount handler. */
    (void)signal(SIGINT, SIG_DFL);

    /* fuse_main installs SIGINT/SIGTERM handlers and an exit handler that
     * unmounts; fv_destroy releases all buffers after a clean unmount. */
    int rc = fuse_main(fac, fargv, &fv_ops, &st);
    if (!st.destroyed) fv_cleanup(&st);
    return rc;
}
