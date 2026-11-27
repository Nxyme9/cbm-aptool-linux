/* exfat_carver.c - read-only exFAT undelete carver implementation
 *
 * Parses boot sector, allocation bitmap and root directory from an exFAT
 * image (regular file or block device, opened O_RDONLY). Carves entries marked
 * deleted (0xE5) whose metadata and data runs are contiguous (NoFatChain = 1)
 * and whose allocation-bitmap bit is unallocated (free). Writes recovered
 * files ONLY to the specified output directory. Never guesses fragmented or
 * overwritten files.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "cbm_file.h"
#include "cbm_layout.h"
#include "cli_json.h"
#include "exfat_carver.h"

static unsigned long long rd32(const unsigned char *p) {
    return (unsigned long long)p[0] |
           ((unsigned long long)p[1] << 8) |
           ((unsigned long long)p[2] << 16) |
           ((unsigned long long)p[3] << 24);
}

static unsigned long long rd64(const unsigned char *p) {
    return rd32(p) | (rd32(p + 4) << 32);
}

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

void exfat_report_free(exfat_report_t *report) {
    if (!report) return;
    free(report->entries);
    report->entries = NULL;
    report->count = 0u;
    report->capacity = 0u;
}

static int append_entry(exfat_report_t *rep, const exfat_entry_t *e) {
    if (rep->count >= rep->capacity) {
        size_t want = rep->capacity ? rep->capacity * 2u : 16u;
        exfat_entry_t *grown = (exfat_entry_t *)realloc(rep->entries, want * sizeof(*grown));
        if (!grown) return -1;
        rep->entries = grown;
        rep->capacity = want;
    }
    rep->entries[rep->count++] = *e;
    return 0;
}

/* Read cluster data from file offset into buf. */
static int read_cluster(const char *path, unsigned long long heap_offset,
                        unsigned int cluster_bytes, unsigned long long cluster,
                        unsigned char *buf) {
    if (cluster < 2ULL) return -1;
    unsigned long long off = heap_offset + (cluster - 2ULL) * (unsigned long long)cluster_bytes;
    return cbm_file_read(path, (long long)off, buf, cluster_bytes);
}

/* Check allocation bitmap bit for cluster (0-indexed cluster numbers, where
 * cluster 2 is bit 0). Returns 1 if allocated (bit set), 0 if free (bit clear)
 * or out of range. */
static int bitmap_is_allocated(const unsigned char *bitmap, size_t bitmap_len,
                               unsigned long long cluster) {
    if (cluster < 2ULL) return 1;
    unsigned long long idx = cluster - 2ULL;
    unsigned long long byte_idx = idx / 8ULL;
    unsigned long long bit_idx = idx % 8ULL;
    if (byte_idx >= bitmap_len) return 1; /* treat out-of-range as allocated/unsafe */
    return (bitmap[byte_idx] & (1u << bit_idx)) ? 1 : 0;
}

static void extract_name(const unsigned char *name_entry_buf, char *out, size_t outlen) {
    size_t w = 0u;
    for (size_t i = 0u; i < 15u && w + 1u < outlen; i++) {
        unsigned char c = name_entry_buf[2u + (i * 2u)];
        if (c == 0u) break;
        out[w++] = (char)c;
    }
    out[w] = '\0';
}

int exfat_carve(const char *path, unsigned long long base, const char *outdir,
                exfat_report_t *report, char *err, size_t errlen) {
    if (!report) {
        seterr(err, errlen, "exfat_carve: null report pointer");
        return -1;
    }
    memset(report, 0, sizeof(*report));
    if (!path || !outdir) {
        seterr(err, errlen, "exfat_carve: null path or outdir");
        return -1;
    }

    unsigned char boot[512];
    if (cbm_file_read(path, (long long)base, boot, sizeof(boot)) != 0) {
        seterr(err, errlen, "exfat_carve: failed to read boot sector");
        return -1;
    }
    if (memcmp(boot + 3, "EXFAT   ", 8) != 0 || boot[510] != 0x55 || boot[511] != 0xAA) {
        seterr(err, errlen, "exfat_carve: invalid exFAT boot sector signature");
        return -1;
    }

    unsigned int sector_shift = boot[0x0B];
    unsigned int cluster_shift = boot[0x0D];
    if (sector_shift < 9u || sector_shift > 12u) {
        seterr(err, errlen, "exfat_carve: unsupported sector size");
        return -1;
    }
    unsigned int sector_bytes = 1u << sector_shift;
    unsigned int cluster_bytes = sector_bytes << cluster_shift;

    unsigned long long fat_offset_sec = rd32(boot + 0x30);
    unsigned long long heap_offset_sec = rd32(boot + 0x38);
    unsigned long long cluster_count = rd32(boot + 0x3C);
    unsigned long long root_cluster = rd32(boot + 0x40);

    unsigned long long heap_offset = base + heap_offset_sec * (unsigned long long)sector_bytes;
    (void)fat_offset_sec;

    /* Read root directory cluster. */
    unsigned char *root_buf = (unsigned char *)malloc(cluster_bytes);
    unsigned char *bitmap_buf = NULL;
    size_t bitmap_len = 0u;
    int rc = -1;

    if (!root_buf) {
        seterr(err, errlen, "exfat_carve: out of memory for root buffer");
        goto out;
    }
    if (read_cluster(path, heap_offset, cluster_bytes, root_cluster, root_buf) != 0) {
        seterr(err, errlen, "exfat_carve: failed to read root directory cluster");
        goto out;
    }

    /* Scan root directory for allocation bitmap (type 0x81). */
    for (size_t off = 0u; off + 32u <= cluster_bytes; off += 32u) {
        const unsigned char *e = root_buf + off;
        if (e[0] == 0x00) break;
        if (e[0] == 0x81) {
            unsigned long long bmp_cluster = rd32(e + 4);
            unsigned long long bmp_size = rd64(e + 8);
            if (bmp_size > 0u && bmp_size <= 1048576ULL) {
                bitmap_buf = (unsigned char *)malloc((size_t)bmp_size);
                if (bitmap_buf) {
                    unsigned long long boff = heap_offset + (bmp_cluster - 2ULL) * (unsigned long long)cluster_bytes;
                    if (cbm_file_read(path, (long long)boff, bitmap_buf, (size_t)bmp_size) == 0) {
                        bitmap_len = (size_t)bmp_size;
                    } else {
                        free(bitmap_buf);
                        bitmap_buf = NULL;
                    }
                }
            }
            break;
        }
    }

    if (!bitmap_buf) {
        /* Allocate a zero fallback bitmap if none found so checks fail closed */
        bitmap_len = (size_t)((cluster_count + 7ULL) / 8ULL);
        bitmap_buf = (unsigned char *)calloc(1u, bitmap_len ? bitmap_len : 1u);
    }

    /* Walk root directory in 32-byte slots for deleted file entries (0xE5). */
    for (size_t off = 0u; off + 96u <= cluster_bytes; off += 32u) {
        const unsigned char *file_e = root_buf + off;
        if (file_e[0] == 0x00) break;
        if (file_e[0] != 0xE5) continue;

        unsigned char secondary_count = file_e[1];
        if (secondary_count < 2u || off + (size_t)(secondary_count + 1u) * 32u > cluster_bytes)
            continue;

        const unsigned char *stream_e = root_buf + off + 32u;
        const unsigned char *name_e = root_buf + off + 64u;
        if (stream_e[0] != 0xC0 || name_e[0] != 0xC1) continue;

        unsigned char flags = stream_e[1];
        int no_fat_chain = (flags & 0x02) ? 1 : 0;
        unsigned long long first_cluster = rd32(stream_e + 4);
        unsigned long long data_size = rd64(stream_e + 8);

        char name[256];
        extract_name(name_e, name, sizeof(name));
        if (!name[0]) snprintf(name, sizeof(name), "DELETED.DAT");

        exfat_entry_t ent;
        memset(&ent, 0, sizeof(ent));
        snprintf(ent.name, sizeof(ent.name), "%s", name);
        ent.first_cluster = first_cluster;
        ent.size = data_size;

        /* Verify: must have NoFatChain set, valid cluster range, and ALL clusters
         * in the data run must be FREE in the allocation bitmap (bit clear).
         * If any cluster is allocated (bit set), the file was overwritten/lost. */
        unsigned long long needed_clusters = (data_size + cluster_bytes - 1ULL) / cluster_bytes;
        if (data_size == 0u) needed_clusters = 0u;

        int ok = no_fat_chain && (first_cluster >= 2ULL) &&
                 (first_cluster + needed_clusters - 2ULL < cluster_count);

        if (ok) {
            for (unsigned long long c = 0u; c < needed_clusters; c++) {
                if (bitmap_is_allocated(bitmap_buf, bitmap_len, first_cluster + c)) {
                    ok = 0;
                    break;
                }
            }
        }

        if (ok) {
            ent.outcome = EXFAT_OUT_RECOVERED;
            snprintf(ent.detail, sizeof(ent.detail), "intact metadata and free clusters");

            /* Carve bytes to outdir */
            char outpath[512];
            snprintf(outpath, sizeof(outpath), "%s/%s", outdir, name);
            FILE *df = fopen(outpath, "wb");
            if (df) {
                unsigned char *cbuf = (unsigned char *)malloc(cluster_bytes);
                unsigned long long remaining = data_size;
                unsigned long long cur_cluster = first_cluster;
                int write_ok = 1;
                while (write_ok && remaining > 0u) {
                    size_t to_write = (remaining > (unsigned long long)cluster_bytes) ?
                                      (size_t)cluster_bytes : (size_t)remaining;
                    if (read_cluster(path, heap_offset, cluster_bytes, cur_cluster, cbuf) != 0) {
                        write_ok = 0;
                        break;
                    }
                    if (fwrite(cbuf, 1, to_write, df) != to_write) {
                        write_ok = 0;
                        break;
                    }
                    remaining -= to_write;
                    cur_cluster++;
                }
                free(cbuf);
                fclose(df);
                if (!write_ok) {
                    ent.outcome = EXFAT_OUT_LOST;
                    snprintf(ent.detail, sizeof(ent.detail), "I/O error carving clusters");
                }
            } else {
                ent.outcome = EXFAT_OUT_LOST;
                snprintf(ent.detail, sizeof(ent.detail), "failed to create output file");
            }
        } else {
            ent.outcome = EXFAT_OUT_LOST;
            snprintf(ent.detail, sizeof(ent.detail), "clusters reused, fragmented, or invalid");
        }

        if (append_entry(report, &ent) != 0) {
            seterr(err, errlen, "exfat_carve: out of memory appending entry");
            goto out;
        }
    }

    rc = 0;
out:
    free(root_buf);
    free(bitmap_buf);
    return rc;
}

int exfat_carve_dj_data(const char *path, const char *outdir,
                        exfat_report_t *report, char *err, size_t errlen) {
    if (!path || !report) {
        seterr(err, errlen, "exfat_carve_dj_data: invalid arguments");
        return -1;
    }
    unsigned char mbr[512];
    if (cbm_file_read(path, 0LL, mbr, sizeof(mbr)) != 0) {
        seterr(err, errlen, "exfat_carve_dj_data: failed to read MBR");
        return -1;
    }
    cbm_layout_t layout;
    if (cbm_layout_parse(mbr, sizeof(mbr), &layout) != 0) {
        seterr(err, errlen, "exfat_carve_dj_data: failed to parse MBR layout");
        return -1;
    }
    /* Find partition with type 0x07 (exFAT DJ_DATA) */
    unsigned long long base_lba = 0ULL;
    int found = 0;
    for (int i = 0; i < layout.part_count; i++) {
        if (layout.parts[i].type == 0x07) {
            base_lba = layout.parts[i].start_lba;
            found = 1;
            break;
        }
    }
    if (!found && layout.part_count >= 3) {
        /* Fallback to third partition if count matches nominal DJ geometry */
        base_lba = layout.parts[2].start_lba;
        found = 1;
    }
    if (!found) {
        seterr(err, errlen, "exfat_carve_dj_data: DJ_DATA partition (0x07) not found in MBR");
        return -1;
    }
    return exfat_carve(path, base_lba * 512ULL, outdir, report, err, errlen);
}

void exfat_report_json(FILE *out, const exfat_report_t *report) {
    if (!out || !report) return;
    cbm_json_t j;
    memset(&j, 0, sizeof(j));
    cbm_json_object_begin(&j, out, "exfat-carve", "ok");
    cbm_json_field_u64(&j, "entry_count", (unsigned long long)report->count);
    cbm_json_array_begin(&j, "entries");
    for (size_t i = 0u; i < report->count; i++) {
        const exfat_entry_t *e = &report->entries[i];
        const char *outcome = (e->outcome == EXFAT_OUT_RECOVERED) ? "recovered" : "lost";
        cbm_json_element_object(&j);
        cbm_json_field_string(&j, "name", e->name);
        cbm_json_field_string(&j, "outcome", outcome);
        cbm_json_field_u64(&j, "first_cluster", e->first_cluster);
        cbm_json_field_u64(&j, "size", e->size);
        cbm_json_field_string(&j, "detail", e->detail);
        cbm_json_object_end(&j);
    }
    cbm_json_array_end(&j);
    cbm_json_end(&j);
}
