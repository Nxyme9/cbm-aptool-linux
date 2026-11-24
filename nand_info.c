/* nand_info.c - NAND controller identity probe (host-observable) */
#define _GNU_SOURCE
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "nand_info.h"

static int read_sysfs(const char *path, char *buf, size_t len) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(buf, (int)len, f)) { fclose(f); return -1; }
    fclose(f);
    size_t n = strlen(buf);
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = '\0';
    return 0;
}

static int resolve_usb_dir(const char *block_dev, char *out, size_t outlen) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/block/%s", block_dev);
    char abs[PATH_MAX];
    if (!realpath(path, abs)) return -1;

    /* Walk up from the block device looking for the USB device (has idVendor). */
    for (int i = 0; i < 16; i++) {
        char probe[PATH_MAX];
        snprintf(probe, sizeof(probe), "%s/idVendor", abs);
        if (access(probe, R_OK) == 0) {
            snprintf(out, outlen, "%s", abs);
            return 0;
        }
        char *slash = strrchr(abs, '/');
        if (!slash || slash == abs) break;
        *slash = '\0';
    }
    return -1;
}

static void find_driver(const char *usbdir, char *drv, size_t drvlen) {
    DIR *d = opendir(usbdir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        /* USB interfaces are named like "1-4:1.0", "1-4:1.1". */
        if (!strstr(e->d_name, ":1.")) continue;
        char p[PATH_MAX];
        snprintf(p, sizeof(p), "%s/%s/driver", usbdir, e->d_name);
        char link[PATH_MAX] = {0};
        ssize_t n = readlink(p, link, sizeof(link) - 1);
        if (n < 0) continue;
        link[n] = '\0';
        const char *base = strrchr(link, '/');
        snprintf(drv, drvlen, "%s", base ? base + 1 : link);
        break;
    }
    closedir(d);
}

int nand_info_probe(const char *block_dev, nand_info_t *info) {
    if (!block_dev || !info) return -1;
    memset(info, 0, sizeof(*info));

    char usbdir[PATH_MAX];
    if (resolve_usb_dir(block_dev, usbdir, sizeof(usbdir)) != 0) return -1;
    snprintf(info->sysfs_path, sizeof(info->sysfs_path), "%s", usbdir);

    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/idVendor", usbdir);
    read_sysfs(p, info->vendor_id, sizeof(info->vendor_id));
    snprintf(p, sizeof(p), "%s/idProduct", usbdir);
    read_sysfs(p, info->product_id, sizeof(info->product_id));
    snprintf(p, sizeof(p), "%s/manufacturer", usbdir);
    read_sysfs(p, info->vendor, sizeof(info->vendor));
    snprintf(p, sizeof(p), "%s/product", usbdir);
    read_sysfs(p, info->model, sizeof(info->model));
    find_driver(usbdir, info->driver, sizeof(info->driver));

    if (info->vendor_id[0] == '\0') return -1;
    return 0;
}

int nand_info_is_chipsbank(const nand_info_t *info) {
    /* Chipsbank Co. Ltd USB VID = 0x048d */
    return info && strncasecmp(info->vendor_id, "048d", 4) == 0;
}
