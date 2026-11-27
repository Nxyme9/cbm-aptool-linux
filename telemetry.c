/* telemetry.c - read-only Prometheus telemetry exporter implementation
 *
 * Everything here is read-only with respect to the observed device: regular
 * files are stat()ed, block devices are opened O_RDONLY for BLKGETSIZE64, and
 * counters are loaded from a caller-named key=value file. The HTTP listener is
 * loopback by default (":PORT"); no authentication is provided, so exposing it
 * on a routable interface is an explicit opt-in by the caller.
 */
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/fs.h>

#include "cbm_backend.h"
#include "cli_json.h"
#include "telemetry.h"

void telemetry_state_init(telemetry_state_t *st) {
    if (!st) return;
    memset(st, 0, sizeof(*st));
    st->crypto_backend_native = 1; /* clean-room native TEA is the default */
}

static void errbuf(char **err, size_t *errlen, char *dummy, size_t dummy_len) {
    if (!*err || *errlen == 0u) {
        *err = dummy;
        *errlen = dummy_len;
    }
}

static char *trim_ws(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' ||
                       end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }
    return s;
}

int telemetry_scrub_device(const char *path, char *out, size_t outlen,
                           char *err, size_t errlen) {
    char dummy[8], resolved[4096];
    errbuf(&err, &errlen, dummy, sizeof(dummy));
    (void)err;
    (void)errlen;
    if (!out || outlen == 0u) return -1;
    out[0] = '\0';
    if (!path || !*path || realpath(path, resolved) == NULL) {
        snprintf(out, outlen, "%s", "unknown");
        return 0;
    }
    const char *base = strrchr(resolved, '/');
    base = base ? base + 1 : resolved;
    snprintf(out, outlen, "%s", base && *base ? base : "unknown");
    return 0;
}

int telemetry_probe_device(const char *path, telemetry_state_t *st,
                           char *err, size_t errlen) {
    char dummy[8];
    errbuf(&err, &errlen, dummy, sizeof(dummy));
    (void)err;
    (void)errlen;
    if (!path || !st) return -1;
    telemetry_scrub_device(path, st->device_label, sizeof(st->device_label),
                           NULL, 0u);
    st->device_present = 0;
    st->device_capacity_bytes = 0ULL;

    struct stat sb;
    if (stat(path, &sb) != 0) return 0; /* absent device, not an error */
    if (S_ISREG(sb.st_mode)) {
        st->device_present = 1;
        st->device_capacity_bytes = (unsigned long long)sb.st_size;
    } else if (S_ISBLK(sb.st_mode)) {
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            uint64_t bytes = 0u;
            if (ioctl(fd, BLKGETSIZE64, &bytes) == 0) {
                st->device_present = 1;
                st->device_capacity_bytes = (unsigned long long)bytes;
            }
            close(fd);
        }
    }
    return 0;
}

static int parse_u64(const char *s, unsigned long long *out) {
    if (!s || !*s || s[0] < '0' || s[0] > '9') return -1;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || !end || *end != '\0') return -1;
    *out = v;
    return 0;
}

static int parse_ratio(const char *s, double *out) {
    if (!s || !*s) return -1;
    errno = 0;
    char *end = NULL;
    double v = strtod(s, &end);
    if (errno != 0 || !end || *end != '\0') return -1;
    if (!(v >= 0.0 && v <= 1.0)) return -1; /* rejects NaN and infinities */
    *out = v;
    return 0;
}

static int apply_state_line(telemetry_state_t *tmp, char *line, unsigned lineno,
                            char *err, size_t errlen) {
    line[strcspn(line, "\r\n")] = '\0';
    char *p = trim_ws(line);
    if (*p == '\0' || *p == '#') return 0;
    char *eq = strchr(p, '=');
    if (!eq) {
        snprintf(err, errlen, "state line %u: missing '='", lineno);
        return -1;
    }
    *eq = '\0';
    const char *key = trim_ws(p);
    const char *val = trim_ws(eq + 1);
    if (!*key || !*val) {
        snprintf(err, errlen, "state line %u: empty key or value", lineno);
        return -1;
    }
    unsigned long long u;
    if (strcmp(key, "scan_progress_ratio") == 0) {
        double v;
        if (parse_ratio(val, &v) != 0) {
            snprintf(err, errlen, "state line %u: bad ratio '%s'", lineno, val);
            return -1;
        }
        tmp->scan_progress_ratio = v;
        return 0;
    }
    if (strcmp(key, "containers_found") == 0 ||
        strcmp(key, "cdb_commands_total") == 0 ||
        strcmp(key, "entropy_blocks_total") == 0 ||
        strcmp(key, "last_validation_timestamp_seconds") == 0) {
        if (parse_u64(val, &u) != 0) {
            snprintf(err, errlen, "state line %u: bad unsigned '%s'", lineno, val);
            return -1;
        }
        if (strcmp(key, "containers_found") == 0) tmp->containers_found = u;
        else if (strcmp(key, "cdb_commands_total") == 0) tmp->cdb_commands_total = u;
        else if (strcmp(key, "entropy_blocks_total") == 0) tmp->entropy_blocks_total = u;
        else tmp->last_validation_timestamp_seconds = u;
        return 0;
    }
    snprintf(err, errlen, "state line %u: unknown key '%s'", lineno, key);
    return -1;
}

int telemetry_load_state(const char *path, telemetry_state_t *st,
                         char *err, size_t errlen) {
    char dummy[8];
    errbuf(&err, &errlen, dummy, sizeof(dummy));
    if (!path || !st) {
        snprintf(err, errlen, "telemetry state: invalid arguments");
        return -1;
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(err, errlen, "telemetry state: cannot open state file");
        return -1;
    }
    telemetry_state_t tmp = *st;
    char line[256];
    unsigned lineno = 0u;
    while (fgets(line, sizeof(line), f) != NULL) {
        lineno++;
        if (apply_state_line(&tmp, line, lineno, err, errlen) != 0) {
            fclose(f);
            return -1;
        }
    }
    if (ferror(f)) {
        fclose(f);
        snprintf(err, errlen, "telemetry state: read error");
        return -1;
    }
    fclose(f);
    *st = tmp;
    return 0;
}

static void emit_label(FILE *out, const char *label) {
    fputs("{device=\"", out);
    for (const char *p = label ? label : ""; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '\\' || c == '"') {
            fputc('\\', out);
            fputc((int)c, out);
        } else if (c == '\n') {
            fputs("\\n", out);
        } else if (c >= 0x20u && c < 0x7fu) {
            fputc((int)c, out);
        } else {
            fputc('_', out); /* no control bytes in the exposition format */
        }
    }
    fputs("\"}", out);
}

void telemetry_render(FILE *out, const telemetry_state_t *st) {
    if (!out || !st) return;
    fputs("# HELP device_present 1 when the device is observable read-only, else 0.\n"
          "# TYPE device_present gauge\n"
          "device_present", out);
    emit_label(out, st->device_label);
    fprintf(out, " %d\n", st->device_present ? 1 : 0);

    fputs("# HELP device_capacity_bytes Capacity of the observed device in bytes.\n"
          "# TYPE device_capacity_bytes gauge\n"
          "device_capacity_bytes", out);
    emit_label(out, st->device_label);
    fprintf(out, " %llu\n", st->device_capacity_bytes);

    fprintf(out,
            "# HELP scan_progress_ratio Last reported scan progress (0..1).\n"
            "# TYPE scan_progress_ratio gauge\n"
            "scan_progress_ratio %.6f\n"
            "# HELP containers_found Containers found by the last scan.\n"
            "# TYPE containers_found counter\n"
            "containers_found %llu\n"
            "# HELP cdb_commands_total CDB commands seen by the last capture.\n"
            "# TYPE cdb_commands_total counter\n"
            "cdb_commands_total %llu\n"
            "# HELP entropy_blocks_total Blocks measured by the last entropy map.\n"
            "# TYPE entropy_blocks_total counter\n"
            "entropy_blocks_total %llu\n"
            "# HELP last_validation_timestamp_seconds Unix time of the last validation.\n"
            "# TYPE last_validation_timestamp_seconds gauge\n"
            "last_validation_timestamp_seconds %llu\n"
            "# HELP crypto_backend_native 1 when the native TEA backend is selected.\n"
            "# TYPE crypto_backend_native gauge\n"
            "crypto_backend_native %d\n",
            st->scan_progress_ratio, st->containers_found,
            st->cdb_commands_total, st->entropy_blocks_total,
            st->last_validation_timestamp_seconds,
            st->crypto_backend_native ? 1 : 0);
}

int telemetry_listen(const char *addr, int *fd, char *err, size_t errlen) {
    char dummy[8];
    errbuf(&err, &errlen, dummy, sizeof(dummy));
    if (!addr || !fd) {
        snprintf(err, errlen, "telemetry listen: invalid arguments");
        return -1;
    }
    const char *colon = strrchr(addr, ':');
    if (!colon) {
        snprintf(err, errlen, "telemetry listen: expected HOST:PORT or :PORT");
        return -1;
    }
    char host[64];
    size_t hlen = (size_t)(colon - addr);
    if (hlen == 0u) {
        host[0] = '\0';
    } else if (hlen >= sizeof(host)) {
        snprintf(err, errlen, "telemetry listen: host too long");
        return -1;
    } else {
        memcpy(host, addr, hlen);
        host[hlen] = '\0';
    }
    const char *portstr = colon + 1;
    if (!*portstr) {
        snprintf(err, errlen, "telemetry listen: missing port");
        return -1;
    }
    for (const char *p = portstr; *p; p++) {
        if (*p < '0' || *p > '9') {
            snprintf(err, errlen, "telemetry listen: port must be decimal digits");
            return -1;
        }
    }
    errno = 0;
    char *pend = NULL;
    long port = strtol(portstr, &pend, 10);
    if (errno != 0 || !pend || *pend != '\0' || port < 0 || port > 65535) {
        snprintf(err, errlen, "telemetry listen: port out of range");
        return -1;
    }
    if (hlen == 0u) snprintf(host, sizeof(host), "%s", "127.0.0.1");
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        snprintf(err, errlen,
                 "telemetry listen: host must be numeric IPv4 (or :PORT)");
        return -1;
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        snprintf(err, errlen, "telemetry listen: socket failed: %s", strerror(errno));
        return -1;
    }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        snprintf(err, errlen, "telemetry listen: bind failed: %s", strerror(errno));
        close(s);
        return -1;
    }
    if (listen(s, 16) != 0) {
        snprintf(err, errlen, "telemetry listen: listen failed: %s", strerror(errno));
        close(s);
        return -1;
    }
    *fd = s;
    return 0;
}

static void send_all(int fd, const char *buf, size_t len) {
    size_t off = 0u;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) return;
        off += (size_t)n;
    }
}

static void respond(int fd, int code, const char *reason, const char *ctype,
                    const char *extra, const char *body) {
    char head[512];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %d %s\r\nContent-Type: %s\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n%s\r\n",
                     code, reason, ctype, strlen(body), extra ? extra : "");
    if (n < 0 || (size_t)n >= sizeof(head)) return;
    send_all(fd, head, (size_t)n);
    send_all(fd, body, strlen(body));
}

static int telemetry_refresh(telemetry_state_t *st) {
    char err[192];
    if (st->state_file[0] != '\0') {
        if (telemetry_load_state(st->state_file, st, err, sizeof(err)) != 0) {
            fprintf(stderr, "telemetry: state refresh failed: %s\n", err);
            return -1;
        }
    }
    if (st->device_path[0] != '\0') {
        if (telemetry_probe_device(st->device_path, st, err, sizeof(err)) != 0) {
            fprintf(stderr, "telemetry: device probe failed\n");
            return -1;
        }
    }
    return 0;
}

void telemetry_handle_conn(int fd, telemetry_state_t *st) {
    if (fd < 0 || !st) return;
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    char req[4096];
    size_t got = 0u;
    req[0] = '\0';
    while (got + 1u < sizeof(req)) {
        ssize_t n = recv(fd, req + got, sizeof(req) - 1u - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
        req[got] = '\0';
        if (strstr(req, "\r\n\r\n") != NULL || strstr(req, "\n\n") != NULL) break;
    }
    char method[16] = "", target[1024] = "";
    if (sscanf(req, "%15s %1023s", method, target) < 2) {
        respond(fd, 400, "Bad Request", "text/plain; charset=utf-8", "",
                "bad request\n");
        return;
    }
    if (strcmp(method, "GET") != 0) {
        respond(fd, 405, "Method Not Allowed", "text/plain; charset=utf-8",
                "Allow: GET\r\n", "method not allowed\n");
        return;
    }
    char *q = strchr(target, '?');
    if (q) *q = '\0';
    if (strcmp(target, "/") == 0) {
        respond(fd, 200, "OK", "text/plain; charset=utf-8", "",
                "cbm-tool telemetry\nScrape /metrics for Prometheus text exposition.\n");
        return;
    }
    if (strcmp(target, "/metrics") != 0) {
        respond(fd, 404, "Not Found", "text/plain; charset=utf-8", "",
                "not found\n");
        return;
    }
    if (telemetry_refresh(st) != 0) {
        respond(fd, 500, "Internal Server Error", "text/plain; charset=utf-8",
                "", "telemetry state unavailable\n");
        return;
    }
    char *body = NULL;
    size_t len = 0u;
    FILE *mem = open_memstream(&body, &len);
    if (!mem) {
        respond(fd, 500, "Internal Server Error", "text/plain; charset=utf-8",
                "", "telemetry state unavailable\n");
        return;
    }
    telemetry_render(mem, st);
    if (fclose(mem) != 0 || !body) {
        free(body);
        respond(fd, 500, "Internal Server Error", "text/plain; charset=utf-8",
                "", "telemetry state unavailable\n");
        return;
    }
    char head[512];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                     "Content-Length: %zu\r\nConnection: close\r\n\r\n", len);
    if (n > 0 && (size_t)n < sizeof(head)) {
        send_all(fd, head, (size_t)n);
        send_all(fd, body, len);
    }
    free(body);
}

int telemetry_serve(const char *addr, telemetry_state_t *st,
                    volatile sig_atomic_t *stop, char *err, size_t errlen) {
    char dummy[8];
    errbuf(&err, &errlen, dummy, sizeof(dummy));
    int lfd = -1;
    if (telemetry_listen(addr, &lfd, err, errlen) != 0) return -1;
    while (stop == NULL || *stop == 0) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lfd, &rfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        int n = select(lfd + 1, &rfds, NULL, NULL, &tv);
        if (n < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errlen, "telemetry serve: select failed: %s", strerror(errno));
            close(lfd);
            return -1;
        }
        if (n == 0) continue;
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            continue;
        }
        telemetry_handle_conn(cfd, st);
        close(cfd);
    }
    close(lfd);
    return 0;
}

static void telemetry_usage(FILE *err) {
    fprintf(err,
            "Usage:\n"
            "  cbm-tool telemetry --listen ADDR [--device PATH] [--state-file PATH]\n"
            "  cbm-tool telemetry --print [--device PATH] [--state-file PATH] [--json]\n"
            "\n"
            "ADDR is :PORT (loopback only) or a numeric HOST:PORT.\n"
            "The device is observed read-only; counters come from a key=value file.\n");
}

static volatile sig_atomic_t g_telemetry_stop = 0;
static void telemetry_signal(int sig) {
    (void)sig;
    g_telemetry_stop = 1;
}

int telemetry_cli_ex(int argc, char **argv, FILE *out, FILE *err, FILE *json) {
    if (!out) out = stdout;
    if (!err) err = stderr;
    if (argc < 2) {
        telemetry_usage(err);
        return 2;
    }
    const char *listen = NULL, *device = NULL, *state_file = NULL;
    int print_mode = 0;
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--listen") == 0 || strcmp(a, "--device") == 0 ||
            strcmp(a, "--state-file") == 0) {
            if (i + 1 >= argc) {
                fprintf(err, "Error: %s needs a value\n", a);
                return 2;
            }
            const char *v = argv[++i];
            if (strcmp(a, "--listen") == 0) listen = v;
            else if (strcmp(a, "--device") == 0) device = v;
            else state_file = v;
        } else if (strcmp(a, "--print") == 0) {
            print_mode = 1;
        } else {
            fprintf(err, "Error: unknown telemetry option '%s'\n", a);
            telemetry_usage(err);
            return 2;
        }
    }
    telemetry_state_t st;
    telemetry_state_init(&st);
    st.crypto_backend_native = (cbm_backend_get() == CBM_BACKEND_NATIVE) ? 1 : 0;
    char msg[192];
    if (device) {
        snprintf(st.device_path, sizeof(st.device_path), "%s", device);
        if (telemetry_probe_device(device, &st, msg, sizeof(msg)) != 0) {
            fprintf(err, "Error: %s\n", msg);
            return 1;
        }
    }
    if (state_file) {
        snprintf(st.state_file, sizeof(st.state_file), "%s", state_file);
        if (telemetry_load_state(state_file, &st, msg, sizeof(msg)) != 0) {
            fprintf(err, "Error: %s\n", msg);
            return 1;
        }
    }
    if (print_mode) {
        if (json) {
            cbm_json_t j;
            memset(&j, 0, sizeof(j));
            cbm_json_object_begin(&j, json, "telemetry", "ok");
            cbm_json_field_string(&j, "device", st.device_label);
            cbm_json_field_bool(&j, "device_present", st.device_present);
            cbm_json_field_u64(&j, "device_capacity_bytes", st.device_capacity_bytes);
            cbm_json_field_fixed6(&j, "scan_progress_ratio", st.scan_progress_ratio);
            cbm_json_field_u64(&j, "containers_found", st.containers_found);
            cbm_json_field_u64(&j, "cdb_commands_total", st.cdb_commands_total);
            cbm_json_field_u64(&j, "entropy_blocks_total", st.entropy_blocks_total);
            cbm_json_field_u64(&j, "last_validation_timestamp_seconds",
                               st.last_validation_timestamp_seconds);
            cbm_json_field_bool(&j, "crypto_backend_native", st.crypto_backend_native);
            cbm_json_end(&j);
        } else {
            telemetry_render(out, &st);
        }
        return 0;
    }
    if (!listen) {
        fprintf(err, "Error: --listen ADDR or --print is required\n");
        telemetry_usage(err);
        return 2;
    }
    if (json) {
        fprintf(err, "Error: --json requires --print (a server cannot emit one document)\n");
        return 2;
    }
    signal(SIGINT, telemetry_signal);
    signal(SIGTERM, telemetry_signal);
    g_telemetry_stop = 0;
    if (telemetry_serve(listen, &st, &g_telemetry_stop, msg, sizeof(msg)) != 0) {
        fprintf(err, "Error: %s\n", msg);
        return 1;
    }
    return 0;
}
