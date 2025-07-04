/*
 * fuse_overlay.c – FUSE daemon tạo lớp phủ ảo cho /proc & /sys
 *
 *  - Pass-through hầu hết file tới lowerdir (mặc định /)
 *  - Fake nội dung cho một số file telemetry CPU:
 *      • /proc/cpuinfo
 *      • /sys/class/thermal/.../temp
 *      • /sys/class/hwmon/.../temp*_input
 *      • /sys/devices/system/cpu/.../cpufreq/*_freq
 *
 *  Giá trị giả lấy từ map BPF cloaking_cfg được pin tại
 *      /sys/fs/bpf/cpu_throttle/cloaking_cfg
 *
 *  Build:
 *      gcc -Wall -O2 -pthread fuse_overlay.c -o fuse_overlay `pkg-config fuse3 --cflags --libs` -lbpf
 *
 *  Usage:
 *      sudo ./fuse_overlay --mount <mountpoint> --lower / --debug
 */
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <bpf/bpf.h>

#define PIN_BASE "/sys/fs/bpf/cpu_throttle"
#define PATH_CFG  PIN_BASE "/cloaking_cfg"

struct cloaking_cfg {
    uint32_t enabled;
    uint32_t target_temp;  /* milli-Celsius */
    uint32_t target_util;
    uint32_t target_freq;  /* kHz */
    uint32_t strategy;
    uint32_t detection_defense;
    uint32_t sampling_rate;
};

static const char *lowerdir = "/";
static int cfg_fd = -1;
static int debug_enabled = 0;

static void log_debug(const char *fmt, ...) {
    if (!debug_enabled) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

/* Read cloaking config map (key 0) */
static int load_config(struct cloaking_cfg *cfg) {
    uint32_t key = 0;
    if (cfg_fd < 0) {
        cfg_fd = bpf_obj_get(PATH_CFG);
        if (cfg_fd < 0) return -1;
    }
    if (bpf_map_lookup_elem(cfg_fd, &key, cfg) < 0) return -1;
    return 0;
}

/* Helpers to test path */
static int ends_with(const char *s, const char *suffix) {
    size_t ls = strlen(s), lsuf = strlen(suffix);
    return ls >= lsuf && strcmp(s + ls - lsuf, suffix) == 0;
}

static int path_match_fake(const char *relpath) {
    if (strcmp(relpath, "proc/cpuinfo") == 0) return 1;
    if (strstr(relpath, "sys/class/thermal/") && ends_with(relpath, "/temp")) return 2;
    if (strstr(relpath, "sys/class/hwmon/") && strstr(relpath, "temp") && ends_with(relpath, "_input")) return 2;
    if (strstr(relpath, "sys/devices/system/cpu/") && strstr(relpath, "cpufreq") && ends_with(relpath, "_freq")) return 3;
    return 0;
}

/* Build real path in lowerdir */
static void fullpath(char fbuf[PATH_MAX], const char *rel) {
    snprintf(fbuf, PATH_MAX, "%s/%s", lowerdir, rel);
}

/* ================= FUSE callbacks ================ */
static int ov_getattr(const char *path, struct stat *st, struct fuse_file_info *fi) {
    (void)fi;
    char real[PATH_MAX];
    if (strcmp(path, "/") == 0) {
        fullpath(real, "");
        return lstat(real, st);
    }
    fullpath(real, path + 1); /* skip leading / */
    int fake_type = path_match_fake(real);
    if (fake_type) {
        memset(st, 0, sizeof(*st));
        st->st_mode = S_IFREG | 0444;
        st->st_nlink = 1;
        st->st_size = 4096; /* arbitrary */
        return 0;
    }
    return lstat(real, st);
}

static int ov_open(const char *path, struct fuse_file_info *fi) {
    char real[PATH_MAX];
    fullpath(real, path + 1);
    int fake_type = path_match_fake(real);
    if (fake_type) return 0; /* allow */
    int fd = open(real, fi->flags);
    if (fd == -1) return -errno;
    fi->fh = fd;
    return 0;
}

static int ov_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char real[PATH_MAX];
    fullpath(real, path + 1);
    int fake_type = path_match_fake(real);
    if (fake_type) {
        /* Generate fake content */
        struct cloaking_cfg cfg = {0};
        load_config(&cfg);
        char content[4096];
        int len = 0;
        if (fake_type == 1) { /* cpuinfo */
            len = snprintf(content, sizeof(content),
                           "processor\t: 0\nmodel name\t: FakeCPU 3.14GHz\ncpu MHz\t\t: %.0f\n", cfg.target_freq ? cfg.target_freq / 1000.0 : 3140.0);
        } else if (fake_type == 2) { /* temp */
            len = snprintf(content, sizeof(content), "%u\n", cfg.target_temp ? cfg.target_temp : 50000);
        } else if (fake_type == 3) { /* freq */
            len = snprintf(content, sizeof(content), "%u\n", cfg.target_freq ? cfg.target_freq : 2200000);
        }
        if ((size_t)offset >= (size_t)len) return 0;
        if (offset + size > (size_t)len) size = len - offset;
        memcpy(buf, content + offset, size);
        return size;
    }

    /* Pass-through */
    int fd = fi->fh;
    if (!fd) {
        fd = open(real, O_RDONLY);
        if (fd == -1) return -errno;
    }
    ssize_t res = pread(fd, buf, size, offset);
    if (res == -1) res = -errno;
    return res;
}

static int ov_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    if (fi->fh) close(fi->fh);
    return 0;
}

static const struct fuse_operations ov_ops = {
    .getattr = ov_getattr,
    .open    = ov_open,
    .read    = ov_read,
    .release = ov_release,
};

/* -------------- main --------------- */
static struct options {
    const char *mountpoint;
    const char *lower;
    int debug;
} opts = { .lower = "/" };

static void usage(const char *prog) {
    fprintf(stderr, "Usage: %s --mount <mnt> [--lower /proc] [--debug]\n", prog);
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--mount") == 0 && i + 1 < argc) {
            opts.mountpoint = argv[++i];
        } else if (strcmp(argv[i], "--lower") == 0 && i + 1 < argc) {
            opts.lower = argv[++i];
        } else if (strcmp(argv[i], "--debug") == 0) {
            opts.debug = 1;
        }
    }
    if (!opts.mountpoint) {
        usage(argv[0]);
        return 1;
    }
    debug_enabled = opts.debug;
    lowerdir = opts.lower;
    log_debug("Lowerdir=%s mountpoint=%s", lowerdir, opts.mountpoint);
    return fuse_main(args.argc, args.argv, &ov_ops, NULL);
} 