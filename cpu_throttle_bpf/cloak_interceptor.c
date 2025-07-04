//  * cloak_interceptor.c – Userspace LD_PRELOAD library
//  * Mục đích: thay thế giá trị CPU telemetry bằng giá trị "giả" được lưu trong BPF maps.
//  *
//  *  Chiến lược:
//  *  1. Hook pread64/read khi đọc từ /dev/cpu/*/msr để trả về fake MSR (fake_msr_map).
//  *  2. Hook syscall() để intercept SCHED_SETATTR (SYS_sched_setattr) và chèn util_clamp_max giả (fake_sched_attr_map).
//  *  3. Hook fopen/open để chuyển truy cập file nhạy cảm tới lớp FUSE overlay.
//  *
//  *  Biến môi trường hỗ trợ:
//  *    CLOAK_DEBUG=1   -> bật log.
//  *
//  *  Biên dịch:
//  *    gcc -Wall -O2 -shared -fPIC -ldl -lpthread -lbpf -o libcloak.so cloak_interceptor.c
//  *    export LD_PRELOAD=/path/to/libcloak.so
//  *

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/sched.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* ----------------------------- Config ----------------------------- */
#define PIN_BASE "/sys/fs/bpf/cpu_throttle"
#define PATH_FAKE_MSR  PIN_BASE "/fake_msr_map"
#define PATH_FAKE_UCLAMP PIN_BASE "/fake_sched_attr_map"
#define DEBUG_ENABLED (getenv("CLOAK_DEBUG") != NULL)

/* ------------------------- Helpers ------------------------------- */
static void debug_log(const char *fmt, ...) {
    if (!DEBUG_ENABLED) return;
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[cloak] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static int open_bpf_map_cached(const char *path) {
    static struct {
        const char *path;
        int fd;
    } cache[4] = {{0}};
    for (int i = 0; i < 4; ++i) {
        if (cache[i].path && strcmp(cache[i].path, path) == 0) {
            return cache[i].fd;
        }
    }
    for (int i = 0; i < 4; ++i) {
        if (!cache[i].path) {
            int fd = bpf_obj_get(path);
            if (fd < 0) {
                debug_log("cannot open map %s: %s", path, strerror(errno));
            }
            cache[i].path = path;
            cache[i].fd = fd;
            return fd;
        }
    }
    return -1;
}

/* -------------------- Original function pointers ----------------- */
static ssize_t (*real_pread64)(int, void *, size_t, off_t) = NULL;
static ssize_t (*real_read)(int, void *, size_t) = NULL;
static long (*real_syscall)(long number, ...) = NULL;
static int (*real_open)(const char *pathname, int flags, ...) = NULL;
static FILE *(*real_fopen)(const char *pathname, const char *mode) = NULL;

/* --------------------- Constructor / Destructor ------------------ */
__attribute__((constructor)) static void cloak_init(void) {
    real_pread64 = dlsym(RTLD_NEXT, "pread64");
    real_read = dlsym(RTLD_NEXT, "read");
    real_syscall = dlsym(RTLD_NEXT, "syscall");
    real_open = dlsym(RTLD_NEXT, "open");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    debug_log("interceptor loaded");
}

/* ----------------------- Helper – is MSR FD ---------------------- */
static int fd_is_msr(int fd, char *out_path, size_t sz) {
    char link[64];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(link, out_path, sz - 1);
    if (len <= 0) return 0;
    out_path[len] = '\0';
    return strstr(out_path, "/dev/cpu/") && strstr(out_path, "/msr");
}

/* ---------------------- pread64 override ------------------------- */
ssize_t pread64(int fd, void *buf, size_t count, off_t offset) {
    if (!real_pread64) {
        errno = EBADF;
        return -1;
    }
    /* Cloak dynamic telemetry (temperature / current freq) via MSR read */
    if (count == 8) {
        char path[PATH_MAX];
        if (fd_is_msr(fd, path, sizeof(path))) {
            uint64_t fake_val;
            int map_fd = open_bpf_map_cached(PATH_FAKE_MSR);
            if (map_fd >= 0 && bpf_map_lookup_elem(map_fd, &offset, &fake_val) == 0) {
                memcpy(buf, &fake_val, sizeof(fake_val));
                debug_log("Cloak MSR 0x%x -> 0x%llx", (unsigned)offset, (unsigned long long)fake_val);
                return 8; /* done */
            }
        }
    }
    /* Otherwise pass-through */
    return real_pread64(fd, buf, count, offset);
}

/* ---------------------- read override (for msr via read) --------- */
ssize_t read(int fd, void *buf, size_t count) {
    if (!real_read) {
        errno = EBADF;
        return -1;
    }
    /* Fallback to original */
    return real_read(fd, buf, count);
}

/* ---------------------- syscall override ------------------------- */
long syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    if (number == SYS_sched_setattr) {
        pid_t pid = va_arg(ap, pid_t);
        struct sched_attr *attr = va_arg(ap, struct sched_attr *);
        unsigned int flags = va_arg(ap, unsigned int);
        va_end(ap);

        int map_fd = open_bpf_map_cached(PATH_FAKE_UCLAMP);
        if (map_fd >= 0) {
            uint32_t fake_util;
            if (bpf_map_lookup_elem(map_fd, &pid, &fake_util) == 0) {
                struct sched_attr modified = *attr;
                modified.sched_util_max = fake_util;
                debug_log("PID %d util_clamp_max -> fake %u", pid, fake_util);
                return real_syscall(SYS_sched_setattr, pid, &modified, flags);
            }
        }
        /* no fake */
        return real_syscall(SYS_sched_setattr, pid, attr, flags);
    }

    /* Pass-through for other syscalls */
    va_end(ap);
    va_start(ap, number);
    long ret = real_syscall(number, va_arg(ap, long), va_arg(ap, long), va_arg(ap, long),
                             va_arg(ap, long), va_arg(ap, long), va_arg(ap, long));
    va_end(ap);
    return ret;
}

/* ---------------------- open / fopen override -------------------- */
int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
    }
    /* Redirect certain files to FUSE overlay if path matches and overlay active */
    if (strstr(pathname, "/proc/") || strstr(pathname, "/sys/")) {
        /* rely on mount namespace remap; just log */
        debug_log("open path=%s", pathname);
    }
    return (flags & O_CREAT) ? real_open(pathname, flags, mode) : real_open(pathname, flags);
}

FILE *fopen(const char *pathname, const char *mode) {
    /* rely on overlay; just log */
    if (strstr(pathname, "/proc/") || strstr(pathname, "/sys/")) {
        debug_log("fopen path=%s", pathname);
    }
    return real_fopen(pathname, mode);
} 