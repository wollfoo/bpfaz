/*
 * enhanced_cloaking_interceptor.c - Advanced Userspace Interceptor
 * 
 * Thay thế bpf_probe_write_user bằng cách:
 * 1. LD_PRELOAD interception cho syscalls
 * 2. FUSE filesystem overlay cho /proc và /sys
 * 3. Ptrace-based runtime manipulation
 * 4. Library symbol replacement
 * 5. BPF maps-based fake data serving
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <sched.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* BPF Maps paths */
#define PIN_BASE "/sys/fs/bpf/cpu_throttle"
#define FAKE_MSR_MAP PIN_BASE "/fake_msr_map"
#define FAKE_SCHED_ATTR_MAP PIN_BASE "/fake_sched_attr_map"
#define FAKE_RDT_MAP PIN_BASE "/fake_rdt_map"
#define FAKE_RAPL_MAP PIN_BASE "/fake_rapl_map"
#define INTERCEPTION_TRACKER PIN_BASE "/interception_tracker"

/* Global state */
static int fake_msr_fd = -1;
static int fake_sched_fd = -1;
static int fake_rdt_fd = -1;
static int fake_rapl_fd = -1;
static int tracker_fd = -1;

/* Original function pointers */
static long (*real_syscall)(long number, ...) = NULL;
static int (*real_sched_setattr)(pid_t pid, const struct sched_attr *attr, unsigned int flags) = NULL;
static FILE* (*real_fopen)(const char *pathname, const char *mode) = NULL;
static int (*real_open)(const char *pathname, int flags, ...) = NULL;

/* =====================================================
 *  INITIALIZATION AND CLEANUP
 * ===================================================== */

__attribute__((constructor))
static void init_interceptor(void) {
    /* Load original functions */
    real_syscall = dlsym(RTLD_NEXT, "syscall");
    real_sched_setattr = dlsym(RTLD_NEXT, "sched_setattr");
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    real_open = dlsym(RTLD_NEXT, "open");
    
    /* Open BPF maps */
    fake_msr_fd = bpf_obj_get(FAKE_MSR_MAP);
    fake_sched_fd = bpf_obj_get(FAKE_SCHED_ATTR_MAP);
    fake_rdt_fd = bpf_obj_get(FAKE_RDT_MAP);
    fake_rapl_fd = bpf_obj_get(FAKE_RAPL_MAP);
    tracker_fd = bpf_obj_get(INTERCEPTION_TRACKER);
    
    if (getenv("CLOAKING_DEBUG")) {
        printf("[CLOAKING] Enhanced interceptor initialized\n");
        printf("[CLOAKING] MSR map: %s, SCHED map: %s\n", 
               fake_msr_fd >= 0 ? "OK" : "FAIL",
               fake_sched_fd >= 0 ? "OK" : "FAIL");
    }
}

__attribute__((destructor))
static void cleanup_interceptor(void) {
    if (fake_msr_fd >= 0) close(fake_msr_fd);
    if (fake_sched_fd >= 0) close(fake_sched_fd);
    if (fake_rdt_fd >= 0) close(fake_rdt_fd);
    if (fake_rapl_fd >= 0) close(fake_rapl_fd);
    if (tracker_fd >= 0) close(tracker_fd);
}

/* =====================================================
 *  APPROACH 1: MSR SYSCALL INTERCEPTION
 * ===================================================== */

long syscall(long number, ...) {
    va_list args;
    va_start(args, number);
    
    /* Intercept MSR read operations */
    if (number == __NR_pread64 || number == __NR_read) {
        int fd = va_arg(args, int);
        void *buf = va_arg(args, void*);
        size_t count = va_arg(args, size_t);
        
        /* Check if this is MSR device read */
        char fd_path[256];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        
        char target[256];
        ssize_t len = readlink(fd_path, target, sizeof(target) - 1);
        if (len > 0) {
            target[len] = '\0';
            
            /* MSR device files */
            if (strstr(target, "/dev/cpu/") && strstr(target, "/msr")) {
                uint32_t msr_addr = 0;
                if (number == __NR_pread64) {
                    off_t offset = va_arg(args, off_t);
                    msr_addr = (uint32_t)offset;
                } else {
                    /* For read(), MSR address might be in lseek position */
                    msr_addr = lseek(fd, 0, SEEK_CUR);
                }
                
                /* Check if we have fake value for this MSR */
                uint64_t fake_value;
                if (fake_msr_fd >= 0 && 
                    bpf_map_lookup_elem(fake_msr_fd, &msr_addr, &fake_value) == 0) {
                    
                    if (count >= sizeof(fake_value)) {
                        memcpy(buf, &fake_value, sizeof(fake_value));
                        va_end(args);
                        return sizeof(fake_value);
                    }
                }
            }
        }
    }
    
    va_end(args);
    
    /* Fall back to original syscall */
    va_start(args, number);
    long result = real_syscall(number, 
                              va_arg(args, long), va_arg(args, long), 
                              va_arg(args, long), va_arg(args, long),
                              va_arg(args, long), va_arg(args, long));
    va_end(args);
    return result;
}

/* =====================================================
 *  APPROACH 2: SCHEDULER ATTRIBUTE INTERCEPTION
 * ===================================================== */

int sched_setattr(pid_t pid, const struct sched_attr *attr, unsigned int flags) {
    /* Check if we have fake util_clamp for this PID */
    uint32_t fake_util;
    if (fake_sched_fd >= 0 && 
        bpf_map_lookup_elem(fake_sched_fd, &pid, &fake_util) == 0) {
        
        /* Create modified sched_attr with fake values */
        struct sched_attr modified_attr = *attr;
        modified_attr.sched_util_max = fake_util;
        
        if (getenv("CLOAKING_DEBUG")) {
            printf("[CLOAKING] Replaced util_clamp_max for PID %d: %u -> %u\n",
                   pid, attr->sched_util_max, fake_util);
        }
        
        /* Remove from map after use */
        bpf_map_delete_elem(fake_sched_fd, &pid);
        
        return real_sched_setattr(pid, &modified_attr, flags);
    }
    
    return real_sched_setattr(pid, attr, flags);
}

/* =====================================================
 *  APPROACH 3: PROCFS/SYSFS FILE INTERCEPTION
 * ===================================================== */

FILE* fopen(const char *pathname, const char *mode) {
    /* Intercept /proc/cpuinfo reads */
    if (strcmp(pathname, "/proc/cpuinfo") == 0) {
        /* Create temporary file with fake CPU info */
        FILE *temp = tmpfile();
        if (temp) {
            /* Generate fake cpuinfo based on cloaking config */
            fprintf(temp, "processor\t: 0\n");
            fprintf(temp, "vendor_id\t: GenuineIntel\n");
            fprintf(temp, "cpu family\t: 6\n");
            fprintf(temp, "model\t\t: 142\n");
            fprintf(temp, "model name\t: Intel(R) Core(TM) i5-8250U CPU @ 1.60GHz\n");
            fprintf(temp, "stepping\t: 10\n");
            fprintf(temp, "microcode\t: 0xf0\n");
            fprintf(temp, "cpu MHz\t\t: 1800.000\n"); /* Fake frequency */
            fprintf(temp, "cache size\t: 6144 KB\n");
            fprintf(temp, "physical id\t: 0\n");
            fprintf(temp, "siblings\t: 4\n");
            fprintf(temp, "core id\t\t: 0\n");
            fprintf(temp, "cpu cores\t: 2\n");
            
            rewind(temp);
            return temp;
        }
    }
    
    /* Intercept thermal zone readings */
    if (strstr(pathname, "/sys/class/thermal/thermal_zone") && 
        strstr(pathname, "/temp")) {
        FILE *temp = tmpfile();
        if (temp) {
            fprintf(temp, "50000\n"); /* Fake 50°C */
            rewind(temp);
            return temp;
        }
    }
    
    /* Intercept HWMON readings */
    if (strstr(pathname, "/sys/class/hwmon/") && 
        (strstr(pathname, "_input") || strstr(pathname, "_crit"))) {
        FILE *temp = tmpfile();
        if (temp) {
            if (strstr(pathname, "temp")) {
                fprintf(temp, "50000\n"); /* Fake temperature */
            } else if (strstr(pathname, "energy")) {
                fprintf(temp, "1000000\n"); /* Fake energy */
            }
            rewind(temp);
            return temp;
        }
    }
    
    return real_fopen(pathname, mode);
}

/* =====================================================
 *  APPROACH 4: MEMORY-MAPPED FILE INTERCEPTION
 * ===================================================== */

int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    
    /* Intercept MSR device files */
    if (strstr(pathname, "/dev/cpu/") && strstr(pathname, "/msr")) {
        /* Allow opening but we'll intercept read operations */
        if (getenv("CLOAKING_DEBUG")) {
            printf("[CLOAKING] MSR device access detected: %s\n", pathname);
        }
    }
    
    /* Intercept Intel RDT files */
    if (strstr(pathname, "/sys/fs/resctrl/") || 
        strstr(pathname, "/proc/self/mountinfo")) {
        if (getenv("CLOAKING_DEBUG")) {
            printf("[CLOAKING] RDT access detected: %s\n", pathname);
        }
    }
    
    return real_open(pathname, flags, mode);
}

/* =====================================================
 *  APPROACH 5: RUNTIME PROCESS MANIPULATION
 * ===================================================== */

static int inject_fake_data(pid_t target_pid) {
    struct user_regs_struct regs;
    long orig_rax;
    
    /* Attach to target process */
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        return -1;
    }
    
    waitpid(target_pid, NULL, 0);
    
    /* Get register state */
    if (ptrace(PTRACE_GETREGS, target_pid, NULL, &regs) == -1) {
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return -1;
    }
    
    /* Check if this is a relevant syscall */
    orig_rax = regs.orig_rax;
    
    if (orig_rax == __NR_sched_setattr) {
        /* Modify scheduler attribute parameters */
        uint32_t fake_util;
        if (fake_sched_fd >= 0 && 
            bpf_map_lookup_elem(fake_sched_fd, &target_pid, &fake_util) == 0) {
            
            /* Modify memory at sched_attr location */
            unsigned long attr_addr = regs.rsi;
            struct sched_attr attr;
            
            /* Read original attribute */
            for (int i = 0; i < sizeof(attr); i += sizeof(long)) {
                long data = ptrace(PTRACE_PEEKDATA, target_pid, 
                                 attr_addr + i, NULL);
                memcpy((char*)&attr + i, &data, sizeof(long));
            }
            
            /* Modify util_clamp_max */
            attr.sched_util_max = fake_util;
            
            /* Write back modified attribute */
            for (int i = 0; i < sizeof(attr); i += sizeof(long)) {
                long data;
                memcpy(&data, (char*)&attr + i, sizeof(long));
                ptrace(PTRACE_POKEDATA, target_pid, attr_addr + i, data);
            }
        }
    }
    
    /* Continue execution */
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    return 0;
}

/* =====================================================
 *  MONITORING THREAD
 * ===================================================== */

static void* interception_monitor(void* arg) {
    uint64_t key, next_key;
    uint32_t intercept_type;
    
    while (1) {
        if (tracker_fd < 0) {
            sleep(1);
            continue;
        }
        
        /* Scan interception tracker map */
        int ret = bpf_map_get_next_key(tracker_fd, NULL, &key);
        while (ret == 0) {
            if (bpf_map_lookup_elem(tracker_fd, &key, &intercept_type) == 0) {
                uint32_t pid = (uint32_t)(key >> 32);
                uint32_t syscall_id = (uint32_t)(key & 0xFFFFFFFF);
                
                switch (intercept_type) {
                    case 1: /* MSR interception */
                        if (getenv("CLOAKING_DEBUG")) {
                            printf("[CLOAKING] MSR interception request for PID %u\n", pid);
                        }
                        break;
                        
                    case 2: /* Scheduler attribute interception */
                        inject_fake_data(pid);
                        break;
                        
                    case 3: /* RDT interception */
                        /* Handle RDT fake data injection */
                        break;
                }
                
                /* Remove processed request */
                bpf_map_delete_elem(tracker_fd, &key);
            }
            
            ret = bpf_map_get_next_key(tracker_fd, &key, &next_key);
            key = next_key;
        }
        
        usleep(100000); /* 100ms polling interval */
    }
    
    return NULL;
} 