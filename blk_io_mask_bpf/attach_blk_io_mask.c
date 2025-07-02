// SPDX-License-Identifier: GPL-2.0
// attach_blk_io_mask.c - Userspace loader cho blk_io_mask_bpf
// 
// Chức năng:
// 1. Tải và gắn chương trình eBPF blk_io_mask_bpf.o vào tracepoint block/block_rq_issue.
// 2. Pin maps vào bpffs nếu cần, xuất thống kê cơ bản.
// 3. Tuỳ chọn chạy ở chế độ daemon (-d) và ghi log sự kiện ring buffer.
// 4. Cho phép cấu hình mask_ratio và enabled từ dòng lệnh.
//
// Thư viện: libbpf (>= 1.2)

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <seccomp.h>
#include <bpf/libbpf.h>
#include "blk_io_mask_bpf.skel.h"

#define DEFAULT_RINGBUF_POLL_MS 500

static volatile sig_atomic_t exiting = 0;

static void handle_sigint(int sig)
{
    exiting = 1;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        exit(EXIT_FAILURE);
    }
}

/* Thiết lập seccomp filter để hạn chế system calls */
static int setup_seccomp(void)
{
    scmp_filter_ctx ctx;
    
    /* Khởi tạo seccomp context với strict mode (mặc định KILL) */
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        fprintf(stderr, "Không thể khởi tạo seccomp context\n");
        return -1;
    }
    
    /* Định nghĩa danh sách syscalls cho phép với phân nhóm chức năng */
    
    /* 1. Core và I/O cơ bản */
    int basic_syscalls[] = {
        SCMP_SYS(read),
        SCMP_SYS(write),
        SCMP_SYS(close),
        SCMP_SYS(fstat),
        SCMP_SYS(lseek),
        SCMP_SYS(ioctl),         /* Cần cho BPF operations */
        SCMP_SYS(mmap),
        SCMP_SYS(mprotect),
        SCMP_SYS(munmap),
        SCMP_SYS(exit),
        SCMP_SYS(exit_group),
        SCMP_SYS(brk),
        SCMP_SYS(futex),         /* Cần cho pthread */
    };
    
    /* 2. File system access - có thể hạn chế hơn nữa */
    int fs_syscalls[] = {
        SCMP_SYS(open),
        SCMP_SYS(openat),
        SCMP_SYS(stat),
        SCMP_SYS(lstat),
        SCMP_SYS(newfstatat),
        SCMP_SYS(getdents64),    /* Đọc thư mục */
    };
    
    /* 3. Network - cần hạn chế */
    int net_syscalls[] = {
        SCMP_SYS(socket),        /* Chỉ cho AF_NETLINK và AF_LOCAL */
        SCMP_SYS(bind),
        SCMP_SYS(connect),
        SCMP_SYS(sendto),
        SCMP_SYS(recvfrom),
        SCMP_SYS(sendmsg),
        SCMP_SYS(recvmsg),
        SCMP_SYS(shutdown),
        SCMP_SYS(getsockopt),
        SCMP_SYS(setsockopt),
        SCMP_SYS(getsockname),
    };
    
    /* 4. System/Process info */
    int proc_syscalls[] = {
        SCMP_SYS(getuid),
        SCMP_SYS(geteuid),
        SCMP_SYS(getgid),
        SCMP_SYS(getegid),
        SCMP_SYS(getpid),
        SCMP_SYS(gettid),
        SCMP_SYS(arch_prctl),
        SCMP_SYS(sched_getaffinity),
    };
    
    /* 5. Time và Polling */
    int time_syscalls[] = {
        SCMP_SYS(clock_gettime),
        SCMP_SYS(time),
        SCMP_SYS(nanosleep),
        SCMP_SYS(clock_nanosleep),
        SCMP_SYS(poll),
        SCMP_SYS(ppoll),
    };
    
    /* 6. Signal handling */
    int signal_syscalls[] = {
        SCMP_SYS(rt_sigaction),
        SCMP_SYS(rt_sigprocmask),
        SCMP_SYS(rt_sigreturn),
    };
    
    /* 7. BPF và perf */
    int bpf_syscalls[] = {
        SCMP_SYS(bpf),           /* Cho các hoạt động BPF */
        SCMP_SYS(perf_event_open), /* Cho perf ring buffer */
    };
    
    /* Thêm các syscall cơ bản */
    size_t i;
    for (i = 0; i < sizeof(basic_syscalls) / sizeof(basic_syscalls[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, basic_syscalls[i], 0) < 0) {
            fprintf(stderr, "Không thể thêm syscall %d vào whitelist\n", basic_syscalls[i]);
            seccomp_release(ctx);
            return -1;
        }
    }
    
    /* Thêm các syscall filesystem */
    for (i = 0; i < sizeof(fs_syscalls) / sizeof(fs_syscalls[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, fs_syscalls[i], 0) < 0) {
            fprintf(stderr, "Không thể thêm syscall %d vào whitelist\n", fs_syscalls[i]);
            seccomp_release(ctx);
            return -1;
        }
    }
    
    /* Thêm các syscall network với ràng buộc */
    /* Socket chỉ cho phép AF_NETLINK và AF_LOCAL */
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 2,
                         SCMP_A0(SCMP_CMP_EQ, AF_NETLINK),
                         SCMP_A1(SCMP_CMP_EQ, SOCK_RAW)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 2,
                         SCMP_A0(SCMP_CMP_EQ, AF_UNIX),
                         SCMP_A1(SCMP_CMP_EQ, SOCK_STREAM)) < 0) {
        fprintf(stderr, "Không thể thêm socket syscall với ràng buộc\n");
        seccomp_release(ctx);
        return -1;
    }
    
    /* Thêm các syscall network còn lại */
    for (i = 1; i < sizeof(net_syscalls) / sizeof(net_syscalls[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, net_syscalls[i], 0) < 0) {
            fprintf(stderr, "Không thể thêm syscall %d vào whitelist\n", net_syscalls[i]);
            seccomp_release(ctx);
            return -1;
        }
    }
    
    /* Thêm các syscall thông tin hệ thống */
    for (i = 0; i < sizeof(proc_syscalls) / sizeof(proc_syscalls[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, proc_syscalls[i], 0) < 0) {
            fprintf(stderr, "Không thể thêm syscall %d vào whitelist\n", proc_syscalls[i]);
            seccomp_release(ctx);
            return -1;
        }
    }
    
    /* Thêm các syscall thời gian và polling */
    for (i = 0; i < sizeof(time_syscalls) / sizeof(time_syscalls[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, time_syscalls[i], 0) < 0) {
            fprintf(stderr, "Không thể thêm syscall %d vào whitelist\n", time_syscalls[i]);
            seccomp_release(ctx);
            return -1;
        }
    }
    
    /* Thêm các syscall xử lý tín hiệu */
    for (i = 0; i < sizeof(signal_syscalls) / sizeof(signal_syscalls[0]); i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, signal_syscalls[i], 0) < 0) {
            fprintf(stderr, "Không thể thêm syscall %d vào whitelist\n", signal_syscalls[i]);
            seccomp_release(ctx);
            return -1;
        }
    }
    
    /* Thêm các syscall BPF với hạn chế */
    /* BPF chỉ cho phép một số cmd liên quan đến maps */
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bpf), 1,
                         SCMP_A0(SCMP_CMP_EQ, BPF_MAP_LOOKUP_ELEM)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bpf), 1,
                         SCMP_A0(SCMP_CMP_EQ, BPF_MAP_UPDATE_ELEM)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bpf), 1,
                         SCMP_A0(SCMP_CMP_EQ, BPF_MAP_DELETE_ELEM)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bpf), 1,
                         SCMP_A0(SCMP_CMP_EQ, BPF_MAP_GET_NEXT_KEY)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bpf), 1,
                         SCMP_A0(SCMP_CMP_EQ, BPF_OBJ_GET)) < 0) {
        fprintf(stderr, "Không thể thêm bpf syscall với ràng buộc\n");
        seccomp_release(ctx);
        return -1;
    }
    
    /* Thêm syscall perf_event_open với ràng buộc */
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(perf_event_open), 0) < 0) {
        fprintf(stderr, "Không thể thêm perf_event_open syscall\n");
        seccomp_release(ctx);
        return -1;
    }
    
    /* Tải seccomp filter */
    if (seccomp_load(ctx) < 0) {
        fprintf(stderr, "Không thể tải seccomp filter\n");
        seccomp_release(ctx);
        return -1;
    }
    
    /* Giải phóng seccomp context */
    seccomp_release(ctx);
    
    fprintf(stderr, "[+] Seccomp filter đã được áp dụng thành công\n");
    return 0;
}

static void print_help(const char *prog)
{
    printf("Usage: %s [--mask <0-100>] [--disable] [-d]\n", prog);
    printf("\nOptions:\n");
    printf("  --mask <percent>\tThiết lập mask_ratio (%% che giấu)\n");
    printf("  --disable\t\tTắt cloaking (enabled = 0)\n");
    printf("  -d, --daemon\t\tChạy background ghi log minimal\n");
    printf("  -h, --help\t\tHiển thị trợ giúp\n");
}

int main(int argc, char **argv)
{
    struct blk_io_mask_bpf *skel;
    int err;
    bool daemon = false;
    int mask_ratio_cli = -1;
    bool disable_cli = false;

    static struct option long_options[] = {
        {"mask", required_argument, 0, 'm'},
        {"disable", no_argument, 0, 'x'},
        {"daemon", no_argument, 0, 'd'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:dxh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'm':
            mask_ratio_cli = atoi(optarg);
            if (mask_ratio_cli < 0 || mask_ratio_cli > 100) {
                fprintf(stderr, "mask_ratio phải 0-100\n");
                return EXIT_FAILURE;
            }
            break;
        case 'x':
            disable_cli = true;
            break;
        case 'd':
            daemon = true;
            break;
        case 'h':
        default:
            print_help(argv[0]);
            return EXIT_SUCCESS;
        }
    }

    bump_memlock_rlimit();

    /* Open & load skeleton */
    skel = blk_io_mask_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return EXIT_FAILURE;
    }

    /* Override config before loading if CLI provided */
    if (mask_ratio_cli >= 0 || disable_cli) {
        struct blk_mask_cfg *cfg = &skel->bss->cfg_map.values[0];
        if (disable_cli)
            cfg->enabled = 0;
        if (mask_ratio_cli >= 0)
            cfg->mask_ratio = (uint16_t)mask_ratio_cli;
    }

    err = blk_io_mask_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = blk_io_mask_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    printf("[+] blk_io_mask_bpf loaded & attached\n");

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    /* Poll ring buffer */
    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), NULL, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    if (daemon) {
        if (daemon(0, 0) < 0) {
            perror("daemon()");
            goto cleanup;
        }
        
        /* Áp dụng seccomp filter trong chế độ daemon */
        if (setup_seccomp() < 0) {
            fprintf(stderr, "Cảnh báo: Không thể áp dụng seccomp filter\n");
        }
    }

    while (!exiting) {
        err = ring_buffer__poll(rb, DEFAULT_RINGBUF_POLL_MS /* ms */);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    blk_io_mask_bpf__destroy(skel);
    return err < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
} 