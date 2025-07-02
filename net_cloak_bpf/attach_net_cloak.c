//SPDX-License-Identifier: GPL-2.0
/* Chương trình userspace để nạp và gắn net_cloak_bpf.o sử dụng skeleton code tự động */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Thêm include file skeleton tự động sinh
#include "net_cloak_bpf.skel.h"

/* Cấu trúc sự kiện từ ringbuffer */
struct event {
    __u64 cgid;
    __u32 bytes;
    __u8  action;    /* 0=OK, 1=OBF, 2=REDIR, 3=DROP */
    __u8  protocol;  /* 6=TCP, 17=UDP */
    __u16 dport;     /* Cổng đích */
    __u32 saddr;     /* Địa chỉ nguồn */
    __u32 daddr;     /* Địa chỉ đích */
    __u64 timestamp; /* Thời gian sự kiện */
};

/* Tên của loại sự kiện */
const char *action_names[] = {
    "ALLOW",
    "OBFUSCATE",
    "REDIRECT",
    "DROP"
};

/* Biến toàn cục cho skeleton và maps */
static struct net_cloak_bpf *skel = NULL;

/* File descriptor cho ringbuf */
static struct ring_buffer *rb = NULL;

/* Flag kiểm soát chương trình */
static volatile int running = 1;

/* Đường dẫn đến thư mục pin map */
#define PIN_BASE_DIR "/sys/fs/bpf"
#define CPU_THROTTLE_DIR "/sys/fs/bpf/cpu_throttle"

/* Hàm hỗ trợ in debug thông qua libbpf */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

/* Chương trình sẽ chạy cho đến khi bị kill */
static void sig_handler(int sig) {
    running = 0;
}

/* Xử lý sự kiện từ ringbuf */
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    
    /* Định dạng địa chỉ IP */
    char src_ip[16], dst_ip[16];
    unsigned char *saddr_bytes = (unsigned char *)&e->saddr;
    unsigned char *daddr_bytes = (unsigned char *)&e->daddr;
    
    snprintf(src_ip, sizeof(src_ip), "%u.%u.%u.%u", 
             saddr_bytes[0], saddr_bytes[1], saddr_bytes[2], saddr_bytes[3]);
    snprintf(dst_ip, sizeof(dst_ip), "%u.%u.%u.%u", 
             daddr_bytes[0], daddr_bytes[1], daddr_bytes[2], daddr_bytes[3]);
    
    /* In ra thông tin sự kiện dạng JSON */
    printf("{\"time\": %llu, \"cgid\": %llu, \"bytes\": %u, \"action\": \"%s\", \"proto\": %u, \"src\": \"%s\", \"dst\": \"%s\", \"dport\": %u}\n",
           e->timestamp, e->cgid, e->bytes, 
           action_names[e->action], e->protocol,
           src_ip, dst_ip, e->dport);
    
    return 0;
}

/* Nâng giới hạn ulimit cho maps */
static void bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Lỗi: setrlimit() thất bại với errno = %d\n", errno);
        exit(1);
    }
}

/* Gắn XDP vào giao diện mạng sử dụng skeleton */
static int attach_xdp_interface(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Lỗi: không tìm thấy giao diện '%s'\n", ifname);
        return -1;
    }
    
    // Sử dụng chương trình từ skeleton
    int err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_ingress), 0, NULL);
    if (err) {
        fprintf(stderr, "Lỗi khi gắn XDP vào giao diện '%s': %s\n", 
                ifname, strerror(-err));
        return -1;
    }
    
    printf("Đã gắn XDP vào giao diện '%s' (ifindex %d)\n", ifname, ifindex);
    return 0;
}

/* Gắn TC vào giao diện mạng sử dụng skeleton */
static int attach_tc_interface(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Lỗi: không tìm thấy giao diện '%s'\n", ifname);
        return -1;
    }
    
    /* Sử dụng libbpf để gắn vào TC */
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, 
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    );
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = bpf_program__fd(skel->progs.tc_ingress),
    );
    
    /* Tạo hook TC */
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "Lỗi khi tạo hook TC: %s\n", strerror(-err));
        return -1;
    }
    
    /* Gắn chương trình vào hook */
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Lỗi khi gắn TC: %s\n", strerror(-err));
        return -1;
    }
    
    printf("Đã gắn TC vào giao diện '%s' (ifindex %d)\n", ifname, ifindex);
    return 0;
}

/* Kiểm tra và tạo map chia sẻ hoặc sử dụng map đã có */
static int setup_shared_maps(void) {
    int err;
    
    /* Tạo thư mục pin nếu chưa tồn tại */
    if (mkdir(CPU_THROTTLE_DIR, 0700) && errno != EEXIST) {
        fprintf(stderr, "Lỗi: không thể tạo thư mục %s: %s\n", 
                CPU_THROTTLE_DIR, strerror(errno));
        return -1;
    }
    
    /* Kiểm tra xem map đã được pin từ cpu_throttle chưa */
    int quota_fd = bpf_obj_get(CPU_THROTTLE_DIR "/quota_cg");
    int obfuscate_fd = bpf_obj_get(CPU_THROTTLE_DIR "/obfuscate_cg");
    int events_fd = bpf_obj_get(CPU_THROTTLE_DIR "/events");
    
    /* Nếu các map đã tồn tại, sử dụng chúng */
    if (quota_fd >= 0 && obfuscate_fd >= 0 && events_fd >= 0) {
        printf("Sử dụng các map chia sẻ từ %s\n", CPU_THROTTLE_DIR);
        
        /* Thay thế map trong skeleton bằng map đã tồn tại */
        err = bpf_map__reuse_fd(skel->maps.quota_cg, quota_fd);
        if (err) {
            fprintf(stderr, "Lỗi: không thể tái sử dụng quota_map: %s\n", strerror(-err));
            return -1;
        }
        
        err = bpf_map__reuse_fd(skel->maps.obfuscate_cg, obfuscate_fd);
        if (err) {
            fprintf(stderr, "Lỗi: không thể tái sử dụng obfuscate_map: %s\n", strerror(-err));
            return -1;
        }
        
        err = bpf_map__reuse_fd(skel->maps.events, events_fd);
        if (err) {
            fprintf(stderr, "Lỗi: không thể tái sử dụng events_map: %s\n", strerror(-err));
            return -1;
        }
        
        printf("Đã tái sử dụng thành công các map chia sẻ\n");
    } else {
        /* Nếu không tìm thấy map, tạo mới và pin chúng */
        printf("Không tìm thấy map chia sẻ, sẽ pin map từ skeleton\n");
        
        /* Đóng các fd đã mở nếu có */
        if (quota_fd >= 0) close(quota_fd);
        if (obfuscate_fd >= 0) close(obfuscate_fd);
        if (events_fd >= 0) close(events_fd);
        
        /* Pin các map từ skeleton */
        err = bpf_map__pin(skel->maps.quota_cg, CPU_THROTTLE_DIR "/quota_cg");
        if (err) {
            fprintf(stderr, "Lỗi: không thể pin quota_map: %s\n", strerror(-err));
            return -1;
        }
        
        err = bpf_map__pin(skel->maps.obfuscate_cg, CPU_THROTTLE_DIR "/obfuscate_cg");
        if (err) {
            fprintf(stderr, "Lỗi: không thể pin obfuscate_map: %s\n", strerror(-err));
            return -1;
        }
        
        err = bpf_map__pin(skel->maps.events, CPU_THROTTLE_DIR "/events");
        if (err) {
            fprintf(stderr, "Lỗi: không thể pin events_map: %s\n", strerror(-err));
            return -1;
        }
        
        printf("Đã pin các map tại %s\n", CPU_THROTTLE_DIR);
    }
    
    return 0;
}

static void usage(const char *prog) {
    fprintf(stderr, "Sử dụng: %s [options]\n"
            "\n"
            "Options:\n"
            "  -i <ifname>  Gắn XDP và TC vào giao diện mạng (bắt buộc)\n"
            "  -d           Chế độ debug (in thêm log)\n"
            "  -h           Hiển thị trợ giúp này\n"
            "", prog);
}

int main(int argc, char **argv) {
    int opt;
    char ifname[IF_NAMESIZE] = "";
    bool debug = false;
    int err;
    
    /* Parse command line arguments */
    while ((opt = getopt(argc, argv, "i:dh")) != -1) {
        switch (opt) {
        case 'i':
            strncpy(ifname, optarg, IF_NAMESIZE - 1);
            ifname[IF_NAMESIZE - 1] = '\0';
            break;
        case 'd':
            debug = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }
    
    /* Kiểm tra tham số bắt buộc */
    if (ifname[0] == '\0') {
        fprintf(stderr, "Lỗi: Cần chỉ định giao diện mạng với -i\n");
        usage(argv[0]);
        return 1;
    }
    
    /* Thiết lập xử lý tín hiệu */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Nâng giới hạn rlimit */
    bump_memlock_rlimit();
    
    /* Thiết lập libbpf */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    if (debug)
        libbpf_set_print(libbpf_print_fn);
    
    /* Mở và nạp skeleton */
    skel = net_cloak_bpf__open();
    if (!skel) {
        fprintf(stderr, "Lỗi: không thể mở skeleton\n");
        return 1;
    }
    
    /* Thiết lập các map chia sẻ */
    err = setup_shared_maps();
    if (err) {
        fprintf(stderr, "Lỗi: không thể thiết lập map chia sẻ\n");
        goto cleanup;
    }
    
    /* Nạp và xác minh chương trình */
    err = net_cloak_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Lỗi: không thể nạp chương trình eBPF: %s\n", strerror(-err));
        goto cleanup;
    }
    
    /* Gắn chương trình XDP */
    err = attach_xdp_interface(ifname);
    if (err) {
        fprintf(stderr, "Lỗi: không thể gắn chương trình XDP\n");
        goto cleanup;
    }
    
    /* Gắn chương trình TC */
    err = attach_tc_interface(ifname);
    if (err) {
        fprintf(stderr, "Lỗi: không thể gắn chương trình TC\n");
        goto cleanup;
    }
    
    /* Gắn các chương trình cgroup */
    err = bpf_program__attach_cgroup_inet_ingress(skel->progs.handle_prerouting, 0);
    if (err) {
        fprintf(stderr, "Lỗi: không thể gắn chương trình cgroup ingress: %s\n", strerror(-err));
    } else {
        printf("Đã gắn cgroup ingress filter\n");
    }
    
    err = bpf_program__attach_cgroup_inet_egress(skel->progs.handle_local_out, 0);
    if (err) {
        fprintf(stderr, "Lỗi: không thể gắn chương trình cgroup egress: %s\n", strerror(-err));
    } else {
        printf("Đã gắn cgroup egress filter\n");
    }
    
    /* Thiết lập ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Lỗi: không thể tạo ring buffer\n");
        goto cleanup;
    }
    
    printf("Net Cloak đã khởi động thành công\n");
    
    /* Vòng lặp chính - xử lý sự kiện */
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Lỗi: ring buffer poll: %s\n", strerror(-err));
            break;
        }
    }
    
cleanup:
    /* Dọn dẹp tài nguyên */
    if (rb)
        ring_buffer__free(rb);
    net_cloak_bpf__destroy(skel);
    
    return err < 0 ? 1 : 0;
} 