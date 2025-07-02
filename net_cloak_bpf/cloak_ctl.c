//SPDX-License-Identifier: GPL-2.0
/* Công cụ dòng lệnh để điều khiển net_cloak */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Cấu trúc thông tin chuyển hướng cổng */
struct redirect_info {
    __u16 target_port;
    __u8  enabled;
};

/* Lệnh được hỗ trợ */
typedef enum {
    CMD_UNKNOWN,
    CMD_SET_QUOTA,
    CMD_ADD_REDIRECT,
    CMD_DEL_REDIRECT,
    CMD_ENABLE_OBFUSCATE,
    CMD_DISABLE_OBFUSCATE,
    CMD_SHOW_STATS
} cmd_t;

/* Đường dẫn đến thư mục pin map */
#define PIN_BASE_DIR "/sys/fs/bpf"
#define CPU_THROTTLE_DIR "/sys/fs/bpf/cpu_throttle"

/* In thông tin sử dụng */
static void usage(const char *prog) {
    fprintf(stderr,
            "Sử dụng: %s <command> [options]\n"
            "\n"
            "Commands:\n"
            "  quota <cgid> <bytes>       Đặt/cập nhật quota cho cgroup\n"
            "  redirect <src> <dst> [on]  Thêm chuyển hướng cổng (mặc định on=1)\n"
            "  delredirect <src>          Xóa chuyển hướng cổng\n"
            "  obfuscate <cgid> <on>      Bật/tắt obfuscation cho cgroup (1=on, 0=off)\n"
            "  stats                      Hiển thị thống kê\n"
            "\n"
            "Examples:\n"
            "  %s quota 12345 1048576     Đặt quota 1MB cho cgroup 12345\n"
            "  %s redirect 80 8080        Chuyển hướng cổng 80 -> 8080\n"
            "  %s obfuscate 12345 1       Bật obfuscation cho cgroup 12345\n"
            "\n", prog, prog, prog, prog);
}

/* Mở các maps cần thiết */
static int open_map(const char *name) {
    char path[256];
    int fd;
    
    /* Thử mở từ thư mục CPU_THROTTLE_DIR trước */
    if (strcmp(name, "quota_cg") == 0 || strcmp(name, "obfuscate_cg") == 0 || strcmp(name, "events") == 0) {
        snprintf(path, sizeof(path), "%s/%s", CPU_THROTTLE_DIR, name);
        fd = bpf_obj_get(path);
        if (fd >= 0) {
            printf("Sử dụng map chia sẻ từ %s\n", path);
            return fd;
        }
    }
    
    /* Thử mở từ bpf filesystem trước */
    snprintf(path, sizeof(path), "/sys/fs/bpf/net_cloak/%s", name);
    fd = bpf_obj_get(path);
    if (fd >= 0)
        return fd;
    
    /* Thử mở từ pinned filesystem default */
    snprintf(path, sizeof(path), "/sys/fs/bpf/%s", name);
    fd = bpf_obj_get(path);
    if (fd >= 0)
        return fd;
    
    /* Nếu đang chạy loader, mở từ object file */
    struct bpf_object *obj = bpf_object__open("./output/net_cloak.bpf.o");
    if (!libbpf_get_error(obj)) {
        /* Nếu object đã được load, lấy map fd từ đó */
        int map_fd = bpf_object__find_map_fd_by_name(obj, name);
        if (map_fd >= 0)
            return map_fd;
        bpf_object__close(obj);
    }
    
    return -1;
}

/* Hiển thị thống kê */
static int show_stats(void) {
    int stats_fd = open_map("stats");
    if (stats_fd < 0) {
        fprintf(stderr, "Lỗi: không thể mở map 'stats'\n");
        return -1;
    }
    
    __u64 values[4][4] = {0}; /* 4 loại thống kê, tối đa 4 CPU */
    __u32 key;
    
    /* Đọc tất cả thống kê */
    for (key = 0; key < 4; key++) {
        if (bpf_map_lookup_elem(stats_fd, &key, &values[key]) < 0) {
            fprintf(stderr, "Lỗi: không thể đọc thống kê cho key %u\n", key);
            continue;
        }
    }
    
    /* Tính tổng cho mỗi loại thống kê */
    __u64 totals[4] = {0};
    for (int i = 0; i < 4; i++) {
        for (int cpu = 0; cpu < 4; cpu++) { /* Giả sử tối đa 4 CPU */
            totals[i] += values[i][cpu];
        }
    }
    
    /* Hiển thị thống kê */
    printf("Thống kê Net Cloak:\n");
    printf("- Tổng số bytes đã xử lý: %llu\n", totals[0]);
    printf("- Số gói XDP đã xử lý: %llu\n", totals[1]);
    printf("- Số lượng chuyển hướng socket: %llu\n", totals[2]);
    printf("- Số lượng xử lý LSM/tracepoint: %llu\n", totals[3]);
    
    return 0;
}

/* Đặt/cập nhật quota cho cgroup */
static int set_quota(__u64 cgid, __u64 quota) {
    int quota_fd = open_map("quota_cg");
    if (quota_fd < 0) {
        fprintf(stderr, "Lỗi: không thể mở map 'quota_cg'\n");
        return -1;
    }
    
    if (bpf_map_update_elem(quota_fd, &cgid, &quota, BPF_ANY) < 0) {
        fprintf(stderr, "Lỗi: không thể cập nhật quota cho cgid %llu: %s\n", 
                cgid, strerror(errno));
        return -1;
    }
    
    printf("Đã cập nhật quota cho cgid %llu: %llu bytes\n", cgid, quota);
    return 0;
}

/* Thêm/cập nhật rule chuyển hướng cổng */
static int add_redirect(__u16 src_port, __u16 dst_port, __u8 enabled) {
    int redirect_fd = open_map("port_redirect");
    if (redirect_fd < 0) {
        fprintf(stderr, "Lỗi: không thể mở map 'port_redirect'\n");
        return -1;
    }
    
    struct redirect_info redir;
    redir.target_port = dst_port;
    redir.enabled = enabled;
    
    if (bpf_map_update_elem(redirect_fd, &src_port, &redir, BPF_ANY) < 0) {
        fprintf(stderr, "Lỗi: không thể cập nhật chuyển hướng cổng %u -> %u: %s\n", 
                src_port, dst_port, strerror(errno));
        return -1;
    }
    
    printf("Đã %s chuyển hướng cổng %u -> %u\n", 
           enabled ? "bật" : "tắt", src_port, dst_port);
    return 0;
}

/* Xóa rule chuyển hướng cổng */
static int del_redirect(__u16 src_port) {
    int redirect_fd = open_map("port_redirect");
    if (redirect_fd < 0) {
        fprintf(stderr, "Lỗi: không thể mở map 'port_redirect'\n");
        return -1;
    }
    
    if (bpf_map_delete_elem(redirect_fd, &src_port) < 0) {
        fprintf(stderr, "Lỗi: không thể xóa chuyển hướng cổng %u: %s\n", 
                src_port, strerror(errno));
        return -1;
    }
    
    printf("Đã xóa chuyển hướng cổng %u\n", src_port);
    return 0;
}

/* Bật/tắt obfuscation cho cgroup */
static int set_obfuscate(__u64 cgid, __u8 enabled) {
    int obfuscate_fd = open_map("obfuscate_cg");
    if (obfuscate_fd < 0) {
        fprintf(stderr, "Lỗi: không thể mở map 'obfuscate_cg'\n");
        return -1;
    }
    
    if (bpf_map_update_elem(obfuscate_fd, &cgid, &enabled, BPF_ANY) < 0) {
        fprintf(stderr, "Lỗi: không thể %s obfuscation cho cgid %llu: %s\n", 
                enabled ? "bật" : "tắt", cgid, strerror(errno));
        return -1;
    }
    
    printf("Đã %s obfuscation cho cgid %llu\n", 
           enabled ? "bật" : "tắt", cgid);
    return 0;
}

int main(int argc, char **argv) {
    cmd_t cmd = CMD_UNKNOWN;
    
    /* Kiểm tra đủ tham số */
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    
    /* Xác định lệnh */
    if (strcmp(argv[1], "quota") == 0)
        cmd = CMD_SET_QUOTA;
    else if (strcmp(argv[1], "redirect") == 0)
        cmd = CMD_ADD_REDIRECT;
    else if (strcmp(argv[1], "delredirect") == 0)
        cmd = CMD_DEL_REDIRECT;
    else if (strcmp(argv[1], "obfuscate") == 0)
        cmd = CMD_ENABLE_OBFUSCATE;
    else if (strcmp(argv[1], "stats") == 0)
        cmd = CMD_SHOW_STATS;
    
    /* Thực hiện lệnh */
    switch (cmd) {
    case CMD_SET_QUOTA:
        if (argc < 4) {
            fprintf(stderr, "Lỗi: quota cần cgid và bytes\n");
            usage(argv[0]);
            return 1;
        }
        return set_quota(strtoull(argv[2], NULL, 0), 
                      strtoull(argv[3], NULL, 0));
        
    case CMD_ADD_REDIRECT:
        if (argc < 4) {
            fprintf(stderr, "Lỗi: redirect cần source port và destination port\n");
            usage(argv[0]);
            return 1;
        }
        /* Tham số thứ 5 là tùy chọn (on/off) */
        __u8 enabled = 1;
        if (argc > 4)
            enabled = atoi(argv[4]) ? 1 : 0;
        return add_redirect(atoi(argv[2]), atoi(argv[3]), enabled);
        
    case CMD_DEL_REDIRECT:
        if (argc < 3) {
            fprintf(stderr, "Lỗi: delredirect cần source port\n");
            usage(argv[0]);
            return 1;
        }
        return del_redirect(atoi(argv[2]));
        
    case CMD_ENABLE_OBFUSCATE:
        if (argc < 4) {
            fprintf(stderr, "Lỗi: obfuscate cần cgid và flag (1=on, 0=off)\n");
            usage(argv[0]);
            return 1;
        }
        return set_obfuscate(strtoull(argv[2], NULL, 0), 
                          atoi(argv[3]) ? 1 : 0);
        
    case CMD_SHOW_STATS:
        return show_stats();
        
    default:
        fprintf(stderr, "Lỗi: lệnh không xác định: %s\n", argv[1]);
        usage(argv[0]);
        return 1;
    }
    
    return 0;
} 