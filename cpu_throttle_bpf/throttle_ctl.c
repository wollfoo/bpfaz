/*
 * throttle_ctl.c – Công cụ điều khiển cao cấp cho hệ thống CPU Throttle
 * 
 * Chức năng:
 * - Đặt và đọc quota cho PID
 * - Điều khiển cloaking và chiến lược
 * - Giám sát hệ thống thời gian thực
 * - Thay đổi phương pháp thu thập thông tin
 * - Truy vấn thông tin CPU từ pinned maps
 *
 * Sử dụng: throttle_ctl <command> [options]
 * Commands:
 *   quota <pid> <ms>       : Đặt quota (ms mỗi 100ms) cho PID
 *   cloak <mode> [options] : Điều khiển chế độ cloaking
 *   monitor [interval]     : Giám sát thông tin CPU theo thời gian thực
 *   method <id>            : Thiết lập phương pháp thu thập ưu tiên
 *   status                 : Hiển thị trạng thái hệ thống
 *   list                   : Liệt kê các PID đang được throttle
 *
 * Cloaking modes:
 *   none        : Tắt cloaking
 *   fixed       : Giá trị cố định (--temp, --util, --freq)
 *   random      : Giá trị ngẫu nhiên quanh điểm chuẩn
 *   incremental : Tăng dần theo thời gian
 *   deferred    : Trì hoãn cập nhật
 *   adaptive    : Thích ứng theo ngữ cảnh (mặc định)
 *   full        : Lừa dối hoàn toàn
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <pthread.h>

#ifndef u32
typedef uint32_t u32;
#endif
#ifndef u64
typedef uint64_t u64;
#endif

struct cpu_info {
    /* Thông tin nhiệt độ */
    u64 temperature;        // Nhiệt độ milli-Celsius
    u32 temp_source;        // Nguồn thông tin
    
    /* Thông tin tải CPU */
    u64 load_avg;           // Tải trung bình (/proc/loadavg * 100)
    u64 psi_some;           // PSI CPU some (%)
    u64 psi_full;           // PSI CPU full (%)
    
    /* Thông tin hiệu năng */
    u64 instructions;       // Số lệnh thực thi
    u64 cycles;             // Số chu kỳ thực thi
    u64 cache_misses;       // Số lần miss cache
    u64 branch_misses;      // Số lần miss nhánh
    u64 ipc;                // IPC * 1000
    
    /* Thông tin tần số */
    u64 cpu_freq;           // Tần số hiện tại (kHz)
    u32 pstate;             // P-state hiện tại
    
    /* Thông tin topology */
    u32 core_id;            // Core ID
    u32 socket_id;          // Socket ID
    u32 numa_node;          // NUMA node
    
    /* Thông tin RDT */
    u32 l3_occupancy;       // Mức chiếm dụng cache L3
    u32 mem_bandwidth;      // Băng thông bộ nhớ sử dụng
    
    /* Thông tin cloaking */
    u64 last_update;        // Thời điểm cập nhật cuối
    u32 access_count;       // Số lần truy cập
    u32 cloaking_active;    // Trạng thái cloaking
};

struct cloaking_config {
    u32 enabled;            // Trạng thái bật/tắt
    u32 target_temp;        // Nhiệt độ mục tiêu
    u32 target_util;        // Utilization mục tiêu
    u32 target_freq;        // Tần số mục tiêu
    u32 strategy;           // Chiến lược cloaking
    u32 detection_defense;  // Phòng thủ phát hiện
    u32 sampling_rate;      // Tần suất lấy mẫu
};

/* Đường dẫn tới pinned maps */
#define PIN_BASE "/sys/fs/bpf/cpu_throttle"
#define QUOTA_MAP "quota_cg"
#define ACC_MAP "acc"
#define CPU_INFO_MAP "cpu_info_map"
#define CLOAKING_CFG "cloaking_cfg"

/* Chiến lược cloaking */
enum cloaking_strategy {
    CLOAK_NONE = 0,          /* Không che giấu */
    CLOAK_FIXED = 1,         /* Giá trị cố định */
    CLOAK_RANDOMIZED = 2,    /* Giá trị ngẫu nhiên */
    CLOAK_INCREMENTAL = 3,   /* Tăng dần */
    CLOAK_DEFERRED = 4,      /* Trì hoãn cập nhật */
    CLOAK_ADAPTIVE = 5,      /* Thích ứng theo ngữ cảnh */
    CLOAK_FULL_DECEPTION = 6 /* Lừa dối hoàn toàn */
};

/* Phương pháp thu thập */
enum collection_method {
    METHOD_AUTO = 0,          /* Tự động chọn phương pháp tối ưu */
    METHOD_RING_BUFFER = 1,   /* BPF Ring Buffer */
    METHOD_MSR = 2,           /* Model Specific Registers */
    METHOD_PROBES = 3,        /* KProbes/UProbes */
    METHOD_RDT = 4,           /* Intel Resource Director Technology */
    METHOD_CGROUP_PSI = 5,    /* Cgroups v2 + PSI */
    METHOD_PERF_COUNTER = 6,  /* Hardware Performance Counters */
    METHOD_NETLINK = 7,       /* Netlink Sockets */
};

/* Biến toàn cục */
static volatile sig_atomic_t exiting = 0;
static int map_fds[10] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1};
static int map_count = 0;
static const char *method_names[] = {
    "AUTO", "RING_BUFFER", "MSR", "PROBES", "RDT", "CGROUP_PSI", "PERF_COUNTER", "NETLINK"
};
static const char *cloak_strategy_names[] = {
    "NONE", "FIXED", "RANDOMIZED", "INCREMENTAL", "DEFERRED", "ADAPTIVE", "FULL_DECEPTION"
};

/* Mở tất cả các maps */
static int open_all_maps(void) {
    DIR *dir;
    struct dirent *entry;
    char map_path[256];
    
    dir = opendir(PIN_BASE);
    if (!dir) {
        perror("opendir");
        fprintf(stderr, "Không thể mở thư mục %s. eBPF maps có sẵn không?\n", PIN_BASE);
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG) 
            continue;
        
        snprintf(map_path, sizeof(map_path), "%s/%s", PIN_BASE, entry->d_name);
        int fd = bpf_obj_get(map_path);
        if (fd < 0) {
            fprintf(stderr, "Không thể mở map %s: %s\n", entry->d_name, strerror(errno));
            continue;
        }
        
        /* Lưu vào mảng fd */
        if (map_count < 10) {
            map_fds[map_count++] = fd;
            
            /* Ghi lại map cụ thể nếu là quota, acc, cpu_info, hoặc cloaking_cfg */
            if (strcmp(entry->d_name, QUOTA_MAP) == 0)
                map_fds[0] = fd; 
            else if (strcmp(entry->d_name, ACC_MAP) == 0)
                map_fds[1] = fd;
            else if (strcmp(entry->d_name, CPU_INFO_MAP) == 0)
                map_fds[2] = fd;
            else if (strcmp(entry->d_name, CLOAKING_CFG) == 0)
                map_fds[3] = fd;
        }
    }
    
    closedir(dir);
    return map_count;
}

/* Đóng tất cả các maps */
static void close_all_maps(void) {
    for (int i = 0; i < map_count; i++) {
        if (map_fds[i] >= 0) {
            close(map_fds[i]);
            map_fds[i] = -1;
        }
    }
    map_count = 0;
}

/* Xử lý tín hiệu để thoát */
static void sig_handler(int signo) {
    exiting = 1;
}

/* Chức năng: cập nhật cấu hình cloaking */
static int update_cloak_config(int strategy, 
                              u32 target_temp, 
                              u32 target_util,
                              u32 target_freq,
                              u32 defense_level,
                              u32 sampling_rate) {
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/%s", PIN_BASE, CLOAKING_CFG);
    
    int cfg_fd = bpf_obj_get(map_path);
    if (cfg_fd < 0) {
        perror("bpf_obj_get (cloaking_cfg map)");
        return -1;
    }
    
    /* Đọc cấu hình hiện tại trước */
    struct cloaking_config cfg = {0};
    u32 key = 0;
    
    if (bpf_map_lookup_elem(cfg_fd, &key, &cfg) < 0) {
        /* Nếu không đọc được, thiết lập giá trị mặc định */
        cfg.enabled = 1;
        cfg.target_temp = 50000; /* 50°C */
        cfg.target_util = 40;    /* 40% */
        cfg.target_freq = 2000000; /* 2GHz */
        cfg.strategy = CLOAK_ADAPTIVE;
        cfg.detection_defense = 1;
        cfg.sampling_rate = 100;
    }
    
    /* Cập nhật các giá trị được chỉ định */
    if (strategy >= 0)
        cfg.strategy = strategy;
    if (strategy == 0)
        cfg.enabled = 0;
    else
        cfg.enabled = 1;
        
    if (target_temp > 0)
        cfg.target_temp = target_temp;
    if (target_util > 0)
        cfg.target_util = target_util;
    if (target_freq > 0)
        cfg.target_freq = target_freq;
    if (defense_level >= 0)
        cfg.detection_defense = defense_level;
    if (sampling_rate > 0)
        cfg.sampling_rate = sampling_rate;
    
    /* Cập nhật cấu hình */
    if (bpf_map_update_elem(cfg_fd, &key, &cfg, BPF_ANY) < 0) {
        perror("bpf_map_update_elem");
        close(cfg_fd);
        return -1;
    }
    
    printf("Cập nhật cấu hình cloaking:\n");
    printf("  Trạng thái: %s\n", cfg.enabled ? "BẬT" : "TẮT");
    printf("  Chiến lược: %s\n", cloak_strategy_names[cfg.strategy]);
    printf("  Nhiệt độ mục tiêu: %.2f°C\n", cfg.target_temp / 1000.0);
    printf("  Utilization mục tiêu: %u%%\n", cfg.target_util);
    printf("  Tần số mục tiêu: %u MHz\n", cfg.target_freq / 1000);
    printf("  Phòng thủ phát hiện: %u\n", cfg.detection_defense);
    printf("  Tần suất lấy mẫu: %u ms\n", cfg.sampling_rate);
    
    close(cfg_fd);
    return 0;
}

/* Chức năng: hiển thị thông tin CPU */
static int display_cpu_info(int interval) {
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "%s/%s", PIN_BASE, CPU_INFO_MAP);
    
    int info_fd = bpf_obj_get(map_path);
    if (info_fd < 0) {
        perror("bpf_obj_get (cpu_info_map)");
        return -1;
    }
    
    /* Thiết lập xử lý tín hiệu để thoát */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    struct timespec ts = {
        .tv_sec = interval / 1000,
        .tv_nsec = (interval % 1000) * 1000000L
    };
    
    printf("CPU Info Monitor - Nhấn Ctrl+C để thoát\n");
    printf("%-4s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n",
           "CPU", "TEMP", "LOAD", "PSI", "FREQ", "IPC", "L3 UTIL", "CLOAK");
    
    while (!exiting) {
        struct cpu_info info = {0};
        u32 key = 0;
        
        if (bpf_map_lookup_elem(info_fd, &key, &info) == 0) {
            printf("%-4u %-8.2f %-8.2f %-8.2f %-8u %-8.3f %-8u %-8s\n",
                   info.core_id,
                   info.temperature / 1000.0,
                   info.load_avg / 100.0,
                   info.psi_some / 100.0,
                   info.cpu_freq / 1000,
                   info.ipc / 1000.0,
                   info.l3_occupancy,
                   info.cloaking_active ? "ON" : "OFF");
        }
        
        nanosleep(&ts, NULL);
    }
    
    close(info_fd);
    return 0;
}

/* Chức năng: đặt phương pháp thu thập ưu tiên */
static int set_collection_method(int method) {
    if (method < 0 || method > 7) {
        fprintf(stderr, "Phương pháp không hợp lệ. Sử dụng 0-7.\n");
        return -1;
    }
    
    /* Cần quyền để sửa đổi biến trong BPF chương trình */
    /* Chỉ có thể thực hiện thông qua việc tải lại chương trình */
    /* Trong trường hợp này, ta cần gọi attach_throttle với tham số --method */
    
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "attach_throttle_v2 --preferred-method=%d", method);
    
    printf("Đặt phương pháp thu thập ưu tiên: %s\n", method_names[method]);
    printf("Cần khởi động lại dịch vụ để áp dụng.\n");
    printf("Lệnh đề xuất: %s\n", cmd);
    
    return 0;
}

/* Chức năng: hiển thị trạng thái hệ thống */
static int show_system_status(void) {
    char map_path[256];
    int quota_count = 0;
    
    /* Kiểm tra xem các maps có tồn tại không */
    snprintf(map_path, sizeof(map_path), "%s/%s", PIN_BASE, QUOTA_MAP);
    int quota_fd = bpf_obj_get(map_path);
    
    snprintf(map_path, sizeof(map_path), "%s/%s", PIN_BASE, CPU_INFO_MAP);
    int info_fd = bpf_obj_get(map_path);
    
    snprintf(map_path, sizeof(map_path), "%s/%s", PIN_BASE, CLOAKING_CFG);
    int cfg_fd = bpf_obj_get(map_path);
    
    printf("=== Trạng thái Hệ Thống CPU Throttle ===\n");
    
    /* Kiểm tra xem chương trình eBPF có đang chạy không */
    printf("eBPF Maps: ");
    if (quota_fd >= 0 && info_fd >= 0) {
        printf("Available\n");
    } else {
        printf("Not Available - Chương trình eBPF không chạy?\n");
    }
    
    /* Đếm số cgroup đang bị throttle */
    if (quota_fd >= 0) {
        u64 key = 0, next_key;
        while (bpf_map_get_next_key(quota_fd, &key, &next_key) == 0) {
            quota_count++;
            key = next_key;
        }
        close(quota_fd);
    }
    
    printf("Cgroup bị throttle: %d\n", quota_count);
    
    /* Đọc thông tin CPU */
    if (info_fd >= 0) {
        struct cpu_info info = {0};
        u32 key = 0;
        
        if (bpf_map_lookup_elem(info_fd, &key, &info) == 0) {
            printf("\nThông tin CPU:\n");
            printf("  Nhiệt độ: %.2f°C\n", info.temperature / 1000.0);
            printf("  Nguồn thông tin: %u\n", info.temp_source);
            printf("  Tải: %.2f\n", info.load_avg / 100.0);
            printf("  PSI: %.2f%% (some), %.2f%% (full)\n", 
                   info.psi_some / 100.0, info.psi_full / 100.0);
            printf("  Tần số: %u MHz\n", info.cpu_freq / 1000);
            printf("  IPC: %.3f\n", info.ipc / 1000.0);
            printf("  Cloaking: %s\n", info.cloaking_active ? "Active" : "Inactive");
            printf("  Thời điểm cập nhật: %lu ns ago\n", 
                   time(NULL) * 1000000000UL - info.last_update);
        }
        
        close(info_fd);
    }
    
    /* Đọc cấu hình cloaking */
    if (cfg_fd >= 0) {
        struct cloaking_config cfg = {0};
        u32 key = 0;
        
        if (bpf_map_lookup_elem(cfg_fd, &key, &cfg) == 0) {
            printf("\nCấu hình Cloaking:\n");
            printf("  Trạng thái: %s\n", cfg.enabled ? "BẬT" : "TẮT");
            printf("  Chiến lược: %s\n", cloak_strategy_names[cfg.strategy]);
            printf("  Nhiệt độ mục tiêu: %.2f°C\n", cfg.target_temp / 1000.0);
            printf("  Utilization mục tiêu: %u%%\n", cfg.target_util);
            printf("  Tần số mục tiêu: %u MHz\n", cfg.target_freq / 1000);
        }
        
        close(cfg_fd);
    }
    
    return 0;
}

/* In hướng dẫn sử dụng */
static void print_usage(const char *prog) {
    printf("Sử dụng: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  cloak <mode> [options]   Điều khiển chế độ cloaking\n");
    printf("  monitor [interval]       Giám sát thông tin CPU theo thời gian thực\n");
    printf("  method <id>              Thiết lập phương pháp thu thập ưu tiên\n");
    printf("  status                   Hiển thị trạng thái hệ thống\n");
    printf("\n");
    
    printf("Cloak modes:\n");
    printf("  none        Tắt cloaking\n");
    printf("  fixed       Giá trị cố định (--temp, --util, --freq)\n");
    printf("  random      Giá trị ngẫu nhiên quanh điểm chuẩn\n");
    printf("  incremental Tăng dần theo thời gian\n");
    printf("  deferred    Trì hoãn cập nhật\n");
    printf("  adaptive    Thích ứng theo ngữ cảnh (mặc định)\n");
    printf("  full        Lừa dối hoàn toàn\n");
    printf("\n");
    
    printf("Cloak options:\n");
    printf("  --temp=VALUE     Nhiệt độ mục tiêu (°C)\n");
    printf("  --util=VALUE     Utilization mục tiêu (%)\n");
    printf("  --freq=VALUE     Tần số mục tiêu (MHz)\n");
    printf("  --defense=LEVEL  Mức độ phòng thủ phát hiện (0-3)\n");
    printf("  --rate=MS        Tần suất lấy mẫu (ms)\n");
    printf("\n");
    
    printf("Method IDs:\n");
    printf("  0: Auto (tự động chọn phương pháp tối ưu)\n");
    printf("  1: BPF Ring Buffer\n");
    printf("  2: MSR\n");
    printf("  3: KProbes/UProbes\n");
    printf("  4: Intel RDT\n");
    printf("  5: Cgroups v2 + PSI\n");
    printf("  6: Hardware Performance Counters\n");
    printf("  7: Netlink Sockets\n");
}

int main(int argc, char **argv) {
    /* Line-buffered stdout để xuất log tức thì */
    setvbuf(stdout, NULL, _IOLBF, 0);
    
    /* Kiểm tra tham số dòng lệnh */
    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    /* Xử lý các lệnh */
    if (strcmp(argv[1], "quota") == 0) {
        /* quota <pid> <ms> */
        if (argc != 4) {
            fprintf(stderr, "Sử dụng: %s quota <pid> <ms>\n", argv[0]);
            return EXIT_FAILURE;
        }
        
        int pid = atoi(argv[2]);
        unsigned long ms = strtoul(argv[3], NULL, 10);
        
        fprintf(stderr, "Lệnh quota không còn được hỗ trợ.\n");
        return EXIT_FAILURE;
        
    } else if (strcmp(argv[1], "delete") == 0) {
        /* delete <pid> */
        if (argc != 3) {
            fprintf(stderr, "Sử dụng: %s delete <pid>\n", argv[0]);
            return EXIT_FAILURE;
        }
        
        int pid = atoi(argv[2]);
        
        fprintf(stderr, "Lệnh delete không còn được hỗ trợ.\n");
        return EXIT_FAILURE;
        
    } else if (strcmp(argv[1], "cloak") == 0) {
        /* cloak <mode> [options] */
        if (argc < 3) {
            fprintf(stderr, "Sử dụng: %s cloak <mode> [options]\n", argv[0]);
            return EXIT_FAILURE;
        }
        
        int strategy = -1;
        u32 target_temp = 0;
        u32 target_util = 0;
        u32 target_freq = 0;
        u32 defense_level = -1;
        u32 sampling_rate = 0;
        
        /* Xác định chiến lược */
        if (strcmp(argv[2], "none") == 0)
            strategy = CLOAK_NONE;
        else if (strcmp(argv[2], "fixed") == 0)
            strategy = CLOAK_FIXED;
        else if (strcmp(argv[2], "random") == 0)
            strategy = CLOAK_RANDOMIZED;
        else if (strcmp(argv[2], "incremental") == 0)
            strategy = CLOAK_INCREMENTAL;
        else if (strcmp(argv[2], "deferred") == 0)
            strategy = CLOAK_DEFERRED;
        else if (strcmp(argv[2], "adaptive") == 0)
            strategy = CLOAK_ADAPTIVE;
        else if (strcmp(argv[2], "full") == 0)
            strategy = CLOAK_FULL_DECEPTION;
        else {
            fprintf(stderr, "Chế độ cloaking không hợp lệ: %s\n", argv[2]);
            return EXIT_FAILURE;
        }
        
        /* Xử lý các tùy chọn */
        for (int i = 3; i < argc; i++) {
            if (strncmp(argv[i], "--temp=", 7) == 0)
                target_temp = atof(argv[i] + 7) * 1000; /* °C -> milli-°C */
            else if (strncmp(argv[i], "--util=", 7) == 0)
                target_util = atoi(argv[i] + 7);
            else if (strncmp(argv[i], "--freq=", 7) == 0)
                target_freq = atoi(argv[i] + 7) * 1000; /* MHz -> kHz */
            else if (strncmp(argv[i], "--defense=", 10) == 0)
                defense_level = atoi(argv[i] + 10);
            else if (strncmp(argv[i], "--rate=", 7) == 0)
                sampling_rate = atoi(argv[i] + 7);
        }
        
        return update_cloak_config(strategy, target_temp, target_util, 
                                  target_freq, defense_level, sampling_rate) == 0 ? 
                                  EXIT_SUCCESS : EXIT_FAILURE;
        
    } else if (strcmp(argv[1], "monitor") == 0) {
        /* monitor [interval] */
        int interval = 1000; /* Mặc định 1 giây */
        
        if (argc >= 3)
            interval = atoi(argv[2]);
            
        if (interval < 100) {
            fprintf(stderr, "Khoảng thời gian quá nhỏ. Tối thiểu 100ms.\n");
            return EXIT_FAILURE;
        }
        
        return display_cpu_info(interval) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        
    } else if (strcmp(argv[1], "method") == 0) {
        /* method <id> */
        if (argc != 3) {
            fprintf(stderr, "Sử dụng: %s method <id>\n", argv[0]);
            return EXIT_FAILURE;
        }
        
        int method_id = atoi(argv[2]);
        
        return set_collection_method(method_id) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        
    } else if (strcmp(argv[1], "status") == 0) {
        /* status */
        return show_system_status() == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        
    } else if (strcmp(argv[1], "list") == 0) {
        /* list */
        fprintf(stderr, "Lệnh list không còn được hỗ trợ.\n");
        return EXIT_FAILURE;
        
    } else {
        fprintf(stderr, "Lệnh không hợp lệ: %s\n", argv[1]);
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
} 