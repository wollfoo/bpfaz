/* attach_throttle_v2.c - Chương trình nạp và quản lý cpu_throttle.bpf.c 
 * Tích hợp đầy đủ 7 phương pháp thu thập và cloaking thông tin CPU
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>  /* Thêm hỗ trợ cho uint32_t và uint64_t */
#include <linux/types.h>
#include <linux/version.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <fcntl.h>
#include <time.h>
#include <dirent.h>  /* Thêm hỗ trợ duyệt thư mục */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/utsname.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/ioctl.h>  /* ioctl */
#include <math.h>  /* Thêm hỗ trợ cho các hàm toán học */
#include <sched.h>  /* Thêm cho sched_getcpu */

/* Định nghĩa kiểu dữ liệu u32 và u64 */
#ifndef u32
typedef uint32_t u32;
#endif
#ifndef u64
typedef uint64_t u64;
#endif

/* Cài đặt hỗ trợ Intel RDT nếu có */
#include <stdlib.h>
/* Định nghĩa NO_RDT để bỏ qua tính năng RDT */
// #define NO_RDT 1  /* Đã tắt để bật hỗ trợ Intel RDT */
#ifndef NO_RDT
#include <pqos.h>
#endif

/* Cài đặt thư viện MSR */
#include <errno.h>
#include <sys/io.h>
#ifndef NO_MSR
#include <cpuid.h>
#endif

/* Hỗ trợ netlink */
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <sys/socket.h>

#include "cpu_throttle_bpf.skel.h"

/* Định nghĩa phiên bản kernel tối thiểu */
#define KERNEL_VERSION_MIN_MAJOR 5
#define KERNEL_VERSION_MIN_MINOR 8
#define KERNEL_VERSION_MIN_PATCH 0

/* Pin paths */
#define PIN_BASEDIR "/sys/fs/bpf/cpu_throttle"
#define PIN_MAP_ACC PIN_BASEDIR "/acc"
#define PIN_MAP_QUOTA PIN_BASEDIR "/quota_cg"
#define PIN_LINK PIN_BASEDIR "/link"

/* Enum các phương pháp thu thập */
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

/* Enum các chiến lược cloaking */
enum cloaking_strategy {
    CLOAK_NONE = 0,          /* Không che giấu */
    CLOAK_FIXED = 1,         /* Giá trị cố định */
    CLOAK_RANDOMIZED = 2,    /* Giá trị ngẫu nhiên */
    CLOAK_INCREMENTAL = 3,   /* Tăng dần */
    CLOAK_DEFERRED = 4,      /* Trì hoãn cập nhật */
    CLOAK_ADAPTIVE = 5,      /* Thích ứng theo ngữ cảnh */
    CLOAK_FULL_DECEPTION = 6 /* Lừa dối hoàn toàn */
};

/* Loại sự kiện trong ring buffer */
enum event_type {
    EVENT_THROTTLE = 0,       /* Sự kiện throttle */
    EVENT_TEMP_UPDATE = 1,    /* Cập nhật nhiệt độ */
    EVENT_IPC_UPDATE = 2,     /* Cập nhật IPC */
    EVENT_PSI_UPDATE = 3,     /* Cập nhật PSI */
    EVENT_CLOAK_ACTIVE = 4,   /* Kích hoạt cloaking */
    EVENT_DETECTION_AVOID = 5 /* Phát hiện tránh né */
};

/* Cấu trúc sự kiện cho ring buffer */
struct throttle_event {
    u32 pid;                /* Process ID */
    u32 tgid;               /* Thread group ID */
    u64 quota_ns;           /* Quota thời gian (ns) */
    u64 used_ns;            /* Thời gian đã sử dụng (ns) */
    u64 timestamp;          /* Thời điểm (ns) */
    u32 cpu;                /* CPU ID */
    u32 throttled;          /* Trạng thái tiết lưu */
    u32 method_id;          /* Phương pháp đang sử dụng */
    u32 event_type;         /* Loại sự kiện */
};

/* Cấu trúc dữ liệu CPU */
struct cpu_info {
    u64 temperature;
    u32 temp_source;
    u64 load_avg;
    u64 psi_some;
    u64 psi_full;
    u64 instructions;
    u64 cycles;
    u64 ipc_raw;
    u64 cpu_freq;
    u32 pstate;
    u32 core_id;
    u32 socket_id;
    u32 l3_occupancy;
    u32 mem_bandwidth;
    u64 last_update;
    u32 access_count;
    u32 cloaking_active;
    u32 numa_node;
    u64 cache_misses;
    u64 branch_misses;
    u64 ipc;
};

/* Cấu trúc cloaking */
struct cloaking_config {
    u32 enabled;
    u32 target_temp;
    u32 target_util;
    u32 target_freq;
    u32 strategy;
    u32 detection_defense;
    u32 sampling_rate;
};

/* Biến toàn cục */
static volatile sig_atomic_t exiting = 0;
static struct cpu_throttle_bpf *skel = NULL;
static pthread_t collection_thread;
static pthread_t ring_buffer_thread;
static pthread_t cg_scan_thread;
static int cgroup_psi_fd = -1;
static int perf_ipc_fd = -1;
static int netlink_socket_fd = -1;

/* Biến cho INCREMENTAL và DEFERRED cloaking */
static u64 incremental_start_time = 0;  /* Thời gian bắt đầu cho chiến lược INCREMENTAL */
static u64 incremental_step = 0;        /* Bước tăng hiện tại cho chiến lược INCREMENTAL */
static u64 deferred_values[5] = {0};    /* Lưu trữ giá trị gốc cho DEFERRED [0=temp, 1=psi, 2=ipc, 3=load, 4=freq] */
static u64 deferred_update_time = 0;    /* Thời điểm cập nhật cuối cùng cho DEFERRED */
static u64 deferred_delay_ms = 5000;    /* Độ trễ mặc định cho DEFERRED (5 giây) */

/* Biến quản lý các phương pháp */
static struct {
    bool enabled;
    bool available;
    int fd;
    void *data;
} methods[8] = {0};

/* Cấu trúc tùy chọn */
struct options {
    bool verbose;
    bool debug;
    int preferred_method;
    bool use_hwmon;
    bool use_msr;
    bool use_rdt;
    bool use_psi;
    bool use_perf;
    bool use_netlink;
    bool cloaking_enabled;
    int cloaking_strategy;
    int collection_interval_ms;
    bool pin_maps;
    bool seccomp_enabled;
    char hwmon_path[256];
    /* Tùy chọn cấu hình bổ sung cho INCREMENTAL và DEFERRED */
    int incremental_duration;  /* Thời gian (giây) để hoàn thành một chu kỳ tăng dần */
    int deferred_delay;        /* Độ trễ (ms) giữa các lần cập nhật cho chiến lược DEFERRED */
};

static struct options opt = {
    .verbose = false,
    .debug = false,
    .preferred_method = 0, // AUTO
    .use_hwmon = true,
    .use_msr = true,
    .use_rdt = true,
    .use_psi = true,
    .use_perf = true,
    .use_netlink = true,
    .cloaking_enabled = true,
    .cloaking_strategy = 5, // CLOAK_ADAPTIVE
    .collection_interval_ms = 100,
    .pin_maps = true,
    .seccomp_enabled = false,
    .hwmon_path = "",
    .incremental_duration = 300, // 5 phút cho một chu kỳ
    .deferred_delay = 5000,     // 5 giây độ trễ
};

/* Xử lý tín hiệu dừng */
static void sig_handler(int sig) {
    exiting = 1;
}

/* Kiểm tra phiên bản kernel */
static bool check_kernel_version(void) {
    struct utsname utsname;
    unsigned int major, minor, patch;
    
    if (uname(&utsname) < 0) {
        perror("uname");
        return false;
    }
    
    if (sscanf(utsname.release, "%u.%u.%u", &major, &minor, &patch) != 3) {
        fprintf(stderr, "Không thể phân tích phiên bản kernel: %s\n", utsname.release);
        return false;
    }
    
    if (opt.verbose) {
        printf("Kernel version: %u.%u.%u\n", major, minor, patch);
    }
    
    return (major > KERNEL_VERSION_MIN_MAJOR || 
           (major == KERNEL_VERSION_MIN_MAJOR && minor >= KERNEL_VERSION_MIN_MINOR));
}

/* Hàm libbpf_print_fn */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !opt.debug)
        return 0;
        
    return vfprintf(stderr, format, args);
}

/* Tìm đường dẫn hwmon phù hợp */
static int find_thermal_path(char *path, size_t max_len) {
    FILE *fp;
    char cmd[512];
    char buf[512];
    int found = 0;
    
    /* Ưu tiên cảm biến CPU */
    snprintf(cmd, sizeof(cmd), 
             "find /sys/class/hwmon -type f -name \"*label\" -exec grep -l \"Core\\|CPU\\|Package\" {} \\; "
             "| sed 's/label/temp1_input/g' | head -n 1");
    
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(buf, sizeof(buf), fp) != NULL) {
            /* Xóa ký tự xuống dòng */
            size_t len = strlen(buf);
            if (len > 0 && buf[len-1] == '\n')
                buf[len-1] = '\0';
                
            /* Kiểm tra xem tệp có tồn tại không */
            if (access(buf, R_OK) == 0) {
                strncpy(path, buf, max_len - 1);
                path[max_len - 1] = '\0';
                found = 1;
            }
        }
        pclose(fp);
    }
    
    /* Nếu không tìm thấy, thử đọc từ thermal_zone */
    if (!found) {
        int i = 0;
        char zone_path[256];
        char type[64];
        
        while (!found && i < 10) {
            snprintf(zone_path, sizeof(zone_path), "/sys/class/thermal/thermal_zone%d/type", i);
            fp = fopen(zone_path, "r");
            if (fp) {
                if (fgets(type, sizeof(type), fp)) {
                    /* Tìm zone CPU */
                    if (strstr(type, "x86_pkg_temp") || strstr(type, "cpu") || 
                        strstr(type, "CPU") || strstr(type, "core")) {
                        snprintf(path, max_len, "/sys/class/thermal/thermal_zone%d/temp", i);
                        found = 1;
                    }
                }
                fclose(fp);
            }
            i++;
        }
        
        /* Nếu vẫn không tìm thấy, sử dụng zone đầu tiên */
        if (!found && access("/sys/class/thermal/thermal_zone0/temp", R_OK) == 0) {
            snprintf(path, max_len, "/sys/class/thermal/thermal_zone0/temp");
            found = 1;
        }
    }
    
    if (found && opt.verbose) {
        printf("Đã tìm thấy cảm biến nhiệt độ: %s\n", path);
    }
    
    return found ? 0 : -1;
}

/* Khởi tạo RDT nếu có sẵn */
static bool setup_rdt(void) {
#ifdef NO_RDT
    if (opt.verbose)
        printf("RDT: Không được hỗ trợ (biên dịch với NO_RDT)\n");
    return false;
#else
    if (!opt.use_rdt)
        return false;

    struct pqos_config cfg;
    int ret;
    
    memset(&cfg, 0, sizeof(cfg));
    cfg.fd_log = STDOUT_FILENO;
    cfg.verbose = opt.debug;
    
    ret = pqos_init(&cfg);
    if (ret != PQOS_RETVAL_OK) {
        if (opt.verbose)
            fprintf(stderr, "RDT không khả dụng: %d\n", ret);
        return false;
    }
    
    /* Kiểm tra hỗ trợ CMT (Cache Monitoring Technology) */
    const struct pqos_cap *cap = NULL;
    const struct pqos_cpuinfo *cpu = NULL;
    ret = pqos_cap_get(&cap, &cpu);
    if (ret != PQOS_RETVAL_OK) {
        pqos_fini();
        return false;
    }
    
    const struct pqos_capability *cmt_cap = NULL;
    ret = pqos_cap_get_type(cap, PQOS_CAP_TYPE_MON, &cmt_cap);
    if (ret != PQOS_RETVAL_OK || cmt_cap == NULL) {
        if (opt.verbose)
            printf("CMT không được hỗ trợ trên nền tảng này\n");
        pqos_fini();
        return false;
    }
    
    methods[METHOD_RDT].available = true;
    methods[METHOD_RDT].data = cap;
    
    if (opt.verbose)
        printf("RDT được khởi tạo thành công\n");
    return true;
#endif
}

/* Đọc thông tin CPU từ MSR với auto-loading và persistent setup */
static bool setup_msr(void) {
    if (!opt.use_msr)
        return false;

    /* Kiểm tra MSR truy cập có khả dụng không */
    if (access("/dev/cpu/0/msr", R_OK) != 0) {
        if (opt.verbose)
            printf("MSR device không khả dụng, đang thử load module...\n");

        /* Thử nạp msr module với sudo */
        int ret = system("sudo modprobe msr 2>/dev/null");
        if (ret != 0) {
            /* Thử không sudo (có thể đã có quyền) */
            ret = system("modprobe msr 2>/dev/null");
        }

        /* Đợi một chút để device file được tạo */
        usleep(100000); // 100ms

        if (access("/dev/cpu/0/msr", R_OK) != 0) {
            if (opt.verbose) {
                fprintf(stderr, "MSR access không khả dụng (/dev/cpu/0/msr)\n");
                fprintf(stderr, "Hướng dẫn khắc phục:\n");
                fprintf(stderr, "  1. Chạy: sudo modprobe msr\n");
                fprintf(stderr, "  2. Hoặc thêm 'msr' vào /etc/modules\n");
                fprintf(stderr, "  3. Hoặc tạo file: echo 'msr' | sudo tee /etc/modules-load.d/msr.conf\n");
            }
            return false;
        }
    }

    /* Kiểm tra quyền đọc */
    if (access("/dev/cpu/0/msr", R_OK) != 0) {
        if (opt.verbose) {
            fprintf(stderr, "MSR device tồn tại nhưng không có quyền đọc\n");
            fprintf(stderr, "Cần chạy với quyền root hoặc thêm user vào group 'msr'\n");
        }
        return false;
    }

    methods[METHOD_MSR].available = true;
    if (opt.verbose)
        printf("MSR access được kích hoạt thành công\n");

    return true;
}

/* Đọc nhiệt độ từ MSR */
static u64 read_temp_from_msr(int cpu_id) {
    if (!methods[METHOD_MSR].available)
        return 0;
        
    char msr_path[64];
    int fd;
    u64 msr_val = 0;
    
    /* Mở thiết bị MSR */
    snprintf(msr_path, sizeof(msr_path), "/dev/cpu/%d/msr", cpu_id);
    fd = open(msr_path, O_RDONLY);
    if (fd < 0)
        return 0;
    
    /* Đọc MSR_IA32_THERM_STATUS */
    if (pread(fd, &msr_val, sizeof(msr_val), 0x19C) != sizeof(msr_val)) {
        close(fd);
        return 0;
    }
    
    close(fd);
    
    /* Tính toán nhiệt độ từ MSR */
    u64 temp_target = 100000;  // 100°C mặc định
    u32 thermal_status = (msr_val >> 16) & 0x7F;
    
    if (thermal_status > 0) {
        u64 temp = temp_target - thermal_status * 1000;
        return temp;
    }
    
    return 0;
}

/* Thiết lập perf events cho IPC */
static bool setup_perf_events(void) {
    if (!opt.use_perf)
        return false;
        
    static struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_TASK_CLOCK,
        .size = sizeof(struct perf_event_attr),
        .sample_period = 1000000, // 1M instructions
        .sample_type = PERF_SAMPLE_PERIOD,
        .read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
        .disabled = 1,
        .exclude_kernel = 1,
        .exclude_hv = 1
    };
    
    /* Mở perf event cho instructions */
    int fd = syscall(__NR_perf_event_open, &attr, -1, 0, -1, 0);
    if (fd < 0) {
        if (opt.verbose)
            perror("perf_event_open instructions");
        return false;
    }
    
    /* Kích hoạt counting */
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    
    perf_ipc_fd = fd;
    methods[METHOD_PERF_COUNTER].available = true;
    methods[METHOD_PERF_COUNTER].fd = fd;
    
    if (opt.verbose)
        printf("Perf events được thiết lập thành công\n");
    
    return true;
}

/* Thiết lập cgroups v2 và PSI */
static bool setup_cgroups_psi(void) {
    if (!opt.use_psi)
        return false;
        
    /* Kiểm tra xem PSI có khả dụng không */
    if (access("/proc/pressure/cpu", R_OK) != 0) {
        if (opt.verbose)
            fprintf(stderr, "PSI không khả dụng (/proc/pressure/cpu)\n");
        return false;
    }
    
    /* Mở file PSI để đọc liên tục */
    int fd = open("/proc/pressure/cpu", O_RDONLY);
    if (fd < 0) {
        if (opt.verbose)
            perror("open /proc/pressure/cpu");
        return false;
    }
    
    cgroup_psi_fd = fd;
    methods[METHOD_CGROUP_PSI].available = true;
    methods[METHOD_CGROUP_PSI].fd = fd;
    
    if (opt.verbose)
        printf("PSI monitoring được thiết lập thành công\n");
    
    return true;
}

/* Đọc thông tin PSI */
static u64 read_psi_from_procfs(void) {
    if (!methods[METHOD_CGROUP_PSI].available)
        return 0;
        
    char buf[256];
    double some = 0;
    ssize_t bytes;
    
    /* Di chuyển đến đầu file */
    lseek(cgroup_psi_fd, 0, SEEK_SET);
    
    /* Đọc dữ liệu PSI */
    bytes = read(cgroup_psi_fd, buf, sizeof(buf) - 1);
    if (bytes <= 0)
        return 0;
        
    buf[bytes] = '\0';
    
    /* Phân tích dữ liệu PSI */
    if (sscanf(buf, "some avg10=%lf", &some) != 1)
        some = 0;
        
    return (u64)(some * 100);
}

/* Thiết lập Netlink Socket */
static bool setup_netlink_socket(void) {
    if (!opt.use_netlink)
        return false;
        
    /* Tạo socket netlink */
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) {
        if (opt.verbose)
            perror("socket netlink");
        return false;
    }
    
    /* Thiết lập địa chỉ netlink */
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = getpid(),
        .nl_groups = 0
    };
    
    /* Bind socket */
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (opt.verbose)
            perror("bind netlink");
        close(fd);
        return false;
    }
    
    netlink_socket_fd = fd;
    methods[METHOD_NETLINK].available = true;
    methods[METHOD_NETLINK].fd = fd;
    
    if (opt.verbose)
        printf("Netlink socket được thiết lập thành công\n");
    
    return true;
}

/* Xử lý sự kiện từ ring buffer */
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct throttle_event *e = data;
    
    if (opt.debug) {
        printf("Sự kiện: pid=%u, cpu=%u, throttled=%u, method=%u, type=%u\n",
                e->pid, e->cpu, e->throttled, e->method_id, e->event_type);
    }
    
    return 0;
}

/* Thiết lập ring buffer */
static int setup_ring_buffer(void) {
    struct ring_buffer *rb = NULL;
    int map_fd;
    
    if (!skel) {
        fprintf(stderr, "BPF skeleton chưa được khởi tạo\n");
        return -1;
    }
    
    /* Lấy file descriptor của map events */
    map_fd = bpf_map__fd(skel->maps.events);
    if (map_fd < 0) {
        fprintf(stderr, "Không thể lấy file descriptor của map events\n");
        return -1;
    }
    
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Không thể tạo ring buffer\n");
        return -1;
    }
    
    methods[METHOD_RING_BUFFER].data = rb;
    methods[METHOD_RING_BUFFER].fd = map_fd;
    methods[METHOD_RING_BUFFER].available = true;
    
    if (opt.verbose)
        printf("Ring buffer đã được thiết lập\n");
    
    if (opt.verbose) printf("Sau setup_ring_buffer()\n");
    
    return 0;
}

/* Thread đọc ring buffer */
static void *ring_buffer_poll(void *arg) {
    struct ring_buffer *rb = methods[METHOD_RING_BUFFER].data;
    
    if (!rb)
        return NULL;
    
    while (!exiting) {
        ring_buffer__poll(rb, 100 /* timeout, ms */);
    }
    
    return NULL;
}

/* Đọc thông tin nhiệt độ từ hwmon */
static u64 read_temp_from_hwmon(void) {
    int fd;
    char buf[16];
    ssize_t bytes_read;
    u64 temp = 0;
    
    if (!opt.use_hwmon || !opt.hwmon_path[0])
        return 0;
    
    fd = open(opt.hwmon_path, O_RDONLY);
    if (fd < 0)
        return 0;
    
    bytes_read = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    
    if (bytes_read <= 0)
        return 0;
    
    buf[bytes_read] = '\0';
    temp = strtoull(buf, NULL, 10);
    
    return temp;
}

/* Thu thập thông tin CPU từ nhiều nguồn */
static void collect_cpu_info(struct cpu_info *info) {
    unsigned cpu_id = sched_getcpu();
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    u64 current_time = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    
    /* Khởi tạo thông tin cơ bản */
    info->core_id = cpu_id;
    info->last_update = current_time;
    info->access_count++;
    
    /* 1. Thu thập nhiệt độ theo thứ tự ưu tiên */
    /* a) MSR - truy cập trực tiếp */
    if (methods[METHOD_MSR].available) {
        u64 temp = read_temp_from_msr(cpu_id);
        if (temp > 0) {
            info->temperature = temp;
            info->temp_source = METHOD_MSR;
        }
    }
    
    /* b) Hwmon - nếu MSR không có hoặc không đọc được */
    if (info->temperature == 0 && opt.hwmon_path[0]) {
        u64 temp = read_temp_from_hwmon();
        if (temp > 0) {
            info->temperature = temp;
            info->temp_source = 3; /* hwmon */
        }
    }
    
    /* 2. Thu thập PSI */
    if (methods[METHOD_CGROUP_PSI].available) {
        info->psi_some = read_psi_from_procfs();
    }
    
    /* 3. Thu thập thông tin tải */
    FILE *fp = fopen("/proc/loadavg", "r");
    if (fp) {
        float load1, load5, load15;
        if (fscanf(fp, "%f %f %f", &load1, &load5, &load15) == 3) {
            info->load_avg = (u64)(load1 * 100);
        }
        fclose(fp);
    }
    
    /* 4. Thu thập thông tin tần số */
    char freq_path[100];
    snprintf(freq_path, sizeof(freq_path), 
             "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", cpu_id);
    
    fp = fopen(freq_path, "r");
    if (fp) {
        if (fscanf(fp, "%lu", &info->cpu_freq) != 1) {
            info->cpu_freq = 0;
        }
        fclose(fp);
    }
    
    /* 5. Thu thập thông tin IPC nếu perf khả dụng */
    if (methods[METHOD_PERF_COUNTER].available && perf_ipc_fd >= 0) {
        struct {
            u64 count;
            u64 time_enabled;
            u64 time_running;
        } counts;
        
        if (read(perf_ipc_fd, &counts, sizeof(counts)) == sizeof(counts)) {
            u64 prev_instr = info->instructions;
            u64 prev_cycles = info->cycles;
            
            /* Cập nhật thông tin chỉ số */
            info->instructions = counts.count;
            
            /* Tính IPC nếu có đủ thông tin */
            if (prev_instr > 0 && prev_cycles > 0) {
                u64 instr_delta = info->instructions - prev_instr;
                u64 cycles_delta = info->cycles - prev_cycles;
                
                if (cycles_delta > 0) {
                    info->ipc = (instr_delta * 1000) / cycles_delta;
                }
            }
        }
    }
    
    /* 6. Thu thập thông tin RDT nếu có */
#ifndef NO_RDT
    if (methods[METHOD_RDT].available) {
        /* Đọc thông tin L3 occupancy qua RDT API */
        struct pqos_mon_data mon_data;
        memset(&mon_data, 0, sizeof(mon_data));
        
        if (pqos_mon_start(1, &cpu_id, PQOS_MON_EVENT_L3_OCCUP, NULL, &mon_data) 
                == PQOS_RETVAL_OK) {
            /* Cập nhật thông tin */
            info->l3_occupancy = mon_data.values.llc;
            info->mem_bandwidth = mon_data.values.mbm_local;
            
            /* Dừng monitoring */
            pqos_mon_stop(&mon_data);
        }
    }
#endif
    
    /* Áp dụng cloaking nếu được bật */
    if (opt.cloaking_enabled) {
        /* Tùy thuộc vào chiến lược cloaking */
        switch (opt.cloaking_strategy) {
            case CLOAK_FIXED: {
                /* Giá trị cố định */
                info->temperature = 65000; /* 65°C */
                info->psi_some = 1500;     /* 15% */
                info->ipc = 950;           /* 0.95 */
                info->cloaking_active = 1;
                break;
            }
            
            case CLOAK_RANDOMIZED: {
                /* Giá trị ngẫu nhiên */
                int rand_temp = rand() % 10000;  /* ±5°C */
                info->temperature = 60000 + rand_temp;
                info->psi_some = 1000 + (rand() % 1000);
                info->ipc = 900 + (rand() % 200);
                info->cloaking_active = 1;
                break;
            }
            
            case CLOAK_INCREMENTAL: {
                /* Chiến lược tăng dần theo thời gian */
                /* Đây là phương pháp mới được triển khai */
                
                /* Khởi tạo thời gian bắt đầu nếu chưa có */
                if (incremental_start_time == 0) {
                    incremental_start_time = current_time;
                    incremental_step = 0;
                }
                
                /* Tính toán thời gian đã trôi qua (ms) */
                u64 elapsed_ms = (current_time - incremental_start_time) / 1000000ULL;
                u64 total_duration_ms = opt.incremental_duration * 1000ULL;
                
                /* Tính toán vị trí trong chu kỳ (0-1) */
                double cycle_position = fmod((double)elapsed_ms / total_duration_ms, 1.0);
                
                /* Tính giá trị sin trong chu kỳ (từ 0 đến 1) */
                double sin_val = (sin(cycle_position * 2 * M_PI) + 1) / 2.0;
                
                /* Áp dụng sin wave cho nhiệt độ, CPU usage, và IPC */
                info->temperature = 55000 + (u64)(sin_val * 20000); /* 55-75°C */
                info->psi_some = 500 + (u64)(sin_val * 3000);       /* 5-35% */
                info->ipc = 800 + (u64)(sin_val * 400);             /* 0.8-1.2 */
                info->load_avg = 30 + (u64)(sin_val * 50);          /* 30-80% */
                
                /* Tăng bước và ghi nhận hoạt động cloaking */
                incremental_step++;
                info->cloaking_active = 1;
                break;
            }
            
            case CLOAK_DEFERRED: {
                /* Chiến lược trì hoãn cập nhật */
                /* Đây là phương pháp mới được triển khai */
                
                /* Lưu trữ giá trị gốc nếu chưa có */
                if (deferred_values[0] == 0) {
                    deferred_values[0] = info->temperature;
                    deferred_values[1] = info->psi_some;
                    deferred_values[2] = info->ipc;
                    deferred_values[3] = info->load_avg;
                    deferred_values[4] = info->cpu_freq;
                    deferred_update_time = current_time;
                }
                
                /* Kiểm tra xem đã đến lúc cập nhật chưa */
                u64 elapsed_ms = (current_time - deferred_update_time) / 1000000ULL;
                
                if (elapsed_ms >= (u64)opt.deferred_delay) {
                    /* Cập nhật giá trị lưu trữ */
                    deferred_values[0] = info->temperature;
                    deferred_values[1] = info->psi_some;
                    deferred_values[2] = info->ipc;
                    deferred_values[3] = info->load_avg;
                    deferred_values[4] = info->cpu_freq;
                    deferred_update_time = current_time;
                    
                    if (opt.debug) {
                        printf("Deferred: Cập nhật giá trị lưu trữ - temp=%.2f°C psi=%.2f%% ipc=%.3f\n",
                               info->temperature/1000.0, info->psi_some/100.0, info->ipc/1000.0);
                    }
                } else {
                    /* Sử dụng giá trị cũ đã lưu trữ */
                    info->temperature = deferred_values[0];
                    info->psi_some = deferred_values[1];
                    info->ipc = deferred_values[2];
                    info->load_avg = deferred_values[3];
                    info->cpu_freq = deferred_values[4];
                    
                    /* Thêm một ít nhiễu ngẫu nhiên nhỏ để tránh phát hiện */
                    info->temperature += (rand() % 200) - 100; /* ±0.1°C */
                    info->psi_some += (rand() % 20) - 10;      /* ±0.1% */
                }
                
                info->cloaking_active = 1;
                break;
            }
            
            case CLOAK_ADAPTIVE: {
                /* Thích ứng theo ngữ cảnh */
                u64 real_temp = info->temperature;
                u64 real_psi = info->psi_some;
                
                /* Nếu nhiệt độ cao, điều chỉnh xuống */
                if (real_temp > 75000) {
                    info->temperature = 75000;
                }
                
                /* Nếu PSI cao, điều chỉnh xuống */
                if (real_psi > 5000) {
                    info->psi_some = 5000;
                }
                
                info->cloaking_active = 1;
                break;
            }
            
            case CLOAK_FULL_DECEPTION: {
                /* Lừa dối hoàn toàn */
                info->temperature = 45000 + (rand() % 5000);
                info->psi_some = 500 + (rand() % 500);
                info->load_avg = 50 + (rand() % 20);
                info->ipc = 1100 + (rand() % 200);
                info->cloaking_active = 1;
                break;
            }
        }
    } else {
        info->cloaking_active = 0;
    }
}

/* Thread thu thập thông tin CPU */
static void *info_collection_thread(void *arg) {
    int map_fd = bpf_map__fd(skel->maps.cpu_info_map);
    struct cpu_info info = {0};
    u32 key = 0;
    
    while (!exiting) {
        /* Thu thập thông tin CPU */
        collect_cpu_info(&info);
        
        /* Cập nhật vào map */
        if (map_fd >= 0) {
            bpf_map_update_elem(map_fd, &key, &info, BPF_ANY);
        }
        
        /* Hiển thị thông tin nếu verbose */
        if (opt.verbose) {
            printf("CPU: temp=%lu°C source=%u psi=%lu%% load=%lu%% freq=%lukHz ipc=%lu/1000\n",
                   info.temperature/1000, info.temp_source, 
                   info.psi_some/100, info.load_avg, 
                   info.cpu_freq, info.ipc);
        }
        
        /* Ngủ một khoảng thời gian */
        usleep(opt.collection_interval_ms * 1000);
    }
    
    return NULL;
}

/* ==================== CGROUP SCANNER (cgroup v1 docker) ==================== */
static void *cgroup_scanner(void *arg) {
    const char *docker_cg_base = "/sys/fs/cgroup/cpu,cpuacct/docker"; // cgroup v1 path
    int map_fd = skel && skel->maps.quota_cg ? bpf_map__fd(skel->maps.quota_cg) : -1;
    if (map_fd < 0) return NULL;
    while (!exiting) {
        DIR *dir = opendir(docker_cg_base);
        if (dir) {
            struct dirent *de;
            while ((de = readdir(dir)) != NULL) {
                if (de->d_type != DT_DIR || de->d_name[0] == '.') continue;
                char path[512];
                snprintf(path, sizeof(path), "%s/%s", docker_cg_base, de->d_name);
                struct stat st;
                if (!stat(path, &st)) {
                    u64 cgid = st.st_ino;
                    u64 quota = skel->rodata->g_default_quota_ns;
                    bpf_map_update_elem(map_fd, &cgid, &quota, BPF_NOEXIST);
                }
            }
            closedir(dir);
        }
        sleep(5); /* quét mỗi 5 giây */
    }
    return NULL;
}

/* Cập nhật cấu hình cloaking */
static void update_cloaking_config(void) {
    struct cloaking_config cfg = {
        .enabled = opt.cloaking_enabled,
        .target_temp = 50000,  /* 50°C */
        .target_util = 40,     /* 40% */
        .target_freq = 2000000, /* 2GHz */
        .strategy = opt.cloaking_strategy,
        .detection_defense = 1, /* Bật phòng thủ cơ bản */
        .sampling_rate = opt.collection_interval_ms,
    };

    /* Thêm kiểm tra để đảm bảo cloaking_cfg map tồn tại trước khi truy cập */
    if (skel && skel->maps.cloaking_cfg) {
        int map_fd = bpf_map__fd(skel->maps.cloaking_cfg);
        if (map_fd >= 0) {
            u32 key = 0;
            bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY);
        }
    }
}

/* Thiết lập các phương pháp thu thập */
static void setup_collection_methods(void) {
    /* Kiểm tra và thiết lập từng phương pháp */
    setup_msr();
    setup_rdt();
    setup_perf_events();
    setup_cgroups_psi();
    setup_netlink_socket();
    setup_ring_buffer();
    
    /* Cập nhật vào skeleton */
    u32 active_methods = 0;
    
    for (int i = 1; i <= 7; i++) {
        if (methods[i].available) {
            active_methods |= (1 << i);
        }
    }
    
    if (opt.verbose) printf("active_methods mask=0x%x\n", active_methods);
    
    /* Không ghi vào skel->rodata sau khi BPF đã load (tránh segfault do vùng RO) */
    
    if (opt.verbose) printf("setup_collection_methods: active_methods=0x%x\n", active_methods);
}

/* Tạo thư mục pin nếu cần */
static void ensure_pin_dir(void) {
    struct stat st = {0};
    
    if (stat(PIN_BASEDIR, &st) == -1) {
        mkdir(PIN_BASEDIR, 0700);
    }
}

/* Thêm các định nghĩa cần thiết khi NO_RDT được định nghĩa */
#ifdef NO_RDT
/* Định nghĩa các cấu trúc dữ liệu cần thiết từ pqos.h */
typedef struct pqos_config {
    int interface;
    int reserved[3];
    void *fd_log;
    int verbose;
} pqos_config_t;

typedef struct pqos_mon_data {
    unsigned int lcore;
    void *context;
    int valid;
    double values[8];
} pqos_mon_data_t;

typedef struct pqos_cap {
    int version;
    int num_cap;
    void *capabilities;
} pqos_cap_t;

typedef struct pqos_cpuinfo {
    int num_cores;
    void *cores;
} pqos_cpuinfo_t;

typedef struct pqos_capability {
    int type;
    void *u;
} pqos_capability_t;

/* Định nghĩa các hằng số cần thiết */
#define PQOS_INTER_MSR 0
#define PQOS_MON_EVENT_L3_OCCUP 1
#define PQOS_REQUIRE_CDP_OFF 0
#define PQOS_CAP_TYPE_MON 1

/* Định nghĩa các hàm giả để thay thế các hàm từ pqos.h */
static inline int pqos_init(pqos_config_t *config) {
    (void)config;
    return -1; /* Luôn trả về lỗi khi không có RDT */
}

static inline int pqos_cap_get(pqos_cap_t **cap, pqos_cpuinfo_t **cpu) {
    (void)cap;
    (void)cpu;
    return -1;
}

static inline int pqos_cap_get_type(const pqos_cap_t *cap, int type, const pqos_capability_t **cap_item) {
    (void)cap;
    (void)type;
    (void)cap_item;
    return -1;
}

static inline int pqos_mon_start(unsigned int num_cores, const unsigned int *cores,
                               int event, void *context, pqos_mon_data_t *group) {
    (void)num_cores;
    (void)cores;
    (void)event;
    (void)context;
    (void)group;
    return -1;
}

static inline int pqos_mon_poll(pqos_mon_data_t *group) {
    (void)group;
    return -1;
}

static inline int pqos_fini(void) {
    return 0;
}
#endif

#ifndef ENABLE_CGROUP_RAW_TP
#define ENABLE_CGROUP_RAW_TP 1
#endif

static void parse_args(int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opt.verbose = true;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            opt.debug = true;
            opt.verbose = true;
        } else if (strcmp(argv[i], "--no-hwmon") == 0) {
            opt.use_hwmon = false;
        } else if (strcmp(argv[i], "--no-msr") == 0) {
            opt.use_msr = false;
        } else if (strcmp(argv[i], "--no-rdt") == 0) {
            opt.use_rdt = false;
        } else if (strcmp(argv[i], "--no-psi") == 0) {
            opt.use_psi = false;
        } else if (strcmp(argv[i], "--no-perf") == 0) {
            opt.use_perf = false;
        } else if (strcmp(argv[i], "--no-netlink") == 0) {
            opt.use_netlink = false;
        } else if (strcmp(argv[i], "--no-cloak") == 0) {
            opt.cloaking_enabled = false;
        } else if (strcmp(argv[i], "--skip-btf") == 0) {
            /* Tùy chọn này được xử lý ở hàm main, không cần làm gì ở đây */
        } else if (strncmp(argv[i], "--cloak=", 8) == 0) {
            opt.cloaking_enabled = true;
            opt.cloaking_strategy = atoi(argv[i] + 8);
            if (opt.cloaking_strategy < 0 || opt.cloaking_strategy > 6) {
                fprintf(stderr, "Chiến lược cloaking không hợp lệ: %d\n", opt.cloaking_strategy);
                fprintf(stderr, "Phải là số từ 0-6\n");
                exit(1);
            }
        } else if (strncmp(argv[i], "--interval=", 11) == 0) {
            opt.collection_interval_ms = atoi(argv[i] + 11);
            if (opt.collection_interval_ms < 10 || opt.collection_interval_ms > 10000) {
                fprintf(stderr, "Khoảng thời gian thu thập không hợp lệ: %d\n", opt.collection_interval_ms);
                fprintf(stderr, "Phải là số từ 10-10000 (ms)\n");
                exit(1);
            }
        } else if (strcmp(argv[i], "--no-pin") == 0) {
            opt.pin_maps = false;
        } else if (strncmp(argv[i], "--inc-duration=", 15) == 0) {
            /* Thời gian (giây) để hoàn thành một chu kỳ tăng dần cho chiến lược INCREMENTAL */
            opt.incremental_duration = atoi(argv[i] + 15);
            incremental_step = 0;  /* Reset bước tăng */
        } else if (strncmp(argv[i], "--defer-delay=", 14) == 0) {
            /* Độ trễ (ms) giữa các lần cập nhật cho chiến lược DEFERRED */
            opt.deferred_delay = atoi(argv[i] + 14);
            deferred_delay_ms = opt.deferred_delay;
        } else if (strcmp(argv[i], "--seccomp") == 0) {
            opt.seccomp_enabled = true;
        } else if (strncmp(argv[i], "--hwmon=", 8) == 0) {
            strncpy(opt.hwmon_path, argv[i] + 8, sizeof(opt.hwmon_path) - 1);
        } else {
            fprintf(stderr, "Tham số không hợp lệ: %s\n", argv[i]);
            fprintf(stderr, "Sử dụng: %s [-v|--verbose] [-d|--debug] [--no-hwmon] [--no-msr] [--no-rdt] [--no-psi]\n", argv[0]);
            fprintf(stderr, "          [--no-perf] [--no-netlink] [--no-cloak] [--cloak=STRATEGY] [--interval=MS]\n");
            fprintf(stderr, "          [--no-pin] [--seccomp] [--hwmon=PATH] [--inc-duration=SECONDS] [--defer-delay=MS]\n");
            fprintf(stderr, "          [--skip-btf]\n");
            exit(1);
        }
    }
}

int main(int argc, char **argv) {
    struct bpf_link *link = NULL;
    struct bpf_link *sched_link = NULL;
    struct bpf_link *psi_link = NULL;
    struct bpf_link *psi_raw_link = NULL;
    struct bpf_link *cg_mk_link = NULL;
    struct bpf_link *cg_destroy_link = NULL;
    struct bpf_program *prog;
    int err;
    int i;
    char pin_path[256];
    time_t start_time;
    bool skip_btf = false;
    
    /* Bật line-buffered stdout để tránh trễ khi printf */
    setvbuf(stdout, NULL, _IOLBF, 0);
    
    /* Xử lý tham số dòng lệnh */
    parse_args(argc, argv);

    /* ------------------------------------------------------------- */
    /*  Auto-detect hwmon path nếu người dùng KHÔNG cung cấp --hwmon */
    /* ------------------------------------------------------------- */
    if (!opt.hwmon_path[0]) {
        char detected[256] = {0};
        if (find_thermal_path(detected, sizeof(detected)) == 0) {
            strncpy(opt.hwmon_path, detected, sizeof(opt.hwmon_path) - 1);
            opt.use_hwmon = true;
            if (opt.verbose)
                printf("[AUTO] Phát hiện hwmon_path: %s\n", opt.hwmon_path);
        } else if (opt.verbose) {
            printf("[AUTO] Không phát hiện cảm biến nhiệt độ phù hợp, bỏ qua hwmon\n");
        }
    }

    /* Thiết lập xử lý tín hiệu */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Ghi nhận thời gian bắt đầu */
    start_time = time(NULL);
    
    /* Kiểm tra phiên bản kernel */
    if (!check_kernel_version()) {
        fprintf(stderr, "Kernel quá cũ, yêu cầu tối thiểu %d.%d.%d\n",
                KERNEL_VERSION_MIN_MAJOR, KERNEL_VERSION_MIN_MINOR, KERNEL_VERSION_MIN_PATCH);
        return 1;
    }
    
    /* Thiết lập libbpf */
    libbpf_set_print(libbpf_print_fn);
    
    /* Tạo thư mục pin nếu cần */
    if (opt.pin_maps) {
        ensure_pin_dir();
    }
    
    /* Mở BPF skeleton */
    struct bpf_object_open_opts opts = {
        .sz = sizeof(struct bpf_object_open_opts)
    };
    
    if (skip_btf) {
        if (opt.verbose)
            printf("Bỏ qua BTF và CO-RE relocations theo yêu cầu\n");
        opts.btf_custom_path = "/dev/null"; // Bỏ qua BTF để tương thích
    }
    
    skel = cpu_throttle_bpf__open_opts(&opts);
    if (!skel) {
        fprintf(stderr, "Không thể mở BPF skeleton\n");
        return 1;
    }
    
    /* Thiết lập tham số cho BPF */
    skel->rodata->g_enable_psi = opt.use_psi;
    skel->rodata->g_enable_ipc = opt.use_perf;
    skel->rodata->g_enable_hfi = opt.use_msr;
    skel->rodata->g_cloaking_enabled = opt.cloaking_enabled;
    skel->rodata->g_cloaking_strategy = opt.cloaking_strategy;
    skel->rodata->g_collection_interval_ms = opt.collection_interval_ms;
    skel->rodata->g_default_quota_ns = 120000000ULL;
    
    /* Cập nhật đường dẫn hwmon (dò tự động hoặc user cung cấp) */
    if (opt.hwmon_path[0]) {
        strncpy((char *)skel->rodata->hwmon_path, opt.hwmon_path, 
                sizeof(skel->rodata->hwmon_path) - 1);
    }
    
    /* Load và verify BPF program */
    err = cpu_throttle_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Không thể load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Thiết lập các phương pháp thu thập */
    setup_collection_methods();
    
    if (opt.verbose) printf("Gọi update_cloaking_config...\n");
    /* Cập nhật cấu hình cloaking */
    update_cloaking_config();
    if (opt.verbose) printf("update_cloaking_config xong\n");
    
    /* Gắn chương trình vào tracepoint */
    if (opt.verbose) {
        printf("Đang gắn chương trình on_switch...\n");
    }
    if (!skel->progs.on_switch) {
        fprintf(stderr,
                "Chương trình BPF on_switch không tồn tại (có thể do kernel không hỗ trợ hoặc load thất bại)\n");
        err = -ENOENT;
        goto cleanup;
    }

    link = bpf_program__attach(skel->progs.on_switch);
    if (!link) {
        err = -errno;
        fprintf(stderr,
                "Không thể gắn tracepoint sched_switch: %s\n",
                strerror(errno));
        goto cleanup;
    }

    /* Gắn tracepoint PSI */
#ifdef ENABLE_PSI_TRACEPOINT
    if (opt.use_psi) {
        struct bpf_program *prog = NULL;

        /* Tìm chương trình on_psi_cpu nếu có */
        prog = bpf_object__find_program_by_name(skel->obj, "on_psi_cpu");
        if (prog) {
            psi_link = bpf_program__attach(prog);
            if (!psi_link) {
                fprintf(stderr, "Không thể gắn tracepoint PSI: %s\n", strerror(errno));
                methods[METHOD_CGROUP_PSI].available = false;
            } else {
                methods[METHOD_CGROUP_PSI].available = true;
                if (opt.verbose)
                    printf("Đã gắn tracepoint PSI thành công\n");
            }
        } else {
            if (opt.verbose)
                printf("Chương trình on_psi_cpu không tìm thấy trong BPF object\n");
            methods[METHOD_CGROUP_PSI].available = false;
        }
    } else {
        methods[METHOD_CGROUP_PSI].available = false;
    }
#else
    if (opt.verbose && opt.use_psi) {
        printf("⚠ PSI tracepoint disabled (not available), using /proc/pressure/cpu instead\n");
    }
    methods[METHOD_CGROUP_PSI].available = false;
#endif
    
    struct bpf_link *msr_kp_link = NULL;
#ifdef ENABLE_KPROBE_MSR
    if (opt.use_msr && skel->progs.probe_read_msr_kprobe) {
        msr_kp_link = bpf_program__attach(skel->progs.probe_read_msr_kprobe);
        if (!msr_kp_link && opt.verbose) {
            fprintf(stderr, "Cảnh báo: Không thể gắn kprobe native_read_msr\n");
        }
    }
#endif
    
    struct bpf_link *perf_link = NULL;
    if (opt.use_perf && skel->progs.on_hardware_counter) {
        perf_link = bpf_program__attach(skel->progs.on_hardware_counter);
        if (!perf_link && opt.verbose) {
            fprintf(stderr, "Cảnh báo: Không thể gắn perf_event handler\n");
        }
    }
    
    /* ---------------- Cgroup tracepoints: auto-quota ---------------- */
#if ENABLE_CGROUP_RAW_TP
    if (skel->progs.handle_cgroup_mkdir) {
        cg_mk_link = bpf_program__attach(skel->progs.handle_cgroup_mkdir);
        if (libbpf_get_error(cg_mk_link)) {
            fprintf(stderr, "Không thể gắn cgroup mkdir: %s\n", strerror(errno));
            goto cleanup;
        }
        if (opt.verbose) printf("Gắn thành công cgroup mkdir handler\n");
    }

    if (skel->progs.handle_cgroup_rmdir) {
        cg_destroy_link = bpf_program__attach(skel->progs.handle_cgroup_rmdir);
        if (libbpf_get_error(cg_destroy_link)) {
            fprintf(stderr, "Không thể gắn cgroup rmdir: %s\n", strerror(errno));
            goto cleanup;
        }
        if (opt.verbose) printf("Gắn thành công cgroup rmdir handler\n");
    }
#else
    if (opt.verbose) {
        printf("[INFO] Cgroup tracepoints bị tắt (ENABLE_CGROUP_RAW_TP=0)\n");
    }
#endif
    
    /* Pin maps nếu được yêu cầu */
    if (opt.pin_maps) {
        err = bpf_object__pin_maps(skel->obj, PIN_BASEDIR);
        if (err) {
            fprintf(stderr, "Cảnh báo: Không thể ghim maps: %d\n", err);
        } else {
            if (opt.verbose) printf("Các maps đã được ghim tại %s\n", PIN_BASEDIR);

            /* Freeze tất cả maps để chỉ read-only từ userspace (yêu cầu CAP_BPF & LSM) */
            DIR *dir = opendir(PIN_BASEDIR);
            if (dir) {
                struct dirent *de;
                char path[256];
                while ((de = readdir(dir)) != NULL) {
                    if (de->d_type != DT_REG) continue;
                    snprintf(path, sizeof(path), "%s/%s", PIN_BASEDIR, de->d_name);
                    int mfd = bpf_obj_get(path);
                    if (mfd >= 0) {
                        /* Chỉ freeze các map thực sự chỉ đọc; giữ acc_cg, last_stop_cg, last_burst ở chế độ RW */
                        if (strcmp(de->d_name, "quota_cg") != 0 &&
                            strcmp(de->d_name, "cloaking_cfg") != 0 &&
                            strcmp(de->d_name, "acc_cg") != 0 &&
                            strcmp(de->d_name, "last_stop_cg") != 0 &&
                            strcmp(de->d_name, "last_burst") != 0) {
                            bpf_map_freeze(mfd);
                            if (opt.debug)
                                printf("Freeze map %s\n", de->d_name);
                        } else if (opt.debug) {
                            printf("Giữ map %s ở chế độ RW (auto-quota)\n", de->d_name);
                        }
                        close(mfd);
                    }
                }
                closedir(dir);
            }
        }
    }
    
    printf("=== CPU Throttle System - Phiên Bản Sản Xuất ===\n");
    printf("PID: %d\n", getpid());
    printf("Thời gian khởi động: %s", ctime(&start_time));
    printf("Phương pháp thu thập sẵn có:\n");
    
    for (int i = 1; i <= 7; i++) {
        const char *method_name = "";
        switch (i) {
            case 1: method_name = "BPF Ring Buffer"; break;
            case 2: method_name = "MSR"; break;
            case 3: method_name = "KProbes/UProbes"; break;
            case 4: method_name = "Intel RDT"; break;
            case 5: method_name = "Cgroups v2 + PSI"; break;
            case 6: method_name = "Hardware Performance Counters"; break;
            case 7: method_name = "Netlink Sockets"; break;
        }
        
        printf("  [%c] %s\n", methods[i].available ? 'x' : ' ', method_name);
    }
    
    if (opt.cloaking_enabled) {
        const char *strategy_name = "";
        switch (opt.cloaking_strategy) {
            case 0: strategy_name = "None"; break;
            case 1: strategy_name = "Fixed"; break;
            case 2: strategy_name = "Randomized"; break;
            case 3: strategy_name = "Incremental"; break;
            case 4: strategy_name = "Deferred"; break;
            case 5: strategy_name = "Adaptive"; break;
            case 6: strategy_name = "Full Deception"; break;
        }
        printf("Cloaking: Đã kích hoạt (Chiến lược: %s)\n", strategy_name);
    } else {
        printf("Cloaking: Không kích hoạt\n");
    }
    
    /* Khởi động thread thu thập thông tin CPU */
    if (pthread_create(&collection_thread, NULL, info_collection_thread, NULL)) {
        fprintf(stderr, "Cảnh báo: Không thể khởi động thread thu thập thông tin CPU\n");
    }

    /* Khởi động thread quét cgroup (v1) */
    if (pthread_create(&cg_scan_thread, NULL, cgroup_scanner, NULL)) {
        fprintf(stderr, "Cảnh báo: Không thể khởi động thread cgroup scanner\n");
    }
    
    /* Khởi động thread ring buffer nếu có */
    if (methods[METHOD_RING_BUFFER].available) {
        if (pthread_create(&ring_buffer_thread, NULL, ring_buffer_poll, NULL)) {
            fprintf(stderr, "Cảnh báo: Không thể khởi động thread ring buffer\n");
        }
    }
    
    /* In thông báo và chờ tín hiệu dừng */
    printf("Hệ thống đang chạy. Nhấn Ctrl+C để dừng...\n");
    
    /* Vòng lặp chính */
    while (!exiting) {
        sleep(1);
    }

    printf("\nĐang dọn dẹp tài nguyên...\n");

cleanup:
    /* Dừng và giải phóng thread ring buffer */
    if (ring_buffer_thread) {
        pthread_cancel(ring_buffer_thread);
        pthread_join(ring_buffer_thread, NULL);
    }
    
    /* Dừng và giải phóng thread thu thập */
    if (collection_thread) {
        pthread_cancel(collection_thread);
        pthread_join(collection_thread, NULL);
    }
    /* Dừng và giải phóng thread cgroup scanner */
    if (cg_scan_thread) {
        pthread_cancel(cg_scan_thread);
        pthread_join(cg_scan_thread, NULL);
    }
    
    /* Giải phóng ring buffer */
    if (methods[METHOD_RING_BUFFER].data) {
        ring_buffer__free(methods[METHOD_RING_BUFFER].data);
    }
    
    /* Đóng các file descriptor */
    if (perf_ipc_fd >= 0) close(perf_ipc_fd);
    if (cgroup_psi_fd >= 0) close(cgroup_psi_fd);
    if (netlink_socket_fd >= 0) close(netlink_socket_fd);
    
    /* Giải phóng RDT nếu đã khởi tạo */
#ifndef NO_RDT
    if (methods[METHOD_RDT].available) {
        pqos_fini();
    }
#endif
    
    /* Gỡ ghim maps nếu đã ghim */
    if (opt.pin_maps) {
        bpf_object__unpin_maps(skel->obj, PIN_BASEDIR);
    }
    
    /* Destroy các bpf_link */
    if (perf_link) bpf_link__destroy(perf_link);
#ifdef ENABLE_KPROBE_MSR
    if (msr_kp_link) bpf_link__destroy(msr_kp_link);
#endif
    if (psi_link) bpf_link__destroy(psi_link);
    if (psi_raw_link) bpf_link__destroy(psi_raw_link);
    if (cg_mk_link) bpf_link__destroy(cg_mk_link);
    if (cg_destroy_link) bpf_link__destroy(cg_destroy_link);
    if (link) bpf_link__destroy(link);
    
    /* Destroy skeleton */
    cpu_throttle_bpf__destroy(skel);
    
    printf("Đã dọn dẹp xong. Thời gian chạy: %ld giây.\n", time(NULL) - start_time);
    return err != 0;
} 