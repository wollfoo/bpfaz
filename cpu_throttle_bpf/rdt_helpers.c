/*
 * rdt_helpers.c - Triển khai các hàm hỗ trợ cho Intel RDT
 * 
 * Intel RDT (Resource Director Technology) cung cấp khả năng giám sát và
 * kiểm soát tài nguyên cache L3, bộ nhớ và băng thông cho các ứng dụng.
 * 
 * Thư viện này cung cấp một lớp trừu tượng trên giao diện sysfs của RDT.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "rdt_helpers.h"

#ifdef HAS_RDT

/* Định nghĩa đường dẫn */
#define RDT_SYSFS_PATH           "/sys/fs/resctrl"
#define RDT_INFO_PATH            RDT_SYSFS_PATH "/info"
#define RDT_MON_DATA_PATH        RDT_SYSFS_PATH "/%s/mon_data"
#define RDT_MON_L3_PATH          RDT_SYSFS_PATH "/%s/mon_data/mon_L3_%u/llc_occupancy"
#define RDT_MON_MBM_PATH         RDT_SYSFS_PATH "/%s/mon_data/mon_L3_%u/mbm_%s"
#define RDT_L3_MASK_PATH         RDT_SYSFS_PATH "/%s/schemata"
#define RDT_MBA_PATH             RDT_SYSFS_PATH "/%s/schemata"
#define RDT_TASKS_PATH           RDT_SYSFS_PATH "/%s/tasks"

/* Cấu trúc dữ liệu nội bộ */
struct rdt_internal_data {
    struct rdt_config config;
    bool initialized;
    struct rdt_cpu_info cpu_info;
};

/* Dữ liệu toàn cục */
static struct rdt_internal_data g_rdt_data = {
    .initialized = false,
    .config = {
        .verbose = false,
        .use_llc_occupancy = true,
        .use_memory_bandwidth = true,
        .use_cat = false,
        .use_mba = false,
        .mba_percent = 100,
        .cat_ways = 0
    },
    .cpu_info = {
        .num_cores = 0,
        .num_sockets = 0,
        .core_to_socket = NULL,
        .socket_to_l3 = NULL
    }
};

/* Hàm trợ giúp để kiểm tra sự tồn tại của tệp/thư mục */
static bool file_exists(const char *path) {
    struct stat st;
    return (stat(path, &st) == 0);
}

/* Hàm đọc giá trị số từ tệp */
static int read_value_from_file(const char *path, uint64_t *value) {
    FILE *f;
    char buf[64];
    int ret = -1;

    f = fopen(path, "r");
    if (!f) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (fgets(buf, sizeof(buf), f) != NULL) {
        *value = strtoull(buf, NULL, 0);
        ret = 0;
    }

    fclose(f);
    return ret;
}

/* Hàm ghi giá trị vào tệp */
static int write_value_to_file(const char *path, const char *value) {
    FILE *f;
    int ret = -1;
    size_t len = strlen(value);

    f = fopen(path, "w");
    if (!f) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to open %s for writing: %s\n", path, strerror(errno));
        return -1;
    }

    if (fwrite(value, 1, len, f) == len)
        ret = 0;

    fclose(f);
    return ret;
}

/* Khởi tạo thông tin CPU */
static int init_cpu_info(void) {
    FILE *f;
    char buf[256];
    unsigned int max_core = 0;
    unsigned int max_socket = 0;

    /* Đọc thông tin CPU từ /proc/cpuinfo */
    f = fopen("/proc/cpuinfo", "r");
    if (!f) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to open /proc/cpuinfo: %s\n", strerror(errno));
        return -1;
    }

    /* Đếm số lõi và socket */
    g_rdt_data.cpu_info.num_cores = 0;
    g_rdt_data.cpu_info.num_sockets = 0;

    while (fgets(buf, sizeof(buf), f)) {
        unsigned int core_id, socket_id;
        
        if (sscanf(buf, "processor : %u", &core_id) == 1) {
            if (core_id > max_core)
                max_core = core_id;
        }
        
        if (sscanf(buf, "physical id : %u", &socket_id) == 1) {
            if (socket_id > max_socket)
                max_socket = socket_id;
        }
    }

    fclose(f);

    /* Số lượng là giá trị lớn nhất + 1 */
    g_rdt_data.cpu_info.num_cores = max_core + 1;
    g_rdt_data.cpu_info.num_sockets = max_socket + 1;

    /* Phân bổ các mảng ánh xạ */
    g_rdt_data.cpu_info.core_to_socket = calloc(g_rdt_data.cpu_info.num_cores, 
                                              sizeof(unsigned int));
    if (!g_rdt_data.cpu_info.core_to_socket) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to allocate memory for core_to_socket mapping\n");
        return -1;
    }

    g_rdt_data.cpu_info.socket_to_l3 = calloc(g_rdt_data.cpu_info.num_sockets, 
                                            sizeof(unsigned int));
    if (!g_rdt_data.cpu_info.socket_to_l3) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to allocate memory for socket_to_l3 mapping\n");
        free(g_rdt_data.cpu_info.core_to_socket);
        g_rdt_data.cpu_info.core_to_socket = NULL;
        return -1;
    }

    /* Đặt lại file pointer và đọc lại để tạo ánh xạ */
    f = fopen("/proc/cpuinfo", "r");
    if (!f) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to reopen /proc/cpuinfo: %s\n", strerror(errno));
        free(g_rdt_data.cpu_info.core_to_socket);
        free(g_rdt_data.cpu_info.socket_to_l3);
        g_rdt_data.cpu_info.core_to_socket = NULL;
        g_rdt_data.cpu_info.socket_to_l3 = NULL;
        return -1;
    }

    unsigned int current_cpu = 0;
    while (fgets(buf, sizeof(buf), f)) {
        unsigned int socket_id;
        
        if (strncmp(buf, "processor", 9) == 0)
            sscanf(buf, "processor : %u", &current_cpu);
        
        if (strncmp(buf, "physical id", 11) == 0) {
            sscanf(buf, "physical id : %u", &socket_id);
            if (current_cpu < g_rdt_data.cpu_info.num_cores)
                g_rdt_data.cpu_info.core_to_socket[current_cpu] = socket_id;
        }
    }

    fclose(f);

    /* Giả định socket ID là L3 ID - Điều này đúng cho hầu hết các hệ thống */
    for (unsigned int i = 0; i < g_rdt_data.cpu_info.num_sockets; i++)
        g_rdt_data.cpu_info.socket_to_l3[i] = i;

    return 0;
}

/* Kiểm tra xem RDT có khả dụng không */
bool rdt_is_available(void) {
    return file_exists(RDT_SYSFS_PATH);
}

/* Khởi tạo thư viện RDT */
int rdt_init(struct rdt_config *config) {
    if (g_rdt_data.initialized)
        return 0;  /* Đã khởi tạo rồi */

    /* Kiểm tra xem RDT có khả dụng trên hệ thống */
    if (!rdt_is_available()) {
        return -1;
    }

    /* Khởi tạo cấu hình */
    if (config)
        memcpy(&g_rdt_data.config, config, sizeof(struct rdt_config));

    /* Khởi tạo thông tin CPU */
    if (init_cpu_info() < 0) {
        return -1;
    }

    g_rdt_data.initialized = true;
    return 0;
}

/* Giải phóng tài nguyên RDT */
void rdt_fini(void) {
    if (!g_rdt_data.initialized)
        return;

    free(g_rdt_data.cpu_info.core_to_socket);
    free(g_rdt_data.cpu_info.socket_to_l3);
    g_rdt_data.cpu_info.core_to_socket = NULL;
    g_rdt_data.cpu_info.socket_to_l3 = NULL;

    g_rdt_data.initialized = false;
}

/* Lấy thông tin CPU */
int rdt_get_cpu_info(struct rdt_cpu_info *cpu_info) {
    if (!g_rdt_data.initialized)
        return -1;

    if (!cpu_info)
        return -1;

    cpu_info->num_cores = g_rdt_data.cpu_info.num_cores;
    cpu_info->num_sockets = g_rdt_data.cpu_info.num_sockets;
    cpu_info->core_to_socket = g_rdt_data.cpu_info.core_to_socket;
    cpu_info->socket_to_l3 = g_rdt_data.cpu_info.socket_to_l3;

    return 0;
}

/* Bắt đầu giám sát một lõi CPU */
int rdt_monitor_core(unsigned int core_id, struct rdt_monitor_data *mon_data) {
    char group_name[64];
    char path[256];
    char buf[256];

    if (!g_rdt_data.initialized || !mon_data)
        return -1;

    if (core_id >= g_rdt_data.cpu_info.num_cores) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Invalid core ID: %u\n", core_id);
        return -1;
    }

    /* Khởi tạo dữ liệu giám sát */
    mon_data->core_id = core_id;
    mon_data->pid = 0;
    mon_data->mon_data = NULL;

    /* Lấy socket ID và L3 ID từ core ID */
    unsigned int socket_id = g_rdt_data.cpu_info.core_to_socket[core_id];
    unsigned int l3_id = g_rdt_data.cpu_info.socket_to_l3[socket_id];

    mon_data->cache.socket_id = socket_id;
    mon_data->cache.l3_id = l3_id;
    mon_data->cache.class_id = 0;  /* Mặc định là root group */

    /* Tạo một tên nhóm giám sát duy nhất */
    snprintf(group_name, sizeof(group_name), "core%u_mon", core_id);

    /* Tạo thư mục cho nhóm */
    snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s", group_name);
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to create monitoring group: %s\n", strerror(errno));
        return -1;
    }

    /* Thêm CPU vào nhóm */
    snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s/cpus", group_name);
    snprintf(buf, sizeof(buf), "%u", core_id);
    if (write_value_to_file(path, buf) < 0) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to assign CPU to monitoring group\n");
        return -1;
    }

    /* Lưu tên nhóm vào dữ liệu giám sát */
    mon_data->mon_data = strdup(group_name);
    if (!mon_data->mon_data) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to allocate memory for monitor data\n");
        return -1;
    }

    return 0;
}

/* Bắt đầu giám sát một PID */
int rdt_monitor_pid(unsigned int pid, struct rdt_monitor_data *mon_data) {
    char group_name[64];
    char path[256];
    char buf[256];

    if (!g_rdt_data.initialized || !mon_data)
        return -1;

    /* Kiểm tra PID */
    if (pid == 0) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Invalid PID: 0\n");
        return -1;
    }

    /* Khởi tạo dữ liệu giám sát */
    mon_data->core_id = 0;  /* Không áp dụng khi giám sát PID */
    mon_data->pid = pid;
    mon_data->mon_data = NULL;

    /* Sử dụng socket 0 và L3 0 làm mặc định */
    mon_data->cache.socket_id = 0;
    mon_data->cache.l3_id = 0;
    mon_data->cache.class_id = 0;  /* Mặc định là root group */

    /* Tạo một tên nhóm giám sát duy nhất */
    snprintf(group_name, sizeof(group_name), "pid%u_mon", pid);

    /* Tạo thư mục cho nhóm */
    snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s", group_name);
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to create monitoring group: %s\n", strerror(errno));
        return -1;
    }

    /* Thêm PID vào nhóm */
    snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s/tasks", group_name);
    snprintf(buf, sizeof(buf), "%u", pid);
    if (write_value_to_file(path, buf) < 0) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to assign PID to monitoring group\n");
        return -1;
    }

    /* Lưu tên nhóm vào dữ liệu giám sát */
    mon_data->mon_data = strdup(group_name);
    if (!mon_data->mon_data) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to allocate memory for monitor data\n");
        return -1;
    }

    return 0;
}

/* Cập nhật dữ liệu giám sát */
int rdt_update_monitor(struct rdt_monitor_data *mon_data) {
    char path[256];
    uint64_t value;

    if (!g_rdt_data.initialized || !mon_data || !mon_data->mon_data)
        return -1;

    /* Lấy tên nhóm */
    const char *group_name = (const char *)mon_data->mon_data;

    /* Đọc LLC occupancy */
    if (g_rdt_data.config.use_llc_occupancy) {
        snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s/mon_data/mon_L3_%u/llc_occupancy",
                 group_name, mon_data->cache.l3_id);
        if (read_value_from_file(path, &value) == 0)
            mon_data->cache.llc_occupancy = value;
    }

    /* Đọc thông tin băng thông bộ nhớ */
    if (g_rdt_data.config.use_memory_bandwidth) {
        /* Băng thông local */
        snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s/mon_data/mon_L3_%u/mbm_local_bytes",
                 group_name, mon_data->cache.l3_id);
        if (read_value_from_file(path, &value) == 0)
            mon_data->cache.mbm_local = value;

        /* Tổng băng thông */
        snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s/mon_data/mon_L3_%u/mbm_total_bytes",
                 group_name, mon_data->cache.l3_id);
        if (read_value_from_file(path, &value) == 0)
            mon_data->cache.mbm_total = value;

        /* Tính băng thông remote */
        mon_data->cache.mbm_remote = mon_data->cache.mbm_total - mon_data->cache.mbm_local;
    }

    return 0;
}

/* Dừng giám sát */
int rdt_stop_monitor(struct rdt_monitor_data *mon_data) {
    char path[256];

    if (!g_rdt_data.initialized || !mon_data || !mon_data->mon_data)
        return -1;

    /* Lấy tên nhóm */
    const char *group_name = (const char *)mon_data->mon_data;

    /* Xóa thư mục nhóm */
    snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s", group_name);
    if (rmdir(path) < 0 && errno != ENOENT) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to remove monitoring group: %s\n", strerror(errno));
        return -1;
    }

    /* Giải phóng bộ nhớ */
    free(mon_data->mon_data);
    mon_data->mon_data = NULL;

    return 0;
}

/* Đặt cấu hình CAT */
int rdt_set_cat_config(unsigned int l3_id, unsigned int class_id, uint64_t mask) {
    char path[256];
    char buf[256];
    char group_name[64];

    if (!g_rdt_data.initialized)
        return -1;

    /* Kiểm tra xem CAT có khả dụng không */
    if (!file_exists(RDT_INFO_PATH "/L3_CAT"))
        return -1;

    /* Xác định tên nhóm dựa trên class_id */
    if (class_id == 0)
        strcpy(group_name, "");  /* Root group */
    else
        snprintf(group_name, sizeof(group_name), "class%u", class_id);

    /* Tạo thư mục cho lớp nếu chưa tồn tại */
    if (class_id > 0) {
        snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s", group_name);
        if (mkdir(path, 0755) < 0 && errno != EEXIST) {
            if (g_rdt_data.config.verbose)
                fprintf(stderr, "Failed to create class directory: %s\n", strerror(errno));
            return -1;
        }
    }

    /* Định dạng schemata */
    snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s/schemata", group_name);
    snprintf(buf, sizeof(buf), "L3:%u=%lx", l3_id, mask);

    /* Ghi vào schemata */
    if (write_value_to_file(path, buf) < 0) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to write CAT configuration\n");
        return -1;
    }

    return 0;
}

/* Đặt cấu hình MBA */
int rdt_set_mba_config(unsigned int l3_id, unsigned int class_id, unsigned int mb_percent) {
    char path[256];
    char buf[256];
    char group_name[64];

    if (!g_rdt_data.initialized)
        return -1;

    /* Kiểm tra xem MBA có khả dụng không */
    if (!file_exists(RDT_INFO_PATH "/MB"))
        return -1;

    /* Giới hạn phần trăm */
    if (mb_percent > 100)
        mb_percent = 100;
    if (mb_percent < 1)
        mb_percent = 1;

    /* Xác định tên nhóm dựa trên class_id */
    if (class_id == 0)
        strcpy(group_name, "");  /* Root group */
    else
        snprintf(group_name, sizeof(group_name), "class%u", class_id);

    /* Tạo thư mục cho lớp nếu chưa tồn tại */
    if (class_id > 0) {
        snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s", group_name);
        if (mkdir(path, 0755) < 0 && errno != EEXIST) {
            if (g_rdt_data.config.verbose)
                fprintf(stderr, "Failed to create class directory: %s\n", strerror(errno));
            return -1;
        }
    }

    /* Định dạng schemata */
    snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s/schemata", group_name);
    snprintf(buf, sizeof(buf), "MB:%u=%u", l3_id, mb_percent);

    /* Ghi vào schemata */
    if (write_value_to_file(path, buf) < 0) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to write MBA configuration\n");
        return -1;
    }

    return 0;
}

/* Gán một PID vào lớp RDT */
int rdt_assign_pid(unsigned int pid, unsigned int class_id) {
    char path[256];
    char buf[256];
    char group_name[64];

    if (!g_rdt_data.initialized)
        return -1;

    /* Kiểm tra PID */
    if (pid == 0) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Invalid PID: 0\n");
        return -1;
    }

    /* Xác định tên nhóm dựa trên class_id */
    if (class_id == 0)
        strcpy(group_name, "");  /* Root group */
    else
        snprintf(group_name, sizeof(group_name), "class%u", class_id);

    /* Kiểm tra xem nhóm có tồn tại không */
    snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s", group_name);
    if (!file_exists(path) && class_id > 0) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Class does not exist: %u\n", class_id);
        return -1;
    }

    /* Thêm PID vào nhóm */
    snprintf(path, sizeof(path), RDT_SYSFS_PATH "/%s/tasks", group_name);
    snprintf(buf, sizeof(buf), "%u", pid);
    if (write_value_to_file(path, buf) < 0) {
        if (g_rdt_data.config.verbose)
            fprintf(stderr, "Failed to assign PID to class\n");
        return -1;
    }

    return 0;
}

/* Lấy thông tin về khả năng RDT của hệ thống */
int rdt_get_capabilities(bool *has_cmt, bool *has_cat, bool *has_mba) {
    if (!g_rdt_data.initialized)
        return -1;

    if (has_cmt)
        *has_cmt = file_exists(RDT_INFO_PATH "/L3_MON");

    if (has_cat)
        *has_cat = file_exists(RDT_INFO_PATH "/L3_CAT");

    if (has_mba)
        *has_mba = file_exists(RDT_INFO_PATH "/MB");

    return 0;
}

#endif /* HAS_RDT */ 