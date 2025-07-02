/* SPDX-License-Identifier: GPL-2.0
 * prometheus_exporter.c - Prometheus metrics exporter cho blk_io_mask_bpf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include <getopt.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <sys/stat.h>

#include "include/blk_io_mask_common.h"

#define BPF_FS_PATH "/sys/fs/bpf"
#define PROMETHEUS_PORT 9923
#define METRIC_PREFIX "blk_io_mask"
#define DEFAULT_TOKEN_FILE "/etc/blk_io_mask/auth_token"
#define DEFAULT_TOKEN "blk_io_mask_default_token" /* Chỉ dùng nếu không có token file */
#define AUTH_HEADER_PREFIX "Authorization: Bearer "

static volatile sig_atomic_t exiting;
static char auth_token[256] = {0};

/* Cấu trúc lưu trữ thông tin metric */
struct metric {
    char *name;         // Tên metric
    char *help;         // Mô tả metric
    char *type;         // Kiểu metric (counter, gauge)
    int map_fd;         // File descriptor của map BPF
    int is_map_array;   // Có phải là map array?
    char *(*format_cb)(void *key, void *val, char *buf, size_t size); // Callback định dạng metric
};

/* Danh sách các metrics hỗ trợ */
static struct metric metrics[] = {
    {
        .name = METRIC_PREFIX "_masked_bytes_total",
        .help = "Tổng số bytes đã che giấu theo thiết bị",
        .type = "counter",
        .is_map_array = 0,
        // format_cb được điền sau
    },
    {
        .name = METRIC_PREFIX "_read_bytes_total",
        .help = "Tổng số bytes đọc theo thiết bị",
        .type = "counter",
        .is_map_array = 0,
        // format_cb được điền sau
    },
    {
        .name = METRIC_PREFIX "_write_bytes_total",
        .help = "Tổng số bytes ghi theo thiết bị",
        .type = "counter",
        .is_map_array = 0,
        // format_cb được điền sau
    },
    {
        .name = METRIC_PREFIX "_latency_seconds",
        .help = "Độ trễ trung bình của hoạt động I/O theo thiết bị",
        .type = "gauge",
        .is_map_array = 0,
        // format_cb được điền sau
    },
    {
        .name = METRIC_PREFIX "_mask_ratio",
        .help = "Tỷ lệ che giấu hiện tại",
        .type = "gauge",
        .is_map_array = 1,
        // format_cb được điền sau
    },
    {
        .name = METRIC_PREFIX "_enabled",
        .help = "Trạng thái bật/tắt chức năng che giấu",
        .type = "gauge",
        .is_map_array = 1,
        // format_cb được điền sau
    },
    // Thêm metrics khác nếu cần
};
#define NUM_METRICS (sizeof(metrics) / sizeof(metrics[0]))

/* Đọc token từ file */
static int load_auth_token(const char *token_file) {
    FILE *fp;
    struct stat st;
    char token_buf[256] = {0};
    size_t len;
    
    /* Kiểm tra nếu file tồn tại */
    if (stat(token_file, &st) != 0) {
        fprintf(stderr, "Cảnh báo: Không thể đọc token file %s: %s\n", 
                token_file, strerror(errno));
        fprintf(stderr, "Sử dụng token mặc định (KHÔNG AN TOÀN CHO MÔI TRƯỜNG PRODUCTION)\n");
        strcpy(auth_token, DEFAULT_TOKEN);
        return 0;
    }
    
    /* Kiểm tra quyền truy cập file */
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        fprintf(stderr, "Lỗi: Quyền file %s quá rộng (0%o), phải chỉ cho phép chủ sở hữu đọc/ghi\n", 
                token_file, st.st_mode & 0777);
        return -1;
    }
    
    /* Mở file token */
    fp = fopen(token_file, "r");
    if (!fp) {
        fprintf(stderr, "Lỗi: Không thể mở token file %s: %s\n", 
                token_file, strerror(errno));
        return -1;
    }
    
    /* Đọc token */
    if (fgets(token_buf, sizeof(token_buf), fp) == NULL) {
        fprintf(stderr, "Lỗi: Không thể đọc token từ %s\n", token_file);
        fclose(fp);
        return -1;
    }
    
    /* Cắt bỏ newline nếu có */
    len = strlen(token_buf);
    if (len > 0 && token_buf[len-1] == '\n') {
        token_buf[len-1] = '\0';
    }
    
    /* Kiểm tra token hợp lệ */
    if (strlen(token_buf) < 16) {
        fprintf(stderr, "Lỗi: Token quá ngắn (ít nhất 16 ký tự)\n");
        fclose(fp);
        return -1;
    }
    
    strcpy(auth_token, token_buf);
    fclose(fp);
    
    printf("Đã tải token xác thực từ %s\n", token_file);
    return 0;
}

/* Tạo token file mặc định nếu không tồn tại */
static int create_default_token_file(const char *token_file) {
    FILE *fp;
    char token_dir[256];
    char *dir_end;
    
    /* Tạo thư mục cha nếu cần */
    strncpy(token_dir, token_file, sizeof(token_dir));
    dir_end = strrchr(token_dir, '/');
    if (dir_end) {
        *dir_end = '\0';
        if (mkdir(token_dir, 0755) != 0 && errno != EEXIST) {
            fprintf(stderr, "Lỗi: Không thể tạo thư mục %s: %s\n", 
                    token_dir, strerror(errno));
            return -1;
        }
    }
    
    /* Kiểm tra xem file đã tồn tại chưa */
    if (access(token_file, F_OK) == 0) {
        return 0; /* File đã tồn tại */
    }
    
    /* Tạo token file */
    fp = fopen(token_file, "w");
    if (!fp) {
        fprintf(stderr, "Lỗi: Không thể tạo token file %s: %s\n", 
                token_file, strerror(errno));
        return -1;
    }
    
    /* Tạo token ngẫu nhiên */
    unsigned char rand_bytes[32];
    FILE *urandom = fopen("/dev/urandom", "r");
    if (!urandom) {
        fprintf(stderr, "Lỗi: Không thể mở /dev/urandom: %s\n", strerror(errno));
        fclose(fp);
        return -1;
    }
    
    if (fread(rand_bytes, 1, sizeof(rand_bytes), urandom) != sizeof(rand_bytes)) {
        fprintf(stderr, "Lỗi: Không thể đọc dữ liệu ngẫu nhiên\n");
        fclose(urandom);
        fclose(fp);
        return -1;
    }
    fclose(urandom);
    
    /* Chuyển đổi bytes ngẫu nhiên thành chuỗi hex */
    char token_hex[65] = {0};
    for (int i = 0; i < 32; i++) {
        sprintf(token_hex + i*2, "%02x", rand_bytes[i]);
    }
    
    /* Ghi token vào file */
    fprintf(fp, "%s\n", token_hex);
    fclose(fp);
    
    /* Thiết lập quyền truy cập hạn chế */
    if (chmod(token_file, 0600) != 0) {
        fprintf(stderr, "Lỗi: Không thể thiết lập quyền cho %s: %s\n", 
                token_file, strerror(errno));
        return -1;
    }
    
    printf("Đã tạo token file %s với token ngẫu nhiên\n", token_file);
    return 0;
}

/* Xác thực token từ header Authorization */
static int authenticate_request(const char *request) {
    const char *auth_header = strstr(request, AUTH_HEADER_PREFIX);
    if (!auth_header) {
        return 0; /* Không có header xác thực */
    }
    
    /* Trích xuất token từ header */
    const char *token_start = auth_header + strlen(AUTH_HEADER_PREFIX);
    char token[256] = {0};
    
    /* Tìm điểm kết thúc của token (newline hoặc \r) */
    const char *token_end = strpbrk(token_start, "\r\n");
    if (!token_end) {
        return 0; /* Header không hợp lệ */
    }
    
    /* Sao chép token */
    size_t token_len = token_end - token_start;
    if (token_len >= sizeof(token)) {
        return 0; /* Token quá dài */
    }
    strncpy(token, token_start, token_len);
    token[token_len] = '\0';
    
    /* So sánh với token đã được tải */
    return (strcmp(token, auth_token) == 0);
}

/* Hàm định dạng metrics cho dev_stats */
static char *format_dev_stats(void *key, void *val, char *buf, size_t size)
{
    u64 *dev_id = (u64 *)key;
    struct io_device_stat *stat = (struct io_device_stat *)val;
    
    if (!dev_id || !stat)
        return NULL;
    
    unsigned int major = *dev_id >> 20;
    unsigned int minor = *dev_id & 0xFFFFF;
    
    // Format metric với labels device="major:minor"
    snprintf(buf, size, "device=\"%u:%u\"", major, minor);
    return buf;
}

/* Hàm định dạng metrics cho masked_bytes_total */
static char *format_masked_bytes(void *key, void *val, char *buf, size_t size)
{
    struct io_device_stat *stat = (struct io_device_stat *)val;
    snprintf(buf, size, " %lu", stat->masked_bytes);
    return buf;
}

/* Hàm định dạng metrics cho read_bytes_total */
static char *format_read_bytes(void *key, void *val, char *buf, size_t size)
{
    struct io_device_stat *stat = (struct io_device_stat *)val;
    snprintf(buf, size, " %lu", stat->read_bytes);
    return buf;
}

/* Hàm định dạng metrics cho write_bytes_total */
static char *format_write_bytes(void *key, void *val, char *buf, size_t size)
{
    struct io_device_stat *stat = (struct io_device_stat *)val;
    snprintf(buf, size, " %lu", stat->write_bytes);
    return buf;
}

/* Hàm định dạng metrics cho latency_seconds */
static char *format_latency(void *key, void *val, char *buf, size_t size)
{
    struct io_device_stat *stat = (struct io_device_stat *)val;
    double latency_sec = 0.0;
    if (stat->count > 0) {
        latency_sec = (double)stat->latency_sum_ns / (stat->count * 1e9);
    }
    snprintf(buf, size, " %f", latency_sec);
    return buf;
}

/* Hàm định dạng metrics cho cfg_map (mask_ratio) */
static char *format_mask_ratio(void *key, void *val, char *buf, size_t size)
{
    struct blk_mask_cfg *cfg = (struct blk_mask_cfg *)val;
    snprintf(buf, size, " %u", cfg->mask_ratio);
    return buf;
}

/* Hàm định dạng metrics cho cfg_map (enabled) */
static char *format_enabled(void *key, void *val, char *buf, size_t size)
{
    struct blk_mask_cfg *cfg = (struct blk_mask_cfg *)val;
    snprintf(buf, size, " %u", cfg->enabled);
    return buf;
}

/* Xử lý tín hiệu để thoát */
static void sig_handler(int sig)
{
    exiting = 1;
}

/* Tạo HTTP response với metrics */
static void generate_metrics(int client_fd)
{
    char buf[4096];
    char label_buf[512];
    char val_buf[256];
    int i, ret;
    
    // Header HTTP
    const char *http_header = "HTTP/1.1 200 OK\r\n"
                             "Content-Type: text/plain\r\n"
                             "Connection: close\r\n\r\n";
    write(client_fd, http_header, strlen(http_header));
    
    // Duyệt qua từng metric
    for (i = 0; i < NUM_METRICS; i++) {
        struct metric *m = &metrics[i];
        
        // Bỏ qua metric không có map_fd
        if (m->map_fd <= 0)
            continue;
        
        // In tiêu đề metric
        snprintf(buf, sizeof(buf), "# HELP %s %s\n# TYPE %s %s\n", 
                m->name, m->help, m->name, m->type);
        write(client_fd, buf, strlen(buf));
        
        if (m->is_map_array) {
            // Xử lý map kiểu array
            uint32_t key = 0;
            struct blk_mask_cfg cfg;
            
            if (bpf_map_lookup_elem(m->map_fd, &key, &cfg) == 0) {
                if (m->format_cb) {
                    m->format_cb(&key, &cfg, val_buf, sizeof(val_buf));
                    snprintf(buf, sizeof(buf), "%s%s\n", m->name, val_buf);
                    write(client_fd, buf, strlen(buf));
                }
            }
        } else {
            // Xử lý map kiểu hash
            uint64_t prev_key = 0, key;
            struct io_device_stat val;
            
            while (bpf_map_get_next_key(m->map_fd, &prev_key, &key) == 0) {
                if (bpf_map_lookup_elem(m->map_fd, &key, &val) == 0) {
                    if (format_dev_stats(&key, &val, label_buf, sizeof(label_buf)) &&
                        m->format_cb && m->format_cb(&key, &val, val_buf, sizeof(val_buf))) {
                        snprintf(buf, sizeof(buf), "%s{%s}%s\n", 
                                m->name, label_buf, val_buf);
                        write(client_fd, buf, strlen(buf));
                    }
                }
                prev_key = key;
            }
        }
    }
}

/* Trả về lỗi 401 Unauthorized */
static void send_unauthorized_response(int client_fd)
{
    const char *unauthorized = "HTTP/1.1 401 Unauthorized\r\n"
                               "Content-Type: text/plain\r\n"
                               "WWW-Authenticate: Bearer\r\n"
                               "Connection: close\r\n\r\n"
                               "Unauthorized: Authentication required\n";
    write(client_fd, unauthorized, strlen(unauthorized));
}

/* Thread xử lý kết nối HTTP */
static void *http_server_thread(void *arg)
{
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;
    
    // Tạo socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Không thể tạo socket");
        return NULL;
    }
    
    // Thiết lập socket
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return NULL;
    }
    
    // Thiết lập địa chỉ
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PROMETHEUS_PORT);
    
    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return NULL;
    }
    
    // Listen
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return NULL;
    }
    
    printf("Prometheus exporter đang lắng nghe trên cổng %d\n", PROMETHEUS_PORT);
    
    // Vòng lặp chấp nhận kết nối
    while (!exiting) {
        // Accept kết nối với timeout
        fd_set readfds;
        struct timeval tv;
        
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        
        tv.tv_sec = 1;  // timeout 1 giây
        tv.tv_usec = 0;
        
        int ready = select(server_fd + 1, &readfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        } else if (ready == 0) {
            // Timeout, kiểm tra cờ exiting
            continue;
        }
        
        // Accept kết nối
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        
        // Xử lý request HTTP
        char request[1024];
        ssize_t n = read(client_fd, request, sizeof(request) - 1);
        if (n > 0) {
            request[n] = '\0';
            
            // Kiểm tra nếu là GET /metrics
            if (strstr(request, "GET /metrics") != NULL) {
                // Xác thực token
                if (authenticate_request(request) || strlen(auth_token) == 0) {
                    generate_metrics(client_fd);
                } else {
                    send_unauthorized_response(client_fd);
                }
            } else {
                // Trả về 404 cho các request khác
                const char *not_found = "HTTP/1.1 404 Not Found\r\n"
                                       "Content-Type: text/plain\r\n"
                                       "Connection: close\r\n\r\n"
                                       "404 Not Found\n";
                write(client_fd, not_found, strlen(not_found));
            }
        }
        
        close(client_fd);
    }
    
    close(server_fd);
    return NULL;
}

/* Hiển thị trợ giúp */
static void print_help(const char *prog) {
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -p, --port PORT       Thiết lập cổng HTTP (mặc định: %d)\n", PROMETHEUS_PORT);
    printf("  -t, --token-file FILE Đường dẫn đến token file (mặc định: %s)\n", DEFAULT_TOKEN_FILE);
    printf("  -c, --create-token    Tạo token file mới nếu không tồn tại\n");
    printf("  -h, --help            Hiển thị trợ giúp này\n");
}

int main(int argc, char **argv)
{
    pthread_t http_thread;
    char token_file[256] = DEFAULT_TOKEN_FILE;
    int port = PROMETHEUS_PORT;
    bool create_token = false;
    int c;
    
    struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"token-file", required_argument, 0, 't'},
        {"create-token", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    /* Xử lý tham số dòng lệnh */
    while ((c = getopt_long(argc, argv, "p:t:ch", long_options, NULL)) != -1) {
        switch (c) {
        case 'p':
            port = atoi(optarg);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Lỗi: Cổng không hợp lệ: %s\n", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 't':
            strncpy(token_file, optarg, sizeof(token_file) - 1);
            token_file[sizeof(token_file) - 1] = '\0';
            break;
        case 'c':
            create_token = true;
            break;
        case 'h':
            print_help(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_help(argv[0]);
            return EXIT_FAILURE;
        }
    }
    
    /* Tạo token file nếu cần */
    if (create_token) {
        if (create_default_token_file(token_file) < 0) {
            return EXIT_FAILURE;
        }
    }
    
    /* Tải token xác thực */
    if (load_auth_token(token_file) < 0) {
        fprintf(stderr, "Cảnh báo: Không thể tải token xác thực, tiếp tục mà không có xác thực\n");
    }
    
    // Khởi tạo mảng metrics
    metrics[0].format_cb = format_masked_bytes;
    metrics[1].format_cb = format_read_bytes;
    metrics[2].format_cb = format_write_bytes;
    metrics[3].format_cb = format_latency;
    metrics[4].format_cb = format_mask_ratio;
    metrics[5].format_cb = format_enabled;
    
    // Mở các map BPF với API hiện đại
    struct bpf_map_helper {
        struct bpf_object *obj;
        struct bpf_map *map;
        int fd;
    } helper = {0};
    
    char path[256];
    snprintf(path, sizeof(path), "%s/cpu_throttle/blk_io_mask_bpf.o", BPF_FS_PATH);
    
    /* Mở object BPF */
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    helper.obj = bpf_object__open_file(path, &opts);
    if (!helper.obj) {
        /* Fallback: thử sử dụng bpf_obj_get */
        snprintf(path, sizeof(path), "%s/cpu_throttle/blk_dev_stats", BPF_FS_PATH);
        metrics[0].map_fd = metrics[1].map_fd = metrics[2].map_fd = metrics[3].map_fd = 
            bpf_obj_get(path);
        if (metrics[0].map_fd < 0) {
            perror("Không thể mở map dev_stats");
            return EXIT_FAILURE;
        }
        
        snprintf(path, sizeof(path), "%s/cpu_throttle/blk_cfg_map", BPF_FS_PATH);
        metrics[4].map_fd = metrics[5].map_fd = bpf_obj_get(path);
        if (metrics[4].map_fd < 0) {
            perror("Không thể mở map cfg_map");
            close(metrics[0].map_fd);
            return EXIT_FAILURE;
        }
    } else {
        /* Sử dụng API hiện đại */
        struct bpf_map *dev_stats_map = bpf_object__find_map_by_name(helper.obj, "dev_stats");
        struct bpf_map *cfg_map = bpf_object__find_map_by_name(helper.obj, "cfg_map");
        
        if (!dev_stats_map || !cfg_map) {
            fprintf(stderr, "Không thể tìm thấy maps trong object BPF\n");
            bpf_object__close(helper.obj);
            return EXIT_FAILURE;
        }
        
        metrics[0].map_fd = metrics[1].map_fd = metrics[2].map_fd = metrics[3].map_fd = 
            bpf_map__fd(dev_stats_map);
        metrics[4].map_fd = metrics[5].map_fd = bpf_map__fd(cfg_map);
    }
    
    // Đăng ký signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Khởi động HTTP server thread
    if (pthread_create(&http_thread, NULL, http_server_thread, NULL) != 0) {
        perror("pthread_create");
        if (helper.obj) {
            bpf_object__close(helper.obj);
        } else {
            close(metrics[0].map_fd);
            close(metrics[4].map_fd);
        }
        return EXIT_FAILURE;
    }
    
    // Vòng lặp chính
    while (!exiting) {
        sleep(1);
    }
    
    // Chờ HTTP thread kết thúc
    pthread_join(http_thread, NULL);
    
    // Đóng các map BPF
    if (helper.obj) {
        bpf_object__close(helper.obj);
    } else {
        close(metrics[0].map_fd);
        close(metrics[4].map_fd);
    }
    
    return EXIT_SUCCESS;
} 