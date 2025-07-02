// SPDX-License-Identifier: GPL-2.0
// blk_mask_ctl.c - Công cụ điều khiển cho blk_io_mask_bpf
//
// Chức năng:
// 1. Cấu hình mask_ratio và chế độ hoạt động qua Netlink
// 2. Hiển thị thống kê I/O và mức che giấu
// 3. Bật/tắt chế độ thích ứng (adaptive mode)
// 4. Cấu hình tỉ lệ che giấu cho từng tầng

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <pthread.h>
#include <pwd.h>
#include <grp.h>

#include "include/blk_io_mask_common.h"
#include "adaptive_masking.h"

#define BPF_FS_PATH "/sys/fs/bpf"
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Cấu trúc utility để quản lý maps */
struct bpf_map_helper {
    struct bpf_object *obj;     /* Đối tượng BPF chứa map */
    struct bpf_map *map;        /* Map BPF */
    int fd;                     /* File descriptor của map */
};

/* Tìm và mở map BPF bằng API hiện đại */
static int open_bpf_map(struct bpf_map_helper *helper, const char *path, const char *map_name)
{
    struct bpf_object *obj;
    struct bpf_map *map;
    int fd;
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    
    /* Reset cấu trúc helper */
    memset(helper, 0, sizeof(*helper));
    
    /* Mở BPF object */
    obj = bpf_object__open_file(path, &opts);
    if (!obj) {
        int err = -errno;
        fprintf(stderr, "Không thể mở BPF object từ %s: %s\n", path, strerror(-err));
        return err;
    }
    
    /* Tìm map theo tên */
    map = bpf_object__find_map_by_name(obj, map_name);
    if (!map) {
        fprintf(stderr, "Không tìm thấy map '%s' trong object\n", map_name);
        bpf_object__close(obj);
        return -ENOENT;
    }
    
    /* Lấy file descriptor của map */
    fd = bpf_map__fd(map);
    if (fd < 0) {
        int err = -errno;
        fprintf(stderr, "Không thể lấy fd cho map '%s': %s\n", map_name, strerror(-err));
        bpf_object__close(obj);
        return err;
    }
    
    /* Lưu thông tin vào helper */
    helper->obj = obj;
    helper->map = map;
    helper->fd = fd;
    
    return 0;
}

/* Đóng và giải phóng tài nguyên bpf_map_helper */
static void close_bpf_map(struct bpf_map_helper *helper)
{
    if (helper && helper->obj) {
        bpf_object__close(helper->obj);
        helper->obj = NULL;
        helper->map = NULL;
        helper->fd = -1;
    }
}

/* Định nghĩa mã lỗi */
#define ERR_INVALID_PARAM   -1   /* Tham số không hợp lệ */
#define ERR_PERMISSION      -2   /* Không đủ quyền */
#define ERR_MAP_OPEN        -3   /* Không thể mở map */
#define ERR_MAP_LOOKUP      -4   /* Không thể đọc từ map */
#define ERR_MAP_UPDATE      -5   /* Không thể cập nhật map */
#define ERR_SOCKET          -6   /* Lỗi socket */
#define ERR_NETLINK         -7   /* Lỗi netlink */
#define ERR_BIND            -8   /* Lỗi bind */
#define ERR_RESOURCE        -9   /* Lỗi tài nguyên */

/* In thông báo lỗi dựa trên mã lỗi */
static void print_error(int err_code, const char *custom_msg)
{
    const char *err_msg = "Lỗi không xác định";
    
    switch (err_code) {
    case ERR_INVALID_PARAM:
        err_msg = "Tham số không hợp lệ";
        break;
    case ERR_PERMISSION:
        err_msg = "Không đủ quyền";
        break;
    case ERR_MAP_OPEN:
        err_msg = "Không thể mở BPF map";
        break;
    case ERR_MAP_LOOKUP:
        err_msg = "Không thể đọc dữ liệu từ BPF map";
        break;
    case ERR_MAP_UPDATE:
        err_msg = "Không thể cập nhật BPF map";
        break;
    case ERR_SOCKET:
        err_msg = "Lỗi socket";
        break;
    case ERR_NETLINK:
        err_msg = "Lỗi kết nối netlink";
        break;
    case ERR_BIND:
        err_msg = "Lỗi bind socket";
        break;
    case ERR_RESOURCE:
        err_msg = "Lỗi tài nguyên hệ thống";
        break;
    default:
        if (err_code < 0)
            err_msg = strerror(-err_code);
        break;
    }
    
    if (custom_msg)
        fprintf(stderr, "Lỗi: %s - %s\n", custom_msg, err_msg);
    else
        fprintf(stderr, "Lỗi: %s\n", err_msg);
}

// Hàm nội bộ để thiết lập tỷ lệ che giấu (export cho adaptive_masking.c)
int set_mask_ratio_internal(uint16_t ratio);

/* Cấu trúc lưu trữ thông tin Netlink */
struct nl_ctx {
    int fd;                     /* Socket file descriptor */
    int family_id;              /* Generic netlink family ID */
    unsigned int seq;           /* Sequence number */
};

/* Hiển thị trợ giúp */
static void print_help(const char *prog)
{
    printf("Công cụ điều khiển blk_io_mask_bpf\n");
    printf("Sử dụng: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  stats                  Hiển thị thống kê I/O và mức che giấu\n");
    printf("  config                 Hiển thị cấu hình hiện tại\n");
    printf("  enable                 Bật chế độ che giấu\n");
    printf("  disable                Tắt chế độ che giấu\n");
    printf("  set-mask <ratio>       Thiết lập tỉ lệ che giấu chung (0-100)\n");
    printf("  set-layer-mask <layer> <ratio>  Thiết lập tỉ lệ che giấu cho tầng cụ thể\n");
    printf("                         layer: issue, complete, kprobe, lsm, cgroup\n");
    printf("  adaptive <on|off>      Bật/tắt chế độ thích ứng\n");
    printf("  monitor                Giám sát sự kiện I/O theo thời gian thực\n");
    printf("\nOptions:\n");
    printf("  -d, --device <dev>     Chỉ định thiết bị (major:minor)\n");
    printf("  -c, --cgid <id>        Chỉ định cgroup ID\n");
    printf("  -h, --help             Hiển thị trợ giúp\n");
}

/* Lấy family_id từ genl_ctrl_resolve() */
static int get_family_id(struct nl_ctx *ctx)
{
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[256];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = GENL_ID_CTRL,
        .g.cmd = CTRL_CMD_GETFAMILY,
    };
    struct nlattr *attr;
    int ret, nl_socket = ctx->fd;
    
    /* Chuẩn bị CTRL_CMD_GETFAMILY request */
    attr = (struct nlattr *)(((char *)&req) + NLMSG_LENGTH(GENL_HDRLEN));
    attr->nla_type = CTRL_ATTR_FAMILY_NAME;
    attr->nla_len = NLA_HDRLEN + strlen(BLK_MASK_GENL_NAME) + 1;
    strcpy(((char *)attr) + NLA_HDRLEN, BLK_MASK_GENL_NAME);
    req.n.nlmsg_len += NLMSG_ALIGN(attr->nla_len);

    /* Gửi request */
    if (sendto(nl_socket, &req, req.n.nlmsg_len, 0, NULL, 0) < 0) {
        perror("sendto");
        return -1;
    }

    /* Nhận phản hồi */
    char buf[4096];
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    int len = recv(nl_socket, nlh, sizeof(buf), 0);
    if (len < 0) {
        perror("recv");
        return -1;
    }
    if (len == 0) {
        fprintf(stderr, "EOF từ netlink\n");
        return -1;
    }

    /* Kiểm tra phản hồi */
    if (!NLMSG_OK(nlh, len)) {
        fprintf(stderr, "Phản hồi netlink không hợp lệ\n");
        return -1;
    }
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error == 0) {
            /* ACK message */
            return 0;
        }
        fprintf(stderr, "Lỗi netlink: %s\n", strerror(-err->error));
        return -1;
    }

    /* Phân tích phản hồi */
    struct genlmsghdr *gnlh = (struct genlmsghdr *)NLMSG_DATA(nlh);
    if (gnlh->cmd != CTRL_CMD_NEWFAMILY) {
        fprintf(stderr, "Không phải phản hồi CTRL_CMD_NEWFAMILY\n");
        return -1;
    }

    /* Tìm family ID từ phản hồi */
    struct nlattr *tb[CTRL_ATTR_MAX + 1] = {0};
    int remaining = len - NLMSG_LENGTH(GENL_HDRLEN);
    
    /* Phân tích attributes */
    attr = (struct nlattr *)((char *)gnlh + GENL_HDRLEN);
    while (NLA_OK(attr, remaining)) {
        if (attr->nla_type <= CTRL_ATTR_MAX)
            tb[attr->nla_type] = attr;
        attr = NLA_NEXT(attr, remaining);
    }

    /* Lấy family ID */
    if (!tb[CTRL_ATTR_FAMILY_ID]) {
        fprintf(stderr, "Không tìm thấy family ID\n");
        return -1;
    }

    uint16_t family_id = *((uint16_t *)NLA_DATA(tb[CTRL_ATTR_FAMILY_ID]));
    return family_id;
}

/* Hàm dọn dẹp tài nguyên Netlink */
static void cleanup_netlink(struct nl_ctx *ctx)
{
    if (ctx && ctx->fd > 0) {
        close(ctx->fd);
        ctx->fd = -1;
        ctx->family_id = 0;
    }
}

/* Khởi tạo kết nối Netlink */
static int init_netlink(struct nl_ctx *ctx)
{
    struct sockaddr_nl sa;
    int fd;

    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (fd < 0) {
        print_error(ERR_SOCKET, "Không thể tạo socket netlink");
        return ERR_SOCKET;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        print_error(ERR_BIND, "Không thể bind socket netlink");
        close(fd);
        return ERR_BIND;
    }

    ctx->fd = fd;
    ctx->seq = time(NULL);

    /* Lấy family ID */
    ctx->family_id = get_family_id(ctx);
    if (ctx->family_id < 0) {
        fprintf(stderr, "Cảnh báo: Không thể lấy family_id cho %s, tiếp tục với bpf maps\n", 
                BLK_MASK_GENL_NAME);
        // Không trả lỗi, chỉ dùng map BPF trực tiếp
    } else {
        printf("Đã kết nối tới Generic Netlink family %s với ID %d\n",
               BLK_MASK_GENL_NAME, ctx->family_id);
    }

    return 0;
}

/* Gửi lệnh Netlink */
static int send_netlink_cmd(struct nl_ctx *ctx, uint8_t cmd, void *data, size_t data_len)
{
    /* Nếu family_id không hợp lệ, không gửi lệnh Netlink */
    if (ctx->family_id <= 0) {
        return -ENOENT;
    }

    struct sockaddr_nl sa;
    struct nlmsghdr *nlh;
    struct genlmsghdr *genl;
    char buf[4096];
    size_t total_len;

    /* Chuẩn bị message */
    memset(buf, 0, sizeof(buf));
    nlh = (struct nlmsghdr *)buf;
    genl = (struct genlmsghdr *)(nlh + 1);
    
    /* Điền header */
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + data_len);
    nlh->nlmsg_type = ctx->family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ctx->seq++;
    nlh->nlmsg_pid = getpid();
    
    /* Điền Generic Netlink header */
    genl->cmd = cmd;
    genl->version = BLK_MASK_GENL_VERSION;
    
    /* Sao chép dữ liệu */
    if (data && data_len > 0)
        memcpy(genl + 1, data, data_len);
    
    /* Chuẩn bị địa chỉ đích */
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    
    /* Gửi message */
    total_len = NLMSG_ALIGN(nlh->nlmsg_len);
    if (sendto(ctx->fd, buf, total_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
        return -1;
    }
    
    return 0;
}

/* Nhận phản hồi Netlink */
static int recv_netlink_response(struct nl_ctx *ctx, void *buf, size_t buf_len)
{
    /* Nếu family_id không hợp lệ, không nhận phản hồi Netlink */
    if (ctx->family_id <= 0) {
        return -ENOENT;
    }

    struct sockaddr_nl sa;
    socklen_t sa_len = sizeof(sa);
    int len;
    
    /* Thiết lập timeout để không bị block vĩnh viễn */
    struct timeval tv;
    tv.tv_sec = 2;  /* 2 giây timeout */
    tv.tv_usec = 0;
    
    if (setsockopt(ctx->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt");
        return -1;
    }
    
    len = recvfrom(ctx->fd, buf, buf_len, 0, (struct sockaddr *)&sa, &sa_len);
    if (len < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            fprintf(stderr, "Timeout khi nhận phản hồi Netlink\n");
        } else {
            perror("recvfrom");
        }
        return -1;
    }
    
    return len;
}

/* Hiển thị thống kê I/O */
static int show_stats(struct nl_ctx *ctx, uint64_t dev_id, uint64_t cgid)
{
    /* Trong trường hợp Netlink chưa được thiết lập, đọc từ map trực tiếp */
    struct bpf_map_helper helper;
    struct io_device_stat stat;
    char path[256];
    int err;
    
    /* Mở map dev_stats sử dụng API hiện đại */
    snprintf(path, sizeof(path), "%s/cpu_throttle/blk_io_mask_bpf.o", BPF_FS_PATH);
    err = open_bpf_map(&helper, path, "dev_stats");
    if (err < 0) {
        fprintf(stderr, "Không thể mở map dev_stats: %s\n", strerror(-err));
        return -1;
    }
    
    /* Đọc thống kê thiết bị */
    if (bpf_map_lookup_elem(helper.fd, &dev_id, &stat) == 0) {
        printf("Thống kê thiết bị %lu:%lu\n", dev_id >> 20, dev_id & 0xFFFFF);
        printf("  Số lần đọc: %lu\n", stat.reads);
        printf("  Số lần ghi: %lu\n", stat.writes);
        printf("  Bytes đọc: %lu\n", stat.read_bytes);
        printf("  Bytes ghi: %lu\n", stat.write_bytes);
        printf("  Bytes đã che giấu: %lu (%.2f%%)\n", 
               stat.masked_bytes, 
               (double)stat.masked_bytes * 100.0 / (stat.read_bytes + stat.write_bytes));
        printf("  Độ trễ trung bình: %.2f µs\n", 
               stat.count > 0 ? (double)stat.latency_sum_ns / stat.count / 1000.0 : 0);
    } else {
        printf("Không tìm thấy thống kê cho thiết bị %lu:%lu\n", 
               dev_id >> 20, dev_id & 0xFFFFF);
    }
    
    /* Giải phóng tài nguyên */
    close_bpf_map(&helper);
    return 0;
}

/* Hiển thị cấu hình */
static int show_config(struct nl_ctx *ctx)
{
    /* Trong trường hợp Netlink chưa được thiết lập, đọc từ map trực tiếp */
    struct bpf_map_helper helper;
    struct blk_mask_cfg cfg;
    char path[256];
    uint32_t key = 0;
    int err;
    
    /* Mở map cfg_map sử dụng API hiện đại */
    snprintf(path, sizeof(path), "%s/cpu_throttle/blk_io_mask_bpf.o", BPF_FS_PATH);
    err = open_bpf_map(&helper, path, "cfg_map");
    if (err < 0) {
        fprintf(stderr, "Không thể mở map cfg_map: %s\n", strerror(-err));
        return -1;
    }
    
    /* Đọc cấu hình */
    if (bpf_map_lookup_elem(helper.fd, &key, &cfg) == 0) {
        printf("Cấu hình hiện tại:\n");
        printf("  Trạng thái: %s\n", cfg.enabled ? "Bật" : "Tắt");
        printf("  Chế độ thích ứng: %s\n", cfg.adaptive_mode ? "Bật" : "Tắt");
        printf("  Tỉ lệ che giấu chung: %u%%\n", cfg.mask_ratio);
        printf("  Tỉ lệ che giấu theo tầng:\n");
        printf("    - Tracepoint issue: %u%%\n", cfg.tp_issue_ratio);
        printf("    - Tracepoint complete: %u%%\n", cfg.tp_complete_ratio);
        printf("    - Kprobe: %u%%\n", cfg.kprobe_ratio);
        printf("    - LSM: %u%%\n", cfg.lsm_ratio);
        printf("    - Cgroup I/O: %u%%\n", cfg.cgroup_io_ratio);
        printf("    - Tracepoint insert: %u%%\n", cfg.tp_insert_ratio);
        printf("  Tỉ lệ che giấu theo loại I/O:\n");
        printf("    - Read: %u%%\n", cfg.read_ratio);
        printf("    - Write: %u%%\n", cfg.write_ratio);
    } else {
        printf("Không thể đọc cấu hình\n");
    }
    
    /* Giải phóng tài nguyên */
    close_bpf_map(&helper);
    return 0;
}

/* Thiết lập tỉ lệ che giấu - phiên bản nội bộ để sử dụng từ adaptive_masking.c */
int set_mask_ratio_internal(uint16_t ratio)
{
    struct bpf_map_helper helper;
    struct blk_mask_cfg cfg;
    char path[256];
    uint32_t key = 0;
    int err;
    
    /* Kiểm tra tham số */
    if (ratio > 100) {
        print_error(ERR_INVALID_PARAM, "Tỉ lệ che giấu phải từ 0 đến 100");
        return ERR_INVALID_PARAM;
    }
    
    /* Sử dụng mutex để đảm bảo thread safety */
    pthread_mutex_lock(&ratio_mutex);
    
    /* Mở map cfg_map sử dụng API hiện đại */
    snprintf(path, sizeof(path), "%s/cpu_throttle/blk_io_mask_bpf.o", BPF_FS_PATH);
    err = open_bpf_map(&helper, path, "cfg_map");
    if (err < 0) {
        print_error(ERR_MAP_OPEN, path);
        pthread_mutex_unlock(&ratio_mutex);
        return ERR_MAP_OPEN;
    }
    
    /* Đọc cấu hình hiện tại */
    if (bpf_map_lookup_elem(helper.fd, &key, &cfg) != 0) {
        print_error(ERR_MAP_LOOKUP, "cfg_map");
        close_bpf_map(&helper);
        pthread_mutex_unlock(&ratio_mutex);
        return ERR_MAP_LOOKUP;
    }
    
    /* Cập nhật tỉ lệ che giấu */
    cfg.mask_ratio = ratio;
    
    /* Ghi lại cấu hình */
    if (bpf_map_update_elem(helper.fd, &key, &cfg, BPF_ANY) != 0) {
        print_error(ERR_MAP_UPDATE, "cfg_map");
        close_bpf_map(&helper);
        pthread_mutex_unlock(&ratio_mutex);
        return ERR_MAP_UPDATE;
    }
    
    close_bpf_map(&helper);
    pthread_mutex_unlock(&ratio_mutex);
    return 0;
}

/* Thiết lập tỉ lệ che giấu (public API) */
static int set_mask_ratio(struct nl_ctx *ctx, uint16_t ratio)
{
    /* Kiểm tra tham số */
    if (ratio > 100) {
        print_error(ERR_INVALID_PARAM, "Tỉ lệ che giấu phải từ 0 đến 100");
        return ERR_INVALID_PARAM;
    }
    
    int ret = set_mask_ratio_internal(ratio);
    if (ret < 0)
        return ret;
    
    printf("Đã thiết lập tỉ lệ che giấu chung: %u%%\n", ratio);
    return 0;
}

/* Thiết lập tỉ lệ che giấu cho tầng cụ thể */
static int set_layer_mask(struct nl_ctx *ctx, const char *layer, uint16_t ratio)
{
    struct bpf_map_helper helper;
    struct blk_mask_cfg cfg;
    char path[256];
    uint32_t key = 0;
    int err;
    
    /* Kiểm tra tham số */
    if (ratio > 100) {
        print_error(ERR_INVALID_PARAM, "Tỉ lệ che giấu phải từ 0 đến 100");
        return ERR_INVALID_PARAM;
    }
    
    /* Mở map cfg_map sử dụng API hiện đại */
    snprintf(path, sizeof(path), "%s/cpu_throttle/blk_io_mask_bpf.o", BPF_FS_PATH);
    err = open_bpf_map(&helper, path, "cfg_map");
    if (err < 0) {
        print_error(ERR_MAP_OPEN, path);
        return ERR_MAP_OPEN;
    }
    
    /* Đọc cấu hình hiện tại */
    if (bpf_map_lookup_elem(helper.fd, &key, &cfg) != 0) {
        print_error(ERR_MAP_LOOKUP, "cfg_map");
        close_bpf_map(&helper);
        return ERR_MAP_LOOKUP;
    }
    
    /* Cập nhật tỉ lệ che giấu theo tầng */
    if (strcmp(layer, "issue") == 0) {
        cfg.tp_issue_ratio = ratio;
        printf("Đã thiết lập tỉ lệ che giấu cho tracepoint issue: %u%%\n", ratio);
    } else if (strcmp(layer, "complete") == 0) {
        cfg.tp_complete_ratio = ratio;
        printf("Đã thiết lập tỉ lệ che giấu cho tracepoint complete: %u%%\n", ratio);
    } else if (strcmp(layer, "kprobe") == 0) {
        cfg.kprobe_ratio = ratio;
        printf("Đã thiết lập tỉ lệ che giấu cho kprobe: %u%%\n", ratio);
    } else if (strcmp(layer, "lsm") == 0) {
        cfg.lsm_ratio = ratio;
        printf("Đã thiết lập tỉ lệ che giấu cho LSM: %u%%\n", ratio);
    } else if (strcmp(layer, "cgroup") == 0) {
        cfg.cgroup_io_ratio = ratio;
        printf("Đã thiết lập tỉ lệ che giấu cho cgroup I/O: %u%%\n", ratio);
    } else if (strcmp(layer, "insert") == 0) {
        cfg.tp_insert_ratio = ratio;
        printf("Đã thiết lập tỉ lệ che giấu cho tracepoint insert: %u%%\n", ratio);
    } else if (strcmp(layer, "read") == 0) {
        cfg.read_ratio = ratio;
        printf("Đã thiết lập tỉ lệ che giấu cho thao tác đọc: %u%%\n", ratio);
    } else if (strcmp(layer, "write") == 0) {
        cfg.write_ratio = ratio;
        printf("Đã thiết lập tỉ lệ che giấu cho thao tác ghi: %u%%\n", ratio);
    } else {
        print_error(ERR_INVALID_PARAM, "Tầng không hợp lệ");
        close_bpf_map(&helper);
        return ERR_INVALID_PARAM;
    }
    
    /* Ghi lại cấu hình */
    if (bpf_map_update_elem(helper.fd, &key, &cfg, BPF_ANY) != 0) {
        print_error(ERR_MAP_UPDATE, "cfg_map");
        close_bpf_map(&helper);
        return ERR_MAP_UPDATE;
    }
    
    close_bpf_map(&helper);
    return 0;
}

/* Bật/tắt chế độ che giấu */
static int set_enabled(struct nl_ctx *ctx, bool enabled)
{
    struct bpf_map_helper helper;
    struct blk_mask_cfg cfg;
    char path[256];
    uint32_t key = 0;
    int err;
    
    /* Mở map cfg_map sử dụng API hiện đại */
    snprintf(path, sizeof(path), "%s/cpu_throttle/blk_io_mask_bpf.o", BPF_FS_PATH);
    err = open_bpf_map(&helper, path, "cfg_map");
    if (err < 0) {
        print_error(ERR_MAP_OPEN, path);
        return ERR_MAP_OPEN;
    }
    
    /* Đọc cấu hình hiện tại */
    if (bpf_map_lookup_elem(helper.fd, &key, &cfg) != 0) {
        print_error(ERR_MAP_LOOKUP, "cfg_map");
        close_bpf_map(&helper);
        return ERR_MAP_LOOKUP;
    }
    
    /* Cập nhật trạng thái */
    cfg.enabled = enabled ? 1 : 0;
    
    /* Ghi lại cấu hình */
    if (bpf_map_update_elem(helper.fd, &key, &cfg, BPF_ANY) != 0) {
        print_error(ERR_MAP_UPDATE, "cfg_map");
        close_bpf_map(&helper);
        return ERR_MAP_UPDATE;
    }
    
    printf("Đã %s chế độ che giấu\n", enabled ? "bật" : "tắt");
    
    close_bpf_map(&helper);
    return 0;
}

/* Cập nhật hàm set_adaptive để sử dụng adaptive masking thread */
static int set_adaptive(struct nl_ctx *ctx, bool enabled)
{
    /* Trong trường hợp Netlink chưa được thiết lập, ghi vào map trực tiếp */
    struct bpf_map_helper helper;
    struct blk_mask_cfg cfg;
    char path[256];
    uint32_t key = 0;
    int err;
    
    /* Mở map cfg_map sử dụng API hiện đại */
    snprintf(path, sizeof(path), "%s/cpu_throttle/blk_io_mask_bpf.o", BPF_FS_PATH);
    err = open_bpf_map(&helper, path, "cfg_map");
    if (err < 0) {
        fprintf(stderr, "Không thể mở map cfg_map: %s\n", strerror(-err));
        return -1;
    }
    
    /* Đọc cấu hình hiện tại */
    if (bpf_map_lookup_elem(helper.fd, &key, &cfg) != 0) {
        fprintf(stderr, "Không thể đọc cấu hình\n");
        close_bpf_map(&helper);
        return -1;
    }
    
    /* Cập nhật chế độ thích ứng */
    cfg.adaptive_mode = enabled ? 1 : 0;
    
    /* Ghi lại cấu hình */
    if (bpf_map_update_elem(helper.fd, &key, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "Không thể cập nhật cấu hình\n");
        close_bpf_map(&helper);
        return -1;
    }
    
    /* Khởi động/dừng thread adaptive masking */
    if (enabled) {
        pthread_mutex_lock(&adaptive_mutex);
        bool running = adaptive_running;
        pthread_mutex_unlock(&adaptive_mutex);
        
        if (!running) {
            init_adaptive_config();
            if (start_adaptive_thread() != 0) {
                fprintf(stderr, "Lỗi: Không thể khởi động thread adaptive masking\n");
                cfg.adaptive_mode = 0;
                bpf_map_update_elem(helper.fd, &key, &cfg, BPF_ANY);
                close_bpf_map(&helper);
                return -1;
            }
        }
    } else {
        pthread_mutex_lock(&adaptive_mutex);
        bool running = adaptive_running;
        pthread_mutex_unlock(&adaptive_mutex);
        
        if (running) {
            stop_adaptive_thread();
        }
    }
    
    printf("Đã %s chế độ thích ứng (adaptive mode)\n", enabled ? "bật" : "tắt");
    
    close_bpf_map(&helper);
    return 0;
}

/* Theo dõi sự kiện từ ring buffer */
static int monitor_events(struct nl_ctx *ctx)
{
    struct bpf_map_helper helper;
    struct ring_buffer *rb = NULL;
    char path[256];
    int err;
    
    /* Mở ring buffer sử dụng API hiện đại */
    snprintf(path, sizeof(path), "%s/cpu_throttle/blk_io_mask_bpf.o", BPF_FS_PATH);
    err = open_bpf_map(&helper, path, "events");
    if (err < 0) {
        fprintf(stderr, "Không thể mở ring buffer events: %s\n", strerror(-err));
        return -1;
    }
    
    /* Callback xử lý sự kiện */
    static int handle_event(void *ctx, void *data, size_t data_sz)
    {
        const struct blk_event *e = data;
        char ts_buf[32];
        time_t t;
        struct tm *tm;
        
        /* Định dạng thời gian */
        t = e->timestamp_ns / 1000000000;
        tm = localtime(&t);
        strftime(ts_buf, sizeof(ts_buf), "%H:%M:%S", tm);
        
        /* Hiển thị thông tin sự kiện */
        printf("[%s.%09lu] cgid=%lu comm=%-16s bytes=%lu masked=%lu (%u%%) ",
               ts_buf, e->timestamp_ns % 1000000000, e->cgid, e->comm,
               e->orig_bytes, e->masked_bytes, e->mask_ratio);
        
        /* Hiển thị loại sự kiện */
        switch (e->event_source) {
        case SRC_TRACEPOINT_ISSUE:
            printf("source=tp_issue ");
            break;
        case SRC_TRACEPOINT_COMPLETE:
            printf("source=tp_complete latency=%.2fus ", e->latency_ns / 1000.0);
            break;
        case SRC_KPROBE:
            printf("source=kprobe ");
            break;
        case SRC_LSM:
            printf("source=lsm ");
            break;
        case SRC_CGROUP_IO:
            printf("source=cgroup_io ");
            break;
        case SRC_PERF_EVENT:
            printf("source=perf_event ");
            break;
        case SRC_TRACEPOINT_INSERT:
            printf("source=tp_insert ");
            break;
        default:
            printf("source=unknown ");
            break;
        }
        
        /* Hiển thị loại I/O */
        switch (e->io_op) {
        case IO_READ:
            printf("op=read ");
            break;
        case IO_WRITE:
            printf("op=write ");
            break;
        case IO_SYNC:
            printf("op=sync ");
            break;
        default:
            printf("op=other ");
            break;
        }
        
        /* Hiển thị thiết bị */
        printf("dev=%lu:%lu\n", e->device_id >> 20, e->device_id & 0xFFFFF);
        
        return 0;
    }
    
    /* Tạo ring buffer */
    rb = ring_buffer__new(helper.fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Không thể tạo ring buffer\n");
        close_bpf_map(&helper);
        return -1;
    }
    
    /* Đăng ký signal handler để thoát */
    signal(SIGINT, [](int) { exit(0); });
    
    printf("Đang giám sát sự kiện I/O... (Ctrl+C để thoát)\n");
    
    /* Vòng lặp chính */
    while (1) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0 && err != -EINTR) {
            printf("Lỗi khi đọc ring buffer: %s\n", strerror(-err));
            break;
        }
    }
    
    ring_buffer__free(rb);
    close_bpf_map(&helper);
    return 0;
}

/* Kiểm tra quyền hạn của người dùng */
static int check_permissions(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();
    
    /* Cho phép root hoặc user blkio */
    if (uid == 0) {
        return 0; /* Root luôn được phép */
    }
    
    /* Kiểm tra người dùng và nhóm 'blkio' */
    struct passwd *pw = getpwnam("blkio");
    struct group *gr = getgrnam("blkio");
    
    if (pw && pw->pw_uid == uid) {
        return 0; /* User blkio được phép */
    }
    
    if (gr && gr->gr_gid == gid) {
        return 0; /* Thành viên của nhóm blkio được phép */
    }
    
    /* Kiểm tra xem người dùng hiện tại có thuộc nhóm blkio? */
    if (gr) {
        int ngroups = 0;
        gid_t *groups = NULL;
        
        /* Lấy số lượng nhóm */
        getgroups(0, NULL);
        ngroups = getgroups(0, NULL);
        
        if (ngroups > 0) {
            groups = malloc(ngroups * sizeof(gid_t));
            if (groups) {
                if (getgroups(ngroups, groups) != -1) {
                    for (int i = 0; i < ngroups; i++) {
                        if (groups[i] == gr->gr_gid) {
                            free(groups);
                            return 0; /* Người dùng thuộc nhóm blkio */
                        }
                    }
                }
                free(groups);
            }
        }
    }
    
    /* Kiểm tra quyền của file BPF map */
    char path[256];
    struct stat st;
    
    snprintf(path, sizeof(path), "%s/cpu_throttle/blk_io_mask_bpf.o", BPF_FS_PATH);
    if (stat(path, &st) == 0) {
        /* Kiểm tra quyền other */
        if ((st.st_mode & S_IROTH) && (st.st_mode & S_IWOTH)) {
            return 0; /* File có quyền đọc/ghi cho other */
        }
        
        /* Kiểm tra quyền group nếu cùng group với file */
        if ((st.st_gid == gid) && (st.st_mode & S_IRGRP) && (st.st_mode & S_IWGRP)) {
            return 0; /* Người dùng cùng group với file và có quyền đọc/ghi */
        }
    }
    
    print_error(ERR_PERMISSION, "Chỉ root hoặc thành viên nhóm blkio mới có thể thực hiện thao tác này");
    return ERR_PERMISSION;
}

int main(int argc, char **argv)
{
    struct nl_ctx ctx = {0};
    int opt;
    uint64_t dev_id = 0;
    uint64_t cgid = 0;
    int ret = EXIT_SUCCESS;
    
    static struct option long_options[] = {
        {"device", required_argument, 0, 'd'},
        {"cgid", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    /* Phân tích tham số */
    while ((opt = getopt_long(argc, argv, "d:c:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'd': {
            unsigned int major, minor;
            if (sscanf(optarg, "%u:%u", &major, &minor) != 2) {
                fprintf(stderr, "Định dạng thiết bị không hợp lệ. Sử dụng major:minor\n");
                return EXIT_FAILURE;
            }
            dev_id = (uint64_t)major << 20 | minor;
            break;
        }
        case 'c':
            cgid = strtoull(optarg, NULL, 10);
            break;
        case 'h':
            print_help(argv[0]);
            return EXIT_SUCCESS;
        default:
            print_help(argv[0]);
            return EXIT_FAILURE;
        }
    }
    
    /* Kiểm tra lệnh */
    if (optind >= argc) {
        print_help(argv[0]);
        return EXIT_FAILURE;
    }
    
    /* Kiểm tra quyền hạn của người dùng */
    if (check_permissions() != 0) {
        return EXIT_FAILURE;
    }
    
    /* Khởi tạo Netlink nếu cần */
    if (init_netlink(&ctx) < 0) {
        fprintf(stderr, "Cảnh báo: Không thể khởi tạo kết nối Netlink, sẽ sử dụng BPF maps trực tiếp\n");
    }
    
    /* Xử lý lệnh */
    const char *cmd = argv[optind];
    
    if (strcmp(cmd, "stats") == 0) {
        ret = show_stats(&ctx, dev_id, cgid);
    } else if (strcmp(cmd, "config") == 0) {
        ret = show_config(&ctx);
    } else if (strcmp(cmd, "enable") == 0) {
        ret = set_enabled(&ctx, true);
    } else if (strcmp(cmd, "disable") == 0) {
        ret = set_enabled(&ctx, false);
    } else if (strcmp(cmd, "set-mask") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Thiếu tham số tỉ lệ che giấu\n");
            ret = EXIT_FAILURE;
        } else {
            uint16_t ratio = atoi(argv[optind + 1]);
            ret = set_mask_ratio(&ctx, ratio);
        }
    } else if (strcmp(cmd, "set-layer-mask") == 0) {
        if (optind + 2 >= argc) {
            fprintf(stderr, "Thiếu tham số tầng hoặc tỉ lệ che giấu\n");
            ret = EXIT_FAILURE;
        } else {
            const char *layer = argv[optind + 1];
            uint16_t ratio = atoi(argv[optind + 2]);
            ret = set_layer_mask(&ctx, layer, ratio);
        }
    } else if (strcmp(cmd, "adaptive") == 0) {
        if (optind + 1 >= argc) {
            fprintf(stderr, "Thiếu tham số on/off\n");
            ret = EXIT_FAILURE;
        } else {
            const char *mode = argv[optind + 1];
            if (strcmp(mode, "on") == 0) {
                ret = set_adaptive(&ctx, true);
            } else if (strcmp(mode, "off") == 0) {
                ret = set_adaptive(&ctx, false);
            } else {
                fprintf(stderr, "Tham số không hợp lệ. Sử dụng on hoặc off\n");
                ret = EXIT_FAILURE;
            }
        }
    } else if (strcmp(cmd, "monitor") == 0) {
        ret = monitor_events(&ctx);
    } else {
        fprintf(stderr, "Lệnh không hợp lệ: %s\n", cmd);
        print_help(argv[0]);
        ret = EXIT_FAILURE;
    }
    
    /* Dọn dẹp tài nguyên */
    cleanup_netlink(&ctx);
    
    return ret;
} 