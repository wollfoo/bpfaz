/* SPDX-License-Identifier: GPL-2.0 */
/* blk_io_mask_common.h - Định nghĩa chung cho cả BPF và user-space */

#ifndef _BLK_IO_MASK_COMMON_H
#define _BLK_IO_MASK_COMMON_H

#include <linux/types.h>

/* Định nghĩa Generic Netlink */
#define BLK_MASK_GENL_NAME "blk_io_mask"
#define BLK_MASK_GENL_VERSION 1

/* Nguồn sự kiện - để phân biệt sự kiện đến từ tầng nào */
enum event_source {
    SRC_TRACEPOINT_ISSUE = 0,    /* Tracepoint block_rq_issue */
    SRC_TRACEPOINT_COMPLETE = 1, /* Tracepoint block_rq_complete */
    SRC_KPROBE = 2,              /* Kprobe blk_account_io_completion */
    SRC_LSM = 3,                 /* LSM hook security_file_permission */
    SRC_CGROUP_IO = 4,           /* Cgroup I/O controller */
    SRC_PERF_EVENT = 5,          /* Perf event rblk/wblk */
    SRC_TRACEPOINT_INSERT = 6,   /* Tracepoint block_rq_insert - Blk-MQ */
};

/* Loại hoạt động I/O */
enum io_operation {
    IO_READ = 0,     /* Đọc dữ liệu */
    IO_WRITE = 1,    /* Ghi dữ liệu */
    IO_SYNC = 2,     /* Đồng bộ hoá */
    IO_OTHER = 3,    /* Khác */
};

/* Lý do che giấu */
enum mask_reason {
    MASK_DEFAULT = 0,        /* Che giấu mặc định */
    MASK_QUOTA_LOW = 1,      /* Quota thấp */
    MASK_ADAPTIVE = 2,       /* Thích ứng theo tải */
    MASK_MANUAL = 3,         /* Cấu hình thủ công */
    MASK_DETECTION_AVOID = 4 /* Tránh phát hiện */
};

/* Sự kiện gửi qua ring buffer - cấu trúc hợp nhất từ nhiều tầng */
struct blk_event {
    __u64 cgid;                /* Cgroup ID liên quan */
    __u64 orig_bytes;          /* Số byte gốc kernel cung cấp */
    __u64 masked_bytes;        /* Số byte đã che giấu */
    __u32 rwbs;                /* Cờ đọc/ghi – RWBS field từ tracepoint */
    __u32 mask_ratio;          /* mask_ratio tại thời điểm sự kiện */
    __u64 timestamp_ns;        /* Thời điểm (ns) */
    __u64 latency_ns;          /* Độ trễ (ns) - cho block_rq_complete */
    __u32 event_source;        /* Nguồn sự kiện (enum event_source) */
    __u32 io_op;               /* Loại hoạt động I/O (enum io_operation) */
    __u64 device_id;           /* ID thiết bị (major:minor) */
    char comm[16];             /* Tên tiến trình */
};

/* Cấu hình cloaking cơ bản của module – cho phép Netlink userspace chỉnh */
struct blk_mask_cfg {
    __u8  enabled;             /* 0 = tắt, 1 = bật */
    __u8  adaptive_mode;       /* 0 = cố định, 1 = thích ứng theo tải */
    __u16 mask_ratio;          /* Tỉ lệ che (%) 0‒100 */
    __u16 tp_issue_ratio;      /* Tỉ lệ che tại tracepoint issue (%) */
    __u16 tp_complete_ratio;   /* Tỉ lệ che tại tracepoint complete (%) */
    __u16 kprobe_ratio;        /* Tỉ lệ che tại kprobe (%) */
    __u16 lsm_ratio;           /* Tỉ lệ che tại LSM (%) */
    __u16 cgroup_io_ratio;     /* Tỉ lệ che tại cgroup I/O (%) */
    __u16 tp_insert_ratio;     /* Tỉ lệ che tại tracepoint insert (%) */
    __u16 read_ratio;          /* Tỉ lệ che giấu thao tác đọc (%) */
    __u16 write_ratio;         /* Tỉ lệ che giấu thao tác ghi (%) */
};

/* Thống kê I/O theo loại thiết bị */
struct io_device_stat {
    __u64 reads;               /* Số lần đọc */
    __u64 writes;              /* Số lần ghi */
    __u64 read_bytes;          /* Bytes đọc */
    __u64 write_bytes;         /* Bytes ghi */
    __u64 masked_bytes;        /* Bytes đã che giấu */
    __u64 latency_sum_ns;      /* Tổng độ trễ (ns) */
    __u32 count;               /* Số lần truy cập */
};

/* Danh sách các lệnh Netlink */
enum {
    BLK_MASK_CMD_UNSPEC,
    BLK_MASK_CMD_GET_CONFIG,    /* Lấy cấu hình hiện tại */
    BLK_MASK_CMD_SET_CONFIG,    /* Đặt cấu hình mới */
    BLK_MASK_CMD_GET_STATS,     /* Lấy thống kê */
    BLK_MASK_CMD_SET_ENABLED,   /* Bật/tắt */
    BLK_MASK_CMD_SET_MASK_RATIO, /* Thiết lập tỉ lệ che chung */
    BLK_MASK_CMD_SET_LAYER_MASK, /* Thiết lập tỉ lệ che cho từng tầng */
    BLK_MASK_CMD_SET_ADAPTIVE,  /* Bật/tắt chế độ thích ứng */
    __BLK_MASK_CMD_MAX,
};

#define BLK_MASK_CMD_MAX (__BLK_MASK_CMD_MAX - 1)

/* Định nghĩa thuộc tính */
enum {
    BLK_MASK_ATTR_UNSPEC,
    BLK_MASK_ATTR_CONFIG,       /* Cấu hình */
    BLK_MASK_ATTR_DEV_ID,       /* ID thiết bị */
    BLK_MASK_ATTR_STATS,        /* Thống kê */
    BLK_MASK_ATTR_ENABLED,      /* Trạng thái bật/tắt */
    BLK_MASK_ATTR_MASK_RATIO,   /* Tỉ lệ che chung */
    BLK_MASK_ATTR_LAYER,        /* Loại tầng */
    BLK_MASK_ATTR_LAYER_MASK,   /* Tỉ lệ che cho tầng */
    BLK_MASK_ATTR_ADAPTIVE,     /* Chế độ thích ứng */
    __BLK_MASK_ATTR_MAX,
};

#define BLK_MASK_ATTR_MAX (__BLK_MASK_ATTR_MAX - 1)

#endif /* _BLK_IO_MASK_COMMON_H */ 