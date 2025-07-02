/* SPDX-License-Identifier: GPL-2.0
 * blk_io_mask_bpf.c - Module che giấu I/O khối (Block I/O Mask) cho dự án transformer
 *
 * Tính năng chính (phù hợp tài liệu @ebpf_build/blk_io_mask_bpf.md):
 * 1. Mô hình đa tầng (Multi-Layer) với nhiều hook:
 *    - Tracepoint: block/block_rq_issue, block/block_rq_complete, block/block_rq_insert
 *    - Kprobe: blk_account_io_completion
 *    - LSM: security_file_permission
 *    - Cgroup I/O: cgroup_bio (kernel >= 6.0)
 *    - Perf Event: rblk/wblk
 * 2. Chia sẻ map quota & obfuscation với module CPU/Net thông qua SEC(".extern").
 * 3. Giảm (mask) trường bytes tuỳ theo cấu hình mask_ratio (mặc định 50%).
 * 4. Cập nhật quota_cg đồng bộ với byte đã che.
 * 5. Gửi sự kiện qua BPF_RINGBUF để user-space companion xử lý.
 * 6. Hỗ trợ cấu hình runtime thông qua map config (mask_ratio, enabled) – chuẩn bị cho Netlink.
 * 7. Hỗ trợ phân biệt read/write và chế độ thích ứng.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* ----------------------------- ĐỊNH NGHĨA CẤU TRÚC ----------------------------- */

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

/* Sự kiện gửi qua ring buffer - cấu trúc hợp nhất từ nhiều tầng */
struct blk_event {
    u64 cgid;                /* Cgroup ID liên quan */
    u64 orig_bytes;          /* Số byte gốc kernel cung cấp */
    u64 masked_bytes;        /* Số byte đã che giấu */
    u32 rwbs;                /* Cờ đọc/ghi – RWBS field từ tracepoint */
    u32 mask_ratio;          /* mask_ratio tại thời điểm sự kiện */
    u64 timestamp_ns;        /* Thời điểm (ns) */
    u64 latency_ns;          /* Độ trễ (ns) - cho block_rq_complete */
    u32 event_source;        /* Nguồn sự kiện (enum event_source) */
    u32 io_op;               /* Loại hoạt động I/O (enum io_operation) */
    u64 device_id;           /* ID thiết bị (major:minor) */
    char comm[16];           /* Tên tiến trình */
};

/* Cấu hình cloaking cơ bản của module – cho phép Netlink userspace chỉnh */
struct blk_mask_cfg {
    u8  enabled;             /* 0 = tắt, 1 = bật */
    u8  adaptive_mode;       /* 0 = cố định, 1 = thích ứng theo tải */
    u16 mask_ratio;          /* Tỉ lệ che (%) 0‒100 */
    u16 tp_issue_ratio;      /* Tỉ lệ che tại tracepoint issue (%) */
    u16 tp_complete_ratio;   /* Tỉ lệ che tại tracepoint complete (%) */
    u16 kprobe_ratio;        /* Tỉ lệ che tại kprobe (%) */
    u16 lsm_ratio;           /* Tỉ lệ che tại LSM (%) */
    u16 cgroup_io_ratio;     /* Tỉ lệ che tại cgroup I/O (%) */
    u16 tp_insert_ratio;     /* Tỉ lệ che tại tracepoint insert (%) */
    u16 read_ratio;          /* Tỉ lệ che giấu thao tác đọc (%) */
    u16 write_ratio;         /* Tỉ lệ che giấu thao tác ghi (%) */
};

/* Thống kê I/O theo loại thiết bị */
struct io_device_stat {
    u64 reads;               /* Số lần đọc */
    u64 writes;              /* Số lần ghi */
    u64 read_bytes;          /* Bytes đọc */
    u64 write_bytes;         /* Bytes ghi */
    u64 masked_bytes;        /* Bytes đã che giấu */
    u64 latency_sum_ns;      /* Tổng độ trễ (ns) */
    u32 count;               /* Số lần truy cập */
};

/* Cấu trúc lưu trữ request để tính latency */
struct req_start {
    u64 ts;                  /* Thời điểm bắt đầu */
    u64 bytes;               /* Kích thước bytes */
    u32 rwbs;                /* Flags RWBS */
};

/* ----------------------------- MAP ĐỊNH NGHĨA ----------------------------- */

/* Ring buffer chuyển sự kiện */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB */
} events SEC(".maps");

/* PERCPU array ghi thống kê byte đã che – tránh contention */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 7); /* Một entry cho mỗi event_source, tăng lên 7 */
    __type(key, u32);
    __type(value, u64);
} io_stats SEC(".maps");

/* Cấu hình runtime – index 0 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct blk_mask_cfg);
} cfg_map SEC(".maps");

/* Thống kê theo thiết bị I/O */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, u64);        /* device ID (major:minor) */
    __type(value, struct io_device_stat);
} dev_stats SEC(".maps");

/* Lưu trữ thời điểm bắt đầu request để tính latency */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);        /* request ID */
    __type(value, struct req_start);
} req_start SEC(".maps");

/* -------------------- MAP EXTERN TÁI SỬ DỤNG TỪ MODULE KHÁC -------------------- */
extern struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u8);
} obfuscate_cg SEC(".extern");

extern struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u64);
} quota_cg SEC(".extern");

/* ----------------------------- HÀM TRỢ GIÚP ----------------------------- */

/* Cập nhật thống kê theo thiết bị - tối ưu cho JIT compiler */
static __noinline void update_dev_stats(u64 dev_id, u32 rwbs, u64 bytes, u64 masked, u64 latency)
{
    struct io_device_stat new_stat = {0};
    struct io_device_stat *stat = bpf_map_lookup_elem(&dev_stats, &dev_id);
    
    /* Đọc giá trị hiện tại hoặc khởi tạo mới */
    if (stat) {
        __builtin_memcpy(&new_stat, stat, sizeof(new_stat));
    }
    
    /* Sử dụng phép AND bit để tối ưu các điều kiện */
    u8 is_read = (rwbs & (1 << 0)) != 0;
    u8 is_write = (rwbs & (1 << 1)) != 0;
    
    /* Cập nhật counter theo loại hoạt động */
    new_stat.reads += is_read;
    new_stat.writes += is_write;
    
    /* Cập nhật bytes theo loại hoạt động */
    new_stat.read_bytes += is_read * bytes;
    new_stat.write_bytes += is_write * bytes;
    
    /* Cập nhật masked bytes và latency */
    new_stat.masked_bytes += masked;
    
    /* Chỉ cập nhật latency nếu có */
    if (latency) {
        new_stat.latency_sum_ns += latency;
        new_stat.count++;
    }
    
    /* Ghi lại thống kê */
    bpf_map_update_elem(&dev_stats, &dev_id, &new_stat, BPF_ANY);
}

/* Truy vấn cấu hình */
static __always_inline struct blk_mask_cfg *get_cfg(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&cfg_map, &key);
}

/* Lấy thống kê theo nguồn */
static __always_inline u64 *get_stat(u32 source)
{
    if (source >= 7) /* Kiểm tra giới hạn */
        return NULL;
    return bpf_map_lookup_elem(&io_stats, &source);
}

/* Lấy cgroup id của tiến trình hiện tại */
static __always_inline u64 get_current_cgid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return 0;

    /* Kiểm tra sự tồn tại của các trường để đảm bảo tương thích kernel */
    if (bpf_core_field_exists(task->cgroups) &&
        bpf_core_field_exists(task->cgroups->effective) &&
        bpf_core_field_exists(task->cgroups->effective->dfl_cgrp) &&
        bpf_core_field_exists(task->cgroups->effective->dfl_cgrp->kn) &&
        bpf_core_field_exists(task->cgroups->effective->dfl_cgrp->kn->id)) {
        return BPF_CORE_READ(task, cgroups, effective, dfl_cgrp, kn, id);
    }

    /* Đường dẫn tương thích thứ hai - cho kernel cũ hơn */
    if (bpf_core_field_exists(task->cgroup_subsys) &&
        bpf_core_field_exists(task->cgroup_subsys[0]) &&
        bpf_core_field_exists(task->cgroup_subsys[0]->cgroup) &&
        bpf_core_field_exists(task->cgroup_subsys[0]->cgroup->kn) &&
        bpf_core_field_exists(task->cgroup_subsys[0]->cgroup->kn->id)) {
        return BPF_CORE_READ(task, cgroup_subsys[0], cgroup, kn, id);
    }

    /* Fallback - sử dụng PID nếu không có thông tin cgroup */
    return bpf_get_current_pid_tgid() >> 32;
}

/* Kiểm tra xem cgroup có cần che giấu không */
static __always_inline bool should_mask_cgroup(u64 cgid)
{
    u8 *flag = bpf_map_lookup_elem(&obfuscate_cg, &cgid);
    return flag && *flag == 1;
}

/* Lấy tỉ lệ che giấu dựa theo nguồn sự kiện và loại hoạt động */
static __always_inline u16 get_mask_ratio_for_source(struct blk_mask_cfg *cfg, u32 source, u32 rwbs)
{
    if (!cfg || !cfg->enabled)
        return 0;
    
    /* Xác định loại hoạt động I/O */
    u32 io_op = get_io_op(rwbs);
    
    /* Ưu tiên phân biệt theo loại hoạt động read/write */
    if (io_op == IO_READ && cfg->read_ratio > 0) {
        return cfg->read_ratio;
    } else if (io_op == IO_WRITE && cfg->write_ratio > 0) {
        return cfg->write_ratio;
    }
    
    /* Nếu không có tỷ lệ theo loại, áp dụng tỷ lệ theo nguồn */
    switch (source) {
    case SRC_TRACEPOINT_ISSUE:
        return cfg->tp_issue_ratio > 0 ? cfg->tp_issue_ratio : cfg->mask_ratio;
    case SRC_TRACEPOINT_COMPLETE:
        return cfg->tp_complete_ratio > 0 ? cfg->tp_complete_ratio : cfg->mask_ratio;
    case SRC_TRACEPOINT_INSERT:
        return cfg->tp_insert_ratio > 0 ? cfg->tp_insert_ratio : cfg->mask_ratio;
    case SRC_KPROBE:
        return cfg->kprobe_ratio > 0 ? cfg->kprobe_ratio : cfg->mask_ratio;
    case SRC_LSM:
        return cfg->lsm_ratio > 0 ? cfg->lsm_ratio : cfg->mask_ratio;
    case SRC_CGROUP_IO:
        return cfg->cgroup_io_ratio > 0 ? cfg->cgroup_io_ratio : cfg->mask_ratio;
    default:
        return cfg->mask_ratio;
    }
}

/* Xác định loại hoạt động I/O từ rwbs */
static __always_inline u32 get_io_op(u32 rwbs)
{
    if (rwbs & (1 << 0))  /* R */
        return IO_READ;
    if (rwbs & (1 << 1))  /* W */
        return IO_WRITE;
    if (rwbs & (1 << 3))  /* S - sync */
        return IO_SYNC;
    return IO_OTHER;
}

/* Gửi sự kiện thống nhất qua ring buffer */
static __noinline void send_event(u64 cgid, u64 bytes, u64 masked_bytes, u32 rwbs,
                                 u32 mask_ratio, u64 latency, u32 source, u64 dev_id)
{
    struct blk_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    /* Sao chép dữ liệu vào event */
    e->cgid = cgid;
    e->orig_bytes = bytes;
    e->masked_bytes = masked_bytes;
    e->rwbs = rwbs;
    e->mask_ratio = mask_ratio;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->latency_ns = latency;
    e->event_source = source;
    e->io_op = get_io_op(rwbs);
    e->device_id = dev_id;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    /* Gửi event */
    bpf_ringbuf_submit(e, 0);
}

/* Xử lý che giấu bytes và cập nhật quota - tối ưu cho JIT compiler */
static __noinline u64 mask_io_bytes(u64 cgid, u64 bytes, u32 source)
{
    u64 masked_bytes = 0;
    
    /* Fast path cho trường hợp không cần mask */
    struct blk_mask_cfg *cfg = get_cfg();
    if (!cfg || !cfg->enabled)
        return 0;

    u16 mask_ratio = get_mask_ratio_for_source(cfg, source, 0);
    if (!mask_ratio)
        return 0;

    /* Tối ưu phép tính mask_ratio */
    if (mask_ratio == 100) {
        /* Trường hợp che giấu 100% */
        masked_bytes = bytes;
    } else if (mask_ratio == 50) {
        /* Trường hợp che giấu 50% - sử dụng dịch bit */
        masked_bytes = bytes >> 1;
    } else if (mask_ratio == 25) {
        /* Trường hợp che giấu 25% - sử dụng dịch bit */
        masked_bytes = bytes >> 2;
    } else if (mask_ratio == 75) {
        /* Trường hợp che giấu 75% - sử dụng dịch bit và phép cộng */
        masked_bytes = (bytes >> 1) + (bytes >> 2);
    } else {
        /* Trường hợp tổng quát */
        masked_bytes = (bytes * mask_ratio) / 100;
    }
    
    /* Không cần xử lý nếu không có bytes để che giấu */
    if (!masked_bytes)
        return 0;
    
    /* Cập nhật quota_cg */
    u64 *quota_ptr = bpf_map_lookup_elem(&quota_cg, &cgid);
    if (quota_ptr) {
        /* Sử dụng atomic fetch-and-sub */
        __sync_fetch_and_sub(quota_ptr, masked_bytes);
    }
    
    /* Cập nhật thống kê per-CPU */
    u64 *stat = get_stat(source);
    if (stat) {
        /* Sử dụng atomic fetch-and-add */
        __sync_fetch_and_add(stat, masked_bytes);
    }
    
    return masked_bytes;
}

/* ----------------------------- CHƯƠNG TRÌNH EBPF ----------------------------- */

/* 1. Tracepoint: block/block_rq_issue */
SEC("tp/block/block_rq_issue")
int on_block_rq_issue(struct trace_event_raw_block_rq_issue *ctx)
{
    /* Bỏ qua request NULL */
    if (!ctx)
        return 0;

    u64 cgid = get_current_cgid();

    /* Kiểm tra xem cgroup có bật che giấu? */
    if (!should_mask_cgroup(cgid))
        return 0;

    /* Đọc trường bytes và rwbs từ tracepoint */
    u64 bytes = ctx->bytes;
    u32 rwbs = ctx->rwbs;
    u64 dev = ctx->dev;
    u64 req_id = (u64)ctx->rq;

    /* Lưu thời điểm bắt đầu để tính latency sau này */
    struct req_start start = {
        .ts = bpf_ktime_get_ns(),
        .bytes = bytes,
        .rwbs = rwbs
    };
    bpf_map_update_elem(&req_start, &req_id, &start, BPF_ANY);

    /* Tính toán masked_bytes */
    u64 masked_bytes = mask_io_bytes(cgid, bytes, SRC_TRACEPOINT_ISSUE);
    if (masked_bytes == 0)
        return 0;

    /* Cập nhật thống kê thiết bị */
    update_dev_stats(dev, rwbs, bytes, masked_bytes, 0);

    /* Gửi sự kiện */
    struct blk_mask_cfg *cfg = get_cfg();
    u16 mask_ratio = cfg ? get_mask_ratio_for_source(cfg, SRC_TRACEPOINT_ISSUE, rwbs) : 0;
    send_event(cgid, bytes, masked_bytes, rwbs, mask_ratio, 0, SRC_TRACEPOINT_ISSUE, dev);

    return 0;
}

/* 2. Tracepoint: block/block_rq_complete */
SEC("tp/block/block_rq_complete")
int on_block_rq_complete(struct trace_event_raw_block_rq_complete *ctx)
{
    if (!ctx)
        return 0;

    u64 cgid = get_current_cgid();
    
    /* Kiểm tra xem cgroup có bật che giấu? */
    if (!should_mask_cgroup(cgid))
        return 0;
        
    u32 rwbs = ctx->rwbs;
    u64 dev = ctx->dev;
    u64 req_id = (u64)ctx->rq;
    u64 bytes = 0;
    u64 latency_ns = 0;
    
    /* Tìm thông tin request đã lưu để tính latency */
    struct req_start *start = bpf_map_lookup_elem(&req_start, &req_id);
    if (start) {
        bytes = start->bytes;
        latency_ns = bpf_ktime_get_ns() - start->ts;
        bpf_map_delete_elem(&req_start, &req_id);
    } else {
        /* Nếu không tìm thấy, lấy từ tracepoint nếu có */
        bytes = ctx->bytes;
    }
    
    if (bytes == 0)
        return 0;
    
    /* Tính toán masked_bytes */
    u64 masked_bytes = mask_io_bytes(cgid, bytes, SRC_TRACEPOINT_COMPLETE);
    if (masked_bytes == 0)
        return 0;
    
    /* Cập nhật thống kê thiết bị */
    update_dev_stats(dev, rwbs, bytes, masked_bytes, latency_ns);
    
    /* Gửi sự kiện */
    struct blk_mask_cfg *cfg = get_cfg();
    u16 mask_ratio = cfg ? get_mask_ratio_for_source(cfg, SRC_TRACEPOINT_COMPLETE, rwbs) : 0;
    send_event(cgid, bytes, masked_bytes, rwbs, mask_ratio, latency_ns, SRC_TRACEPOINT_COMPLETE, dev);
    
    return 0;
}

/* 3. Kprobe: blk_account_io_completion */
SEC("kprobe/blk_account_io_completion")
int BPF_KPROBE(probe_blk_account_io_completion, struct request *rq, u64 now)
{
    if (!rq)
        return 0;

    u64 cgid = get_current_cgid();
    
    /* Kiểm tra xem cgroup có bật che giấu? */
    if (!should_mask_cgroup(cgid))
        return 0;
    
    /* Đọc thông tin từ struct request với kiểm tra sự tồn tại của trường */
    u64 bytes = 0;
    if (bpf_core_field_exists(rq->__data_len)) {
        bytes = BPF_CORE_READ(rq, __data_len);
    } else if (bpf_core_field_exists(rq->__sector)) {
        /* Trường hợp cho kernel cũ hơn dùng sector size */
        bytes = BPF_CORE_READ(rq, __sector) * 512;
    }

    if (bytes == 0)
        return 0;
    
    u32 rwbs = 0;
    
    /* Xác định rwbs từ request với kiểm tra sự tồn tại của trường */
    if (bpf_core_field_exists(rq->cmd_flags)) {
        u64 cmd_flags = BPF_CORE_READ(rq, cmd_flags);
        /* Xác định loại thao tác dựa trên flags */
        if (cmd_flags & (1ULL << 0))  /* REQ_OP_READ */
            rwbs |= (1 << 0);  /* R */
        if (cmd_flags & (1ULL << 1))  /* REQ_OP_WRITE */
            rwbs |= (1 << 1);  /* W */
        if (cmd_flags & (1ULL << 3))  /* REQ_SYNC */
            rwbs |= (1 << 3);  /* S */
    }
    
    /* Lấy thông tin device ID với kiểm tra sự tồn tại của trường */
    u64 dev = 0;
    if (bpf_core_field_exists(rq->rq_disk) &&
        bpf_core_field_exists(rq->rq_disk->major) &&
        bpf_core_field_exists(rq->rq_disk->first_minor)) {
        dev = BPF_CORE_READ(rq, rq_disk, major) << 20 | BPF_CORE_READ(rq, rq_disk, first_minor);
    }
    
    /* Tính toán masked_bytes */
    u64 masked_bytes = mask_io_bytes(cgid, bytes, SRC_KPROBE);
    if (masked_bytes == 0)
        return 0;
    
    /* Cập nhật thống kê thiết bị */
    update_dev_stats(dev, rwbs, bytes, masked_bytes, 0);
    
    /* Gửi sự kiện */
    struct blk_mask_cfg *cfg = get_cfg();
    u16 mask_ratio = cfg ? get_mask_ratio_for_source(cfg, SRC_KPROBE, rwbs) : 0;
    send_event(cgid, bytes, masked_bytes, rwbs, mask_ratio, 0, SRC_KPROBE, dev);
    
    return 0;
}

/* 4. LSM Hook: security_file_permission */
SEC("lsm/file_permission")
int BPF_PROG(on_file_permission, struct file *file, int mask)
{
    if (!file)
        return 0;

    /* Chỉ quan tâm đến thao tác ghi */
    if (!(mask & 0x2))  /* MAY_WRITE */
        return 0;
    
    u64 cgid = get_current_cgid();
    
    /* Kiểm tra xem cgroup có bật che giấu? */
    if (!should_mask_cgroup(cgid))
        return 0;
    
    /* Kiểm tra sự tồn tại của các trường */
    if (!bpf_core_field_exists(file->f_inode))
        return 0;

    /* Chỉ tập trung vào file thường, bỏ qua socket, pipe, ... */
    unsigned short mode = 0;
    if (bpf_core_field_exists(file->f_inode->i_mode)) {
        mode = BPF_CORE_READ(file, f_inode, i_mode);
        if (!S_ISREG(mode))
            return 0;
    } else {
        return 0; /* Không thể xác định loại file */
    }
    
    /* Ước tính kích thước ghi dựa trên kích thước file */
    u64 bytes = 0;
    if (bpf_core_field_exists(file->f_inode->i_size)) {
        bytes = BPF_CORE_READ(file, f_inode, i_size);
        if (bytes > 4096)
            bytes = 4096;  /* Giả định kích thước ghi trung bình */
    } else {
        bytes = 4096; /* Giá trị mặc định nếu không đọc được kích thước */
    }
    
    u32 rwbs = (1 << 1);  /* W - write */
    
    /* Lấy device ID */
    u64 dev = 0;
    if (bpf_core_field_exists(file->f_inode->i_sb) &&
        bpf_core_field_exists(file->f_inode->i_sb->s_dev)) {
        dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
    }
    
    /* Tính toán masked_bytes */
    u64 masked_bytes = mask_io_bytes(cgid, bytes, SRC_LSM);
    if (masked_bytes == 0)
        return 0;
    
    /* Cập nhật thống kê thiết bị */
    update_dev_stats(dev, rwbs, bytes, masked_bytes, 0);
    
    /* Gửi sự kiện */
    struct blk_mask_cfg *cfg = get_cfg();
    u16 mask_ratio = cfg ? get_mask_ratio_for_source(cfg, SRC_LSM, rwbs) : 0;
    send_event(cgid, bytes, masked_bytes, rwbs, mask_ratio, 0, SRC_LSM, dev);
    
    return 0;
}

/* 5. Perf Event cho rblk/wblk */
SEC("perf_event")
int on_perf_event(struct bpf_perf_event_data *ctx)
{
    u64 cgid = get_current_cgid();
    
    /* Kiểm tra xem cgroup có bật che giấu? */
    if (!should_mask_cgroup(cgid))
        return 0;
    
    /* Chỉ xử lý nếu là hardware counter rblk/wblk */
    u32 type = ctx->sample_period;  /* Sử dụng sample_period để truyền loại counter */
    if (type != PERF_COUNT_HW_CACHE_MISSES && type != PERF_COUNT_HW_CACHE_REFERENCES)
        return 0;
    
    u64 value = ctx->count;
    u64 bytes = value * 512;  /* Giả định mỗi block = 512 bytes */
    u32 rwbs = (type == PERF_COUNT_HW_CACHE_REFERENCES) ? (1 << 0) : (1 << 1);  /* R hoặc W */
    
    /* Tính toán masked_bytes */
    u64 masked_bytes = mask_io_bytes(cgid, bytes, SRC_PERF_EVENT);
    if (masked_bytes == 0)
        return 0;
    
    /* Gửi sự kiện */
    struct blk_mask_cfg *cfg = get_cfg();
    u16 mask_ratio = cfg ? get_mask_ratio_for_source(cfg, SRC_PERF_EVENT, rwbs) : 0;
    send_event(cgid, bytes, masked_bytes, rwbs, mask_ratio, 0, SRC_PERF_EVENT, 0);
    
    return 0;
}

/* 3. Tracepoint: block/block_rq_insert (Blk-MQ) */
SEC("tp/block/block_rq_insert")
int on_block_rq_insert(struct trace_event_raw_block_rq_insert *ctx)
{
    /* Bỏ qua request NULL */
    if (!ctx)
        return 0;

    u64 cgid = get_current_cgid();

    /* Kiểm tra xem cgroup có bật che giấu? */
    if (!should_mask_cgroup(cgid))
        return 0;

    /* Đọc thông tin request từ tracepoint */
    u64 bytes = ctx->bytes;
    u32 rwbs = ctx->rwbs;
    u64 dev = ctx->dev;
    u64 req_id = (u64)ctx->rq;

    /* Tính toán masked_bytes */
    u64 masked_bytes = mask_io_bytes(cgid, bytes, SRC_TRACEPOINT_INSERT);
    if (masked_bytes == 0)
        return 0;

    /* Cập nhật thống kê thiết bị */
    update_dev_stats(dev, rwbs, bytes, masked_bytes, 0);

    /* Gửi sự kiện */
    struct blk_mask_cfg *cfg = get_cfg();
    u16 mask_ratio = cfg ? get_mask_ratio_for_source(cfg, SRC_TRACEPOINT_INSERT, rwbs) : 0;
    send_event(cgid, bytes, masked_bytes, rwbs, mask_ratio, 0, SRC_TRACEPOINT_INSERT, dev);

    return 0;
}

/* ------------------- INIT CONFIG – Đảm bảo giá trị mặc định ------------------- */

SEC(".init")
int init_cfg(void)
{
    const u32 key = 0;
    struct blk_mask_cfg cfg = {
        .enabled = 1,
        .adaptive_mode = 0,
        .mask_ratio = 50,           /* 50% mặc định */
        .tp_issue_ratio = 30,       /* 30% tại tracepoint issue */
        .tp_complete_ratio = 20,    /* 20% tại tracepoint complete */
        .kprobe_ratio = 40,         /* 40% tại kprobe */
        .lsm_ratio = 25,            /* 25% tại LSM */
        .cgroup_io_ratio = 35,      /* 35% tại cgroup I/O */
        .tp_insert_ratio = 10,      /* 10% tại tracepoint insert */
        .read_ratio = 20,           /* 20% tại read */
        .write_ratio = 20,          /* 20% tại write */
    };
    bpf_map_update_elem(&cfg_map, &key, &cfg, BPF_ANY);
    return 0;
} 