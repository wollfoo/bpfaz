# Block I/O Mask eBPF (Che giấu I/O khối)

Module eBPF che giấu hoạt động I/O khối (block I/O) bằng cách giảm số lượng byte báo cáo trong các tracepoints, kprobe và LSM hooks để tránh phát hiện.

## Tính năng chính

- **Mô hình đa tầng (Multi-Layer)** với nhiều hook:
  - Tracepoint: block/block_rq_issue, block/block_rq_complete, **block/block_rq_insert**
  - Kprobe: blk_account_io_completion
  - LSM: security_file_permission
  - Cgroup I/O: cgroup_bio
  - Perf Event: rblk/wblk

- **Che giấu thích ứng (Adaptive Masking)** sử dụng:
  - Hàm sigmoid dựa trên CPU load từ `/proc/loadavg`
  - Nhiệt độ từ thermal zones (/sys/class/thermal/)
  - Tạo mô phỏng tiêu thụ điện dao động tự nhiên

- **Phân tách Read/Write** với tỷ lệ che giấu khác nhau cho thao tác đọc và ghi

- **Blk-MQ support** thông qua tracepoint `block/block_rq_insert` 

- **Runtime Configuration** qua Generic Netlink socket:
  - Thay đổi tỷ lệ che giấu mà không cần reload BPF program
  - Cấu hình động cho từng tầng hook

- **Bảo mật nâng cao**:
  - Seccomp filter để hạn chế system calls
  - Chạy dưới quyền hạn chế với systemd
  - Tách biệt quyền và không gian hoạt động

- **Giám sát và gỡ lỗi**:
  - Prometheus metrics exporter với endpoint `/metrics`
  - Thống kê chi tiết theo thiết bị và latency
  - Công cụ dòng lệnh để kiểm tra trạng thái

## Cài đặt

```bash
# Biên dịch
make

# Cài đặt và đăng ký dịch vụ systemd
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable blk_mask.service
sudo systemctl start blk_mask.service
```

## Sử dụng

### Công cụ điều khiển

```bash
# Xem trợ giúp
blk_mask_ctl --help

# Xem thống kê
blk_mask_ctl stats

# Hiển thị cấu hình hiện tại
blk_mask_ctl config

# Bật/tắt chế độ che giấu
blk_mask_ctl enable
blk_mask_ctl disable

# Thiết lập tỷ lệ che giấu chung
blk_mask_ctl set-mask 60

# Thiết lập tỷ lệ cho tầng cụ thể
blk_mask_ctl set-layer-mask issue 40
blk_mask_ctl set-layer-mask complete 30
blk_mask_ctl set-layer-mask insert 50
blk_mask_ctl set-layer-mask kprobe 45

# Bật/tắt chế độ thích ứng
blk_mask_ctl adaptive on
blk_mask_ctl adaptive off

# Giám sát sự kiện theo thời gian thực
blk_mask_ctl monitor
```

### Prometheus Metrics

Module bao gồm Prometheus exporter cung cấp metrics qua HTTP trên cổng 9923.

```bash
# Khởi động exporter
prometheus_exporter &

# Truy cập metrics
curl http://localhost:9923/metrics
```

Metrics có sẵn:
- `blk_io_mask_masked_bytes_total`: Tổng số bytes đã che giấu theo thiết bị
- `blk_io_mask_read_bytes_total`: Tổng số bytes đọc theo thiết bị
- `blk_io_mask_write_bytes_total`: Tổng số bytes ghi theo thiết bị
- `blk_io_mask_latency_seconds`: Độ trễ trung bình của hoạt động I/O theo thiết bị
- `blk_io_mask_mask_ratio`: Tỷ lệ che giấu hiện tại
- `blk_io_mask_enabled`: Trạng thái bật/tắt chức năng che giấu

## Cấu trúc

```
.
├── adaptive_masking.c   - Triển khai chế độ che giấu thích ứng (sigmoid)
├── adaptive_masking.h   - Header cho chế độ thích ứng
├── attach_blk_io_mask.c - Tập tin chính để tải và gắn chương trình eBPF
├── blk_io_mask_bpf.c    - Mã nguồn chương trình eBPF
├── blk_mask_ctl.c       - Công cụ điều khiển
├── blk_mask.service     - Định nghĩa dịch vụ systemd
├── include/
│   └── blk_io_mask_common.h - Định nghĩa cấu trúc dữ liệu dùng chung
├── Makefile
├── prometheus_exporter.c - Prometheus metrics exporter
└── README.md
```

## Yêu cầu

- Kernel Linux >= 5.8
- libbpf >= 0.6.0
- libseccomp
- bpftool
- clang & LLVM

## Ghi chú bảo mật

Module này được thiết kế với các tính năng bảo mật nâng cao:
- Seccomp filters để hạn chế system calls được sử dụng
- Chạy dưới quyền hạn chế (capability) với systemd
- Giới hạn syscalls chỉ cho những syscalls cần thiết
- Kiểm soát chặt chẽ quyền truy cập vào hệ thống tập tin

## Tích hợp với module khác

Module này chia sẻ map với các module CPU/Net thông qua map extern:

- `obfuscate_cg`: Bật/tắt che giấu theo cgroup
- `quota_cg`: Quota còn lại cho mỗi cgroup

## Giấy phép

GPL-2.0 