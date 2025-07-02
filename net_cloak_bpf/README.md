# Net Cloak - Hệ thống che giấu và kiểm soát lưu lượng mạng

Net Cloak là một hệ thống đa tầng dựa trên [eBPF](https://ebpf.io/) (Extended Berkeley Packet Filter) cho phép che giấu và kiểm soát lưu lượng mạng. Hệ thống này sử dụng nhiều hook points khác nhau trong kernel Linux để đạt hiệu năng tối đa và tính linh hoạt cao.

## Tính năng chính

- **Giới hạn băng thông**: Kiểm soát quota và giới hạn lưu lượng theo cgroup
- **Che giấu lưu lượng HTTP**: Chỉnh sửa User-Agent và Host header để ngụy trang
- **Chuyển hướng cổng**: Chuyển hướng kết nối từ cổng này sang cổng khác
- **Giám sát thống kê**: Thu thập và hiển thị thông tin về lưu lượng mạng
- **Hook đa tầng**: Sử dụng XDP, TC, cgroups, LSM, và tracepoints để bảo đảm độ tin cậy
- **Chia sẻ trạng thái**: Đồng bộ trạng thái với các module eBPF khác (như CPU throttle)

## Yêu cầu hệ thống

- Linux kernel 5.10+ (khuyến nghị 6.0+)
- LLVM/Clang 12+
- libbpf 1.0+
- bpftool (từ linux-tools-common)

## Cài đặt

### Cài đặt từ source

```bash
# Cài đặt các gói phụ thuộc
apt install -y build-essential clang llvm libelf-dev libbpf-dev linux-tools-common linux-tools-$(uname -r)

# Clone repository và build
git clone https://github.com/example/net_cloak.git
cd net_cloak
make
sudo make install
```

### Kích hoạt dịch vụ

```bash
sudo systemctl enable --now netcloak
```

## Cách sử dụng

### Bước 1: Khởi động dịch vụ

```bash
# Khởi động với eth0
sudo attach_net_cloak -i eth0
```

### Bước 2: Đặt quota cho cgroup

```bash
# Đặt quota 100MB cho cgroup 10000
sudo cloak_ctl quota 10000 104857600
```

### Bước 3: Bật chế độ che giấu

```bash
# Bật che giấu cho cgroup 10000
sudo cloak_ctl obfuscate 10000 1
```

### Bước 4: Thêm chuyển hướng cổng

```bash
# Chuyển hướng từ cổng 80 sang 8080
sudo cloak_ctl redirect 80 8080
```

### Bước 5: Xem thống kê

```bash
sudo cloak_ctl stats
```

## Hook Points được sử dụng

Net Cloak triển khai tất cả các loại hook sau đây:

1. **XDP (eXpress Data Path)**: Bắt gói sớm nhất có thể, hiệu năng tối ưu
2. **TC (Traffic Control)**: Xử lý gói tin linh hoạt hơn XDP
3. **Cgroup SKB**: Lọc gói theo cgroup (ingress/egress)
4. **LSM (Linux Security Module)**: Tích hợp với hệ thống bảo mật
5. **Kprobe/Tracepoint**: Theo dõi các hàm kernel và sự kiện hệ thống

## Chia sẻ trạng thái giữa các module

Net Cloak hỗ trợ chia sẻ trạng thái với các module eBPF khác như CPU throttle thông qua cơ chế map pinning:

1. **Map được chia sẻ**:
   - `quota_cg`: Kiểm soát quota băng thông cho mỗi cgroup
   - `obfuscate_cg`: Cấu hình che giấu lưu lượng cho mỗi cgroup
   - `events`: Ring buffer chung để gửi sự kiện lên userspace

2. **Vị trí pin**:
   ```
   /sys/fs/bpf/cpu_throttle/quota_cg
   /sys/fs/bpf/cpu_throttle/obfuscate_cg
   /sys/fs/bpf/cpu_throttle/events
   ```

3. **Cách hoạt động**:
   - Khi khởi động, Net Cloak sẽ kiểm tra xem các map đã tồn tại chưa
   - Nếu tồn tại, sẽ tái sử dụng map đó thay vì tạo map mới
   - Nếu chưa tồn tại, sẽ tạo map mới và pin để các module khác có thể sử dụng

4. **Lợi ích**:
   - Đồng bộ quota giữa điều tiết CPU và lưu lượng mạng
   - Tránh trùng lặp dữ liệu và đảm bảo nhất quán
   - Giảm tài nguyên sử dụng trong kernel

## Thiết kế kiến trúc

```
                    +-------------+
                    |  User-space |
                    |  (Control)  |
                    +------+------+
                           |
             +-------------v------------+
             |  Events & Configuration  |
             |  (BPF Maps & Ring buffer)|
             +-------------+------------+
                           |
          +----------------v--------------+
          |                               |
+---------v------+   +-----------+   +----v---------+
| XDP Programs   |   | TC Filter |   | Cgroup Hooks |
+---------+------+   +-----+-----+   +----+---------+
          |                |              |
          +----------------+--------------+
                           |
                    +------v------+
                    | Linux Kernel|
                    +------+------+
                           |
                   +-------v--------+
                   | Network Traffic |
                   +----------------+
```

## Gỡ rối

### Kiểm tra trạng thái dịch vụ

```bash
systemctl status netcloak
```

### Xem logs

```bash
journalctl -u netcloak
```

### Kiểm tra chương trình eBPF đã nạp

```bash
sudo bpftool prog list
```

### Kiểm tra maps được chia sẻ

```bash
sudo bpftool map list
sudo bpftool map dump pinned /sys/fs/bpf/cpu_throttle/quota_cg
```

## Bảo mật

Net Cloak yêu cầu đặc quyền cao (CAP_SYS_ADMIN) để nạp chương trình eBPF. Systemd service đã được cấu hình để giới hạn đặc quyền xuống mức tối thiểu cần thiết.

## Giấy phép

GPL-2.0 