# Nhật Ký Biên Dịch Kernel Tùy Chỉnh cho eBPF

Tài liệu này ghi lại quá trình biên dịch một kernel Linux tùy chỉnh trên nền tảng Ubuntu, với mục tiêu kích hoạt đầy đủ các tính năng cần thiết cho việc phát triển và giám sát bằng công nghệ eBPF (extended Berkeley Packet Filter).

*   **Ngày bắt đầu:** 2024-07-27
*   **Kernel gốc:** `linux-image-unsigned-6.8.0-1030-azure`
*   **Mục tiêu:** Kích hoạt `PSI tracepoints`, `MSR probes`, các `tracepoints` của `cgroup`, và tùy chỉnh tên kernel.

## Giai đoạn 1: Biên Dịch và Cài Đặt Lần Đầu

### 1.1. Tải Mã Nguồn và Biên Dịch

Quá trình bắt đầu bằng việc tải mã nguồn của kernel hiện tại và tiến hành biên dịch các gói `.deb` bằng công cụ chuẩn của Debian/Ubuntu.

```bash
# Tải mã nguồn
apt-get source linux-image-unsigned-6.8.0-1030-azure
cd linux-azure-6.8.0/

# Biên dịch
fakeroot debian/rules binary-headers binary-generic binary-perarch
```

### 1.2. Lỗi Cài Đặt và Cách Khắc Phục

Sau khi biên dịch xong, quá trình cài đặt các gói `.deb` đã gặp lỗi.

*   **Vấn đề:** Gói `linux-modules-extra-6.8.0-1030-azure_6.8.0-1030.31_amd64.deb` không thể cài đặt do thiếu một gói phụ thuộc (dependency) là `wireless-regdb`.
*   **Phân tích:** Lỗi này xảy ra do môi trường xây dựng và môi trường đích thiếu gói cần thiết.
*   **Giải pháp:** Cài đặt thủ công gói bị thiếu và sau đó tiến hành lại việc cài đặt kernel.

```bash
# Cài đặt gói phụ thuộc còn thiếu
sudo apt-get install wireless-regdb

# Cài đặt lại các gói kernel đã biên dịch
sudo dpkg -i linux-headers-*.deb linux-image-*.deb linux-modules-*.deb
```

Sau bước này, hệ thống đã khởi động thành công với kernel mới.

## Giai đoạn 2: Kiểm Tra, Phát Hiện Vấn Đề và Phân Tích Nguyên Nhân

### 2.1. Kiểm Tra Tính Năng eBPF

Sau khi khởi động vào kernel mới, chúng tôi đã sử dụng công cụ `bpftool` để kiểm tra các tính năng đã được kích hoạt. Kết quả cho thấy nhiều tính năng quan trọng vẫn chưa hoạt động như mong đợi.

```bash
sudo bpftool feature probe
```

*   **Kết quả:**
    1.  `PSI tracepoint disabled (not available)`
    2.  `MSR probe disabled (fentry not available)`
    3.  Các `tracepoint` như `cgroup_destroy` và `cgroup_free` không tồn tại trong `/sys/kernel/debug/tracing/events/cgroup/`.

### 2.2. Phân Tích Nguyên Nhân Gốc Rễ

Chúng tôi đã tiến hành phân tích sâu vào tệp cấu hình (`.config`) và các tệp `Kconfig` của kernel để tìm ra nguyên nhân.

1.  **Vấn đề PSI:** Tùy chọn `CONFIG_PSI=y` đã bị hệ thống xây dựng kernel vô hiệu hóa một cách "âm thầm". Nguyên nhân là do nó xung đột với hai tùy chọn khác liên quan đến việc tiết kiệm năng lượng và quản lý `CPU tick`, đó là `CONFIG_CPU_IDLE_GOV_MENU=y` và `CONFIG_NO_HZ_FULL=y`.
2.  **Vấn đề MSR Probe:** Cảnh báo `fentry not available` xuất phát từ việc tùy chọn `CONFIG_X86_KERNEL_IBT=y` (Intel's Indirect Branch Tracking) được bật. Tính năng bảo mật này không tương thích với cơ chế `fentry` mà `MSR probe` yêu cầu.

## Giai đoạn 3: Thử Nghiệm và Tìm Kiếm Giải Pháp Xây Dựng Đúng Đắn

Để khắc phục các vấn đề trên, chúng tôi đã thử nhiều cách tiếp cận khác nhau để tùy chỉnh cấu hình kernel trong quy trình xây dựng của Ubuntu.

### 3.1. Thử nghiệm 1 & 2: Ghi đè toàn bộ tệp `.config` (Thất bại)

*   **Ý tưởng:** Thay thế hoàn toàn tệp `.config` do hệ thống tạo ra bằng một tệp `full.config` đã được sửa lỗi.
*   **Hành động:** Chỉnh sửa tệp `debian/rules.d/2-binary-arch.mk` để sao chép `full.config` vào thư mục xây dựng.
*   **Kết quả:**
    *   **Lần 1:** Lỗi `cp: cannot stat ...` do sai đường dẫn.
    *   **Lần 2 (sau khi sửa đường dẫn):** Quá trình biên dịch thất bại với lỗi `check-config: 5542 config options have changed`.
*   **Kết luận:** Hệ thống xây dựng của Ubuntu có một cơ chế kiểm tra an toàn, ngăn chặn việc thay đổi cấu hình quá đột ngột so với "chính sách" mặc định. Cách tiếp cận này không phù hợp.

### 3.2. Giải Pháp Cuối Cùng: Tạo Bản Vá Cấu Hình Tùy Chỉnh

Chúng tôi nhận ra rằng cách tiếp cận đúng đắn và an toàn nhất là tôn trọng quy trình xây dựng mặc định và chỉ "tiêm" những thay đổi cần thiết vào cuối quá trình tạo cấu hình.

1.  **Hoàn tác:** Khôi phục tệp `debian/rules.d/2-binary-arch.mk` về trạng thái ban đầu.

2.  **Tạo tệp cấu hình mảnh (config snippet):** Tạo một tệp mới tại `debian/config.custom`. Tệp này **chỉ chứa** những thay đổi cần thiết (delta) so với cấu hình mặc định.

    ```makefile
    #
    # Custom config settings for eBPF full features
    #

    # Disable conflicting options to re-enable PSI
    CONFIG_CPU_IDLE_GOV_MENU=n
    CONFIG_NO_HZ_FULL=n

    # Disable IBT to re-enable fentry for MSR probes
    CONFIG_X86_KERNEL_IBT=n

    # Set custom kernel version string
    CONFIG_LOCALVERSION="-azure-full"
    CONFIG_LOCALVERSION_AUTO=n

    # Ensure critical BPF/tracing options are enabled
    CONFIG_PSI=y
    CONFIG_BPF_EVENTS=y
    CONFIG_FTRACE=y
    CONFIG_KPROBE_EVENTS=y
    CONFIG_UPROBE_EVENTS=y
    CONFIG_BPF_KPROBE_OVERRIDE=y
    CONFIG_CGROUPS=y
    CONFIG_CGROUP_BPF=y
    ```

3.  **Áp dụng bản vá:** Sửa đổi tệp `debian/rules.d/2-binary-arch.mk` để nối (append) nội dung của `debian/config.custom` vào cuối tệp `.config` được tạo tự động.

    ```makefile
    # ... các dòng code có sẵn ...
    	find $(builddir) -name .config* -delete
    	cp debian/config.kdump $(builddir)/.config
    # DÒNG THÊM VÀO: Nối cấu hình tùy chỉnh
    	cat debian/config.custom >> $(builddir)/.config
    	$(MAKE) -f debian/rules.real -C $(builddir) olddefconfig
    # ... các dòng code có sẵn ...
    ```

## Tình Trạng Hiện Tại

Môi trường và các kịch bản xây dựng đã được cấu hình một cách chính xác. Các thay đổi cần thiết được áp dụng một cách có chọn lọc mà không phá vỡ quy trình chuẩn của Ubuntu.

**Bước tiếp theo:** Chạy lại quá trình biên dịch để tạo ra các gói kernel mới với đầy đủ tính năng mong muốn.
```bash
fakeroot debian/rules binary-headers binary-generic binary-perarch
``` 