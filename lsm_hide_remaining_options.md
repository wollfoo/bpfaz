# Tuỳ chọn nâng cao **chưa** tích hợp vào LSM Hide Module

> Danh sách này bao gồm các kỹ thuật nâng cao (đã nêu từ 1 ➔ 15) **nhưng chưa được đưa vào** LSM Hide Module sau giai đoạn nâng cấp. Mỗi mục gồm: mô tả, lợi ích, rủi ro, mức độ phức tạp triển khai.

| # | Tuỳ chọn | Mô tả (tiếng Việt) | Lợi ích chính | Rủi ro / Phức tạp | Đề xuất triển khai riêng |
|---|----------|--------------------|---------------|-------------------|--------------------------|
| 7 | **[cgroup_bpf_attach]** (Gắn BPF filter vào cgroup) | Gắn chương trình BPF ở chế độ `cgroup/skb`, `cgroup/sysctl`,… cho cgroup Miner nhằm hạn chế syscalls/IO khi Miner di chuyển sang cgroup khác. | • Khoá phạm vi syscalls<br/>• Bảo vệ khi PID bị "reparent" | • Cần CAP_BPF & `cgroup_bpf`; chồng chéo logic nếu LSM Hide đã phủ PID.<br/>• Verifier yêu cầu stack nhỏ ( <128B ) ở cgroup/ hooks. | Tạo module phụ `cgroup_limit.bpf.c` + loader cập nhật cùng map `target_cgrp_id`. |
| 8 | **[sock_ops v4]** (BPF `sock_ops`/`skmsg`) | Hook `BPF_PROG_TYPE_SOCK_OPS` vào sự kiện TCP (`TCP_CONNECT`, `TCP_LISTEN`) để sửa đổi `sport/dport` hoặc droplog gói của Miner, ẩn luồng mạng khỏi `/proc/net/tcp`. | • Che giấu kết nối mạng (mining pool).<br/>• Có thể chặn scan cổng. | • Yêu cầu BPF `sock_ops` (kernel ≥4.13).<br/>• Verifier khó (need XDP helpers).<br/>• Delay latency nếu xử lý sai. | Tách thành `net_hide.bpf.c`; dùng map `target_cgrp_id` để lọc cgroup. |
| 11 | **[Kernel Symbol Hiding]** (Ẩn symbol trong BTF/sysfs) | Thay đổi quyền pin object `/sys/fs/bpf`, đặt **chmod 0** hoặc gắn vào path ẩn; tùy kernel patch `CONFIG_SECURITY_BPFLSM_HIDE` để chặn `bpftool prog show`. | • Giảm khả năng người dùng thường thấy chương trình BPF.<br/>• Bịt lỗ audit `bpf_obj_get_info_by_fd`. | • Yêu cầu quyền root + remount sysfs.<br/>• Patch kernel (compile-time) nếu bật tùy chọn. | Thực hiện hoàn toàn trong loader người dùng (shell script) – không cần thay đổi LSM Hide. |
| 12 | **[NVML-spoof]** (Giả lập mức sử dụng GPU thấp) | Dùng `LD_PRELOAD` chặn hàm `nvmlDeviceGetUtilizationRates` & bạn bè, trả về giá trị thấp; đồng bộ với CPU throttling. | • Tránh cảnh báo GPU/telemetry (datacenter, cloud). | • Không phải BPF; phụ thuộc libc loader.<br/>• Có thể bị phát hiện qua checksum LD_PRELOAD. | Tạo thư viện `libnvml_spoof.so`; tự inject thông qua `LD_PRELOAD` khi khởi động Miner. |
| 13 | **[Thermal Noise Injection]** (Tiêm nhiễu dữ liệu nhiệt độ) | Hook `kprobe:hwmon_read` hoặc chỉnh sửa giá trị đọc được từ `/sys/class/hwmon/.../temp` để dao động ±3 °C. | • Che giấu mức tăng nhiệt bất thường. | • Đọc/ghi user-space file → phải dùng `BPF_LSM_FILE_PERMISSION` (kernel 6.8).<br/>• Verifier cấm ghi trực tiếp userspace, cần helper `bpf_ima_inode_setxattr` → phức tạp. | Tách module `thermal_mask.bpf.c`; chỉ build khi kernel hỗ trợ helper mới. |
| 14 | **[Dynamic Clock Modulation]** (Điều tiết xung CPU thời gian thực) | Kết hợp với "CPU Throttler": hạ `cpufreq` bằng giao diện `cpufreq_set_policy` hoặc MSR `IA32_PERF_CTL` theo burst. | • Mô phỏng workload hợp lệ, giảm tiêu thụ điện & nhiệt. | • Yêu cầu quyền `CAP_SYS_NICE` + `wrmsr`.<br/>• Risk "hang" hệ thống nếu chỉnh sai. | Giữ logic trong user-space daemon (đã có `attach_throttle_v2`) → không cần thêm vào LSM Hide. |
| 15 | **[Process Namespace Pivot]** (Chạy Miner trong PID-NS riêng) | Fork Miner bên trong **PID Namespace** + mount `/proc` riêng → `ps/top` trên host không thấy PID. | • Ẩn hoàn toàn PID khỏi host namespace.<br/>• Tăng cô lập. | • Không phải BPF; thao tác namespace cần setuid or `unshare(CLONE_NEWPID)`. | Thực hiện qua wrapper shell `minerd --namespace-pivot` + cgroup id vẫn nhận diện bởi LSM Hide.

---
## Tổng kết
- **Không tích hợp** các kỹ thuật trên vào LSM Hide nhằm giữ **kích thước chương trình nhỏ**, tránh vượt giới hạn verifier & giảm rủi ro xung đột.
- Chúng phù hợp dưới dạng **module phụ** hoặc **userspace helper**, chia nhỏ trách nhiệm:
  * LSM Hide: ẩn `/proc` & thuộc tính tiến trình.
  * Syscall Guard: chặn debug/bpf/perf.
  * Các module phụ trên xử lý mạng, GPU, nhiệt độ, clock, & namespace.
- Triển khai rời rạc giúp dễ bật/tắt tuỳ nhu cầu, và giảm diện tấn công khi không cần thiết. 