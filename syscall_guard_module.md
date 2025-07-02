# Syscall Guard Module

> Hợp nhất các tùy chọn nâng cao trùng với **[LSM Hide Module]** (Module BPF-LSM ẩn tiến trình) để tạo module mới **[Syscall Guard Module]** (Module chặn theo dõi syscall) – tập trung ngăn debugger, trình phân tích hiệu năng, và truy vấn BPF khỏi tiến trình Miner.

## 1️⃣ Mục tiêu & Phạm vi
* Ẩn tiến trình Miner **thêm một lớp**: chặn mọi nỗ lực quan sát động (dynamic-inspection) như **[strace]** (Công cụ theo dõi hệ thống gọi), **[perf]** (Trình phân tích hiệu năng), **[bpftool]** (Công cụ thao tác BPF).
* Giảm footprint: dùng chung **BPF_MAP** `target_cgrp_id` với LSM Hide; không cần nạp lại price toàn bộ map.

## 2️⃣ Các Hook LSM/BPF Chính
| Hook | Chức năng | Quyết định trả về | Ghi chú |
|------|-----------|-------------------|---------|
| **[ptrace_access_check]** (Hàm kiểm tra quyền gỡ lỗi) | Kiểm tra khi tiến trình A cố gắng gắn PTRACE vào tiến trình B | Nếu `current->cgroupid == TARGET_CGID` **hoặc** `B->cgroupid == TARGET_CGID` ⇒ `-EPERM` | Ngăn **strace/gdb/ltrace** |
| **[security_bpf]** (LSM hook cho syscall `bpf()`) | Kiểm soát thao tác BPF toàn cục | Từ chối `BPF_PROG_GET_FD_BY_ID`, `BPF_MAP_GET_FD_BY_ID`, `BPF_OBJ_GET_INFO_BY_FD` khi PID truy vấn != root và `TARGET_CGID` "đang ẩn" ⇒ `-EPERM` | Che giấu chương trình/map khỏi bpftool |
| **[perf_event_open]** (fentry kprobe) | Được gọi khi tạo perf event | Nếu `current->cgroupid == TARGET_CGID` ⇒ `-EPERM` | Ngăn đo đạc CPU samples |

> **Lưu ý**: Kernel ≥ 5.8 đã cung cấp LSM hook `security_bpf`. Với 6.8 có đủ chức năng.

## 3️⃣ Kiến trúc Module
```
+-------------------------+
| Userspace Loader        |  <-- cập nhật map target_cgrp_id
+-------------------------+
           |
           v
+-------------------------+
| BPF_MAP target_cgrp_id  |  <-- dùng chung với LSM Hide
+-------------------------+
   ^          ^           ^
   |          |           |
   |  ptrace_access_check |
   |  security_bpf        |
   |  fentry perf_event   |
+--+----------------------+--+
|   Syscall Guard Module     |
+----------------------------+
```

### 3.1 Re-use Map
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgrp_id SEC(".maps");
```

### 3.2 Chương trình LSM Sleepable
```c
SEC("lsm.s/ptrace_access_check")
int BPF_PROG(block_ptrace, struct task_struct *child, unsigned int mode) {
    if (!is_hidden_cgroup())
        return 0;
    return -EPERM;
}
```

### 3.3 Hook security_bpf
```c
SEC("lsm.s/bpf")
int BPF_PROG(block_bpf_syscall, int cmd, union bpf_attr *attr, unsigned int size) {
    if (!is_hidden_cgroup())
        return 0;
    if (cmd == BPF_PROG_GET_FD_BY_ID || ... )
        return -EPERM;
    return 0;
}
```

### 3.4 fentry trên perf_event_open
```c
SEC("fentry/__x64_sys_perf_event_open")
int BPF_PROG(block_perf_event) {
    if (!is_hidden_cgroup())
        return 0;
    return -EPERM;
}
```

## 4️⃣ Xung đột Tiềm tàng & Cách giải quyết
1. **Double-attach** LSM: Kernel cho phép **nhiều** chương trình trên cùng hook nếu cài đặt `CONFIG_BPF_LSM_MULTI`. Nếu không, _hợp nhất_ logic của LSM Hide & Syscall Guard thành **một** file `.bpf.c`.
2. **Verifier Stack Limit**: 3 hook + 1 helper vẫn an toàn (< 512 B stack). Dùng thuộc tính `__always_inline` & `relaxed_maps`.
3. **Khả năng bị phát hiện bởi bpftool**: Thiết lập quyền thư mục pin `/run/.hidden/lsm_guard` và `chmod 0` như đã khuyến nghị.

## 5️⃣ Makefile Bổ sung
Sửa `ebpf_build/lsm_hide/Makefile` thành:
```make
all: lsm_hide.bpf.o syscall_guard.bpf.o loader
```
… và build `syscall_guard.bpf.c`.

## 6️⃣ Trình Tải (Loader) – cập nhật duy nhất
Không cần loader riêng; `lsm_hide_loader` hiện tại chỉ cần **link thêm** object `syscall_guard.bpf.o`:
```c
obj = bpf_object__open_file("lsm_hide.bpf.o", &opts);
obj2 = bpf_object__open_file("syscall_guard.bpf.o", &opts);
```
Sau khi `bpf_object__load()` hai object, cùng cập nhật map.

## 7️⃣ Kiểm thử
* **strace**: `strace -p <Miner-PID>` ⇒ `strace: attach: Operation not permitted` (EPERM).
* **perf**: `perf top -p <Miner>` ⇒ `Failed to open perf event: Operation not permitted`.
* **bpftool**: `bpftool prog show` (với quyền user) không hiển thị chương trình.

## 8️⃣ Kết luận
Module **Syscall Guard** bọc thêm một lớp che chắn tiến trình Miner khỏi các công cụ quan sát động. Việc chia sẻ map giúp footprint nhỏ, triển khai đơn giản, không trùng lặp logic với LSM Hide. 
