# BPF System Complete Cleanup Script

## Tổng quan

**[cleanup_bpf_system.sh]** (script dọn dẹp hệ thống BPF) là một công cụ hoàn chỉnh để **reset** toàn bộ hệ thống **eBPF** về trạng thái ban đầu. Script này được thiết kế để dọn dẹp tất cả các thành phần eBPF một cách an toàn và có thể rollback.

## Tính năng chính

### 🔧 **[Complete System Reset]** (Reset Hệ thống Hoàn chỉnh)
- Dọn dẹp tất cả **eBPF processes**, **programs**, **maps**, và **pinned objects**
- Không chỉ riêng **hide_process** mà bao gồm tất cả eBPF components
- **System-wide BPF subsystem reset** để đảm bảo clean state

### 🛡️ **[Safety Features]** (Tính năng An toàn)
- **Backup automatic** trước khi thực hiện cleanup
- **Confirmation prompts** cho các thao tác nguy hiểm
- **Dry-run mode** để preview những gì sẽ được thực hiện
- **Rollback capability** nếu có lỗi xảy ra

### 📊 **[Comprehensive Verification]** (Xác minh Toàn diện)
- Kiểm tra không còn **custom BPF programs**
- Xác minh không còn **custom BPF maps**
- Verify **pinned objects** đã được dọn dẹp
- Confirm không còn **eBPF processes** đang chạy

## Cách sử dụng

### Cú pháp cơ bản
```bash
sudo ./cleanup_bpf_system.sh [OPTIONS]
```

### Options
- `-h, --help`: Hiển thị help
- `-n, --dry-run`: Chế độ dry-run (không thực hiện thay đổi thực tế)
- `-f, --force`: Force mode (không hỏi xác nhận)
- `-v, --verbose`: Verbose output
- `--rollback`: Thực hiện rollback từ backup gần nhất

### Ví dụ sử dụng

#### 1. **[Preview Mode]** (Chế độ Xem trước)
```bash
sudo ./cleanup_bpf_system.sh --dry-run --verbose
```
- Xem những gì sẽ được thực hiện mà không thay đổi gì
- Hiển thị chi tiết tất cả components sẽ được dọn dẹp

#### 2. **[Interactive Cleanup]** (Dọn dẹp Tương tác)
```bash
sudo ./cleanup_bpf_system.sh --verbose
```
- Chạy với confirmation prompts
- Cho phép user xác nhận từng phase

#### 3. **[Automated Cleanup]** (Dọn dẹp Tự động)
```bash
sudo ./cleanup_bpf_system.sh --force --verbose
```
- Chạy mà không hỏi confirmations
- Phù hợp cho automation scripts

#### 4. **[Rollback]** (Khôi phục)
```bash
sudo ./cleanup_bpf_system.sh --rollback
```
- Khôi phục từ backup gần nhất
- Hữu ích khi cleanup gặp lỗi

## Các Phase thực hiện

### **Phase 1: Process Cleanup** (Dọn dẹp Tiến trình)
- Tìm và dừng tất cả **eBPF processes**:
  - `hide_process_loader`
  - `hide_process_syncd`
  - `cpu_throttle`
  - `net_cloak`
  - `blk_io_mask`
  - Các `attach_*` processes
- Kill cả **sudo processes** liên quan
- Verify không còn processes nào active

### **Phase 2: BPF Programs Cleanup** (Dọn dẹp Chương trình BPF)
- Detach và unload tất cả **custom BPF programs**
- Giữ lại **system BPF programs** (cgroup_skb, etc.)
- Identify custom programs qua naming patterns:
  - `hide_*`, `on_*`, `enhanced_*`, `hid_*`

### **Phase 3: BPF Maps Cleanup** (Dọn dẹp BPF Maps)
- Clear tất cả **custom BPF maps**:
  - `hidden_pid_map`
  - `events` (ringbuf)
  - `obfuscation_*`
  - `auto_container_*`
  - `proc_dir_filter`
  - `filter_stats`
- Giữ lại **system maps**

### **Phase 4: Pinned Objects Cleanup** (Dọn dẹp Pinned Objects)
- Remove tất cả **pinned objects** trong `/sys/fs/bpf/`
- Dọn dẹp **empty directories**
- Backup pinned objects trước khi xóa

### **Phase 5: System-wide BPF Reset** (Reset BPF Toàn hệ thống)
- **Remount bpffs** để clear state
- Force **garbage collection** của BPF objects
- Clear **kernel caches**

### **Phase 6: Verification** (Xác minh)
- Verify `bpftool prog list` không có custom programs
- Verify `bpftool map list` không có custom maps
- Check `/sys/fs/bpf/` directory clean
- Confirm không còn eBPF processes

## Output và Logging

### **[Log Files]** (File Log)
- Tự động tạo log file: `/tmp/bpf_cleanup_YYYYMMDD_HHMMSS.log`
- Ghi lại tất cả actions và errors
- Timestamp cho mỗi operation

### **[Backup Directory]** (Thư mục Backup)
- Tự động tạo: `/tmp/bpf_backup_YYYYMMDD_HHMMSS/`
- Backup **pinned objects** trước khi xóa
- Backup **programs/maps list** trước cleanup
- Sử dụng cho rollback

### **[Color-coded Output]** (Output Màu sắc)
- 🟢 **GREEN**: INFO messages
- 🟡 **YELLOW**: WARN messages  
- 🔴 **RED**: ERROR messages
- 🔵 **BLUE**: DEBUG messages (với --verbose)

## Troubleshooting

### **[Common Issues]** (Vấn đề Thường gặp)

#### 1. **Permission Denied**
```bash
Error: can't get next program: Operation not permitted
```
**Solution**: Chạy với `sudo`

#### 2. **Programs Still Running**
```bash
ERROR: Vẫn còn eBPF processes đang chạy
```
**Solution**: 
- Check processes: `ps aux | grep -E "(hide_process|cpu_throttle)"`
- Manual kill: `sudo pkill -f hide_process`

#### 3. **Maps Still Exist**
```bash
ERROR: Vẫn còn custom BPF maps
```
**Solution**:
- Programs vẫn đang reference maps
- Ensure tất cả programs đã được unloaded
- Rerun script với `--force`

#### 4. **Pinned Objects Remain**
```bash
WARN: Vẫn còn pinned objects
```
**Solution**:
- Check permissions: `sudo ls -la /sys/fs/bpf/`
- Manual remove: `sudo rm -rf /sys/fs/bpf/cpu_throttle/`

### **[Recovery Steps]** (Bước Khôi phục)

#### Nếu cleanup fails:
1. Check log file: `/tmp/bpf_cleanup_*.log`
2. Identify failed phase
3. Manual cleanup specific components
4. Hoặc rollback: `sudo ./cleanup_bpf_system.sh --rollback`

#### Nếu system unstable sau cleanup:
1. Reboot system để reset kernel state
2. Check kernel logs: `dmesg | grep -i bpf`
3. Verify BPF subsystem: `sudo bpftool prog list`

## Best Practices

### **[Before Running]** (Trước khi Chạy)
1. **Always dry-run first**: `--dry-run --verbose`
2. **Stop applications** sử dụng eBPF
3. **Check system load** - tránh chạy khi system busy
4. **Backup important data** nếu cần

### **[After Running]** (Sau khi Chạy)
1. **Verify clean state**: Check verification output
2. **Test applications**: Ensure không có side effects
3. **Monitor system**: Check performance và stability
4. **Clean up backups**: Remove old backup directories

### **[For Development]** (Cho Development)
- Sử dụng script này để **reset test environment**
- Chạy trước khi test **auto container detection**
- Ensure **clean state** cho reproducible tests

## Security Considerations

### **[Permissions]** (Quyền hạn)
- Script cần **root privileges** để access BPF subsystem
- Backup directory có **restricted permissions**
- Log files chứa **system information** - protect appropriately

### **[Impact]** (Tác động)
- Script sẽ **stop tất cả eBPF functionality**
- Có thể affect **monitoring tools** sử dụng eBPF
- **Network/security policies** có thể bị disrupted temporarily

## Integration với CI/CD

### **[Automated Testing]** (Testing Tự động)
```bash
# Reset environment trước test
sudo ./cleanup_bpf_system.sh --force --verbose

# Run tests
./run_ebpf_tests.sh

# Cleanup sau test
sudo ./cleanup_bpf_system.sh --force
```

### **[Health Checks]** (Kiểm tra Sức khỏe)
```bash
# Verify clean state
if sudo ./cleanup_bpf_system.sh --dry-run | grep -q "ERROR"; then
    echo "System not clean, running cleanup..."
    sudo ./cleanup_bpf_system.sh --force
fi
```

---

## Liên hệ và Hỗ trợ

Nếu gặp vấn đề với script, vui lòng:
1. Check log files trong `/tmp/bpf_cleanup_*.log`
2. Run với `--verbose` để có thêm thông tin
3. Provide log output khi báo cáo issues

**Script Version**: 1.0  
**Last Updated**: 2025-07-03  
**Compatibility**: Ubuntu 22.04, Kernel 6.8+, libbpf v1.4+
