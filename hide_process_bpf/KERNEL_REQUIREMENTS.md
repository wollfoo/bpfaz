# 🔧 **Kernel Requirements and Compatibility Matrix**

## **[Overview]** (Tổng quan)

Tài liệu này mô tả **[kernel configuration requirements]** (yêu cầu cấu hình kernel - các thiết lập kernel cần thiết) và **[compatibility matrix]** (ma trận tương thích - bảng tương thích với các phiên bản kernel) cho dự án **hide_process_bpf**.

## **[Critical Kernel Configurations]** (Cấu hình Kernel Quan trọng)

### **🔴 CRITICAL - Required for Core Functionality**

| Configuration | Required Value | Impact | Solution |
|---------------|----------------|---------|----------|
| `CONFIG_BPF_KPROBE_OVERRIDE` | `y` | **[bpf_override_return()]** (ghi đè giá trị trả về) calls | Recompile kernel |
| `CONFIG_FUNCTION_ERROR_INJECTION` | `y` | **[Error injection]** (tiêm lỗi) support | Recompile kernel |

**⚠️ Without these configurations, hide_process_bpf will NOT work.**

### **🟡 ESSENTIAL - Required for Basic eBPF Support**

| Configuration | Required Value | Impact | Solution |
|---------------|----------------|---------|----------|
| `CONFIG_BPF` | `y` | **[Basic BPF subsystem]** (hệ thống BPF cơ bản) | Install kernel with BPF |
| `CONFIG_BPF_SYSCALL` | `y` | **[BPF system call interface]** (giao diện syscall BPF) | Enable BPF syscalls |
| `CONFIG_KPROBES` | `y` | **[Kernel probes]** (đầu dò kernel) for function interception | Enable kprobes |

### **🟢 IMPORTANT - Recommended for Optimal Performance**

| Configuration | Required Value | Impact | Solution |
|---------------|----------------|---------|----------|
| `CONFIG_BPF_EVENTS` | `y` | **[Enhanced monitoring]** (giám sát nâng cao) | Enable for better performance |
| `CONFIG_TRACEPOINTS` | `y` | **[Syscall interception]** (chặn syscall) | Enable tracepoints |
| `CONFIG_FTRACE` | `y` | **[Function tracing]** (theo dõi hàm) | Enable for debugging |
| `CONFIG_DYNAMIC_FTRACE` | `y` | **[Dynamic tracing]** (theo dõi động) | Performance optimization |
| `CONFIG_HAVE_KPROBES` | `y` | **[Architecture support]** (hỗ trợ kiến trúc) | Architecture-specific |
| `CONFIG_KPROBE_EVENTS` | `y` | **[Event tracing]** (theo dõi sự kiện) | Enhanced functionality |

## **[Runtime Environment Requirements]** (Yêu cầu Môi trường Runtime)

### **🔧 System Requirements**

1. **[BTF Support]** (Hỗ trợ BTF - Binary Type Format):
   - **File**: `/sys/kernel/btf/vmlinux` must be readable
   - **Purpose**: **[Type information]** (thông tin kiểu) for modern eBPF programs
   - **Solution**: Ensure `CONFIG_DEBUG_INFO_BTF=y`

2. **[BPF Filesystem]** (Hệ thống tệp BPF):
   - **Mount**: `/sys/fs/bpf` mounted as `bpf` filesystem
   - **Purpose**: **[Map pinning]** (ghim map) and program persistence
   - **Solution**: `sudo mount -t bpf bpf /sys/fs/bpf`

3. **[Privileges]** (Quyền):
   - **Required**: Root privileges for BPF operations
   - **Alternative**: `CAP_BPF` capability (kernel 5.8+)
   - **Solution**: Run with `sudo` or appropriate capabilities

## **[Compatibility Matrix]** (Ma trận Tương thích)

### **✅ Tested and Supported Kernels**

| Kernel Version | Architecture | Status | Notes |
|----------------|--------------|---------|-------|
| `6.8.0-1026-azure` | x86_64 | ✅ **FULLY SUPPORTED** | Azure-optimized, all features work |
| `6.8.x-generic` | x86_64 | ✅ **SUPPORTED** | Standard Ubuntu kernels |
| `6.5.x-azure` | x86_64 | ⚠️ **PARTIAL** | May lack some optimizations |

### **⚠️ Limited Support Kernels**

| Kernel Version | Architecture | Status | Limitations |
|----------------|--------------|---------|-------------|
| `5.15.x-azure` | x86_64 | ⚠️ **LIMITED** | Missing some BPF features |
| `5.4.x-generic` | x86_64 | ❌ **NOT SUPPORTED** | Lacks critical BPF support |

### **🚫 Unsupported Kernels**

- **Kernel < 5.8**: Missing essential BPF features
- **Non-x86_64 architectures**: Not tested (may work with modifications)
- **Custom kernels**: Depends on configuration

## **[Azure Cloud Specific Considerations]** (Cân nhắc Đặc thù Azure Cloud)

### **🌩️ Azure Environment Optimizations**

1. **[Azure Kernel Features]** (Tính năng Kernel Azure):
   - **Optimized for cloud**: Better performance in Azure VMs
   - **Security enhancements**: Additional security policies may affect BPF
   - **Container support**: Enhanced container runtime integration

2. **[Known Limitations]** (Hạn chế Đã biết):
   - Some BPF features may be restricted by Azure security policies
   - Container environments may have additional limitations
   - Network security groups may affect BPF network operations

3. **[Recommendations]** (Khuyến nghị):
   - Use Azure-optimized kernel images when possible
   - Test in Azure Container Instances for container compatibility
   - Consider Azure security policy implications for production

## **[Validation and Testing]** (Xác thực và Kiểm thử)

### **🔍 Automated Validation**

```bash
# Quick compatibility check
make check-kernel-compat

# Comprehensive validation
make verify-bpf-support

# Strict validation (fails on warnings)
make check-kernel-config
```

### **🧪 Manual Validation**

```bash
# Run validation script directly
./scripts/validate_kernel_config.sh

# With different options
./scripts/validate_kernel_config.sh --comprehensive --azure-mode
./scripts/validate_kernel_config.sh --strict --test-runtime
```

### **📊 Validation Output Interpretation**

| Exit Code | Meaning | Action Required |
|-----------|---------|-----------------|
| `0` | ✅ **All validations passed** | Proceed with deployment |
| `1` | ❌ **Critical errors** | Fix kernel configuration |
| `2` | ⚠️ **Essential errors** | Install missing packages |
| `3` | ⚠️ **Warnings in strict mode** | Consider optimizations |
| `10` | 🔧 **Script execution error** | Check script permissions |

## **[Troubleshooting Guide]** (Hướng dẫn Khắc phục Sự cố)

### **🔧 Common Issues and Solutions**

#### **1. "CONFIG_BPF_KPROBE_OVERRIDE not enabled"**

**Problem**: Critical configuration missing
```
❌ CRITICAL: CONFIG_BPF_KPROBE_OVERRIDE=not_set (expected: y)
   Impact: bpf_override_return() calls will fail
```

**Solutions**:
1. **Recompile kernel** with `CONFIG_BPF_KPROBE_OVERRIDE=y`
2. **Use alternative kernel** with required support
3. **Azure**: Consider custom kernel or alternative approach

#### **2. "No readable kernel configuration file found"**

**Problem**: Cannot find kernel config
```
❌ CRITICAL: No readable kernel configuration file found
   Searched locations: /proc/config.gz /boot/config-* ...
```

**Solutions**:
```bash
# Install kernel headers
sudo apt install linux-headers-$(uname -r)

# Or install generic headers
sudo apt install linux-headers-generic
```

#### **3. "BTF not available"**

**Problem**: Missing BTF support
```
❌ ERROR: BTF not available at /sys/kernel/btf/vmlinux
   Impact: Modern eBPF programs may not load correctly
```

**Solutions**:
1. **Recompile kernel** with `CONFIG_DEBUG_INFO_BTF=y`
2. **Use kernel** with BTF support enabled
3. **Check**: `ls -la /sys/kernel/btf/`

#### **4. "BPF filesystem not mounted"**

**Problem**: BPF filesystem not available
```
⚠️ WARN: BPF filesystem not mounted
   Impact: BPF map pinning may not work
```

**Solutions**:
```bash
# Mount BPF filesystem
sudo mount -t bpf bpf /sys/fs/bpf

# Make persistent
echo "bpf /sys/fs/bpf bpf defaults 0 0" | sudo tee -a /etc/fstab
```

### **🚀 Performance Optimization Tips**

1. **[Enable all recommended configs]** (Bật tất cả cấu hình khuyến nghị):
   ```bash
   # Check current status
   ./scripts/validate_kernel_config.sh --comprehensive
   ```

2. **[Use Azure-optimized kernels]** (Sử dụng kernel tối ưu Azure):
   ```bash
   # Check current kernel
   uname -r
   # Should show: *-azure
   ```

3. **[Monitor BPF performance]** (Giám sát hiệu suất BPF):
   ```bash
   # Check BPF program performance
   sudo bpftool prog show
   sudo bpftool map show
   ```

## **[Development and Testing Environment Setup]** (Thiết lập Môi trường Phát triển và Kiểm thử)

### **🛠️ Recommended Development Setup**

```bash
# 1. Validate kernel compatibility
make check-kernel-config

# 2. Setup development environment
sudo ./scripts/setup_dev_environment.sh --comprehensive

# 3. Build and test
make all
make test-standalone

# 4. Verify functionality
sudo make install
```

### **🧪 Testing in Different Environments**

1. **[Local Development]** (Phát triển Cục bộ):
   - Use `make check-kernel-compat` before development
   - Test with `make test-standalone`

2. **[Azure VM Testing]** (Kiểm thử Azure VM):
   - Use `--azure-mode` flag for validation
   - Test container compatibility

3. **[Production Deployment]** (Triển khai Sản xuất):
   - Run `make verify-bpf-support` before deployment
   - Monitor system logs for BPF-related issues

---

## **[Conclusion]** (Kết luận)

**[Kernel configuration validation]** (xác thực cấu hình kernel) là **[critical step]** (bước quan trọng) để đảm bảo **hide_process_bpf** hoạt động đúng. Sử dụng **[automated validation tools]** (công cụ xác thực tự động) được cung cấp để:

### **✅ Key Benefits**
- **Early detection** of compatibility issues
- **Automated validation** integrated into build process  
- **Comprehensive troubleshooting** guidance
- **Azure cloud optimization** for production deployments
- **Performance optimization** recommendations

### **🎯 Best Practices**
- Always run validation before deployment
- Use Azure-optimized kernels in cloud environments
- Monitor BPF subsystem performance in production
- Keep kernel and BPF tools updated for security
