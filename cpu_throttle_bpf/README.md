# Enhanced Dynamic CPU Quota System

🚀 **Production-ready eBPF-based CPU throttling system** với auto-detection và dynamic quota management cho Docker containers.

## ✨ Features

### 🎯 **Dynamic Quota System**
- **6 CPU cores default limit** - Auto-assign 600000000 ns quota
- **Auto-detection containers** - Comprehensive Docker container scanning
- **Real-time monitoring** - Continuous cgroup scanning mỗi 5 giây
- **Dynamic adjustment** - PSI, temperature, IPC, burst mode adaptation

### 🛡️ **Enhanced CPU Throttling**
- **NO SIGSTOP** - Process preservation với CPU limiting only
- **util_clamp + cgroup backup** - Dual throttling mechanism
- **Aggressive thresholds** - 5% buffer + extreme throttling cho 8+ cores
- **BPF cgroup detection fix** - Giải quyết kernel 6.8.0-1026-azure mismatch

### 🔍 **Comprehensive Detection**
- **Multiple cgroup IDs** - Detect tất cả cgroup IDs mà container sử dụng
- **Process-level scanning** - Scan `/proc` để tìm container processes
- **Alternative detection** - Backup detection cho mining processes
- **Enhanced fallback** - 24 candidates mapping cho unknown cgroups

## 🏗️ **Architecture**

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Docker        │    │   Cgroup         │    │   BPF           │
│   Containers    │───▶│   Scanner        │───▶│   Throttling    │
│                 │    │   (Userspace)    │    │   (Kernel)      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌────────▼────────┐             │
         │              │  Auto-Detection │             │
         │              │  & Quota Setup  │             │
         │              └─────────────────┘             │
         │                                              │
         └──────────────────────────────────────────────▼
                        CPU Usage: 800% → 600%
                        (8+ cores → 6 cores limit)
```

## 🚀 **Quick Start**

### Prerequisites
- Ubuntu với kernel 6.8.0+
- BPF development tools
- Docker runtime
- Root privileges

### Environment Setup
```bash
# Automated BPF environment setup
cd setup_bpf_environment
sudo ./ebpf_one_shot_setup.sh

# Verify environment
sudo ./verify_environment.sh
```

### Build
```bash
make clean && make all
```

### Deploy
```bash
# Khởi động dynamic quota system
sudo bash -c 'nohup ./obj/attach_throttle --verbose --interval=50 --debug > /var/log/cpu_throttle.log 2>&1 < /dev/null &'

# Tạo test container
sudo docker run -d --name miner --security-opt seccomp=unconfined xmrig/xmrig [options]

# Monitor throttling
sudo tail -f /var/log/cpu_throttle.log
```

## 📊 **Performance Results**

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| **CPU Usage** | 800%+ | ~600% | ✅ 25% reduction |
| **Process Survival** | ❌ Killed | ✅ Preserved | ✅ 100% uptime |
| **Auto-Detection** | ❌ Manual | ✅ Automatic | ✅ Zero config |
| **Throttling Method** | ❌ SIGSTOP | ✅ CPU Limiting | ✅ Gentle control |

## 🛠️ **Tools**

### Core Tools
#### `attach_throttle`
Main daemon với comprehensive cgroup detection và auto-throttling.

#### `throttle_ctl`
Control tool cho monitoring và system status:
```bash
./obj/throttle_ctl status    # System status
./obj/throttle_ctl monitor   # Real-time monitoring
```

### Setup Tools (`setup_bpf_environment/`)
#### `ebpf_one_shot_setup.sh`
Automated BPF environment setup - installs all dependencies và configures system.

#### `verify_environment.sh`
Validates BPF environment và kernel configuration.

#### `cleanup_bpf_system.sh`
Removes BPF development tools và cleans up system.

#### `rollback_environment.sh`
Rollback system changes made by setup scripts.

## 🔧 **Configuration**

### Default Settings
- **CPU Limit**: 6 cores (600000000 ns)
- **Scan Interval**: 5 seconds
- **Throttle Threshold**: 5% buffer (630000000 ns)
- **Extreme Threshold**: 33% buffer (800000000 ns)

### Advanced Tuning
- **PSI Integration**: Automatic load-based adjustment
- **Temperature Monitoring**: Thermal-aware throttling
- **IPC Efficiency**: Performance-based optimization
- **Burst Mode**: Temporary quota increase

## 📝 **Logs & Monitoring**

```bash
# Real-time logs
sudo tail -f /var/log/cpu_throttle.log

# BPF debug messages
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep throttle

# Container CPU usage
top -bn1 | grep xmrig
```

## 🎯 **Use Cases**

- **Container CPU limiting** - Prevent containers từ monopolizing CPU
- **Mining process control** - Throttle cryptocurrency miners
- **Resource management** - Dynamic quota allocation
- **System protection** - Prevent CPU starvation

## 🔬 **Technical Details**

### BPF Programs
- **Tracepoint**: `sched_switch` event hooking
- **Maps**: `quota_cg`, `acc_cg` cho quota tracking
- **Helper**: Enhanced cgroup ID detection

### Kernel Compatibility
- **Tested**: Ubuntu kernel 6.8.0-1026-azure
- **Required**: BPF CO-RE support
- **Cgroups**: v1 CPU subsystem

## 🤝 **Contributing**

1. Fork repository
2. Create feature branch
3. Test với real containers
4. Submit pull request

## 📄 **License**

MIT License - See LICENSE file for details.

---

**🎉 Enhanced Dynamic CPU Quota System** - Production-ready eBPF throttling với zero-config auto-detection!
