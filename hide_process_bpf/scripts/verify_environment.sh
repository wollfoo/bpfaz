#!/bin/bash
# verify_environment.sh - Comprehensive eBPF Environment Verification
# Script xác minh môi trường eBPF toàn diện cho hide_process_bpf
#
# Usage: ./verify_environment.sh [--detailed] [--fix-issues]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
DETAILED_MODE=false
FIX_ISSUES=false
SCORE=0
MAX_SCORE=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((SCORE++))
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_detail() {
    if [[ "$DETAILED_MODE" == "true" ]]; then
        echo -e "${PURPLE}[DETAIL]${NC} $1"
    fi
}

# Parse arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --detailed)
                DETAILED_MODE=true
                shift
                ;;
            --fix-issues)
                FIX_ISSUES=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Verify eBPF development environment for hide_process_bpf compilation.

OPTIONS:
    --detailed          Show detailed information for each check
    --fix-issues        Attempt to fix minor issues automatically
    -h, --help          Show this help message

EXAMPLES:
    $0                  # Basic verification
    $0 --detailed       # Detailed verification with extra info
    $0 --fix-issues     # Fix minor issues automatically

EOF
}

# Banner
print_banner() {
    echo "================================================================"
    echo "  🔍 eBPF Environment Verification for hide_process_bpf"
    echo "  Target: Complete compilation readiness assessment"
    echo "================================================================"
    echo ""
}

# Check system basics
check_system_basics() {
    log_info "Checking system basics..."
    ((MAX_SCORE += 4))
    
    # OS version
    if grep -q "Ubuntu 22.04" /etc/os-release; then
        log_success "Ubuntu 22.04 detected"
        log_detail "OS: $(lsb_release -d | cut -f2)"
    else
        log_error "Not Ubuntu 22.04 (compatibility may be limited)"
        log_detail "Current OS: $(lsb_release -d | cut -f2 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME)"
    fi
    
    # Kernel version
    local kernel_version=$(uname -r)
    local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
    
    if [[ $kernel_major -gt 6 ]] || [[ $kernel_major -eq 6 && $kernel_minor -ge 8 ]]; then
        log_success "Kernel $kernel_version (>= 6.8 required)"
    else
        log_error "Kernel $kernel_version < 6.8 (upgrade required)"
    fi
    
    # Architecture
    if [[ "$(uname -m)" == "x86_64" ]]; then
        log_success "x86_64 architecture"
    else
        log_error "Architecture $(uname -m) not supported"
    fi
    
    # Root privileges check
    if [[ $EUID -eq 0 ]]; then
        log_success "Running with root privileges"
    else
        log_warning "Not running as root (some checks may be limited)"
    fi
    
    echo ""
}

# Check clang compiler
check_clang() {
    log_info "Checking clang compiler..."
    ((MAX_SCORE += 3))
    
    if command -v clang >/dev/null 2>&1; then
        local clang_version=$(clang --version | head -1)
        local version_number=$(echo "$clang_version" | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local major_version=$(echo "$version_number" | cut -d. -f1)
        
        if [[ $major_version -ge 15 ]]; then
            log_success "clang v$version_number (>= v15.0 required)"
            log_detail "$clang_version"
        else
            log_error "clang v$version_number < v15.0 (upgrade required)"
        fi
        
        # Test BPF target support
        if echo 'int main() { return 0; }' | clang -target bpf -c -x c - -o /tmp/test_bpf.o 2>/dev/null; then
            log_success "BPF target support working"
            rm -f /tmp/test_bpf.o
        else
            log_error "BPF target support failed"
        fi
        
        # Check LLVM tools
        if command -v llc >/dev/null 2>&1; then
            log_success "LLVM tools available"
            log_detail "llc: $(llc --version | head -1)"
        else
            log_warning "LLVM tools not found (may affect advanced compilation)"
        fi
        
    else
        log_error "clang not found (installation required)"
        if [[ "$FIX_ISSUES" == "true" ]]; then
            log_info "Attempting to install clang..."
            if apt update -qq && apt install -y clang llvm; then
                log_success "clang installed successfully"
            else
                log_error "Failed to install clang"
            fi
        fi
    fi
    
    echo ""
}

# Check gcc compiler optimization
check_gcc_optimization() {
    log_info "Checking gcc compiler optimization..."
    ((MAX_SCORE += 3))

    if command -v gcc >/dev/null 2>&1; then
        local gcc_version=$(gcc --version | head -1)
        local version_number=$(echo "$gcc_version" | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local major_version=$(echo "$version_number" | cut -d. -f1)

        if [[ $major_version -ge 12 ]]; then
            log_success "gcc v$version_number (>= v12.0 for BPF optimization)"
            log_detail "$gcc_version"
        else
            log_warning "gcc v$version_number < v12.0 (optimization recommended)"
        fi

        # Test optimization flags
        if echo 'int main() { return 0; }' | gcc -O2 -march=native -c -x c - -o /tmp/test_gcc_opt.o 2>/dev/null; then
            log_success "gcc optimization flags working"
            rm -f /tmp/test_gcc_opt.o
        else
            log_warning "gcc optimization flags test failed"
        fi

        # Check alternatives configuration
        if update-alternatives --query gcc >/dev/null 2>&1; then
            log_success "gcc alternatives configured"
            if [[ "$DETAILED_MODE" == "true" ]]; then
                local alternatives_info=$(update-alternatives --query gcc 2>/dev/null | grep "Value:" | head -1)
                log_detail "Current alternative: $alternatives_info"
            fi
        else
            log_warning "gcc alternatives not configured"
        fi

    else
        log_error "gcc not found (installation required)"
        if [[ "$FIX_ISSUES" == "true" ]]; then
            log_info "Attempting to install gcc-12..."
            if apt update -qq && apt install -y gcc-12 g++-12; then
                update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 120
                update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 120
                log_success "gcc-12 installed and configured"
            else
                log_error "Failed to install gcc-12"
            fi
        fi
    fi

    echo ""
}

# Check libbpf
check_libbpf() {
    log_info "Checking libbpf library..."
    ((MAX_SCORE += 4))
    
    # Check if libbpf is available
    if ldconfig -p | grep -q "libbpf"; then
        log_success "libbpf library found"
        
        # Check version
        if ldconfig -p | grep -q "libbpf.so.1.4"; then
            log_success "libbpf v1.4.x detected"
        elif ldconfig -p | grep -q "libbpf.so.0"; then
            log_warning "libbpf v0.x detected (v1.4.0+ recommended)"
        else
            log_warning "libbpf version unclear"
        fi
        
        # Show library details
        if [[ "$DETAILED_MODE" == "true" ]]; then
            log_detail "Library paths:"
            ldconfig -p | grep libbpf | while read line; do
                log_detail "  $line"
            done
        fi
        
        # Check development headers
        if [[ -d /usr/include/bpf ]]; then
            log_success "libbpf development headers found"
            if [[ "$DETAILED_MODE" == "true" ]]; then
                local header_count=$(find /usr/include/bpf -name "*.h" | wc -l)
                log_detail "Header files: $header_count found"
            fi
        else
            log_error "libbpf development headers missing"
        fi
        
        # Check pkg-config
        if pkg-config --exists libbpf 2>/dev/null; then
            log_success "libbpf pkg-config available"
            if [[ "$DETAILED_MODE" == "true" ]]; then
                local pkg_version=$(pkg-config --modversion libbpf 2>/dev/null || echo "unknown")
                log_detail "pkg-config version: $pkg_version"
            fi
        else
            log_warning "libbpf pkg-config not found"
        fi
        
    else
        log_error "libbpf library not found"
        if [[ "$FIX_ISSUES" == "true" ]]; then
            log_info "Attempting to install libbpf..."
            if apt update -qq && apt install -y libbpf0 libbpf-dev; then
                log_success "libbpf installed successfully"
            else
                log_error "Failed to install libbpf"
            fi
        fi
    fi
    
    echo ""
}

# Check development packages
check_dev_packages() {
    log_info "Checking development packages..."
    
    local packages=(
        "libbpf-dev:libbpf development headers"
        "libelf-dev:ELF library development headers"
        "zlib1g-dev:zlib compression library headers"
        "build-essential:Essential build tools"
        "pkg-config:Package configuration tool"
        "git:Version control system"
        "cmake:Cross-platform build system"
    )
    
    ((MAX_SCORE += ${#packages[@]}))
    
    for package_info in "${packages[@]}"; do
        local package=$(echo "$package_info" | cut -d: -f1)
        local description=$(echo "$package_info" | cut -d: -f2)
        
        if dpkg -l | grep -q "^ii  $package "; then
            log_success "$package installed"
            if [[ "$DETAILED_MODE" == "true" ]]; then
                local version=$(dpkg -l | grep "^ii  $package " | awk '{print $3}')
                log_detail "$description - version: $version"
            fi
        else
            log_error "$package missing"
            if [[ "$FIX_ISSUES" == "true" ]]; then
                log_info "Installing $package..."
                if apt install -y "$package"; then
                    log_success "$package installed"
                else
                    log_error "Failed to install $package"
                fi
            fi
        fi
    done
    
    echo ""
}

# Check kernel configuration
check_kernel_config() {
    log_info "Checking kernel configuration..."
    
    local required_configs=(
        "CONFIG_BPF=y:Core BPF support"
        "CONFIG_BPF_SYSCALL=y:BPF syscall interface"
        "CONFIG_KPROBES=y:Kernel probes support"
        "CONFIG_BPF_KPROBE_OVERRIDE=y:BPF kprobe override (critical)"
        "CONFIG_FUNCTION_ERROR_INJECTION=y:Function error injection"
        "CONFIG_BPF_LSM=y:BPF LSM support"
        "CONFIG_BPF_JIT=y:BPF JIT compilation"
    )
    
    ((MAX_SCORE += ${#required_configs[@]}))
    
    # Find kernel config file
    local config_file=""
    if [[ -f /proc/config.gz ]]; then
        config_file="/proc/config.gz"
    elif [[ -f "/boot/config-$(uname -r)" ]]; then
        config_file="/boot/config-$(uname -r)"
    elif [[ -f "/usr/src/linux-headers-$(uname -r)/.config" ]]; then
        config_file="/usr/src/linux-headers-$(uname -r)/.config"
    else
        log_warning "Kernel config file not found - skipping config checks"
        return 0
    fi
    
    log_detail "Using config file: $config_file"
    
    for config_info in "${required_configs[@]}"; do
        local config=$(echo "$config_info" | cut -d: -f1)
        local description=$(echo "$config_info" | cut -d: -f2)
        
        local found=false
        if [[ $config_file == *.gz ]]; then
            if zgrep -q "^$config" "$config_file"; then
                found=true
            fi
        else
            if grep -q "^$config" "$config_file"; then
                found=true
            fi
        fi
        
        if [[ "$found" == "true" ]]; then
            log_success "$config"
            log_detail "$description"
        else
            log_error "$config missing"
            log_detail "$description - REQUIRED for hide_process_bpf"
        fi
    done
    
    echo ""
}

# Check BPF infrastructure
check_bpf_infrastructure() {
    log_info "Checking BPF infrastructure..."
    ((MAX_SCORE += 4))
    
    # BTF support
    if [[ -r /sys/kernel/btf/vmlinux ]]; then
        log_success "Kernel BTF available"
        if [[ "$DETAILED_MODE" == "true" ]]; then
            local btf_size=$(stat -c%s /sys/kernel/btf/vmlinux 2>/dev/null || echo "unknown")
            log_detail "BTF size: $btf_size bytes"
        fi
    else
        log_error "Kernel BTF not available"
    fi
    
    # BPF filesystem
    if mount | grep -q "bpf on /sys/fs/bpf"; then
        log_success "BPF filesystem mounted"
        if [[ "$DETAILED_MODE" == "true" ]]; then
            local mount_info=$(mount | grep "bpf on /sys/fs/bpf")
            log_detail "$mount_info"
        fi
    else
        log_error "BPF filesystem not mounted"
        if [[ "$FIX_ISSUES" == "true" ]] && [[ $EUID -eq 0 ]]; then
            log_info "Mounting BPF filesystem..."
            if mount -t bpf bpf /sys/fs/bpf; then
                log_success "BPF filesystem mounted"
            else
                log_error "Failed to mount BPF filesystem"
            fi
        fi
    fi
    
    # bpftool
    if command -v bpftool >/dev/null 2>&1; then
        log_success "bpftool available"
        if [[ "$DETAILED_MODE" == "true" ]]; then
            local bpftool_version=$(bpftool version 2>/dev/null | head -1 || echo "version unknown")
            log_detail "$bpftool_version"
        fi
        
        # Test bpftool functionality
        if bpftool prog list >/dev/null 2>&1; then
            log_success "bpftool functionality working"
        else
            log_warning "bpftool functionality test failed"
        fi
    else
        log_error "bpftool not found"
    fi
    
    echo ""
}

# Test compilation capability
test_compilation() {
    log_info "Testing compilation capability..."
    ((MAX_SCORE += 3))

    # Create test directory
    local test_dir="/tmp/bpf_verify_test_$$"
    mkdir -p "$test_dir"
    cd "$test_dir"

    # Test basic BPF compilation
    cat > test_basic.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_openat")
int test_openat(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    if clang -target bpf -O2 -c test_basic.c -o test_basic.o 2>/dev/null; then
        log_success "Basic BPF compilation working"
    else
        log_error "Basic BPF compilation failed"
    fi

    # Test advanced BPF features
    cat > test_advanced.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} test_map SEC(".maps");

SEC("kprobe/do_sys_openat2")
int test_kprobe(struct pt_regs *ctx) {
    u32 key = 1, value = 1;
    bpf_map_update_elem(&test_map, &key, &value, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    if clang -target bpf -O2 -c test_advanced.c -o test_advanced.o 2>/dev/null; then
        log_success "Advanced BPF features compilation working"
    else
        log_warning "Advanced BPF features compilation failed"
    fi

    # Test hide_process_bpf specific compilation
    local hide_process_dir="$(dirname "$0")/.."
    if [[ -f "$hide_process_dir/hide_process_bpf.c" ]]; then
        cd "$hide_process_dir"
        if make clean >/dev/null 2>&1 && make test >/dev/null 2>&1; then
            log_success "hide_process_bpf compilation working"
        else
            log_error "hide_process_bpf compilation failed"
        fi
    else
        log_warning "hide_process_bpf.c not found - skipping specific test"
    fi

    # Cleanup
    cd /
    rm -rf "$test_dir"

    echo ""
}

# Check system resources
check_system_resources() {
    log_info "Checking system resources..."
    ((MAX_SCORE += 3))

    # Memory
    local total_mem=$(free -m | awk 'NR==2{print $2}')
    if [[ $total_mem -ge 2048 ]]; then
        log_success "Memory: ${total_mem}MB (>= 2GB recommended)"
    elif [[ $total_mem -ge 1024 ]]; then
        log_warning "Memory: ${total_mem}MB (2GB+ recommended for compilation)"
    else
        log_error "Memory: ${total_mem}MB (insufficient for compilation)"
    fi

    # Disk space
    local available_space=$(df /tmp 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    local space_mb=$((available_space / 1024))
    if [[ $space_mb -ge 500 ]]; then
        log_success "Disk space: ${space_mb}MB available (>= 500MB required)"
    else
        log_error "Disk space: ${space_mb}MB available (500MB+ required)"
    fi

    # CPU cores
    local cpu_cores=$(nproc)
    if [[ $cpu_cores -ge 2 ]]; then
        log_success "CPU cores: $cpu_cores (>= 2 recommended)"
    else
        log_warning "CPU cores: $cpu_cores (2+ recommended for faster compilation)"
    fi

    echo ""
}

# Generate detailed report
generate_report() {
    local percentage=$((SCORE * 100 / MAX_SCORE))

    echo "================================================================"
    echo "  📊 eBPF Environment Verification Report"
    echo "================================================================"
    echo ""
    echo "🎯 Overall Score: $SCORE/$MAX_SCORE ($percentage%)"
    echo ""

    if [[ $percentage -ge 90 ]]; then
        echo "🟢 Status: EXCELLENT - Ready for hide_process_bpf compilation"
        echo "✅ All critical components are properly configured"
    elif [[ $percentage -ge 75 ]]; then
        echo "🟡 Status: GOOD - Minor issues may affect compilation"
        echo "⚠️  Some non-critical components need attention"
    elif [[ $percentage -ge 50 ]]; then
        echo "🟠 Status: FAIR - Several issues need to be resolved"
        echo "❌ Critical components missing or misconfigured"
    else
        echo "🔴 Status: POOR - Major setup required"
        echo "❌ Environment not ready for compilation"
    fi

    echo ""
    echo "📋 Recommendations:"
    echo ""

    if [[ $percentage -lt 90 ]]; then
        echo "1. Run setup script to fix issues:"
        echo "   sudo $(dirname "$0")/setup_dev_environment.sh"
        echo ""
    fi

    if [[ $percentage -ge 75 ]]; then
        echo "2. Test compilation:"
        echo "   cd $(dirname "$0")/.."
        echo "   make clean && make test"
        echo ""
    fi

    echo "3. For detailed analysis, run:"
    echo "   $0 --detailed"
    echo ""

    if [[ "$FIX_ISSUES" == "true" ]]; then
        echo "4. Some issues were automatically fixed"
        echo "   Re-run verification to see updated status"
        echo ""
    fi

    echo "📁 For troubleshooting:"
    echo "   - Check system logs: journalctl -xe"
    echo "   - Verify kernel config: zcat /proc/config.gz | grep BPF"
    echo "   - Test BPF manually: bpftool prog list"
    echo ""
}

# Main execution
main() {
    parse_arguments "$@"
    print_banner

    check_system_basics
    check_clang
    check_gcc_optimization
    check_libbpf
    check_dev_packages
    check_kernel_config
    check_bpf_infrastructure
    test_compilation
    check_system_resources

    generate_report

    # Exit with appropriate code
    local percentage=$((SCORE * 100 / MAX_SCORE))
    if [[ $percentage -ge 75 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
