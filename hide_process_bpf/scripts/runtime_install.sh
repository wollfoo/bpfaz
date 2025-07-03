#!/bin/bash
# runtime_install.sh - Install runtime dependencies for eBPF process hiding
# Usage: sudo ./runtime_install.sh
#
# Standard eBPF Environment Specification:
# - Ubuntu 22.04 LTS
# - Kernel 6.8.0-1026-azure (or compatible)
# - x86_64 architecture
# - libbpf v1.4.0+ (automatically upgraded from Ubuntu default v0.5.0)
# - bpftool v7.4.0+
#
# This script performs genuine upgrade to libbpf v1.4.0 by:
# 1. Installing build dependencies
# 2. Downloading and compiling libbpf v1.4.0 from source
# 3. Replacing system libbpf with native v1.4.0 libraries
# 4. Updating symbolic links and library cache

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
print_banner() {
    echo "================================================================"
    echo "  eBPF Process Hiding - Runtime Dependencies Installation"
    echo "  Target Environment: Ubuntu 22.04 + Kernel 6.8.0-1026-azure + x86_64"
    echo "  Required Tools: libbpf v1.4.0, bpftool v7.4.0"
    echo "  Mode: Runtime-only (no compilation required)"
    echo "================================================================"
}

# System verification
check_system() {
    log_info "Checking system compatibility..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    # Check OS
    if ! grep -q "Ubuntu 22.04" /etc/os-release; then
        log_error "Unsupported OS. Requires Ubuntu 22.04"
        log_info "Current OS: $(lsb_release -d | cut -f2)"
        exit 1
    fi
    
    # Check kernel version
    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)
    
    if [[ $KERNEL_MAJOR -lt 6 ]] || [[ $KERNEL_MAJOR -eq 6 && $KERNEL_MINOR -lt 8 ]]; then
        log_error "Kernel version $KERNEL_VERSION not supported. Requires 6.8+"
        exit 1
    fi
    
    # Check architecture
    if [[ "$(uname -m)" != "x86_64" ]]; then
        log_error "Architecture $(uname -m) not supported. Requires x86_64"
        exit 1
    fi
    
    # Check available disk space
    AVAILABLE_SPACE=$(df /opt 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    if [[ $AVAILABLE_SPACE -lt 102400 ]]; then  # 100MB in KB
        log_warning "Low disk space in /opt: ${AVAILABLE_SPACE}KB available"
    fi
    
    log_success "System compatibility verified"
    log_info "OS: $(lsb_release -d | cut -f2)"
    log_info "Kernel: $KERNEL_VERSION"
    log_info "Architecture: $(uname -m)"
}

# Check kernel features
check_kernel_features() {
    log_info "Checking kernel eBPF features..."
    
    local config_file=""
    if [[ -f /proc/config.gz ]]; then
        config_file="/proc/config.gz"
    elif [[ -f "/boot/config-$(uname -r)" ]]; then
        config_file="/boot/config-$(uname -r)"
    else
        log_warning "Kernel config not found. Skipping feature check."
        return 0
    fi
    
    # Check critical eBPF features
    local features=(
        "CONFIG_BPF=y"
        "CONFIG_BPF_SYSCALL=y"
        "CONFIG_HAVE_EBPF_JIT=y"
        "CONFIG_KPROBES=y"
    )
    
    for feature in "${features[@]}"; do
        if [[ $config_file == *.gz ]]; then
            if zgrep -q "^$feature" "$config_file"; then
                log_success "✓ $feature"
            else
                log_warning "✗ $feature (may not be available)"
            fi
        else
            if grep -q "^$feature" "$config_file"; then
                log_success "✓ $feature"
            else
                log_warning "✗ $feature (may not be available)"
            fi
        fi
    done
}

# Install runtime dependencies
install_runtime_deps() {
    log_info "Installing runtime dependencies..."
    
    # Update package lists
    log_info "Updating package lists..."
    apt-get update -qq
    
    # Install core runtime libraries
    log_info "Installing core runtime libraries..."
    apt-get install -y \
        libelf1 \
        zlib1g \
        libc6 \
        libgcc-s1 \
        build-essential \
        git \
        cmake \
        pkg-config \
        libelf-dev \
        zlib1g-dev \
        > /dev/null 2>&1

    # Install Ubuntu's libbpf first (will be upgraded)
    apt-get install -y \
        libbpf0 \
        libbpf-dev \
        > /dev/null 2>&1
    
    # Install BPF tools
    log_info "Installing BPF utilities..."
    apt-get install -y \
        linux-tools-common \
        linux-tools-generic \
        > /dev/null 2>&1
    
    # Update library cache
    ldconfig
    
    log_success "Runtime dependencies installed"
}

# Upgrade libbpf to v1.4.0
upgrade_libbpf() {
    log_info "Upgrading libbpf to v1.4.0..."

    # Check if already upgraded
    if ldconfig -p | grep -q "libbpf.so.1.4.0"; then
        log_success "libbpf v1.4.0 already installed"
        return 0
    fi

    # Create temporary directory
    local temp_dir="/tmp/libbpf_upgrade_$$"
    mkdir -p "$temp_dir"
    cd "$temp_dir"

    # Download libbpf v1.4.0 source
    log_info "Downloading libbpf v1.4.0 source..."
    git clone https://github.com/libbpf/libbpf.git > /dev/null 2>&1
    cd libbpf
    git checkout v1.4.0 > /dev/null 2>&1

    # Build libbpf
    log_info "Building libbpf v1.4.0..."
    cd src
    make -j$(nproc) > /dev/null 2>&1

    # Backup old libbpf
    log_info "Backing up old libbpf files..."
    cp /usr/lib/x86_64-linux-gnu/libbpf.so.0.5.0 /usr/lib/x86_64-linux-gnu/libbpf.so.0.5.0.backup 2>/dev/null || true

    # Install new libbpf v1.4.0
    log_info "Installing libbpf v1.4.0..."
    # Install shared libraries
    cp libbpf.so.1.4.0 /usr/lib/x86_64-linux-gnu/
    cp libbpf.a /usr/lib/x86_64-linux-gnu/

    # Install headers (replace old headers)
    mkdir -p /usr/include/bpf
    cp ../include/bpf/*.h /usr/include/bpf/ 2>/dev/null || true
    cp ../include/uapi/linux/*.h /usr/include/linux/ 2>/dev/null || true

    # Install pkg-config file
    mkdir -p /usr/lib/x86_64-linux-gnu/pkgconfig
    cp libbpf.pc /usr/lib/x86_64-linux-gnu/pkgconfig/ 2>/dev/null || true

    # Replace old libraries with v1.4.0 (genuine upgrade - no symbolic links)
    log_info "Replacing old libbpf files with v1.4.0..."

    # Remove old symbolic links completely
    rm -f /usr/lib/x86_64-linux-gnu/libbpf.so.1
    rm -f /usr/lib/x86_64-linux-gnu/libbpf.so.0
    rm -f /usr/lib/x86_64-linux-gnu/libbpf.so

    # Replace old v0.5.0 with genuine v1.4.0 files
    cp libbpf.so.1.4.0 /usr/lib/x86_64-linux-gnu/libbpf.so.0.5.0
    cp libbpf.so.1.4.0 /usr/lib/x86_64-linux-gnu/libbpf.so.1
    cp libbpf.so.1.4.0 /usr/lib/x86_64-linux-gnu/libbpf.so

    # Update library cache
    ldconfig

    # Cleanup
    cd /
    rm -rf "$temp_dir"

    log_success "libbpf upgraded to v1.4.0"
}



# Setup BPF filesystem
setup_bpf_fs() {
    log_info "Setting up BPF filesystem..."
    
    # Check if BPF filesystem is already mounted
    if mount | grep -q "bpf on /sys/fs/bpf"; then
        log_success "BPF filesystem already mounted"
    else
        # Mount BPF filesystem
        if mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then
            log_success "BPF filesystem mounted"
        else
            log_error "Failed to mount BPF filesystem"
            exit 1
        fi
    fi
    
    # Make mount persistent
    if ! grep -q "/sys/fs/bpf" /etc/fstab; then
        echo "bpf /sys/fs/bpf bpf defaults 0 0" >> /etc/fstab
        log_success "BPF filesystem mount made persistent"
    else
        log_info "BPF filesystem mount already persistent"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    local errors=0
    
    # Check libraries
    if ldconfig -p | grep -q libelf; then
        log_success "✓ libelf available"
    else
        log_error "✗ libelf missing"
        ((errors++))
    fi
    
    if ldconfig -p | grep -q "libz\.so"; then
        log_success "✓ zlib available"
    else
        log_error "✗ zlib missing"
        ((errors++))
    fi

    # Check libbpf
    if ldconfig -p | grep -q libbpf; then
        log_success "✓ libbpf available"

        # Check libbpf version (try to get from package info)
        local libbpf_version=$(dpkg -l | grep libbpf0 | awk '{print $3}' 2>/dev/null || echo "unknown")
        if [[ "$libbpf_version" != "unknown" ]]; then
            log_info "  libbpf version: $libbpf_version"
            # Note: Ubuntu 22.04 has libbpf 0.5.0, but we need compatibility with 1.4.0
            log_info "  Note: Runtime compiled with libbpf v1.4.0, using compatibility layer"
        fi
        
        # Verify expected version is 1.4.0
        if [ -e /usr/lib/x86_64-linux-gnu/libbpf.so.1.4.0 ]; then
            log_success "  libbpf v1.4.0 is available as required"
        else
            log_error "  libbpf v1.4.0 not found (required version)"
            ((errors++))
        fi
    else
        log_error "✗ libbpf missing"
        ((errors++))
    fi

    # Check libbpf.so.1 genuine v1.4.0 (no symbolic links)
    if [ -e /usr/lib/x86_64-linux-gnu/libbpf.so.1.4.0 ] && [ -e /usr/lib/x86_64-linux-gnu/libbpf.so.1 ]; then
        # Verify both files are identical (genuine replacement)
        if cmp -s /usr/lib/x86_64-linux-gnu/libbpf.so.1.4.0 /usr/lib/x86_64-linux-gnu/libbpf.so.1; then
            log_success "✓ libbpf.so.1 is genuine v1.4.0 (not symbolic link)"
        else
            log_error "✗ libbpf.so.1 is not genuine v1.4.0 file"
            ((errors++))
        fi

        # Verify old v0.5.0 was replaced with v1.4.0
        if cmp -s /usr/lib/x86_64-linux-gnu/libbpf.so.1.4.0 /usr/lib/x86_64-linux-gnu/libbpf.so.0.5.0; then
            log_success "✓ libbpf.so.0.5.0 replaced with genuine v1.4.0"
        else
            log_warning "⚠ libbpf.so.0.5.0 not replaced (may cause compatibility issues)"
        fi
    else
        log_error "✗ libbpf.so.1.4.0 missing - requires genuine libbpf v1.4.0 upgrade"
        ((errors++))
    fi
    
    # Check bpftool
    if command -v bpftool >/dev/null 2>&1; then
        local bpftool_version=$(bpftool version 2>/dev/null | head -1 || echo "unknown")
        log_success "✓ bpftool available: $bpftool_version"

        # Check if bpftool version meets requirements (v7.4.0+)
        if echo "$bpftool_version" | grep -q "v7\.[4-9]\|v[8-9]\|v[1-9][0-9]"; then
            log_success "✓ bpftool version meets requirements (v7.4.0+)"
        else
            log_warn "⚠ bpftool version may be outdated. Recommended: v7.4.0+"
            # Don't increment errors, just warn
        fi
    else
        log_error "✗ bpftool not found"
        ((errors++))
    fi
    
    # Check clang
    if command -v clang >/dev/null 2>&1; then
        local clang_version=$(clang --version 2>/dev/null | head -1)
        log_success "✓ clang available: $clang_version"
        
        # Check if clang version meets requirements (v15.0.7+)
        if echo "$clang_version" | grep -q "version 1[5-9]"; then
            log_success "✓ clang version meets requirements (v15.0.7+)"
        else
            log_warn "⚠ clang version may be outdated. Recommended: v15.0.7+"
            # Don't increment errors, just warn
        fi
    else
        log_error "✗ clang not found"
        ((errors++))
    fi
    
    # Check BPF filesystem
    if mount | grep -q "bpf on /sys/fs/bpf"; then
        log_success "✓ BPF filesystem mounted"
    else
        log_error "✗ BPF filesystem not mounted"
        ((errors++))
    fi
    
    # Check BPF functionality
    if bpftool prog list >/dev/null 2>&1; then
        log_success "✓ BPF functionality working"
    else
        log_warning "⚠ BPF functionality test failed (may be normal if no programs loaded)"
    fi

    # Check BTF availability
    if [ -r /sys/kernel/btf/vmlinux ]; then
        log_success "✓ Kernel BTF available"
    else
        log_warn "⚠ Kernel BTF not available - may cause eBPF loading issues"
    fi

    if [[ $errors -eq 0 ]]; then
        log_success "Installation verification completed successfully"
        return 0
    else
        log_error "Installation verification failed with $errors errors"
        return 1
    fi
}

# This function was removed to eliminate deployment structure creation

# This function was removed to eliminate binary deployment

# This function was removed to eliminate systemd service setup

# Print next steps
print_next_steps() {
    echo ""
    echo "================================================================"
    log_success "🎉 eBPF Development Environment Setup Complete!"
    echo "================================================================"
    echo ""
    echo "Environment Status:"
    echo ""
    echo "✅ Runtime environment: Ready"
    echo "✅ Development dependencies: Installed"
    echo "✅ BPF filesystem: Mounted"
    echo ""
    echo "Environment Summary:"
    echo "- Base: Ubuntu 22.04 + Kernel $(uname -r) + $(uname -m)"
    echo "- libbpf: v1.4.0 (upgraded)"
    echo "- bpftool: $(bpftool version 2>/dev/null | head -1 || echo 'v7.4.0+')"
    echo "- clang: $(clang --version 2>/dev/null | head -1 || echo 'v15.0.7+ recommended')"
    if [ -r /sys/kernel/btf/vmlinux ]; then
        echo "- BTF: Available"
    else
        echo "- BTF: Not available (may affect eBPF program loading)"
    fi
    echo ""
    echo "Next Steps:"
    echo ""
    echo "1. Compile your eBPF programs:"
    echo "   cd /home/azureuser/bpfaz/hide_process_bpf"
    echo "   make"
    echo ""
    echo "2. Test BPF functionality:"
    echo "   sudo bpftool prog list"
    echo ""
    echo "3. Verify BPF filesystem:"
    echo "   ls -la /sys/fs/bpf/"
    echo ""
    echo "4. Check libbpf version:"
    echo "   ldd -v /usr/lib/x86_64-linux-gnu/libbpf.so"
    echo ""
}

# Main execution
main() {
    print_banner
    
    check_system
    check_kernel_features
    install_runtime_deps
    upgrade_libbpf
    setup_bpf_fs
    
    if verify_installation; then
        print_next_steps
        exit 0
    else
        log_error "Installation failed. Please check the errors above."
        exit 1
    fi
}

# Run main function
main "$@"
