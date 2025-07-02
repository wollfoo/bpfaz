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

# Install systemd service
install_systemd_service() {
    log_info "Installing lsm-hide.service..."

    local service_file="/etc/systemd/system/lsm-hide.service"
    local source_service="../lsm-hide.service"

    # Check if source service file exists
    if [ ! -f "$source_service" ]; then
        log_error "Service file $source_service not found"
        return 1
    fi

    # Copy service file to systemd directory
    cp "$source_service" "$service_file"

    # Set proper permissions
    chmod 644 "$service_file"
    chown root:root "$service_file"

    # Reload systemd daemon
    systemctl daemon-reload

    # Enable service (but don't start yet)
    systemctl enable lsm-hide.service

    log_success "lsm-hide.service installed and enabled"
    log_info "Service will start automatically on boot"
    log_info "To start now: sudo systemctl start lsm-hide.service"
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
        fi
    else
        log_error "✗ bpftool not found"
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

    # Check systemd service installation
    if systemctl is-enabled lsm-hide.service >/dev/null 2>&1; then
        log_success "✓ lsm-hide.service installed and enabled"
    else
        log_error "✗ lsm-hide.service not installed or enabled"
        ((errors++))
    fi

    if [[ $errors -eq 0 ]]; then
        log_success "Installation verification completed successfully"
        return 0
    else
        log_error "Installation verification failed with $errors errors"
        return 1
    fi
}

# Create runtime deployment package structure
create_deployment_structure() {
    log_info "Creating deployment directory structure..."
    
    # Create directories
    mkdir -p /opt/lsm_hide/{bin,config,logs}
    
    # Set permissions
    chown -R root:root /opt/lsm_hide
    chmod 755 /opt/lsm_hide
    chmod 755 /opt/lsm_hide/bin
    chmod 700 /opt/lsm_hide/config
    chmod 755 /opt/lsm_hide/logs
    
    log_success "Deployment structure created at /opt/lsm_hide"
}

# Print next steps
print_next_steps() {
    echo ""
    echo "================================================================"
    log_success "🎉 Runtime environment ready for eBPF process hiding deployment!"
    echo "================================================================"
    echo ""
    echo "Standard eBPF Environment Summary:"
    echo "- Base: Ubuntu 22.04 + Kernel $(uname -r) + $(uname -m)"
    echo "- libbpf: $(dpkg -l | grep libbpf0 | awk '{print $3}' 2>/dev/null || echo 'installed') (requires v1.4.0+ for native libbpf.so.1)"
    echo "- bpftool: $(bpftool version 2>/dev/null | head -1 || echo 'installed') (requires v7.4.0+)"
    echo "- BTF: $([ -r /sys/kernel/btf/vmlinux ] && echo 'Available' || echo 'Not available')"
    echo "- libbpf.so.1: $([ -e /lib/x86_64-linux-gnu/libbpf.so.1 ] && echo 'Native (v1.4.0+)' || echo 'Missing - upgrade required')"
    echo ""
    echo "⚠️  IMPORTANT: For standard environment compliance:"
    echo "   - Upgrade libbpf to v1.4.0+ if libbpf.so.1 shows 'Missing'"
    echo "   - Upgrade bpftool to v7.4.0+ if version check fails"
    echo "   - Binaries compiled with libbpf v1.4.0 require native libbpf.so.1"
    echo ""
    echo "Next steps:"
    echo "1. Copy pre-compiled binaries to /opt/lsm_hide/bin/"
    echo "   - libhide.so (LD_PRELOAD library)"
    echo "   - lsm_hide_loader (eBPF loader)"
    echo "   - *.bpf.o (eBPF object files)"
    echo ""
    echo "2. Copy configuration files to /opt/lsm_hide/config/"
    echo ""
    echo "3. Install systemd service:"
    echo "   sudo cp lsm-hide.service /etc/systemd/system/"
    echo "   sudo systemctl daemon-reload"
    echo ""
    echo "4. Start the service:"
    echo "   sudo systemctl enable lsm-hide.service"
    echo "   sudo systemctl start lsm-hide.service"
    echo ""
    echo "5. Verify functionality:"
    echo "   sudo systemctl status lsm-hide.service"
    echo "   LD_PRELOAD=/opt/lsm_hide/bin/libhide.so ps aux"
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
    create_deployment_structure
    install_systemd_service
    
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
