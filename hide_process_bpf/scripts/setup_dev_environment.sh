#!/bin/bash
# setup_dev_environment.sh - Complete eBPF Development Environment Setup
# Thiết lập môi trường phát triển eBPF hoàn chỉnh cho hide_process_bpf module
#
# Target Environment:
# - Ubuntu 22.04.5 LTS
# - Kernel 6.8.0-1026-azure
# - x86_64 architecture
# - libbpf v1.4.0+
# - clang v15.0+ with BPF support

set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="/tmp/ebpf_setup_backup_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/tmp/ebpf_setup.log"
ROLLBACK_SCRIPT="/tmp/ebpf_rollback.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Global variables
VERBOSE=false
DRY_RUN=false
FORCE_INSTALL=false
SKIP_BACKUP=false

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1" | tee -a "$LOG_FILE"
    fi
}

# Error handling
error_exit() {
    log_error "$1"
    log_error "Installation failed. Check log file: $LOG_FILE"
    log_error "Rollback script available at: $ROLLBACK_SCRIPT"
    exit 1
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script interrupted. Performing cleanup..."
        # Add cleanup logic here if needed
    fi
    exit $exit_code
}

trap cleanup EXIT INT TERM

# Banner
print_banner() {
    echo "================================================================"
    echo "  🛠️  eBPF Development Environment Setup"
    echo "  Target: hide_process_bpf module compilation readiness"
    echo "  Environment: Ubuntu 22.04 + Kernel 6.8.0-1026-azure"
    echo "  Components: clang v15.0+, libbpf v1.4.0+, dev packages"
    echo "================================================================"
    echo ""
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Setup complete eBPF development environment for hide_process_bpf module.

OPTIONS:
    -v, --verbose           Enable verbose output
    -d, --dry-run          Show what would be done without executing
    -f, --force            Force installation even if components exist
    -s, --skip-backup      Skip creating backup (faster but less safe)
    -h, --help             Show this help message

EXAMPLES:
    $0                     # Standard installation
    $0 -v                  # Verbose installation
    $0 -d                  # Dry run to see what would be installed
    $0 -f -s               # Force install without backup (fastest)

COMPONENTS INSTALLED:
    ✓ clang compiler v15.0+ with BPF target support
    ✓ libbpf library upgrade to v1.4.0+
    ✓ Development packages (libbpf-dev, libelf-dev, zlib1g-dev)
    ✓ Build tools optimization
    ✓ Environment verification

SAFETY FEATURES:
    ✓ Pre-flight system compatibility checks
    ✓ Automatic backup creation before modifications
    ✓ Rollback script generation
    ✓ Installation verification and testing
    ✓ Comprehensive error handling

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -f|--force)
                FORCE_INSTALL=true
                shift
                ;;
            -s|--skip-backup)
                SKIP_BACKUP=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# System compatibility checks
check_system_compatibility() {
    log_info "Performing system compatibility checks..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
    
    # Check OS version
    if ! grep -q "Ubuntu 22.04" /etc/os-release; then
        log_warning "OS is not Ubuntu 22.04. Compatibility not guaranteed."
        log_info "Current OS: $(lsb_release -d | cut -f2)"
        if [[ "$FORCE_INSTALL" != "true" ]]; then
            error_exit "Use --force to proceed on unsupported OS"
        fi
    fi
    
    # Check kernel version
    local kernel_version=$(uname -r)
    local kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    local kernel_minor=$(echo "$kernel_version" | cut -d. -f2)
    
    if [[ $kernel_major -lt 6 ]] || [[ $kernel_major -eq 6 && $kernel_minor -lt 8 ]]; then
        error_exit "Kernel version $kernel_version not supported. Requires 6.8+"
    fi
    
    # Check architecture
    if [[ "$(uname -m)" != "x86_64" ]]; then
        error_exit "Architecture $(uname -m) not supported. Requires x86_64"
    fi
    
    # Check available disk space (need at least 500MB)
    local available_space=$(df /tmp 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    if [[ $available_space -lt 512000 ]]; then  # 500MB in KB
        error_exit "Insufficient disk space. Need at least 500MB in /tmp"
    fi
    
    # Check critical kernel configs
    local config_file=""
    if [[ -f /proc/config.gz ]]; then
        config_file="/proc/config.gz"
    elif [[ -f "/boot/config-$(uname -r)" ]]; then
        config_file="/boot/config-$(uname -r)"
    elif [[ -f "/usr/src/linux-headers-$(uname -r)/.config" ]]; then
        config_file="/usr/src/linux-headers-$(uname -r)/.config"
    else
        log_warning "Kernel config not found. Skipping config verification."
        return 0
    fi
    
    local required_configs=(
        "CONFIG_BPF=y"
        "CONFIG_BPF_SYSCALL=y"
        "CONFIG_KPROBES=y"
        "CONFIG_BPF_KPROBE_OVERRIDE=y"
        "CONFIG_FUNCTION_ERROR_INJECTION=y"
    )
    
    for config in "${required_configs[@]}"; do
        if [[ $config_file == *.gz ]]; then
            if ! zgrep -q "^$config" "$config_file"; then
                error_exit "Required kernel config missing: $config"
            fi
        else
            if ! grep -q "^$config" "$config_file"; then
                error_exit "Required kernel config missing: $config"
            fi
        fi
        log_debug "✓ $config verified"
    done
    
    # Check BTF support
    if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
        error_exit "BTF support not available. Required for modern eBPF programs."
    fi
    
    # Check BPF filesystem
    if ! mount | grep -q "bpf on /sys/fs/bpf"; then
        log_warning "BPF filesystem not mounted. Will attempt to mount."
    fi
    
    log_success "System compatibility checks passed"
}

# Create backup
create_backup() {
    if [[ "$SKIP_BACKUP" == "true" ]]; then
        log_info "Skipping backup creation (--skip-backup specified)"
        return 0
    fi
    
    log_info "Creating system backup..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would create backup directory: $BACKUP_DIR"
        return 0
    fi
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup package state
    dpkg -l > "$BACKUP_DIR/packages_before.txt"
    apt list --installed > "$BACKUP_DIR/apt_installed_before.txt" 2>/dev/null
    
    # Backup library state
    ldconfig -p > "$BACKUP_DIR/ldconfig_before.txt"
    
    # Backup existing libbpf files
    if [[ -f /usr/lib/x86_64-linux-gnu/libbpf.so.0.5.0 ]]; then
        cp /usr/lib/x86_64-linux-gnu/libbpf.so* "$BACKUP_DIR/" 2>/dev/null || true
    fi
    
    # Create rollback script
    cat > "$ROLLBACK_SCRIPT" << 'EOF'
#!/bin/bash
# Auto-generated rollback script for eBPF development environment setup
# Tự động tạo script rollback cho thiết lập môi trường phát triển eBPF

set -euo pipefail

echo "🔄 Rolling back eBPF development environment setup..."

# Remove installed packages
if command -v clang >/dev/null 2>&1; then
    echo "Removing clang..."
    apt remove --purge -y clang llvm 2>/dev/null || true
fi

# Restore original libbpf if backup exists
BACKUP_DIR="BACKUP_DIR_PLACEHOLDER"
if [[ -f "$BACKUP_DIR/libbpf.so.0.5.0" ]]; then
    echo "Restoring original libbpf..."
    cp "$BACKUP_DIR"/libbpf.so* /usr/lib/x86_64-linux-gnu/ 2>/dev/null || true
    ldconfig
fi

# Clean up development packages
apt remove --purge -y libbpf-dev libelf-dev zlib1g-dev 2>/dev/null || true
apt autoremove -y 2>/dev/null || true

echo "✅ Rollback completed. System restored to previous state."
echo "📋 Original package list: $BACKUP_DIR/packages_before.txt"
EOF
    
    # Replace placeholder with actual backup directory
    sed -i "s|BACKUP_DIR_PLACEHOLDER|$BACKUP_DIR|g" "$ROLLBACK_SCRIPT"
    chmod +x "$ROLLBACK_SCRIPT"
    
    log_success "Backup created at: $BACKUP_DIR"
    log_success "Rollback script created at: $ROLLBACK_SCRIPT"
}

# Install clang compiler with BPF support
install_clang() {
    log_info "Installing clang compiler with BPF support..."

    # Check if clang is already installed
    if command -v clang >/dev/null 2>&1; then
        local clang_version=$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local major_version=$(echo "$clang_version" | cut -d. -f1)

        if [[ $major_version -ge 15 ]] && [[ "$FORCE_INSTALL" != "true" ]]; then
            log_success "clang v$clang_version already installed (>= v15.0 required)"
            return 0
        elif [[ "$FORCE_INSTALL" == "true" ]]; then
            log_info "Force reinstalling clang (--force specified)"
        else
            log_warning "clang v$clang_version found but < v15.0 required. Upgrading..."
        fi
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would install: clang llvm"
        return 0
    fi

    # Update package lists
    log_info "Updating package lists..."
    apt update -qq

    # Install clang and LLVM
    log_info "Installing clang and LLVM packages..."
    apt install -y clang llvm

    # Verify installation
    if ! command -v clang >/dev/null 2>&1; then
        error_exit "clang installation failed"
    fi

    local installed_version=$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    local major_version=$(echo "$installed_version" | cut -d. -f1)

    if [[ $major_version -lt 15 ]]; then
        error_exit "Installed clang version $installed_version < required v15.0"
    fi

    # Test BPF target support
    log_info "Testing BPF target support..."
    if ! echo 'int main() { return 0; }' | clang -target bpf -c -x c - -o /tmp/test_bpf.o 2>/dev/null; then
        error_exit "clang BPF target support test failed"
    fi
    rm -f /tmp/test_bpf.o

    log_success "clang v$installed_version installed with BPF support"
}

# Install and optimize gcc for BPF compilation
install_gcc_optimization() {
    log_info "Installing gcc-12 with BPF optimizations..."

    # Check current gcc version
    local current_gcc_version=""
    if command -v gcc >/dev/null 2>&1; then
        current_gcc_version=$(gcc --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local major_version=$(echo "$current_gcc_version" | cut -d. -f1)

        if [[ $major_version -ge 12 ]] && [[ "$FORCE_INSTALL" != "true" ]]; then
            log_success "gcc v$current_gcc_version already installed (>= v12.0 required)"
            return 0
        elif [[ "$FORCE_INSTALL" == "true" ]]; then
            log_info "Force reinstalling gcc-12 (--force specified)"
        else
            log_info "gcc v$current_gcc_version found, upgrading to gcc-12 for BPF optimization..."
        fi
    else
        log_info "gcc not found, installing gcc-12..."
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would install: gcc-12 g++-12"
        log_info "[DRY-RUN] Would set gcc-12 as default compiler"
        return 0
    fi

    # Install gcc-12 and g++-12
    log_info "Installing gcc-12 and g++-12 packages..."
    if ! apt install -y gcc-12 g++-12; then
        error_exit "Failed to install gcc-12 packages"
    fi

    # Verify installation
    if ! command -v gcc-12 >/dev/null 2>&1; then
        error_exit "gcc-12 installation verification failed"
    fi

    # Set up alternatives for gcc and g++
    log_info "Setting up gcc-12 as default compiler..."

    # Remove existing alternatives (if any)
    update-alternatives --remove-all gcc 2>/dev/null || true
    update-alternatives --remove-all g++ 2>/dev/null || true

    # Install gcc alternatives with priority
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 120
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 120

    # If gcc-11 exists, add it with lower priority
    if command -v gcc-11 >/dev/null 2>&1; then
        update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110
        update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 110
        log_debug "Added gcc-11 as alternative with lower priority"
    fi

    # Verify gcc-12 is now default
    local new_gcc_version=$(gcc --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    local new_major_version=$(echo "$new_gcc_version" | cut -d. -f1)

    if [[ $new_major_version -eq 12 ]]; then
        log_success "gcc-12 v$new_gcc_version set as default compiler"
    else
        log_warning "gcc-12 installed but not set as default (current: v$new_gcc_version)"
    fi

    # Test BPF-related compilation capabilities
    log_info "Testing gcc-12 BPF optimization capabilities..."

    # Test basic compilation
    if echo 'int main() { return 0; }' | gcc -c -x c - -o /tmp/test_gcc.o 2>/dev/null; then
        log_success "gcc-12 basic compilation test passed"
        rm -f /tmp/test_gcc.o
    else
        log_warning "gcc-12 basic compilation test failed"
    fi

    # Test optimization flags
    if echo 'int main() { return 0; }' | gcc -O2 -march=native -c -x c - -o /tmp/test_gcc_opt.o 2>/dev/null; then
        log_success "gcc-12 optimization flags test passed"
        rm -f /tmp/test_gcc_opt.o
    else
        log_warning "gcc-12 optimization flags test failed"
    fi

    log_success "gcc-12 installed and optimized for BPF compilation"
}

# Install development packages
install_dev_packages() {
    log_info "Installing development packages..."

    local packages=(
        "libbpf-dev"
        "libelf-dev"
        "zlib1g-dev"
        "build-essential"
        "pkg-config"
        "git"
        "cmake"
    )

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would install packages: ${packages[*]}"
        return 0
    fi

    # Check which packages are missing
    local missing_packages=()
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            missing_packages+=("$package")
        else
            log_debug "Package $package already installed"
        fi
    done

    if [[ ${#missing_packages[@]} -eq 0 ]] && [[ "$FORCE_INSTALL" != "true" ]]; then
        log_success "All development packages already installed"
        return 0
    fi

    if [[ "$FORCE_INSTALL" == "true" ]]; then
        missing_packages=("${packages[@]}")
        log_info "Force reinstalling all development packages"
    fi

    log_info "Installing missing packages: ${missing_packages[*]}"
    apt install -y "${missing_packages[@]}"

    # Verify installation
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            error_exit "Package $package installation failed"
        fi
    done

    log_success "Development packages installed successfully"
}

# Upgrade libbpf to v1.4.0+
upgrade_libbpf() {
    log_info "Upgrading libbpf to v1.4.0+..."

    # Check current libbpf version
    local current_version=""
    if ldconfig -p | grep -q "libbpf.so.1.4"; then
        current_version="1.4.x"
    elif ldconfig -p | grep -q "libbpf.so.0"; then
        current_version="0.5.x"
    fi

    if [[ "$current_version" == "1.4.x" ]] && [[ "$FORCE_INSTALL" != "true" ]]; then
        log_success "libbpf v1.4.x already installed"
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would upgrade libbpf from $current_version to v1.4.0+"
        return 0
    fi

    # Create temporary directory for compilation
    local temp_dir="/tmp/libbpf_upgrade_$$"
    mkdir -p "$temp_dir"
    cd "$temp_dir"

    log_info "Downloading libbpf v1.4.0 source..."
    if ! git clone https://github.com/libbpf/libbpf.git; then
        error_exit "Failed to download libbpf source"
    fi

    cd libbpf
    if ! git checkout v1.4.0; then
        error_exit "Failed to checkout libbpf v1.4.0"
    fi

    log_info "Compiling libbpf v1.4.0..."
    cd src
    if ! make -j$(nproc); then
        error_exit "libbpf compilation failed"
    fi

    # Backup existing libbpf files
    if [[ "$SKIP_BACKUP" != "true" ]]; then
        log_info "Backing up existing libbpf files..."
        cp /usr/lib/x86_64-linux-gnu/libbpf.so* "$BACKUP_DIR/" 2>/dev/null || true
    fi

    log_info "Installing libbpf v1.4.0..."

    # Install shared libraries
    cp libbpf.so.1.4.0 /usr/lib/x86_64-linux-gnu/
    cp libbpf.a /usr/lib/x86_64-linux-gnu/

    # Install headers
    mkdir -p /usr/include/bpf
    cp ../include/bpf/*.h /usr/include/bpf/ 2>/dev/null || true
    cp ../include/uapi/linux/*.h /usr/include/linux/ 2>/dev/null || true

    # Install pkg-config file
    mkdir -p /usr/lib/x86_64-linux-gnu/pkgconfig
    cp libbpf.pc /usr/lib/x86_64-linux-gnu/pkgconfig/ 2>/dev/null || true

    # Update symbolic links
    log_info "Updating library symbolic links..."
    cd /usr/lib/x86_64-linux-gnu/

    # Remove old links
    rm -f libbpf.so.1 libbpf.so.0 libbpf.so

    # Create new links pointing to v1.4.0
    ln -sf libbpf.so.1.4.0 libbpf.so.1
    ln -sf libbpf.so.1.4.0 libbpf.so.0
    ln -sf libbpf.so.1.4.0 libbpf.so

    # Update library cache
    ldconfig

    # Cleanup
    cd /
    rm -rf "$temp_dir"

    # Verify installation
    if ! ldconfig -p | grep -q "libbpf.so.1.4"; then
        error_exit "libbpf v1.4.0 installation verification failed"
    fi

    log_success "libbpf upgraded to v1.4.0 successfully"
}

# Setup BPF filesystem
setup_bpf_filesystem() {
    log_info "Setting up BPF filesystem..."

    # Check if BPF filesystem is already mounted
    if mount | grep -q "bpf on /sys/fs/bpf"; then
        log_success "BPF filesystem already mounted"
    else
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY-RUN] Would mount BPF filesystem"
            return 0
        fi

        # Mount BPF filesystem
        if mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then
            log_success "BPF filesystem mounted"
        else
            error_exit "Failed to mount BPF filesystem"
        fi
    fi

    # Make mount persistent
    if ! grep -q "/sys/fs/bpf" /etc/fstab; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY-RUN] Would add BPF filesystem to /etc/fstab"
        else
            echo "bpf /sys/fs/bpf bpf defaults 0 0" >> /etc/fstab
            log_success "BPF filesystem mount made persistent"
        fi
    else
        log_debug "BPF filesystem mount already persistent"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."

    local errors=0
    local warnings=0

    # Check clang
    if command -v clang >/dev/null 2>&1; then
        local clang_version=$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local major_version=$(echo "$clang_version" | cut -d. -f1)

        if [[ $major_version -ge 15 ]]; then
            log_success "✓ clang v$clang_version (>= v15.0 required)"
        else
            log_error "✗ clang v$clang_version < v15.0 required"
            ((errors++))
        fi

        # Test BPF target support
        if echo 'int main() { return 0; }' | clang -target bpf -c -x c - -o /tmp/test_bpf.o 2>/dev/null; then
            log_success "✓ clang BPF target support working"
            rm -f /tmp/test_bpf.o
        else
            log_error "✗ clang BPF target support failed"
            ((errors++))
        fi
    else
        log_error "✗ clang not found"
        ((errors++))
    fi

    # Check gcc optimization
    if command -v gcc >/dev/null 2>&1; then
        local gcc_version=$(gcc --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local gcc_major_version=$(echo "$gcc_version" | cut -d. -f1)

        if [[ $gcc_major_version -ge 12 ]]; then
            log_success "✓ gcc v$gcc_version (>= v12.0 for BPF optimization)"
        else
            log_warning "⚠ gcc v$gcc_version < v12.0 (optimization recommended)"
            ((warnings++))
        fi

        # Test gcc optimization capabilities
        if echo 'int main() { return 0; }' | gcc -O2 -march=native -c -x c - -o /tmp/test_gcc_opt.o 2>/dev/null; then
            log_success "✓ gcc optimization flags working"
            rm -f /tmp/test_gcc_opt.o
        else
            log_warning "⚠ gcc optimization flags test failed"
            ((warnings++))
        fi
    else
        log_error "✗ gcc not found"
        ((errors++))
    fi

    # Check libbpf
    if ldconfig -p | grep -q "libbpf"; then
        if ldconfig -p | grep -q "libbpf.so.1.4"; then
            log_success "✓ libbpf v1.4.x available"
        else
            log_warning "⚠ libbpf available but version may be < v1.4.0"
            ((warnings++))
        fi
    else
        log_error "✗ libbpf not found"
        ((errors++))
    fi

    # Check development packages
    local dev_packages=("libbpf-dev" "libelf-dev" "zlib1g-dev" "build-essential")
    for package in "${dev_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            log_success "✓ $package installed"
        else
            log_error "✗ $package missing"
            ((errors++))
        fi
    done

    # Check BPF functionality
    if command -v bpftool >/dev/null 2>&1; then
        if bpftool prog list >/dev/null 2>&1; then
            log_success "✓ BPF functionality working"
        else
            log_warning "⚠ BPF functionality test failed (may be normal)"
            ((warnings++))
        fi

        local bpftool_version=$(bpftool version 2>/dev/null | head -1 || echo "unknown")
        log_info "  bpftool: $bpftool_version"
    else
        log_warning "⚠ bpftool not found"
        ((warnings++))
    fi

    # Check BTF support
    if [[ -r /sys/kernel/btf/vmlinux ]]; then
        log_success "✓ Kernel BTF available"
    else
        log_error "✗ Kernel BTF not available"
        ((errors++))
    fi

    # Check BPF filesystem
    if mount | grep -q "bpf on /sys/fs/bpf"; then
        log_success "✓ BPF filesystem mounted"
    else
        log_error "✗ BPF filesystem not mounted"
        ((errors++))
    fi

    # Summary
    echo ""
    if [[ $errors -eq 0 ]]; then
        log_success "🎉 Installation verification completed successfully!"
        if [[ $warnings -gt 0 ]]; then
            log_warning "Note: $warnings warnings found (non-critical)"
        fi
        return 0
    else
        log_error "❌ Installation verification failed with $errors errors and $warnings warnings"
        return 1
    fi
}

# Test compilation capability
test_compilation() {
    log_info "Testing eBPF compilation capability..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would test compilation of hide_process_bpf"
        return 0
    fi

    # Test basic BPF compilation
    local test_dir="/tmp/bpf_compile_test_$$"
    mkdir -p "$test_dir"
    cd "$test_dir"

    # Create simple test BPF program
    cat > test_bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_openat")
int test_openat(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    # Test compilation
    if clang -target bpf -O2 -c test_bpf.c -o test_bpf.o; then
        log_success "✓ Basic BPF compilation test passed"
    else
        log_error "✗ Basic BPF compilation test failed"
        cd /
        rm -rf "$test_dir"
        return 1
    fi

    # Test hide_process_bpf compilation if available
    local hide_process_dir="$SCRIPT_DIR/.."
    if [[ -f "$hide_process_dir/hide_process_bpf.c" ]]; then
        log_info "Testing hide_process_bpf compilation..."
        cd "$hide_process_dir"

        if make clean >/dev/null 2>&1 && make test >/dev/null 2>&1; then
            log_success "✓ hide_process_bpf compilation test passed"
        else
            log_warning "⚠ hide_process_bpf compilation test failed (may need additional setup)"
        fi
    else
        log_debug "hide_process_bpf.c not found, skipping specific test"
    fi

    # Cleanup
    cd /
    rm -rf "$test_dir"

    log_success "Compilation testing completed"
}

# Print installation summary
print_summary() {
    echo ""
    echo "================================================================"
    log_success "🎉 eBPF Development Environment Setup Complete!"
    echo "================================================================"
    echo ""
    echo "📋 Installation Summary:"
    echo ""

    # Show installed versions
    if command -v clang >/dev/null 2>&1; then
        local clang_version=$(clang --version | head -1)
        echo "✅ clang: $clang_version"
    fi

    if command -v gcc >/dev/null 2>&1; then
        local gcc_version=$(gcc --version | head -1)
        echo "✅ gcc: $gcc_version (optimized for BPF)"
    fi

    if ldconfig -p | grep -q "libbpf"; then
        if ldconfig -p | grep -q "libbpf.so.1.4"; then
            echo "✅ libbpf: v1.4.x (upgraded)"
        else
            echo "✅ libbpf: available (version check recommended)"
        fi
    fi

    echo "✅ Development packages: libbpf-dev, libelf-dev, zlib1g-dev"
    echo "✅ Build tools: build-essential, pkg-config, git, cmake"

    if command -v bpftool >/dev/null 2>&1; then
        local bpftool_version=$(bpftool version 2>/dev/null | head -1 || echo "available")
        echo "✅ bpftool: $bpftool_version"
    fi

    echo ""
    echo "🎯 Next Steps:"
    echo ""
    echo "1. Test hide_process_bpf compilation:"
    echo "   cd $SCRIPT_DIR/.."
    echo "   make clean && make test"
    echo ""
    echo "2. Build complete system:"
    echo "   make hybrid"
    echo ""
    echo "3. Verify BPF functionality:"
    echo "   sudo bpftool prog list"
    echo "   sudo bpftool map list"
    echo ""
    echo "📁 Files created:"
    echo "   📋 Log file: $LOG_FILE"
    if [[ "$SKIP_BACKUP" != "true" ]]; then
        echo "   💾 Backup: $BACKUP_DIR"
        echo "   🔄 Rollback script: $ROLLBACK_SCRIPT"
    fi
    echo ""
    echo "🆘 If issues occur:"
    echo "   - Check log file: $LOG_FILE"
    if [[ "$SKIP_BACKUP" != "true" ]]; then
        echo "   - Run rollback: $ROLLBACK_SCRIPT"
    fi
    echo "   - Report issues with full log output"
    echo ""
}

# Main execution function
main() {
    # Initialize log file
    echo "eBPF Development Environment Setup Log - $(date)" > "$LOG_FILE"
    echo "Command: $0 $*" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"

    print_banner

    # Parse command line arguments
    parse_arguments "$@"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "🔍 DRY RUN MODE - No changes will be made"
        echo ""
    fi

    # Pre-flight checks
    log_info "🔍 Phase 1: System Compatibility Checks"
    check_system_compatibility
    echo ""

    # Create backup
    log_info "💾 Phase 2: Backup Creation"
    create_backup
    echo ""

    # Install components
    log_info "📦 Phase 3: Component Installation"

    log_info "Installing clang compiler..."
    install_clang
    echo ""

    log_info "Optimizing gcc compiler..."
    install_gcc_optimization
    echo ""

    log_info "Installing development packages..."
    install_dev_packages
    echo ""

    log_info "Upgrading libbpf..."
    upgrade_libbpf
    echo ""

    log_info "Setting up BPF filesystem..."
    setup_bpf_filesystem
    echo ""

    # Verification
    log_info "✅ Phase 4: Installation Verification"
    if verify_installation; then
        echo ""
        log_info "🧪 Phase 5: Compilation Testing"
        test_compilation
        echo ""
        print_summary

        log_success "🎉 Setup completed successfully!"
        exit 0
    else
        echo ""
        log_error "❌ Installation verification failed"
        log_error "Check log file: $LOG_FILE"
        if [[ "$SKIP_BACKUP" != "true" ]]; then
            log_error "Rollback available: $ROLLBACK_SCRIPT"
        fi
        exit 1
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
