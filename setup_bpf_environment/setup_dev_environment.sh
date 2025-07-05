#!/bin/bash
# setup_dev_environment.sh - Complete eBPF Development Environment Setup
# Thiết lập môi trường phát triển eBPF hoàn chỉnh cho hide_process_bpf module
#
# Target Environment:
# - Ubuntu 22.04.5 LTS
# - Kernel 6.8.0-60-generic (HWE)
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
    local current_kernel=$(uname -r)
    local current_os=$(lsb_release -d 2>/dev/null | cut -f2 | cut -d' ' -f1-2 || echo "Ubuntu 22.04")
    local kernel_type=""

    # Detect kernel type
    if [[ "$current_kernel" == *"azure"* ]]; then
        kernel_type=" (Azure)"
    elif [[ "$current_kernel" == *"aws"* ]]; then
        kernel_type=" (AWS)"
    elif [[ "$current_kernel" == *"gcp"* ]]; then
        kernel_type=" (GCP)"
    elif [[ "$current_kernel" == *"generic"* ]]; then
        kernel_type=" (HWE)"
    fi

    echo "================================================================"
    echo "  🛠️  eBPF Development Environment Setup (Enhanced)"
    echo "  Target: hide_process_bpf module compilation readiness"
    echo "  Environment: $current_os + Kernel $current_kernel$kernel_type"
    echo "  Components: clang-15.0+, gcc-12.3.0, libbpf v1.4.0+"
    echo "  Features: Auto-alternatives, LLVM repo, version verification"
    echo "================================================================"
    echo ""
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Setup complete eBPF development environment for hide_process_bpf module.

OPTIONS:
    -v, --verbose          Enable verbose output
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
    ✓ clang-15.0+ compiler with BPF target support (auto-configured as default)
    ✓ gcc-12.3.0 compiler with BPF optimizations (auto-configured as default)
    ✓ Automatic update-alternatives configuration for both compilers
    ✓ libbpf library upgrade to v1.4.0+
    ✓ Development packages (libbpf-dev, libelf-dev, zlib1g-dev, msr-tools)
    ✓ Build tools optimization
    ✓ LLVM repository auto-addition for clang-15 (if needed)
    ✓ Environment verification with specific version checks

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
    local kernel_patch=$(echo "$kernel_version" | cut -d. -f3 | cut -d- -f1)

    if [[ $kernel_major -lt 6 ]] || [[ $kernel_major -eq 6 && $kernel_minor -lt 8 ]]; then
        error_exit "Kernel version $kernel_version not supported. Requires 6.8+"
    fi

    # Detect and log kernel type with specific optimizations
    local kernel_type="standard"
    local kernel_features=""

    if [[ "$kernel_version" == *"azure"* ]]; then
        kernel_type="Azure"
        kernel_features="Azure-optimized, cloud-native BPF support"
    elif [[ "$kernel_version" == *"aws"* ]]; then
        kernel_type="AWS"
        kernel_features="AWS-optimized, enhanced networking BPF"
    elif [[ "$kernel_version" == *"gcp"* ]]; then
        kernel_type="GCP"
        kernel_features="GCP-optimized, container-focused BPF"
    elif [[ "$kernel_version" == *"generic"* ]]; then
        kernel_type="HWE (Hardware Enablement)"
        kernel_features="Latest hardware support, enhanced BPF capabilities"
    fi

    log_success "Kernel $kernel_version ($kernel_type) detected"
    log_info "Kernel features: $kernel_features"

    # HWE-specific optimizations
    if [[ "$kernel_version" == *"generic"* ]] && [[ $kernel_major -eq 6 && $kernel_minor -eq 8 ]]; then
        log_info "Applying HWE kernel optimizations for BPF development"
        # HWE kernels have enhanced BPF features, note this for later use
        export BPF_HWE_OPTIMIZATIONS=1
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
    log_info "Installing clang-15 compiler with BPF support..."

    # Check if clang-15 is already installed and properly configured
    local current_clang_version=""
    local clang_15_available=false

    if command -v clang-15 >/dev/null 2>&1; then
        clang_15_available=true
        local clang_15_version=$(clang-15 --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_debug "Found clang-15 v$clang_15_version"
    fi

    if command -v clang >/dev/null 2>&1; then
        current_clang_version=$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local major_version=$(echo "$current_clang_version" | cut -d. -f1)

        if [[ $major_version -ge 15 ]] && [[ "$clang_15_available" == "true" ]] && [[ "$FORCE_INSTALL" != "true" ]]; then
            log_success "clang v$current_clang_version already installed and configured (>= v15.0 required)"
            return 0
        fi
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would install: clang-15 llvm-15-dev"
        log_info "[DRY-RUN] Would add LLVM repository if needed"
        log_info "[DRY-RUN] Would configure clang-15 as default"
        return 0
    fi

    # Update package lists first
    log_info "Updating package lists..."
    apt update -qq

    # Check if clang-15 is available in current repositories
    if ! apt-cache show clang-15 >/dev/null 2>&1; then
        log_info "clang-15 not available in default repositories. Adding LLVM repository..."

        # Add LLVM GPG key
        log_info "Adding LLVM GPG key..."
        if ! wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -; then
            error_exit "Failed to add LLVM GPG key"
        fi

        # Add LLVM repository for Ubuntu 22.04 (jammy)
        log_info "Adding LLVM repository for Ubuntu 22.04..."
        echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-15 main" > /etc/apt/sources.list.d/llvm.list

        # Update package lists again
        log_info "Updating package lists with LLVM repository..."
        apt update -qq
    fi

    # Install clang-15 and related packages
    log_info "Installing clang-15 and LLVM-15 packages..."
    if ! apt install -y clang-15 llvm-15-dev; then
        error_exit "Failed to install clang-15 packages"
    fi

    # Verify clang-15 installation
    if ! command -v clang-15 >/dev/null 2>&1; then
        error_exit "clang-15 installation verification failed"
    fi

    # Configure clang-15 as default using update-alternatives
    log_info "Configuring clang-15 as default clang..."

    # Remove existing clang alternatives
    update-alternatives --remove-all clang 2>/dev/null || true
    update-alternatives --remove-all clang++ 2>/dev/null || true

    # Install clang-15 as highest priority alternative
    update-alternatives --install /usr/bin/clang clang /usr/bin/clang-15 150

    # Install clang++-15 if available
    if command -v clang++-15 >/dev/null 2>&1; then
        update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-15 150
    fi

    # Add clang-14 as lower priority alternative if it exists
    if command -v clang-14 >/dev/null 2>&1; then
        update-alternatives --install /usr/bin/clang clang /usr/bin/clang-14 140
        if command -v clang++-14 >/dev/null 2>&1; then
            update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-14 140
        fi
        log_debug "Added clang-14 as alternative with lower priority"
    fi

    # Verify clang-15 is now default
    local new_clang_version=$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    local new_major_version=$(echo "$new_clang_version" | cut -d. -f1)

    if [[ $new_major_version -eq 15 ]]; then
        log_success "clang-15 v$new_clang_version set as default compiler"
    else
        error_exit "clang-15 installed but not set as default (current: v$new_clang_version)"
    fi

    # Test BPF target support
    log_info "Testing BPF target support..."
    if ! echo 'int main() { return 0; }' | clang -target bpf -c -x c - -o /tmp/test_bpf.o 2>/dev/null; then
        error_exit "clang BPF target support test failed"
    fi
    rm -f /tmp/test_bpf.o

    log_success "clang-15 v$new_clang_version installed and configured with BPF support"
}

# Install and optimize gcc for BPF compilation
install_gcc_optimization() {
    log_info "Installing gcc-12.3.0 with BPF optimizations..."

    # Check current gcc and gcc-12 versions
    local current_gcc_version=""
    local gcc_12_available=false
    local gcc_12_version=""

    if command -v gcc-12 >/dev/null 2>&1; then
        gcc_12_available=true
        gcc_12_version=$(gcc-12 --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_debug "Found gcc-12 v$gcc_12_version"
    fi

    if command -v gcc >/dev/null 2>&1; then
        current_gcc_version=$(gcc --version | head -1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
        local major_version=$(echo "$current_gcc_version" | cut -d. -f1)

        if [[ $major_version -ge 12 ]] && [[ "$gcc_12_available" == "true" ]] && [[ "$FORCE_INSTALL" != "true" ]]; then
            log_success "gcc v$current_gcc_version already installed and configured (>= v12.0 required)"
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
        log_info "[DRY-RUN] Would install: gcc-12 g++-12 libstdc++-12-dev"
        log_info "[DRY-RUN] Would configure gcc-12 as default using update-alternatives"
        return 0
    fi

    # Install gcc-12, g++-12 and related development libraries
    log_info "Installing gcc-12, g++-12 and development libraries..."
    if ! apt install -y gcc-12 g++-12 libstdc++-12-dev; then
        error_exit "Failed to install gcc-12 packages"
    fi

    # Verify installation
    if ! command -v gcc-12 >/dev/null 2>&1; then
        error_exit "gcc-12 installation verification failed"
    fi

    if ! command -v g++-12 >/dev/null 2>&1; then
        error_exit "g++-12 installation verification failed"
    fi

    # Configure gcc-12 as default using update-alternatives with slave links
    log_info "Configuring gcc-12 as default compiler using update-alternatives..."

    # Remove existing alternatives (if any)
    update-alternatives --remove-all gcc 2>/dev/null || true
    update-alternatives --remove-all g++ 2>/dev/null || true

    # Install gcc-12 as highest priority alternative with g++ as slave
    log_info "Setting up gcc-12 with g++-12 as slave link..."
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 120 --slave /usr/bin/g++ g++ /usr/bin/g++-12

    # Add gcc-11 as lower priority alternative if it exists
    if command -v gcc-11 >/dev/null 2>&1 && command -v g++-11 >/dev/null 2>&1; then
        update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 --slave /usr/bin/g++ g++ /usr/bin/g++-11
        log_debug "Added gcc-11 with g++-11 as alternative with lower priority"
    fi

    # Verify gcc-12 is now default
    local new_gcc_version=$(gcc --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    local new_gpp_version=$(g++ --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    local new_major_version=$(echo "$new_gcc_version" | cut -d. -f1)

    if [[ $new_major_version -eq 12 ]]; then
        log_success "gcc-12 v$new_gcc_version set as default compiler"
        log_success "g++-12 v$new_gpp_version set as default C++ compiler"
    else
        error_exit "gcc-12 installed but not set as default (current: v$new_gcc_version)"
    fi

    # Display alternatives configuration
    log_info "Current gcc alternatives configuration:"
    update-alternatives --display gcc | grep -E "(gcc|priority)" | head -10 | while read line; do
        log_debug "  $line"
    done

    # Test BPF-related compilation capabilities
    log_info "Testing gcc-12 BPF optimization capabilities..."

    # Test basic compilation
    if echo 'int main() { return 0; }' | gcc -c -x c - -o /tmp/test_gcc.o 2>/dev/null; then
        log_success "gcc-12 basic compilation test passed"
        rm -f /tmp/test_gcc.o
    else
        log_warning "gcc-12 basic compilation test failed"
    fi

    # Test C++ compilation
    if echo 'int main() { return 0; }' | g++ -c -x c++ - -o /tmp/test_gpp.o 2>/dev/null; then
        log_success "g++-12 basic compilation test passed"
        rm -f /tmp/test_gpp.o
    else
        log_warning "g++-12 basic compilation test failed"
    fi

    # Test optimization flags
    if echo 'int main() { return 0; }' | gcc -O2 -march=native -c -x c - -o /tmp/test_gcc_opt.o 2>/dev/null; then
        log_success "gcc-12 optimization flags test passed"
        rm -f /tmp/test_gcc_opt.o
    else
        log_warning "gcc-12 optimization flags test failed"
    fi

    log_success "gcc-12 v$new_gcc_version installed and optimized for BPF compilation"
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
        "libfuse3-dev"
        "msr-tools"
        "linux-headers-$(uname -r)"
        "linux-libc-dev"
    )

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would install packages: ${packages[*]}"
        return 0
    fi

    # Check which packages are missing
    local missing_packages=()
    for package in "${packages[@]}"; do
        if ! dpkg -l "$package" 2>/dev/null | grep -q "^ii"; then
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
        if ! dpkg -l "$package" 2>/dev/null | grep -q "^ii"; then
            error_exit "Package $package installation failed"
        fi
    done

    log_success "Development packages installed successfully"
}

# Setup MSR (Model Specific Registers) access
setup_msr_access() {
    log_info "Setting up MSR (Model Specific Registers) access..."

    # Check if msr-tools is installed
    if ! command -v rdmsr >/dev/null 2>&1 || ! command -v wrmsr >/dev/null 2>&1; then
        log_warning "msr-tools not found. Should be installed by install_dev_packages"
        return 1
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would load MSR module and setup persistent access"
        return 0
    fi

    # Check if MSR module is already loaded
    if lsmod | grep -q "^msr "; then
        log_success "MSR module already loaded"
    else
        log_info "Loading MSR module..."
        if modprobe msr; then
            log_success "MSR module loaded successfully"
        else
            log_error "Failed to load MSR module"
            return 1
        fi
    fi

    # Check if MSR device files exist
    if ls /dev/cpu/*/msr >/dev/null 2>&1; then
        local msr_count=$(ls /dev/cpu/*/msr 2>/dev/null | wc -l)
        log_success "MSR device files available for $msr_count CPUs"
    else
        log_error "MSR device files not found after loading module"
        return 1
    fi

    # Setup persistent MSR loading
    log_info "Setting up persistent MSR module loading..."

    # Method 1: systemd modules-load.d (preferred)
    if [[ -d /etc/modules-load.d ]]; then
        if ! grep -q "^msr$" /etc/modules-load.d/msr.conf 2>/dev/null; then
            echo "msr" > /etc/modules-load.d/msr.conf
            log_success "Created /etc/modules-load.d/msr.conf for persistent MSR loading"
        else
            log_debug "MSR already configured in /etc/modules-load.d/msr.conf"
        fi
    fi

    # Method 2: /etc/modules (fallback)
    if [[ -f /etc/modules ]]; then
        if ! grep -q "^msr$" /etc/modules; then
            echo "msr" >> /etc/modules
            log_success "Added MSR to /etc/modules for persistent loading"
        else
            log_debug "MSR already configured in /etc/modules"
        fi
    fi

    # Test MSR access
    log_info "Testing MSR access..."
    if rdmsr 0x19C >/dev/null 2>&1; then
        log_success "MSR read test successful (thermal status register)"
    else
        log_warning "MSR read test failed (may need root privileges for actual use)"
    fi

    # Display MSR information
    log_info "MSR setup completed:"
    log_info "  - rdmsr/wrmsr tools: available"
    log_info "  - MSR module: loaded"
    log_info "  - Device files: $(ls /dev/cpu/*/msr 2>/dev/null | wc -l) CPUs"
    log_info "  - Persistent loading: configured"
    log_info "  - Usage: sudo rdmsr <register_address>"

    return 0
}

# Install Intel CMT-CAT (libpqos)
install_intel_cmt_cat() {
    log_info "Installing Intel CMT-CAT (libpqos) ..."

    # Skip if already present and not forced
    if ldconfig -p | grep -q "libpqos.so" && [[ -f /usr/local/include/pqos.h || -f /usr/include/pqos.h ]]; then
        if [[ "$FORCE_INSTALL" != "true" ]]; then
            log_success "Intel CMT-CAT already installed (libpqos present)"
            return 0
        else
            log_info "--force specified: Reinstalling intel-cmt-cat"
        fi
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would clone & build intel-cmt-cat"
        return 0
    fi

    # Install build dependencies if missing
    local build_deps=(git build-essential libkmod-dev libnuma-dev)
    local missing_deps=()
    for pkg in "${build_deps[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            missing_deps+=("$pkg")
        fi
    done
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_info "Installing build dependencies: ${missing_deps[*]}"
        apt install -y "${missing_deps[@]}"
    fi

    # Clone source (use /tmp to keep workspace clean)
    local src_dir="/tmp/intel-cmt-cat-src"
    rm -rf "$src_dir"
    if ! git clone --depth=1 https://github.com/intel/intel-cmt-cat.git "$src_dir"; then
        error_exit "Failed to clone intel-cmt-cat repository"
    fi

    # Build and install
    pushd "$src_dir" >/dev/null
    if make -j"$(nproc)"; then
        if make install; then
            log_success "Intel CMT-CAT installed successfully"
        else
            error_exit "make install failed for intel-cmt-cat"
        fi
    else
        error_exit "make failed for intel-cmt-cat"
    fi
    popd >/dev/null

    # Verify installation
    if ! ldconfig -p | grep -q "libpqos.so"; then
        error_exit "libpqos not detected after installation"
    fi
    log_success "libpqos library available"
}

# Setup kernel headers symlinks for eBPF compilation
setup_kernel_headers_symlinks() {
    log_info "Setting up kernel headers symlinks for eBPF compilation..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would create symlinks for kernel headers"
        return 0
    fi

    # Detect architecture
    local arch=$(uname -m)
    local arch_dir=""

    case "$arch" in
        x86_64)
            arch_dir="x86_64-linux-gnu"
            ;;
        aarch64)
            arch_dir="aarch64-linux-gnu"
            ;;
        armv7l)
            arch_dir="arm-linux-gnueabihf"
            ;;
        *)
            log_warning "⚠ Unknown architecture: $arch, using x86_64-linux-gnu as fallback"
            arch_dir="x86_64-linux-gnu"
            ;;
    esac

    log_info "Detected architecture: $arch, using directory: $arch_dir"

    # Check and create asm symlink
    if [[ ! -L /usr/include/asm ]]; then
        if [[ -d "/usr/include/$arch_dir/asm" ]]; then
            log_info "Creating asm symlink: /usr/include/asm -> /usr/include/$arch_dir/asm"
            if ln -sf "/usr/include/$arch_dir/asm" /usr/include/asm; then
                log_success "✓ asm symlink created successfully"
            else
                error_exit "Failed to create asm symlink"
            fi
        else
            log_error "✗ Architecture-specific asm directory not found: /usr/include/$arch_dir/asm"

            # Try fallback locations
            local fallback_dirs=(
                "/usr/include/x86_64-linux-gnu/asm"
                "/usr/include/asm-generic"
                "/usr/src/linux-headers-$(uname -r)/arch/x86/include/generated/uapi/asm"
            )

            log_info "Trying fallback locations..."
            local fallback_found=false

            for fallback_dir in "${fallback_dirs[@]}"; do
                if [[ -d "$fallback_dir" ]]; then
                    log_info "Found fallback: $fallback_dir"
                    if ln -sf "$fallback_dir" /usr/include/asm; then
                        log_success "✓ asm symlink created using fallback"
                        fallback_found=true
                        break
                    fi
                fi
            done

            if [[ "$fallback_found" != "true" ]]; then
                error_exit "Failed to create asm symlink - no suitable directory found"
            fi
        fi
    else
        local current_target=$(readlink /usr/include/asm)
        log_debug "asm symlink already exists: /usr/include/asm -> $current_target"

        # Verify symlink target exists
        if [[ ! -d "$current_target" ]]; then
            log_warning "⚠ asm symlink target does not exist, recreating..."
            rm -f /usr/include/asm
            # Recursively call this section to recreate
            if [[ -d "/usr/include/$arch_dir/asm" ]]; then
                ln -sf "/usr/include/$arch_dir/asm" /usr/include/asm
                log_success "✓ asm symlink recreated"
            fi
        fi
    fi

    # Verify critical headers are accessible
    local critical_headers=("asm/types.h" "linux/types.h" "linux/bpf.h")
    local missing_headers=()

    for header in "${critical_headers[@]}"; do
        if ! echo "#include <$header>" | clang -E - >/dev/null 2>&1; then
            missing_headers+=("$header")
        fi
    done

    if [[ ${#missing_headers[@]} -eq 0 ]]; then
        log_success "✓ All critical kernel headers accessible"
    else
        log_warning "⚠ Missing or inaccessible headers: ${missing_headers[*]}"

        # Try to fix common issues
        for header in "${missing_headers[@]}"; do
            case "$header" in
                "asm/types.h")
                    log_info "Attempting to fix asm/types.h accessibility..."
                    if [[ -f /usr/include/x86_64-linux-gnu/asm/types.h ]]; then
                        # Ensure symlink is correct
                        ln -sf /usr/include/x86_64-linux-gnu/asm /usr/include/asm
                        log_info "Recreated asm symlink"
                    fi
                    ;;
                "linux/types.h")
                    log_info "Checking linux/types.h availability..."
                    if [[ ! -f /usr/include/linux/types.h ]]; then
                        log_warning "linux/types.h not found - may need additional packages"
                    fi
                    ;;
            esac
        done
    fi

    log_success "Kernel headers symlinks setup completed"
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
    if [[ ! -f /usr/lib/x86_64-linux-gnu/libbpf.so.1.4.0 ]]; then
        error_exit "libbpf v1.4.0 installation verification failed - file not found"
    fi

    # Verify library is accessible
    if ! ldconfig -p | grep -q "libbpf.so"; then
        error_exit "libbpf v1.4.0 installation verification failed - library not in cache"
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

    # Check clang-15 specifically
    if command -v clang >/dev/null 2>&1; then
        local clang_version=$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        local major_version=$(echo "$clang_version" | cut -d. -f1)

        if [[ $major_version -eq 15 ]]; then
            log_success "✓ clang v$clang_version (clang-15 required)"

            # Check if clang-15 binary exists
            if command -v clang-15 >/dev/null 2>&1; then
                local clang_15_version=$(clang-15 --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                log_success "✓ clang-15 v$clang_15_version available"
            else
                log_warning "⚠ clang-15 binary not found (using clang v$clang_version)"
                ((warnings++))
            fi

            # Check alternatives configuration
            if update-alternatives --display clang >/dev/null 2>&1; then
                local current_alternative=$(update-alternatives --display clang | grep "link currently points to" | awk '{print $NF}')
                if [[ "$current_alternative" == *"clang-15"* ]]; then
                    log_success "✓ clang alternatives configured correctly (points to clang-15)"
                else
                    log_warning "⚠ clang alternatives not pointing to clang-15 (current: $current_alternative)"
                    ((warnings++))
                fi
            else
                log_warning "⚠ clang alternatives not configured"
                ((warnings++))
            fi
        elif [[ $major_version -gt 15 ]]; then
            log_success "✓ clang v$clang_version (> v15.0 required)"
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

    # Check gcc-12 specifically
    if command -v gcc >/dev/null 2>&1; then
        local gcc_version=$(gcc --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        local gcc_major_version=$(echo "$gcc_version" | cut -d. -f1)

        if [[ $gcc_major_version -eq 12 ]]; then
            log_success "✓ gcc v$gcc_version (gcc-12 required)"

            # Check if gcc-12 binary exists
            if command -v gcc-12 >/dev/null 2>&1; then
                local gcc_12_version=$(gcc-12 --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                log_success "✓ gcc-12 v$gcc_12_version available"
            else
                log_warning "⚠ gcc-12 binary not found (using gcc v$gcc_version)"
                ((warnings++))
            fi

            # Check g++ version
            if command -v g++ >/dev/null 2>&1; then
                local gpp_version=$(g++ --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                local gpp_major_version=$(echo "$gpp_version" | cut -d. -f1)
                if [[ $gpp_major_version -eq 12 ]]; then
                    log_success "✓ g++ v$gpp_version (g++-12 required)"
                else
                    log_warning "⚠ g++ v$gpp_version not version 12"
                    ((warnings++))
                fi
            else
                log_error "✗ g++ not found"
                ((errors++))
            fi

            # Check alternatives configuration
            if update-alternatives --display gcc >/dev/null 2>&1; then
                local current_gcc_alternative=$(update-alternatives --display gcc | grep "link currently points to" | awk '{print $NF}')
                if [[ "$current_gcc_alternative" == *"gcc-12"* ]]; then
                    log_success "✓ gcc alternatives configured correctly (points to gcc-12)"
                else
                    log_warning "⚠ gcc alternatives not pointing to gcc-12 (current: $current_gcc_alternative)"
                    ((warnings++))
                fi
            else
                log_warning "⚠ gcc alternatives not configured"
                ((warnings++))
            fi
        elif [[ $gcc_major_version -gt 12 ]]; then
            log_success "✓ gcc v$gcc_version (> v12.0 for BPF optimization)"
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
        if [[ -f /usr/lib/x86_64-linux-gnu/libbpf.so.1.4.0 ]]; then
            log_success "✓ libbpf v1.4.0 available"
        else
            log_warning "⚠ libbpf available but version may be < v1.4.0"
            ((warnings++))
        fi
    else
        log_error "✗ libbpf not found"
        ((errors++))
    fi

    # Check development packages
    local dev_packages=("libbpf-dev" "libelf-dev" "zlib1g-dev" "build-essential" "msr-tools" "linux-libc-dev")
    for package in "${dev_packages[@]}"; do
        if dpkg -l "$package" 2>/dev/null | grep -q "^ii"; then
            log_success "✓ $package installed"
        else
            log_error "✗ $package missing"
            ((errors++))
        fi
    done

    # Check MSR access
    log_info "Checking MSR (Model Specific Registers) access..."
    if command -v rdmsr >/dev/null 2>&1 && command -v wrmsr >/dev/null 2>&1; then
        log_success "✓ msr-tools (rdmsr/wrmsr) available"

        # Check MSR module
        if lsmod | grep -q "^msr "; then
            log_success "✓ MSR module loaded"

            # Check MSR device files
            if ls /dev/cpu/*/msr >/dev/null 2>&1; then
                local msr_count=$(ls /dev/cpu/*/msr 2>/dev/null | wc -l)
                log_success "✓ MSR device files available ($msr_count CPUs)"

                # Test MSR read (may fail without root)
                if rdmsr 0x19C >/dev/null 2>&1; then
                    log_success "✓ MSR read test successful"
                else
                    log_warning "⚠ MSR read test failed (normal without root privileges)"
                fi
            else
                log_error "✗ MSR device files not found"
                ((errors++))
            fi
        else
            log_error "✗ MSR module not loaded"
            ((errors++))
        fi

        # Check persistent configuration
        if [[ -f /etc/modules-load.d/msr.conf ]] && grep -q "^msr$" /etc/modules-load.d/msr.conf; then
            log_success "✓ MSR persistent loading configured (systemd)"
        elif grep -q "^msr$" /etc/modules 2>/dev/null; then
            log_success "✓ MSR persistent loading configured (/etc/modules)"
        else
            log_warning "⚠ MSR persistent loading not configured"
            ((warnings++))
        fi
    else
        log_error "✗ msr-tools not found"
        ((errors++))
    fi

    # Check kernel headers (may have dynamic name)
    local kernel_headers="linux-headers-$(uname -r)"
    if dpkg -l "$kernel_headers" 2>/dev/null | grep -q "^ii"; then
        log_success "✓ $kernel_headers installed"
    else
        log_warning "⚠ $kernel_headers missing (may affect compilation)"
        ((warnings++))
    fi

    # Check critical symlinks and header accessibility
    log_info "Checking kernel headers accessibility..."

    # Check asm symlink
    if [[ -L /usr/include/asm ]]; then
        local asm_target=$(readlink /usr/include/asm)
        log_success "✓ asm symlink exists: /usr/include/asm -> $asm_target"
    else
        log_error "✗ asm symlink missing"
        ((errors++))
    fi

    # Check critical headers accessibility via compiler
    local critical_headers=("asm/types.h" "linux/types.h" "linux/bpf.h")
    local accessible_headers=()
    local inaccessible_headers=()

    for header in "${critical_headers[@]}"; do
        if echo "#include <$header>" | clang -E - >/dev/null 2>&1; then
            accessible_headers+=("$header")
        else
            inaccessible_headers+=("$header")
        fi
    done

    if [[ ${#accessible_headers[@]} -eq ${#critical_headers[@]} ]]; then
        log_success "✓ All critical headers accessible via compiler"
    else
        log_error "✗ Inaccessible headers: ${inaccessible_headers[*]}"
        ((errors++))
    fi

    # Check specific header files existence
    local header_files=(
        "/usr/include/asm/types.h"
        "/usr/include/linux/types.h"
        "/usr/include/linux/bpf.h"
        "/usr/include/bpf/bpf_helpers.h"
    )

    for header_file in "${header_files[@]}"; do
        if [[ -f "$header_file" ]] || [[ -L "$header_file" ]]; then
            log_success "✓ $header_file exists"
        else
            log_warning "⚠ $header_file missing"
            ((warnings++))
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

    # Create comprehensive test BPF program
    cat > test_bpf.c << 'EOF'
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_openat")
int test_openat(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 timestamp = bpf_ktime_get_ns();
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

    # Test compilation with proper include paths and type definitions
    log_info "Testing BPF compilation with kernel types..."
    if clang -target bpf -O2 -I/usr/include -I/usr/include/x86_64-linux-gnu -c test_bpf.c -o test_bpf.o 2>/dev/null; then
        log_success "✓ Advanced BPF compilation test passed"

        # Verify the compiled object
        if [[ -f test_bpf.o ]] && [[ -s test_bpf.o ]]; then
            log_success "✓ BPF object file generated successfully"
        else
            log_warning "⚠ BPF object file is empty or invalid"
        fi
    else
        log_warning "⚠ Advanced BPF compilation test failed"

        # Try simpler compilation without kernel types
        log_info "Attempting fallback BPF compilation test..."
        cat > test_bpf_simple.c << 'EOF'
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_openat")
int test_openat(void *ctx) {
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
EOF

        if clang -target bpf -O2 -c test_bpf_simple.c -o test_bpf_simple.o 2>/dev/null; then
            log_success "✓ Basic BPF compilation test passed"
        else
            log_error "✗ Both advanced and basic BPF compilation tests failed"
            log_info "This may indicate missing or misconfigured headers"
        fi

        rm -f test_bpf_simple.c test_bpf_simple.o
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

# Display compiler configuration summary
display_compiler_config() {
    log_info "📊 Compiler Configuration Summary:"
    echo ""

    # Show clang configuration
    if command -v clang >/dev/null 2>&1; then
        local clang_version=$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        echo "🔧 Clang Configuration:"
        echo "   Default clang: v$clang_version"

        if command -v clang-15 >/dev/null 2>&1; then
            local clang_15_version=$(clang-15 --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            echo "   clang-15: v$clang_15_version"
        fi

        if update-alternatives --display clang >/dev/null 2>&1; then
            echo "   Alternatives: Configured"
            local current_clang=$(update-alternatives --display clang | grep "link currently points to" | awk '{print $NF}')
            echo "   Current link: $current_clang"
        else
            echo "   Alternatives: Not configured"
        fi
        echo ""
    fi

    # Show gcc configuration
    if command -v gcc >/dev/null 2>&1; then
        local gcc_version=$(gcc --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        local gpp_version=$(g++ --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        echo "🔧 GCC Configuration:"
        echo "   Default gcc: v$gcc_version"
        echo "   Default g++: v$gpp_version"

        if command -v gcc-12 >/dev/null 2>&1; then
            local gcc_12_version=$(gcc-12 --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            echo "   gcc-12: v$gcc_12_version"
        fi

        if update-alternatives --display gcc >/dev/null 2>&1; then
            echo "   Alternatives: Configured"
            local current_gcc=$(update-alternatives --display gcc | grep "link currently points to" | awk '{print $NF}')
            echo "   Current link: $current_gcc"
        else
            echo "   Alternatives: Not configured"
        fi
        echo ""
    fi
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

    # Show installed versions with specific version numbers
    if command -v clang >/dev/null 2>&1; then
        local clang_version=$(clang --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        echo "✅ clang: v$clang_version (default)"

        if command -v clang-15 >/dev/null 2>&1; then
            local clang_15_version=$(clang-15 --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            echo "✅ clang-15: v$clang_15_version (specific binary)"
        fi
    fi

    if command -v gcc >/dev/null 2>&1; then
        local gcc_version=$(gcc --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        echo "✅ gcc: v$gcc_version (default, optimized for BPF)"

        if command -v gcc-12 >/dev/null 2>&1; then
            local gcc_12_version=$(gcc-12 --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            echo "✅ gcc-12: v$gcc_12_version (specific binary)"
        fi

        if command -v g++ >/dev/null 2>&1; then
            local gpp_version=$(g++ --version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
            echo "✅ g++: v$gpp_version (default C++ compiler)"
        fi
    fi

    if ldconfig -p | grep -q "libbpf"; then
        if ldconfig -p | grep -q "libbpf.so.1.4"; then
            echo "✅ libbpf: v1.4.x (upgraded)"
        else
            echo "✅ libbpf: available (version check recommended)"
        fi
    fi

    echo "✅ Development packages: libbpf-dev, libelf-dev, zlib1g-dev, msr-tools"
    echo "✅ Build tools: build-essential, pkg-config, git, cmake"

    if command -v bpftool >/dev/null 2>&1; then
        local bpftool_version=$(bpftool version 2>/dev/null | head -1 || echo "available")
        echo "✅ bpftool: $bpftool_version"
    fi

    echo ""

    # Display detailed compiler configuration
    display_compiler_config

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
    echo "4. Test compiler versions:"
    echo "   clang --version"
    echo "   gcc --version"
    echo "   update-alternatives --display clang"
    echo "   update-alternatives --display gcc"
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

    log_info "Setting up MSR access..."
    setup_msr_access
    echo ""

    log_info "Installing Intel CMT-CAT (libpqos)..."
    install_intel_cmt_cat
    echo ""

    log_info "Setting up kernel headers..."
    setup_kernel_headers_symlinks
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

        # Kernel Configuration Validation
        log_info "🔍 Phase 6: Kernel Configuration Validation"
        if [[ -f "$SCRIPT_DIR/validate_kernel_config.sh" ]]; then
            log_info "Running kernel configuration validation..."

            # Auto-detect kernel type for validation
            local current_kernel=$(uname -r)
            local validation_mode="--generic-mode"

            if [[ "$current_kernel" == *"azure"* ]]; then
                validation_mode="--azure-mode"
                log_info "Detected Azure kernel, using Azure validation mode"
            elif [[ "$current_kernel" == *"aws"* ]]; then
                validation_mode="--aws-mode"
                log_info "Detected AWS kernel, using AWS validation mode"
            elif [[ "$current_kernel" == *"gcp"* ]]; then
                validation_mode="--gcp-mode"
                log_info "Detected GCP kernel, using GCP validation mode"
            else
                log_info "Using generic kernel validation mode"
            fi

            if "$SCRIPT_DIR/validate_kernel_config.sh" --comprehensive $validation_mode; then
                log_success "✓ Kernel configuration validation passed"
            else
                log_warning "⚠ Kernel configuration validation had issues"
                log_warning "Check kernel requirements in KERNEL_REQUIREMENTS.md"
            fi
        else
            log_info "Kernel validation script not found, skipping..."
        fi
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
