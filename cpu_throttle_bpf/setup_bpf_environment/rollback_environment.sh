#!/bin/bash
# rollback_environment.sh - eBPF Environment Rollback Script
# Script khôi phục môi trường eBPF về trạng thái ban đầu
#
# Usage: ./rollback_environment.sh [--backup-dir /path/to/backup] [--force]

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BACKUP_DIR=""
FORCE_ROLLBACK=false
DRY_RUN=false

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

# Error handling
error_exit() {
    log_error "$1"
    exit 1
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Rollback eBPF development environment to previous state.

OPTIONS:
    --backup-dir DIR    Specify backup directory path
    --force             Force rollback without confirmation
    --dry-run           Show what would be done without executing
    -h, --help          Show this help message

EXAMPLES:
    $0                                          # Interactive rollback
    $0 --backup-dir /tmp/ebpf_setup_backup_*    # Use specific backup
    $0 --force                                  # Force rollback without prompts
    $0 --dry-run                               # Preview rollback actions

ROLLBACK ACTIONS:
    ✓ Remove installed clang/llvm packages
    ✓ Restore original libbpf library files
    ✓ Remove development packages
    ✓ Clean up temporary files
    ✓ Restore system package state

EOF
}

# Parse arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --backup-dir)
                BACKUP_DIR="$2"
                shift 2
                ;;
            --force)
                FORCE_ROLLBACK=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
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

# Banner
print_banner() {
    echo "================================================================"
    echo "  🔄 eBPF Environment Rollback"
    echo "  Restore system to pre-installation state"
    echo "================================================================"
    echo ""
}

# Find backup directory
find_backup_directory() {
    if [[ -n "$BACKUP_DIR" ]]; then
        if [[ ! -d "$BACKUP_DIR" ]]; then
            error_exit "Specified backup directory not found: $BACKUP_DIR"
        fi
        log_info "Using specified backup directory: $BACKUP_DIR"
        return 0
    fi
    
    # Look for recent backup directories
    local backup_pattern="/tmp/ebpf_setup_backup_*"
    local backup_dirs=($(ls -dt $backup_pattern 2>/dev/null || true))
    
    if [[ ${#backup_dirs[@]} -eq 0 ]]; then
        log_warning "No backup directories found matching: $backup_pattern"
        log_info "Will proceed with package-based rollback only"
        return 0
    fi
    
    if [[ ${#backup_dirs[@]} -eq 1 ]]; then
        BACKUP_DIR="${backup_dirs[0]}"
        log_info "Found backup directory: $BACKUP_DIR"
        return 0
    fi
    
    # Multiple backups found - let user choose
    echo "Multiple backup directories found:"
    for i in "${!backup_dirs[@]}"; do
        local backup_date=$(basename "${backup_dirs[$i]}" | sed 's/ebpf_setup_backup_//')
        echo "  $((i+1)). ${backup_dirs[$i]} (created: $backup_date)"
    done
    
    if [[ "$FORCE_ROLLBACK" == "true" ]]; then
        BACKUP_DIR="${backup_dirs[0]}"
        log_info "Using most recent backup (--force): $BACKUP_DIR"
    else
        echo ""
        read -p "Select backup to use (1-${#backup_dirs[@]}): " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le ${#backup_dirs[@]} ]]; then
            BACKUP_DIR="${backup_dirs[$((choice-1))]}"
            log_info "Selected backup: $BACKUP_DIR"
        else
            error_exit "Invalid selection"
        fi
    fi
}

# Confirm rollback
confirm_rollback() {
    if [[ "$FORCE_ROLLBACK" == "true" ]] || [[ "$DRY_RUN" == "true" ]]; then
        return 0
    fi
    
    echo ""
    log_warning "This will rollback the following changes:"
    echo "  - Remove clang and LLVM packages"
    echo "  - Restore original gcc configuration"
    echo "  - Restore original libbpf library"
    echo "  - Remove development packages"
    echo "  - Clean up installed files"
    echo ""
    
    if [[ -n "$BACKUP_DIR" ]]; then
        echo "Using backup from: $BACKUP_DIR"
    else
        echo "No backup available - package-based rollback only"
    fi
    
    echo ""
    read -p "Are you sure you want to proceed? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Rollback cancelled by user"
        exit 0
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root (use sudo)"
    fi
}

# Remove clang packages
remove_clang() {
    log_info "Removing clang and LLVM packages..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would remove: clang llvm"
        return 0
    fi
    
    # Check if clang is installed
    if ! command -v clang >/dev/null 2>&1; then
        log_info "clang not found - skipping removal"
        return 0
    fi
    
    # Remove packages
    if apt remove --purge -y clang llvm 2>/dev/null; then
        log_success "clang and LLVM packages removed"
    else
        log_warning "Failed to remove some clang/LLVM packages"
    fi
    
    # Clean up any remaining files
    rm -f /usr/bin/clang* /usr/bin/llvm* 2>/dev/null || true
}

# Restore gcc configuration
restore_gcc_config() {
    log_info "Restoring original gcc configuration..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would restore gcc alternatives"
        return 0
    fi

    # Remove gcc-12 alternatives
    update-alternatives --remove-all gcc 2>/dev/null || true
    update-alternatives --remove-all g++ 2>/dev/null || true

    # Restore default gcc-11 if available
    if command -v gcc-11 >/dev/null 2>&1; then
        update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110
        update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 110
        log_success "Restored gcc-11 as default"
    else
        log_warning "gcc-11 not found - manual gcc configuration may be needed"
    fi

    # Optionally remove gcc-12 packages
    if dpkg -l | grep -q "^ii  gcc-12 "; then
        if apt remove --purge -y gcc-12 g++-12 2>/dev/null; then
            log_success "gcc-12 packages removed"
        else
            log_warning "Failed to remove gcc-12 packages"
        fi
    fi
}

# Restore libbpf
restore_libbpf() {
    log_info "Restoring original libbpf library..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would restore libbpf from backup"
        return 0
    fi
    
    if [[ -z "$BACKUP_DIR" ]]; then
        log_warning "No backup directory - attempting package-based restore"
        
        # Remove any manually installed libbpf files
        rm -f /usr/lib/x86_64-linux-gnu/libbpf.so.1.4.* 2>/dev/null || true
        
        # Reinstall original package
        if apt install --reinstall -y libbpf0 2>/dev/null; then
            log_success "libbpf package reinstalled"
        else
            log_warning "Failed to reinstall libbpf package"
        fi
        
        ldconfig
        return 0
    fi
    
    # Restore from backup
    if [[ -f "$BACKUP_DIR/libbpf.so.0.5.0" ]]; then
        log_info "Restoring libbpf files from backup..."
        
        # Remove new files
        rm -f /usr/lib/x86_64-linux-gnu/libbpf.so.1.4.* 2>/dev/null || true
        
        # Restore original files
        cp "$BACKUP_DIR"/libbpf.so* /usr/lib/x86_64-linux-gnu/ 2>/dev/null || true
        
        # Update library cache
        ldconfig
        
        log_success "libbpf restored from backup"
    else
        log_warning "No libbpf backup found - using package reinstall"
        apt install --reinstall -y libbpf0 2>/dev/null || true
        ldconfig
    fi
}

# Remove development packages
remove_dev_packages() {
    log_info "Removing development packages..."
    
    local packages=(
        "libbpf-dev"
        "libelf-dev"
        "zlib1g-dev"
    )
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would remove packages: ${packages[*]}"
        return 0
    fi
    
    # Check which packages are installed
    local installed_packages=()
    for package in "${packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            installed_packages+=("$package")
        fi
    done
    
    if [[ ${#installed_packages[@]} -eq 0 ]]; then
        log_info "No development packages to remove"
        return 0
    fi
    
    log_info "Removing packages: ${installed_packages[*]}"
    if apt remove --purge -y "${installed_packages[@]}" 2>/dev/null; then
        log_success "Development packages removed"
    else
        log_warning "Failed to remove some development packages"
    fi
    
    # Clean up
    apt autoremove -y 2>/dev/null || true
}

# Clean up temporary files
cleanup_temp_files() {
    log_info "Cleaning up temporary files..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would clean up temporary files"
        return 0
    fi
    
    # Remove compilation test files
    rm -rf /tmp/bpf_*test* 2>/dev/null || true
    rm -rf /tmp/libbpf_upgrade_* 2>/dev/null || true
    
    # Remove log files (but keep backup)
    rm -f /tmp/ebpf_setup.log 2>/dev/null || true
    
    log_success "Temporary files cleaned up"
}

# Verify rollback
verify_rollback() {
    log_info "Verifying rollback..."
    
    local issues=0
    
    # Check clang removal
    if command -v clang >/dev/null 2>&1; then
        log_warning "clang still present after removal"
        ((issues++))
    else
        log_success "clang successfully removed"
    fi
    
    # Check libbpf version
    if ldconfig -p | grep -q "libbpf.so.1.4"; then
        log_warning "libbpf v1.4.x still present"
        ((issues++))
    elif ldconfig -p | grep -q "libbpf.so.0"; then
        log_success "libbpf restored to v0.x"
    else
        log_warning "libbpf status unclear"
        ((issues++))
    fi
    
    # Check development packages
    local dev_packages=("libbpf-dev" "libelf-dev" "zlib1g-dev")
    for package in "${dev_packages[@]}"; do
        if dpkg -l | grep -q "^ii  $package "; then
            log_warning "$package still installed"
            ((issues++))
        fi
    done
    
    if [[ $issues -eq 0 ]]; then
        log_success "Rollback verification passed"
        return 0
    else
        log_warning "Rollback verification found $issues issues"
        return 1
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "================================================================"
    log_success "🎉 eBPF Environment Rollback Complete!"
    echo "================================================================"
    echo ""
    echo "📋 Rollback Summary:"
    echo ""
    echo "✅ clang and LLVM packages removed"
    echo "✅ gcc configuration restored to original state"
    echo "✅ libbpf library restored to original version"
    echo "✅ Development packages removed"
    echo "✅ Temporary files cleaned up"
    echo ""
    
    if [[ -n "$BACKUP_DIR" ]]; then
        echo "💾 Backup directory preserved: $BACKUP_DIR"
        echo "   (You can safely delete this directory if no longer needed)"
        echo ""
    fi
    
    echo "🔍 To verify system state:"
    echo "   clang --version          # Should show 'command not found'"
    echo "   ldconfig -p | grep libbpf # Should show v0.x"
    echo "   dpkg -l | grep -E 'clang|libbpf-dev' # Should show no results"
    echo ""
    
    echo "🚀 To reinstall eBPF environment:"
    echo "   sudo $(dirname "$0")/setup_dev_environment.sh"
    echo ""
}

# Main execution
main() {
    parse_arguments "$@"
    print_banner
    
    check_root
    find_backup_directory
    confirm_rollback
    
    log_info "🔄 Starting rollback process..."
    echo ""
    
    remove_clang
    restore_gcc_config
    restore_libbpf
    remove_dev_packages
    cleanup_temp_files
    
    echo ""
    if verify_rollback; then
        print_summary
        exit 0
    else
        log_error "Rollback completed with some issues"
        log_info "Manual cleanup may be required"
        exit 1
    fi
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
