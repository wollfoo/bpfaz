#!/bin/bash

# ============================================================================
# BPF System Complete Cleanup Script
# ============================================================================
# Mục đích: Reset toàn bộ hệ thống eBPF về trạng thái ban đầu
# Tác giả: eBPF Development Team
# Ngày tạo: $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/bpf_cleanup_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/tmp/bpf_backup_$(date +%Y%m%d_%H%M%S)"
DRY_RUN=false
FORCE=false
VERBOSE=false

# ============================================================================
# Utility Functions
# ============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") [[ "$VERBOSE" == "true" ]] && echo -e "${BLUE}[DEBUG]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

confirm_action() {
    local message="$1"
    if [[ "$FORCE" == "true" ]]; then
        log "INFO" "Force mode: $message"
        return 0
    fi
    
    echo -e "${YELLOW}$message${NC}"
    read -p "Bạn có chắc chắn muốn tiếp tục? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        return 0
    else
        log "INFO" "Người dùng hủy bỏ thao tác"
        return 1
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "Script này cần quyền root để thực hiện"
        echo "Vui lòng chạy với: sudo $0"
        exit 1
    fi
}

create_backup() {
    log "INFO" "Tạo backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    
    # Backup pinned BPF objects
    if [[ -d "/sys/fs/bpf" ]]; then
        log "DEBUG" "Backup pinned BPF objects"
        sudo find /sys/fs/bpf -type f -exec cp {} "$BACKUP_DIR/" \; 2>/dev/null || true
    fi
    
    # Backup current BPF programs list
    sudo bpftool prog list > "$BACKUP_DIR/programs_before_cleanup.txt" 2>/dev/null || true
    sudo bpftool map list > "$BACKUP_DIR/maps_before_cleanup.txt" 2>/dev/null || true
    
    log "INFO" "Backup hoàn tất tại: $BACKUP_DIR"
}

# ============================================================================
# Phase 1: Process Cleanup (Dọn dẹp Tiến trình)
# ============================================================================

cleanup_processes() {
    log "INFO" "=== PHASE 1: Process Cleanup ==="
    
    if ! confirm_action "Dừng tất cả eBPF processes đang chạy?"; then
        return 1
    fi
    
    # Find and kill eBPF related processes
    local ebpf_processes=(
        "hide_process_loader"
        "hide_process_syncd"
        "cpu_throttle"
        "net_cloak"
        "blk_io_mask"
        "attach_"
    )
    
    for process in "${ebpf_processes[@]}"; do
        log "DEBUG" "Tìm kiếm processes: $process"
        local pids=$(pgrep -f "$process" 2>/dev/null || true)
        
        if [[ -n "$pids" ]]; then
            log "INFO" "Dừng processes: $process (PIDs: $pids)"
            if [[ "$DRY_RUN" == "false" ]]; then
                echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
                sleep 2
                # Force kill if still running
                echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
            fi
        else
            log "DEBUG" "Không tìm thấy process: $process"
        fi
    done
    
    # Kill any remaining sudo processes related to eBPF
    local sudo_pids=$(pgrep -f "sudo.*\(hide_process\|cpu_throttle\|net_cloak\|blk_io\)" 2>/dev/null || true)
    if [[ -n "$sudo_pids" ]]; then
        log "INFO" "Dừng sudo eBPF processes (PIDs: $sudo_pids)"
        if [[ "$DRY_RUN" == "false" ]]; then
            echo "$sudo_pids" | xargs -r kill -TERM 2>/dev/null || true
            sleep 2
            echo "$sudo_pids" | xargs -r kill -KILL 2>/dev/null || true
        fi
    fi
    
    # Verify no eBPF processes remain
    sleep 3
    local remaining=$(pgrep -f "\(hide_process\|cpu_throttle\|net_cloak\|blk_io\)" 2>/dev/null || true)
    if [[ -n "$remaining" ]]; then
        log "WARN" "Vẫn còn eBPF processes đang chạy: $remaining"
        return 1
    else
        log "INFO" "✓ Tất cả eBPF processes đã được dừng"
        return 0
    fi
}

# ============================================================================
# Phase 2: BPF Programs Cleanup (Dọn dẹp Chương trình BPF)
# ============================================================================

cleanup_bpf_programs() {
    log "INFO" "=== PHASE 2: BPF Programs Cleanup ==="
    
    if ! confirm_action "Detach và unload tất cả custom BPF programs?"; then
        return 1
    fi
    
    # Get list of all BPF programs
    local prog_ids=$(sudo bpftool prog list | grep -E "^[0-9]+:" | awk '{print $1}' | sed 's/:$//' || true)
    
    if [[ -z "$prog_ids" ]]; then
        log "INFO" "Không tìm thấy BPF programs nào"
        return 0
    fi
    
    log "INFO" "Tìm thấy $(echo "$prog_ids" | wc -l) BPF programs"
    
    # Filter out system programs (keep only custom programs)
    for prog_id in $prog_ids; do
        local prog_info=$(sudo bpftool prog show id "$prog_id" 2>/dev/null || true)
        
        # Skip if program info cannot be retrieved
        if [[ -z "$prog_info" ]]; then
            continue
        fi
        
        # Check if this is a custom program (has our naming patterns)
        if echo "$prog_info" | grep -qE "(hide_|on_|enhanced_|hid_)"; then
            log "INFO" "Unloading custom BPF program ID: $prog_id"
            if [[ "$DRY_RUN" == "false" ]]; then
                # Try to unload the program
                sudo bpftool prog detach id "$prog_id" 2>/dev/null || true
                # Note: Programs will be automatically unloaded when no longer referenced
            fi
        else
            log "DEBUG" "Keeping system BPF program ID: $prog_id"
        fi
    done
    
    log "INFO" "✓ Custom BPF programs cleanup hoàn tất"
    return 0
}

# ============================================================================
# Phase 3: BPF Maps Cleanup (Dọn dẹp BPF Maps)
# ============================================================================

cleanup_bpf_maps() {
    log "INFO" "=== PHASE 3: BPF Maps Cleanup ==="

    if ! confirm_action "Clear tất cả custom BPF maps?"; then
        return 1
    fi

    # Get list of all BPF maps
    local map_ids=$(sudo bpftool map list | grep -E "^[0-9]+:" | awk '{print $1}' | sed 's/:$//' || true)

    if [[ -z "$map_ids" ]]; then
        log "INFO" "Không tìm thấy BPF maps nào"
        return 0
    fi

    log "INFO" "Tìm thấy $(echo "$map_ids" | wc -l) BPF maps"

    # Filter and clean custom maps
    for map_id in $map_ids; do
        local map_info=$(sudo bpftool map show id "$map_id" 2>/dev/null || true)

        if [[ -z "$map_info" ]]; then
            continue
        fi

        # Check if this is a custom map
        if echo "$map_info" | grep -qE "(hidden_pid_map|events|obfuscation|auto_container|proc_dir_filter|filter_stats)"; then
            local map_name=$(echo "$map_info" | grep -o 'name [^ ]*' | awk '{print $2}')
            log "INFO" "Clearing custom BPF map: $map_name (ID: $map_id)"

            if [[ "$DRY_RUN" == "false" ]]; then
                # Try to clear the map contents
                sudo bpftool map delete id "$map_id" 2>/dev/null || true
            fi
        else
            log "DEBUG" "Keeping system BPF map ID: $map_id"
        fi
    done

    log "INFO" "✓ Custom BPF maps cleanup hoàn tất"
    return 0
}

# ============================================================================
# Phase 4: Pinned Objects Cleanup (Dọn dẹp Pinned Objects)
# ============================================================================

cleanup_pinned_objects() {
    log "INFO" "=== PHASE 4: Pinned Objects Cleanup ==="

    if ! confirm_action "Remove tất cả pinned BPF objects trong /sys/fs/bpf/?"; then
        return 1
    fi

    # Find all pinned objects
    local pinned_objects=$(sudo find /sys/fs/bpf -type f 2>/dev/null || true)

    if [[ -z "$pinned_objects" ]]; then
        log "INFO" "Không tìm thấy pinned BPF objects nào"
        return 0
    fi

    log "INFO" "Tìm thấy $(echo "$pinned_objects" | wc -l) pinned objects"

    # Remove pinned objects
    while IFS= read -r obj; do
        if [[ -n "$obj" ]]; then
            log "INFO" "Removing pinned object: $obj"
            if [[ "$DRY_RUN" == "false" ]]; then
                sudo rm -f "$obj" 2>/dev/null || true
            fi
        fi
    done <<< "$pinned_objects"

    # Remove empty directories
    local pinned_dirs=$(sudo find /sys/fs/bpf -type d -empty 2>/dev/null | grep -v "^/sys/fs/bpf$" || true)
    while IFS= read -r dir; do
        if [[ -n "$dir" ]]; then
            log "INFO" "Removing empty directory: $dir"
            if [[ "$DRY_RUN" == "false" ]]; then
                sudo rmdir "$dir" 2>/dev/null || true
            fi
        fi
    done <<< "$pinned_dirs"

    log "INFO" "✓ Pinned objects cleanup hoàn tất"
    return 0
}

# ============================================================================
# Phase 5: System-wide BPF Reset (Reset BPF Toàn hệ thống)
# ============================================================================

reset_bpf_subsystem() {
    log "INFO" "=== PHASE 5: System-wide BPF Reset ==="

    if ! confirm_action "Thực hiện system-wide BPF reset?"; then
        return 1
    fi

    # Check if bpffs is mounted
    if mount | grep -q "bpffs"; then
        log "INFO" "BPF filesystem đang được mount"

        # Remount bpffs to clear any remaining state
        if [[ "$DRY_RUN" == "false" ]]; then
            log "INFO" "Remounting BPF filesystem"
            sudo umount /sys/fs/bpf 2>/dev/null || true
            sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
        fi
    fi

    # Clear any remaining BPF-related kernel modules state
    log "INFO" "Clearing BPF subsystem state"

    # Force garbage collection of BPF objects
    if [[ "$DRY_RUN" == "false" ]]; then
        echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>&1 || true
    fi

    log "INFO" "✓ System-wide BPF reset hoàn tất"
    return 0
}

# ============================================================================
# Phase 6: Verification Steps (Bước Xác minh)
# ============================================================================

verify_cleanup() {
    log "INFO" "=== PHASE 6: Verification Steps ==="

    local errors=0

    # Verify no custom BPF programs remain
    log "INFO" "Kiểm tra BPF programs..."
    local remaining_progs=$(sudo bpftool prog list | grep -E "(hide_|on_|enhanced_|hid_)" || true)
    if [[ -n "$remaining_progs" ]]; then
        log "ERROR" "Vẫn còn custom BPF programs:"
        echo "$remaining_progs"
        ((errors++))
    else
        log "INFO" "✓ Không còn custom BPF programs"
    fi

    # Verify no custom BPF maps remain
    log "INFO" "Kiểm tra BPF maps..."
    local remaining_maps=$(sudo bpftool map list | grep -E "(hidden_pid_map|events|obfuscation|auto_container|proc_dir_filter|filter_stats)" || true)
    if [[ -n "$remaining_maps" ]]; then
        log "ERROR" "Vẫn còn custom BPF maps:"
        echo "$remaining_maps"
        ((errors++))
    else
        log "INFO" "✓ Không còn custom BPF maps"
    fi

    # Verify /sys/fs/bpf/ is clean
    log "INFO" "Kiểm tra pinned objects..."
    local remaining_pinned=$(sudo find /sys/fs/bpf -type f 2>/dev/null || true)
    if [[ -n "$remaining_pinned" ]]; then
        log "WARN" "Vẫn còn pinned objects:"
        echo "$remaining_pinned"
        # This might be acceptable for system objects
    else
        log "INFO" "✓ Không còn pinned objects"
    fi

    # Verify no eBPF processes running
    log "INFO" "Kiểm tra eBPF processes..."
    local remaining_procs=$(pgrep -f "\(hide_process\|cpu_throttle\|net_cloak\|blk_io\)" 2>/dev/null || true)
    if [[ -n "$remaining_procs" ]]; then
        log "ERROR" "Vẫn còn eBPF processes đang chạy:"
        ps aux | grep -E "(hide_process|cpu_throttle|net_cloak|blk_io)" | grep -v grep
        ((errors++))
    else
        log "INFO" "✓ Không còn eBPF processes đang chạy"
    fi

    # Summary
    if [[ $errors -eq 0 ]]; then
        log "INFO" "🎉 VERIFICATION PASSED: Hệ thống eBPF đã được reset hoàn toàn"
        return 0
    else
        log "ERROR" "❌ VERIFICATION FAILED: $errors lỗi được phát hiện"
        return 1
    fi
}

# ============================================================================
# Rollback Functions (Chức năng Rollback)
# ============================================================================

rollback_cleanup() {
    log "WARN" "=== ROLLBACK: Khôi phục từ backup ==="

    if [[ ! -d "$BACKUP_DIR" ]]; then
        log "ERROR" "Không tìm thấy backup directory: $BACKUP_DIR"
        return 1
    fi

    log "INFO" "Khôi phục từ: $BACKUP_DIR"

    # This is a placeholder for rollback functionality
    # In practice, rollback for BPF objects is complex and may not be fully possible
    log "WARN" "Rollback cho BPF objects có thể không hoàn toàn khả thi"
    log "INFO" "Vui lòng kiểm tra backup tại: $BACKUP_DIR"
    log "INFO" "Và khởi động lại các services cần thiết manually"

    return 0
}

# ============================================================================
# Main Functions
# ============================================================================

show_usage() {
    cat << EOF
Sử dụng: $0 [OPTIONS]

BPF System Complete Cleanup Script - Reset toàn bộ hệ thống eBPF về trạng thái ban đầu

OPTIONS:
    -h, --help          Hiển thị help này
    -n, --dry-run       Chế độ dry-run (không thực hiện thay đổi thực tế)
    -f, --force         Force mode (không hỏi xác nhận)
    -v, --verbose       Verbose output
    --rollback          Thực hiện rollback từ backup gần nhất

PHASES:
    1. Process Cleanup      - Dừng tất cả eBPF processes
    2. BPF Programs Cleanup - Detach và unload BPF programs
    3. BPF Maps Cleanup     - Clear tất cả BPF maps
    4. Pinned Objects       - Remove pinned objects trong /sys/fs/bpf/
    5. System Reset         - Reset BPF subsystem
    6. Verification         - Xác minh cleanup hoàn tất

EXAMPLES:
    sudo $0                 # Chạy cleanup với confirmations
    sudo $0 --dry-run       # Preview những gì sẽ được thực hiện
    sudo $0 --force         # Chạy mà không hỏi confirmations
    sudo $0 --rollback      # Rollback từ backup

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -n|--dry-run)
                DRY_RUN=true
                log "INFO" "Dry-run mode enabled"
                shift
                ;;
            -f|--force)
                FORCE=true
                log "INFO" "Force mode enabled"
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                log "INFO" "Verbose mode enabled"
                shift
                ;;
            --rollback)
                # Find latest backup
                local latest_backup=$(ls -1t /tmp/bpf_backup_* 2>/dev/null | head -1 || true)
                if [[ -n "$latest_backup" ]]; then
                    BACKUP_DIR="$latest_backup"
                    rollback_cleanup
                    exit $?
                else
                    log "ERROR" "Không tìm thấy backup nào"
                    exit 1
                fi
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

main() {
    # Initialize
    log "INFO" "=== BPF System Complete Cleanup Script ==="
    log "INFO" "Bắt đầu lúc: $(date '+%Y-%m-%d %H:%M:%S')"
    log "INFO" "Log file: $LOG_FILE"

    # Check prerequisites
    check_root

    # Create backup before starting
    create_backup

    # Execute cleanup phases
    local phase_errors=0

    # Phase 1: Process Cleanup
    if ! cleanup_processes; then
        log "ERROR" "Phase 1 failed: Process Cleanup"
        ((phase_errors++))
    fi

    # Phase 2: BPF Programs Cleanup
    if ! cleanup_bpf_programs; then
        log "ERROR" "Phase 2 failed: BPF Programs Cleanup"
        ((phase_errors++))
    fi

    # Phase 3: BPF Maps Cleanup
    if ! cleanup_bpf_maps; then
        log "ERROR" "Phase 3 failed: BPF Maps Cleanup"
        ((phase_errors++))
    fi

    # Phase 4: Pinned Objects Cleanup
    if ! cleanup_pinned_objects; then
        log "ERROR" "Phase 4 failed: Pinned Objects Cleanup"
        ((phase_errors++))
    fi

    # Phase 5: System-wide BPF Reset
    if ! reset_bpf_subsystem; then
        log "ERROR" "Phase 5 failed: System-wide BPF Reset"
        ((phase_errors++))
    fi

    # Phase 6: Verification
    if ! verify_cleanup; then
        log "ERROR" "Phase 6 failed: Verification"
        ((phase_errors++))
    fi

    # Final summary
    log "INFO" "=== CLEANUP SUMMARY ==="
    if [[ $phase_errors -eq 0 ]]; then
        log "INFO" "🎉 SUCCESS: Tất cả phases hoàn thành thành công"
        log "INFO" "Hệ thống eBPF đã được reset về clean state"
        log "INFO" "Backup được lưu tại: $BACKUP_DIR"
        exit 0
    else
        log "ERROR" "❌ FAILED: $phase_errors phases gặp lỗi"
        log "ERROR" "Kiểm tra log file: $LOG_FILE"
        log "INFO" "Để rollback, chạy: $0 --rollback"
        exit 1
    fi
}

# ============================================================================
# Script Entry Point
# ============================================================================

# Parse command line arguments
parse_arguments "$@"

# Run main function
main
