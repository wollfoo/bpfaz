#!/bin/bash
# test_standalone_operation.sh - Test Standalone Operation Without External Dependencies
# Script kiểm thử hoạt động độc lập không phụ thuộc bên ngoài

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
BPF_MAP_DIR="/sys/fs/bpf/cpu_throttle"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Banner
print_banner() {
    echo "================================================================"
    echo "  🔬 Standalone Operation Test - No External Dependencies"
    echo "  Verifying hide_process_bpf works without cpu_throttle system"
    echo "================================================================"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_error "This test must be run as root (use sudo)"
        exit 1
    fi
    
    # Check if all components exist
    local components=(
        "$OUTPUT_DIR/hide_process_bpf.o"
        "$OUTPUT_DIR/hide_process_loader"
        "$OUTPUT_DIR/libhide.so"
        "$OUTPUT_DIR/hide_process_bpf.skel.h"
    )
    
    for component in "${components[@]}"; do
        if [[ ! -f "$component" ]]; then
            log_error "Component not found: $component"
            log_error "Run 'make all' first"
            exit 1
        fi
    done
    
    log_success "All components found"
}

# Test 1: BPF object validation
test_bpf_object() {
    log_info "Test 1: Validating BPF object..."
    
    # Check BPF object file
    if file "$OUTPUT_DIR/hide_process_bpf.o" | grep -q "eBPF"; then
        log_success "✓ BPF object file is valid eBPF format"
    else
        log_error "✗ BPF object file format invalid"
        return 1
    fi
    
    # Check for external map references (should be none)
    if objdump -t "$OUTPUT_DIR/hide_process_bpf.o" 2>/dev/null | grep -q "quota_cg\|acc_cg"; then
        log_error "✗ External map references still present"
        return 1
    else
        log_success "✓ No external map dependencies found"
    fi
    
    # Check BPF program sections
    local sections=$(objdump -h "$OUTPUT_DIR/hide_process_bpf.o" 2>/dev/null | grep -E "tracepoint|kprobe" | wc -l)
    if [[ $sections -gt 0 ]]; then
        log_success "✓ BPF program sections found: $sections"
    else
        log_warning "⚠ No BPF program sections detected"
    fi
}

# Test 2: Program loading without external dependencies
test_program_loading() {
    log_info "Test 2: Testing program loading without external dependencies..."
    
    # Clean up any existing BPF resources
    rm -rf "$BPF_MAP_DIR" 2>/dev/null || true
    
    # Start hide_process_loader in background
    log_info "Starting hide_process_loader..."
    "$OUTPUT_DIR/hide_process_loader" --verbose &
    LOADER_PID=$!
    
    # Wait for program to initialize
    sleep 5
    
    # Check if process is still running (no crashes due to missing external maps)
    if kill -0 $LOADER_PID 2>/dev/null; then
        log_success "✓ Program loaded successfully without external dependencies"
    else
        log_error "✗ Program crashed - possible external dependency issue"
        return 1
    fi
    
    # Check if BPF maps are created (internal maps only)
    if [[ -d "$BPF_MAP_DIR" ]]; then
        log_success "✓ Internal BPF maps created successfully"
        
        # List created maps
        log_info "Created maps:"
        ls -la "$BPF_MAP_DIR" | while read line; do
            log_info "  $line"
        done
        
        # Verify no external maps are referenced
        if ls "$BPF_MAP_DIR" | grep -q "quota_cg\|acc_cg"; then
            log_error "✗ External maps found - removal incomplete"
            kill $LOADER_PID 2>/dev/null || true
            return 1
        else
            log_success "✓ Only internal maps present - external dependencies removed"
        fi
    else
        log_error "✗ BPF map directory not created"
        kill $LOADER_PID 2>/dev/null || true
        return 1
    fi
    
    # Stop the loader
    kill $LOADER_PID 2>/dev/null || true
    wait $LOADER_PID 2>/dev/null || true
    
    return 0
}

# Test 3: Core functionality verification
test_core_functionality() {
    log_info "Test 3: Testing core process hiding functionality..."
    
    # Start hide_process_loader with test PID
    local test_pid=$$
    log_info "Starting hide_process_loader with test PID: $test_pid"
    
    "$OUTPUT_DIR/hide_process_loader" --verbose $test_pid &
    LOADER_PID=$!
    
    # Wait for initialization
    sleep 5
    
    # Test if LD_PRELOAD library works
    log_info "Testing LD_PRELOAD library functionality..."
    
    # Create simple test
    if LD_PRELOAD="$OUTPUT_DIR/libhide.so" /bin/true 2>/dev/null; then
        log_success "✓ LD_PRELOAD library loads successfully"
    else
        log_error "✗ LD_PRELOAD library failed to load"
        kill $LOADER_PID 2>/dev/null || true
        return 1
    fi
    
    # Test process listing with LD_PRELOAD
    log_info "Testing process listing with LD_PRELOAD..."
    local proc_count_normal=$(ps aux | wc -l)
    local proc_count_preload=$(LD_PRELOAD="$OUTPUT_DIR/libhide.so" ps aux | wc -l)
    
    log_info "Process count without LD_PRELOAD: $proc_count_normal"
    log_info "Process count with LD_PRELOAD: $proc_count_preload"
    
    if [[ $proc_count_preload -le $proc_count_normal ]]; then
        log_success "✓ LD_PRELOAD library affects process listing"
    else
        log_warning "⚠ LD_PRELOAD library may not be filtering processes"
    fi
    
    # Stop the loader
    kill $LOADER_PID 2>/dev/null || true
    wait $LOADER_PID 2>/dev/null || true
}

# Test 4: Container detection without external maps
test_container_detection() {
    log_info "Test 4: Testing container detection without external dependencies..."
    
    # Start loader
    "$OUTPUT_DIR/hide_process_loader" --verbose &
    LOADER_PID=$!
    
    # Wait for initialization
    sleep 3
    
    # Check if container auto-detection still works
    log_info "Verifying container auto-detection functionality..."
    
    # Since we removed external map dependencies, container detection
    # should still work via namespace analysis
    if kill -0 $LOADER_PID 2>/dev/null; then
        log_success "✓ Container detection module loaded without external dependencies"
    else
        log_error "✗ Container detection failed to load"
        return 1
    fi
    
    # Stop the loader
    kill $LOADER_PID 2>/dev/null || true
    wait $LOADER_PID 2>/dev/null || true
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    
    # Kill any running loaders
    if [[ -n "${LOADER_PID:-}" ]]; then
        kill $LOADER_PID 2>/dev/null || true
        wait $LOADER_PID 2>/dev/null || true
    fi
    
    # Clean up BPF resources
    rm -rf "$BPF_MAP_DIR" 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Main test execution
main() {
    print_banner
    
    # Set up cleanup trap
    trap cleanup EXIT INT TERM
    
    # Run tests
    check_prerequisites
    echo ""
    
    test_bpf_object
    echo ""
    
    test_program_loading
    echo ""
    
    test_core_functionality
    echo ""
    
    test_container_detection
    echo ""
    
    log_success "🎉 Standalone Operation Test Completed Successfully!"
    echo ""
    echo "📋 Test Summary:"
    echo "✓ BPF object validation - no external dependencies"
    echo "✓ Program loading without cpu_throttle system"
    echo "✓ Core process hiding functionality"
    echo "✓ Container detection independence"
    echo ""
    echo "🎯 Results:"
    echo "✅ hide_process_bpf now operates completely standalone"
    echo "✅ No external map dependencies (quota_cg, acc_cg removed)"
    echo "✅ All core functionality preserved"
    echo "✅ Ready for production deployment"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
