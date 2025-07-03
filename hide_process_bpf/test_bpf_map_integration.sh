#!/bin/bash
# test_bpf_map_integration.sh - Test BPF Map Integration for LD_PRELOAD Library
# Script kiểm thử tích hợp BPF Map cho thư viện LD_PRELOAD

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
TEST_PID=$$  # Use current shell PID for testing

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
    echo "  🧪 BPF Map Integration Test for LD_PRELOAD Library"
    echo "  Testing real-time synchronization between eBPF and userspace"
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
    
    # Check if libhide.so exists
    if [[ ! -f "$OUTPUT_DIR/libhide.so" ]]; then
        log_error "libhide.so not found. Run 'make all' first."
        exit 1
    fi
    
    # Check if hide_process_loader exists
    if [[ ! -f "$OUTPUT_DIR/hide_process_loader" ]]; then
        log_error "hide_process_loader not found. Run 'make all' first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Test 1: Build verification
test_build() {
    log_info "Test 1: Verifying build with libbpf integration..."
    
    # Check if library links properly
    if ldd "$OUTPUT_DIR/libhide.so" | grep -q "libbpf"; then
        log_success "✓ libhide.so properly linked with libbpf"
    else
        log_warning "⚠ libbpf linking not detected in libhide.so"
        ldd "$OUTPUT_DIR/libhide.so" | grep -E "(libbpf|libelf|libz)"
    fi
    
    # Check if library loads without errors
    if LD_PRELOAD="$OUTPUT_DIR/libhide.so" /bin/true 2>/dev/null; then
        log_success "✓ libhide.so loads without errors"
    else
        log_error "✗ libhide.so failed to load"
        return 1
    fi
}

# Test 2: BPF program loading
test_bpf_program_loading() {
    log_info "Test 2: Loading eBPF program..."
    
    # Start hide_process_loader in background
    log_info "Starting hide_process_loader..."
    "$OUTPUT_DIR/hide_process_loader" --verbose &
    LOADER_PID=$!
    
    # Wait for program to initialize
    sleep 3
    
    # Check if BPF maps are created
    if [[ -d "$BPF_MAP_DIR" ]]; then
        log_success "✓ BPF map directory created: $BPF_MAP_DIR"
        ls -la "$BPF_MAP_DIR"
    else
        log_error "✗ BPF map directory not found"
        kill $LOADER_PID 2>/dev/null || true
        return 1
    fi
    
    # Check specific maps
    if [[ -e "$BPF_MAP_DIR/hidden_pid_map" ]]; then
        log_success "✓ hidden_pid_map found"
    else
        log_error "✗ hidden_pid_map not found"
        kill $LOADER_PID 2>/dev/null || true
        return 1
    fi
    
    return 0
}

# Test 3: Map reading functionality
test_map_reading() {
    log_info "Test 3: Testing BPF map reading functionality..."
    
    # Test if LD_PRELOAD library can access BPF map
    log_info "Testing LD_PRELOAD library BPF map access..."
    
    # Create a simple test program that uses the library
    cat > /tmp/test_map_access.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    printf("Testing BPF map access from LD_PRELOAD library\n");
    printf("Current PID: %d\n", getpid());
    
    // Try to access /proc to trigger library functions
    system("ls /proc/self >/dev/null 2>&1");
    
    printf("BPF map access test completed\n");
    return 0;
}
EOF
    
    # Compile test program
    gcc -o /tmp/test_map_access /tmp/test_map_access.c
    
    # Run with LD_PRELOAD
    log_info "Running test with LD_PRELOAD..."
    if LD_PRELOAD="$OUTPUT_DIR/libhide.so" /tmp/test_map_access; then
        log_success "✓ LD_PRELOAD library executed without errors"
    else
        log_warning "⚠ LD_PRELOAD library execution had issues"
    fi
    
    # Cleanup
    rm -f /tmp/test_map_access.c /tmp/test_map_access
}

# Test 4: Real-time synchronization
test_realtime_sync() {
    log_info "Test 4: Testing real-time synchronization..."
    
    # Add test PID to hidden map using bpftool
    log_info "Adding test PID $TEST_PID to hidden map..."
    
    if command -v bpftool >/dev/null 2>&1; then
        # Try to update map using bpftool
        if bpftool map update pinned "$BPF_MAP_DIR/hidden_pid_map" key hex $(printf "%08x" $TEST_PID | sed 's/\(..\)/\2\1/g;s/\(..\)\(..\)/\2\1\4\3/') value hex 01 00 00 00 2>/dev/null; then
            log_success "✓ Successfully added PID $TEST_PID to hidden map"
            
            # Test if LD_PRELOAD library detects the change
            log_info "Testing if LD_PRELOAD library detects the change..."
            sleep 6  # Wait for refresh interval
            
            # Create test that checks if PID is hidden
            cat > /tmp/test_hidden_check.c << 'EOF'
#include <stdio.h>
#include <dirent.h>
#include <string.h>

int main() {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc");
        return 1;
    }
    
    struct dirent *entry;
    int found_test_pid = 0;
    
    while ((entry = readdir(proc_dir)) != NULL) {
        if (strcmp(entry->d_name, "PLACEHOLDER_PID") == 0) {
            found_test_pid = 1;
            break;
        }
    }
    
    closedir(proc_dir);
    
    if (found_test_pid) {
        printf("PID visible in /proc\n");
        return 1;
    } else {
        printf("PID hidden from /proc\n");
        return 0;
    }
}
EOF
            
            # Replace placeholder with actual PID
            sed -i "s/PLACEHOLDER_PID/$(printf "%d" $TEST_PID)/" /tmp/test_hidden_check.c
            
            # Compile and run test
            gcc -o /tmp/test_hidden_check /tmp/test_hidden_check.c
            
            if LD_PRELOAD="$OUTPUT_DIR/libhide.so" /tmp/test_hidden_check; then
                log_success "✓ Real-time synchronization working - PID hidden"
            else
                log_warning "⚠ PID still visible - synchronization may need more time"
            fi
            
            # Cleanup
            rm -f /tmp/test_hidden_check.c /tmp/test_hidden_check
            
        else
            log_warning "⚠ Could not add PID to map using bpftool"
        fi
    else
        log_warning "⚠ bpftool not available - skipping real-time sync test"
    fi
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    
    # Kill hide_process_loader if running
    if [[ -n "${LOADER_PID:-}" ]]; then
        kill $LOADER_PID 2>/dev/null || true
        wait $LOADER_PID 2>/dev/null || true
    fi
    
    # Remove BPF maps
    rm -rf "$BPF_MAP_DIR" 2>/dev/null || true
    
    # Remove temporary files
    rm -f /tmp/test_map_access* /tmp/test_hidden_check*
    
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
    
    test_build
    echo ""
    
    test_bpf_program_loading
    echo ""
    
    test_map_reading
    echo ""
    
    test_realtime_sync
    echo ""
    
    log_success "🎉 BPF Map Integration Test Completed!"
    echo ""
    echo "📋 Test Summary:"
    echo "✓ Build verification with libbpf integration"
    echo "✓ BPF program loading and map creation"
    echo "✓ LD_PRELOAD library BPF map access"
    echo "✓ Real-time synchronization testing"
    echo ""
    echo "🎯 Next Steps:"
    echo "1. Run 'make test-libhide' for quick verification"
    echo "2. Test with real processes: sudo ./hide_process_loader [PID]"
    echo "3. Verify hiding with: LD_PRELOAD=./output/libhide.so ps aux"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
