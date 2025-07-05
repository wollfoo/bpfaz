#!/bin/bash
# validate_kernel_config.sh - Comprehensive Kernel Configuration Validation for eBPF
# Script xác thực cấu hình kernel toàn diện cho eBPF operations

set -uo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_VERSION=$(uname -r)
AZURE_KERNEL_PATTERN="azure"
GENERIC_KERNEL_PATTERN="generic"
AWS_KERNEL_PATTERN="aws"
GCP_KERNEL_PATTERN="gcp"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
STRICT_MODE=false
COMPREHENSIVE_MODE=false
TEST_RUNTIME=false
AZURE_MODE=false
GENERIC_MODE=false
AWS_MODE=false
GCP_MODE=false
FIX_ATTEMPTS=false
OUTPUT_FORMAT="human"
LOG_LEVEL="INFO"

# Validation results
CRITICAL_ERRORS=0
ESSENTIAL_ERRORS=0
IMPORTANT_WARNINGS=0
TOTAL_CHECKS=0
PASSED_CHECKS=0

# Logging functions
log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    ((CRITICAL_ERRORS++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
    ((IMPORTANT_WARNINGS++))
}

log_info() {
    if [[ "$LOG_LEVEL" != "ERROR" ]]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    ((PASSED_CHECKS++))
}

log_debug() {
    if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
        echo -e "${PURPLE}[DEBUG]${NC} $1"
    fi
}

log_critical() {
    echo -e "${RED}[CRITICAL]${NC} $1" >&2
    ((CRITICAL_ERRORS++))
}

# Banner
print_banner() {
    local kernel_type="Standard"
    local environment_desc=""

    # Auto-detect kernel type and set appropriate mode
    if [[ "$KERNEL_VERSION" =~ $AZURE_KERNEL_PATTERN ]]; then
        kernel_type="Azure Cloud"
        environment_desc="Azure Cloud (optimized validation)"
        AZURE_MODE=true
    elif [[ "$KERNEL_VERSION" =~ $AWS_KERNEL_PATTERN ]]; then
        kernel_type="AWS Cloud"
        environment_desc="AWS Cloud (optimized validation)"
        AWS_MODE=true
    elif [[ "$KERNEL_VERSION" =~ $GCP_KERNEL_PATTERN ]]; then
        kernel_type="GCP Cloud"
        environment_desc="GCP Cloud (optimized validation)"
        GCP_MODE=true
    elif [[ "$KERNEL_VERSION" =~ $GENERIC_KERNEL_PATTERN ]]; then
        kernel_type="HWE (Hardware Enablement)"
        environment_desc="Ubuntu HWE kernel (enhanced BPF support)"
        GENERIC_MODE=true
    fi

    echo "================================================================"
    echo "  🔍 Kernel Configuration Validation for eBPF Operations"
    echo "  Target: hide_process_bpf compatibility verification"
    echo "  Kernel: $KERNEL_VERSION ($kernel_type)"
    if [[ -n "$environment_desc" ]]; then
        echo "  Environment: $environment_desc"
    fi
    echo "================================================================"
    echo ""
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Validate kernel configuration for eBPF operations in hide_process_bpf.

OPTIONS:
    --strict                Enable strict validation mode (fail on warnings)
    --comprehensive         Run comprehensive validation including runtime tests
    --test-runtime          Test actual BPF functionality (requires root)
    --azure-mode            Enable Azure cloud-specific optimizations
    --generic-mode          Enable generic/HWE kernel optimizations
    --aws-mode              Enable AWS cloud-specific optimizations
    --gcp-mode              Enable GCP cloud-specific optimizations
    --fix-attempts          Attempt to fix minor issues automatically
    --output-format FORMAT  Output format: human, json (default: human)
    --log-level LEVEL       Log level: ERROR, WARN, INFO, DEBUG (default: INFO)
    -h, --help              Show this help message

EXAMPLES:
    $0                      # Basic validation (auto-detects kernel type)
    $0 --strict             # Strict mode (fail on warnings)
    $0 --comprehensive      # Full validation with runtime tests
    $0 --azure-mode         # Azure cloud optimized validation
    $0 --generic-mode       # Generic/HWE kernel optimized validation

EXIT CODES:
    0   All validations passed
    1   Critical errors found (eBPF will not work)
    2   Essential errors found (limited functionality)
    3   Important warnings (may affect performance)
    10  Script execution error

EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --strict)
                STRICT_MODE=true
                shift
                ;;
            --comprehensive)
                COMPREHENSIVE_MODE=true
                shift
                ;;
            --test-runtime)
                TEST_RUNTIME=true
                shift
                ;;
            --azure-mode)
                AZURE_MODE=true
                shift
                ;;
            --generic-mode)
                GENERIC_MODE=true
                shift
                ;;
            --aws-mode)
                AWS_MODE=true
                shift
                ;;
            --gcp-mode)
                GCP_MODE=true
                shift
                ;;
            --fix-attempts)
                FIX_ATTEMPTS=true
                shift
                ;;
            --output-format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            --log-level)
                LOG_LEVEL="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 10
                ;;
        esac
    done
}

# Find kernel config file
find_kernel_config() {
    local config_file=""
    
    # Priority order for config file detection
    local config_sources=(
        "/proc/config.gz"
        "/boot/config-$KERNEL_VERSION"
        "/usr/src/linux-headers-$KERNEL_VERSION/.config"
        "/lib/modules/$KERNEL_VERSION/build/.config"
        "/usr/src/linux/.config"
    )
    
    log_info "Searching for kernel configuration file..." >&2

    for source in "${config_sources[@]}"; do
        if [[ -r "$source" ]]; then
            config_file="$source"
            log_success "Found kernel config: $source" >&2
            break
        fi
    done
    
    if [[ -z "$config_file" ]]; then
        log_critical "No readable kernel configuration file found"
        log_error "Searched locations: ${config_sources[*]}"
        log_error "Solution: Install linux-headers-$KERNEL_VERSION package"
        return 1
    fi
    
    echo "$config_file"
}

# Check specific kernel config option
check_config_option() {
    local config_file="$1"
    local option="$2"
    local required_value="$3"
    local severity="$4"  # CRITICAL, ESSENTIAL, IMPORTANT
    local description="$5"
    
    ((TOTAL_CHECKS++))
    
    local actual_value=""
    
    # Handle compressed config files
    if [[ "$config_file" == *.gz ]]; then
        # First check if option is explicitly disabled
        if zgrep -q "^# $option is not set" "$config_file" 2>/dev/null; then
            actual_value="not_set"
        else
            # Get the actual value
            actual_value=$(zgrep "^$option=" "$config_file" 2>/dev/null | cut -d= -f2)
            if [[ -z "$actual_value" ]]; then
                actual_value="not_set"
            fi
        fi
    else
        # First check if option is explicitly disabled
        if grep -q "^# $option is not set" "$config_file" 2>/dev/null; then
            actual_value="not_set"
        else
            # Get the actual value
            actual_value=$(grep "^$option=" "$config_file" 2>/dev/null | cut -d= -f2)
            if [[ -z "$actual_value" ]]; then
                actual_value="not_set"
            fi
        fi
    fi
    
    log_debug "Checking $option: expected=$required_value, actual=$actual_value"
    
    if [[ "$actual_value" == "$required_value" ]]; then
        log_success "$option=$actual_value ($description)"
        return 0
    else
        case "$severity" in
            "CRITICAL")
                log_critical "$option=$actual_value (expected: $required_value)"
                log_error "Impact: $description"
                log_error "Solution: Recompile kernel with $option=$required_value"
                if [[ "$AZURE_MODE" == "true" ]]; then
                    log_error "Azure Note: This may require custom kernel or alternative approach"
                fi
                ;;
            "ESSENTIAL")
                log_error "$option=$actual_value (expected: $required_value)"
                log_error "Impact: $description"
                ((ESSENTIAL_ERRORS++))
                ;;
            "IMPORTANT")
                log_warn "$option=$actual_value (expected: $required_value)"
                log_warn "Impact: $description"
                ;;
        esac
        return 1
    fi
}

# Validate critical BPF configurations
validate_critical_configs() {
    log_info "Validating critical BPF configurations..."

    local config_file
    config_file=$(find_kernel_config) || return 1

    log_debug "Using config file: $config_file"
    
    # Critical configurations for bpf_override_return functionality
    check_config_option "$config_file" "CONFIG_BPF_KPROBE_OVERRIDE" "y" "CRITICAL" \
        "Required for bpf_override_return() calls in hide_process_bpf"
    
    check_config_option "$config_file" "CONFIG_FUNCTION_ERROR_INJECTION" "y" "CRITICAL" \
        "Required for error injection and syscall override functionality"
    
    # Essential BPF support
    check_config_option "$config_file" "CONFIG_BPF" "y" "ESSENTIAL" \
        "Basic BPF subsystem support"
    
    check_config_option "$config_file" "CONFIG_BPF_SYSCALL" "y" "ESSENTIAL" \
        "BPF system call interface"
    
    check_config_option "$config_file" "CONFIG_KPROBES" "y" "ESSENTIAL" \
        "Kernel probes for function interception"
    
    # Important configurations for full functionality
    if [[ "$COMPREHENSIVE_MODE" == "true" ]]; then
        check_config_option "$config_file" "CONFIG_BPF_EVENTS" "y" "IMPORTANT" \
            "BPF event support for enhanced monitoring"
        
        check_config_option "$config_file" "CONFIG_TRACEPOINTS" "y" "IMPORTANT" \
            "Tracepoint support for syscall interception"
        
        check_config_option "$config_file" "CONFIG_FTRACE" "y" "IMPORTANT" \
            "Function tracing support"
        
        check_config_option "$config_file" "CONFIG_DYNAMIC_FTRACE" "y" "IMPORTANT" \
            "Dynamic function tracing"
        
        check_config_option "$config_file" "CONFIG_HAVE_KPROBES" "y" "IMPORTANT" \
            "Architecture support for kprobes"
        
        check_config_option "$config_file" "CONFIG_KPROBE_EVENTS" "y" "IMPORTANT" \
            "Kprobe-based event tracing"
    fi
}

# Validate runtime environment
validate_runtime_environment() {
    log_info "Validating runtime environment..."
    
    ((TOTAL_CHECKS++))
    
    # Check BTF availability
    if [[ -r /sys/kernel/btf/vmlinux ]]; then
        log_success "BTF (Binary Type Format) available"
        ((PASSED_CHECKS++))
    else
        log_error "BTF not available at /sys/kernel/btf/vmlinux"
        log_error "Impact: Modern eBPF programs may not load correctly"
        log_error "Solution: Ensure kernel compiled with CONFIG_DEBUG_INFO_BTF=y"
    fi
    
    ((TOTAL_CHECKS++))
    
    # Check BPF filesystem
    if mount | grep -q "bpf on /sys/fs/bpf"; then
        log_success "BPF filesystem mounted at /sys/fs/bpf"
        ((PASSED_CHECKS++))
    else
        log_warn "BPF filesystem not mounted"
        log_warn "Impact: BPF map pinning may not work"
        if [[ "$FIX_ATTEMPTS" == "true" ]]; then
            log_info "Attempting to mount BPF filesystem..."
            if mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then
                log_success "BPF filesystem mounted successfully"
                ((PASSED_CHECKS++))
            else
                log_error "Failed to mount BPF filesystem (requires root)"
            fi
        else
            log_warn "Solution: Run 'sudo mount -t bpf bpf /sys/fs/bpf'"
        fi
    fi
    
    ((TOTAL_CHECKS++))
    
    # Check if running as root for BPF operations
    if [[ $EUID -eq 0 ]]; then
        log_success "Running with root privileges (required for BPF operations)"
        ((PASSED_CHECKS++))
    else
        log_warn "Not running as root"
        log_warn "Impact: BPF program loading will require sudo"
        log_warn "Solution: Run eBPF programs with sudo"
    fi
}

# Test actual BPF functionality
test_bpf_functionality() {
    if [[ "$TEST_RUNTIME" != "true" ]]; then
        return 0
    fi

    log_info "Testing actual BPF functionality..."

    ((TOTAL_CHECKS++))

    # Check if bpftool is available
    if command -v bpftool >/dev/null 2>&1; then
        log_success "bpftool available for BPF testing"
        ((PASSED_CHECKS++))

        # Test basic BPF operations
        if bpftool prog list >/dev/null 2>&1; then
            log_success "BPF program listing works"
        else
            log_warn "BPF program listing failed (may be normal if no programs loaded)"
        fi

        if bpftool map list >/dev/null 2>&1; then
            log_success "BPF map listing works"
        else
            log_warn "BPF map listing failed (may be normal if no maps exist)"
        fi
    else
        log_warn "bpftool not available"
        log_warn "Impact: Cannot test BPF functionality"
        log_warn "Solution: Install bpftool package"
    fi
}

# Generic/HWE kernel-specific validations
validate_generic_environment() {
    if [[ "$GENERIC_MODE" != "true" ]]; then
        return 0
    fi

    log_info "Performing Generic/HWE kernel-specific validations..."

    # Check HWE kernel version compatibility
    if [[ "$KERNEL_VERSION" =~ 6\.8\.0.*generic ]]; then
        log_success "HWE kernel version $KERNEL_VERSION is fully supported"
        log_info "HWE kernel benefits:"
        log_info "  - Latest hardware support and drivers"
        log_info "  - Enhanced BPF capabilities and performance"
        log_info "  - Better compatibility with modern eBPF features"
    else
        log_warn "Kernel version $KERNEL_VERSION may not be HWE-optimized"
        log_warn "Recommended: Use Ubuntu HWE kernel (6.8.0-*-generic)"
    fi

    # Check for HWE-specific features
    log_info "HWE kernel features:"
    log_info "  - Full BTF support for CO-RE (Compile Once, Run Everywhere)"
    log_info "  - Enhanced kprobe and tracepoint support"
    log_info "  - Improved BPF verifier with relaxed constraints"
    log_info "  - Better performance for BPF programs"

    # Additional HWE-specific checks
    ((TOTAL_CHECKS++))
    if [[ -d /sys/kernel/debug/tracing ]]; then
        log_success "Enhanced tracing infrastructure available"
        ((PASSED_CHECKS++))
    else
        log_warn "Enhanced tracing infrastructure not available"
        if [[ "$FIX_ATTEMPTS" == "true" ]] && [[ $EUID -eq 0 ]]; then
            log_info "Attempting to mount debugfs..."
            if mount -t debugfs none /sys/kernel/debug 2>/dev/null; then
                log_success "Debugfs mounted successfully"
                ((PASSED_CHECKS++))
            else
                log_warn "Failed to mount debugfs automatically"
                log_warn "Solution: Run 'sudo mount -t debugfs none /sys/kernel/debug'"
            fi
        else
            log_warn "Solution: Mount debugfs with 'sudo mount -t debugfs none /sys/kernel/debug'"
        fi
    fi
}

# Azure-specific validations
validate_azure_environment() {
    if [[ "$AZURE_MODE" != "true" ]]; then
        return 0
    fi

    log_info "Performing Azure cloud-specific validations..."

    # Check Azure kernel version compatibility
    if [[ "$KERNEL_VERSION" =~ 6\.8\.0.*azure ]]; then
        log_success "Azure kernel version $KERNEL_VERSION is supported"
    else
        log_warn "Kernel version $KERNEL_VERSION may not be optimized for Azure"
        log_warn "Recommended: Use Azure-optimized kernel (6.8.0-*-azure)"
    fi

    # Check for Azure-specific limitations
    log_info "Azure environment notes:"
    log_info "  - Some BPF features may be restricted by Azure security policies"
    log_info "  - Container environments may have additional limitations"
    log_info "  - Consider using Azure Container Instances for testing"
}

# AWS-specific validations
validate_aws_environment() {
    if [[ "$AWS_MODE" != "true" ]]; then
        return 0
    fi

    log_info "Performing AWS cloud-specific validations..."

    # Check AWS kernel version compatibility
    if [[ "$KERNEL_VERSION" =~ 6\.8\.0.*aws ]]; then
        log_success "AWS kernel version $KERNEL_VERSION is supported"
    else
        log_warn "Kernel version $KERNEL_VERSION may not be optimized for AWS"
        log_warn "Recommended: Use AWS-optimized kernel (6.8.0-*-aws)"
    fi

    log_info "AWS environment notes:"
    log_info "  - Enhanced networking BPF features available"
    log_info "  - Consider EC2 instance type limitations"
    log_info "  - Some BPF features may require specific instance types"
}

# GCP-specific validations
validate_gcp_environment() {
    if [[ "$GCP_MODE" != "true" ]]; then
        return 0
    fi

    log_info "Performing GCP cloud-specific validations..."

    # Check GCP kernel version compatibility
    if [[ "$KERNEL_VERSION" =~ 6\.8\.0.*gcp ]]; then
        log_success "GCP kernel version $KERNEL_VERSION is supported"
    else
        log_warn "Kernel version $KERNEL_VERSION may not be optimized for GCP"
        log_warn "Recommended: Use GCP-optimized kernel (6.8.0-*-gcp)"
    fi

    log_info "GCP environment notes:"
    log_info "  - Container-optimized features available"
    log_info "  - Consider using Container-Optimized OS for containers"
    log_info "  - Some BPF features optimized for GKE workloads"
}

# Generate JSON output
generate_json_output() {
    cat << EOF
{
  "validation_summary": {
    "kernel_version": "$KERNEL_VERSION",
    "environment_modes": {
      "azure_mode": $AZURE_MODE,
      "generic_mode": $GENERIC_MODE,
      "aws_mode": $AWS_MODE,
      "gcp_mode": $GCP_MODE
    },
    "total_checks": $TOTAL_CHECKS,
    "passed_checks": $PASSED_CHECKS,
    "critical_errors": $CRITICAL_ERRORS,
    "essential_errors": $ESSENTIAL_ERRORS,
    "important_warnings": $IMPORTANT_WARNINGS,
    "validation_result": "$(get_validation_result)"
  },
  "recommendations": [
    $(get_recommendations)
  ]
}
EOF
}

# Get validation result
get_validation_result() {
    if [[ $CRITICAL_ERRORS -gt 0 ]]; then
        echo "CRITICAL_FAILURE"
    elif [[ $ESSENTIAL_ERRORS -gt 0 ]]; then
        echo "ESSENTIAL_FAILURE"
    elif [[ $IMPORTANT_WARNINGS -gt 0 && "$STRICT_MODE" == "true" ]]; then
        echo "STRICT_FAILURE"
    else
        echo "SUCCESS"
    fi
}

# Get recommendations
get_recommendations() {
    local recommendations=""

    if [[ $CRITICAL_ERRORS -gt 0 ]]; then
        recommendations+='"Recompile kernel with missing critical configurations",'
    fi

    if [[ $ESSENTIAL_ERRORS -gt 0 ]]; then
        recommendations+='"Install missing kernel packages or enable essential BPF support",'
    fi

    if [[ $IMPORTANT_WARNINGS -gt 0 ]]; then
        recommendations+='"Consider enabling additional BPF features for optimal performance",'
    fi

    # Remove trailing comma
    recommendations=${recommendations%,}
    echo "$recommendations"
}

# Print validation summary
print_summary() {
    echo ""
    echo "================================================================"
    echo "  📊 Kernel Configuration Validation Summary"
    echo "================================================================"
    echo ""

    echo "🔍 Validation Results:"
    echo "   Total Checks: $TOTAL_CHECKS"
    echo "   Passed: $PASSED_CHECKS"
    echo "   Critical Errors: $CRITICAL_ERRORS"
    echo "   Essential Errors: $ESSENTIAL_ERRORS"
    echo "   Important Warnings: $IMPORTANT_WARNINGS"
    echo ""

    local result=$(get_validation_result)
    case "$result" in
        "SUCCESS")
            echo -e "${GREEN}✅ VALIDATION PASSED${NC}"
            echo "   hide_process_bpf should work correctly on this kernel"
            ;;
        "STRICT_FAILURE")
            echo -e "${YELLOW}⚠️  VALIDATION PASSED WITH WARNINGS${NC}"
            echo "   hide_process_bpf will work but with reduced functionality"
            ;;
        "ESSENTIAL_FAILURE")
            echo -e "${YELLOW}❌ VALIDATION FAILED - ESSENTIAL ERRORS${NC}"
            echo "   hide_process_bpf will have limited functionality"
            ;;
        "CRITICAL_FAILURE")
            echo -e "${RED}💥 VALIDATION FAILED - CRITICAL ERRORS${NC}"
            echo "   hide_process_bpf will NOT work on this kernel"
            ;;
    esac

    echo ""

    if [[ $CRITICAL_ERRORS -gt 0 || $ESSENTIAL_ERRORS -gt 0 || ($IMPORTANT_WARNINGS -gt 0 && "$STRICT_MODE" == "true") ]]; then
        echo "🔧 Recommended Actions:"

        if [[ $CRITICAL_ERRORS -gt 0 ]]; then
            echo "   1. Recompile kernel with missing critical configurations"
            echo "   2. Or use alternative kernel with required BPF support"
        fi

        if [[ $ESSENTIAL_ERRORS -gt 0 ]]; then
            echo "   3. Install linux-headers-$KERNEL_VERSION package"
            echo "   4. Verify BPF subsystem is properly enabled"
        fi

        if [[ $IMPORTANT_WARNINGS -gt 0 ]]; then
            echo "   5. Consider enabling additional BPF features for optimal performance"
        fi

        if [[ "$AZURE_MODE" == "true" ]]; then
            echo ""
            echo "☁️  Azure Cloud Recommendations:"
            echo "   - Use Azure-optimized kernel images when possible"
            echo "   - Test in Azure Container Instances for container compatibility"
            echo "   - Consider Azure security policy implications"
        fi
    fi

    echo ""
}

# Main execution function
main() {
    # Parse command line arguments
    parse_arguments "$@"

    # Print banner
    print_banner

    # Run validations
    validate_critical_configs
    echo ""

    validate_runtime_environment
    echo ""

    if [[ "$COMPREHENSIVE_MODE" == "true" ]]; then
        test_bpf_functionality
        echo ""
    fi

    validate_generic_environment
    echo ""

    validate_azure_environment
    echo ""

    validate_aws_environment
    echo ""

    validate_gcp_environment
    echo ""

    # Output results
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        generate_json_output
    else
        print_summary
    fi

    # Determine exit code
    if [[ $CRITICAL_ERRORS -gt 0 ]]; then
        exit 1
    elif [[ $ESSENTIAL_ERRORS -gt 0 ]]; then
        exit 2
    elif [[ $IMPORTANT_WARNINGS -gt 0 && "$STRICT_MODE" == "true" ]]; then
        exit 3
    else
        exit 0
    fi
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
