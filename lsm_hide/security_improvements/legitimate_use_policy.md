# LSM Hide - Legitimate Use Policy & Security Framework

## 1. Legitimate Use Cases Declaration

### Approved Use Cases:
- **Container Workload Protection**: Ẩn container processes khỏi host monitoring
- **Security Research**: Penetration testing và red team exercises  
- **System Administration**: Bảo vệ critical system processes
- **Performance Testing**: Ẩn benchmark processes khỏi monitoring overhead

### Prohibited Use Cases:
- **Malware Hiding**: Che giấu malicious processes
- **Unauthorized Access**: Bypass security controls
- **Data Exfiltration**: Ẩn data theft activities

## 2. Security Attestation Framework

### Digital Signature Requirements:
```bash
# Code signing với certificate authority
codesign --sign "Developer ID Application" lsm_hide_loader
codesign --sign "Developer ID Application" libhide.so

# Verify signatures
codesign --verify --verbose lsm_hide_loader
```

### Runtime Attestation:
```c
// Add to lsm_hide_loader.c
static int verify_legitimate_use(void) {
    // Check for legitimate use indicators
    if (getenv("LSM_HIDE_LEGITIMATE_USE") == NULL) {
        fprintf(stderr, "ERROR: LSM_HIDE_LEGITIMATE_USE environment variable required\n");
        return -1;
    }
    
    // Log usage for audit trail
    syslog(LOG_INFO, "LSM Hide started for legitimate use: %s", 
           getenv("LSM_HIDE_USE_CASE"));
    return 0;
}
```

## 3. Whitelist-Based Operation

### Process Whitelist:
```c
// Chỉ ẩn processes trong whitelist thay vì arbitrary PIDs
static const char* legitimate_process_patterns[] = {
    "docker-*",
    "containerd-*", 
    "benchmark-*",
    "test-*",
    NULL
};

static bool is_legitimate_process(const char* comm) {
    for (int i = 0; legitimate_process_patterns[i]; i++) {
        if (fnmatch(legitimate_process_patterns[i], comm, 0) == 0) {
            return true;
        }
    }
    return false;
}
```

**Effort**: Medium (2-3 tuần)  
**Complexity**: Low-Medium  
**Impact**: High - Giảm đáng kể nguy cơ bị phát hiện
