/* =====================================================
 *  Test Loader cho Optimized LSM Hide
 *  Simplified loader để test kprobe functionality
 * ===================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "test_optimized.skel.h"

static struct test_optimized_bpf *skel;
static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct {
        uint32_t event_type;
        uint32_t pid;
        uint64_t timestamp;
    } *e = data;
    
    const char *event_names[] = {
        [6] = "getdents64_called",
        [8] = "openat_blocked", 
        [11] = "stat_blocked"
    };
    
    const char *event_name = (e->event_type < sizeof(event_names)/sizeof(event_names[0]) && 
                             event_names[e->event_type]) ? 
                             event_names[e->event_type] : "unknown";
    
    printf("Event: %s, PID: %u, Time: %llu\n", event_name, e->pid, e->timestamp);
    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    int err;

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

    /* Open BPF application */
    skel = test_optimized_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = test_optimized_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* Attach tracepoints */
    err = test_optimized_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Successfully started test optimized LSM Hide\n");

    /* Add test PID if provided */
    if (argc > 1) {
        uint32_t test_pid = atoi(argv[1]);
        uint32_t value = 1;
        
        err = bpf_map_update_elem(bpf_map__fd(skel->maps.hidden_pid_map), 
                                 &test_pid, &value, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to add PID %u to hidden map: %d\n", test_pid, err);
        } else {
            printf("Added PID %u to hidden list\n", test_pid);
        }
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Monitoring events... Press Ctrl-C to exit\n");

    /* Process events */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    test_optimized_bpf__destroy(skel);
    return -err;
}
