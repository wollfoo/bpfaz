/* =====================================================
 *  hide_process_syncd.c - Privileged Side-Car Daemon
 *  Root daemon for syncing BPF maps to Unix socket
 * ===================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Configuration */
#define SOCKET_PATH "/run/hide_process/sock"
#define SOCKET_DIR "/run/hide_process"
#define BPF_MAP_PATH "/sys/fs/bpf/cpu_throttle/hidden_pid_map"
#define EVENTS_MAP_PATH "/sys/fs/bpf/cpu_throttle/lsm_events"
#define MAX_HIDDEN_PIDS 1024
#define SYNC_INTERVAL 300  /* seconds - reduced due to ringbuf push model */
#define MAX_CLIENTS 10

/* Global state */
static int running = 1;
static int server_fd = -1;
static int hidden_pid_map_fd = -1;
static int events_map_fd = -1;
static int client_fds[MAX_CLIENTS];
static int client_count = 0;
static struct ring_buffer *rb = NULL; /* Ringbuf consumer */

/* PID list structure for socket communication */
struct pid_list_msg {
    uint32_t magic;      /* 0xDEADBEEF */
    uint32_t count;      /* Number of PIDs */
    uint32_t pids[MAX_HIDDEN_PIDS];
};

/* Event structure from ringbuf */
struct event_data {
    uint32_t event_type;
    uint32_t pid;
    uint64_t timestamp;
};

/* =====================================================
 *  Signal Handlers
 * ===================================================== */

static void signal_handler(int sig) {
    printf("Received signal %d, shutting down...\n", sig);
    running = 0;
}

/* =====================================================
 *  Socket Management
 * ===================================================== */

static int setup_unix_socket(void) {
    struct sockaddr_un addr;
    int ret;

    /* Create socket directory */
    ret = mkdir(SOCKET_DIR, 0755);
    if (ret < 0 && errno != EEXIST) {
        perror("mkdir socket directory");
        return -1;
    }

    /* Remove existing socket */
    unlink(SOCKET_PATH);

    /* Create Unix domain socket */
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }

    /* Setup address */
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    /* Bind socket */
    ret = bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
        perror("bind");
        close(server_fd);
        return -1;
    }

    /* Set socket permissions (0660 for group access) */
    ret = chmod(SOCKET_PATH, 0660);
    if (ret < 0) {
        perror("chmod socket");
        close(server_fd);
        return -1;
    }

    /* Listen for connections */
    ret = listen(server_fd, MAX_CLIENTS);
    if (ret < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }

    printf("Unix socket listening on %s\n", SOCKET_PATH);
    return 0;
}

static void cleanup_socket(void) {
    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }
    
    /* Close all client connections */
    for (int i = 0; i < client_count; i++) {
        if (client_fds[i] >= 0) {
            close(client_fds[i]);
        }
    }
    client_count = 0;
    
    unlink(SOCKET_PATH);
    rmdir(SOCKET_DIR);
}

/* =====================================================
 *  BPF Map Operations
 * ===================================================== */

static int open_bpf_maps(void) {
    /* Open hidden_pid_map */
    hidden_pid_map_fd = bpf_obj_get(BPF_MAP_PATH);
    if (hidden_pid_map_fd < 0) {
        fprintf(stderr, "Failed to open hidden_pid_map: %s\n", strerror(errno));
        return -1;
    }

    /* Open events map */
    events_map_fd = bpf_obj_get(EVENTS_MAP_PATH);
    if (events_map_fd < 0) {
        fprintf(stderr, "Failed to open events map: %s\n", strerror(errno));
        close(hidden_pid_map_fd);
        return -1;
    }

    printf("BPF maps opened successfully\n");

    /* Khởi tạo ringbuf consumer */
    rb = ring_buffer__new(events_map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        /* Không thoát: sẽ fallback sang polling */
    }

    return 0;
}

static void close_bpf_maps(void) {
    if (hidden_pid_map_fd >= 0) {
        close(hidden_pid_map_fd);
        hidden_pid_map_fd = -1;
    }
    if (events_map_fd >= 0) {
        close(events_map_fd);
        events_map_fd = -1;
    }
}

/* =====================================================
 *  PID List Management
 * ===================================================== */

static int read_hidden_pids(struct pid_list_msg *msg) {
    uint32_t key = 0;
    uint32_t next_key;
    uint32_t value;
    int ret;

    msg->magic = 0xDEADBEEF;
    msg->count = 0;

    /* Iterate through BPF map */
    ret = bpf_map_get_next_key(hidden_pid_map_fd, NULL, &key);
    if (ret != 0) {
        /* Map is empty */
        return 0;
    }

    do {
        /* Lookup value for current key */
        ret = bpf_map_lookup_elem(hidden_pid_map_fd, &key, &value);
        if (ret == 0 && value == 1) {
            /* This PID is marked as hidden */
            if (msg->count < MAX_HIDDEN_PIDS) {
                msg->pids[msg->count] = key;
                msg->count++;
            } else {
                fprintf(stderr, "Warning: PID list full, skipping PID %u\n", key);
                break;
            }
        }

        /* Get next key */
        ret = bpf_map_get_next_key(hidden_pid_map_fd, &key, &next_key);
        if (ret != 0) {
            break; /* No more keys */
        }
        key = next_key;

    } while (msg->count < MAX_HIDDEN_PIDS);

    printf("Read %u hidden PIDs from BPF map\n", msg->count);
    return msg->count;
}

/* =====================================================
 *  Client Management
 * ===================================================== */

static void accept_new_client(void) {
    int client_fd;
    struct sockaddr_un client_addr;
    socklen_t client_len = sizeof(client_addr);

    client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept");
        }
        return;
    }

    if (client_count < MAX_CLIENTS) {
        client_fds[client_count] = client_fd;
        client_count++;
        printf("New client connected (total: %d)\n", client_count);
    } else {
        fprintf(stderr, "Too many clients, rejecting connection\n");
        close(client_fd);
    }
}

static void broadcast_pid_list(struct pid_list_msg *msg) {
    ssize_t msg_size = sizeof(uint32_t) * 2 + sizeof(uint32_t) * msg->count;
    
    for (int i = 0; i < client_count; i++) {
        if (client_fds[i] >= 0) {
            ssize_t sent = send(client_fds[i], msg, msg_size, MSG_NOSIGNAL);
            if (sent < 0) {
                if (errno == EPIPE || errno == ECONNRESET) {
                    printf("Client %d disconnected\n", i);
                    close(client_fds[i]);
                    /* Remove client from array */
                    for (int j = i; j < client_count - 1; j++) {
                        client_fds[j] = client_fds[j + 1];
                    }
                    client_count--;
                    i--; /* Adjust index after removal */
                } else {
                    perror("send to client");
                }
            }
        }
    }
}

/* =====================================================
 *  Ringbuf Event Handler
 * ===================================================== */

/* Callback được libbpf gọi mỗi khi có bản tin từ ringbuf */
static int handle_event(void *ctx, void *data, size_t size)
{
    /* data chính là struct event_data ở hide_process_bpf.c */
    struct event_data *ev = (struct event_data *)data;

    /* Chỉ quan tâm sự kiện cập nhật PID ẩn (99) hoặc gỡ ẩn (100) */
    if (ev->event_type == 99 || ev->event_type == 100) {
        struct pid_list_msg msg;
        /* Đọc lại danh sách PID ẩn mới nhất */
        if (read_hidden_pids(&msg) >= 0 && client_count > 0) {
            broadcast_pid_list(&msg);
        }
    }

    return 0; /* 0 để tiếp tục đọc */
}

/* =====================================================
 *  Main Loop
 * ===================================================== */

int main(int argc, char *argv[]) {
    struct pid_list_msg msg;
    time_t last_sync = 0;
    int verbose = 0;

    /* Parse arguments */
    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        verbose = 1;
    }

    printf("Starting hide_process_syncd daemon...\n");

    /* Setup signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Initialize client array */
    for (int i = 0; i < MAX_CLIENTS; i++) {
        client_fds[i] = -1;
    }

    /* Setup Unix socket */
    if (setup_unix_socket() < 0) {
        exit(1);
    }

    /* Open BPF maps */
    if (open_bpf_maps() < 0) {
        cleanup_socket();
        exit(1);
    }

    printf("Daemon initialized successfully\n");

    /* Main event loop */
    while (running) {
        fd_set readfds;
        struct timeval timeout;
        int max_fd = server_fd;
        time_t current_time = time(NULL);

        /* Poll ringbuf nếu đã khởi tạo (không block quá 100ms) */
        if (rb) {
            ring_buffer__poll(rb, 100 /* milliseconds */);
        }

        /* Setup select() */
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);

        /* Add client sockets to select */
        for (int i = 0; i < client_count; i++) {
            if (client_fds[i] >= 0) {
                FD_SET(client_fds[i], &readfds);
                if (client_fds[i] > max_fd) {
                    max_fd = client_fds[i];
                }
            }
        }

        /* Set timeout for periodic sync */
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(max_fd + 1, &readfds, NULL, NULL, &timeout);
        if (activity < 0 && errno != EINTR) {
            perror("select");
            break;
        }

        /* Handle new connections */
        if (FD_ISSET(server_fd, &readfds)) {
            accept_new_client();
        }

        /* Periodic PID list sync */
        if (current_time - last_sync >= SYNC_INTERVAL) {
            int pid_count = read_hidden_pids(&msg);
            if (pid_count >= 0 && client_count > 0) {
                broadcast_pid_list(&msg);
                if (verbose) {
                    printf("Synced %d PIDs to %d clients\n", pid_count, client_count);
                }
            }
            last_sync = current_time;
        }

        /* Khi đã dùng ringbuf__poll ở trên, ta chỉ cần ngủ nhẹ nếu không có ringbuf */
        if (!rb) {
            usleep(100000); /* 100ms */
        }
    }

    printf("Shutting down daemon...\n");
    if (rb) {
        ring_buffer__free(rb);
    }
    close_bpf_maps();
    cleanup_socket();
    return 0;
}
