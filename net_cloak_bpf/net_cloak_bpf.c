//SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023-2024 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/cgroup.h>
#include <linux/version.h>
#include <linux/netfilter.h>

#ifndef MAX_HTTP_HEADER_SIZE
#define MAX_HTTP_HEADER_SIZE 512
#endif

#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif

#ifndef MAX_REDIRECT_PORTS
#define MAX_REDIRECT_PORTS 8
#endif

#ifndef MAX_REWRITE_ATTEMPTS
#define MAX_REWRITE_ATTEMPTS 4
#endif

/* Event types for ringbuffer event logging */
#define ACTION_OK       0
#define ACTION_OBF      1
#define ACTION_REDIR    2
#define ACTION_DROP     3

/* Cấu trúc dữ liệu để lưu sự kiện ring buffer */
struct event {
    __u64 cgid;
    __u32 bytes;
    __u8  action;    /* 0=OK, 1=OBF, 2=REDIR, 3=DROP */
    __u8  protocol;  /* 6=TCP, 17=UDP */
    __u16 dport;     /* Cổng đích */
    __u32 saddr;     /* Địa chỉ nguồn */
    __u32 daddr;     /* Địa chỉ đích */
    __u64 timestamp; /* Thời gian sự kiện */
};

/* Cấu trúc lưu thông tin HTTP header để tối ưu tốc độ xử lý */
struct http_hdr {
    __u16 ua_offset;     /* User-Agent offset */
    __u16 ua_len;        /* User-Agent length */
    __u16 host_offset;   /* Host offset */
    __u16 host_len;      /* Host length */
    __u16 content_len;   /* Content-Length value */
    __u8  is_http;       /* Flag đánh dấu có phải HTTP */
};

/* Cấu trúc thông tin chuyển hướng cổng */
struct redirect_info {
    __u16 target_port;
    __u8  enabled;
};

/* Map lưu thông tin quota cho mỗi cgroup - chia sẻ từ bên ngoài */
extern struct { 
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 1024);
    __type(key, __u64);     /* cgroup id */ 
    __type(value, __u64);   /* quota còn lại tính bằng byte */
} quota_cg SEC(".maps");

/* Map đánh dấu các cgroup cần được obfuscate - chia sẻ từ bên ngoài */
extern struct { 
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 1024);
    __type(key, __u64);     /* cgroup id */ 
    __type(value, __u8);    /* 1 = cần obfuscate, 0 = không */
} obfuscate_cg SEC(".maps");

/* Map lưu thông tin port mapping - chỉ dùng nội bộ */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u16);    /* port nguồn */
    __type(value, struct redirect_info); /* thông tin chuyển hướng */
} port_redirect SEC(".maps");

/* Ring buffer để đẩy sự kiện lên userspace - chia sẻ từ bên ngoài */
extern struct { 
    __uint(type, BPF_MAP_TYPE_RINGBUF); 
    __uint(max_entries, 1 << 20); /* 1MB ring buffer */
} events SEC(".maps");

/* Map PERCPU lưu thống kê hiệu năng */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

/* Hằng số chuỗi thay thế cho User-Agent */
const volatile char replacement_ua[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36";
/* Hằng số chuỗi thay thế cho Host */
const volatile char replacement_host[] = "www.google.com";

/* Hàm lấy cgroup ID từ skb */
static __always_inline __u64 get_cgroup_id(struct __sk_buff *skb) {
    __u64 cgid = 0;
    bpf_skb_cgroup_id(skb, &cgid);
    return cgid;
}

/* Hàm kiểm tra và cập nhật quota */
static __always_inline bool quota_check(__u64 cgid, __u32 pkt_len) {
    __u64 *quota = bpf_map_lookup_elem(&quota_cg, &cgid);
    
    /* Nếu không tìm thấy quota hoặc không được theo dõi */
    if (!quota) {
        return true; /* Cho phép gói đi qua */
    }

    /* Kiểm tra nếu còn đủ quota */
    if (*quota < pkt_len) {
        /* Ghi log sự kiện hết quota */
        struct event *e;
        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (e) {
            e->cgid = cgid;
            e->bytes = pkt_len;
            e->action = ACTION_DROP;
            e->timestamp = bpf_ktime_get_ns();
            bpf_ringbuf_submit(e, 0);
        }
        return false;
    }

    /* Giảm quota - sử dụng atomic để đảm bảo an toàn đa luồng */
    __sync_fetch_and_sub(quota, pkt_len);
    
    /* Cập nhật thống kê */
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&stats, &key);
    if (counter) {
        __sync_fetch_and_add(counter, pkt_len);
    }
    
    return true;
}

/* Hàm kiểm tra xem cgroup có cần obfuscate không */
static __always_inline bool needs_obfuscate(__u64 cgid) {
    __u8 *flag = bpf_map_lookup_elem(&obfuscate_cg, &cgid);
    return flag && (*flag == 1);
}

/* Hàm phân tích header HTTP */
static __always_inline int parse_http(struct __sk_buff *skb, struct http_hdr *hdr) {
    /* Khởi tạo hdr với giá trị mặc định */
    hdr->ua_offset = 0;
    hdr->ua_len = 0;
    hdr->host_offset = 0;
    hdr->host_len = 0;
    hdr->is_http = 0;
    
    /* Lấy Ethernet header */
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return -1;
    }
    
    /* Kiểm tra nếu không phải IP */
    if (eth.h_proto != bpf_htons(ETH_P_IP)) {
        return -1;
    }
    
    /* Lấy IP header */
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0) {
        return -1;
    }
    
    /* Kiểm tra nếu không phải TCP */
    if (iph.protocol != IPPROTO_TCP) {
        return -1;
    }

    /* Tính offset của TCP header */
    __u32 ip_hdr_len = iph.ihl * 4;
    __u32 tcp_off = ETH_HLEN + ip_hdr_len;
    
    /* Lấy TCP header */
    struct tcphdr tcph;
    if (bpf_skb_load_bytes(skb, tcp_off, &tcph, sizeof(tcph)) < 0) {
        return -1;
    }
    
    /* Tính offset của HTTP payload */
    __u32 tcp_hdr_len = tcph.doff * 4;
    __u32 payload_off = tcp_off + tcp_hdr_len;
    
    /* Kiểm tra cổng đích, bình thường là HTTP (80) hoặc HTTPS (443) */
    __u16 dport = bpf_ntohs(tcph.dest);
    if (dport != 80 && dport != 443) {
        return -1;
    }
    
    /* Kiểm tra HTTP signature (GET, POST, HEAD, PUT, DELETE...) */
    char http_sig[8] = {};
    if (bpf_skb_load_bytes(skb, payload_off, http_sig, sizeof(http_sig)) < 0) {
        return -1;
    }
    
    /* Kiểm tra các method phổ biến */
    if (!(
        (http_sig[0] == 'G' && http_sig[1] == 'E' && http_sig[2] == 'T') ||
        (http_sig[0] == 'P' && http_sig[1] == 'O' && http_sig[2] == 'S' && http_sig[3] == 'T') ||
        (http_sig[0] == 'H' && http_sig[1] == 'E' && http_sig[2] == 'A' && http_sig[3] == 'D') ||
        (http_sig[0] == 'P' && http_sig[1] == 'U' && http_sig[2] == 'T') ||
        (http_sig[0] == 'D' && http_sig[1] == 'E' && http_sig[2] == 'L')
    )) {
        return -1;
    }

    /* Đánh dấu là HTTP request */
    hdr->is_http = 1;
    
    /* Tìm User-Agent trong HTTP header */
    char http_header[MAX_HTTP_HEADER_SIZE] = {};
    if (bpf_skb_load_bytes(skb, payload_off, http_header, MAX_HTTP_HEADER_SIZE) < 0) {
        return 0; /* Vẫn là HTTP nhưng không đọc được toàn bộ header */
    }
    
    /* Tìm User-Agent bằng cách duyệt qua header có giới hạn 
     * Phiên bản tối ưu cho eBPF verifier 
     */
    #pragma unroll
    for (int i = 0; i < MAX_HTTP_HEADER_SIZE - 11; i++) {
        if (http_header[i] == 'U' && 
            http_header[i+1] == 's' && 
            http_header[i+2] == 'e' && 
            http_header[i+3] == 'r' && 
            http_header[i+4] == '-' && 
            http_header[i+5] == 'A' && 
            http_header[i+6] == 'g' && 
            http_header[i+7] == 'e' && 
            http_header[i+8] == 'n' && 
            http_header[i+9] == 't' && 
            http_header[i+10] == ':') {
            
            /* Tìm thấy User-Agent */
            hdr->ua_offset = payload_off + i + 12; /* +12 cho "User-Agent: " + khoảng trắng */
            
            /* Tìm độ dài của User-Agent (đến \r hoặc kết thúc) */
            for (int j = i + 12; j < MAX_HTTP_HEADER_SIZE - i; j++) {
                if (http_header[j] == '\r' || http_header[j] == '\n') {
                    hdr->ua_len = j - (i + 12);
                    break;
                }
            }
            
            /* Đảm bảo độ dài hợp lệ */
            if (hdr->ua_len == 0 || hdr->ua_len > 256) {
                hdr->ua_len = 0;
                hdr->ua_offset = 0;
            }
            
            break;
        }
    }
    
    /* Tìm Host header */
    #pragma unroll
    for (int i = 0; i < MAX_HTTP_HEADER_SIZE - 6; i++) {
        if (http_header[i] == 'H' && 
            http_header[i+1] == 'o' && 
            http_header[i+2] == 's' && 
            http_header[i+3] == 't' && 
            http_header[i+4] == ':') {
            
            /* Tìm thấy Host */
            hdr->host_offset = payload_off + i + 6; /* +6 cho "Host: " + khoảng trắng */
            
            /* Tìm độ dài của Host (đến \r hoặc kết thúc) */
            for (int j = i + 6; j < MAX_HTTP_HEADER_SIZE - i; j++) {
                if (http_header[j] == '\r' || http_header[j] == '\n') {
                    hdr->host_len = j - (i + 6);
                    break;
                }
            }
            
            /* Đảm bảo độ dài hợp lệ */
            if (hdr->host_len == 0 || hdr->host_len > 128) {
                hdr->host_len = 0;
                hdr->host_offset = 0;
            }
            
            break;
        }
    }
    
    return 0;
}

/* Hàm viết lại HTTP headers để che giấu thông tin */
static __always_inline int rewrite_http_headers(struct __sk_buff *skb, struct http_hdr *hdr) {
    /* Nếu không phải HTTP hoặc không có header cần chỉnh sửa */
    if (!hdr->is_http) {
        return 0;
    }

    /* Đếm số lần thành công */
    int rewrite_count = 0;
    
    /* Thay thế User-Agent nếu có */
    if (hdr->ua_offset > 0 && hdr->ua_len > 0) {
        /* Giới hạn kích thước thay thế để tránh làm thay đổi kích thước gói */
        __u16 replace_len = sizeof(replacement_ua) - 1; /* -1 để bỏ null terminator */
        if (replace_len > hdr->ua_len) {
            replace_len = hdr->ua_len;
        }
        
        /* Thực hiện thay thế */
        if (bpf_skb_store_bytes(skb, hdr->ua_offset, replacement_ua, replace_len, BPF_F_RECOMPUTE_CSUM) == 0) {
            rewrite_count++;
        }
    }
    
    /* Thay thế Host nếu có */
    if (hdr->host_offset > 0 && hdr->host_len > 0) {
        /* Giới hạn kích thước thay thế để tránh làm thay đổi kích thước gói */
        __u16 replace_len = sizeof(replacement_host) - 1; /* -1 để bỏ null terminator */
        if (replace_len > hdr->host_len) {
            replace_len = hdr->host_len;
        }
        
        /* Thực hiện thay thế */
        if (bpf_skb_store_bytes(skb, hdr->host_offset, replacement_host, replace_len, BPF_F_RECOMPUTE_CSUM) == 0) {
            rewrite_count++;
        }
    }
    
    return rewrite_count;
}

/* Hàm thực hiện chuyển hướng gói */
static __always_inline int do_redirect(struct __sk_buff *skb, __u16 target_port) {
    /* Lấy các header cần thiết */
    struct ethhdr eth;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
        return TC_ACT_OK; /* Tiếp tục xử lý bình thường nếu không đọc được */
    }
    
    /* Kiểm tra nếu không phải IP */
    if (eth.h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    /* Lấy IP header */
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) < 0) {
        return TC_ACT_OK;
    }
    
    /* Kiểm tra nếu không phải TCP */
    if (iph.protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    /* Tính offset của TCP header */
    __u32 ip_hdr_len = iph.ihl * 4;
    __u32 tcp_off = ETH_HLEN + ip_hdr_len;
    
    /* Lấy TCP header */
    struct tcphdr tcph;
    if (bpf_skb_load_bytes(skb, tcp_off, &tcph, sizeof(tcph)) < 0) {
        return TC_ACT_OK;
    }

    /* Sửa đổi cổng đích */
    tcph.dest = bpf_htons(target_port);
    
    /* Viết lại TCP header với cổng đích mới */
    if (bpf_skb_store_bytes(skb, tcp_off, &tcph, sizeof(tcph), BPF_F_RECOMPUTE_CSUM) < 0) {
        return TC_ACT_OK;
    }
    
    /* Cập nhật checksum */
    bpf_l4_csum_replace(skb, tcp_off + offsetof(struct tcphdr, check), 0, 0, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0);
    
    return TC_ACT_OK;
}

/* Hàm ghi sự kiện vào ring buffer */
static __always_inline void submit_event(__u64 cgid, __u32 bytes, __u8 action, 
                                        __u8 protocol, __u16 dport, 
                                        __u32 saddr, __u32 daddr) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->cgid = cgid;
        e->bytes = bytes;
        e->action = action;
        e->protocol = protocol;
        e->dport = dport;
        e->saddr = saddr;
        e->daddr = daddr;
        e->timestamp = bpf_ktime_get_ns();
        bpf_ringbuf_submit(e, 0);
    }
}

/* Xử lý gói chính (common handler cho nhiều hook) */
static __always_inline int process_skb(struct __sk_buff *skb) {
    __u64 cgid = get_cgroup_id(skb);
    
    /* Kiểm tra và cập nhật quota cho gói */
    if (!quota_check(cgid, skb->len)) {
        /* Gói bị từ chối do hết quota */
        /* Thống kê đã được cập nhật trong quota_check */
        return NF_DROP;
    }
    
    /* Lấy các thông tin cơ bản để log */
    __u8 protocol = 0;
    __u16 dport = 0;
    __u32 saddr = 0, daddr = 0;
    
    /* Lấy header IP */
    struct iphdr iph;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph, sizeof(iph)) == 0) {
        protocol = iph.protocol;
        saddr = iph.saddr;
        daddr = iph.daddr;
        
        /* Nếu là TCP, lấy thêm thông tin cổng */
        if (iph.protocol == IPPROTO_TCP) {
            struct tcphdr tcph;
            if (bpf_skb_load_bytes(skb, ETH_HLEN + (iph.ihl * 4), &tcph, sizeof(tcph)) == 0) {
                dport = bpf_ntohs(tcph.dest);
                
                /* Kiểm tra và thực hiện chuyển hướng cổng nếu cần */
                struct redirect_info *redir = bpf_map_lookup_elem(&port_redirect, &dport);
                if (redir && redir->enabled) {
                    do_redirect(skb, redir->target_port);
                    
                    /* Ghi nhận sự kiện chuyển hướng */
                    submit_event(cgid, skb->len, ACTION_REDIR, protocol, dport, saddr, daddr);
                    /* Cập nhật cổng đích */
                    dport = redir->target_port;
                }
            }
        }
    }
    
    /* Kiểm tra xem có cần che giấu gói không */
    if (needs_obfuscate(cgid)) {
        /* Phân tích HTTP nếu cần */
        struct http_hdr hdr;
        if (parse_http(skb, &hdr) == 0 && hdr.is_http) {
            /* Nếu là HTTP, thực hiện viết lại header */
            int rewrite_count = rewrite_http_headers(skb, &hdr);
            
            /* Ghi nhận sự kiện che giấu */
            if (rewrite_count > 0) {
                submit_event(cgid, skb->len, ACTION_OBF, protocol, dport, saddr, daddr);
            }
        }
    } else {
        /* Ghi nhận sự kiện thông thường */
        submit_event(cgid, skb->len, ACTION_OK, protocol, dport, saddr, daddr);
    }
    
    return NF_ACCEPT;
}

/* Thiết lập các hooks */

/* TC classifier hook */
SEC("classifier")
int tc_ingress(struct __sk_buff *skb) {
    return process_skb(skb);
}

/* XDP hook - hiệu suất cao nhất, áp dụng sớm nhất */
SEC("xdp")
int xdp_ingress(struct xdp_md *ctx) {
    /* Chuyển đổi ctx sang __sk_buff để dùng chung hàm xử lý */
    /* XDP không hỗ trợ đầy đủ các tính năng cần thiết, 
       nên chỉ thực hiện kiểm tra đơn giản và chuyển tiếp */
    
    /* Cập nhật thống kê XDP */
    __u32 key = 1; 
    __u64 *counter = bpf_map_lookup_elem(&stats, &key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    
    return XDP_PASS; /* Để TC hoặc netfilter xử lý đầy đủ */
}

/* Hook cho netfilter pre-routing (gói đến) */
SEC("cgroup_skb/ingress")
int handle_prerouting(struct __sk_buff *skb) {
    return process_skb(skb);
}

/* Hook cho netfilter local-out (gói đi) */
SEC("cgroup_skb/egress")
int handle_local_out(struct __sk_buff *skb) {
    return process_skb(skb);
}

/* Hook cgroup socket address */
SEC("cgroup/connect4")
int handle_connect4(struct bpf_sock_addr *ctx) {
    /* Lấy thông tin cgroup và cập nhật thống kê */
    __u64 cgid = bpf_get_current_cgroup_id();
    __u16 dport = bpf_ntohs(ctx->user_port);
    
    /* Kiểm tra nếu cổng cần được chuyển hướng */
    struct redirect_info *redir = bpf_map_lookup_elem(&port_redirect, &dport);
    if (redir && redir->enabled) {
        /* Thực hiện chuyển hướng ở tầng socket */
        ctx->user_port = bpf_htons(redir->target_port);
        
        /* Ghi nhận sự kiện */
        __u32 key = 2;
        __u64 *counter = bpf_map_lookup_elem(&stats, &key);
        if (counter) {
            __sync_fetch_and_add(counter, 1);
        }
    }
    
    return 1; /* Cho phép kết nối */
}

/* LSM hook để giám sát quá trình tạo socket */
SEC("lsm/socket_connect")
int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    /* Cập nhật thống kê LSM */
    __u32 key = 3;
    __u64 *counter = bpf_map_lookup_elem(&stats, &key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    
    return 0; /* Cho phép kết nối */
}

/* Raw tracepoint hook để theo dõi hoạt động mạng */
SEC("raw_tp/tcp_connect")
int handle_tcp_connect(struct bpf_raw_tracepoint_args *ctx) {
    /* Tăng bộ đếm */
    __u32 key = 3;
    __u64 *counter = bpf_map_lookup_elem(&stats, &key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    
    return 0;
}

/* Fentry/fexit hookpoints - chỉ khả dụng trên kernel mới */
#if defined(BPF_PROG_TYPE_TRACING) && defined(BPF_TRACE_FENTRY)
SEC("fentry/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_entry) {
    /* Tăng bộ đếm */
    __u32 key = 3;
    __u64 *counter = bpf_map_lookup_elem(&stats, &key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    
    return 0;
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_exit) {
    return 0;
}
#endif

/* Kprobe/kretprobe hookpoints */
SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx) {
    /* Tăng bộ đếm */
    __u32 key = 3;
    __u64 *counter = bpf_map_lookup_elem(&stats, &key);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
    
    return 0;
}

/* Bản đồ tương thích cho libbpf */
char LICENSE[] SEC("license") = "GPL"; 
 