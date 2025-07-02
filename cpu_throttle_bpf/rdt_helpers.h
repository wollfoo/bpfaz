/*
 * rdt_helpers.h - Định nghĩa các hàm và cấu trúc hỗ trợ cho Intel RDT
 * 
 * Intel RDT (Resource Director Technology) là công nghệ giám sát và kiểm soát
 * tài nguyên cache L3, bộ nhớ và băng thông cho các ứng dụng.
 * 
 * Thư viện này cung cấp các API đơn giản hóa để làm việc với RDT thông qua
 * giao diện PQoS (Platform QoS).
 */

#ifndef RDT_HELPERS_H
#define RDT_HELPERS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/* Định nghĩa kiểu dữ liệu */
typedef uint32_t u32;
typedef uint64_t u64;

/* Cấu trúc thông tin L3 cache occupancy */
struct rdt_cache_info {
    unsigned int socket_id;   /* ID socket */
    unsigned int l3_id;       /* ID L3 cache */
    unsigned int class_id;    /* ID nhóm lớp RDT */
    uint64_t llc_occupancy;   /* Phần chiếm dụng của L3 cache (bytes) */
    uint64_t mbm_local;       /* Băng thông bộ nhớ local (bytes/s) */
    uint64_t mbm_total;       /* Tổng băng thông bộ nhớ (bytes/s) */
    uint64_t mbm_remote;      /* Băng thông bộ nhớ remote (bytes/s) */
};

/* Cấu trúc thông tin CPU cho RDT */
struct rdt_cpu_info {
    unsigned int num_cores;        /* Số lõi CPU */
    unsigned int num_sockets;      /* Số socket CPU */
    unsigned int *core_to_socket;  /* Ánh xạ từ lõi sang socket */
    unsigned int *socket_to_l3;    /* Ánh xạ từ socket sang L3 cache */
};

/* Cấu trúc giám sát RDT */
struct rdt_monitor_data {
    unsigned int core_id;      /* Lõi đang giám sát */
    unsigned int pid;          /* Process ID đang giám sát (0 nếu là toàn bộ hệ thống) */
    void *mon_data;            /* Dữ liệu giám sát nội bộ (pqos_mon_data) */
    struct rdt_cache_info cache; /* Thông tin cache đã thu thập */
};

/* Cấu trúc cấu hình RDT */
struct rdt_config {
    bool verbose;                /* Bật chế độ output chi tiết */
    bool use_llc_occupancy;     /* Sử dụng giám sát LLC occupancy */
    bool use_memory_bandwidth;   /* Sử dụng giám sát băng thông bộ nhớ */
    bool use_cat;                /* Sử dụng CAT (Cache Allocation Technology) */
    bool use_mba;                /* Sử dụng MBA (Memory Bandwidth Allocation) */
    unsigned int mba_percent;    /* % băng thông tối đa được cấp (nếu dùng MBA) */
    unsigned int cat_ways;       /* Số cache ways được cấp (nếu dùng CAT) */
};

/*
 * Các hàm chính
 */

#ifdef HAS_RDT
/**
 * Khởi tạo thư viện RDT và phát hiện khả năng phần cứng
 * 
 * @param config: cấu hình cho RDT, NULL để sử dụng cài đặt mặc định
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_init(struct rdt_config *config);

/**
 * Giải phóng tài nguyên RDT
 */
void rdt_fini(void);

/**
 * Lấy thông tin CPU sẵn có
 * 
 * @param cpu_info: con trỏ đến cấu trúc để lưu thông tin CPU
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_get_cpu_info(struct rdt_cpu_info *cpu_info);

/**
 * Bắt đầu giám sát một CPU core
 * 
 * @param core_id: ID của lõi CPU cần giám sát
 * @param mon_data: con trỏ đến cấu trúc để lưu dữ liệu giám sát
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_monitor_core(unsigned int core_id, struct rdt_monitor_data *mon_data);

/**
 * Bắt đầu giám sát một PID cụ thể
 * 
 * @param pid: Process ID cần giám sát
 * @param mon_data: con trỏ đến cấu trúc để lưu dữ liệu giám sát
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_monitor_pid(unsigned int pid, struct rdt_monitor_data *mon_data);

/**
 * Cập nhật dữ liệu giám sát (đọc giá trị hiện tại)
 * 
 * @param mon_data: con trỏ đến cấu trúc giám sát
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_update_monitor(struct rdt_monitor_data *mon_data);

/**
 * Dừng giám sát
 * 
 * @param mon_data: con trỏ đến cấu trúc giám sát
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_stop_monitor(struct rdt_monitor_data *mon_data);

/**
 * Khởi tạo cấu hình CAT (Cache Allocation Technology)
 * 
 * @param l3_id: ID của L3 cache
 * @param class_id: ID của lớp RDT
 * @param mask: Bit mask cho các cache ways được phân bổ
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_set_cat_config(unsigned int l3_id, unsigned int class_id, uint64_t mask);

/**
 * Khởi tạo cấu hình MBA (Memory Bandwidth Allocation)
 * 
 * @param l3_id: ID của L3 cache
 * @param class_id: ID của lớp RDT
 * @param mb_percent: % băng thông tối đa (1-100)
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_set_mba_config(unsigned int l3_id, unsigned int class_id, unsigned int mb_percent);

/**
 * Gán một process vào lớp RDT cụ thể
 * 
 * @param pid: Process ID cần gán
 * @param class_id: ID của lớp RDT
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_assign_pid(unsigned int pid, unsigned int class_id);

/**
 * Lấy thông tin khả năng RDT của hệ thống
 * 
 * @param has_cmt: đặt giá trị true nếu hệ thống hỗ trợ CMT (Cache Monitoring Technology)
 * @param has_cat: đặt giá trị true nếu hệ thống hỗ trợ CAT (Cache Allocation Technology)
 * @param has_mba: đặt giá trị true nếu hệ thống hỗ trợ MBA (Memory Bandwidth Allocation)
 * @return: 0 nếu thành công, <0 nếu thất bại
 */
int rdt_get_capabilities(bool *has_cmt, bool *has_cat, bool *has_mba);

/**
 * Kiểm tra xem RDT có khả dụng trên hệ thống hay không
 * 
 * @return: true nếu khả dụng, false nếu không
 */
bool rdt_is_available(void);

#else /* !HAS_RDT */

/* Định nghĩa stub functions nếu không hỗ trợ RDT */
static inline int rdt_init(struct rdt_config *config) { (void)config; return -1; }
static inline void rdt_fini(void) { }
static inline int rdt_get_cpu_info(struct rdt_cpu_info *cpu_info) { (void)cpu_info; return -1; }
static inline int rdt_monitor_core(unsigned int core_id, struct rdt_monitor_data *mon_data) { (void)core_id; (void)mon_data; return -1; }
static inline int rdt_monitor_pid(unsigned int pid, struct rdt_monitor_data *mon_data) { (void)pid; (void)mon_data; return -1; }
static inline int rdt_update_monitor(struct rdt_monitor_data *mon_data) { (void)mon_data; return -1; }
static inline int rdt_stop_monitor(struct rdt_monitor_data *mon_data) { (void)mon_data; return -1; }
static inline int rdt_set_cat_config(unsigned int l3_id, unsigned int class_id, uint64_t mask) { (void)l3_id; (void)class_id; (void)mask; return -1; }
static inline int rdt_set_mba_config(unsigned int l3_id, unsigned int class_id, unsigned int mb_percent) { (void)l3_id; (void)class_id; (void)mb_percent; return -1; }
static inline int rdt_assign_pid(unsigned int pid, unsigned int class_id) { (void)pid; (void)class_id; return -1; }
static inline int rdt_get_capabilities(bool *has_cmt, bool *has_cat, bool *has_mba) { if(has_cmt) *has_cmt = false; if(has_cat) *has_cat = false; if(has_mba) *has_mba = false; return -1; }
static inline bool rdt_is_available(void) { return false; }

#endif /* HAS_RDT */

#endif /* RDT_HELPERS_H */ 