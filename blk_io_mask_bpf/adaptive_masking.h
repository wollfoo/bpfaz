/* SPDX-License-Identifier: GPL-2.0
 * adaptive_masking.h - Chức năng điều chỉnh thích ứng tỷ lệ che giấu
 */

#ifndef __ADAPTIVE_MASKING_H
#define __ADAPTIVE_MASKING_H

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// Cấu trúc cấu hình cho adaptive masking
struct adaptive_config {
    double cpu_load_weight;      // Trọng số của CPU load (0-1)
    double temp_weight;          // Trọng số của nhiệt độ (0-1)
    double sigmoid_steepness;    // Độ dốc của hàm sigmoid (1-20)
    double sigmoid_midpoint;     // Điểm giữa của hàm sigmoid (0-1)
    double min_ratio;            // Tỷ lệ che giấu tối thiểu (%)
    double max_ratio;            // Tỷ lệ che giấu tối đa (%)
    int update_interval;         // Khoảng thời gian cập nhật (giây)
    char thermal_zone_path[256]; // Đường dẫn đến thermal zone
    int min_temp;                // Nhiệt độ tối thiểu (°C)
    int max_temp;                // Nhiệt độ tối đa (°C)
    double max_load;             // Giá trị tối đa của CPU load
};

// Biến toàn cục
extern struct adaptive_config adap_cfg;
extern pthread_t adaptive_thread;
extern volatile bool adaptive_running;
extern pthread_mutex_t adaptive_mutex;   // Mutex để bảo vệ adap_cfg
extern pthread_mutex_t ratio_mutex;      // Mutex để bảo vệ khi thay đổi ratio

// Các hàm
void init_adaptive_config(void);
double get_cpu_load(void);
double get_thermal_temp(void);
double compute_sigmoid_mask_ratio(double cpu_load, double temp);
void *adaptive_mask_thread(void *arg);
int start_adaptive_thread(void);
int stop_adaptive_thread(void);

#endif /* __ADAPTIVE_MASKING_H */ 