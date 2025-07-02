/* SPDX-License-Identifier: GPL-2.0
 * adaptive_masking.c - Chức năng điều chỉnh thích ứng tỷ lệ che giấu
 */

#include "adaptive_masking.h"
#include <string.h>
#include <time.h>
#include <errno.h>

// Biến toàn cục
struct adaptive_config adap_cfg;
pthread_t adaptive_thread;
volatile bool adaptive_running = false;
pthread_mutex_t adaptive_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ratio_mutex = PTHREAD_MUTEX_INITIALIZER;

// Prototype của hàm từ blk_mask_ctl.c
int set_mask_ratio_internal(uint16_t ratio);

// Khởi tạo cấu hình mặc định
void init_adaptive_config(void)
{
    pthread_mutex_lock(&adaptive_mutex);
    
    adap_cfg.cpu_load_weight = 0.7;    // 70% trọng số cho CPU load
    adap_cfg.temp_weight = 0.3;        // 30% trọng số cho nhiệt độ
    adap_cfg.sigmoid_steepness = 8.0;   // Độ dốc của sigmoid
    adap_cfg.sigmoid_midpoint = 0.5;    // Điểm giữa của sigmoid
    adap_cfg.min_ratio = 30.0;          // Tối thiểu 30% masking
    adap_cfg.max_ratio = 70.0;          // Tối đa 70% masking
    adap_cfg.update_interval = 5;       // Cập nhật mỗi 5 giây
    strcpy(adap_cfg.thermal_zone_path, "/sys/class/thermal/thermal_zone0/temp");
    adap_cfg.min_temp = 40;             // 40°C là nhiệt độ thấp
    adap_cfg.max_temp = 80;             // 80°C là nhiệt độ cao
    adap_cfg.max_load = 10.0;           // Load 10.0 là giá trị cao
    
    pthread_mutex_unlock(&adaptive_mutex);
}

// Đọc CPU load từ /proc/loadavg
double get_cpu_load(void)
{
    FILE *fp = fopen("/proc/loadavg", "r");
    if (!fp) {
        fprintf(stderr, "Không thể mở /proc/loadavg: %s\n", strerror(errno));
        return 0.0;
    }
    
    double load1, load5, load15;
    if (fscanf(fp, "%lf %lf %lf", &load1, &load5, &load15) != 3) {
        fprintf(stderr, "Lỗi đọc dữ liệu từ /proc/loadavg\n");
        fclose(fp);
        return 0.0;
    }
    
    fclose(fp);
    return load1;  // Sử dụng load trung bình 1 phút
}

// Đọc nhiệt độ từ thermal zone
double get_thermal_temp(void)
{
    char thermal_path[256];
    
    // Lấy đường dẫn thermal zone với mutex
    pthread_mutex_lock(&adaptive_mutex);
    strncpy(thermal_path, adap_cfg.thermal_zone_path, sizeof(thermal_path));
    pthread_mutex_unlock(&adaptive_mutex);
    
    FILE *fp = fopen(thermal_path, "r");
    if (!fp) {
        // Thử thermal zone khác nếu zone được chỉ định không tồn tại
        int i;
        char alt_path[256];
        for (i = 0; i < 5; i++) {
            snprintf(alt_path, sizeof(alt_path), "/sys/class/thermal/thermal_zone%d/temp", i);
            fp = fopen(alt_path, "r");
            if (fp) {
                pthread_mutex_lock(&adaptive_mutex);
                strcpy(adap_cfg.thermal_zone_path, alt_path);
                pthread_mutex_unlock(&adaptive_mutex);
                break;
            }
        }
        
        if (!fp) {
            fprintf(stderr, "Không thể mở thermal zone: %s\n", strerror(errno));
            return 0.0;
        }
    }
    
    int temp_millic;
    if (fscanf(fp, "%d", &temp_millic) != 1) {
        fprintf(stderr, "Lỗi đọc dữ liệu từ thermal zone\n");
        fclose(fp);
        return 0.0;
    }
    
    fclose(fp);
    return temp_millic / 1000.0;  // Chuyển đổi từ milli-Celsius sang Celsius
}

// Hàm sigmoid để tính toán tỷ lệ che giấu thích ứng
double compute_sigmoid_mask_ratio(double cpu_load, double temp)
{
    double cpu_load_weight, temp_weight, sigmoid_steepness, sigmoid_midpoint;
    double min_ratio, max_ratio, max_load;
    double min_temp, max_temp;
    
    // Lấy cấu hình với mutex
    pthread_mutex_lock(&adaptive_mutex);
    cpu_load_weight = adap_cfg.cpu_load_weight;
    temp_weight = adap_cfg.temp_weight;
    sigmoid_steepness = adap_cfg.sigmoid_steepness;
    sigmoid_midpoint = adap_cfg.sigmoid_midpoint;
    min_ratio = adap_cfg.min_ratio;
    max_ratio = adap_cfg.max_ratio;
    max_load = adap_cfg.max_load;
    min_temp = adap_cfg.min_temp;
    max_temp = adap_cfg.max_temp;
    pthread_mutex_unlock(&adaptive_mutex);
    
    // Chuẩn hóa CPU load (giá trị từ 0 đến max_load)
    double norm_load = fmin(cpu_load / max_load, 1.0);
    
    // Chuẩn hóa nhiệt độ (giá trị từ min_temp đến max_temp)
    double norm_temp = fmin(fmax((temp - min_temp) / 
                           (max_temp - min_temp), 0.0), 1.0);
    
    // Kết hợp các chỉ số theo trọng số
    double combined = cpu_load_weight * norm_load + 
                      temp_weight * norm_temp;
    
    // Áp dụng hàm sigmoid: f(x) = 1 / (1 + e^(-k * (x - midpoint)))
    // k là sigmoid_steepness, midpoint là sigmoid_midpoint
    double sigmoid = 1.0 / (1.0 + exp(-sigmoid_steepness * 
                            (combined - sigmoid_midpoint)));
    
    // Ánh xạ giá trị sigmoid (0-1) vào khoảng min_ratio đến max_ratio
    double ratio = min_ratio + 
                  (max_ratio - min_ratio) * sigmoid;
    
    return ratio;
}

// Thread chạy nền để điều chỉnh tỷ lệ che giấu
void *adaptive_mask_thread(void *arg)
{
    time_t last_log = 0;
    bool is_running;
    
    while (1) {
        // Kiểm tra trạng thái running với mutex
        pthread_mutex_lock(&adaptive_mutex);
        is_running = adaptive_running;
        pthread_mutex_unlock(&adaptive_mutex);
        
        if (!is_running)
            break;
        
        // Lấy thông tin hệ thống
        double cpu_load = get_cpu_load();
        double temp = get_thermal_temp();
        
        // Tính toán tỷ lệ che giấu mới
        double new_ratio = compute_sigmoid_mask_ratio(cpu_load, temp);
        int ratio_int = (int)round(new_ratio);
        
        // Áp dụng tỷ lệ mới với mutex
        pthread_mutex_lock(&ratio_mutex);
        set_mask_ratio_internal(ratio_int);
        pthread_mutex_unlock(&ratio_mutex);
        
        // Log thông tin định kỳ (mỗi phút)
        time_t now = time(NULL);
        if (now - last_log >= 60) {
            fprintf(stderr, "[%s] Adaptive masking: load=%.2f, temp=%.2f°C, ratio=%d%%\n",
                    ctime(&now), cpu_load, temp, ratio_int);
            last_log = now;
        }
        
        // Lấy khoảng thời gian cập nhật với mutex
        int update_interval;
        pthread_mutex_lock(&adaptive_mutex);
        update_interval = adap_cfg.update_interval;
        pthread_mutex_unlock(&adaptive_mutex);
        
        // Đợi đến khoảng thời gian cập nhật tiếp theo
        sleep(update_interval);
    }
    
    return NULL;
}

// Bắt đầu thread adaptive
int start_adaptive_thread(void)
{
    bool already_running = false;
    
    pthread_mutex_lock(&adaptive_mutex);
    already_running = adaptive_running;
    if (!already_running) {
        adaptive_running = true;
    }
    pthread_mutex_unlock(&adaptive_mutex);
    
    if (already_running) {
        fprintf(stderr, "Thread adaptive masking đã đang chạy\n");
        return 0;  // Đã chạy rồi, không lỗi
    }
    
    if (pthread_create(&adaptive_thread, NULL, adaptive_mask_thread, NULL) != 0) {
        fprintf(stderr, "Không thể tạo thread adaptive masking: %s\n", strerror(errno));
        
        pthread_mutex_lock(&adaptive_mutex);
        adaptive_running = false;
        pthread_mutex_unlock(&adaptive_mutex);
        
        return -1;
    }
    
    return 0;
}

// Dừng thread adaptive
int stop_adaptive_thread(void)
{
    bool was_running = false;
    
    pthread_mutex_lock(&adaptive_mutex);
    was_running = adaptive_running;
    adaptive_running = false;
    pthread_mutex_unlock(&adaptive_mutex);
    
    if (!was_running) {
        return 0;  // Đã dừng rồi, không lỗi
    }
    
    pthread_join(adaptive_thread, NULL);
    
    return 0;
}