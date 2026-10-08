/*
 * camera_discovery.h — Kamera Keşif Motoru
 *
 * Yerel ağdaki IP kameralarını (RTSP / ONVIF / HTTP arayüzü / OUI) tespit eder.
 * Aktif yöntemler:
 *   1. Kamera imzalı TCP port taraması (554, 8554, 37777, 34567, 8000, ...)
 *   2. RTSP OPTIONS/DESCRIBE sondası (Server başlığı, 401 realm)
 *   3. HTTP web arayüzü sondası (Server başlığı + kamera imza kelimeleri)
 *   4. ONVIF WS-Discovery (UDP 239.255.255.250:3702 multicast Probe)
 *   5. MAC OUI veritabanı (bilinen kamera üreticileri)
 *
 * Sonuçlar, kamera başına kanıt maskesi ve 0-100 güven skoru ile raporlanır.
 */
#ifndef CAMERA_DISCOVERY_H
#define CAMERA_DISCOVERY_H

#include "platform.h"

/* ========== Sabitler ========== */
#define CAM_MAX_DEVICES   256
#define CAM_MAX_PORTS     20
#define CAM_URL_LEN       256
#define CAM_REALM_LEN     160
#define CAM_SERVER_LEN    160
#define CAM_MODEL_LEN     128
#define CAM_EVIDENCE_LEN  256
#define CAM_MAX_LOG_LINES 200
#define CAM_MAX_HOSTS     1024   /* tarama başına üst sınır (gürültü/DoS kontrolü) */
#define CAM_MAX_WORKERS   32

/* ========== Kanıt Bitleri ========== */
enum {
    CAM_EV_PORT      = 1u << 0,   /* kamera imzalı TCP portu açık */
    CAM_EV_RTSP      = 1u << 1,   /* RTSP OPTIONS/DESCRIBE yanıtı */
    CAM_EV_RTSP_AUTH = 1u << 2,   /* RTSP 401 — kimlik doğrulama gerekiyor */
    CAM_EV_HTTP      = 1u << 3,   /* HTTP kamera web arayüzü imzası */
    CAM_EV_ONVIF     = 1u << 4,   /* ONVIF WS-Discovery yanıtı */
    CAM_EV_OUI       = 1u << 5,   /* MAC OUI -> bilinen kamera üreticisi */
    CAM_EV_VPORT     = 1u << 6    /* üreticiye özel port (37777, 34567, 8000...) */
};

/* ========== Kamera Kaydı ========== */
typedef struct {
    char ip[MAX_IP_LEN];
    char mac[MAX_MAC_LEN];
    char vendor[MAX_VENDOR_LEN];       /* OUI veritabanından üretici adı */
    char manufacturer[CAM_MODEL_LEN];  /* ONVIF/RTSP/HTTP'den üretici */
    char model[CAM_MODEL_LEN];         /* ONVIF model bilgisi */
    char rtsp_url[CAM_URL_LEN];        /* RTSP taban adresi (rtsp://ip:port/) */
    char http_url[CAM_URL_LEN];        /* web arayüzü adresi */
    char onvif_xaddr[CAM_URL_LEN];     /* ONVIF device_service (XAddrs) */
    char server_header[CAM_SERVER_LEN];/* RTSP/HTTP Server başlığı */
    char rtsp_realm[CAM_REALM_LEN];    /* RTSP/HTTP 401 realm (varsa) */

    int  ports[CAM_MAX_PORTS];
    int  port_count;
    int  rtsp_port;                    /* tespit edilen RTSP portu (0=yok) */
    int  http_port;                    /* tespit edilen web portu (0=yok) */
    int  rtsp_auth_required;
    int  has_onvif;

    unsigned evidence;                 /* CAM_EV_* maskesi */
    int  confidence;                   /* 0-100 güven skoru */
    char evidence_text[CAM_EVIDENCE_LEN];
    time_t discovered_at;
} CameraDevice;

/* ========== Tarama Sonuçları ========== */
typedef struct {
    CameraDevice cameras[CAM_MAX_DEVICES];
    int  count;

    int  is_scanning;
    int  scan_complete;
    int  progress;                     /* 0-100 */
    char target[64];                   /* taranan hedef (CIDR/IP) */
    char phase[64];                    /* aktif aşama metni */
    int  scanned_hosts;
    int  total_hosts;
    int  responded_hosts;              /* en az bir portu açık olan host sayısı */
    time_t last_scan_time;
    platform_mutex_t lock;
} CameraScanResults;

/* ========== Yaşam Döngüsü ========== */
void camera_discovery_init(void);
void camera_discovery_cleanup(void);

/* ========== Tarama ========== */
/* Senkron tarama. cidr == NULL/boş ise yerel arayüzün ağ aralığı kullanılır.
 * Döner: bulunan kamera sayısı (>=0), hata: -1. */
int  camera_discovery_scan(const char *cidr);

/* Arka plan (asenkron) tarama. Aynı anda tek tarama çalışır. */
void camera_discovery_start_async(const char *cidr);

/* Çalışan taramayı iptal et (sonuçlar korunur). */
void camera_discovery_cancel(void);

int  camera_discovery_is_scanning(void);

/* Sonuçları güvenli şekilde kopyalar. */
void camera_discovery_get_results(CameraScanResults *out);

/* Sadece kamera kayıtlarını kopyalar; döner: kopyalanan kayıt sayısı. */
int  camera_discovery_get_cameras(CameraDevice *out, int max_count);

/* ========== Yardımcılar ========== */
/* Kameranın RTSP URL'sini döndürür; kayıtta yoksa "rtsp://ip:port/" üretir. */
const char *camera_discovery_rtsp_url(const CameraDevice *cam, char *buf, int len);

/* MAC OUI -> bilinen kamera üreticisi mi? Üretici adı vendor_out'a yazılır.
 * Döner: 1 = kamera üreticisi, 0 = değil/bilinmiyor. */
int  camera_discovery_oui_is_camera(const char *mac, char *vendor_out, int len);

/* Kamera web arayüzünde çalışan bir yolu tarayıp göstermek için: varsayılan
 * akış yolları listesi (erişim motoru kullanır). */
const char *const *camera_discovery_common_rtsp_paths(int *count_out);

/* ========== Log ========== */
void camera_discovery_log(const char *fmt, ...);
int  camera_discovery_get_log(char lines[][256], int max_lines);

#endif /* CAMERA_DISCOVERY_H */
