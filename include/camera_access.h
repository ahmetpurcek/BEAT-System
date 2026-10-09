/*
 * camera_access.h — Kamera Erisim Motoru (Faz 3)
 *
 * Kesfedilen bir kameraya OTONOM olarak erisim saglar:
 *   1. RTSP yol kesfi (common paths, hizli DESCRIBE sondasi)
 *   2. Kimliksiz acik akis denemesi
 *   3. Varsayilan kimlik listesi (admin/admin, admin/12345, ubnt/ubnt ...)
 *      -> Basic ile hizli, olmazsa ffmpeg (Basic+Digest) ile dogrulama
 *   4. Elle kullanici/parola denemesi (arayuzden)
 *
 * Basarili olursa tikan URL (gerekirse user:pass gomulu) found_url'e yazilir;
 * arayuz bu URL'yi video_stream ile acip duvar grid'inde gosterir.
 *
 * Tum ag islemleri tek bir arka plan isci thread'de yapilir; arayuz bloke
 * olmaz. Isler mutex ile korunur (platform.h'de kosul degiskeni olmadigindan
 * isci kuyrugu yoklama ile tuketir).
 */
#ifndef CAMERA_ACCESS_H
#define CAMERA_ACCESS_H

#include "platform.h"
#include "camera_discovery.h"

#define CA_MAX_JOBS       128
#define CA_USER_LEN       64
#define CA_PASS_LEN       64
#define CA_ERR_LEN        128
#define CA_DEFAULT_CREDS  96     /* varsayilan kimlik denemesi ust siniri (genis DB) */

/* Erisim isi durumu */
typedef enum {
    CA_IDLE = 0,      /* is yok */
    CA_QUEUED,        /* kuyrukta */
    CA_RUNNING,       /* deneniyor */
    CA_FOUND,         /* erisim saglandi (found_url dolu) */
    CA_FAILED,        /* tum adaylar tukendi */
    CA_CANCELLED      /* iptal edildi */
} CameraAccessState;

typedef struct {
    char              ip[MAX_IP_LEN];
    int               port;
    char              base_url[CAM_URL_LEN];   /* kesiften gelen taban adres */
    int               auth_required;
    char              realm[CAM_REALM_LEN];

    CameraAccessState state;
    int               tried;                   /* denenen aday sayisi */
    int               total;                   /* tahmini toplam aday */

    char              found_url[CAM_URL_LEN];   /* calisan akis URL'i */
    char              found_user[CA_USER_LEN];  /* acik akis ise bos */
    char              found_pass[CA_PASS_LEN];
    int               open_stream;              /* 1 = kimliksiz acik akis */

    char              path[128];                /* bulunan calisan RTSP yolu */
    char              last_error[CA_ERR_LEN];   /* son hata / durum metni */

    /* elle kimlik giris (arayuz doldurur) */
    char              manual_user[CA_USER_LEN];
    char              manual_pass[CA_PASS_LEN];
    int               used_manual;              /* elle kimlik denendi mi */

    /* kesiften gelen ek HTTP baglami (bypass/ONVIF/snapshot icin) */
    int               http_port;                /* 0 = bilinmiyor (varsayilan 80) */
    char              vendor[64];               /* uretici ipucu */
    unsigned          vuln_mask;                /* bulunan bypass/zafiyet maskesi */
    char              vuln_detail[CA_ERR_LEN];  /* sonda aciklamasi */
    int               onvif_used;               /* ONVIF ile mi erisildi */
    char              snapshot_path[256];       /* cekilen son kare dosyasi */
} CameraAccessJob;

/* Sistem yasam dongusu */
void camera_access_init(void);
void camera_access_shutdown(void);

/* Bir kamera icin otonom erisim baslatir (acik + varsayilan kimlikler).
 * ip: hedef; port: rtsp portu; base_url: "rtsp://ip:port/" veya tam URL;
 * auth_required/realm: kesiften. Doner: 0 = kuyruga alindi, -1 = hata. */
int  camera_access_start(const char *ip, int port, const char *base_url,
                         int auth_required, const char *realm);

/* Elle kullanici/parola ile yeniden dene (once Basic, gerekirse ffmpeg/Digest).
 * Doner: 0 = kuyruga alindi, -1 = hata (is zaten calisiyorsa). */
int  camera_access_try_credentials(const char *ip, const char *user,
                                   const char *pass);

/* Isin anlik kopyasini alir. Doner: 1 = kayit var, 0 = yok. */
int  camera_access_get(const char *ip, CameraAccessJob *out);

/* Is kuyrukta/calisiyor mu? */
int  camera_access_busy(const char *ip);

/* Kesiften ek HTTP baglami ekler (bypass/ONVIF/snapshot icin). Additive;
 * camera_access_start'tan once ya da sonra cagrilabilir. */
void camera_access_set_context(const char *ip, int http_port, const char *vendor);

/* Bulunan erisimle HTTP snapshot endpoint'inden tek kare JPEG/PNG cekmeyi dener.
 * Doner: 0 = kare yazildi, -1 = hata/erisim yok. */
int  camera_access_snapshot(const char *ip, const char *out_path);

#endif /* CAMERA_ACCESS_H */
