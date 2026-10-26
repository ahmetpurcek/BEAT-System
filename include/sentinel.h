/*
 * sentinel.h — SENTINEL v2: Otonom Kamera Istismar Platformu Cekirdegi
 *
 * BEAT System'in kamera hattini (camera_discovery / camera_vuln /
 * camera_access / video_stream) BOZMADAN onun ustune kurulan faz motoru.
 *
 * Tasarim ilkeleri:
 *   - Faz 1 keşfi camera_discovery tarafindan uretilir ve SADECE OKUNUR.
 *     SENTINEL kendi keşif kodunu ayrica calistirir; mevcut motor degismez.
 *   - Her faz bagimsiz calistirilabilir; tum durum bellek icindedir.
 *   - Bir modul hata verirse orkestrator sonraki faza gecer (exception
 *     isolation); hata log'a yazilir.
 *   - Tum ag islemleri rate-limit + zaman penceresi ile sinirlidir.
 *
 * C11 / POSIX. Harici bagimliliklar: yok (libcurl opsiyonel).
 */
#ifndef SENTINEL_H
#define SENTINEL_H

#include "platform.h"
#include <stdint.h>

#define SN_VERSION          "2.0"
#define SN_IP_LEN           MAX_IP_LEN   /* platform.h ile ayni */
#define SN_MAX_TARGETS      64
#define SN_MAX_FINDINGS     512
#define SN_MAX_LOG          400
#define SN_PATH_LEN         512
#define SN_URL_LEN          512
#define SN_TITLE_LEN        160
#define SN_DETAIL_LEN       512
#define SN_CLS_LEN          40
#define SN_VEC_LEN          96   /* CVSS 3.1 vektor dizgisi (~45) + etiketler */
#define SN_MAX_HOSTS        512

/* ========== Fazlar ========== */
typedef enum {
    SN_PH_IDLE = 0,
    SN_PH_SURFACE,        /* 1  saldiri yuzeyi haritalama (mevcut recon'u okur) */
    SN_PH_FINGERPRINT,    /* 2  derin vendor/SoC/firmware tespiti */
    SN_PH_FIRMWARE,       /* 3  firmware indirme/unpack/secret mining */
    SN_PH_PROTOCOL,       /* 4  protokol mantik zafiyeti avcisi */
    SN_PH_FUZZ,           /* 5  yapi-farkindalikli fuzzing */
    SN_PH_CLOUD,          /* 6  cloud / P2P zinciri */
    SN_PH_PIVOT,          /* 7  pivot / pasif istismar */
    SN_PH_EXPLOIT,        /* 8  exploit engine + karar motoru */
    SN_PH_REPORT,         /* 10 pentest deliverable */
    SN_PH_DONE,
    SN_PH_COUNT
} SnPhase;

typedef enum {
    SPS_PENDING = 0,
    SPS_RUNNING,
    SPS_OK,
    SPS_SKIPPED,          /* hedef yok / modul kapali — HATA DEGIL */
    SPS_FAILED
} SnPhaseState;

/* ========== Hedef ========== */
typedef struct {
    char  ip[SN_IP_LEN];
    char  mac[MAX_MAC_LEN];
    char  vendor[64];
    char  model[64];
    char  fw_version[64];
    char  soc[64];
    int   http_port;
    int   rtsp_port;
    int   onvif_port;
    int   sdk_port;
    int   confidence;
    unsigned evidence;
    char  cloud_peer[128];
    char  last_vector[SN_VEC_LEN];
    time_t seen_at;
} SnTarget;

/* ========== Bulgu ========== */
typedef struct {
    int   id;
    char  target[SN_IP_LEN];   /* bos = firmware/offline bulgusu */
    char  cls[SN_CLS_LEN];     /* firmware_secret, protocol_logic, ... */
    char  title[SN_TITLE_LEN];
    char  vector[SN_VEC_LEN];  /* hangi vektor/teknik veya CVSS 3.1 dizgisi */
    char  cwe[16];
    char  severity[12];        /* kritik | yuksek | orta | dusuk | bilgi */
    double cvss;
    int   confidence;          /* 0-100 */
    char  status[16];          /* candidate | validated | confirmed | rejected */
    char  detail[SN_DETAIL_LEN];
    char  evidence[SN_PATH_LEN];
    time_t ts;
} SnFinding;

/* ========== Firmware analiz sonucu ========== */
typedef struct {
    char  path[SN_PATH_LEN];
    char  sha256[65];
    char  container[48];
    char  filesystem[48];
    char  extract_dir[SN_PATH_LEN];
    int   encrypted;
    int   depth;
    int   files;
    int   binaries;
    int   secrets;
    int   unsafe_calls;
    int   preauth_candidates;
} SnFwResult;

/* ========== Durum (GUI snapshot) ========== */
typedef struct {
    int   run_active;
    int   run_done;
    SnPhase phase;
    SnPhaseState pstate[SN_PH_COUNT];
    char  msg[160];
    int   progress;
    int   target_count;
    int   finding_count;
    int   confirmed;
    int   candidates;
    SnFwResult fw;
    int   fw_loaded;
    char  report_path[SN_PATH_LEN];
    time_t started;
    time_t finished;
} SnStatus;

/* ========== Yasam dongusu ========== */
/* cfg NULL -> "sentinel.yaml" (varsa). But durum bellek icinde tutulur. */
int  sn_init(const char *cfg_path);
void sn_shutdown(void);
int  sn_load_config(const char *path);

/* ========== Orkestrator ========== */
int  sn_start_run(void);          /* arka plan thread, 0 = basladi */
void sn_stop_run(void);           /* istek: mevcut adimi bitirip dur */
void sn_get_status(SnStatus *st);

/* ========== Veri erisimi (GUI) ========== */
int  sn_get_targets(SnTarget *out, int max);
int  sn_get_findings(SnFinding *out, int max);
int  sn_get_log(char lines[][256], int max);   /* en yeni once */
int  sn_add_target(const char *ip);
int  sn_finding_add(const SnFinding *f);       /* (cls,title,target) dedupe */
void sn_clear_findings(void);
void sn_logf(const char *fmt, ...);

/* ========== Moduller (fazlar bagimsiz cagrilabilir) ========== */
int  sn_surface_scan(void);
int  sn_fingerprint_target(SnTarget *t);
int  sn_fw_analyze(const char *path, SnFwResult *res, int add_findings);
void sn_fw_state_set(const SnFwResult *r);   /* sonucu rapor/orkestrator durumuna yaz */
int  sn_protocol_run(SnTarget *t);
int  sn_fuzz_run(SnTarget *t);
int  sn_cloud_run(SnTarget *t);
int  sn_pivot_run(SnTarget *t);
int  sn_exploit_decide(SnTarget *t);

/* ========== Yardimcilar ========== */
const char *sn_phase_name(SnPhase p);
const char *sn_phase_desc(SnPhase p);
double      sn_cvss_base(const char *vector);   /* CVSS 3.1 base skoru */
void        sn_severity_from_cvss(double s, char *out, int len);
int         sn_sha256_file(const char *path, char *hex, int hexlen);
long        sn_now_ms(void);

#endif /* SENTINEL_H */
