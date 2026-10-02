/*
 * port_scanner.h — Stealth Advanced Port Scanner
 * IDS/IPS Evasion, Akıllı Gürültü Yönetimi, Servis / Zafiyet Tespiti
 */
#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#include "platform.h"

/* ========== Sabitler ========== */
#define PS_MAX_PORTS         4096
#define PS_MAX_RESULTS       512
#define PS_TIMEOUT_BASE      3000      /* base timeout ms */
#define PS_MAX_BANNER        512
#define PS_MAX_THREADS       4         /* düşük tut, gürültüyü azalt */
#define PS_TOP_PORTS_COUNT   100

/* ========== Stealth Parametreleri ========== */
typedef struct {
    int  min_delay_ms;          /* paketler arası minimum gecikme (ms) */
    int  max_delay_ms;          /* maksimum rastgele gecikme sapması (ms) */
    int  jitter_percent;        /* jitter oranı (0-100) */
    int  spoof_mac_enabled;     /* MAC randomizasyonu (raw socket ile) */
    int  fragment_ip;           /* IP fragmentasyonu (raw socket ile) */
    int  decoy_count;           /* decoy kaynak IP sayısı */
    int  randomize_port_order;  /* port sırasını rastgele dağıt */
    int  idle_host_enabled;     /* idle scan (zombie host) */
    char idle_zombie_ip[16];    /* zombie IP */
    int  scan_speed;            /* 0: paranoid, 1: sneaky, 2: polite, 3: normal */
    int  max_retransmits;       /* tekrar deneme sayısı */
    int  ttl_min;               /* TTL varyasyonu alt sınırı */
    int  ttl_max;               /* TTL varyasyonu üst sınırı */
} StealthConfig;

/* Varsayılan stealth konfigürasyonu */
#define STEALTH_CONFIG_DEFAULT { \
    .min_delay_ms        = 200,    \
    .max_delay_ms        = 800,    \
    .jitter_percent      = 40,     \
    .spoof_mac_enabled   = 0,      \
    .fragment_ip         = 0,      \
    .decoy_count         = 0,      \
    .randomize_port_order= 1,      \
    .idle_host_enabled   = 0,      \
    .idle_zombie_ip      = "",     \
    .scan_speed          = 2,      \
    .max_retransmits     = 1,      \
    .ttl_min             = 48,     \
    .ttl_max             = 128     \
}

/* ========== Tarama Tipleri (evasion varyantları ile) ========== */
typedef enum {
    PS_SCAN_CONNECT     = 0,   /* TCP Connect (fallback) */
    PS_SCAN_SYN,               /* SYN half-open */
    PS_SCAN_SYN_FRAG,          /* SYN + IP fragmentation */
    PS_SCAN_FIN,               /* FIN scan */
    PS_SCAN_NULL,              /* NULL scan */
    PS_SCAN_XMAS,              /* Xmas scan */
    PS_SCAN_ACK,               /* ACK scan (firewall rule map) */
    PS_SCAN_WINDOW,            /* Window scan (RST window check) */
    PS_SCAN_MAIMON,            /* Maimon scan (FIN/ACK) */
    PS_SCAN_UDP,               /* UDP scan */
    PS_SCAN_IDLE,              /* Idle scan (zombie) */
    PS_SCAN_FTP_BOUNCE,        /* FTP bounce proxy scan */
    PS_SCAN_SCTP_INIT,         /* SCTP INIT scan */
    PS_SCAN_IP_PROTO           /* IP protocol scan */
} PortScanType;

/* ========== Port Durumu (detaylı) ========== */
typedef enum {
    PORT_CLOSED          = 0,
    PORT_OPEN,
    PORT_FILTERED,
    PORT_OPEN_FILTERED,
    PORT_UNFILTERED
} PortStatus;

/* ========== Zafiyet / Güvenlik Notu ========== */
typedef struct {
    char cve_id[24];             /* CVE-YYYY-NNNNNN */
    char description[256];       /* kısa açıklama */
    char severity[8];            /* CRITICAL / HIGH / MEDIUM / LOW */
    char recommendation[256];    /* düzeltme önerisi */
} VulnerabilityNote;

/* ========== Servis Bilgisi (detaylı) ========== */
typedef struct {
    int         port;
    PortStatus  status;
    char        service[32];
    char        product[64];       /* örn: OpenSSH, Apache httpd */
    char        version[32];       /* örn: 8.9p1, 2.4.57 */
    char        banner[PS_MAX_BANNER];
    double      rtt_ms;
    int         ttl;
    int         is_ssl;            /* SSL/TLS üzerinden mi */
    int         is_auth_required;  /* kimlik doğrulama gerekiyor mu */
    char        os_hint[32];       /* işletim sistemi ipucu */
    VulnerabilityNote vulns[8];   /* tespit edilen zaafiyetler */
    int         vuln_count;
} PortResult;

/* ========== Tarama Sonuçları ========== */
typedef struct {
    char            target_ip[MAX_IP_LEN];
    PortResult      ports[PS_MAX_RESULTS];
    int             open_count;
    int             filtered_count;
    int             closed_count;
    int             total_scanned;
    int             total_target_ports;   /* hedef port sayisi (progress icin) */
    double          scan_time_sec;
    int             is_scanning;
    int             scan_complete;
    char            os_guess[64];
    int             os_confidence;     /* 0-100 */
    PortScanType    scan_type;
    StealthConfig   stealth;
    int             total_vulns_found; /* toplam zafiyet sayısı */
    platform_mutex_t lock;
} PortScanResults;

/* ========== Fonksiyonlar ========== */
void portscan_init(void);
void portscan_cleanup(void);

/* Stealth konfigürasyonu ayarla */
void portscan_set_stealth(StealthConfig cfg);

/* Tarama başlat (gelişmiş) */
void portscan_start(const char *target_ip, PortScanType type,
                    int start_port, int end_port);

/* Top port taraması (akıllı önceliklendirme ile) */
void portscan_start_top(const char *target_ip, PortScanType type);

/* Özel port listesi ile tarama */
void portscan_start_list(const char *target_ip, PortScanType type,
                         const int *ports, int port_count);

/* Sonuçları al */
void portscan_get_results(PortScanResults *out);

/* Taramayı durdur */
void portscan_stop(void);

/* Yardımcı servis/zafiyet sorgulama */
const char *portscan_service_name(int port);
const char *portscan_guess_os(int ttl);
int         portscan_lookup_vulns(const char *service, const char *version,
                                  VulnerabilityNote *out, int max_vulns);

#endif /* PORT_SCANNER_H */