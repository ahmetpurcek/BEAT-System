/*
 * site_block.h — "Site Karartma" motoru (per-IP per-site engelleme).
 *
 * Bir cihazin (IP) hangi alan adlarina gittigini YAPISAL olarak izler
 * (DNS/SNI/HTTP/QUIC; network_monitor dissector'i doldurur) ve secilen
 * (IP, alan adi) ciftleri icin trafigi karartir:
 *
 *   - SINKHOLE : DNS sorgusuna sahte yanit (0.0.0.0) -> istemci cozemez
 *   - RST      : TCP RST enjekte et -> mevcut/olusan baglanti duser
 *   - BOTH     : ikisi birlikte
 *
 * QUIC (UDP/443) icin DNS ve RST ise yaramaz; istemciyi TCP/TLS'e zorlamak
 * uzere ICMP "port unreachable" enjekte edilir (best-effort).
 *
 * Uygulama, ARP spoof ile MITM konumundayken kurban istemciden/sunucudan
 * gecen kareleri sahtelemek icin raw_inject (AF_PACKET / pcap) kullanir.
 * Test sirasinda gercek kare GONDERILMEZ: raw_inject sink kancasi ile
 * yalnizca kurulan kare dogrulanir.
 */
#ifndef SITE_BLOCK_H
#define SITE_BLOCK_H

#include "network_monitor.h"

#define SB_MAX_RULES 256
#define SB_DOMAIN_LEN MAX_DOMAIN_LEN
#define SB_IP_LEN     MAX_IP_LEN
#define SB_OBS_MAX    2048

/* Uygulama modu (kural bazli) */
enum {
    SB_MODE_SINKHOLE = 1,   /* yalnizca DNS sinkhole */
    SB_MODE_RST      = 2,   /* yalnizca TCP RST (+QUIC ICMP) */
    SB_MODE_BOTH     = 3    /* ikisi birlikte */
};

typedef struct {
    char ip[SB_IP_LEN];        /* hedef cihaz IP ("*" = tum cihazlar) */
    char domain[SB_DOMAIN_LEN];/* "facebook.com","*.youtube.com","*youtube.com","*youtube*","*" */
    int  mode;                 /* SB_MODE_* */
    int  enabled;
    unsigned long hits;
    double last_hit;
} SiteBlockRule;

/* Per-IP site gozlemi (GUI'de "hangi IP hangi siteye girdi" listesi) */
typedef struct {
    char ip[SB_IP_LEN];
    char domain[SB_DOMAIN_LEN];
    unsigned char kind;        /* DOMAIN_KIND_* */
    unsigned long count;
    double last_seen;
    int  blocked;              /* su an aktif kural eşleşiyor mu */
} SiteBlockObs;

typedef struct {
    int    enabled;            /* global ac/kapa */
    int    raw_ready;          /* ham enjeksiyon hazir mi */
    int    scope_count;        /* izleme kapsami (0 = tum ag) */
    unsigned long sinkholed;   /* gonderilen sahte DNS yaniti */
    unsigned long rst_sent;    /* gonderilen TCP RST */
    unsigned long icmp_sent;   /* gonderilen ICMP unreachable */
    unsigned long observed;    /* islenen alan adi gozlemi */
    unsigned long sent_total;  /* toplam enjekte edilen kare */
    /* --- Cekirdek (iptables) deterministik katman --- */
    int    fw_ready;           /* BEAT_SB zinciri + atlamalar aktif mi */
    unsigned long fw_ip_rules; /* aktif IP DROP kurali sayisi */
    unsigned long fw_dns_rules;/* aktif DNS string DROP kurali sayisi */
    unsigned long fw_events;   /* kac kez cekirdek kurali kuruldu */
} SiteBlockStats;

/* ---- Yasam dongusu ---- */
void site_block_init(void);
void site_block_cleanup(void);

/* ---- Ag baglami (network_monitor tarafindan beslenir) ---- */
void site_block_set_iface(const char *iface);      /* ham soketi bu arayuzde acar */
void site_block_set_own_mac(const unsigned char mac[6]);
void site_block_set_own_ip(const char *ip);
void site_block_set_gateway_mac(const unsigned char mac[6]);
int  site_block_raw_ready(void);

/* ---- Global kontrol ---- */
void site_block_set_enabled(int on);
int  site_block_is_enabled(void);

/* Sinkhole yanit IP'si (varsayilan "0.0.0.0") */
void site_block_set_sinkhole_ip(const char *ip);
const char *site_block_get_sinkhole_ip(void);

/* ---- Izleme kapsami (izleme listesi kopyasi; bos = tum ag) ---- */
void site_block_set_scope(const char *ips[], int n);
void site_block_clear_scope(void);
int  site_block_scope_contains(const char *ip);

/* ---- Kural yonetimi ---- */
int  site_block_add_rule(const char *ip, const char *domain, int mode);
int  site_block_remove_rule(int index);
void site_block_clear_rules(void);
int  site_block_rule_count(void);
int  site_block_get_rule(int index, SiteBlockRule *out);
int  site_block_find_rule(const char *ip, const char *domain);

/* ---- Eslesme (kural bul; out'a kopyalar) ---- */
int  site_block_match(const char *ip, const char *domain, SiteBlockRule *out);

/* ---- Gozlem + uygulama (network_monitor her yabanci karede cagirir) ---- */
void site_block_observe(const PacketRecord *pkt);

/* ---- GUI gozlem listesi ---- */
int  site_block_observations(SiteBlockObs *out, int max);
void site_block_clear_observations(void);
/* Bir gozlemi (IP+alan adi) dogrudan kurala cevir; mod default BOTH. */
int  site_block_block_observed(const char *ip, const char *domain, int mode);
/* Bir gozlemin engelini kaldir: (ip, domain) ile ESLEMEN tum kurallari
 * (wildcard dahil) siler, cekirdek girdilerini temizler, gozlem bayraklarini
 * tazeler. Kaldirilan kural sayisini dondurur. */
int  site_block_unblock_observed(const char *ip, const char *domain);

/* ---- Istatistik ---- */
void site_block_get_stats(SiteBlockStats *s);

/* ---- Cekirdek (iptables) deterministik karartma katmani ----------------
 * Reaktif enjeksiyonun forward ile yarisa girmesini (race) ortadan
 * kaldirmak icin, eslesen (kurban, hedef) icin cekirdek seviyesinde DROP
 * kurallari kurulur. Boylece gercek DNS yaniti / TLS akisi asla gecmez.
 */
int  site_block_fw_init(void);           /* BEAT_SB zinciri + atlamalar */
void site_block_fw_cleanup(void);        /* atlamalari ve zinciri kaldir */
int  site_block_fw_block_ip(const char *victim, const char *ip,
                            const char *owner_ip, const char *owner_domain);
int  site_block_fw_block_dns(const char *victim, const char *domain,
                             const char *owner_ip, const char *owner_domain);
/* Kural eklendigi anda: alan adini kendimiz cozumle + IP/DNS DROP kur. */
void site_block_fw_prime(const char *owner_ip, const char *domain);
void site_block_fw_unblock_domain(const char *owner_ip, const char *owner_domain);
void site_block_fw_clear(void);
int  site_block_fw_active(void);

/* ---- Test kancasi: gercek ag yerine sink'e yonlendir ---- */
#include "raw_inject.h"
void site_block_set_test_sink(RawInjectSink fn, void *ud);
void site_block_set_test_iface_ok(int ok);   /* ham soket yokmus gibi davran */

#endif /* SITE_BLOCK_H */
