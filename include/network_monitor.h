/*
 * full_monitor.h — Full Packet Capture Engine (Wireshark-style)
 */
#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include "platform.h"
#include "arp_scanner.h"

#define MAX_RAW_SIZE    512
#define MAX_LAYERS      10

/* ===== Site Karartma (per-IP per-site bloklama) için yapısal alanlar =====
 * Uygulama katmanında görülen alan adı (domain) bu alanlarda YAPISAL olarak
 * taşınır; böylece hem GUI listeleri hem de site_block motoru tek bir
 * kaynaktan beslenir. (Eskiden yalnızca info string'ine gömülüyordu.) */
#define MAX_DOMAIN_LEN  160   /* normalize edilmiş alan adı (küçük harf) */
#define DNS_MSG_MAX     320   /* ham DNS başlığı + soru bölümü (sinkhole yanıtı) */

/* Alan adının hangi protokol katmanından çıkarıldığı */
enum {
    DOMAIN_KIND_NONE = 0,
    DOMAIN_KIND_DNS  = 1,   /* DNS sorgu adı (udp/53, tcp/53) */
    DOMAIN_KIND_SNI  = 2,   /* TLS ClientHello SNI (tcp/443, tcp/8443) */
    DOMAIN_KIND_HTTP = 3,   /* HTTP Host başlığı (tcp/80, tcp/8080) */
    DOMAIN_KIND_QUIC = 4    /* QUIC Initial içindeki TLS SNI (udp/443) */
};



typedef enum {
    LAYER_ETHERNET, LAYER_ARP, LAYER_IPV4, LAYER_IPV6,
    LAYER_TCP, LAYER_UDP, LAYER_ICMP,
    LAYER_DNS, LAYER_HTTP, LAYER_TLS, LAYER_DHCP,
    LAYER_MDNS, LAYER_LLMNR, LAYER_NETBIOS, LAYER_SSDP,
    LAYER_NTP, LAYER_SNMP, LAYER_SYSLOG, LAYER_TFTP,
    LAYER_STUN, LAYER_MYSQL, LAYER_POSTGRES, LAYER_REDIS,
    LAYER_MONGODB, LAYER_SSH, LAYER_FTP, LAYER_SMTP,
    LAYER_POP3, LAYER_IMAP, LAYER_RDP, LAYER_VNC,
    LAYER_DATA, LAYER_UNKNOWN
} PduLayerType;

typedef struct {
    PduLayerType type;
    char name[32];
    char summary[256];
    int offset;
    int length;
    char fields[1024];
} PduLayer;

typedef struct {
    double timestamp;
    int packet_number;
    char src_ip[MAX_IP_LEN];
    char dst_ip[MAX_IP_LEN];
    char src_mac[MAX_MAC_LEN];
    char dst_mac[MAX_MAC_LEN];
    char src_port[8];
    char dst_port[8];
    char protocol[32];
    char flags[32];
    char info[512];
    int length;
    int ttl;
    PduLayer layers[MAX_LAYERS];
    int layer_count;
    unsigned char raw_data[MAX_RAW_SIZE];
    int raw_len;

    /* ---- Yapısal uygulama katmanı alan adı (site_block) ---- */
    char          app_domain[MAX_DOMAIN_LEN]; /* küçük harf, son nokta kırpılmış */
    unsigned char domain_kind;                /* DOMAIN_KIND_* */

    /* ---- TCP başlık alanları (RST enjeksiyonu için) ---- */
    unsigned int  tcp_seq;
    unsigned int  tcp_ack;
    unsigned char tcp_flags;                  /* SYN/ACK/RST/... bit maskesi */

    /* ---- Ham DNS mesajı: başlık + soru bölümü (sinkhole yanıtı üretimi) ---- */
    unsigned char dns_msg[DNS_MSG_MAX];
    int           dns_msg_len;
} PacketRecord;

typedef struct {
    int total;
    int tcp;
    int udp;
    int icmp;
    int arp;
    int dns;
    int http;
    int tls;
    int dhcp;
    int mdns;
} FullStats;

void full_monitor_init(void);
void full_monitor_cleanup(void);
void full_monitor_start(const char *iface);
void full_monitor_stop(void);
int  full_monitor_get_mode(void);  /* 0=kapalı, 1=procfs fallback, 2=pcap */
void full_monitor_clear(void);
int  full_monitor_get_packets(PacketRecord *out, int max_count, int offset);
int  full_monitor_get_filtered(PacketRecord *out, int max_count, const char *filter_proto);
/* Delta cekme: cursor'dan sonra gelen yeni paketleri dondurur (kronolojik).
 * Ring tasarsa en yeni max_count paket doldurulur. cursor giris/cikis olarak
 * kullanilir (son gorulen paket numarasi). */
int  full_monitor_get_new_packets(int *cursor, PacketRecord *out, int max_count);
/* Ring'deki mevcut paket sayisi (kilitli okuma) */
int  full_monitor_packet_count(void);
/* Ring nesli: full_monitor_clear sonrasi degisir; GUI tam yenileme karari verir */
unsigned full_monitor_generation(void);
void full_monitor_get_stats(FullStats *s);

/* Yardımcı */
const char *svc_name(int port);
const char *ip_proto_name(int proto);

/* ===== ARP Spoof (MITM trafik yakalama) ===== */
void arp_spoof_start(const char *target_ip, const char *gateway_ip, const char *iface);
void arp_spoof_stop(void);
int  arp_spoof_is_running(void);
const char *arp_spoof_get_target(void);

/* Çoklu hedef (tüm ağ) ARP spoof — MITM ile tüm ağı dinle */
void arp_spoof_start_all(const char *gateway_ip, const char *iface);
void arp_spoof_sync_targets(const Device *devices, int count,
                            const char *gateway_ip, const char *local_ip);
int  arp_spoof_get_target_count(void);
void enable_ip_forward(void);
void disable_ip_forward(void);

/* Tam MITM (full mesh): tek hedef izlerken hedefin tum LAN partnerleriyle
 * trafigini de ele gecir (hedef <-> partner 2 yonlu ARP zehirleme) */
void arp_spoof_sync_partners(const Device *devices, int count,
                             const char *target_ip, const char *local_ip,
                             const char *gateway_ip);
void arp_spoof_set_full_mitm(int enabled);
int  arp_spoof_get_full_mitm(void);
int  arp_spoof_get_partner_count(void);
int  arp_spoof_ip_forward_status(void);
int  arp_spoof_ipv6_forward_status(void);

/* IPv6 (NDP) spoof desteği */
void enable_ipv6_forward(void);
void disable_ipv6_forward(void);

/* ===== Tek kare dissect (yalıtılmış birim testi için) ===== */
int  full_monitor_dissect_frame(int datalink_type, const unsigned char *data,
                                int caplen, PacketRecord *out);

/* ===== PCAP disk kaydı ===== */
int  full_monitor_pcap_record_start(const char *path);
void full_monitor_pcap_record_stop(void);
int  full_monitor_pcap_record_is_active(void);
void full_monitor_pcap_record_path(char *out, int max_len);
unsigned long long full_monitor_pcap_record_bytes(void);

/* ===== SPAN / mirror tespiti ===== */
int  full_monitor_get_foreign_frame_count(void);
int  full_monitor_mirror_suspected(void);
/* Yakalama arayuzunun kendi MAC'i ("aa:bb:cc:dd:ee:ff"), bilinmiyorsa bos */
int  full_monitor_own_mac(char *out, int max_len);

/* ===== Cihaz aktivite takibi ===== */
int  full_monitor_device_active(const char *ip, const char *mac, double window_sec);
/* Son 12 aktivite dilimini virgülle ayrılmış olarak döndürür: "ip|mac|proto,ip|mac|proto,..." */
int  full_monitor_activity_slots(char *out, int max_len);

/* ===== ARP spoof watchdog / son görülme ===== */
double arp_spoof_target_last_seen(const char *ip);

#endif /* NETWORK_MONITOR_H */



