/*
 * raw_inject.h — Keyfi Ethernet/IPv4/UDP/TCP kare enjeksiyonu.
 *
 * Site karartma motoru (site_block.c) DNS sinkhole yanitini ve TCP RST
 * paketlerini bu arayuz uzerinden aga birakir. AF_PACKET ham soketi kullanilir.
 *
 * Checksum'lar (IPv4 basligi + TCP/UDP pseudo-header) otomatik hesaplanir.
 */
#ifndef RAW_INJECT_H
#define RAW_INJECT_H

#include <stddef.h>

#define RI_IFACE_LEN 64

/* Test kancasi: frame'i gercekten aga birakmak yerine bu fonksiyona verir.
 * NULL degilse aga HIC bir sey gonderilmez (yalitilmis test icin). */
typedef int (*RawInjectSink)(void *ud, const unsigned char *frame, int len);

typedef struct {
    int           ok;                 /* 1 = AF_PACKET/Ethernet yolu kullanima hazir */
    int           inited;             /* 1 = yapi init edildi (yerel yol icin yeterli) */
    int           fd;                 /* AF_PACKET soketi (Linux), -1 = kapali */
    int           fd_inet;            /* AF_INET SOCK_RAW (yerel teslim icin), -1 = kapali */
    int           ifindex;
    char          iface[RI_IFACE_LEN];
    unsigned char own_mac[6];         /* kendi arayuz MAC'imiz */
    RawInjectSink sink;               /* NULL = gercek gonderim */
    void         *sink_ud;
} RawInject;

/* Ham soketi ac. Basariliysa 0, aksi halde -1. */
int  raw_inject_init(RawInject *ri, const char *iface);

/* Gonderimi test kancasina yonlendir (sink_ud ile birlikte). NULL = gercek. */
void raw_inject_set_sink(RawInject *ri, RawInjectSink fn, void *sink_ud);
void raw_inject_close(RawInject *ri);

/* Hazir bir Ethernet karesini gonder. 0 = basarili, -1 = hata. */
int  raw_inject_send(RawInject *ri, const unsigned char *frame, int len);

/* ---- Yuksek seviye yardimcilar (Ethernet cercevesini de kurar) ---- */

int  raw_inject_udp(RawInject *ri,
                    const unsigned char dst_mac[6],
                    const unsigned char src_mac[6],
                    const char *src_ip, const char *dst_ip,
                    unsigned short sport, unsigned short dport,
                    const unsigned char *payload, int payload_len);

int  raw_inject_tcp(RawInject *ri,
                    const unsigned char dst_mac[6],
                    const unsigned char src_mac[6],
                    const char *src_ip, const char *dst_ip,
                    unsigned short sport, unsigned short dport,
                    unsigned int seq, unsigned int ack, unsigned char flags,
                    const unsigned char *payload, int payload_len);

/* Herhangi bir IP protokolu (or. ICMP=1) icin Ethernet cercevesi kur+gonder. */
int  raw_inject_ip(RawInject *ri,
                   const unsigned char dst_mac[6],
                   const unsigned char src_mac[6],
                   const char *src_ip, const char *dst_ip,
                   unsigned char proto,
                   const unsigned char *payload, int payload_len);

/* YEREL (loopback'e teslim) enjeksiyon: Ethernet cercevesi YOK.
 * AF_INET SOCK_RAW + IP_HDRINCL ile IP datagramini gonderir. Hedef IP yerel
 * makinenin kendi adresi oldugunda cekirdek paketi loopback'e teslim eder;
 * boylece BEAT-System'in calistigi makinenin KENDI trafigi karartilabilir
 * (managed-mode tek-makine senaryosu: DNS sinkhole / TCP RST). */
int  raw_inject_send_ip(RawInject *ri,
                        const char *src_ip, const char *dst_ip,
                        unsigned char proto,
                        const unsigned char *payload, int payload_len);

/* ---- Dusuk seviye kurucular (birim test icin acik) ---- */

/* RFC1071 internet checksum */
unsigned short ri_checksum16(const void *data, int len);

/* out'a IPv4 basligi + payload yaz. Donen: yazilan toplam bayt, -1 = hata. */
int  ri_build_ipv4(unsigned char *out, int out_size,
                   const char *src_ip, const char *dst_ip,
                   unsigned char proto, const unsigned char *payload, int payload_len);

/* out'a UDP basligi + payload yaz (L4 checksum hesaplanir). */
int  ri_build_udp(unsigned char *out, int out_size,
                  const char *src_ip, const char *dst_ip,
                  unsigned short sport, unsigned short dport,
                  const unsigned char *payload, int payload_len);

/* out'a TCP basligi + payload yaz (L4 checksum hesaplanir). */
int  ri_build_tcp(unsigned char *out, int out_size,
                  const char *src_ip, const char *dst_ip,
                  unsigned short sport, unsigned short dport,
                  unsigned int seq, unsigned int ack, unsigned char flags,
                  const unsigned char *payload, int payload_len);

#endif /* RAW_INJECT_H */
