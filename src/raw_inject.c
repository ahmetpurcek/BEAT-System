/*
 * raw_inject.c — Keyfi Ethernet/IPv4/UDP/TCP kare enjeksiyonu.
 * Linux: AF_PACKET SOCK_RAW. Digerleri: libpcap pcap_inject.
 */
#include "raw_inject.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <pcap.h>

#if defined(__linux__)
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#endif

/* ==================================================================
 *   Checksum yardimcilari
 * ================================================================== */

unsigned short ri_checksum16(const void *data, int len) {
    const unsigned char *p = (const unsigned char *)data;
    unsigned long sum = 0;
    while (len > 1) {
        sum += ((unsigned)p[0] << 8) | (unsigned)p[1];
        p += 2;
        len -= 2;
    }
    if (len > 0) sum += ((unsigned)p[0] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short)(~sum & 0xFFFF);
}

/* TCP/UDP icin pseudo-header + L4 checksum */
static unsigned short l4_checksum(const char *src_ip, const char *dst_ip,
                                  unsigned char proto,
                                  const unsigned char *l4, int l4_len) {
    if (12 + l4_len > 4096) return 0;
    unsigned char buf[12 + 4096];
    struct in_addr s, d;
    if (inet_pton(AF_INET, src_ip, &s) != 1) return 0;
    if (inet_pton(AF_INET, dst_ip, &d) != 1) return 0;
    memcpy(buf, &s, 4);
    memcpy(buf + 4, &d, 4);
    buf[8] = 0;
    buf[9] = proto;
    buf[10] = (l4_len >> 8) & 0xFF;
    buf[11] = l4_len & 0xFF;
    memcpy(buf + 12, l4, l4_len);
    unsigned short c = ri_checksum16(buf, 12 + l4_len);
    return c ? c : 0xFFFF;   /* 0 -> 0xFFFF (UDP'de 0 "checksum yok" demektir) */
}

/* ==================================================================
 *   Dusuk seviye kurucular
 * ================================================================== */

int ri_build_ipv4(unsigned char *out, int out_size,
                  const char *src_ip, const char *dst_ip,
                  unsigned char proto, const unsigned char *payload, int payload_len) {
    if (!out || out_size < 20 + payload_len) return -1;
    struct in_addr s, d;
    if (inet_pton(AF_INET, src_ip, &s) != 1) return -1;
    if (inet_pton(AF_INET, dst_ip, &d) != 1) return -1;

    memset(out, 0, 20);
    out[0] = 0x45;                                   /* IPv4, IHL=5 */
    out[1] = 0x00;                                   /* DSCP/ECN */
    int total = 20 + payload_len;
    out[2] = (total >> 8) & 0xFF;
    out[3] = total & 0xFF;
    out[4] = 0x00; out[5] = 0x00;                    /* identification */
    out[6] = 0x40; out[7] = 0x00;                    /* DF, no fragment */
    out[8] = 64;                                     /* TTL */
    out[9] = proto;
    memcpy(out + 12, &s, 4);
    memcpy(out + 16, &d, 4);
    unsigned short c = ri_checksum16(out, 20);
    out[10] = (c >> 8) & 0xFF;
    out[11] = c & 0xFF;
    if (payload && payload_len > 0) memcpy(out + 20, payload, payload_len);
    return total;
}

int ri_build_udp(unsigned char *out, int out_size,
                 const char *src_ip, const char *dst_ip,
                 unsigned short sport, unsigned short dport,
                 const unsigned char *payload, int payload_len) {
    if (!out || out_size < 8 + payload_len) return -1;
    int l4 = 8 + payload_len;
    out[0] = (sport >> 8) & 0xFF; out[1] = sport & 0xFF;
    out[2] = (dport >> 8) & 0xFF; out[3] = dport & 0xFF;
    out[4] = (l4 >> 8) & 0xFF;    out[5] = l4 & 0xFF;
    out[6] = 0x00; out[7] = 0x00;                    /* checksum (sonra) */
    if (payload && payload_len > 0) memcpy(out + 8, payload, payload_len);
    unsigned short c = l4_checksum(src_ip, dst_ip, 17, out, l4);
    out[6] = (c >> 8) & 0xFF;
    out[7] = c & 0xFF;
    return l4;
}

int ri_build_tcp(unsigned char *out, int out_size,
                 const char *src_ip, const char *dst_ip,
                 unsigned short sport, unsigned short dport,
                 unsigned int seq, unsigned int ack, unsigned char flags,
                 const unsigned char *payload, int payload_len) {
    if (!out || out_size < 20 + payload_len) return -1;
    int l4 = 20 + payload_len;
    memset(out, 0, 20);
    out[0] = (sport >> 8) & 0xFF; out[1] = sport & 0xFF;
    out[2] = (dport >> 8) & 0xFF; out[3] = dport & 0xFF;
    out[4] = (seq >> 24) & 0xFF; out[5] = (seq >> 16) & 0xFF;
    out[6] = (seq >> 8) & 0xFF;  out[7] = seq & 0xFF;
    out[8] = (ack >> 24) & 0xFF; out[9] = (ack >> 16) & 0xFF;
    out[10] = (ack >> 8) & 0xFF; out[11] = ack & 0xFF;
    out[12] = 0x50;                                  /* data offset = 5 (20B), reserved 0 */
    out[13] = flags & 0x3F;                          /* FIN..SYN */
    out[14] = 0xFF; out[15] = 0xFF;                  /* window */
    out[16] = 0x00; out[17] = 0x00;                  /* checksum (sonra) */
    out[18] = 0x00; out[19] = 0x00;                  /* urgent ptr */
    if (payload && payload_len > 0) memcpy(out + 20, payload, payload_len);
    unsigned short c = l4_checksum(src_ip, dst_ip, 6, out, l4);
    out[16] = (c >> 8) & 0xFF;
    out[17] = c & 0xFF;
    return l4;
}

/* ==================================================================
 *   Cerceve kurma + gonderim
 * ================================================================== */

static int send_l4(RawInject *ri,
                   const unsigned char dst_mac[6], const unsigned char src_mac[6],
                   const char *src_ip, const char *dst_ip, unsigned char proto,
                   const unsigned char *l4, int l4_len) {
    unsigned char frame[14 + 20 + 4096];
    if (l4_len < 0 || 14 + 20 + l4_len > (int)sizeof(frame)) return -1;
    memcpy(frame, dst_mac, 6);
    memcpy(frame + 6, src_mac, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;                                /* IPv4 ethertype */
    int n = ri_build_ipv4(frame + 14, (int)sizeof(frame) - 14,
                          src_ip, dst_ip, proto, l4, l4_len);
    if (n < 0) return -1;
    return raw_inject_send(ri, frame, 14 + n);
}

int raw_inject_udp(RawInject *ri,
                   const unsigned char dst_mac[6], const unsigned char src_mac[6],
                   const char *src_ip, const char *dst_ip,
                   unsigned short sport, unsigned short dport,
                   const unsigned char *payload, int payload_len) {
    unsigned char l4[4096];
    int n = ri_build_udp(l4, (int)sizeof(l4), src_ip, dst_ip, sport, dport, payload, payload_len);
    if (n < 0) return -1;
    return send_l4(ri, dst_mac, src_mac, src_ip, dst_ip, 17, l4, n);
}

int raw_inject_tcp(RawInject *ri,
                   const unsigned char dst_mac[6], const unsigned char src_mac[6],
                   const char *src_ip, const char *dst_ip,
                   unsigned short sport, unsigned short dport,
                   unsigned int seq, unsigned int ack, unsigned char flags,
                   const unsigned char *payload, int payload_len) {
    unsigned char l4[4096];
    int n = ri_build_tcp(l4, (int)sizeof(l4), src_ip, dst_ip, sport, dport,
                         seq, ack, flags, payload, payload_len);
    if (n < 0) return -1;
    return send_l4(ri, dst_mac, src_mac, src_ip, dst_ip, 6, l4, n);
}

int raw_inject_ip(RawInject *ri,
                  const unsigned char dst_mac[6], const unsigned char src_mac[6],
                  const char *src_ip, const char *dst_ip,
                  unsigned char proto,
                  const unsigned char *payload, int payload_len) {
    return send_l4(ri, dst_mac, src_mac, src_ip, dst_ip, proto, payload, payload_len);
}

void raw_inject_set_sink(RawInject *ri, RawInjectSink fn, void *sink_ud) {
    if (!ri) return;
    ri->sink = fn;
    ri->sink_ud = sink_ud;
}

/* ==================================================================
 *   Soket yonetimi
 * ================================================================== */

#if defined(__linux__)

int raw_inject_init(RawInject *ri, const char *iface) {
    if (!ri) return -1;
    memset(ri, 0, sizeof(*ri));
    ri->fd = -1;
    ri->fd_inet = -1;
    ri->inited = 1;   /* yerel (AF_INET) teslim yolu iface olmasa da kullanilabilir */
    if (!iface || !iface[0] || strcmp(iface, "any") == 0) return -1;
    strncpy(ri->iface, iface, RI_IFACE_LEN - 1);

    unsigned idx = if_nametoindex(iface);
    if (idx == 0) return -1;
    ri->ifindex = (int)idx;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
        memcpy(ri->own_mac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = (int)idx;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        /* bind basarisiz olsa da sendto ile calisir; devam. */
    }

    ri->fd = fd;
    ri->ok = 1;
    return 0;
}

void raw_inject_close(RawInject *ri) {
    if (!ri) return;
    if (ri->fd >= 0) {
        close(ri->fd);
        ri->fd = -1;
    }
    if (ri->fd_inet >= 0) {
        close(ri->fd_inet);
        ri->fd_inet = -1;
    }
    ri->ok = 0;
}

/* YEREL enjeksiyon: AF_INET SOCK_RAW + IP_HDRINCL. Hedef IP yerel oldugunda
 * cekirdek datagrami loopback'e teslim eder -> kendi makinemizin trafigi
 * (DNS sinkhole / TCP RST) gercekten karartilabilir. */
int raw_inject_send_ip(RawInject *ri, const char *src_ip, const char *dst_ip,
                       unsigned char proto,
                       const unsigned char *payload, int payload_len) {
    if (!ri || !src_ip || !dst_ip || !payload || payload_len <= 0) return -1;

    if (ri->sink) {
        /* Yalitilmis test: sifir MAC'li cerceve olarak sink'e ver */
        unsigned char frame[14 + 20 + 4096];
        if (20 + payload_len > (int)sizeof(frame) - 14) return -1;
        memset(frame, 0, 12);
        frame[12] = 0x08; frame[13] = 0x00;
        int n = ri_build_ipv4(frame + 14, (int)sizeof(frame) - 14,
                              src_ip, dst_ip, proto, payload, payload_len);
        if (n < 0) return -1;
        return ri->sink(ri->sink_ud, frame, 14 + n);
    }

    if (!ri->inited) return -1;
    if (ri->fd_inet < 0) {
        int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (fd < 0) return -1;
        int on = 1;
        if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0) {
            close(fd);
            return -1;
        }
        ri->fd_inet = fd;
    }

    unsigned char buf[20 + 4096];
    int n = ri_build_ipv4(buf, (int)sizeof(buf), src_ip, dst_ip, proto,
                          payload, payload_len);
    if (n < 0) return -1;

    struct sockaddr_in din;
    memset(&din, 0, sizeof(din));
    din.sin_family = AF_INET;
    if (inet_pton(AF_INET, dst_ip, &din.sin_addr) != 1) return -1;

    ssize_t r = sendto(ri->fd_inet, buf, (size_t)n, 0,
                       (struct sockaddr *)&din, sizeof(din));
    return (r == (ssize_t)n) ? 0 : -1;
}

int raw_inject_send(RawInject *ri, const unsigned char *frame, int len) {
    if (!ri || !frame || len <= 0) return -1;
    if (ri->sink) return ri->sink(ri->sink_ud, frame, len);   /* yalitilmis test */
    if (!ri->ok || ri->fd < 0) return -1;
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ri->ifindex;
    sll.sll_halen = 6;
    memcpy(sll.sll_addr, frame, 6);
    ssize_t r = sendto(ri->fd, frame, (size_t)len, 0, (struct sockaddr *)&sll, sizeof(sll));
    return (r == (ssize_t)len) ? 0 : -1;
}

#else /* !__linux__ : libpcap tabanli fallback */

int raw_inject_init(RawInject *ri, const char *iface) {
    if (!ri) return -1;
    memset(ri, 0, sizeof(*ri));
    ri->fd = -1;
    ri->fd_inet = -1;
    if (!iface || !iface[0]) return -1;
    strncpy(ri->iface, iface, RI_IFACE_LEN - 1);
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *h = pcap_open_live(iface, 65536, 0, 10, errbuf);
    if (!h) return -1;
    ri->pcap = h;
    ri->ok = 1;
    return 0;
}

void raw_inject_close(RawInject *ri) {
    if (!ri) return;
    if (ri->pcap) {
        pcap_close((pcap_t *)ri->pcap);
        ri->pcap = NULL;
    }
    ri->ok = 0;
}

int raw_inject_send(RawInject *ri, const unsigned char *frame, int len) {
    if (!ri || !frame || len <= 0) return -1;
    if (ri->sink) return ri->sink(ri->sink_ud, frame, len);   /* yalitilmis test */
    if (!ri->ok || !ri->pcap) return -1;
    return (pcap_inject((pcap_t *)ri->pcap, frame, (size_t)len) == len) ? 0 : -1;
}

/* Linux disi platformlarda yerel loopback enjeksiyonu desteklenmez. */
int raw_inject_send_ip(RawInject *ri, const char *src_ip, const char *dst_ip,
                       unsigned char proto,
                       const unsigned char *payload, int payload_len) {
    (void)ri; (void)src_ip; (void)dst_ip; (void)proto;
    (void)payload; (void)payload_len;
    return -1;
}

#endif
