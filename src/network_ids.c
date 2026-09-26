/*
 * network_ids.c — Kural Tabanlı Ağ Saldırı Tespit Sistemi (IDS).
 * full_monitor paketlerini parse eder; eşik tabanlı kurallarla saldırı
 * tespiti yapar. Durum statik dizilerde (malloc yok) tutulur ve tek
 * mutex ile thread-safe çalışır.
 */

#include "network_ids.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ==================================================================
 *   PAKET PARSE — raw_data üzerinden bağımsız minimal parser
 *   (dissector'a bağımlılık yok, hızlı ve güvenilir)
 * ================================================================== */

typedef struct {
    int      is_ipv4;
    int      is_arp;
    int      is_icmp;
    int      is_tcp;
    int      is_udp;
    int      is_dns;
    int      is_broadcast;
    int      is_multicast;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  tcp_flags;
    int      arp_opcode;
    uint8_t  arp_sender_mac[6];
    uint32_t arp_sender_ip;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint32_t arp_target_ip;   /* ARP hedef IP (cerceve byte 38-41) */
    const uint8_t *payload;   /* TCP/UDP L4 yuku (raw_data icinde) */
    int      payload_len;

    /* SOC v3: DNS/metadata ayristirma */
    int      dns_is_response;   /* DNS QR bayragi (yanit mi) */
    uint16_t dns_qdcount;       /* soru sayisi */
    char     dns_qname[256];    /* ilk sorunun adi */
    int      dns_qname_len;     /* qname'in tukettigi bayt */
    uint32_t mdns_ans_ip;       /* mDNS yaniti A-kaydi IP'si */
    char     nbns_name[64];     /* NetBIOS adi (NBNS sorgusu) */
    int      dhcp_op;           /* 1=REQUEST 2=REPLY */
    uint32_t dhcp_yiaddr;       /* kiralanan IP */
    uint8_t  dhcp_chaddr[6];    /* istemci MAC */
    char     dhcp_hostname[64]; /* istemci adi (opsiyon 12) */
} IdsPktInfo;

static int ids_dns_name(const uint8_t *d, int dlen, int off, char *out, int outlen);
static void ids_decode_nbns(const uint8_t *in, int inlen, char *out, int outlen);

static void ids_parse_pkt(const PacketRecord *pkt, IdsPktInfo *pi) {
    memset(pi, 0, sizeof(*pi));

    const uint8_t *r = pkt->raw_data;
    int len = pkt->raw_len;
    if (len < 14) return;

    /* Ethernet */
    memcpy(pi->dst_mac, r, 6);
    memcpy(pi->src_mac, r + 6, 6);
    uint16_t etype = (r[12] << 8) | r[13];

    int all_ff = 1;
    for (int i = 0; i < 6; i++) if (r[i] != 0xFF) { all_ff = 0; break; }
    pi->is_broadcast = all_ff;
    pi->is_multicast = (r[0] & 1) && !all_ff;

    if (etype == 0x0806) {
        /* ARP */
        pi->is_arp = 1;
        if (len < 42) return;
        pi->arp_opcode = (r[20] << 8) | r[21];
        memcpy(pi->arp_sender_mac, r + 22, 6);
        pi->arp_sender_ip = (uint32_t)r[28] << 24 | (uint32_t)r[29] << 16 |
                            (uint32_t)r[30] << 8 | r[31];
        pi->arp_target_ip = (uint32_t)r[38] << 24 | (uint32_t)r[39] << 16 |
                            (uint32_t)r[40] << 8 | r[41];
        return;
    }

    if (etype != 0x0800) return; /* IPv6 ve diğerleri şimdilik atlanır */
    pi->is_ipv4 = 1;
    if (len < 34) return;

    int ihl = (r[14] & 0x0F) * 4;
    if (ihl < 20 || 14 + ihl + 4 > len) return;

    pi->src_ip = (uint32_t)r[26] << 24 | (uint32_t)r[27] << 16 |
                 (uint32_t)r[28] << 8 | r[29];
    pi->dst_ip = (uint32_t)r[30] << 24 | (uint32_t)r[31] << 16 |
                 (uint32_t)r[32] << 8 | r[33];

    uint8_t proto = r[23];
    const uint8_t *l4 = r + 14 + ihl;
    int l4len = len - (14 + ihl);

    if (proto == 6 && l4len >= 20) {
        pi->is_tcp = 1;
        pi->src_port = (l4[0] << 8) | l4[1];
        pi->dst_port = (l4[2] << 8) | l4[3];
        pi->tcp_flags = l4[13] & 0x3F;
        int doff = (l4[12] >> 4) * 4;
        if (doff >= 20 && l4len > doff) {
            pi->payload = l4 + doff;
            pi->payload_len = l4len - doff;
        }
    } else if (proto == 17 && l4len >= 8) {
        pi->is_udp = 1;
        pi->src_port = (l4[0] << 8) | l4[1];
        pi->dst_port = (l4[2] << 8) | l4[3];
        const uint8_t *pay = l4 + 8;
        int paylen = l4len - 8;

        /* DNS (53): 12 baytlık başlık — QR bayrağı + soru sayısı + ilk ad */
        if (pi->dst_port == 53 && paylen >= 12) {
            pi->dns_qdcount = (uint16_t)((pay[4] << 8) | pay[5]);
            pi->dns_is_response = (pay[2] & 0x80) != 0;
            pi->is_dns = (pi->dns_qdcount > 0);
            int q = ids_dns_name(pay, paylen, 12, pi->dns_qname,
                                 (int)sizeof(pi->dns_qname));
            if (q > 0) pi->dns_qname_len = q;
        }
        /* mDNS (5353): yanıt A-kaydı — soruları atla, C0 işaretçili yanıtı çöz */
        if (pi->dst_port == 5353 && paylen >= 12) {
            pi->dns_qdcount = (uint16_t)((pay[4] << 8) | pay[5]);
            pi->dns_is_response = (pay[2] & 0x80) != 0;
            pi->is_dns = (pi->dns_qdcount > 0);
            int off = 12;
            for (int q = 0; q < pi->dns_qdcount && off < paylen; q++) {
                int n = ids_dns_name(pay, paylen, off,
                                     q == 0 ? pi->dns_qname : NULL,
                                     q == 0 ? (int)sizeof(pi->dns_qname) : 0);
                if (n < 0) { off = paylen; break; }
                off += n + 4;   /* soru: isim + QTYPE + QCLASS */
            }
            if (off + 12 <= paylen && pay[off] == 0xC0) {
                uint16_t rtype = (uint16_t)((pay[off + 2] << 8) | pay[off + 3]);
                uint16_t rdlen = (uint16_t)((pay[off + 10] << 8) | pay[off + 11]);
                if (rtype == 1 && rdlen == 4 && off + 16 <= paylen) {
                    pi->mdns_ans_ip = ((uint32_t)pay[off + 12] << 24) |
                                      ((uint32_t)pay[off + 13] << 16) |
                                      ((uint32_t)pay[off + 14] << 8) | pay[off + 15];
                }
            }
        }
        /* DHCP (67/68): sihirli cookie 0x63825363, opsiyon 12 = hostname */
        if ((pi->dst_port == 67 || pi->dst_port == 68) && paylen >= 240) {
            if (pay[236] == 0x63 && pay[237] == 0x82 &&
                pay[238] == 0x53 && pay[239] == 0x63) {
                pi->dhcp_op = pay[0];
                pi->dhcp_yiaddr = ((uint32_t)pay[16] << 24) |
                                  ((uint32_t)pay[17] << 16) |
                                  ((uint32_t)pay[18] << 8) | pay[19];
                memcpy(pi->dhcp_chaddr, pay + 28, 6);
                int o = 240;
                while (o + 1 < paylen) {
                    uint8_t opt = pay[o];
                    if (opt == 255) break;
                    if (opt == 0) { o++; continue; }
                    uint8_t ol = pay[o + 1];
                    if (o + 2 + ol > paylen) break;
                    if (opt == 12 && ol > 0 && ol < (int)sizeof(pi->dhcp_hostname)) {
                        memcpy(pi->dhcp_hostname, pay + o + 2, ol);
                        pi->dhcp_hostname[ol] = '\0';
                    }
                    o += 2 + ol;
                }
            }
        }
        /* NBNS (137): ad sorgusu (0x20), 32 bayt kodlanmış ad @pay[13] */
        if (pi->dst_port == 137 && paylen >= 45) {
            if (pay[12] == 0x20) {
                ids_decode_nbns(pay + 13, 32, pi->nbns_name,
                                (int)sizeof(pi->nbns_name));
            }
        }
        if (paylen > 0) {
            pi->payload = pay;
            pi->payload_len = paylen;
        }
    } else if (proto == 1 && l4len >= 4) {
        pi->is_icmp = 1;
    }
}

static void ids_ip_to_str(uint32_t ip, char *buf, int len) {
    snprintf(buf, len, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
}

/* DNS isim cozucu: label uzunlugu + dize. C0 isaretcisi -1 dondurur;
 * NULL out ile yalnizca tuketilen bayt sayisi hesaplanir. */
static int ids_dns_name(const uint8_t *d, int dlen, int off, char *out, int outlen) {
    int o = off, w = 0;
    while (o < dlen) {
        uint8_t l = d[o];
        if (l == 0) { o++; break; }
        if (l & 0xC0) return -1;              /* sikistirma isaretcisi */
        o++;
        if (o + l > dlen) return -1;
        for (int i = 0; i < l; i++) {
            if (out && w + 1 < outlen) out[w++] = (char)d[o + i];
        }
        o += l;
        if (o < dlen && d[o] != 0) {
            if (out && w + 1 < outlen) out[w++] = '.';
        }
    }
    if (out && w < outlen) out[w] = '\0';
    return o - off;
}

/* NetBIOS 'A' kodlu ad cozucu: her karakter 2 bayt (nibble+'A').
 * Cozulen bosluk (dolgu) adi keser. */
static void ids_decode_nbns(const uint8_t *in, int inlen, char *out, int outlen) {
    int w = 0;
    for (int i = 0; i + 1 < inlen && w + 1 < outlen; i += 2) {
        char c = (char)(((in[i] - 'A') & 0x0F) << 4) |
                 (char)((in[i + 1] - 'A') & 0x0F);
        if (c == ' ') break;
        out[w++] = c;
    }
    out[w] = '\0';
}

/* ==================================================================
 *   IDS STATE
 * ================================================================== */

IdsAgent g_ids;

static platform_mutex_t g_ids_lock;
static int g_ids_initialized = 0;

/* MAC/IP bağlamı (ARP zehirlenmesi + self-origin bastırma için) */
static uint8_t g_local_mac[6];
static uint8_t g_gateway_mac[6];
static int     g_gateway_mac_valid = 0;
static uint32_t g_gateway_ip = 0;
static uint32_t g_local_ip = 0;

/* ==================================================================
 *   SELF-ORIGINATION SUPPRESSION
 *   Kendi ürettiğimiz trafik (otomatik ARP/ping taraması, fallback
 *   sentetik çerçeveler) uyarı gürültüsü yaratmasın; yabancı MAC'ten
 *   gelen çerçeveler bastırılmaz (spoof'lu IP saldırgan olabilir).
 * ================================================================== */

static int ids_mac_zero(const uint8_t mac[6]) {
    for (int i = 0; i < 6; i++)
        if (mac[i] != 0) return 0;
    return 1;
}

static int ids_is_self_originated(const IdsPktInfo *pi) {
    if (!ids_mac_zero(pi->src_mac)) {
        /* pcap modu: gercek cerceve — kendi NIC MAC'imiz mi? */
        if (memcmp(pi->src_mac, g_local_mac, 6) == 0) return 1;
        /* Yabanci MAC: bastirma yok (ARP poisoning/spoof tespiti korunur) */
        return 0;
    }
    /* Fallback modu: sentetik cerceve (MAC yok) — IP eslesmesine bak */
    if (g_local_ip && pi->src_ip == g_local_ip) return 1;
    return 0;
}

/* Alert ring buffer (kronolojik, en yeni sonda) */
static IdsGuiAlert g_alert_buf[IDS_MAX_ALERTS];
static int g_alert_count = 0;

/* ==================================================================
 *   TRACKER — eşik analizi için akış sayaçları
 * ================================================================== */

typedef struct {
    char     key[96];
    uint32_t count;
    uint32_t unique[64];       /* farklı hedef/port hash'leri */
    int      unique_len;
    /* --- Port alanı için tam farklı-değer sayımı ---
     * unique[64] rapor için ilk 64 örneği tutar; 64'ten fazla farklı port
     * gören tarama doymasın diye sayım 65536 bitlik bitmap'e geçer (Snort
     * sfPortscan / Suricata yöntemi). Bitmap tembel ayrılır; 2-3 porta
     * dokunan normal akış hiç bellek harcamaz. */
    uint8_t *unique_bits;       /* 8192 bayt = 65536 bit (port alani) */
    uint32_t unique_bits_count; /* isaretli bit sayisi = farkli port sayisi */
    int      unique_bits_failed;/* 1 = calloc basarisiz, eski davranisa dus */
    /* --- UZUN UFUK (yavaş / hız sınırlamalı tarama) ---
     * Yukarıdaki count/unique_* KISA pencereyi (IDS_WINDOW_SEC, tumbling)
     * izler ve patlama halindeki taramayı yakalar. Yavaş tarama hiçbir kısa
     * pencereye eşiği dolduracak port bırakmadığı için ayrıca, aktivite
     * boşluğu ile kapanan bir UZUN UFUK izlenir. long_short_hit: kısa
     * pencere aynı ufukta tetiklendiyse uzun ufuk susar (çift rapor yok). */
    uint32_t long_count;
    uint32_t long_unique[64];
    int      long_unique_len;
    uint8_t *long_bits;         /* 65536 bit: port alani icin tam sayim */
    uint32_t long_bits_count;
    int      long_bits_failed;
    int      long_short_hit;
    time_t   long_start;
    time_t   long_last;
    time_t   long_last_alert;
    /* ---  Yatay tarama: özel (RFC1918) / genel hedef ayrımı --- */
    uint32_t private_dst_count;
    uint32_t public_dst_count;
    time_t   window_start;
    time_t   last_alert;
    int      active;
} IdsTracker;

static IdsTracker g_trackers[IDS_MAX_TRACKERS];
static int g_tracker_count = 0;

static uint32_t ids_hash_unique(uint32_t a, uint32_t b) {
    return a ^ (b * 2654435761u);
}

/* Port alani (0..65535) bitmap'i: 65536 bit = 8192 bayt. */
#define IDS_UNIQUE_BITS_BYTES 8192u

/* ===== UZUN UFUK AYARLARI ==============================
 * Varsayılanlar header sabitleridir; kalibrasyon kancası bunları değiştirir,
 * motor hiçbir yerde sabiti doğrudan kullanmaz (test gerçek davranışı ölçer). */
static int g_scan_idle_gap   = IDS_SCAN_IDLE_GAP_SEC;
static int g_scan_window_max = IDS_SCAN_LONG_WINDOW_SEC;
static int g_scan_min_span   = IDS_SCAN_MIN_SPAN_SEC;
static int g_scan_long_thr   = IDS_SCAN_LONG_UNIQUE;

void ids_set_scan_window_params(int idle_gap_sec, int max_window_sec,
                                int min_span_sec, int long_unique_thr) {
    platform_mutex_lock(&g_ids_lock);
    if (idle_gap_sec    > 0) g_scan_idle_gap   = idle_gap_sec;
    if (max_window_sec  > 0) g_scan_window_max = max_window_sec;
    if (min_span_sec    > 0) g_scan_min_span   = min_span_sec;
    if (long_unique_thr > 0) g_scan_long_thr   = long_unique_thr;
    platform_mutex_unlock(&g_ids_lock);
}

void ids_get_scan_window_params(int *idle_gap_sec, int *max_window_sec,
                                int *min_span_sec, int *long_unique_thr) {
    if (idle_gap_sec)    *idle_gap_sec    = g_scan_idle_gap;
    if (max_window_sec)  *max_window_sec  = g_scan_window_max;
    if (min_span_sec)    *min_span_sec    = g_scan_min_span;
    if (long_unique_thr) *long_unique_thr = g_scan_long_thr;
}

/* Tracker'i sifirlar; bitmap varsa once SERBEST birakir (yoksa geri
 * donusturulen her tracker bellek sizintisi olurdu). */
static void ids_tracker_clear(IdsTracker *t) {
    if (t->unique_bits) { free(t->unique_bits); t->unique_bits = NULL; }
    /* uzun ufuk bitmap'i de serbest birakilir (yoksa
     * geri donusturulen her tracker bellek sizintisi olurdu). */
    if (t->long_bits) { free(t->long_bits); t->long_bits = NULL; }
    memset(t, 0, sizeof(*t));
}

static IdsTracker *ids_tracker_get(const char *key) {
    for (int i = 0; i < g_tracker_count; i++) {
        if (g_trackers[i].active && strcmp(g_trackers[i].key, key) == 0)
            return &g_trackers[i];
    }
    if (g_tracker_count >= IDS_MAX_TRACKERS) {
        /* Kap dolu: once pasif kayit, yoksa en eski kayit geri donusturulur */
        IdsTracker *victim = NULL;
        for (int i = 0; i < g_tracker_count; i++) {
            if (!g_trackers[i].active) { victim = &g_trackers[i]; break; }
        }
        if (!victim) {
            victim = &g_trackers[0];
            for (int i = 1; i < g_tracker_count; i++)
                if (g_trackers[i].window_start < victim->window_start)
                    victim = &g_trackers[i];
        }
        ids_tracker_clear(victim);   /* bitmap'i de birakir */
        strncpy(victim->key, key, sizeof(victim->key) - 1);
        victim->active = 1;
        victim->window_start = time(NULL);
        return victim;
    }
    IdsTracker *t = &g_trackers[g_tracker_count++];
    ids_tracker_clear(t);
    strncpy(t->key, key, sizeof(t->key) - 1);
    t->active = 1;
    t->window_start = time(NULL);
    return t;
}

/* Yalnızca arama: yoksa kayıt OLUŞTURMAZ (yan etkisiz).
 * MalPort motorunun tarama istemcisi tespitinde kullanılır. */
static IdsTracker *ids_tracker_peek(const char *key) {
    for (int i = 0; i < g_tracker_count; i++) {
        if (g_trackers[i].active && strcmp(g_trackers[i].key, key) == 0)
            return &g_trackers[i];
    }
    return NULL;
}

static void ids_tracker_reset_if_expired(IdsTracker *t) {
    time_t now = time(NULL);
    if (now - t->window_start > IDS_WINDOW_SEC) {
        t->count = 0;
        t->unique_len = 0;
        /* Pencere kapandi: port bitmap'i de sifirlanir,
         * yoksa onceki pencerenin portlari yeni pencerede sayili kalir. */
        if (t->unique_bits) {
            memset(t->unique_bits, 0, IDS_UNIQUE_BITS_BYTES);
            t->unique_bits_count = 0;
        }
        t->private_dst_count = 0;
        t->public_dst_count = 0;
        t->window_start = now;
    }
}

static void ids_tracker_bump(IdsTracker *t, uint32_t unique_val) {
    ids_tracker_reset_if_expired(t);
    t->count++;
    if (unique_val != 0 && t->unique_len < 64) {
        int found = 0;
        for (int i = 0; i < t->unique_len; i++) {
            if (t->unique[i] == unique_val) { found = 1; break; }
        }
        if (!found) t->unique[t->unique_len++] = unique_val;
    }
}

/* Ornek dizisinden bitmap'e gecis. Yalnizca 65. farkli
 * port goruldugunde cagrilir; mevcut 64 ornek de bitmap'e islenir ki
 * sayac ilk andan itibaren TAM olsun. */
static int ids_tracker_bits_alloc(IdsTracker *t) {
    if (t->unique_bits) return 1;
    if (t->unique_bits_failed) return 0;
    t->unique_bits = (uint8_t *)calloc(1, IDS_UNIQUE_BITS_BYTES);
    if (!t->unique_bits) { t->unique_bits_failed = 1; return 0; }
    for (int i = 0; i < t->unique_len; i++) {
        uint32_t v = t->unique[i];
        if (v >= 65536u) continue;
        uint8_t bit = (uint8_t)(1u << (v & 7u));
        if (!(t->unique_bits[v >> 3] & bit)) {
            t->unique_bits[v >> 3] |= bit;
            t->unique_bits_count++;
        }
    }
    return 1;
}

static void ids_tracker_bits_add(IdsTracker *t, uint32_t v) {
    if (v >= 65536u) return;
    uint8_t bit = (uint8_t)(1u << (v & 7u));
    if (!(t->unique_bits[v >> 3] & bit)) {
        t->unique_bits[v >> 3] |= bit;
        t->unique_bits_count++;
    }
}

/* Port alanli kurallar bunu kullanir: farkli port sayisi 64'u asinca
 * sayac doyuma ugrar DEGIL, TAM saymaya devam eder. */
static void ids_tracker_bump_port(IdsTracker *t, uint32_t port) {
    ids_tracker_reset_if_expired(t);
    t->count++;
    if (port == 0) return;
    if (t->unique_bits) { ids_tracker_bits_add(t, port); return; }
    if (t->unique_len < 64) {
        for (int i = 0; i < t->unique_len; i++)
            if (t->unique[i] == port) return;
        t->unique[t->unique_len++] = port;
        return;
    }
    if (ids_tracker_bits_alloc(t)) ids_tracker_bits_add(t, port);
}

/* Kural esikleri ve uyari metni icin 'kac FARKLI port goruldu' degeri. */
static uint32_t ids_tracker_unique(const IdsTracker *t) {
    return t->unique_bits ? t->unique_bits_count : (uint32_t)t->unique_len;
}

/* ---- Uzun ufuk (yavaş tarama) yardımcıları ------------
 * Ufuk “aktivite boşluğu” (idle gap) veya azami ömür dolunca kapanıp
 * sıfırdan başlar (Zeek flow timeout / Snort sfPortscan mantığı): kapanış
 * paket sayısına değil ZAMANA bağlıdır. */
static void ids_tracker_long_reset(IdsTracker *t, time_t now) {
    t->long_count = 0;
    t->long_unique_len = 0;
    if (t->long_bits) {
        memset(t->long_bits, 0, IDS_UNIQUE_BITS_BYTES);
        t->long_bits_count = 0;
    }
    t->long_short_hit = 0;
    t->long_start = now;
    t->long_last  = now;
}

static void ids_tracker_long_tick(IdsTracker *t) {
    time_t now = time(NULL);
    if (t->long_start == 0 || t->long_last == 0) {
        t->long_start = now;
        t->long_last  = now;
        return;
    }
    if (now - t->long_last > g_scan_idle_gap ||
        now - t->long_start >= g_scan_window_max) {
        ids_tracker_long_reset(t, now);
    }
}

/* 65. farkli degerde ornek dizisinden bitmap'e gecis (kisa penceredeki
 * mantigin aynisi): farkli-port sayaci 64'te DOYUMA UGRAMAZ. */
static int ids_tracker_long_bits_alloc(IdsTracker *t) {
    if (t->long_bits) return 1;
    if (t->long_bits_failed) return 0;
    t->long_bits = (uint8_t *)calloc(1, IDS_UNIQUE_BITS_BYTES);
    if (!t->long_bits) { t->long_bits_failed = 1; return 0; }
    for (int i = 0; i < t->long_unique_len; i++) {
        uint32_t v = t->long_unique[i];
        if (v >= 65536u) continue;
        uint8_t bit = (uint8_t)(1u << (v & 7u));
        if (!(t->long_bits[v >> 3] & bit)) {
            t->long_bits[v >> 3] |= bit;
            t->long_bits_count++;
        }
    }
    return 1;
}

static void ids_tracker_long_bits_add(IdsTracker *t, uint32_t v) {
    if (v >= 65536u) return;
    uint8_t bit = (uint8_t)(1u << (v & 7u));
    if (!(t->long_bits[v >> 3] & bit)) {
        t->long_bits[v >> 3] |= bit;
        t->long_bits_count++;
    }
}

static void ids_tracker_long_bump(IdsTracker *t, uint32_t v) {
    time_t now = time(NULL);
    ids_tracker_long_tick(t);
    t->long_count++;
    t->long_last = now;
    if (v == 0) return;
    /* IP hedefli kurallarda (ping sweep / ARP taramasi / yatay tarama)
     * deger 65536'nin uzerindedir; 65536 bitlik bitmap yalnizca PORT alani
     * icindir. Bu kurallarin esikleri <= 24 oldugundan 64 ornek yeterlidir. */
    if (v >= 65536u) {
        if (t->long_unique_len < 64) {
            for (int i = 0; i < t->long_unique_len; i++)
                if (t->long_unique[i] == v) return;
            t->long_unique[t->long_unique_len++] = v;
        }
        return;
    }
    if (t->long_bits) { ids_tracker_long_bits_add(t, v); return; }
    if (t->long_unique_len < 64) {
        for (int i = 0; i < t->long_unique_len; i++)
            if (t->long_unique[i] == v) return;
        t->long_unique[t->long_unique_len++] = v;
        return;
    }
    if (ids_tracker_long_bits_alloc(t)) ids_tracker_long_bits_add(t, v);
}

static uint32_t ids_tracker_long_unique(const IdsTracker *t) {
    return t->long_bits ? t->long_bits_count : (uint32_t)t->long_unique_len;
}

/* Uzun ufuk tarama kapisi — uc kosul BIRLIKTE saglanmali:
 *  1) bu ufukta kisa pencere kurali hic tetiklenmedi (cift rapor yok),
 *  2) yeterince FARKLI deger goruldu (g_scan_long_thr),
 *  3) gozlem suresi min_span'i gecti (tarama gercekten “yavas”). */
static int ids_tracker_long_scan(const IdsTracker *t) {
    if (t->long_short_hit) return 0;
    if (ids_tracker_long_unique(t) < (uint32_t)g_scan_long_thr) return 0;
    if (t->long_last - t->long_start < (time_t)g_scan_min_span) return 0;
    return 1;
}

static int ids_tracker_can_alert(IdsTracker *t) {
    time_t now = time(NULL);
    if (now - t->last_alert < IDS_ALERT_COOLDOWN) return 0;
    t->last_alert = now;
    return 1;
}

/* ==================================================================
 *   ALERT ÜRETİMİ
 * ================================================================== */

#define SCORE_KRITIK 0.95
#define SCORE_YUKSEK 0.75
#define SCORE_ORTA   0.50
#define SCORE_DUSUK  0.25

/* SOC v3: olay korelasyonu (ids_raise_alert icinden cagrilir) */
static void ids_incident_update(uint32_t att, uint32_t vic, const char *sig,
                                const char *sev, double score);

/* LAN katmanı öne bildirimleri (uygulamaları ids_raise_alert'ten
 * sonraki bölümde) — uyarı üretimi host skorlarını besler. */
static uint32_t ids_sev_points(const char *sev);
static uint32_t ids_sig_flags(const char *sig);
static void ids_host_credit(uint32_t ip, uint32_t points, uint32_t flag);
static void ids_host_victim(uint32_t ip, uint32_t points, uint32_t flag);

/* --- Global uyarı bastırma (dedup) ---
 * Aynı (imza, saldırgan, kurban) üçlüsü IDS_DEDUP_TTL (120 sn) içinde
 * tekrar gelirse bastırılır (tekrarlı akışlar uyarı yağmuruna dönüşmesin).
 * ARP'de src_ip 0 kaldığı için saldırgan/kurban ham çerçevenin
 * sender/target IP'lerinden alınır. */
#define IDS_DEDUP_MAX 256
#define IDS_DEDUP_TTL 120

typedef struct {
    char     key[96];
    time_t   ts;
    int      active;
} IdsDedupEntry;

static IdsDedupEntry g_dedup[IDS_DEDUP_MAX];
static int g_dedup_count = 0;

/* 1 döner: yayınla; 0 döner: bastır (suppressed_fps++). */
static int ids_dedup_check(const char *sig, uint32_t att, uint32_t vic) {
    if (!sig) return 1;
    time_t now = time(NULL);
    char key[96];
    snprintf(key, sizeof(key), "%s|%u|%u", sig, att, vic);
    for (int i = 0; i < g_dedup_count; i++) {
        if (!g_dedup[i].active) continue;
        if (now - g_dedup[i].ts > IDS_DEDUP_TTL) {
            g_dedup[i].active = 0;
            continue;
        }
        if (strcmp(g_dedup[i].key, key) == 0) {
            g_ids.suppressed_fps++;
            return 0;
        }
    }
    if (g_dedup_count < IDS_DEDUP_MAX) {
        IdsDedupEntry *d = &g_dedup[g_dedup_count++];
        d->active = 1;
        d->ts = now;
        strncpy(d->key, key, sizeof(d->key) - 1);
    } else {
        /* Kap dolu: en eski kaydı geri dönüştür */
        IdsDedupEntry *old = &g_dedup[0];
        for (int i = 1; i < IDS_DEDUP_MAX; i++)
            if (g_dedup[i].ts < old->ts) old = &g_dedup[i];
        old->active = 1;
        old->ts = now;
        strncpy(old->key, key, sizeof(old->key) - 1);
    }
    return 1;
}

/* ---  Kanıt bitlerinden risk skoru (0-100) --- */
static uint8_t ids_calc_confidence(uint8_t ev, const char *sev) {
    uint8_t c = 0;
    if (ev & IDS_EV_THRESHOLD_MET)  c += 30;
    if (ev & IDS_EV_HANDSHAKE_SEEN) c += 20;
    if (ev & IDS_EV_REPEATED)       c += 15;
    if (ev & IDS_EV_MULTI_PORT)     c += 10;
    if (ev & IDS_EV_PAYLOAD_MATCH)  c += 15;
    if (ev & IDS_EV_EXTERNAL_SRC)   c += 10;
    if (ev & IDS_EV_KNOWN_BAD_PORT) c += 20;
    if (c > 100) c = 100;
    /* KRITIK şiddeti en az 50 güven ister: ciddi uyarı asla "emin değilim"
     * etiketiyle sulandırılmasın. */
    if (sev && strcmp(sev, "KRITIK") == 0 && c < 50) c = 50;
    return c;
}

/* Şiddeti bir kademe düşür (düşük güven uyarısı için) */
static const char *ids_sev_downgrade(const char *sev) {
    if (!sev) return sev;
    if (strcmp(sev, "KRITIK") == 0) return "YUKSEK";
    if (strcmp(sev, "YUKSEK") == 0) return "ORTA";
    if (strcmp(sev, "ORTA") == 0)   return "DUSUK";
    return sev;
}

/* Uyarı üretim çekirdeği. ev_bits==0 veren çağrılar (eski API türevleri)
 * güven 100 kabul edilir ve şiddet düşürülmez; yeni kural blokları kanıt
 * bitlerini vererek güven mekanizmasını aktifleştirir. */
static int ids_raise_alert_ev(const char *sig, const char *sev, double score,
                              const IdsPktInfo *pi, const char *desc,
                              uint8_t ev_bits) {
    if (!g_ids.running) return -1;
    platform_mutex_lock(&g_ids_lock);

    /* LAN katmanı saldırgan/kurban: ARP'de src/dst IP alanları 0 kalır,
     * ham çerçevedeki sender/target IP'leri kullanılır. */
    uint32_t att = pi->src_ip, vic = pi->dst_ip;
    if (pi->is_arp) {
        att = pi->arp_sender_ip;
        vic = pi->arp_target_ip;
    }

    /* Aynı uyarının kısa sürede tekrarı bastırılır */
    if (!ids_dedup_check(sig, att, vic)) {
        platform_mutex_unlock(&g_ids_lock);
        return -1;
    }

    /* Risk skoru + düşük kanıtta şiddet indirimi */
    uint8_t conf = (ev_bits == 0) ? 100 : ids_calc_confidence(ev_bits, sev);
    char fp_reason[64];
    fp_reason[0] = '\0';
    const char *out_sev = sev;
    if (ev_bits != 0 && conf < 40) {
        out_sev = ids_sev_downgrade(sev);
        snprintf(fp_reason, sizeof(fp_reason),
                 "yetersiz kanit (guven %u/100)", (unsigned)conf);
    }

    IdsGuiAlert *a;
    if (g_alert_count >= IDS_MAX_ALERTS) {
        /* En eskiyi düşür (sondan kopyala) */
        memmove(&g_alert_buf[0], &g_alert_buf[1],
                sizeof(IdsGuiAlert) * (IDS_MAX_ALERTS - 1));
        g_alert_count = IDS_MAX_ALERTS - 1;
        a = &g_alert_buf[g_alert_count];
    } else {
        a = &g_alert_buf[g_alert_count++];
    }

    memset(a, 0, sizeof(*a));
    strncpy(a->sig_name, sig, sizeof(a->sig_name) - 1);
    ids_ip_to_str(pi->src_ip, a->src_ip, sizeof(a->src_ip));
    ids_ip_to_str(pi->dst_ip, a->dst_ip, sizeof(a->dst_ip));
    a->src_port = pi->src_port;
    a->dst_port = pi->dst_port;
    a->score = score;
    strncpy(a->severity, out_sev, sizeof(a->severity) - 1);
    strncpy(a->description, desc, sizeof(a->description) - 1);
    a->confidence = conf;
    a->evidence_bits = ev_bits;
    strncpy(a->fp_reason, fp_reason,
            sizeof(a->fp_reason) - 1);
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    if (tm) {
        strftime(a->timestamp, sizeof(a->timestamp), "%H:%M:%S", tm);
    } else {
        strncpy(a->timestamp, "--:--:--", sizeof(a->timestamp) - 1);
    }

    g_ids.total_alerts++;

    /* LAN katmanı: uyarı kaynak/hedef host skorlarına işlenir (indirilmiş
     * şiddetle). */
    {
        uint32_t pts = ids_sev_points(out_sev);
        uint32_t fl  = ids_sig_flags(sig);
        ids_host_credit(att, pts, fl);
        ids_host_victim(vic, pts, fl);
        ids_incident_update(att, vic, sig, out_sev, score);
    }

    platform_mutex_unlock(&g_ids_lock);
    return g_alert_count - 1;
}

/* Eski API: kanıt biti vermeden çağıran tüm mevcut kurallar için uyumluluk
 * sarmalayıcısı — davranış tamamen korunur (güven 100, düşürme yok). */
static int ids_raise_alert(const char *sig, const char *sev, double score,
                            const IdsPktInfo *pi, const char *desc) {
    return ids_raise_alert_ev(sig, sev, score, pi, desc, 0);
}

/* --- UYARI BİRLEŞTİRME (alert consolidation) ---
 * Kural eşiği aşınca uyarı yayınlanır; IDS_ALERT_COOLDOWN (60 sn) içinde
 * aynı olay yeniden yayınlanmaz. Cooldown içinde gelen daha büyük kanıt
 * MEVCUT kayda işlenir (Suricata threshold+aggregation mantığı); yoksa
 * metin ilk tetiklenme anındaki küçük değerde donar kalırdı. */
/* Uyari kaydinin kimligini belirleyen kaynak/hedef IP: ARP'de ham
 * cercevedeki sender/target IP'leri (pi->src_ip/dst_ip ARP'de 0 kalir). */
static void ids_alert_endpoints(const IdsPktInfo *pi, uint32_t *att,
                                uint32_t *vic) {
    *att = pi->src_ip;
    *vic = pi->dst_ip;
    if (pi->is_arp) {
        *att = pi->arp_sender_ip;
        *vic = pi->arp_target_ip;
    }
}

/* Bastirma (dedup) kaydini serbest birakir. Yalnizca "uyari yayinlanamadi
 * VE listede guncellenecek satir yok" durumunda cagrilir. */
static void ids_dedup_release(const char *sig, uint32_t att, uint32_t vic) {
    if (!sig) return;
    char key[96];
    snprintf(key, sizeof(key), "%s|%u|%u", sig, att, vic);
    platform_mutex_lock(&g_ids_lock);
    for (int i = 0; i < g_dedup_count; i++) {
        if (!g_dedup[i].active) continue;
        if (strcmp(g_dedup[i].key, key) == 0) {
            g_dedup[i].active = 0;
            break;
        }
    }
    platform_mutex_unlock(&g_ids_lock);
}

/* 1 doner: mevcut uyari satiri guncellendi; 0 doner: eslesen satir yok. */
static int ids_aggregate_alert(const char *sig, const IdsPktInfo *pi,
                               const char *desc, uint8_t ev_bits, uint8_t conf) {
    if (!sig || !desc) return 0;
    uint32_t att, vic;
    ids_alert_endpoints(pi, &att, &vic);
    char satt[46], svic[46];
    ids_ip_to_str(att, satt, sizeof(satt));
    ids_ip_to_str(vic, svic, sizeof(svic));
    /* Satirlar ids_raise_alert_ev() icinde pi->src_ip/pi->dst_ip ile
     * doldurulur; ARP'de bu iki alan 0.0.0.0 kalir ve ikinci gecis farkli
     * ARP saldirganlarini karistirirdi -> ARP icin tek gecis. */
    int two_pass = !pi->is_arp;
    int found = 0;

    platform_mutex_lock(&g_ids_lock);
    for (int pass = 0; pass < (two_pass ? 2 : 1) && !found; pass++) {
        for (int i = g_alert_count - 1; i >= 0; i--) {
            IdsGuiAlert *a = &g_alert_buf[i];
            if (strcmp(a->sig_name, sig) != 0) continue;
            if (strcmp(a->src_ip, satt) != 0) continue;
            /* pass 0: ayni kaynak + AYNI hedef; pass 1: ayni kaynak, hedef
             * DEGISTI. Eski kod yalnizca pass 0'a bakiyordu; tarama/brute
             * force'da hedef surekli degistigi icin dedup da bastirmaya devam
             * edip ne satir guncelleniyor ne yeni satir yayinlaniyordu. */
            if (pass == 0 && strcmp(a->dst_ip, svic) != 0) continue;
            strncpy(a->description, desc, sizeof(a->description) - 1);
            a->description[sizeof(a->description) - 1] = '\0';
            if (pass == 1) {
                strncpy(a->dst_ip, svic, sizeof(a->dst_ip) - 1);
                a->dst_ip[sizeof(a->dst_ip) - 1] = '\0';
                a->dst_port = pi->dst_port;
                a->src_port = pi->src_port;
            }
            if (conf > a->confidence) a->confidence = conf;
            a->evidence_bits |= ev_bits;
            if (a->confidence >= 40 && strstr(a->fp_reason, "yetersiz kanit"))
                a->fp_reason[0] = '\0';
            found = 1;
            break;
        }
    }
    platform_mutex_unlock(&g_ids_lock);
    return found;
}

/* Esik asildi: ilk tetiklenmede yeni uyari yayinla; cooldown/dedup icinde
 * ise mevcut uyariyi guncelle. Uyari SAYISI sismez, metin guncel kalir. */
static void ids_raise_or_update(const char *sig, const char *sev, double score,
                                const IdsPktInfo *pi, const char *desc,
                                uint8_t ev_bits, IdsTracker *t) {
    uint8_t conf = (ev_bits == 0) ? 100 : ids_calc_confidence(ev_bits, sev);
    int published = -1;

    /* Kuralin kendi soguma (cooldown) penceresi dolduysa yeni satir yayinla
     * (ids_tracker_can_alert bu cagrida sogumayi silahlandirir). */
    if (t && ids_tracker_can_alert(t))
        published = ids_raise_alert_ev(sig, sev, score, pi, desc, ev_bits);
    if (published >= 0) return;

    /* Yayinlanamadi. Once olayin MEVCUT satirini guncellemeyi dene. */
    if (ids_aggregate_alert(sig, pi, desc, ev_bits, conf)) return;

    /* Ne yayin ne guncellenecek satir var: dedup bastiriyor ama kayit
     * listede yok (liste temizlenmis / en eski kayit dusmus). Olay hala
     * surerken bastirma serbest birakilir ve olay yeniden yayinlanir. */
    uint32_t att, vic;
    ids_alert_endpoints(pi, &att, &vic);
    ids_dedup_release(sig, att, vic);
    if (ids_raise_alert_ev(sig, sev, score, pi, desc, ev_bits) >= 0) return;
    /* Son care: motor durdurulmus olabilir (g_ids.running == 0). */
    ids_aggregate_alert(sig, pi, desc, ev_bits, conf);
}

/* Uzun ufuk uyarisi. ids_raise_or_update()'in uc adimli mantigini kullanir
 * ama AYRI bir soguma alani (long_last_alert) tutar: kisa pencerenin
 * sogumasi uzun ufkun raporunu geciktirmemeli, tersi de olmamali. */
static void ids_raise_or_update_long(const char *sig, const char *sev,
                                     double score, const IdsPktInfo *pi,
                                     const char *desc, uint8_t ev_bits,
                                     IdsTracker *t) {
    uint8_t conf = (ev_bits == 0) ? 100 : ids_calc_confidence(ev_bits, sev);
    time_t now = time(NULL);
    if (t && now - t->long_last_alert >= IDS_ALERT_COOLDOWN) {
        t->long_last_alert = now;
        if (ids_raise_alert_ev(sig, sev, score, pi, desc, ev_bits) >= 0)
            return;
    }
    /* Yayinlanamadi: olayin MEVCUT satirini guncellemeyi dene. */
    if (ids_aggregate_alert(sig, pi, desc, ev_bits, conf)) return;
    /* Ne yayin ne guncellenecek satir var (liste temizlenmis / dusmus):
     * bastirmayi serbest birakip olayi yeniden yayinla (sessiz kayip yok). */
    uint32_t att, vic;
    ids_alert_endpoints(pi, &att, &vic);
    ids_dedup_release(sig, att, vic);
    if (ids_raise_alert_ev(sig, sev, score, pi, desc, ev_bits) >= 0) return;
    ids_aggregate_alert(sig, pi, desc, ev_bits, conf);
}

/* ==================================================================
 *   LAN KATMANI — ağ geneli akış tablosu + host tehdit skorlaması
 *   Tüm ağ trafiği bu makineden geçtiğinde her cihaz için tehdit skoru
 *   (0-100) hesaplanır; uyarı üretimi ve akış analizi bu skorları besler.
 * ================================================================== */

/* Uyarı önem derecesi -> host skor katkısı */
static uint32_t ids_sev_points(const char *sev) {
    if (!sev) return 2;
    if (strcmp(sev, "KRITIK") == 0) return 40;
    if (strcmp(sev, "YUKSEK") == 0) return 20;
    if (strcmp(sev, "ORTA") == 0)   return 8;
    return 2;
}

/* İmza adı -> host tehdit bayrağı (IDS_F_*) */
static uint32_t ids_sig_flags(const char *sig) {
    if (!sig) return IDS_F_SCAN;
    if (strstr(sig, "Brute")) return IDS_F_BRUTEFORCE;
    if (strstr(sig, "Tarama") || strstr(sig, "Sweep")) return IDS_F_SCAN;
    if (strstr(sig, "Flood") || strstr(sig, "DDoS") ||
        strstr(sig, "Storm"))
        return IDS_F_FLOOD;
    if (strstr(sig, "Meterpreter") || strstr(sig, "Shellcode") ||
        strstr(sig, "Backdoor") || strstr(sig, "BackOrifice") ||
        strstr(sig, "RAT") || strstr(sig, "botnet") ||
        strstr(sig, "SQL") || strstr(sig, "XSS") ||
        strstr(sig, "Enjeksiyon") || strstr(sig, "Erisim") ||
        strstr(sig, "Calistirma") || strstr(sig, "Indirme") ||
        strstr(sig, "PowerShell") || strstr(sig, "Log4Shell") ||
        strstr(sig, "JNDI"))
        return IDS_F_MALWARE;
    if (strstr(sig, "ARP") || strstr(sig, "Cakismasi") ||
        strstr(sig, "Eslesme"))
        return IDS_F_ARPSPOOF;
    if (strstr(sig, "DNS") || strstr(sig, "DGA") || strstr(sig, "Tunel"))
        return IDS_F_DNS;
    return IDS_F_SCAN;
}

/* ---- Akış tablosu (5-tuple) ---- */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;          /* 6=TCP, 17=UDP, 1=ICMP */
    uint64_t pkt_count;
    uint64_t byte_count;
    uint32_t syn_count;      /* ACK'sız SYN (tarama işareti) */
    uint32_t rst_count;
    time_t   first_seen;
    time_t   last_seen;
    int      active;
} IdsFlow;

static IdsFlow g_flows[IDS_MAX_FLOWS];
static int g_flow_count = 0;

/* ---- Host tehdit kaydı (dahili, GUI snapshot'ına kopyalanır) ---- */
typedef struct {
    uint32_t ip;
    uint64_t sent_pkts;
    uint64_t recv_pkts;
    uint32_t flows_as_src;
    uint32_t flows_as_dst;
    uint32_t unique_target_ips;    /* analizde hesaplanır */
    uint32_t unique_target_ports;
    uint32_t attack_score;         /* 0-100 */
    uint32_t victim_score;         /* 0-100 */
    uint32_t flags;                /* IDS_F_* */
    char     hostname[64];         /* DHCP/mDNS/NetBIOS'tan ogrenilen ad */
    uint32_t dns_qcount;           /* gonderilen DNS sorgusu sayisi */
    uint32_t dns_dcount;           /* benzersiz, rastgele gorunumlu alan adi */
    char     dns_domains[40][128]; /* gorulen alan adlari (dedupe) */
    int      dns_pending_alert;    /* DGA uyarisi bekliyor */
    int      dns_pending_tunnel;   /* tunel sezgiseli tuttu */
    int      dns_long_label_count; /* [D5] 60 sn pencerede uzun label sayisi */
    time_t   dns_long_label_window;/* [D5] uzun label penceresi baslangici */
    time_t   last_seen;
    int      active;
} IdsHost;

static IdsHost g_hosts[IDS_MAX_HOSTS];
static int g_host_count = 0;

/* ---- SOC v3: DGA yanlis pozitif filtreleri ----
 * Normal gezinme trafigi (CDN alt alanlari, PTR, mDNS, yerel adlar)
 * DGA sayilmasin; yalnizca rastgele gorunumlu benzersiz kayit-edilebilir
 * alan adlari sayaca girer. */

/* DGA esikleri: agir yol 60 sorgu + 20 benzersiz SLD;
 * hafif yol 60 sn pencerede >= 5 uzun alfanumerik label. 25/10 gibi dusuk
 * esikler normal gezinme trafiginde yanlis pozitif uretiyordu. */
#define DGA_MIN_QCOUNT        60
#define DGA_MIN_DCOUNT        20
#define DGA_LONG_LABEL_MIN    12
#define DGA_LONG_LABEL_WIN    60
#define DGA_LONG_LABEL_MAX    5

/* Bilinen guvenilir eTLD+1 alan adlari (CDN, bulut, olcekli servisler):
 * bu alanlarin sorgulari DGA/tunel sayilmaz; tam karsilastirma yapilir. */
static const char *k_dns_trusted_domains[] = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "googlevideo.com", "ggpht.com", "googleusercontent.com",
    "microsoft.com", "live.com", "msftncsi.com", "windowsupdate.com",
    "windows.com", "office.com", "office365.com", "microsoftonline.com",
    "apple.com", "icloud.com", "mzstatic.com", "aaplimg.com",
    "amazon.com", "amazonaws.com", "cloudfront.net",
    "cloudflare.com", "cloudflare-dns.com", "akamai.net", "akamaiedge.net",
    "edgesuite.net", "edgekey.net", "fastly.net", "azureedge.net",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com", "twimg.com", "linkedin.com",
    "netflix.com", "nflxvideo.net", "spotify.com", "scdn.co",
    "github.com", "githubusercontent.com", "wikipedia.org", "wikimedia.org",
    "yahoo.com", "bing.com", "duckduckgo.com", "mozilla.org",
    "adobe.com", "adobedtm.com", "doubleclick.net", "googlesyndication.com",
    "w3.org", "ietf.org", "isc.org", "ntp.org"
};

static int ids_domain_trusted(const char *reg) {
    for (size_t i = 0;
         i < sizeof(k_dns_trusted_domains) / sizeof(k_dns_trusted_domains[0]);
         i++) {
        if (strcmp(reg, k_dns_trusted_domains[i]) == 0) return 1;
    }
    return 0;
}

static const char *k_dns_noise_sfx[] = {
    ".arpa", ".local", ".lan", ".home", ".internal"
};

/* Yaklasik kayit-edilebilir alan adi (eTLD+1): son 2 label; co.uk /
 * com.tr tarzi ikinci derece ccTLD'lerde son 3 label. */
static void ids_registrable_domain(const char *qname, char *out, int outsz) {
    const char *lb[16];
    int ll[16], ln = 0;
    const char *p = qname;
    while (*p && ln < 16) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        if (l <= 0) break;
        lb[ln] = p; ll[ln] = l; ln++;
        if (!dot) break;
        p = dot + 1;
    }
    if (ln == 0) { out[0] = '\0'; return; }
    int take = (ln >= 2) ? 2 : ln;
    if (ln >= 3) {
        static const char *cc[] = { "uk", "tr", "au", "br", "jp", "cn",
                                    "in", "mx", "za", "kr", "nz", "sg",
                                    "ar", "hk", "il" };
        char l2[8];
        int n = ll[ln - 2] < 7 ? ll[ln - 2] : 7;
        memcpy(l2, lb[ln - 2], (size_t)n); l2[n] = '\0';
        for (size_t i = 0; i < sizeof(cc) / sizeof(cc[0]); i++) {
            if (strcmp(l2, cc[i]) == 0 &&
                (ll[ln - 3] == 2 || ll[ln - 3] == 3)) { take = 3; break; }
        }
    }
    int off = ln - take; if (off < 0) off = 0;
    int total = 0;
    for (int i = off; i < ln; i++) {
        int c = snprintf(out + total, (size_t)(outsz - total),
                         (i == off) ? "%.*s" : ".%.*s", ll[i], lb[i]);
        if (c < 0 || total + c >= outsz) break;
        total += c;
    }
}

/* SLD (marka etiketi) rastgele gorunuyor mu? Rakam iceren veya cok
 * uzun (>=14) SLD'ler DGA adayidir; googleapis / gstatic / pkgbuild
 * gibi gercek markalar degildir. */
static int ids_sld_suspicious(const char *reg) {
    const char *dot = strchr(reg, '.');
    int l = dot ? (int)(dot - reg) : (int)strlen(reg);
    if (dot == NULL || l < 5) return 0;
    int digits = 0, letters = 0;
    for (int i = 0; i < l; i++) {
        char c = reg[i];
        if (c >= '0' && c <= '9') digits++;
        else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) letters++;
        else return 0; /* tire/altcizgi: olculu marka adi */
    }
    if (letters == 0) return 0;
    return digits > 0 || l >= 14;
}


/* ---- SOC v3: korelasyonlu olay kayitlari (saldirgan->kurban cifti) ---- */
#define IDS_MAX_INCIDENTS 32
typedef struct {
    uint32_t attacker;
    uint32_t victim;
    uint32_t alert_count;
    uint32_t flags;
    int      killchain;
    char     worst_severity[16];
    double   max_score;
    char     last_sig[64];
    time_t   first_seen;
    time_t   last_seen;
} IdsIncidentInt;

static IdsIncidentInt g_incidents[IDS_MAX_INCIDENTS];
static int g_incident_count = 0;

/* Kapsam (CIDR) — verilmezse özel ağ aralıkları fallback */
static uint32_t g_net_base = 0;
static uint32_t g_net_mask = 0;
static int g_net_range_set = 0;

static time_t g_last_flow_analysis = 0;

void ids_set_network_range(const char *cidr) {
    if (!cidr || !cidr[0]) {
        g_net_range_set = 0;
        return;
    }
    unsigned int a, b, c, d, pp;
    if (sscanf(cidr, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &pp) == 5 &&
        pp <= 32) {
        g_net_base = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                     ((uint32_t)c << 8) | (uint32_t)d;
        g_net_mask = (pp == 0) ? 0 : (0xFFFFFFFFu << (32 - pp));
        g_net_range_set = 1;
    } else {
        g_net_range_set = 0;
    }
}

/* IP, izlenen ağ kapsamında mı? (CIDR yoksa özel ağ fallback) */
static int ids_ip_in_scope(uint32_t ip) {
    if (g_net_range_set)
        return (ip & g_net_mask) == (g_net_base & g_net_mask);
    uint8_t a = (uint8_t)(ip >> 24);
    if (a == 10) return 1;
    if (a == 172) {
        uint8_t b = (uint8_t)(ip >> 16);
        return (b >= 16 && b <= 31);
    }
    if (a == 192) return (uint8_t)(ip >> 16) == 168;
    if (a == 169) return (uint8_t)(ip >> 16) == 254;
    if (a == 127) return 1;
    return 0;
}

/* ---  RFC1918 + loopback + link-local + CGNAT özel adres mi? --- */
static int ids_ip_is_private(uint32_t ip) {
    uint8_t a = (uint8_t)(ip >> 24);
    uint8_t b = (uint8_t)(ip >> 16);
    if (a == 10) return 1;
    if (a == 172 && b >= 16 && b <= 31) return 1;
    if (a == 192 && b == 168) return 1;
    if (a == 127) return 1;
    if (a == 169 && b == 254) return 1;
    if (a == 100 && b >= 64 && b <= 127) return 1; /* CGNAT 100.64.0.0/10 */
    return 0;
}

static int ids_is_web_port(uint16_t p) {
    return (p == 80 || p == 443 || p == 8080 || p == 8443);
}

static int ids_is_auth_port(uint16_t p) {
    switch (p) {
        case 21: case 22: case 23: case 25: case 445:
        case 1433: case 3306: case 3389: case 5432:
        case 5900: case 6379:
            return 1;
        default:
            return 0;
    }
}

/* --- Port siniflari (brute force yanlis pozitif duzeltmesi) ---
 * Web portlari: tarayicilar bir siteye 6-8 paralel TCP baglantisi acar;
 * dis web hedefine giden trafik 'brute force' sayilmaz. Kimlik dogrulama /
 * uzak erisim portlari (auth) ise brute force hedefidir. */
/* Akış bul / yoksa pasif veya en eski slotu geri dönüştür */
static IdsFlow *ids_flow_get(uint32_t src, uint32_t dst, uint16_t sp,
                              uint16_t dp, uint8_t proto, int *created) {
    *created = 0;
    for (int i = 0; i < IDS_MAX_FLOWS; i++) {
        IdsFlow *f = &g_flows[i];
        if (f->active && f->src_ip == src && f->dst_ip == dst &&
            f->src_port == sp && f->dst_port == dp && f->proto == proto)
            return f;
    }
    IdsFlow *victim = NULL;
    if (g_flow_count < IDS_MAX_FLOWS) {
        victim = &g_flows[g_flow_count++];
    } else {
        for (int i = 0; i < IDS_MAX_FLOWS; i++) {
            if (!g_flows[i].active) { victim = &g_flows[i]; break; }
        }
        if (!victim) {
            victim = &g_flows[0];
            for (int i = 1; i < IDS_MAX_FLOWS; i++)
                if (g_flows[i].last_seen < victim->last_seen)
                    victim = &g_flows[i];
        }
    }
    time_t now = time(NULL);
    memset(victim, 0, sizeof(*victim));
    victim->src_ip = src;
    victim->dst_ip = dst;
    victim->src_port = sp;
    victim->dst_port = dp;
    victim->proto = proto;
    victim->first_seen = now;
    victim->last_seen = now;
    victim->active = 1;
    *created = 1;
    return victim;
}

/* Host bul / yoksa pasif veya en eski slotu geri dönüştür */
static IdsHost *ids_host_get_or_create(uint32_t ip) {
    if (!ip) return NULL;
    for (int i = 0; i < IDS_MAX_HOSTS; i++) {
        IdsHost *h = &g_hosts[i];
        if (h->active && h->ip == ip) {
            h->last_seen = time(NULL);
            return h;
        }
    }
    IdsHost *victim = NULL;
    if (g_host_count < IDS_MAX_HOSTS) {
        victim = &g_hosts[g_host_count++];
    } else {
        for (int i = 0; i < IDS_MAX_HOSTS; i++) {
            if (!g_hosts[i].active) { victim = &g_hosts[i]; break; }
        }
        if (!victim) {
            victim = &g_hosts[0];
            for (int i = 1; i < IDS_MAX_HOSTS; i++)
                if (g_hosts[i].last_seen < victim->last_seen)
                    victim = &g_hosts[i];
        }
    }
    memset(victim, 0, sizeof(*victim));
    victim->ip = ip;
    victim->last_seen = time(NULL);
    victim->active = 1;
    return victim;
}

/* Uyarıdan gelen saldırı/kurban skoru (kapsamdaki hostlara) */
static void ids_host_credit(uint32_t ip, uint32_t points, uint32_t flag) {
    if (!ip || !points || !ids_ip_in_scope(ip)) return;
    IdsHost *h = ids_host_get_or_create(ip);
    if (!h) return;
    h->attack_score += points;
    if (h->attack_score > 100) h->attack_score = 100;
    h->flags |= flag;
}

static void ids_host_victim(uint32_t ip, uint32_t points, uint32_t flag) {
    if (!ip || !points || !ids_ip_in_scope(ip)) return;
    IdsHost *h = ids_host_get_or_create(ip);
    if (!h) return;
    h->victim_score += points;
    if (h->victim_score > 100) h->victim_score = 100;
    h->flags |= flag;
}

/* ---- SOC v3: host adi ogrenme ----
 * DHCP REQUEST (MAC -> bekleyen ad), DHCP ACK (MAC + yiaddr), mDNS A-kaydi
 * ve NBNS sorgulari IP -> ad ogretir; ilk ogrenilen ad kazanir. */
typedef struct {
    uint8_t  mac[6];
    char     name[64];
    time_t   ts;
} IdsNamePending;

static IdsNamePending g_name_pending[64];
static int g_name_pending_count = 0;

static void ids_name_pending_set(const uint8_t mac[6], const char *name) {
    for (int i = 0; i < g_name_pending_count; i++) {
        if (memcmp(g_name_pending[i].mac, mac, 6) == 0) {
            strncpy(g_name_pending[i].name, name,
                    sizeof(g_name_pending[i].name) - 1);
            g_name_pending[i].ts = time(NULL);
            return;
        }
    }
    if (g_name_pending_count < 64) {
        memcpy(g_name_pending[g_name_pending_count].mac, mac, 6);
        strncpy(g_name_pending[g_name_pending_count].name, name,
                sizeof(g_name_pending[g_name_pending_count].name) - 1);
        g_name_pending[g_name_pending_count].ts = time(NULL);
        g_name_pending_count++;
    }
}

static const char *ids_name_pending_get(const uint8_t mac[6]) {
    for (int i = 0; i < g_name_pending_count; i++)
        if (memcmp(g_name_pending[i].mac, mac, 6) == 0)
            return g_name_pending[i].name;
    return NULL;
}

/* MAC/IP -> ad ogret; ilk ogrenilen kazanir */
static void ids_hostname_learn(uint32_t ip, const char *name) {
    if (!ip || !name || !name[0]) return;
    IdsHost *h = ids_host_get_or_create(ip);
    if (!h) return;
    if (!h->hostname[0])
        strncpy(h->hostname, name, sizeof(h->hostname) - 1);
}

/* mDNS yanitindaki A-kaydi IP'sine yanit adini bagla */
static void ids_hostname_from_mdns(const IdsPktInfo *pi) {
    if (!pi->mdns_ans_ip) return;
    if (!pi->dns_qname[0]) return;
    ids_hostname_learn(pi->mdns_ans_ip, pi->dns_qname);
}

/* Her pakette çağrılır: akış sayacını ve host istatistiklerini günceller */
static void ids_flow_update(const IdsPktInfo *pi, const PacketRecord *pkt) {
    if (pi->is_arp) {
        /* ARP: akış yok; yalnızca host görünürlüğü (last_seen) */
        if (pi->arp_sender_ip && ids_ip_in_scope(pi->arp_sender_ip)) {
            IdsHost *h = ids_host_get_or_create(pi->arp_sender_ip);
            if (h) h->last_seen = time(NULL);
        }
        return;
    }
    if (!pi->is_ipv4) return;

    uint8_t proto = pi->is_tcp ? 6 : (pi->is_udp ? 17 : (pi->is_icmp ? 1 : 0));
    if (!proto) return;

    int created = 0;
    IdsFlow *f = ids_flow_get(pi->src_ip, pi->dst_ip, pi->src_port,
                              pi->dst_port, proto, &created);
    if (!f) return;
    f->pkt_count++;
    if (pkt && pkt->length > 0) f->byte_count += (uint32_t)pkt->length;
    if (pi->is_tcp) {
        int is_syn = (pi->tcp_flags & 0x02) && !(pi->tcp_flags & 0x10);
        if (is_syn) f->syn_count++;
        if (pi->tcp_flags & 0x04) f->rst_count++;
    }
    f->last_seen = time(NULL);

    /* Host sayaçları — yalnızca kapsamdaki IP'ler için host açılır */
    if (ids_ip_in_scope(pi->src_ip)) {
        IdsHost *h = ids_host_get_or_create(pi->src_ip);
        if (h) {
            h->sent_pkts++;
            h->last_seen = f->last_seen;
            if (created) h->flows_as_src++;
        }
    }
    if (pi->src_ip != pi->dst_ip && ids_ip_in_scope(pi->dst_ip)) {
        IdsHost *h = ids_host_get_or_create(pi->dst_ip);
        if (h) {
            h->recv_pkts++;
            h->last_seen = f->last_seen;
            if (created) h->flows_as_dst++;
        }
    }

    /* ---- SOC v3: DNS/metadata ogrenme (yalnizca UDP) ---- */
    if (pi->is_udp) {
        IdsHost *sh = ids_ip_in_scope(pi->src_ip)
                          ? ids_host_get_or_create(pi->src_ip) : NULL;

        /* DHCP REQUEST: MAC -> ad bekle; DHCP ACK: MAC -> IP ad ogren */
        if ((pi->dst_port == 67 || pi->dst_port == 68) && pi->dhcp_op == 1 &&
            !ids_mac_zero(pi->dhcp_chaddr) && pi->dhcp_hostname[0]) {
            ids_name_pending_set(pi->dhcp_chaddr, pi->dhcp_hostname);
        }
        if ((pi->dst_port == 67 || pi->dst_port == 68) && pi->dhcp_op == 2 &&
            pi->dhcp_yiaddr && !ids_mac_zero(pi->dhcp_chaddr)) {
            const char *nm = ids_name_pending_get(pi->dhcp_chaddr);
            if (nm) ids_hostname_learn(pi->dhcp_yiaddr, nm);
        }
        /* mDNS yaniti: A-kaydi IP'sine ad bagla */
        if (pi->dst_port == 5353 && pi->dns_is_response && pi->mdns_ans_ip)
            ids_hostname_from_mdns(pi);
        /* NBNS sorgusu: kaynak IP'ye NetBIOS adi bagla */
        if (pi->dst_port == 137 && pi->nbns_name[0] && sh)
            ids_hostname_learn(pi->src_ip, pi->nbns_name);

        /* DNS sorgusu (kapsamdaki kaynak): DGA sayaci + tunel sezgiseli.
         * Gurultu filtresi: PTR (.arpa), mDNS (.local) ve yerel adlar hic
         * sayilmaz; ayni sitenin alt alanlari tek SLD sayilir; sayaca
         * yalnizca rastgele gorunumlu SLD'ler girer. */
        if (pi->dst_port == 53 && !pi->dns_is_response && pi->dns_qdcount > 0 &&
            pi->dns_qname[0] && sh) {
            const char *qn = pi->dns_qname;
            int noise = (strchr(qn, '.') == NULL);
            for (size_t i = 0;
                 i < sizeof(k_dns_noise_sfx) / sizeof(k_dns_noise_sfx[0]);
                 i++) {
                if (strstr(qn, k_dns_noise_sfx[i])) { noise = 1; break; }
            }
            if (!noise) {
                char reg[256];
                time_t now = time(NULL);
                ids_registrable_domain(qn, reg, (int)sizeof(reg));
                sh->dns_qcount++;
                /* Guvenilir saglayici (CDN/bulut): DGA/tunel
                 * sayaci beslenmez; qcount yalnizca istatistik icin artar. */
                if (!ids_domain_trusted(reg)) {
                    int dup = 0;
                    for (int i = 0; i < (int)sh->dns_dcount && i < 40; i++) {
                        if (strcmp(sh->dns_domains[i], reg) == 0) { dup = 1; break; }
                    }
                    if (!dup && sh->dns_dcount < 40 && ids_sld_suspicious(reg)) {
                        strncpy(sh->dns_domains[sh->dns_dcount], reg,
                                sizeof(sh->dns_domains[0]) - 1);
                        sh->dns_dcount++;
                    }

                    /* Tunel + uzun-label sezgiseli: ilk label >= MIN karakter,
                     * hem rakam hem harf, tire yok. Tunel uyarisi tek seferlik;
                     * uzun-label sayaci DGA_LONG_LABEL_WIN suresi boyunca birikir. */
                    const char *p = qn;
                    int l = 0;
                    while (*p && *p != '.') { l++; p++; }
                    int digits = 0, letters = 0, hyph = 0;
                    for (int k = 0; k < l; k++) {
                        char c = qn[k];
                        if (c >= '0' && c <= '9') digits++;
                        else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) letters++;
                        else if (c == '-') hyph++;
                    }
                    if (l >= DGA_LONG_LABEL_MIN && digits > 0 && letters > 0 &&
                        hyph == 0) {
                        if (!sh->dns_pending_tunnel) sh->dns_pending_tunnel = 1;
                        if (sh->dns_long_label_window == 0)
                            sh->dns_long_label_window = now;
                        if (now - sh->dns_long_label_window > DGA_LONG_LABEL_WIN) {
                            sh->dns_long_label_window = now;
                            sh->dns_long_label_count = 0;
                        }
                        sh->dns_long_label_count++;
                    }
                }
            }
        }
    }
}

/* Saniyede bir: zaman aşımı, per-host analiz, skor bozunumu */
static void ids_flow_analysis(void) {
    time_t now = time(NULL);
    if (now - g_last_flow_analysis < 1) return;
    g_last_flow_analysis = now;

    /* Zaman aşımı */
    for (int i = 0; i < IDS_MAX_FLOWS; i++) {
        if (g_flows[i].active && now - g_flows[i].last_seen > IDS_FLOW_TIMEOUT)
            g_flows[i].active = 0;
    }
    for (int i = 0; i < IDS_MAX_HOSTS; i++) {
        if (g_hosts[i].active && now - g_hosts[i].last_seen > IDS_HOST_TIMEOUT)
            g_hosts[i].active = 0;
    }

    for (int hi = 0; hi < IDS_MAX_HOSTS; hi++) {
        IdsHost *h = &g_hosts[hi];
        if (!h->active || !h->ip) continue;

        /* Benzersiz hedef IP / port (kaynak olduğu akışlardan) */
        uint32_t uips[128];
        uint32_t uports[128];
        int un_ips = 0, un_ports = 0;
        for (int fi = 0; fi < IDS_MAX_FLOWS; fi++) {
            IdsFlow *f = &g_flows[fi];
            if (!f->active || f->src_ip != h->ip) continue;
            if (un_ips < 128) {
                int k;
                for (k = 0; k < un_ips; k++) if (uips[k] == f->dst_ip) break;
                if (k == un_ips) uips[un_ips++] = f->dst_ip;
            }
            if (un_ports < 128 && f->dst_port) {
                int k;
                for (k = 0; k < un_ports; k++)
                    if (uports[k] == f->dst_port) break;
                if (k == un_ports) uports[un_ports++] = f->dst_port;
            }
        }
        h->unique_target_ips = (uint32_t)un_ips;
        h->unique_target_ports = (uint32_t)un_ports;

        /* Port taraması: >= 8 farklı hedef port */
        if (un_ports >= 8 && !(h->flags & IDS_F_SCAN)) {
            h->flags |= IDS_F_SCAN;
            h->attack_score += 10;
            if (h->attack_score > 100) h->attack_score = 100;
        }
        /* Ağ taraması: >= 6 farklı hedef IP */
        if (un_ips >= 6 && !(h->flags & IDS_F_SWEEP)) {
            h->flags |= IDS_F_SWEEP;
            h->attack_score += 15;
            if (h->attack_score > 100) h->attack_score = 100;
        }
        /* Flood: 60+ akış hedef olarak */
        if (h->flows_as_dst >= 60 && !(h->flags & IDS_F_FLOOD)) {
            h->flags |= IDS_F_FLOOD;
            h->victim_score += 20;
            if (h->victim_score > 100) h->victim_score = 100;
        }
        /* Brute force: ayni port grubunda >= 6 akis ve >= 4 farkli kaynak port.
         * Web portlarinda (80/443/8080/8443) bu kosul normal tarayici
         * davranisini (6-8 paralel baglanti) saldiri saniyordu; orada TEK
         * kaynagin >= 15 akisi firtina (saldiri) kabul edilir. */
        if (h->flows_as_dst >= 6 && !(h->flags & IDS_F_BRUTEFORCE)) {
            typedef struct {
                uint16_t port;
                uint32_t count;
                uint16_t src_ports[32];
                int spn;
                uint32_t srcs[8];   /* kaynak IP'ler (web fırtına kontrolü) */
                uint16_t srcn[8];   /* kaynak IP başına akış sayısı */
                int src_count;
            } BruteBucket;
            BruteBucket bb[16];
            int bn = 0;
            for (int fi = 0; fi < IDS_MAX_FLOWS; fi++) {
                IdsFlow *f = &g_flows[fi];
                if (!f->active || f->dst_ip != h->ip || !f->dst_port) continue;
                int b = -1;
                for (int j = 0; j < bn; j++)
                    if (bb[j].port == f->dst_port) { b = j; break; }
                if (b < 0 && bn < 16) {
                    b = bn++;
                    bb[b].port = f->dst_port;
                    bb[b].count = 0;
                    bb[b].spn = 0;
                    bb[b].src_count = 0;
                    memset(bb[b].srcs, 0, sizeof(bb[b].srcs));
                    memset(bb[b].srcn, 0, sizeof(bb[b].srcn));
                }
                if (b < 0) continue;
                bb[b].count++;
                if (bb[b].spn < 32) {
                    int k;
                    for (k = 0; k < bb[b].spn; k++)
                        if (bb[b].src_ports[k] == f->src_port) break;
                    if (k == bb[b].spn)
                        bb[b].src_ports[bb[b].spn++] = f->src_port;
                }
                /* kaynak IP başına sayaç (web fırtına tespiti) */
                int si = -1;
                for (int j = 0; j < bb[b].src_count; j++)
                    if (bb[b].srcs[j] == f->src_ip) { si = j; break; }
                if (si < 0 && bb[b].src_count < 8) {
                    si = bb[b].src_count++;
                    bb[b].srcs[si] = f->src_ip;
                    bb[b].srcn[si] = 0;
                }
                if (si >= 0) bb[b].srcn[si]++;
            }
            for (int b = 0; b < bn; b++) {
                int hit = 0;
                if (ids_is_web_port(bb[b].port)) {
                    /* Web: tek kaynaktan >= 15 akış = fırtına (saldırı) */
                    for (int j = 0; j < bb[b].src_count; j++)
                        if (bb[b].srcn[j] >= 15) { hit = 1; break; }
                } else {
                    /* Servis portları: dağıtık brute force koşulu korunur */
                    hit = (bb[b].count >= 6 && bb[b].spn >= 4);
                }
                if (hit) {
                    h->flags |= IDS_F_BRUTEFORCE;
                    h->victim_score += 25;
                    if (h->victim_score > 100) h->victim_score = 100;
                    break;
                }
            }
        }

        /* ---- SOC v3: DNS DGA / tunel analizi (saniyede bir) ---- */
        /* Iki bagimsiz kanit yolu:
         * 1) agir esik: DGA_MIN_QCOUNT sorgu + DGA_MIN_DCOUNT benzersiz SLD
         * 2) hafif esik: DGA_LONG_LABEL_WIN sn pencerede >= DGA_LONG_LABEL_MAX
         *    uzun alfanumerik label (guven dusuk -> sev YUKSEK) */
        {
            int dga_hit = (h->dns_qcount >= DGA_MIN_QCOUNT &&
                           h->dns_dcount >= DGA_MIN_DCOUNT);
            if (!dga_hit && h->dns_long_label_window &&
                now - h->dns_long_label_window <= DGA_LONG_LABEL_WIN &&
                h->dns_long_label_count >= DGA_LONG_LABEL_MAX)
                dga_hit = 1;
            if (dga_hit && !(h->flags & IDS_F_DNS)) {
                h->flags |= IDS_F_DNS;
                h->dns_pending_alert = 1;
                h->attack_score += 10;
                if (h->attack_score > 100) h->attack_score = 100;
            }
        }
        if (h->dns_pending_alert) {
            h->dns_pending_alert = 0;
            IdsPktInfo pi;
            memset(&pi, 0, sizeof(pi));
            pi.src_ip = h->ip;
            pi.is_udp = 1;
            char dgadesc[128];
            const char *dga_sev = "KRITIK";
            uint8_t dga_ev = IDS_EV_REPEATED | IDS_EV_PAYLOAD_MATCH;
            if (!(h->dns_qcount >= DGA_MIN_QCOUNT &&
                  h->dns_dcount >= DGA_MIN_DCOUNT)) {
                dga_sev = "YUKSEK";   /* hafif esik: guven dusuk */
                dga_ev = IDS_EV_REPEATED;
            }
            snprintf(dgadesc, sizeof(dgadesc),
                     "%u sorgu / %u benzersiz alan adi (olasi DGA)",
                     h->dns_qcount, h->dns_dcount);
            ids_raise_alert_ev("DGA Suphesi (C2)", dga_sev, SCORE_KRITIK, &pi,
                               dgadesc, dga_ev);
        }
        if (h->dns_pending_tunnel && !(h->flags & IDS_F_TUNNEL)) {
            h->flags |= IDS_F_TUNNEL;
            h->attack_score += 15;
            if (h->attack_score > 100) h->attack_score = 100;
            IdsPktInfo pi;
            memset(&pi, 0, sizeof(pi));
            pi.src_ip = h->ip;
            pi.is_udp = 1;
            ids_raise_alert("DNS Tuneli (C2)", "KRITIK", SCORE_KRITIK, &pi,
                            "Alfa-sayisal uzun label (olasi DNS tunelleme)");
        }

        /* Skor bozunumu: saniyede 1 puan (saldırı bitince geriler) */
        if (h->attack_score > 0) h->attack_score--;
        if (h->victim_score > 0) h->victim_score--;
    }

    int ac = 0, hc = 0;
    for (int i = 0; i < IDS_MAX_FLOWS; i++)
        if (g_flows[i].active) ac++;
    for (int i = 0; i < IDS_MAX_HOSTS; i++)
        if (g_hosts[i].active && g_hosts[i].ip) hc++;
    g_ids.active_flows = (uint32_t)ac;
    g_ids.host_count = (uint32_t)hc;
}

/* Saldırı skoruna göre azalan sıralama (snapshot için) */
static int ids_host_cmp_desc(const void *a, const void *b) {
    const IdsHostThreat *ha = (const IdsHostThreat *)a;
    const IdsHostThreat *hb = (const IdsHostThreat *)b;
    if (ha->attack_score != hb->attack_score)
        return ha->attack_score > hb->attack_score ? -1 : 1;
    if (ha->victim_score != hb->victim_score)
        return ha->victim_score > hb->victim_score ? -1 : 1;
    return strcmp(ha->ip, hb->ip);
}

int ids_get_host_threat_snapshot(IdsHostThreatSnapshot *out) {
    if (!out) return 0;
    platform_mutex_lock(&g_ids_lock);
    memset(out, 0, sizeof(*out));
    out->window_start = time(NULL);

    int n = 0;
    for (int i = 0; i < IDS_MAX_HOSTS && n < IDS_MAX_HOSTS; i++) {
        IdsHost *h = &g_hosts[i];
        if (!h->active || !h->ip) continue;

        IdsHostThreat *t = &out->hosts[n];
        memset(t, 0, sizeof(*t));
        ids_ip_to_str(h->ip, t->ip, sizeof(t->ip));
        t->ip_raw = h->ip;
        t->is_gateway = (g_gateway_ip && h->ip == g_gateway_ip);
        t->is_local = (g_local_ip && h->ip == g_local_ip);
        t->attack_score = h->attack_score;
        t->victim_score = h->victim_score;
        t->total_sent = h->sent_pkts;
        t->total_recv = h->recv_pkts;
        t->flows_as_src = h->flows_as_src;
        t->flows_as_dst = h->flows_as_dst;
        t->unique_target_ips = h->unique_target_ips;
        t->unique_target_ports = h->unique_target_ports;
        t->flags = h->flags;
        t->last_seen = h->last_seen;
        strncpy(t->hostname, h->hostname, sizeof(t->hostname) - 1);

        /* En çok paket gidilen hedef / gelinen kaynak (64 kayıtlık özet) */
        typedef struct { uint32_t ip; uint64_t pkts; } PeerAgg;
        PeerAgg vp[64];
        PeerAgg ap[64];
        int vn = 0, an = 0;
        for (int fi = 0; fi < IDS_MAX_FLOWS; fi++) {
            IdsFlow *f = &g_flows[fi];
            if (!f->active) continue;
            if (f->src_ip == h->ip && f->dst_ip != h->ip) {
                int k = -1;
                for (int j = 0; j < vn; j++)
                    if (vp[j].ip == f->dst_ip) { k = j; break; }
                if (k < 0 && vn < 64) {
                    k = vn++;
                    vp[k].ip = f->dst_ip;
                    vp[k].pkts = 0;
                }
                if (k >= 0) vp[k].pkts += f->pkt_count;
            } else if (f->dst_ip == h->ip && f->src_ip != h->ip) {
                int k = -1;
                for (int j = 0; j < an; j++)
                    if (ap[j].ip == f->src_ip) { k = j; break; }
                if (k < 0 && an < 64) {
                    k = an++;
                    ap[k].ip = f->src_ip;
                    ap[k].pkts = 0;
                }
                if (k >= 0) ap[k].pkts += f->pkt_count;
            }
        }
        uint64_t maxp = 0;
        for (int j = 0; j < vn; j++) {
            if (vp[j].pkts > maxp) {
                maxp = vp[j].pkts;
                ids_ip_to_str(vp[j].ip, t->top_victim_ip, sizeof(t->top_victim_ip));
            }
        }
        maxp = 0;
        for (int j = 0; j < an; j++) {
            if (ap[j].pkts > maxp) {
                maxp = ap[j].pkts;
                ids_ip_to_str(ap[j].ip, t->top_attacker_ip,
                              sizeof(t->top_attacker_ip));
            }
        }

        if (h->attack_score >= 80)
            strncpy(t->status, "KRITIK SALDIRGAN", sizeof(t->status) - 1);
        else if (h->attack_score >= 40)
            strncpy(t->status, "SALDIRGAN", sizeof(t->status) - 1);
        else if (h->attack_score >= 15)
            strncpy(t->status, "SUPHELI", sizeof(t->status) - 1);
        else
            strncpy(t->status, "TEMIZ", sizeof(t->status) - 1);
        n++;
    }

    qsort(out->hosts, n, sizeof(IdsHostThreat), ids_host_cmp_desc);
    out->count = n;

    int ac = 0;
    for (int i = 0; i < IDS_MAX_FLOWS; i++)
        if (g_flows[i].active) ac++;
    out->total_flows = ac;

    platform_mutex_unlock(&g_ids_lock);
    return n;
}

void ids_clear_host_data(void) {
    platform_mutex_lock(&g_ids_lock);
    memset(g_flows, 0, sizeof(g_flows));
    g_flow_count = 0;
    memset(g_hosts, 0, sizeof(g_hosts));
    g_host_count = 0;
    memset(g_name_pending, 0, sizeof(g_name_pending));
    g_name_pending_count = 0;
    memset(g_incidents, 0, sizeof(g_incidents));
    g_incident_count = 0;
    g_last_flow_analysis = 0;
    g_ids.active_flows = 0;
    g_ids.host_count = 0;
    g_ids.incident_count = 0;
    platform_mutex_unlock(&g_ids_lock);
}

/* ==================================================================
 *   KURAL EŞİKLERİ
 * ================================================================== */

/* ---  Yaygın/well-known port mu? (yatay tarama eşik seçimi) --- */
static int ids_port_is_wellknown(uint16_t p) {
    switch (p) {
        case 20: case 21: case 22: case 23: case 25: case 53: case 80:
        case 110: case 143: case 443: case 445: case 465: case 587:
        case 993: case 995: case 3306: case 3389: case 5432: case 6379:
        case 8080: case 8443:
            return 1;
        default:
            return 0;
    }
}

/* ---  "Ortak servis" portları: bilinmeyen yüksek port
 * dinleme tespitinde (level 0) bunlar şüphe sayılmaz (FP önleme) --- */
static int ids_port_is_common_service(uint16_t p) {
    switch (p) {
        case 21: case 22: case 23: case 25: case 53: case 67: case 68:
        case 80: case 110: case 123: case 137: case 138: case 139: case 143:
        case 161: case 389: case 443: case 445: case 465: case 514:
        case 587: case 631: case 636: case 873: case 993: case 995:
        case 1080: case 1433: case 1521: case 3306: case 3389: case 5432:
        case 5900: case 5901: case 6379: case 8080: case 8443: case 8888:
        case 11211: case 27017: case 5353:
            return 1;
        default:
            return 0;
    }
}

/* ---  Binary protokol portları: shellcode eşiği burada yükselir --- */
static int ids_port_is_binary_proto(uint16_t p) {
    switch (p) {
        case 445: case 139: case 137: case 138:   /* SMB/NetBIOS */
        case 3306: case 5432:                     /* MySQL/PostgreSQL */
        case 27017: case 6379: case 11211:        /* MongoDB/Redis/Memcached */
        case 3389: case 5900: case 5901:          /* RDP/VNC */
            return 1;
        default:
            return 0;
    }
}

/* ---  TLS portları: şifreli içerikte payload imzası aranmaz --- */
static int ids_port_is_tls(uint16_t p) {
    switch (p) {
        case 443: case 8443: case 465: case 993: case 995: case 587:
            return 1;
        default:
            return 0;
    }
}

/* ---  Ağ büyüklüğüne göre adaptif eşik çarpanı:
 * host sayısı arttıkça eşikler büyür (küçük ağlarda normal trafik
 * bile tarama gibi görünebildiği için burada ölçeklenir). --- */
static double ids_adaptive_multiplier(void) {
    uint32_t h = g_ids.host_count;
    if (h < 8)  return 1.0;
    if (h < 16) return 1.5;
    if (h < 32) return 2.0;
    if (h < 64) return 2.5;
    return 3.0;
}

static const char *brute_force_name(uint16_t dport) {
    switch (dport) {
        case 22:   return "SSH Brute Force";
        case 21:   return "FTP Brute Force";
        case 3389: return "RDP Brute Force";
        case 3306: return "MySQL Brute Force";
        case 5432: return "PostgreSQL Brute Force";
        case 6379: return "Redis Brute Force";
        case 23:   return "Telnet Brute Force";
        case 80:
        case 443:
        case 8080:
        case 8443: return "Web Brute Force";
        default:   return "Brute Force";
    }
}

/* ==================================================================
 *   BINDING MAP — IP↔MAC esleme takibi (MAC degisimi / spoof icin)
 * ================================================================== */

#define IDS_BIND_MAX     256
#define IDS_BIND_STABLE  5   /* [D6] degisiklik uyarisi icin gereken kararli gozlem */
#define IDS_BIND_ALERT_COOLDOWN 300 /* [D6] binding uyari susturma (sn) */
#define IDS_BIND_FAST_WIN 5   /* [D6] hizli (spoof) degisim penceresi (sn) */

typedef struct {
    uint32_t ip;
    uint8_t  mac[6];
    uint8_t  prev_mac[6];  /* [D6] degisiklik oncesi MAC (kanit/rapor) */
    int      mac_change_count; /* [D6] toplam MAC degisiklik sayisi */
    time_t   first_change; /* [D6] ilk degisiklik zamani */
    time_t   last_change;  /* [D6] son degisiklik zamani (hizli penceresi) */
    int      seen;          /* bu MAC ile gozlenme sayisi */
    time_t   last_seen;
    time_t   last_alert;
    int      valid;
} IdsBinding;

static IdsBinding g_bindings[IDS_BIND_MAX];
static int g_binding_count = 0;

static int ids_binding_find(uint32_t ip) {
    for (int i = 0; i < g_binding_count; i++)
        if (g_bindings[i].valid && g_bindings[i].ip == ip) return i;
    return -1;
}

static int ids_binding_new(void) {
    int i;
    if (g_binding_count < IDS_BIND_MAX) {
        i = g_binding_count++;
    } else {
        /* Kap dolu: en eski kullanilan kayit geri donustur (LRU) */
        i = 0;
        for (int k = 1; k < IDS_BIND_MAX; k++)
            if (g_bindings[k].last_seen < g_bindings[i].last_seen) i = k;
    }
    memset(&g_bindings[i], 0, sizeof(g_bindings[i]));
    return i;
}

/* Guvenilir taban kayitlari (kendi MAC / gateway) icin binding baslat */
static void ids_binding_seed(uint32_t ip, const uint8_t mac[6]) {
    if (!ip || ids_mac_zero(mac)) return;
    int i = ids_binding_find(ip);
    if (i < 0) i = ids_binding_new();
    g_bindings[i].ip = ip;
    memcpy(g_bindings[i].mac, mac, 6);
    g_bindings[i].seen = IDS_BIND_STABLE;
    g_bindings[i].valid = 1;
    g_bindings[i].last_seen = time(NULL);
}

/* Paketlerden IP->MAC eslesmesini ogren; kararli eslesme degisirse uyar */
static void ids_learn_binding(const IdsPktInfo *pi) {
    uint32_t claim_ip;
    if (ids_mac_zero(pi->src_mac)) return;   /* sentetik cerceve: MAC yok */
    claim_ip = pi->is_arp ? pi->arp_sender_ip : pi->src_ip;
    if (!claim_ip) return;
    if (claim_ip == g_gateway_ip || claim_ip == g_local_ip) return;

    int i = ids_binding_find(claim_ip);
    if (i < 0) {
        i = ids_binding_new();
        g_bindings[i].ip = claim_ip;
        memcpy(g_bindings[i].mac, pi->src_mac, 6);
        g_bindings[i].seen = 1;
        g_bindings[i].valid = 1;
        g_bindings[i].last_seen = time(NULL);
        return;
    }
    IdsBinding *b = &g_bindings[i];
    if (memcmp(b->mac, pi->src_mac, 6) != 0) {
        if (b->seen >= IDS_BIND_STABLE) {
            time_t now = time(NULL);
            /* [D6] Hizli degisim: son degisimden IDS_BIND_FAST_WIN sn icinde
             * yeni bir degisim geldi -> roam degil, aktif spoof kabul et.
             * (Roam/aparat MAC'i tek seferlik degisir; spoof titrestirir.) */
            int fast = (b->last_change &&
                        now - b->last_change <= IDS_BIND_FAST_WIN &&
                        b->mac_change_count >= 1);
            if (fast || now - b->last_alert >= IDS_BIND_ALERT_COOLDOWN) {
                char desc[160];
                char ip[46];
                ids_ip_to_str(claim_ip, ip, sizeof(ip));
                b->last_alert = now;
                if (fast) {
                    snprintf(desc, sizeof(desc),
                             "%s icin MAC %02x:%02x:%02x:%02x:%02x:%02x -> "
                             "%02x:%02x:%02x:%02x:%02x:%02x; son %d sn icinde "
                             "%d. degisim (aktif spoof)",
                             ip,
                             b->mac[0], b->mac[1], b->mac[2],
                             b->mac[3], b->mac[4], b->mac[5],
                             pi->src_mac[0], pi->src_mac[1], pi->src_mac[2],
                             pi->src_mac[3], pi->src_mac[4], pi->src_mac[5],
                             IDS_BIND_FAST_WIN, b->mac_change_count + 1);
                } else {
                    snprintf(desc, sizeof(desc),
                             "%s icin MAC %02x:%02x:%02x:%02x:%02x:%02x -> "
                             "%02x:%02x:%02x:%02x:%02x:%02x degisti "
                             "(spoof/roam?)",
                             ip,
                             b->mac[0], b->mac[1], b->mac[2],
                             b->mac[3], b->mac[4], b->mac[5],
                             pi->src_mac[0], pi->src_mac[1], pi->src_mac[2],
                             pi->src_mac[3], pi->src_mac[4], pi->src_mac[5]);
                }
                ids_raise_alert_ev(
                    "IP-MAC Eslesme Degisikligi",
                    fast ? "KRITIK" : "YUKSEK",
                    fast ? SCORE_KRITIK : SCORE_YUKSEK, pi, desc,
                    fast ? (IDS_EV_REPEATED | IDS_EV_THRESHOLD_MET)
                         : IDS_EV_THRESHOLD_MET);
            }
        }
        /* Kanit izi: onceki MAC + zaman damgalari ve sayac guncellenir */
        time_t now = time(NULL);
        memcpy(b->prev_mac, b->mac, 6);
        if (b->first_change == 0) b->first_change = now;
        b->last_change = now;
        b->mac_change_count++;
        memcpy(b->mac, pi->src_mac, 6);
        b->seen = 1;
    } else if (b->seen < IDS_BIND_STABLE) {
        b->seen++;
    }
    b->last_seen = time(NULL);
}

/* ==================================================================
 *   PAYLOAD IMZA MOTORU — L7 iceriginde saldiri deseni arama
 * ================================================================== */

#define IDS_PAYLOAD_SCAN 96  /* imza aramasinda incelenen on yuk (byte) */

typedef struct {
    const char *needle;
    const char *sig;
    const char *sev;
    double      score;
    int         request_only;   /* yalnizca istek yonunde (cevap degil) ara */
} IdsSig;

static const IdsSig g_sigs[] = {
    /* Web / SQLi / XSS — istek yonu */
    { "sqlmap",        "SQLMap (SQLi taramasi)",       "YUKSEK", SCORE_YUKSEK, 1 },
    { "UNION SELECT",  "SQL Injection (UNION SELECT)", "YUKSEK", SCORE_YUKSEK, 1 },
    { "OR 1=1",        "SQL Injection (OR 1=1)",       "YUKSEK", SCORE_YUKSEK, 1 },
    { "<script",       "XSS (script etiketi)",         "YUKSEK", SCORE_YUKSEK, 1 },
    { "onerror=",      "XSS (onerror)",                "ORTA",   SCORE_ORTA,   1 },
    { "javascript:",   "XSS (javascript)",             "ORTA",   SCORE_ORTA,   1 },
    /* Dosya erisimi / komut calistirma */
    { "/etc/passwd",   "Dosya Erisim (/etc/passwd)",   "YUKSEK", SCORE_YUKSEK, 1 },
    { "/etc/shadow",   "Dosya Erisim (/etc/shadow)",   "KRITIK", SCORE_KRITIK, 1 },
    { "cmd.exe",       "Windows Komut (cmd.exe)",      "KRITIK", SCORE_KRITIK, 1 },
    { "/bin/sh",       "Shell Erisim (/bin/sh)",       "KRITIK", SCORE_KRITIK, 1 },
    { "whoami",        "Komut Calistirma (whoami)",    "YUKSEK", SCORE_YUKSEK, 1 },
    { "<?php",         "PHP Kodu Enjeksiyonu",         "YUKSEK", SCORE_YUKSEK, 1 },
    { "eval(",         "Kod Enjeksiyonu (eval)",       "YUKSEK", SCORE_YUKSEK, 1 },
    /* Powershell / yuk indirme: yalniz istek yonu ve dusuk guven. Bu
     * sozcukler servis yanitlarinda, apt/wget, CI/CD ve betik trafiginde
     * yaygin gecer; base64 imzasi kaldirildi (en gurultulu FP kaynagi). */
    { "powershell",    "PowerShell Komutu",            "ORTA",   SCORE_ORTA,   1 },
    { "-enc",          "PowerShell EncodedCommand",    "YUKSEK", SCORE_YUKSEK, 1 },
    { "IEX(",          "PowerShell IEX",               "KRITIK", SCORE_KRITIK, 1 },
    { "wget ",         "Yuk Indirme (wget)",           "DUSUK",  SCORE_DUSUK,  1 },
    { "curl ",         "Yuk Indirme (curl)",           "DUSUK",  SCORE_DUSUK,  1 },
    /* Log4Shell (JNDI) */
    { "jndi:",         "Log4Shell (JNDI)",             "KRITIK", SCORE_KRITIK, 0 },
    { "${jndi:",       "Log4Shell (JNDI ekspr.)",      "KRITIK", SCORE_KRITIK, 0 },
};
#define IDS_SIG_COUNT (int)(sizeof(g_sigs) / sizeof(g_sigs[0]))

static int ids_mem_ci_find_pos(const uint8_t *hay, int hlen, const char *needle) {
    int nlen = (int)strlen(needle);
    if (nlen == 0 || nlen > hlen) return -1;
    for (int i = 0; i + nlen <= hlen; i++) {
        int j = 0;
        for (; j < nlen; j++) {
            char a = (char)hay[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
        }
        if (j == nlen) return i;
    }
    return -1;
}

/* FP DUZELTMESI: yapisal karakterle ('-' gibi) baslayan imzalar icin sol
 * sinir kontrolu. "Accept-Encoding: gzip" baslikindaki "-Enc" dizisi,
 * "-enc" (PowerShell EncodedCommand) imzasiyla buyuk/kucuk harf duyarsiz
 * eslesip normal tarayici GET isteklerinde YUKSEK FP uretiyordu (gercek
 * CDN trafiyle dogrulandi: 151.101.x / 95.101.x / 199.232.x:80 GET'leri).
 * Eslesmeden hemen once harf/rakam varsa eslesme bir sozcugun parcasi
 * kabul edilip atlanir; "powershell -enc <base64>" ve "-EncodedCommand"
 * senaryolarinda oncesinde bosluk/teklif oldugu icin TP korunur.
 * Yapisal karakterle baslamayan imzalar etkilenmez. */
static int ids_sig_left_boundary_ok(const uint8_t *p, int pos, const char *needle) {
    unsigned char first = (unsigned char)needle[0];
    int first_alnum = ((first >= '0' && first <= '9') ||
                       (first >= 'A' && first <= 'Z') ||
                       (first >= 'a' && first <= 'z'));
    if (first_alnum || pos == 0) return 1;
    unsigned char prev = p[pos - 1];
    int prev_alnum = ((prev >= '0' && prev <= '9') ||
                      (prev >= 'A' && prev <= 'Z') ||
                      (prev >= 'a' && prev <= 'z'));
    return !prev_alnum;
}

static int ids_mem_ci_find(const uint8_t *hay, int hlen, const char *needle) {
    return ids_mem_ci_find_pos(hay, hlen, needle) >= 0;
}

static int ids_mem_has_run(const uint8_t *p, int n, uint8_t byte, int min_run) {
    int run = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] == byte) {
            if (++run >= min_run) return 1;
        } else {
            run = 0;
        }
    }
    return 0;
}

/* ---  Yüksek entropili (şifreli/komprese) payload mı?
 * TLS/şifreli tüneller ve arşiv akışları NOP/INT3 gibi yapısal imzaları
 * rastgele üretebildiği için burada kontrol atlanır (FP önleme). --- */
static int ids_payload_likely_encrypted(const uint8_t *p, int n) {
    int lim = n < 64 ? n : 64;
    if (lim < 32) return 0;
    uint8_t seen[256];
    memset(seen, 0, sizeof(seen));
    int uniq = 0;
    for (int i = 0; i < lim; i++) {
        if (!seen[p[i]]) { seen[p[i]] = 1; uniq++; }
    }
    return uniq >= 40;   /* 64 baytta 40+ farklı değer: yüksek entropi */
}

/* Payload'i alintiya cevir: basilabilir karakterler aynen, digerleri "..." */
static void ids_excerpt(const uint8_t *p, int n, char *out, int outlen) {
    int k = 0, i = 0;
    while (i < n && k + 1 < outlen) {
        unsigned char c = p[i];
        if (c >= 0x20 && c < 0x7F) {
            out[k++] = (char)c;
            i++;
        } else {
            if (outlen - k < 4) break;
            out[k++] = '.';
            out[k++] = '.';
            out[k++] = '.';
            while (i < n && !(p[i] >= 0x20 && p[i] < 0x7F)) i++;
        }
    }
    if (i < n && k + 3 < outlen) {
        out[k++] = '.';
        out[k++] = '.';
        out[k++] = '.';
    }
    out[k] = '\0';
}

static void ids_check_payload(const IdsPktInfo *pi) {
    const uint8_t *p = pi->payload;
    int n = pi->payload_len;
    int scan, is_request, i;
    char k2[96];
    char desc[160];
    char ex[64];
    IdsTracker *tr;

    if (!p || n <= 0) return;
    /* TLS portlari: icerik sifreli oldugu icin imza
     * aramasi yalnizca yanlis pozitif uretir (sifreli baytlar desen
     * taklit edebilir). */
    if (ids_port_is_tls(pi->src_port) || ids_port_is_tls(pi->dst_port)) return;
    scan = n < IDS_PAYLOAD_SCAN ? n : IDS_PAYLOAD_SCAN;

    /* IsteK yonu: kaynak port >= 1024 ise istemci istegi kabul et.
     * Servis yanitlarinda (sport < 1024, orn. 80/443/53) yalnizca
     * request_only olmayan imzalar aranir. */
    is_request = (pi->src_port >= 1024);

    /* Yuksek entropili (sifreli/komprese) akis: L7 imzasi
     * ve sled aramasi anlamsizdir; rastgele baytlar yanlis eslesme yapar. */
    if (ids_payload_likely_encrypted(p, n)) return;

    for (i = 0; i < IDS_SIG_COUNT; i++) {
        const IdsSig *sg = &g_sigs[i];
        if (sg->request_only && !is_request) continue;
        int mpos = ids_mem_ci_find_pos(p, scan, sg->needle);
        if (mpos < 0) continue;
        if (!ids_sig_left_boundary_ok(p, mpos, sg->needle)) continue;

        snprintf(k2, sizeof(k2), "G|%d|%u", i, pi->src_ip);
        tr = ids_tracker_get(k2);
        if (!tr) continue;
        ids_tracker_bump(tr, 0);
        if (!ids_tracker_can_alert(tr)) continue;

        ids_excerpt(p, scan < 48 ? scan : 48, ex, sizeof(ex));
        snprintf(desc, sizeof(desc), "L7 yukunde imza: %s | ilk veri: %s",
                 sg->sig, ex);
        ids_raise_alert(sg->sig, sg->sev, sg->score, pi, desc);
    }

    /* Shellcode sled'leri: NOP (0x90) / INT3 (0xCC) serileri.
     *  Esik normalde 16; binary protokol portlarinda 32
     * (SMB/DB akislarinda 0x90/0xCC rastgele dolgu olarak gorulebilir). */
    /* FP DUZELTMESI: yanit yonu (src_port < 1024) icerikleri — CDN/binary
     * indirmelerde (or. Fastly 199.232.x:80, dosya icindeki 0xCC fonksiyon
     * dolgusu) >=16 ardIsIk 0xCC KRITIK "Shellcode (INT3-sled)" FP
     * uretiyordu (gercek trafikle dogrulandi). Yanit yonunde esik ikiye
     * katlanir (32; binary-proto esigiyla ayni); istek yonunde 16 kalir
     * (istek tasimali gercek shellcode TP'si korunur). Yanit yonundeki
     * buyuk sled TP'si (>=32) hala tetiklenir. */
    int sl_edge = (!is_request ||
                   ids_port_is_binary_proto(pi->src_port) ||
                   ids_port_is_binary_proto(pi->dst_port)) ? 32 : 16;
    if (ids_mem_has_run(p, n, 0x90, sl_edge)) {
        snprintf(k2, sizeof(k2), "G|NOP|%u", pi->src_ip);
        tr = ids_tracker_get(k2);
        if (tr) {
            ids_tracker_bump(tr, 0);
            if (ids_tracker_can_alert(tr)) {
                ids_excerpt(p, scan < 48 ? scan : 48, ex, sizeof(ex));
                snprintf(desc, sizeof(desc),
                         ">=%d ardIsIk NOP (0x90) | ilk veri: %s", sl_edge, ex);
                ids_raise_alert("Shellcode (NOP-sled)", "KRITIK", SCORE_KRITIK,
                                pi, desc);
            }
        }
    }
    if (ids_mem_has_run(p, n, 0xCC, sl_edge)) {
        snprintf(k2, sizeof(k2), "G|INT3|%u", pi->src_ip);
        tr = ids_tracker_get(k2);
        if (tr) {
            ids_tracker_bump(tr, 0);
            if (ids_tracker_can_alert(tr)) {
                ids_excerpt(p, scan < 48 ? scan : 48, ex, sizeof(ex));
                snprintf(desc, sizeof(desc),
                         ">=%d ardIsIk INT3 (0xCC) | ilk veri: %s", sl_edge, ex);
                ids_raise_alert("Shellcode (INT3-sled)", "KRITIK", SCORE_KRITIK,
                                pi, desc);
            }
        }
    }
}

/* ==================================================================
 *   AKILLI MAL-PORT / DİNLEME SERVİSİ MOTORU
 *   Sabit “4444 = Meterpreter” kalıbı yalnız hızlandırıcıdır; asıl soru
 *   “bir makinede dışarıya dinleme var mı”.
 *   level2 = bilinen kötü amaçlı port, HER yön (iç-iç dahil) — KRITIK
 *   level1 = şüpheli yüksek port, iç-iç hariç — YUKSEK
 *   level0 = bilinmeyen yüksek port, yerel dinleyici + dış istemci — ORTA
 *   Kapı: connection_count >= 2 VEYA (syn_seen && data_seen); count
 *   yalnız SYN-ACK ile artar; flows_as_dst >= 3 ise KRITIK -> YUKSEK.
 * ================================================================== */

#define IDS_MP_MAX        64
#define IDS_MP_TIMEOUT    300   /* pasif kayıt düşme süresi (sn) */
#define IDS_MP_ALERT_CD   120   /* aynı (listener,client,port) uyarı arası (sn) */

typedef struct {
    char     key[64];          /* "MP|<listener>|<client>|<port>" */
    uint32_t listener_ip;      /* dinleyen (hedef) taraf */
    uint32_t client_ip;        /* bağlanan (kaynak) taraf */
    uint16_t port;
    int      level;            /* 0=bilinmeyen yüksek port, 1=suspicious, 2=critical */
    int      syn_seen;         /* SYN gördük mü */
    int      synack_seen;      /* SYN-ACK gördük mü */
    int      data_seen;        /* veri paketi gördük mü */
    time_t   first_ts;         /* ilk görülme zamanı */
    time_t   last_seen;
    time_t   last_alert;
    uint32_t connection_count; /* SYN-ACK ile tamamlanan bağlantı sayısı */
    uint32_t attempt_count;    /* toplam SYN girişimi */
    int      active;
} IdsMalPortState;

static IdsMalPortState g_malport[IDS_MP_MAX];
static int g_malport_count = 0;

/* Bilinen kötü amaçlı/C2/RAT portları (level 2 — hızlandırıcı) */
static const uint16_t k_mal_ports_critical[] = {
    4444, 4445, 31337, 31338, 54320, 54321, 5555,
    6666, 6667, 1090, 1099, 1524, 1234, 12345, 27374, 22222
};
#define K_MAL_CRIT_N (int)(sizeof(k_mal_ports_critical) / sizeof(k_mal_ports_critical[0]))

/* Normal ağda nadir görülen yönetim/RAT benzeri yüksek
 * portlar (level 1 — iç-iç kullanım uyarı üretmez) */
static const uint16_t k_mal_ports_suspicious[] = {
    4443, 7001, 8001, 8081, 9001, 10001, 20000, 4446, 4555
};
#define K_MAL_SUSP_N (int)(sizeof(k_mal_ports_suspicious) / sizeof(k_mal_ports_suspicious[0]))

static int ids_malport_level(uint16_t port) {
    for (int i = 0; i < K_MAL_CRIT_N; i++)
        if (k_mal_ports_critical[i] == port) return 2;
    for (int i = 0; i < K_MAL_SUSP_N; i++)
        if (k_mal_ports_suspicious[i] == port) return 1;
    return 0;
}

static IdsMalPortState *ids_malport_find(uint32_t listener, uint32_t client,
                                         uint16_t port) {
    for (int i = 0; i < g_malport_count; i++) {
        IdsMalPortState *m = &g_malport[i];
        if (!m->active) continue;
        if (m->listener_ip == listener && m->client_ip == client &&
            m->port == port)
            return m;
        /* veri paketleri ters yönde gelebilir: listener/client takası */
        if (m->listener_ip == client && m->client_ip == listener &&
            m->port == port)
            return m;
    }
    return NULL;
}

static IdsMalPortState *ids_malport_alloc(uint32_t listener, uint32_t client,
                                          uint16_t port, int level) {
    time_t now = time(NULL);
    IdsMalPortState *victim = NULL;
    for (int i = 0; i < g_malport_count; i++) {
        IdsMalPortState *m = &g_malport[i];
        if (!m->active) { victim = m; break; }
    }
    if (!victim && g_malport_count < IDS_MP_MAX)
        victim = &g_malport[g_malport_count++];
    if (!victim) {
        /* Kap dolu: en eski kaydı geri dönüştür */
        victim = &g_malport[0];
        for (int i = 1; i < g_malport_count; i++)
            if (g_malport[i].last_seen < victim->last_seen)
                victim = &g_malport[i];
    }
    memset(victim, 0, sizeof(*victim));
    victim->active = 1;
    victim->listener_ip = listener;
    victim->client_ip = client;
    victim->port = port;
    victim->level = level;
    victim->first_ts = now;
    victim->last_seen = now;
    snprintf(victim->key, sizeof(victim->key), "MP|%u|%u|%u",
             listener, client, (unsigned)port);
    return victim;
}

/* Dinleyicinin hedef olduğu aktif akış sayısı (yerel servis istisnası) */
static int ids_flow_count_as_dst(uint32_t ip) {
    int c = 0;
    for (int i = 0; i < IDS_MAX_FLOWS; i++)
        if (g_flows[i].active && g_flows[i].dst_ip == ip) c++;
    return c;
}

/* TCP paketini dinleme motoruna besler (ids_check_rules içinden çağrılır) */
static void ids_malport_feed(const IdsPktInfo *pi) {
    if (!pi->is_tcp || !pi->dst_port) return;

    /* Zaman asimi: IDS_MP_TIMEOUT (300 sn) sure pasif kalan kayitlar
     * dusulur — suphe zamanla gecerliligini yitirir; yoksa eski kayitlar
     * kabi doldurup gercek kayitlari geri donusturur (kayit basina bir
     * karsilastirma maliyeti). */
    time_t now0 = time(NULL);
    for (int i = 0; i < g_malport_count; i++) {
        if (g_malport[i].active &&
            now0 - g_malport[i].last_seen > IDS_MP_TIMEOUT)
            g_malport[i].active = 0;
    }

    int is_syn    = (pi->tcp_flags & 0x02) && !(pi->tcp_flags & 0x10);
    int is_synack = (pi->tcp_flags & 0x12) == 0x12;
    int has_data  = (pi->payload && pi->payload_len > 0);
    if (!is_syn && !is_synack && !has_data) return;

    /* Yön tayini: SYN'de dinleyici hedef (dst) taraftır; SYN-ACK'te
     * kaynak tarafa döner. Veri paketinde SYN yönü esas alınır. */
    uint32_t listener, client;
    uint16_t port;
    if (is_syn) {
        listener = pi->dst_ip;
        client   = pi->src_ip;
        port     = pi->dst_port;
    } else if (is_synack) {
        listener = pi->src_ip;
        client   = pi->dst_ip;
        port     = pi->src_port;
    } else {
        listener = pi->dst_ip;
        client   = pi->src_ip;
        port     = pi->dst_port;
    }
    if (!listener || !client) return;

    /* Tarama istemcisi ayrimi: ayni kaynak kisa pencerede 8+ farkli hedef
     * porta SYN attiysa bu port taramasidir; tarama SYN'leri dinleme kaniti
     * olarak kayda gecirilmez (taramayi S| kurali zaten alarmlar). */
    if (is_syn) {
        char sk[32];
        snprintf(sk, sizeof(sk), "S|%u", pi->src_ip);
        IdsTracker *st = ids_tracker_peek(sk);
        if (st) {
            ids_tracker_reset_if_expired(st);
            if (ids_tracker_unique(st) >= 8) return;   /* [17] tam sayac */
        }
    }

    IdsMalPortState *m = ids_malport_find(listener, client, port);

    /* Yetim SYN-ACK: eslesen SYN kaniti olmayan SYN-ACK dinleme kaniti
     * degildir. Self tarama SYN'leri bastirildiginda hedefin SYN-ACK
     * cevaplari yetim kalip YANLIS “Dinleme Servisi” alarmi uretiyordu. */
    if (is_synack && !m) return;

    /* Kayit yoksa olusturma kosullari:
     * - level 2 (critical): her yon, ic-ic dahil
     * - level 1 (suspicious): her yon (uyarida ic-ic elenir)
     * - level 0: yalniz SYN yonunde; yerel dinleyici + dis istemci +
     *   yuksek port + ortak servis degil */
    if (!m) {
        int lvl = ids_malport_level(port);
        if (lvl == 0) {
            if (!is_syn) return;                    /* bilinmeyen porta yalnız SYN açar */
            if (port < 1024) return;
            if (ids_port_is_common_service(port)) return;
            if (!ids_ip_in_scope(listener)) return; /* dinleyici yerel olmalı */
            if (ids_ip_in_scope(client)) return;    /* istemci dışarıdan olmalı */
        }
        m = ids_malport_alloc(listener, client, port, lvl);
    }
    if (!m) return;

    if (is_syn) {
        m->syn_seen = 1;
        m->attempt_count++;
    } else if (is_synack) {
        if (!m->syn_seen) return;  /* SYN'siz cevap sayılmaz */
        m->synack_seen = 1;
        m->connection_count++;
    } else {
        m->data_seen = 1;
    }
    m->last_seen = time(NULL);

    /* Kapi: gercek istemci temasi (SYN geldi + dinleyici SYN-ACK ile
     * cevapladi) ilk baglantida uyari uretir; eskiden 2. baglanti veya veri
     * bekleniyordu. Fallback modunda yalniz SYN gorulur (SYN-ACK yok),
     * o zaman bilincli olarak uyari verilmez. */
    int gate = (m->connection_count >= 2) ||
               (m->syn_seen && m->data_seen) ||
               (m->syn_seen && m->synack_seen);
    if (!gate) return;

    time_t now = m->last_seen;
    if (now - m->last_alert < IDS_MP_ALERT_CD) return;
    m->last_alert = now;

    /* Şiddet: level bazlı + yerel servis istisnası */
    const char *sev;
    double score;
    uint8_t ev = IDS_EV_THRESHOLD_MET | IDS_EV_KNOWN_BAD_PORT;
    if (m->level == 2) {
        sev = "KRITIK"; score = SCORE_KRITIK;
        /* Dinleyici çok sayıda akışa hizmet veriyorsa gerçek bir yerel
         * servistir: KRITIK -> YUKSEK (FP önleme) */
        if (ids_flow_count_as_dst(listener) >= 3) {
            sev = "YUKSEK"; score = SCORE_YUKSEK;
        }
    } else if (m->level == 1) {
        /* İç-iç (local-local) şüpheli port kullanımı FP riski yüksek */
        if (ids_ip_in_scope(listener) && ids_ip_in_scope(client)) return;
        sev = "YUKSEK"; score = SCORE_YUKSEK;
    } else {
        if (ids_ip_in_scope(client)) return;        /* güvenlik kopyası */
        sev = "ORTA"; score = SCORE_ORTA;
        ev = IDS_EV_THRESHOLD_MET;                  /* KNOWN_BAD_PORT yok */
    }
    if (m->connection_count >= 2) ev |= IDS_EV_REPEATED;
    if (m->synack_seen)           ev |= IDS_EV_HANDSHAKE_SEEN;
    if (!ids_ip_in_scope(client)) ev |= IDS_EV_EXTERNAL_SRC;

    char desc[192];
    char lstr[46], cstr[46];
    long age = (long)(now - m->first_ts);
    ids_ip_to_str(listener, lstr, sizeof(lstr));
    ids_ip_to_str(client, cstr, sizeof(cstr));
    const char *lvl_name = (m->level == 2) ? "kritik port" :
                           (m->level == 1) ? "supheli port" : "yuksek port";
    snprintf(desc, sizeof(desc),
             "%s:%u uzerinde %s dinleme kanitlari: %u tamamlanan baglanti"
             " (SYN-ACK), %u SYN girisimi, %s; ilk temas %ld sn once",
             lstr, (unsigned)m->port, lvl_name,
             (unsigned)m->connection_count, (unsigned)m->attempt_count,
             m->data_seen ? "veri akisi goruldu" : "veri akisi yok",
             age);

    const char *sig = (m->level == 2) ? "Dinleme Servisi (Kritik Port)" :
                      (m->level == 1) ? "Dinleme Servisi (Supheli Port)" :
                                      "Yuksek Port Dinleme (Harici Erisim)";
    int ai = ids_raise_alert_ev(sig, sev, score, pi, desc, ev);
    if (ai >= 0) {
        /* Port sahibi saldırgandır: GUI yön göstergesi */
        platform_mutex_lock(&g_ids_lock);
        g_alert_buf[ai].port_owner_attacker = 1;
        platform_mutex_unlock(&g_ids_lock);
    }
}

static void ids_check_rules(const IdsPktInfo *pi) {
    char key[96];
    IdsTracker *t;
    /* Adaptif eşik çarpanı: ağdaki host sayısı arttıkça
     * eşikler ölçeklenir (küçük ağlarda normal trafik tarama gibi
     * görünebileceğinden). */
    double am = ids_adaptive_multiplier();

    /* ---------- 1. ARP Zehirlenmesi (sahte gateway) ---------- */
    if (pi->is_arp && pi->arp_opcode == 2 && g_gateway_mac_valid &&
        pi->arp_sender_ip == g_gateway_ip) {
        int is_ours = (memcmp(pi->arp_sender_mac, g_local_mac, 6) == 0);
        int is_real = (memcmp(pi->arp_sender_mac, g_gateway_mac, 6) == 0);
        if (!is_ours && !is_real) {
            char desc[128];
            char att_ip[46];
            ids_ip_to_str(pi->arp_sender_ip, att_ip, sizeof(att_ip));
            snprintf(desc, sizeof(desc),
                     "Gateway (%s) icin sahte ARP Reply: MAC %02x:%02x:%02x:%02x:%02x:%02x",
                     att_ip,
                     pi->arp_sender_mac[0], pi->arp_sender_mac[1],
                     pi->arp_sender_mac[2], pi->arp_sender_mac[3],
                     pi->arp_sender_mac[4], pi->arp_sender_mac[5]);
            ids_raise_alert("ARP Zehirlenmesi (MITM)", "KRITIK",
                            SCORE_KRITIK, pi, desc);
        }
    }

    /* ---------- 1b. ARP IP cakismasi: yabanci MAC yerel IP'yi sahipleniyor ---------- */
    /* Kendi MAC baglami (local_mac) henuz ogrenilmediyse bu kontrol
     * atlanir; aksi halde kendi gratuitous ARP'imiz "yabanci MAC yerel
     * IP'yi sahipleniyor" seklinde KRITIK FP uretiyordu (headless
     * baslangicinda local_mac bos oldugu icin gercek trafikle dogrulandi). */
    if (pi->is_arp && g_local_ip && !ids_mac_zero(g_local_mac) &&
        pi->arp_sender_ip == g_local_ip) {
        int is_ours = (memcmp(pi->arp_sender_mac, g_local_mac, 6) == 0);
        if (!is_ours) {
            char desc[160];
            char att_ip[46];
            ids_ip_to_str(pi->arp_sender_ip, att_ip, sizeof(att_ip));
            snprintf(desc, sizeof(desc),
                     "Yabanci MAC (%02x:%02x:%02x:%02x:%02x:%02x) yerel IP %s icin ARP gonderiyor",
                     pi->arp_sender_mac[0], pi->arp_sender_mac[1],
                     pi->arp_sender_mac[2], pi->arp_sender_mac[3],
                     pi->arp_sender_mac[4], pi->arp_sender_mac[5], att_ip);
            ids_raise_alert("ARP IP Cakismasi (Spoof)", "KRITIK",
                            SCORE_KRITIK, pi, desc);
        }
    }

    /* ---------- 1c. ARP taramasi: tek MAC'ten cok hedefe ARP istegi ---------- */
    if (pi->is_arp && pi->arp_opcode == 1) {
        snprintf(key, sizeof(key), "A|%02x%02x%02x%02x%02x%02x",
                 pi->arp_sender_mac[0], pi->arp_sender_mac[1],
                 pi->arp_sender_mac[2], pi->arp_sender_mac[3],
                 pi->arp_sender_mac[4], pi->arp_sender_mac[5]);
        t = ids_tracker_get(key);
        if (t) {
            ids_tracker_bump(t, pi->arp_target_ip);
            ids_tracker_long_bump(t, pi->arp_target_ip);   /* [18] uzun ufuk */
            if (t->count >= 20 && t->unique_len >= 8) {
                t->long_short_hit = 1;   /* [18] kisa pencere yakaladi */
                char desc[160];
                char m[32];
                snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
                         pi->arp_sender_mac[0], pi->arp_sender_mac[1],
                         pi->arp_sender_mac[2], pi->arp_sender_mac[3],
                         pi->arp_sender_mac[4], pi->arp_sender_mac[5]);
                snprintf(desc, sizeof(desc),
                         "%s -> %u farkli IP'ye ARP istegi (%u paket) - ag kesfi",
                         m, t->unique_len, t->count);
                /* Tarama surerken sayilar buyur: metin guncel kalir. */
                ids_raise_or_update("ARP Taramasi (Ag Kesfi)", "ORTA",
                                    SCORE_ORTA, pi, desc, 0, t);
            }
            /* Yavas ARP sweep: 10 sn'de 8 farkli hedef
             * esigini hicbir pencere karşılamasa bile 24+ farkli hedefe
             * yayilan ARP istekleri ag kesfi sayilir. */
            if (ids_tracker_long_scan(t)) {
                char ldesc[192];
                char lm[32];
                snprintf(lm, sizeof(lm), "%02x:%02x:%02x:%02x:%02x:%02x",
                         pi->arp_sender_mac[0], pi->arp_sender_mac[1],
                         pi->arp_sender_mac[2], pi->arp_sender_mac[3],
                         pi->arp_sender_mac[4], pi->arp_sender_mac[5]);
                snprintf(ldesc, sizeof(ldesc),
                         "%s -> %u farkli IP'ye YAVAS ARP istegi "
                         "(%u paket, %d sn) - hiz sinirlamali ag kesfi",
                         lm, ids_tracker_long_unique(t), t->long_count,
                         (int)(t->long_last - t->long_start));
                ids_raise_or_update_long("Yavas ARP Taramasi (Ag Kesfi)",
                                         "ORTA", SCORE_ORTA, pi, ldesc, 0, t);
            }
        }
    }

    /* ---------- 2. Dinleme servisi / kotu amacli port motoru ----------
     * Statik kotu amacli port tablosu kaldirildi (legit servisler FP
     * uretiyordu); yerine durum bilgili motor SYN/SYN-ACK/veri kaniti
     * biriktirir ve ancak connection_count >= 2 veya (syn_seen && data_seen)
     * kapisindan gecenleri uyarir. */
    if (pi->is_tcp) ids_malport_feed(pi);

    /* ---------- 3. TCP tabanlı tarama / saldırılar ---------- */
    if (pi->is_tcp) {
        int is_syn = (pi->tcp_flags & 0x02) && !(pi->tcp_flags & 0x10);
        int is_fin_only = (pi->tcp_flags == 0x01);
        int is_null = (pi->tcp_flags == 0x00);
        int is_xmas = (pi->tcp_flags == 0x29);

        /* SYN kaynak taraması: tek kaynaktan çok farklı port */
        if (is_syn) {
            snprintf(key, sizeof(key), "S|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump_port(t, pi->dst_port);
                ids_tracker_long_bump(t, pi->dst_port);
                /* Esik adaptif: kucuk aglarda (am=1.0) eski davranis, buyuk
                 * aglarda daha fazla kanit beklenir. PASIF KURAL: LAN'daki
                 * DIGER hostlarin disariya SYN davranisini yakalar; kendi
                 * makinemizin taramalari L| kuralina girer. Hem paket sayisi
                 * hem farkli port sayisi yuksek olmali — tek basina 8 farkli
                 * porta SYN atan mesru uygulamalar (cok baglantili istemciler,
                 * paralel guncelleme) FP uretmesin. */
                if (t->count >= (uint32_t)(20 * am) &&
                    ids_tracker_unique(t) >= 8) {
                    t->long_short_hit = 1;   /* [18] kisa pencere yakaladi */
                    char desc[128];
                    char s[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    snprintf(desc, sizeof(desc),
                             "%s -> %d farkli porta SYN taramasi (%u paket)",
                             s, ids_tracker_unique(t), t->count);
                    ids_raise_or_update("Port Taramasi (SYN)", "YUKSEK",
                                        SCORE_YUKSEK, pi, desc, 0, t);
                }
                /* Yavas SYN taramasi: kisa pencere 10 sn'de
                 * 20 paket + 8 farkli port ister; 2 sn aralikli tarama bu
                 * esigi HIC gormez ve eskiden tamamen gorunmezdi. */
                if (ids_tracker_long_scan(t)) {
                    char ldesc[160];
                    char ls[46];
                    ids_ip_to_str(pi->src_ip, ls, sizeof(ls));
                    snprintf(ldesc, sizeof(ldesc),
                             "%s -> %u farkli porta YAVAS SYN taramasi "
                             "(%u paket, %d sn) - hiz sinirlamali tarama",
                             ls, ids_tracker_long_unique(t), t->long_count,
                             (int)(t->long_last - t->long_start));
                    ids_raise_or_update_long("Yavas Port Taramasi (SYN)",
                                             "YUKSEK", SCORE_YUKSEK, pi,
                                             ldesc, 0, t);
                }
            }

            /* SYN flood: tek hedefe çok farklı kaynaktan SYN */
            snprintf(key, sizeof(key), "F|%u|%u", pi->dst_ip, pi->dst_port);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->src_ip);
                /* Esik 100 -> 200 + adaptif carpan;
                 * normal yuksek trafikli sunucular bile 100 SYN toplayabilir. */
                if (t->count >= (uint32_t)(200 * am) && t->unique_len >= 20) {
                    char desc[128];
                    char d[46];
                    ids_ip_to_str(pi->dst_ip, d, sizeof(d));
                    snprintf(desc, sizeof(desc),
                             "%s:%u hedefine %u farkli kaynaktan %u SYN (flood)",
                             d, pi->dst_port, t->unique_len, t->count);
                    ids_raise_or_update("SYN Flood (DDoS)", "KRITIK",
                                        SCORE_KRITIK, pi, desc,
                                        IDS_EV_THRESHOLD_MET |
                                        IDS_EV_REPEATED, t);
                }
            }

            /* Brute force: ayni kaynak -> hedef -> port arasi cok baglanti.
             * Web portlarina (80/443/8080/8443) giden LAN trafigi normal
             * tarayici davranisidir ve ASLA brute force sayilmaz; kural
             * yalniz ozel ag hedefinde VEYA kimlik dogrulama / uzak erisim
             * portunda isler. */
            snprintf(key, sizeof(key), "C|%u|%u|%u", pi->src_ip, pi->dst_ip,
                     pi->dst_port);
            t = ids_tracker_get(key);
            if (t) {
                int dst_priv = ids_ip_is_private(pi->dst_ip);
                int is_web   = ids_is_web_port(pi->dst_port);
                int is_auth  = ids_is_auth_port(pi->dst_port);
                int uni_thr  = is_web ? 12 : (is_auth ? 5 : 8);
                uint32_t cnt_thr = is_web ? (uint32_t)(20 * am)
                                   : (is_auth ? (uint32_t)(8 * am)
                                              : (uint32_t)(12 * am));
                /* Genel web hedefine (dış ağ) giden trafik: normal tarayıcı
                 * davranışı, sayaç hiç artırılmaz ve uyarı üretilmez. */
                if (!(is_web && !dst_priv)) {
                    /* Farkli kaynak portlari say: fallback her 2 sn'de ayni
                     * SYN'i yeniden sentezleyip tek kaynak portunu tekrar tekrar
                     * sayarak yanlis brute force uretiyordu; gercek brute force
                     * her denemede yeni ephemeral kaynak portu kullanir. */
                    ids_tracker_bump_port(t, pi->src_port);
                    /* Adaptif çarpan. */
                    if (t->count >= cnt_thr &&
                        (int)ids_tracker_unique(t) >= uni_thr) {
                        char desc[192];
                        char s[46], d[46];
                        const char *bf_sev = is_web ? "ORTA"
                                           : (is_auth ? "KRITIK" : "YUKSEK");
                        double bf_score = is_web ? SCORE_ORTA
                                         : (is_auth ? SCORE_KRITIK
                                                    : SCORE_YUKSEK);
                        ids_ip_to_str(pi->src_ip, s, sizeof(s));
                        ids_ip_to_str(pi->dst_ip, d, sizeof(d));
                        snprintf(desc, sizeof(desc),
                                 "%s -> %s:%u arasi %u farkli kaynak porttan %u baglanti denemesi%s",
                                 s, d, pi->dst_port, ids_tracker_unique(t),
                                 t->count,
                                 (is_auth && !dst_priv) ? " (dis hedef)" : "");
                        ids_raise_or_update(brute_force_name(pi->dst_port),
                                            bf_sev, bf_score, pi, desc,
                                            IDS_EV_THRESHOLD_MET |
                                            IDS_EV_REPEATED |
                                            (is_auth ? IDS_EV_KNOWN_BAD_PORT
                                                     : 0) |
                                            (!ids_ip_in_scope(pi->src_ip)
                                                 ? IDS_EV_EXTERNAL_SRC : 0),
                                            t);
                    }
                }
            }

            /* Yatay tarama: ayni porta cok farkli hedefe SYN (tek kaynak).
             * Private (RFC1918) / public hedefler ayri sayilir; public tarama
             * daha supheli oldugu icin esigi dusuktur; well-known port (<1024)
             * taramalarinda esikler ikiye katlanir. Sayimlar unique[] icinden
             * yapilir (val her zaman dst_ip degildir). */
            snprintf(key, sizeof(key), "Y|%u|%u", pi->src_ip, pi->dst_port);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->dst_ip);
                ids_tracker_long_bump(t, pi->dst_ip);     /* [18] uzun ufuk */
                int priv = 0, pub = 0;
                for (int u = 0; u < t->unique_len; u++) {
                    if (ids_ip_is_private(t->unique[u])) priv++;
                    else pub++;
                }
                t->private_dst_count = (uint32_t)priv;
                t->public_dst_count = (uint32_t)pub;
                int wk = (pi->dst_port < 1024);
                uint32_t priv_thr = (uint32_t)((wk ? 30 : 15) * am);
                uint32_t pub_thr  = (uint32_t)((wk ? 12 : 6) * am);
                /* FP DUZELTMESI: genel (public) hedeflere WEB portlarinda
                 * (80/443/8080/8443) yatay fan-out normal istemci
                 * davranisidir - tarayicilar, guncelleyiciler ve CDN'ler
                 * onlarca farkli genel IP'ye TLS baglantisi acar. Bu durum
                 * "agda olmayan IP'lerin 443 portunda SYN taramasi"
                 * seklinde YUKSEK yanlis pozitif uretiyordu (gercek
                 * trafikle dogrulandi). Genel web hedefleri yatay tarama
                 * sayimindan MUAF tutulur; ozel (LAN) hedefler ve genel
                 * web-disi portlar (22/445/3389 vb.) eskisi gibi izlenir
                 * (brute-force kuralindaki is_web && !dst_priv muafiyetiyle
                 * ayni mantik). */
                int pub_web = (!ids_ip_is_private(pi->dst_ip) &&
                               ids_is_web_port(pi->dst_port));
                if (!pub_web &&
                    (priv >= (int)priv_thr || pub >= (int)pub_thr)) {
                    t->long_short_hit = 1;   /* [18] kisa pencere yakaladi */
                    char desc[192];
                    char s[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    snprintf(desc, sizeof(desc),
                             "%s -> %u farkli hedefe port %u SYN (yatay tarama; "
                             "%d ozel / %d genel hedef, %u paket)",
                             s, t->unique_len, pi->dst_port, priv, pub,
                             t->count);
                    ids_raise_or_update("Yatay Tarama (Ayni Port)", "YUKSEK",
                                        SCORE_YUKSEK, pi, desc,
                                        IDS_EV_THRESHOLD_MET |
                                        IDS_EV_MULTI_PORT, t);
                }
                /* Yavas yatay tarama (tek port, cok hedef):
                 * hedefler arasinda sn'lerce beklendiginde kisa pencere
                 * esigi (ozel 15 / genel 6) hic dolmuyordu. */
                if (!pub_web && ids_tracker_long_scan(t)) {
                    char ldesc[192];
                    char ls[46];
                    ids_ip_to_str(pi->src_ip, ls, sizeof(ls));
                    snprintf(ldesc, sizeof(ldesc),
                             "%s -> %u farkli hedefe YAVAS port %u taramasi "
                             "(%u paket, %d sn) - hiz sinirlamali yatay tarama",
                             ls, ids_tracker_long_unique(t), pi->dst_port,
                             t->long_count,
                             (int)(t->long_last - t->long_start));
                    ids_raise_or_update_long("Yavas Yatay Tarama (Ayni Port)",
                                             "YUKSEK", SCORE_YUKSEK, pi,
                                             ldesc,
                                             IDS_EV_THRESHOLD_MET |
                                             IDS_EV_MULTI_PORT, t);
                }
            }
        }

        /* Stealth tarama tipleri */
        if (is_fin_only) {
            snprintf(key, sizeof(key), "T|FIN|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump_port(t, pi->dst_port);
                ids_tracker_long_bump(t, pi->dst_port);   /* [18] uzun ufuk */
                if (t->count >= 15 && ids_tracker_unique(t) >= 5) {
                    t->long_short_hit = 1;   /* [18] kisa pencere yakaladi */
                    char desc[128];
                    char s[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    snprintf(desc, sizeof(desc),
                             "%s -> %u farkli porta FIN-only stealth tarama (%u paket)",
                             s, ids_tracker_unique(t), t->count);
                    ids_raise_or_update("Port Taramasi (FIN)", "YUKSEK",
                                        SCORE_YUKSEK, pi, desc, 0, t);
                }
                /* Yavas FIN-only ("stealth") taramasi:
                 * nmap -sF -T1 gibi hiz sinirlamali taramalar 10 sn'de
                 * 15 FIN paketi birakmaz; uzun ufuk bunlari yakalar. */
                if (ids_tracker_long_scan(t)) {
                    char ldesc[160];
                    char ls[46];
                    ids_ip_to_str(pi->src_ip, ls, sizeof(ls));
                    snprintf(ldesc, sizeof(ldesc),
                             "%s -> %u farkli porta YAVAS FIN-only stealth "
                             "tarama (%u paket, %d sn) - hiz sinirlamali",
                             ls, ids_tracker_long_unique(t), t->long_count,
                             (int)(t->long_last - t->long_start));
                    ids_raise_or_update_long("Yavas Port Taramasi (FIN)",
                                             "YUKSEK", SCORE_YUKSEK, pi,
                                             ldesc, 0, t);
                }
            }
        } else if (is_null) {
            snprintf(key, sizeof(key), "T|NULL|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump_port(t, pi->dst_port);
                ids_tracker_long_bump(t, pi->dst_port);   /* [18] uzun ufuk */
                if (t->count >= 15 && ids_tracker_unique(t) >= 5) {
                    t->long_short_hit = 1;   /* [18] kisa pencere yakaladi */
                    char desc[128];
                    char s[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    snprintf(desc, sizeof(desc),
                             "%s -> %u farkli porta flagsiz (NULL) stealth tarama (%u paket)",
                             s, ids_tracker_unique(t), t->count);
                    ids_raise_or_update("Port Taramasi (NULL)", "YUKSEK",
                                        SCORE_YUKSEK, pi, desc, 0, t);
                }
                /* Yavas flagsiz (NULL) tarama. */
                if (ids_tracker_long_scan(t)) {
                    char ldesc[160];
                    char ls[46];
                    ids_ip_to_str(pi->src_ip, ls, sizeof(ls));
                    snprintf(ldesc, sizeof(ldesc),
                             "%s -> %u farkli porta YAVAS flagsiz (NULL) "
                             "stealth tarama (%u paket, %d sn) - hiz sinirlamali",
                             ls, ids_tracker_long_unique(t), t->long_count,
                             (int)(t->long_last - t->long_start));
                    ids_raise_or_update_long("Yavas Port Taramasi (NULL)",
                                             "YUKSEK", SCORE_YUKSEK, pi,
                                             ldesc, 0, t);
                }
            }
        } else if (is_xmas) {
            snprintf(key, sizeof(key), "T|XMAS|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump_port(t, pi->dst_port);
                ids_tracker_long_bump(t, pi->dst_port);   /* [18] uzun ufuk */
                if (t->count >= 15 && ids_tracker_unique(t) >= 5) {
                    t->long_short_hit = 1;   /* [18] kisa pencere yakaladi */
                    char desc[128];
                    char s[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    snprintf(desc, sizeof(desc),
                             "%s -> %u farkli porta FIN+PSH+URG (Xmas) stealth tarama (%u paket)",
                             s, ids_tracker_unique(t), t->count);
                    ids_raise_or_update("Port Taramasi (Xmas)", "YUKSEK",
                                        SCORE_YUKSEK, pi, desc, 0, t);
                }
                /* Yavas Xmas tarama. */
                if (ids_tracker_long_scan(t)) {
                    char ldesc[160];
                    char ls[46];
                    ids_ip_to_str(pi->src_ip, ls, sizeof(ls));
                    snprintf(ldesc, sizeof(ldesc),
                             "%s -> %u farkli porta YAVAS FIN+PSH+URG (Xmas) "
                             "stealth tarama (%u paket, %d sn) - hiz sinirlamali",
                             ls, ids_tracker_long_unique(t), t->long_count,
                             (int)(t->long_last - t->long_start));
                    ids_raise_or_update_long("Yavas Port Taramasi (Xmas)",
                                             "YUKSEK", SCORE_YUKSEK, pi,
                                             ldesc, 0, t);
                }
            }
        }

        /* Bogus bayrak kombinasyonlari (TCP yiginlari kabul etmez) */
        if (pi->tcp_flags == 0x03 || pi->tcp_flags == 0x05 ||
            pi->tcp_flags == 0x06) {
            const char *bogus = "SYN+FIN";
            if (pi->tcp_flags == 0x05)      bogus = "FIN+RST";
            else if (pi->tcp_flags == 0x06) bogus = "SYN+RST";
            snprintf(key, sizeof(key), "W|%02x|%u", pi->tcp_flags, pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, ids_hash_unique(pi->dst_ip, pi->dst_port));
                if (t->count >= 4 && t->unique_len >= 2 && ids_tracker_can_alert(t)) {
                    char desc[128];
                    char sig[64];
                    char s[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    snprintf(sig, sizeof(sig), "Bogus Bayrak (%s)", bogus);
                    snprintf(desc, sizeof(desc),
                             "%s tarafindan %u farkli hedef/porta %s bayrakli %u paket",
                             s, t->unique_len, bogus, t->count);
                    ids_raise_alert(sig, "ORTA", SCORE_ORTA, pi, desc);
                }
            }
        }
    }

    /* ---------- 4. UDP tarama / flood ---------- */
    if (pi->is_udp) {
        /* DNS cevaplari (kaynak port 53 -> yuksek hedef port) tarama gibi
         * gorunup yanlis pozitif uretiyordu; sayac yalnizca dusuk hedef
         * porta giden ve DNS kaynagi olmayan paketlerle beslenir. */
        if (pi->dst_port < 1024 && pi->src_port != 53) {
            snprintf(key, sizeof(key), "U|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump_port(t, pi->dst_port);
                ids_tracker_long_bump(t, pi->dst_port);   /* [18] uzun ufuk */
                if (t->count >= 15 && ids_tracker_unique(t) >= 8 &&
                    ids_tracker_can_alert(t)) {
                    t->long_short_hit = 1;   /* [18] kisa pencere yakaladi */
                    ids_raise_alert("UDP Port Taramasi", "ORTA", SCORE_ORTA, pi,
                                    "Tek kaynaktan cok sayida farkli UDP portuna paket");
                }
                if (t->count >= 200 && ids_tracker_unique(t) >= 10 &&
                    ids_tracker_can_alert(t))
                    ids_raise_alert("UDP Flood", "ORTA", SCORE_ORTA, pi,
                                    "Tek kaynaktan asiri UDP trafigi");
                /* Yavas UDP taramasi (nmap -sU -T1 gibi):
                 * 10 sn'de 15 paket/8 port esigi dolmaz, tarama gorunmezdi. */
                if (ids_tracker_long_scan(t)) {
                    char ldesc[160];
                    char ls[46];
                    ids_ip_to_str(pi->src_ip, ls, sizeof(ls));
                    snprintf(ldesc, sizeof(ldesc),
                             "%s -> %u farkli UDP portuna YAVAS tarama "
                             "(%u paket, %d sn) - hiz sinirlamali",
                             ls, ids_tracker_long_unique(t), t->long_count,
                             (int)(t->long_last - t->long_start));
                    ids_raise_or_update_long("Yavas UDP Port Taramasi", "ORTA",
                                             SCORE_ORTA, pi, ldesc, 0, t);
                }
            }
        }

        /* DNS anomali: tek kaynaktan aşırı sorgu.
         *  Esik 50 -> 150, sev ORTA -> DUSUK: normal aglarda
         * sistem/yedekleme trafigi tek kaynaktan yuzlerce sorgu uretebilir. */
        if (pi->is_dns && pi->dst_port == 53) {
            /* Yalnizca gercek DNS (53) sayilir. mDNS (5353) parse sirasinda
             * is_dns=1 aliyor; yerel multicast kesif sorgularinin DNS
             * anomali/tunneling sayacina sizmasi FP uretiyordu. */
            snprintf(key, sizeof(key), "D|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, 0);
                if (t->count >= 150 && ids_tracker_can_alert(t))
                    ids_raise_alert_ev("DNS Anomali", "DUSUK", SCORE_DUSUK, pi,
                                       "Tek kaynaktan asiri DNS sorgusu (tunneling/flood?)",
                                       IDS_EV_REPEATED);
            }
        }
    }

    /* ---------- 5. ICMP flood / ping sweep ----------
     * Ping sweep sayaci yalniz yerel (RFC1918) hedeflere beslenir; dis IP'lere
     * tek tek ping (8.8.8.8 erisim testleri) tarama sayilmaz. Sweep esigi 20,
     * flood esigi 300'dur (monitoring araclari da ICMP uretir). */
    if (pi->is_icmp) {
        if (ids_ip_is_private(pi->dst_ip)) {
            snprintf(key, sizeof(key), "I|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->dst_ip);
                ids_tracker_long_bump(t, pi->dst_ip);     /* [18] uzun ufuk */
                if (t->unique_len >= 20 && ids_tracker_can_alert(t)) {
                    t->long_short_hit = 1;   /* [18] kisa pencere yakaladi */
                    ids_raise_alert("Ping Sweep", "ORTA", SCORE_ORTA, pi,
                                    "Tek kaynaktan cok sayida farkli yerel hedefe ICMP (ag kesfi)");
                }
                /* Yavas ping sweep: hedefler arasinda
                 * sn'lerce beklenen ag kesfi (nmap -sn --max-rate 1). */
                if (ids_tracker_long_scan(t)) {
                    char ldesc[160];
                    char ls[46];
                    ids_ip_to_str(pi->src_ip, ls, sizeof(ls));
                    snprintf(ldesc, sizeof(ldesc),
                             "%s -> %u farkli yerel hedefe YAVAS ICMP "
                             "(ping sweep) (%u paket, %d sn) - hiz sinirlamali",
                             ls, ids_tracker_long_unique(t), t->long_count,
                             (int)(t->long_last - t->long_start));
                    ids_raise_or_update_long("Yavas Ping Sweep", "ORTA",
                                             SCORE_ORTA, pi, ldesc, 0, t);
                }
            }
        }
        snprintf(key, sizeof(key), "IF|%u", pi->src_ip);
        t = ids_tracker_get(key);
        if (t) {
            ids_tracker_bump(t, 0);
            if (t->count >= 300 && ids_tracker_can_alert(t))
                ids_raise_alert("ICMP Flood", "ORTA", SCORE_ORTA, pi,
                                "Tek kaynaktan asiri ICMP trafigi");
        }
    }

    /* ---------- 6. Broadcast / multicast storm ---------- */
    if (pi->is_broadcast || pi->is_multicast) {
        t = ids_tracker_get("B");
        if (t) {
            ids_tracker_bump(t, 0);
            /* 150 -> 500: ARP/NetBIOS/mDNS gibi normal
             * keşif protokolleri surekli broadcast uretir. */
            if (t->count >= 500 && ids_tracker_can_alert(t))
                ids_raise_alert("Broadcast Storm", "ORTA", SCORE_ORTA, pi,
                                "Asiri broadcast/multicast trafigi (ag yavaslamasi)");
        }
    }

    /* ---------- 7. L7 payload imza taramasi ---------- */
    ids_check_payload(pi);
}

/* ==================================================================
 *   IZLEME KAPSAMI (scope) — gui.c'deki izleme listesinin motor kopyasi.
 *   Bos kapsam = hicbir paket islenmez; dolu kapsam = yalniz listedeki
 *   IP'lere ait paketler islenir (IPv4 src/dst, ARP sender/target).
 * ================================================================== */
#define IDS_SCOPE_IP_STR 16
static char g_scope_ips[IDS_SCOPE_MAX][IDS_SCOPE_IP_STR];
static int  g_scope_count = 0;

static int ids_scope_has(uint32_t ip) {
    char s[IDS_SCOPE_IP_STR];
    ids_ip_to_str(ip, s, sizeof(s));
    for (int i = 0; i < g_scope_count; i++)
        if (strcmp(g_scope_ips[i], s) == 0) return 1;
    return 0;
}

static int ids_scope_allows(const IdsPktInfo *pi) {
    int ok = 0;
    platform_mutex_lock(&g_ids_lock);
    if (g_scope_count > 0) {
        if (ids_scope_has(pi->src_ip) || ids_scope_has(pi->dst_ip)) ok = 1;
        else if (pi->is_arp &&
                 (ids_scope_has(pi->arp_sender_ip) ||
                  ids_scope_has(pi->arp_target_ip))) ok = 1;
    }
    platform_mutex_unlock(&g_ids_lock);
    return ok;
}

void ids_scope_set(const char *ips[], int n) {
    platform_mutex_lock(&g_ids_lock);
    g_scope_count = 0;
    memset(g_scope_ips, 0, sizeof(g_scope_ips));
    if (ips && n > 0) {
        for (int i = 0; i < n && g_scope_count < IDS_SCOPE_MAX; i++) {
            if (!ips[i] || !ips[i][0]) continue;
            unsigned a = 0, b = 0, c = 0, d = 0;
            if (sscanf(ips[i], "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
                a <= 255 && b <= 255 && c <= 255 && d <= 255) {
                strncpy(g_scope_ips[g_scope_count], ips[i],
                        IDS_SCOPE_IP_STR - 1);
                g_scope_ips[g_scope_count][IDS_SCOPE_IP_STR - 1] = '\0';
                g_scope_count++;
            }
        }
    }
    platform_mutex_unlock(&g_ids_lock);
}

void ids_scope_clear(void) {
    platform_mutex_lock(&g_ids_lock);
    g_scope_count = 0;
    memset(g_scope_ips, 0, sizeof(g_scope_ips));
    platform_mutex_unlock(&g_ids_lock);
}

/* ==================================================================
 *   PUBLIC API
 * ================================================================== */

void ids_init(void) {
    if (g_ids_initialized) return;
    platform_mutex_init(&g_ids_lock);
    memset(&g_ids, 0, sizeof(g_ids));
    memset(g_alert_buf, 0, sizeof(g_alert_buf));
    g_alert_count = 0;
    memset(g_trackers, 0, sizeof(g_trackers));
    g_tracker_count = 0;
    memset(g_dedup, 0, sizeof(g_dedup));
    g_dedup_count = 0;
    memset(g_malport, 0, sizeof(g_malport));
    g_malport_count = 0;
    g_ids.suppressed_fps = 0;
    memset(g_bindings, 0, sizeof(g_bindings));
    g_binding_count = 0;
    memset(g_local_mac, 0, sizeof(g_local_mac));
    memset(g_gateway_mac, 0, sizeof(g_gateway_mac));
    g_gateway_mac_valid = 0;
    g_gateway_ip = 0;
    g_local_ip = 0;
    /* LAN katmanı */
    memset(g_flows, 0, sizeof(g_flows));
    g_flow_count = 0;
    memset(g_hosts, 0, sizeof(g_hosts));
    g_host_count = 0;
    memset(g_name_pending, 0, sizeof(g_name_pending));
    g_name_pending_count = 0;
    memset(g_incidents, 0, sizeof(g_incidents));
    g_incident_count = 0;
    g_ids.incident_count = 0;
    g_net_base = 0;
    g_net_mask = 0;
    g_net_range_set = 0;
    g_last_flow_analysis = 0;
    g_ids.active_flows = 0;
    g_ids.host_count = 0;
    g_ids.running = 1;
    g_ids.rule_count = 20;
    /* Izleme kapsami varsayilan: BOS = hicbir sey izlenmez. GUI listesi
     * bos oldugu surece IDS pasif kalir. */
    g_scope_count = 0;
    memset(g_scope_ips, 0, sizeof(g_scope_ips));
    g_ids_initialized = 1;
}

void ids_cleanup(void) {
    if (!g_ids_initialized) return;
    g_ids.running = 0;
    /* Port bitmap'leri malloc'lu: serbest birak. */
    for (int i = 0; i < g_tracker_count; i++) {
        if (g_trackers[i].unique_bits) {
            free(g_trackers[i].unique_bits);
            g_trackers[i].unique_bits = NULL;
        }
        /* uzun ufuk bitmap'i de serbest birakilir. */
        if (g_trackers[i].long_bits) {
            free(g_trackers[i].long_bits);
            g_trackers[i].long_bits = NULL;
        }
    }
    platform_mutex_destroy(&g_ids_lock);
    g_ids_initialized = 0;
}

/* Lokal kaynakli (self) SYN taramasi: kendi makinemizden disariya port
 * taramasi genel kurallara takilmaz (self trafik FP onlemek icin bastirilir).
 * Bu kural yalnizca TCP SYN sayar; ayni kaynaktan cok sayida FARKLI hedef
 * porta SYN gidince uyarir. Normal tarayici 2-3 porta dokunur. */
static void ids_check_local_scan(const IdsPktInfo *pi) {
    char key[64];
    IdsTracker *t;
    if (!pi->is_tcp) return;
    int is_syn = (pi->tcp_flags & 0x02) && !(pi->tcp_flags & 0x10);
    if (!is_syn) return;
    snprintf(key, sizeof(key), "L|%u", pi->src_ip);
    t = ids_tracker_get(key);
    if (t) {
        ids_tracker_bump_port(t, pi->dst_port);
        ids_tracker_long_bump(t, pi->dst_port);           /* [18] uzun ufuk */
        /* Esik yalnizca unique_len uzerinde tutulur: retransmit'siz 8/15 SYN
         * birakan nmap 'count >= 16' kosulunu saglayamiyordu (dogrulanmis
         * yanlis negatif). count her zaman unique_len'den buyuktur; ayrica
         * count esigi gereksiz ve zararlidir. */
        if (ids_tracker_unique(t) >= 8) {
            t->long_short_hit = 1;   /* [18] kisa pencere yakaladi */
            char desc[128];
            char s[46];
            ids_ip_to_str(pi->src_ip, s, sizeof(s));
            snprintf(desc, sizeof(desc),
                     "%s -> %u farkli porta disari SYN taramasi (%u paket)",
                     s, ids_tracker_unique(t), t->count);
            /* Tarama surerken sayilar buyur; uyari METNI guncel kalir. */
            ids_raise_or_update("Yerel Kaynakli Port Taramasi", "YUKSEK",
                                SCORE_YUKSEK, pi, desc, 0, t);
        }
        /* --- UZUN UFUK: yavas (hiz sinirlamali) tarama ---
         * `nmap --scan-delay 1.5s` her kisa pencereye en cok 7 farkli port
         * birakir; L| kurali (8 port) hic tetiklenmezdi — yavaslatmak kacmanin
         * yolu olmustu. Uzun ufuk, kisa pencere tetiklenmediyse ve gozlem suresi
         * min_span'i gectiyse uyarir; patlamalar cift raporlanmaz. */
        if (ids_tracker_long_scan(t)) {
            char ldesc[160];
            char ls[46];
            ids_ip_to_str(pi->src_ip, ls, sizeof(ls));
            snprintf(ldesc, sizeof(ldesc),
                     "%s -> %u farkli porta YAVAS disari SYN taramasi "
                     "(%u paket, %d sn) - hiz sinirlamali tarama",
                     ls, ids_tracker_long_unique(t), t->long_count,
                     (int)(t->long_last - t->long_start));
            ids_raise_or_update_long("Yavas Port Taramasi (Yerel Kaynakli)",
                                     "YUKSEK", SCORE_YUKSEK, pi, ldesc, 0, t);
        }
    }
}

void ids_process_packet(const PacketRecord *pkt) {
    if (!g_ids.running || !pkt) return;

    IdsPktInfo pi;
    ids_parse_pkt(pkt, &pi);
    if (!pi.is_ipv4 && !pi.is_arp) return;

    /* IZLEME KAPSAMI: bos liste = izleme kapali (hicbir paket islenmez);
     * dolu liste = yalnizca listedeki IP'lere ait paketler geciyor. */
    if (!ids_scope_allows(&pi)) return;

    /* LAN katmanı: kendi ürettiğimiz trafik dahil TÜM trafiği akış
     * tablosuna işle — Tehdit Haritası ağ geneli görüşe dayanır. */
    ids_flow_update(&pi, pkt);
    ids_flow_analysis();

    int self_pkt = ids_is_self_originated(&pi);

    /* Self SYN-ACK istisnasi: kendi dinleyicimizin SYN-ACK cevaplari self
     * filtresine takilip synack_seen kaniti toplanamiyor, uyari dakikalar
     * sonra karsi taraftan veri gelince cikiyordu. SYN-ACK'ler self olsa bile
     * dinleme motoruna beslenir. */
    if (self_pkt && pi.is_tcp && ((pi.tcp_flags & 0x12) == 0x12))
        ids_malport_feed(&pi);

    /* Kendi urettigimiz trafik genel kurallari tetiklemesin: otomatik
     * ARP/ping taramasi ve fallback sentetik cerceveler alarm tablosunu
     * dolduruyordu; ama disariya yaptigimiz taramalar da tespit edilsin —
     * self trafikte yalnizca ids_check_local_scan() calisir. */
    if (self_pkt) {
        ids_check_local_scan(&pi);
        return;
    }

    g_ids.total_pkts_processed++;
    ids_learn_binding(&pi);
    ids_check_rules(&pi);
    g_ids.active_trackers = g_tracker_count;
}

int ids_get_alerts_snapshot(IdsGuiAlert *out, int max_count) {
    if (!out || max_count <= 0) return 0;
    platform_mutex_lock(&g_ids_lock);
    int n = (g_alert_count < max_count) ? g_alert_count : max_count;
    for (int i = 0; i < n; i++) out[i] = g_alert_buf[i];
    platform_mutex_unlock(&g_ids_lock);
    return n;
}

void ids_clear_alerts(void) {
    platform_mutex_lock(&g_ids_lock);
    memset(g_alert_buf, 0, sizeof(g_alert_buf));
    g_alert_count = 0;
    platform_mutex_unlock(&g_ids_lock);
}

/* Tek bir uyariyi dizinden siler; sonraki kayitlari bir sola kaydirir.
 * Dizini 0..g_alert_count-1 arasinda olmali (GUI snapshot indeksi). */
int ids_remove_alert(int index) {
    int ok = 0;
    platform_mutex_lock(&g_ids_lock);
    if (index >= 0 && index < g_alert_count) {
        if (index + 1 < g_alert_count) {
            memmove(&g_alert_buf[index], &g_alert_buf[index + 1],
                    sizeof(IdsGuiAlert) * (g_alert_count - index - 1));
        }
        g_alert_count--;
        memset(&g_alert_buf[g_alert_count], 0, sizeof(IdsGuiAlert));
        ok = 1;
    }
    platform_mutex_unlock(&g_ids_lock);
    return ok;
}

/* ---- SOC v3: kill chain asamasi (imza adindan) ---- */
static int ids_killchain_for_sig(const char *sig) {
    if (!sig) return 2;
    if (strstr(sig, "Tarama") || strstr(sig, "Sweep") || strstr(sig, "Scan"))
        return 1;   /* kesif */
    if (strstr(sig, "DGA") || strstr(sig, "Tunel") || strstr(sig, "C2") ||
        strstr(sig, "Komut") || strstr(sig, "Botnet"))
        return 3;   /* C2 / etki */
    return 2;       /* sizma */
}

/* Ayni saldirgan->kurban ciftini 600 sn pencerede birlestir (32 kayit) */
static void ids_incident_update(uint32_t att, uint32_t vic, const char *sig,
                                const char *sev, double score) {
    if (!att || !vic) return;
    time_t now = time(NULL);
    for (int i = 0; i < g_incident_count; i++) {
        IdsIncidentInt *ic = &g_incidents[i];
        if (ic->attacker == att && ic->victim == vic) {
            if (now - ic->last_seen > 600) continue;   /* yeni pencere */
            ic->alert_count++;
            ic->flags |= ids_sig_flags(sig);
            if (score > ic->max_score) ic->max_score = score;
            if (sev) strncpy(ic->worst_severity, sev,
                             sizeof(ic->worst_severity) - 1);
            strncpy(ic->last_sig, sig, sizeof(ic->last_sig) - 1);
            int kc = ids_killchain_for_sig(sig);
            if (kc > ic->killchain) ic->killchain = kc;
            ic->last_seen = now;
            return;
        }
    }
    if (g_incident_count < IDS_MAX_INCIDENTS) {
        IdsIncidentInt *ic = &g_incidents[g_incident_count++];
        memset(ic, 0, sizeof(*ic));
        ic->attacker = att;
        ic->victim = vic;
        ic->alert_count = 1;
        ic->flags = ids_sig_flags(sig);
        ic->killchain = ids_killchain_for_sig(sig);
        ic->max_score = score;
        if (sev) strncpy(ic->worst_severity, sev,
                         sizeof(ic->worst_severity) - 1);
        strncpy(ic->last_sig, sig, sizeof(ic->last_sig) - 1);
        ic->first_seen = ic->last_seen = now;
    }
}

/* En son gorulen once (snapshot siralama) */
static int ids_incident_cmp_last(const void *a, const void *b) {
    const IdsIncident *ia = (const IdsIncident *)a;
    const IdsIncident *ib = (const IdsIncident *)b;
    if (ia->last_seen != ib->last_seen)
        return ia->last_seen > ib->last_seen ? -1 : 1;
    return 0;
}

int ids_get_incidents_snapshot(IdsIncident *out, int max_count) {
    if (!out || max_count <= 0) return 0;
    platform_mutex_lock(&g_ids_lock);
    int n = (g_incident_count < max_count) ? g_incident_count : max_count;
    for (int i = 0; i < n; i++) {
        IdsIncidentInt *ic = &g_incidents[i];
        ids_ip_to_str(ic->attacker, out[i].attacker_ip,
                      sizeof(out[i].attacker_ip));
        ids_ip_to_str(ic->victim, out[i].victim_ip,
                      sizeof(out[i].victim_ip));
        out[i].alert_count = ic->alert_count;
        out[i].flags = ic->flags;
        out[i].killchain = ic->killchain;
        strncpy(out[i].worst_severity, ic->worst_severity,
                sizeof(out[i].worst_severity) - 1);
        out[i].max_score = ic->max_score;
        strncpy(out[i].last_sig, ic->last_sig, sizeof(out[i].last_sig) - 1);
        out[i].first_seen = ic->first_seen;
        out[i].last_seen = ic->last_seen;
    }
    qsort(out, n, sizeof(IdsIncident), ids_incident_cmp_last);
    g_ids.incident_count = (uint32_t)n;
    platform_mutex_unlock(&g_ids_lock);
    return n;
}

/* Uyari triyaji: durum guncelle (index/durum gecersizse 0) */
int ids_set_alert_status(int index, int status) {
    if (index < 0 || index >= g_alert_count) return 0;
    if (status < IDS_ALERT_STATUS_NEW || status > IDS_ALERT_STATUS_FALSEPOS)
        return 0;
    platform_mutex_lock(&g_ids_lock);
    g_alert_buf[index].status = status;
    platform_mutex_unlock(&g_ids_lock);
    return 1;
}

/* Uyari triyaji: analist notu yaz */
int ids_set_alert_note(int index, const char *note) {
    if (index < 0 || index >= g_alert_count) return 0;
    if (!note) return 0;
    platform_mutex_lock(&g_ids_lock);
    strncpy(g_alert_buf[index].note, note,
            sizeof(g_alert_buf[index].note) - 1);
    platform_mutex_unlock(&g_ids_lock);
    return 1;
}

void ids_set_mac_context(const char *local_mac, const char *gateway_mac,
                         const char *gateway_ip, const char *local_ip) {
    unsigned int b[6];
    if (gateway_mac && sscanf(gateway_mac, "%x:%x:%x:%x:%x:%x",
                              &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
        for (int i = 0; i < 6; i++) g_gateway_mac[i] = (uint8_t)b[i];
        g_gateway_mac_valid = 1;
    }
    if (local_mac && sscanf(local_mac, "%x:%x:%x:%x:%x:%x",
                            &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
        for (int i = 0; i < 6; i++) g_local_mac[i] = (uint8_t)b[i];
    }
    if (gateway_ip) {
        unsigned int a, c, d, e;
        if (sscanf(gateway_ip, "%u.%u.%u.%u", &a, &c, &d, &e) == 4)
            g_gateway_ip = (a << 24) | (c << 16) | (d << 8) | e;
    }
    if (local_ip) {
        unsigned int a, c, d, e;
        if (sscanf(local_ip, "%u.%u.%u.%u", &a, &c, &d, &e) == 4)
            g_local_ip = (a << 24) | (c << 16) | (d << 8) | e;
    }

    /* Kapsam: acikca CIDR verilmediyse yerel IP'den sinifli agi turet.
     * Boylece LAN tespiti 'Aga Tara' sonucuna bagimli kalmaz; izleme
     * baslar baslamaz dogru alt ag kapsami hazirdir. */
    if (!g_net_range_set && g_local_ip) {
        uint8_t a = (uint8_t)(g_local_ip >> 24);
        uint8_t b = (uint8_t)(g_local_ip >> 16);
        uint32_t bits = 24;
        if (a == 10) bits = 8;
        else if (a == 172 && b >= 16 && b <= 31) bits = 12;
        else if (a == 192 && b == 168) bits = 16;
        g_net_mask = (bits == 32) ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - bits));
        g_net_base = g_local_ip & g_net_mask;
        g_net_range_set = 1;
    }

    /* Binding map'ine guvenilir taban kayitlarini ekle */
    if (g_gateway_ip && g_gateway_mac_valid)
        ids_binding_seed(g_gateway_ip, g_gateway_mac);
    if (g_local_ip && !ids_mac_zero(g_local_mac))
        ids_binding_seed(g_local_ip, g_local_mac);
}





