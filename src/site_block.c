/*
 * site_block.c — "Site Karartma" motoru.
 *
 * network_monitor'un dissector'i her karede app_domain/domain_kind alanlarini
 * doldurur. Bu motor:
 *   1. Yabanci (kurticidan gelen) karelerdeki alan adlarini gozler
 *   2. Aktif kurallarla (IP + alan adi) eslestirir
 *   3. DNS sinkhole / TCP RST / QUIC ICMP unreachable enjekte eder
 *
 * Enjeksiyon raw_inject uzerinden yapilir; test sirasinda sink kancasi ile
 * gercek gonderim engellenir.
 */
#include "site_block.h"
#include "raw_inject.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* ==================================================================
 *   Durum
 * ================================================================== */

static int  sb_inited = 0;
static platform_mutex_t sb_lock;

static SiteBlockRule sb_rules[SB_MAX_RULES];
static int  sb_rule_count = 0;

static SiteBlockObs  sb_obs[SB_OBS_MAX];
static int  sb_obs_count = 0;

static SiteBlockStats sb_stats;

static char sb_scope[128][SB_IP_LEN];
static int  sb_scope_count = 0;

static char sb_iface[64] = {0};
static unsigned char sb_own_mac[6];
static int  sb_own_mac_valid = 0;
static char sb_own_ip[SB_IP_LEN] = {0};
static unsigned char sb_gw_mac[6];
static int  sb_gw_mac_valid = 0;

static RawInject sb_ri;
static int  sb_enabled = 1;
static char sb_sinkhole_ip[SB_IP_LEN] = "0.0.0.0";

/* Test kancasi */
static RawInjectSink sb_test_sink = NULL;
static void *sb_test_sink_ud = NULL;
static int   sb_test_raw_ok = 0;

static double sb_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ==================================================================
 *   Yasam dongusu
 * ================================================================== */

void site_block_init(void) {
    if (sb_inited) return;
    memset(sb_rules, 0, sizeof(sb_rules));
    memset(sb_obs, 0, sizeof(sb_obs));
    memset(&sb_stats, 0, sizeof(sb_stats));
    memset(sb_scope, 0, sizeof(sb_scope));
    memset(sb_own_mac, 0, sizeof(sb_own_mac));
    memset(sb_gw_mac, 0, sizeof(sb_gw_mac));
    memset(&sb_ri, 0, sizeof(sb_ri));
    sb_ri.fd = -1;
    sb_rule_count = 0;
    sb_obs_count = 0;
    sb_scope_count = 0;
    sb_own_mac_valid = 0;
    sb_gw_mac_valid = 0;
    sb_own_ip[0] = '\0';
    sb_iface[0] = '\0';
    sb_enabled = 1;
    strncpy(sb_sinkhole_ip, "0.0.0.0", sizeof(sb_sinkhole_ip) - 1);
    platform_mutex_init(&sb_lock);
    sb_inited = 1;
}

void site_block_cleanup(void) {
    if (!sb_inited) return;
    raw_inject_close(&sb_ri);
    platform_mutex_destroy(&sb_lock);
    sb_inited = 0;
}

/* ==================================================================
 *   Ag baglami
 * ================================================================== */

static void sb_ensure_raw(void) {
    if (sb_ri.ok) return;
    if (!sb_iface[0]) return;
    if (raw_inject_init(&sb_ri, sb_iface) == 0) {
        if (!sb_own_mac_valid && sb_ri.own_mac[0] | sb_ri.own_mac[1] |
            sb_ri.own_mac[2] | sb_ri.own_mac[3] | sb_ri.own_mac[4] | sb_ri.own_mac[5]) {
            memcpy(sb_own_mac, sb_ri.own_mac, 6);
            sb_own_mac_valid = 1;
        }
        fprintf(stderr, "[SITE_BLOCK] Ham enjeksiyon soketi hazir: %s\n", sb_iface);
    } else {
        fprintf(stderr, "[SITE_BLOCK] Ham soket acilamadi (%s) — "
                        "site karartma enjeksiyonu devre disi\n", sb_iface);
    }
    if (sb_test_sink) raw_inject_set_sink(&sb_ri, sb_test_sink, sb_test_sink_ud);
}

void site_block_set_iface(const char *iface) {
    if (!sb_inited) site_block_init();
    if (!iface || !iface[0] || strcmp(iface, "any") == 0) return;
    platform_mutex_lock(&sb_lock);
    if (strcmp(sb_iface, iface) != 0) {
        if (sb_ri.ok) { raw_inject_close(&sb_ri); }
        strncpy(sb_iface, iface, sizeof(sb_iface) - 1);
        sb_iface[sizeof(sb_iface) - 1] = '\0';
        sb_ensure_raw();
    }
    platform_mutex_unlock(&sb_lock);
}

void site_block_set_own_mac(const unsigned char mac[6]) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    memcpy(sb_own_mac, mac, 6);
    sb_own_mac_valid = 1;
    platform_mutex_unlock(&sb_lock);
}

void site_block_set_own_ip(const char *ip) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    if (ip) { strncpy(sb_own_ip, ip, sizeof(sb_own_ip) - 1); sb_own_ip[sizeof(sb_own_ip) - 1] = '\0'; }
    else sb_own_ip[0] = '\0';
    platform_mutex_unlock(&sb_lock);
}

void site_block_set_gateway_mac(const unsigned char mac[6]) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    memcpy(sb_gw_mac, mac, 6);
    sb_gw_mac_valid = 1;
    platform_mutex_unlock(&sb_lock);
}

int site_block_raw_ready(void) {
    if (!sb_inited) return 0;
    if (sb_test_raw_ok) return 1;
    return sb_ri.ok ? 1 : 0;
}

/* ==================================================================
 *   Global kontrol
 * ================================================================== */

void site_block_set_enabled(int on) {
    if (!sb_inited) site_block_init();
    sb_enabled = on ? 1 : 0;
}
int site_block_is_enabled(void) {
    if (!sb_inited) return 0;
    return sb_enabled;
}

void site_block_set_sinkhole_ip(const char *ip) {
    if (!sb_inited) site_block_init();
    if (!ip || !ip[0]) return;
    platform_mutex_lock(&sb_lock);
    strncpy(sb_sinkhole_ip, ip, sizeof(sb_sinkhole_ip) - 1);
    sb_sinkhole_ip[sizeof(sb_sinkhole_ip) - 1] = '\0';
    platform_mutex_unlock(&sb_lock);
}
const char *site_block_get_sinkhole_ip(void) { return sb_sinkhole_ip; }

/* ==================================================================
 *   Kapsam (izleme listesi)
 * ================================================================== */

void site_block_set_scope(const char *ips[], int n) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    sb_scope_count = 0;
    if (ips) {
        for (int i = 0; i < n && sb_scope_count < 128; i++) {
            if (!ips[i] || !ips[i][0]) continue;
            strncpy(sb_scope[sb_scope_count], ips[i], SB_IP_LEN - 1);
            sb_scope[sb_scope_count][SB_IP_LEN - 1] = '\0';
            sb_scope_count++;
        }
    }
    platform_mutex_unlock(&sb_lock);
}

void site_block_clear_scope(void) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    sb_scope_count = 0;
    platform_mutex_unlock(&sb_lock);
}

int site_block_scope_contains(const char *ip) {
    if (!ip || !ip[0]) return 0;
    if (sb_scope_count == 0) return 1;         /* bos kapsam = tum ag */
    for (int i = 0; i < sb_scope_count; i++)
        if (strcmp(sb_scope[i], ip) == 0) return 1;
    return 0;
}

/* ==================================================================
 *   Kural yonetimi
 * ================================================================== */

static void sb_norm_domain(const char *in, char *out, int out_len) {
    if (!out || out_len <= 0) return;
    out[0] = '\0';
    if (!in) return;
    int k = 0;
    for (const char *p = in; *p && k < out_len - 1; p++) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        out[k++] = c;
    }
    out[k] = '\0';
    while (k > 0 && (out[k - 1] == '.' || out[k - 1] == ' ')) out[--k] = '\0';
}

static int sb_valid_mode(int mode) {
    return (mode == SB_MODE_SINKHOLE || mode == SB_MODE_RST || mode == SB_MODE_BOTH) ? 1 : 0;
}

int site_block_add_rule(const char *ip, const char *domain, int mode) {
    if (!sb_inited) site_block_init();
    if (!domain || !domain[0]) return -1;
    if (!ip || !ip[0]) ip = "*";
    if (!sb_valid_mode(mode)) mode = SB_MODE_BOTH;

    char ndom[SB_DOMAIN_LEN];
    sb_norm_domain(domain, ndom, sizeof(ndom));
    if (!ndom[0]) return -1;

    platform_mutex_lock(&sb_lock);
    /* Ayni (ip, domain) varsa modunu guncelle */
    for (int i = 0; i < sb_rule_count; i++) {
        if (strcmp(sb_rules[i].ip, ip) == 0 && strcmp(sb_rules[i].domain, ndom) == 0) {
            sb_rules[i].mode = mode;
            sb_rules[i].enabled = 1;
            platform_mutex_unlock(&sb_lock);
            return i;
        }
    }
    if (sb_rule_count >= SB_MAX_RULES) { platform_mutex_unlock(&sb_lock); return -1; }
    SiteBlockRule *r = &sb_rules[sb_rule_count];
    memset(r, 0, sizeof(*r));
    strncpy(r->ip, ip, SB_IP_LEN - 1);
    strncpy(r->domain, ndom, SB_DOMAIN_LEN - 1);
    r->mode = mode;
    r->enabled = 1;
    int idx = sb_rule_count++;
    platform_mutex_unlock(&sb_lock);
    return idx;
}

int site_block_remove_rule(int index) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    if (index < 0 || index >= sb_rule_count) { platform_mutex_unlock(&sb_lock); return -1; }
    for (int i = index; i < sb_rule_count - 1; i++) sb_rules[i] = sb_rules[i + 1];
    sb_rule_count--;
    platform_mutex_unlock(&sb_lock);
    return 0;
}

void site_block_clear_rules(void) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    sb_rule_count = 0;
    platform_mutex_unlock(&sb_lock);
}

int site_block_rule_count(void) { return sb_inited ? sb_rule_count : 0; }

int site_block_get_rule(int index, SiteBlockRule *out) {
    if (!sb_inited || !out) return -1;
    platform_mutex_lock(&sb_lock);
    if (index < 0 || index >= sb_rule_count) { platform_mutex_unlock(&sb_lock); return -1; }
    *out = sb_rules[index];
    platform_mutex_unlock(&sb_lock);
    return 0;
}

/* Alan adi eslesmesi: "*" (tum), "*.x" (x + alt alanlari), "x" (x + alt). */
static int sb_domain_match(const char *rule, const char *domain) {
    if (!rule || !domain || !domain[0]) return 0;
    if (strcmp(rule, "*") == 0) return 1;
    const char *base = rule;
    if (rule[0] == '*' && rule[1] == '.') base = rule + 2;
    if (strcmp(domain, base) == 0) return 1;
    size_t bl = strlen(base);
    size_t dl = strlen(domain);
    if (dl > bl && strcmp(domain + (dl - bl), base) == 0 && domain[dl - bl - 1] == '.')
        return 1;
    return 0;
}

int site_block_match(const char *ip, const char *domain, SiteBlockRule *out) {
    if (!sb_inited || !domain || !domain[0]) return 0;
    if (!ip || !ip[0]) ip = "";
    int found = 0;
    platform_mutex_lock(&sb_lock);
    for (int i = 0; i < sb_rule_count; i++) {
        SiteBlockRule *r = &sb_rules[i];
        if (!r->enabled) continue;
        if (strcmp(r->ip, "*") != 0 && strcmp(r->ip, ip) != 0) continue;
        if (!sb_domain_match(r->domain, domain)) continue;
        if (out) *out = *r;
        found = 1;
        break;
    }
    platform_mutex_unlock(&sb_lock);
    return found;
}

int site_block_find_rule(const char *ip, const char *domain) {
    if (!sb_inited) return -1;
    char ndom[SB_DOMAIN_LEN];
    sb_norm_domain(domain, ndom, sizeof(ndom));
    const char *qip = (ip && ip[0]) ? ip : "*";
    platform_mutex_lock(&sb_lock);
    int res = -1;
    for (int i = 0; i < sb_rule_count; i++) {
        if (strcmp(sb_rules[i].ip, qip) == 0 && strcmp(sb_rules[i].domain, ndom) == 0) {
            res = i;
            break;
        }
    }
    platform_mutex_unlock(&sb_lock);
    return res;
}

/* ==================================================================
 *   Gozlem kaydi
 * ================================================================== */

static void sb_note_obs(const char *ip, const char *domain, unsigned char kind, int blocked) {
    /* sb_lock tutulurken cagrilir */
    for (int i = 0; i < sb_obs_count; i++) {
        if (strcmp(sb_obs[i].ip, ip) == 0 && strcmp(sb_obs[i].domain, domain) == 0) {
            sb_obs[i].count++;
            sb_obs[i].last_seen = sb_now();
            sb_obs[i].kind = kind;
            sb_obs[i].blocked = blocked;
            return;
        }
    }
    int slot;
    if (sb_obs_count < SB_OBS_MAX) {
        slot = sb_obs_count++;
    } else {
        /* en eski (last_seen en kucuk) kaydin yerine koy */
        slot = 0;
        for (int i = 1; i < SB_OBS_MAX; i++)
            if (sb_obs[i].last_seen < sb_obs[slot].last_seen) slot = i;
    }
    SiteBlockObs *o = &sb_obs[slot];
    memset(o, 0, sizeof(*o));
    strncpy(o->ip, ip, SB_IP_LEN - 1);
    strncpy(o->domain, domain, SB_DOMAIN_LEN - 1);
    o->kind = kind;
    o->count = 1;
    o->last_seen = sb_now();
    o->blocked = blocked;
}

int site_block_observations(SiteBlockObs *out, int max) {
    if (!sb_inited || !out || max <= 0) return 0;
    platform_mutex_lock(&sb_lock);
    int n = sb_obs_count < max ? sb_obs_count : max;
    for (int i = 0; i < n; i++) out[i] = sb_obs[i];
    platform_mutex_unlock(&sb_lock);
    return n;
}

void site_block_clear_observations(void) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    sb_obs_count = 0;
    platform_mutex_unlock(&sb_lock);
}

int site_block_block_observed(const char *ip, const char *domain, int mode) {
    int r = site_block_add_rule(ip, domain, mode);
    if (r >= 0) {
        platform_mutex_lock(&sb_lock);
        for (int i = 0; i < sb_obs_count; i++)
            if (strcmp(sb_obs[i].ip, ip) == 0 && strcmp(sb_obs[i].domain, domain) == 0)
                sb_obs[i].blocked = 1;
        platform_mutex_unlock(&sb_lock);
    }
    return r;
}

void site_block_get_stats(SiteBlockStats *s) {
    if (!s) return;
    if (!sb_inited) { memset(s, 0, sizeof(*s)); return; }
    *s = sb_stats;
    s->enabled = sb_enabled;
    s->raw_ready = site_block_raw_ready();
    s->scope_count = sb_scope_count;
}

/* ==================================================================
 *   Enjeksiyon yardimcilari
 * ================================================================== */

static int sb_parse_mac(const char *s, unsigned char mac[6]) {
    if (!s || strlen(s) < 17) return -1;
    unsigned int m[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6) return -1;
    for (int i = 0; i < 6; i++) mac[i] = (unsigned char)(m[i] & 0xFF);
    return 0;
}

static int sb_pkt_has_layer(const PacketRecord *pkt, PduLayerType t) {
    for (int i = 0; i < pkt->layer_count; i++)
        if (pkt->layers[i].type == t) return 1;
    return 0;
}

/* ---- DNS sinkhole: sahte yanit uret ve kurban'a gonder ---- */
static int sb_enforce_dns_sinkhole(const PacketRecord *pkt) {
    if (pkt->dns_msg_len < 12 || pkt->dns_msg_len > DNS_MSG_MAX) return -1;
    if (!pkt->src_mac[0] || !sb_own_mac_valid) return -1;

    unsigned char resp[DNS_MSG_MAX + 32];
    int qlen = pkt->dns_msg_len;
    memcpy(resp, pkt->dns_msg, (size_t)qlen);

    resp[2] = 0x81; resp[3] = 0x80;    /* QR=1, RD=1, RA=1, NOERROR */
    resp[4] = 0x00; resp[5] = 0x01;    /* QDCOUNT = 1 */
    resp[6] = 0x00; resp[7] = 0x01;    /* ANCOUNT = 1 */
    resp[8] = 0x00; resp[9] = 0x00;    /* NSCOUNT = 0 */
    resp[10] = 0x00; resp[11] = 0x00;  /* ARCOUNT = 0 */

    int p = qlen;
    resp[p++] = 0xC0; resp[p++] = 0x0C;          /* name ptr -> soru adi */
    resp[p++] = 0x00; resp[p++] = 0x01;          /* TYPE A */
    resp[p++] = 0x00; resp[p++] = 0x01;          /* CLASS IN */
    resp[p++] = 0x00; resp[p++] = 0x00;
    resp[p++] = 0x00; resp[p++] = 0x3C;          /* TTL 60 */
    resp[p++] = 0x00; resp[p++] = 0x04;          /* RDLENGTH 4 */
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(sb_sinkhole_ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) { a = b = c = d = 0; }
    resp[p++] = (unsigned char)(a & 0xFF);
    resp[p++] = (unsigned char)(b & 0xFF);
    resp[p++] = (unsigned char)(c & 0xFF);
    resp[p++] = (unsigned char)(d & 0xFF);

    unsigned char dst_mac[6];
    if (sb_parse_mac(pkt->src_mac, dst_mac) != 0) return -1;

    unsigned short sport = (unsigned short)atoi(pkt->dst_port);  /* 53 */
    unsigned short dport = (unsigned short)atoi(pkt->src_port);  /* ephemeral */
    if (sport == 0) sport = 53;
    if (dport == 0) return -1;

    /* Yanit: sunucu (pkt->dst_ip:53) -> istemci (pkt->src_ip:ephemeral) */
    int r = raw_inject_udp(&sb_ri, dst_mac, sb_own_mac,
                           pkt->dst_ip, pkt->src_ip, sport, dport, resp, p);
    if (r == 0) { sb_stats.sinkholed++; sb_stats.sent_total++; }
    return r;
}

/* ---- TCP RST: kurbanin baglantisini dusur ---- */
static int sb_enforce_rst(const PacketRecord *pkt) {
    if (!pkt->src_mac[0] || !sb_own_mac_valid) return -1;
    unsigned char dst_mac[6];
    if (sb_parse_mac(pkt->src_mac, dst_mac) != 0) return -1;

    unsigned short sport = (unsigned short)atoi(pkt->dst_port);
    unsigned short dport = (unsigned short)atoi(pkt->src_port);
    if (sport == 0 || dport == 0) return -1;

    /* Sunucu -> istemci RST (istemcinin soketini dusurur) */
    int r = raw_inject_tcp(&sb_ri, dst_mac, sb_own_mac,
                           pkt->dst_ip, pkt->src_ip, sport, dport,
                           pkt->tcp_ack, pkt->tcp_seq, 0x14 /* RST|ACK */,
                           NULL, 0);
    if (r == 0) { sb_stats.rst_sent++; sb_stats.sent_total++; }

    /* Istege bagli: istemci -> sunucu RST (gateway MAC'i biliniyorsa) */
    if (sb_gw_mac_valid) {
        int r2 = raw_inject_tcp(&sb_ri, sb_gw_mac, sb_own_mac,
                                pkt->src_ip, pkt->dst_ip, dport, sport,
                                pkt->tcp_seq, pkt->tcp_ack, 0x04 /* RST */,
                                NULL, 0);
        if (r2 == 0) { sb_stats.rst_sent++; sb_stats.sent_total++; }
    }
    return r;
}

/* ---- QUIC: ICMP port unreachable ile istemciyi TCP/TLS'e zorla ---- */
static int sb_enforce_quic_icmp(const PacketRecord *pkt) {
    if (!pkt->src_mac[0] || !sb_own_mac_valid) return -1;
    unsigned char dst_mac[6];
    if (sb_parse_mac(pkt->src_mac, dst_mac) != 0) return -1;

    unsigned short sport = (unsigned short)atoi(pkt->src_port);
    unsigned short dport = (unsigned short)atoi(pkt->dst_port);
    if (sport == 0 || dport == 0) return -1;

    /* Gonderilen orijinal UDP basligi (8 bayt) */
    unsigned char udp8[8];
    udp8[0] = (unsigned char)(sport >> 8); udp8[1] = (unsigned char)(sport & 0xFF);
    udp8[2] = (unsigned char)(dport >> 8); udp8[3] = (unsigned char)(dport & 0xFF);
    udp8[4] = 0x00; udp8[5] = 0x08;
    udp8[6] = 0x00; udp8[7] = 0x00;

    /* ICMP payload icindeki orijinal IP datagram: baslik + ilk 8 bayt */
    unsigned char orig[20 + 8];
    int ol = ri_build_ipv4(orig, (int)sizeof(orig), pkt->src_ip, pkt->dst_ip,
                           17, udp8, 8);
    if (ol < 0) return -1;

    unsigned char icmp[8 + sizeof(orig)];
    icmp[0] = 3;   /* Destination Unreachable */
    icmp[1] = 3;   /* Port Unreachable */
    icmp[2] = 0x00; icmp[3] = 0x00;
    icmp[4] = 0x00; icmp[5] = 0x00; icmp[6] = 0x00; icmp[7] = 0x00;  /* unused/MTU */
    memcpy(icmp + 8, orig, (size_t)ol);

    /* Sunucu -> istemci ICMP */
    int r = raw_inject_ip(&sb_ri, dst_mac, sb_own_mac,
                          pkt->dst_ip, pkt->src_ip, 1 /* ICMP */,
                          icmp, 8 + ol);
    if (r == 0) { sb_stats.icmp_sent++; sb_stats.sent_total++; }
    return r;
}

/* ==================================================================
 *   Gozle + uygula
 * ================================================================== */

void site_block_observe(const PacketRecord *pkt) {
    if (!sb_inited) site_block_init();
    if (!pkt) return;
    if (pkt->app_domain[0] == '\0') return;
    const char *victim = pkt->src_ip;
    if (!victim || !victim[0]) return;

    /* Kapsam disi cihazlari tamamen yoksay */
    if (!site_block_scope_contains(victim)) return;

    int is_tcp = sb_pkt_has_layer(pkt, LAYER_TCP);
    int is_udp = sb_pkt_has_layer(pkt, LAYER_UDP);

    /* Kural var mi? (gozlem kaydinda "blocked" bayragi icin) */
    SiteBlockRule rule;
    int matched = site_block_match(victim, pkt->app_domain, &rule);

    /* Gozlem kaydi */
    platform_mutex_lock(&sb_lock);
    sb_note_obs(victim, pkt->app_domain, pkt->domain_kind, matched);
    platform_mutex_unlock(&sb_lock);

    __sync_fetch_and_add(&sb_stats.observed, 1);

    if (!sb_enabled || !matched) return;

    /* Ham enjeksiyon gerekli */
    if (!sb_ri.ok && !sb_test_sink) {
        platform_mutex_lock(&sb_lock);
        sb_ensure_raw();
        platform_mutex_unlock(&sb_lock);
    }
    if (!sb_ri.ok && !sb_test_sink) return;

    int mode = rule.mode;
    int did = 0;

    switch (pkt->domain_kind) {
    case DOMAIN_KIND_DNS:
        if ((mode & SB_MODE_SINKHOLE) && is_udp) {
            if (sb_enforce_dns_sinkhole(pkt) == 0) did = 1;
        } else if ((mode & SB_MODE_RST) && is_tcp) {
            if (sb_enforce_rst(pkt) == 0) did = 1;
        }
        break;
    case DOMAIN_KIND_SNI:
    case DOMAIN_KIND_HTTP:
        if ((mode & SB_MODE_RST) && is_tcp) {
            if (sb_enforce_rst(pkt) == 0) did = 1;
        }
        break;
    case DOMAIN_KIND_QUIC:
        /* RST ve BOTH modlari ICMP unreachable uretir; SINKHOLE tek basina uretmez */
        if (mode & SB_MODE_RST) {
            if (sb_enforce_quic_icmp(pkt) == 0) did = 1;
        }
        break;
    default:
        break;
    }

    if (did) {
        platform_mutex_lock(&sb_lock);
        for (int i = 0; i < sb_rule_count; i++) {
            if (strcmp(sb_rules[i].ip, rule.ip) == 0 &&
                strcmp(sb_rules[i].domain, rule.domain) == 0) {
                sb_rules[i].hits++;
                sb_rules[i].last_hit = sb_now();
                break;
            }
        }
        platform_mutex_unlock(&sb_lock);
    }
}

/* ==================================================================
 *   Test kancalari
 * ================================================================== */

void site_block_set_test_sink(RawInjectSink fn, void *ud) {
    if (!sb_inited) site_block_init();
    sb_test_sink = fn;
    sb_test_sink_ud = ud;
    raw_inject_set_sink(&sb_ri, fn, ud);
}

void site_block_set_test_iface_ok(int ok) {
    sb_test_raw_ok = ok ? 1 : 0;
}
