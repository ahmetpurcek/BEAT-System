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
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

/* ==================================================================
 *   Cekirdek (iptables) deterministik katman — durum
 * ================================================================== */
#define SB_FW_CHAIN "BEAT_SB"
#define SB_FW_MAX   1024

enum { SB_FW_KIND_IP = 0, SB_FW_KIND_DNS = 1 };

typedef struct {
    char victim[SB_IP_LEN];        /* somut kurban IP'si */
    char arg[SB_DOMAIN_LEN];       /* bloklanan IP (IP) veya alan adi (DNS) */
    char owner_ip[SB_IP_LEN];      /* bu kurali ureten SiteBlockRule.ip */
    char owner_domain[SB_DOMAIN_LEN]; /* ureten SiteBlockRule.domain */
    int  kind;                     /* SB_FW_KIND_* */
} SbFwEnt;

static SbFwEnt sb_fw[SB_FW_MAX];
static int  sb_fw_count = 0;
static int  sb_fw_ready = 0;
static platform_mutex_t sb_fw_lock;
static const char *sb_ipt_bin = NULL;

/* Gozlem aninda cozumleme onbellegi: ayni (kurban,alan adi) cifti icin
 * tekrar getaddrinfo yapilmasini onler (paket yolunda bloklanma olmasin). */
#define SB_PRIME_MAX 512
static char sb_primed_key[SB_PRIME_MAX][SB_IP_LEN + SB_DOMAIN_LEN + 2];
static int  sb_primed_count = 0;

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
    memset(sb_fw, 0, sizeof(sb_fw));
    sb_fw_count = 0;
    sb_fw_ready = 0;
    sb_ipt_bin = NULL;
    memset(sb_primed_key, 0, sizeof(sb_primed_key));
    sb_primed_count = 0;
    platform_mutex_init(&sb_lock);
    platform_mutex_init(&sb_fw_lock);
    sb_inited = 1;
}

void site_block_cleanup(void) {
    if (!sb_inited) return;
    /* Cekirdek kurallarini kaldir + zinciri temizle (yetim kural birakma) */
    site_block_fw_cleanup();
    raw_inject_close(&sb_ri);
    platform_mutex_destroy(&sb_fw_lock);
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
    /* Karartma kapatilinca cekirdek kurallarini da kaldir: net erisim geri gelsin */
    if (!sb_enabled) site_block_fw_clear();
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
    /* Kendi makinemizin IP'si her zaman kapsam icindedir: tek-makine
     * (managed-mode) senaryosunda kendi trafigimizi de karartabilmek icin. */
    if (sb_own_ip[0] && strcmp(ip, sb_own_ip) == 0) return 1;
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

/* sb_lock tutulurken cagrilir; sb_domain_match kilit almaz (guvenli). */
static void sb_refresh_obs_blocked(void);

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
            sb_refresh_obs_blocked();
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

    /* Cekirdek katmanini ONLEYICI olarak kur: kural eklendigi andan itibaren
     * (kurban ilk paketi gondermese bile) engelleme aktif olur. */
    site_block_fw_prime(ip, ndom);

    /* Gozlem kayitlarinin blocked bayraklarini tazele: yeni kural wildcard
     * (ornek "*" veya "*.x") ise eski gozlemler de kirmizi gostermeli. */
    platform_mutex_lock(&sb_lock);
    sb_refresh_obs_blocked();
    platform_mutex_unlock(&sb_lock);
    return idx;
}

int site_block_remove_rule(int index) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    if (index < 0 || index >= sb_rule_count) { platform_mutex_unlock(&sb_lock); return -1; }
    char rip[SB_IP_LEN], rdom[SB_DOMAIN_LEN];
    strncpy(rip, sb_rules[index].ip, SB_IP_LEN - 1); rip[SB_IP_LEN - 1] = '\0';
    strncpy(rdom, sb_rules[index].domain, SB_DOMAIN_LEN - 1); rdom[SB_DOMAIN_LEN - 1] = '\0';
    for (int i = index; i < sb_rule_count - 1; i++) sb_rules[i] = sb_rules[i + 1];
    sb_rule_count--;
    platform_mutex_unlock(&sb_lock);
    /* Bu kuralin kurdugu cekirdek DROP kurallarini kaldir */
    site_block_fw_unblock_domain(rip, rdom);
    /* Kural silindigi icin eslesen gozlemlerin blocked bayragini temizle */
    platform_mutex_lock(&sb_lock);
    sb_refresh_obs_blocked();
    platform_mutex_unlock(&sb_lock);
    return 0;
}

void site_block_clear_rules(void) {
    if (!sb_inited) site_block_init();
    platform_mutex_lock(&sb_lock);
    sb_rule_count = 0;
    platform_mutex_unlock(&sb_lock);
    /* Tum cekirdek kurallarini temizle */
    site_block_fw_clear();
    /* Tum gozlemler artik engelsiz */
    platform_mutex_lock(&sb_lock);
    sb_refresh_obs_blocked();
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

/* Genel joker (glob) eslesmesi: '*' sifir veya daha fazla karakterle eslesir.
 * Domain girdileri sb_norm_domain ile kucultulur; kural da kucultulmus saklanir
 * (bkz. site_block_add_rule), bu yuzden ek kucultme gerekmez. */
static int sb_glob_match(const char *pat, const char *str) {
    while (*pat) {
        if (*pat == '*') {
            while (*pat == '*') pat++;            /* ardisik jokerleri yut */
            if (!*pat) return 1;                  /* son joker: geri kalan her sey */
            for (const char *s = str; ; s++) {
                if (sb_glob_match(pat, s)) return 1;
                if (!*s) break;
            }
            return 0;
        }
        if (*str != *pat) return 0;
        pat++; str++;
    }
    return *str == '\0';
}

/* Alan adi eslesmesi:
 *   "*"            -> tum alan adlari
 *   "*.youtube.com"-> youtube.com + alt alanlari (ozel; mevcut davranis)
 *   "*youtube.com" -> "youtube.com" ile bitenler (a.youtube.com, b.youtube.com)
 *   "*youtube*"    -> icinde "youtube" gecen her sey (youtube.com, myyoutube.net...)
 *   "youtube.com"  -> youtube.com + alt alanlari (joker yok) */
static int sb_domain_match(const char *rule, const char *domain) {
    if (!rule || !domain || !domain[0]) return 0;
    if (strcmp(rule, "*") == 0) return 1;

    if (strchr(rule, '*')) {
        /* "*.x" bicimi (x icinde baska joker yok): x + alt alanlari korunur */
        if (rule[0] == '*' && rule[1] == '.' && !strchr(rule + 2, '*'))
            return sb_domain_match(rule + 2, domain);
        return sb_glob_match(rule, domain);
    }

    /* Joker yok: tam eslesme veya alt alan */
    if (strcmp(domain, rule) == 0) return 1;
    size_t bl = strlen(rule);
    size_t dl = strlen(domain);
    if (dl > bl && strcmp(domain + (dl - bl), rule) == 0 && domain[dl - bl - 1] == '.')
        return 1;
    return 0;
}

/* sb_lock tutulurken cagrilir: tum gozlem kayitlarinin blocked bayragini
 * mevcut kurallara gore YENIDEN hesaplar. Kural ekleme/silme sonrasi eski
 * gozlemlerin kirmizi/kirmizi-degil durumu aninda dogru olur. */
static void sb_refresh_obs_blocked(void) {
    for (int i = 0; i < sb_obs_count; i++) {
        SiteBlockObs *o = &sb_obs[i];
        int blocked = 0;
        for (int j = 0; j < sb_rule_count && !blocked; j++) {
            SiteBlockRule *r = &sb_rules[j];
            if (!r->enabled) continue;
            if (strcmp(r->ip, "*") != 0 && strcmp(r->ip, o->ip) != 0) continue;
            if (!sb_domain_match(r->domain, o->domain)) continue;
            blocked = 1;
        }
        o->blocked = blocked;
    }
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
        /* add_rule zaten sb_refresh_obs_blocked() cagirdi; wildcard kurallar
         * dahil tum eslesen gozlemler kirmizi isaretlenir. */
    }
    return r;
}

/* Bir gozlem satirinin "Ac" (engeli kaldir) islemi: (ip, domain) ile
 * ESLEMEN tum kurallari kaldirir — wildcard kurallar ("*", "*.x", "*x.com", "*x*") dahil.
 * Baska cihazlarin ayni alan adi kurallarina dokunmaz. Kaldirilan her kuralin
 * cekirdek (iptables) girdileri de temizlenir ve gozlem bayraklari tazelenir.
 * Kaldirilan kural sayisini dondurur (0 = eslesen kural yoktu). */
int site_block_unblock_observed(const char *ip, const char *domain) {
    if (!sb_inited) site_block_init();
    if (!domain || !domain[0]) return -1;
    char ndom[SB_DOMAIN_LEN];
    sb_norm_domain(domain, ndom, sizeof(ndom));
    if (!ndom[0]) return -1;
    const char *qip = (ip && ip[0]) ? ip : "*";

    char rip[SB_MAX_RULES][SB_IP_LEN];
    char rdom[SB_MAX_RULES][SB_DOMAIN_LEN];
    int nrem = 0;

    platform_mutex_lock(&sb_lock);
    for (int i = 0; i < sb_rule_count; ) {
        SiteBlockRule *r = &sb_rules[i];
        int match = r->enabled &&
                    (strcmp(r->ip, "*") == 0 || strcmp(r->ip, qip) == 0) &&
                    sb_domain_match(r->domain, ndom);
        if (!match) { i++; continue; }
        if (nrem < SB_MAX_RULES) {
            strncpy(rip[nrem], r->ip, SB_IP_LEN - 1);
            rip[nrem][SB_IP_LEN - 1] = '\0';
            strncpy(rdom[nrem], r->domain, SB_DOMAIN_LEN - 1);
            rdom[nrem][SB_DOMAIN_LEN - 1] = '\0';
            nrem++;
        }
        for (int k = i; k < sb_rule_count - 1; k++) sb_rules[k] = sb_rules[k + 1];
        sb_rule_count--;
        /* i'yi artirma: kaydirilan kural ayni indekse geldi */
    }
    sb_refresh_obs_blocked();
    platform_mutex_unlock(&sb_lock);

    for (int j = 0; j < nrem; j++)
        site_block_fw_unblock_domain(rip[j], rdom[j]);
    return nrem;
}

void site_block_get_stats(SiteBlockStats *s) {
    if (!s) return;
    if (!sb_inited) { memset(s, 0, sizeof(*s)); return; }
    *s = sb_stats;
    s->enabled = sb_enabled;
    s->raw_ready = site_block_raw_ready();
    s->scope_count = sb_scope_count;
    s->fw_ready = sb_fw_ready;
    /* Aktif cekirdek kural sayilarini (tur bazli) gercek listeden hesapla */
    unsigned long nip = 0, ndns = 0;
    platform_mutex_lock(&sb_fw_lock);
    for (int i = 0; i < sb_fw_count; i++) {
        if (sb_fw[i].kind == SB_FW_KIND_IP) nip++; else ndns++;
    }
    platform_mutex_unlock(&sb_fw_lock);
    s->fw_ip_rules = nip;
    s->fw_dns_rules = ndns;
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

/* Kurban IP'si bu makinenin kendi IP'si mi? (tek-makine senaryosu) */
static int sb_is_own_ip(const char *ip) {
    return ip && ip[0] && sb_own_ip[0] && strcmp(ip, sb_own_ip) == 0;
}

/* ---- DNS sinkhole: sahte yanit uret ve kurban'a gonder ---- */
static int sb_enforce_dns_sinkhole(const PacketRecord *pkt, int local) {
    if (pkt->dns_msg_len < 12 || pkt->dns_msg_len > DNS_MSG_MAX) return -1;
    if (!local && (!pkt->src_mac[0] || !sb_own_mac_valid)) return -1;

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

    unsigned short sport = (unsigned short)atoi(pkt->dst_port);  /* 53 */
    unsigned short dport = (unsigned short)atoi(pkt->src_port);  /* ephemeral */
    if (sport == 0) sport = 53;
    if (dport == 0) return -1;

    /* Yanit: sunucu (pkt->dst_ip:53) -> istemci (pkt->src_ip:ephemeral) */
    int r;
    if (local) {
        /* Yerel teslim: Ethernet yok; cekirdek loopback'e birakir. */
        unsigned char l4[4096];
        int n = ri_build_udp(l4, (int)sizeof(l4), pkt->dst_ip, pkt->src_ip,
                             sport, dport, resp, p);
        r = (n < 0) ? -1
                    : raw_inject_send_ip(&sb_ri, pkt->dst_ip, pkt->src_ip, 17, l4, n);
    } else {
        unsigned char dst_mac[6];
        if (sb_parse_mac(pkt->src_mac, dst_mac) != 0) return -1;
        r = raw_inject_udp(&sb_ri, dst_mac, sb_own_mac,
                           pkt->dst_ip, pkt->src_ip, sport, dport, resp, p);
    }
    if (r == 0) { sb_stats.sinkholed++; sb_stats.sent_total++; }
    return r;
}

/* ---- TCP RST: kurbanin baglantisini dusur ---- */
static int sb_enforce_rst(const PacketRecord *pkt, int local) {
    if (!local && (!pkt->src_mac[0] || !sb_own_mac_valid)) return -1;

    unsigned short sport = (unsigned short)atoi(pkt->dst_port);
    unsigned short dport = (unsigned short)atoi(pkt->src_port);
    if (sport == 0 || dport == 0) return -1;

    /* Sunucu -> istemci RST (istemcinin soketini dusurur) */
    int r;
    if (local) {
        unsigned char l4[4096];
        int n = ri_build_tcp(l4, (int)sizeof(l4), pkt->dst_ip, pkt->src_ip,
                             sport, dport, pkt->tcp_ack, pkt->tcp_seq,
                             0x14 /* RST|ACK */, NULL, 0);
        r = (n < 0) ? -1
                    : raw_inject_send_ip(&sb_ri, pkt->dst_ip, pkt->src_ip, 6, l4, n);
    } else {
        unsigned char dst_mac[6];
        if (sb_parse_mac(pkt->src_mac, dst_mac) != 0) return -1;
        r = raw_inject_tcp(&sb_ri, dst_mac, sb_own_mac,
                           pkt->dst_ip, pkt->src_ip, sport, dport,
                           pkt->tcp_ack, pkt->tcp_seq, 0x14 /* RST|ACK */,
                           NULL, 0);
    }
    if (r == 0) { sb_stats.rst_sent++; sb_stats.sent_total++; }

    /* Istege bagli: istemci -> sunucu RST (gateway MAC'i biliniyorsa; yerel modda gerek yok) */
    if (!local && sb_gw_mac_valid) {
        unsigned char dst_mac[6];
        if (sb_parse_mac(pkt->src_mac, dst_mac) == 0) {
            int r2 = raw_inject_tcp(&sb_ri, sb_gw_mac, sb_own_mac,
                                    pkt->src_ip, pkt->dst_ip, dport, sport,
                                    pkt->tcp_seq, pkt->tcp_ack, 0x04 /* RST */,
                                    NULL, 0);
            if (r2 == 0) { sb_stats.rst_sent++; sb_stats.sent_total++; }
        }
    }
    return r;
}

/* ---- QUIC: ICMP port unreachable ile istemciyi TCP/TLS'e zorla ---- */
static int sb_enforce_quic_icmp(const PacketRecord *pkt, int local) {
    if (!local && (!pkt->src_mac[0] || !sb_own_mac_valid)) return -1;

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
    int r;
    if (local) {
        r = raw_inject_send_ip(&sb_ri, pkt->dst_ip, pkt->src_ip, 1 /* ICMP */,
                               icmp, 8 + ol);
    } else {
        unsigned char dst_mac[6];
        if (sb_parse_mac(pkt->src_mac, dst_mac) != 0) return -1;
        r = raw_inject_ip(&sb_ri, dst_mac, sb_own_mac,
                          pkt->dst_ip, pkt->src_ip, 1 /* ICMP */,
                          icmp, 8 + ol);
    }
    if (r == 0) { sb_stats.icmp_sent++; sb_stats.sent_total++; }
    return r;
}

/* ==================================================================
 *   Cekirdek (iptables) deterministik katman
 * ==================================================================
 *
 * Reaktif enjeksiyon "forward" ile YARISA girer: sahte DNS yaniti / RST
 * kurban paketi yola ciktiktan SONRA uretilir, bu yuzden gercek yanit
 * cogu zaman kazanir -> aralikli engelleme. Bu katman cekirdekte DROP
 * kurarak yarisi tamamen ortadan kaldirir:
 *
 *   - DNS (udp/tcp 53) : kurbanin ilgili alan adi sorgusu dusurulur;
 *                        boylece gercek yanit hic uretilmez -> sinkhole
 *                        her zaman kazanir.
 *   - SNI/HTTP/QUIC    : kurban <-> sunucu IP cifti (iki yon) dusurulur;
 *                        TLS/QUIC akisi hic gecmez.
 *
 * Tek kullanici zinciri (BEAT_SB) FORWARD + INPUT + OUTPUT'a takilir:
 *   - FORWARD : ARP-spoof MITM altindaki kurban trafigi (victim != kendi IP)
 *   - OUTPUT  : kendi makinemiz hedef oldugunda giden trafik
 *   - INPUT   : kendi makinemiz hedef oldugunda gelen trafik
 */

static const char *sb_ipt_path(void) {
    if (sb_ipt_bin) return sb_ipt_bin;
    static const char *cand[] = {
        "/usr/sbin/iptables", "/sbin/iptables",
        "/usr/bin/iptables",  "/bin/iptables",
        "iptables", NULL
    };
    for (int i = 0; cand[i]; i++) {
        if (strchr(cand[i], '/')) {
            if (access(cand[i], X_OK) == 0) { sb_ipt_bin = cand[i]; return sb_ipt_bin; }
        } else {
            /* PATH uzerinden: execvp cozer */
            sb_ipt_bin = cand[i];
            return sb_ipt_bin;
        }
    }
    return "iptables";
}

/* iptables komutunu calistir (fork+exec; kabuk yok -> injection yok) */
static int sb_exec(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); if (dn > 2) close(dn); }
        execv(argv[0], argv);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) return -1;
    if (!WIFEXITED(st)) return -1;
    return WEXITSTATUS(st);
}

/* argv[0] yerine cozumlenen iptables yolunu koyan yardimci kurucular */

int site_block_fw_init(void) {
    if (!sb_inited) site_block_init();
    const char *bin = sb_ipt_path();

    platform_mutex_lock(&sb_fw_lock);

    /* Zincir olustur (varsa hata yok), sonra temizle: yetim kurallari sil */
    { char *a[] = {(char*)bin, "-N", SB_FW_CHAIN, NULL}; sb_exec(a); }
    { char *a[] = {(char*)bin, "-F", SB_FW_CHAIN, NULL}; sb_exec(a); }

    /* Atlamalar: FORWARD/INPUT/OUTPUT (yoksa ekle) */
    const char *parents[] = { "FORWARD", "INPUT", "OUTPUT" };
    for (int i = 0; i < 3; i++) {
        char *chk[] = {(char*)bin, "-C", (char*)parents[i], "-j", SB_FW_CHAIN, NULL};
        if (sb_exec(chk) != 0) {
            char *add[] = {(char*)bin, "-I", (char*)parents[i], "1", "-j", SB_FW_CHAIN, NULL};
            sb_exec(add);
        }
    }

    sb_fw_count = 0;
    sb_fw_ready = 1;
    sb_stats.fw_ready = 1;
    platform_mutex_unlock(&sb_fw_lock);
    fprintf(stderr, "[SITE_BLOCK] Cekirdek katman hazir (%s, zincir %s)\n", bin, SB_FW_CHAIN);
    return 0;
}

void site_block_fw_cleanup(void) {
    if (!sb_inited) return;
    const char *bin = sb_ipt_path();

    platform_mutex_lock(&sb_fw_lock);
    const char *parents[] = { "FORWARD", "INPUT", "OUTPUT" };
    for (int i = 0; i < 3; i++) {
        char *a[] = {(char*)bin, "-D", (char*)parents[i], "-j", SB_FW_CHAIN, NULL};
        sb_exec(a);
    }
    { char *a[] = {(char*)bin, "-F", SB_FW_CHAIN, NULL}; sb_exec(a); }
    { char *a[] = {(char*)bin, "-X", SB_FW_CHAIN, NULL}; sb_exec(a); }
    sb_fw_count = 0;
    sb_fw_ready = 0;
    sb_stats.fw_ready = 0;
    platform_mutex_unlock(&sb_fw_lock);
}

/* sb_fw_lock tutulurken cagrilir */
static int sb_fw_find(const char *victim, const char *arg, int kind) {
    for (int i = 0; i < sb_fw_count; i++) {
        if (sb_fw[i].kind == kind &&
            strcmp(sb_fw[i].victim, victim) == 0 &&
            strcmp(sb_fw[i].arg, arg) == 0)
            return i;
    }
    return -1;
}

static void sb_fw_store(const char *victim, const char *arg, int kind,
                        const char *owner_ip, const char *owner_domain) {
    if (sb_fw_count >= SB_FW_MAX) return;
    SbFwEnt *e = &sb_fw[sb_fw_count++];
    memset(e, 0, sizeof(*e));
    strncpy(e->victim, victim, SB_IP_LEN - 1);
    strncpy(e->arg, arg, SB_DOMAIN_LEN - 1);
    strncpy(e->owner_ip, owner_ip ? owner_ip : "*", SB_IP_LEN - 1);
    strncpy(e->owner_domain, owner_domain ? owner_domain : "*", SB_DOMAIN_LEN - 1);
    e->kind = kind;
}

int site_block_fw_block_ip(const char *victim, const char *ip,
                           const char *owner_ip, const char *owner_domain) {
    if (!victim || !victim[0] || !ip || !ip[0]) return -1;
    if (!sb_inited) site_block_init();
    const char *bin = sb_ipt_path();

    platform_mutex_lock(&sb_fw_lock);
    if (!sb_fw_ready) { platform_mutex_unlock(&sb_fw_lock); site_block_fw_init(); platform_mutex_lock(&sb_fw_lock); }
    if (sb_fw_find(victim, ip, SB_FW_KIND_IP) >= 0) { platform_mutex_unlock(&sb_fw_lock); return 0; }

    char *a[] = {(char*)bin, "-A", SB_FW_CHAIN, "-s", (char*)victim, "-d", (char*)ip,
                 "-j", "DROP", NULL};
    if (sb_exec(a) != 0) { platform_mutex_unlock(&sb_fw_lock); return -1; }

    char *b[] = {(char*)bin, "-A", SB_FW_CHAIN, "-s", (char*)ip, "-d", (char*)victim,
                 "-j", "DROP", NULL};
    if (sb_exec(b) != 0) {
        char *roll[] = {(char*)bin, "-D", SB_FW_CHAIN, "-s", (char*)victim, "-d", (char*)ip,
                        "-j", "DROP", NULL};
        sb_exec(roll);
        platform_mutex_unlock(&sb_fw_lock);
        return -1;
    }

    sb_fw_store(victim, ip, SB_FW_KIND_IP, owner_ip, owner_domain);
    sb_stats.fw_ip_rules = (unsigned long)sb_fw_count;
    __sync_fetch_and_add(&sb_stats.fw_events, 1);
    platform_mutex_unlock(&sb_fw_lock);
    return 0;
}

/* DNS tel formati (wire) etiketleri uzunluk-onekli kodlar: "example.com"
 * telde '\x07example\x03com' seklinde gorunur; nokta KARAKTERI yoktur. Bu yuzden
 * duz '--string "example.com"' hicbir sorguya uymaz. Asagidaki yardimci, alan adini
 * '|07|example|03|com|00|' biciminde hex-string desenine cevirir. */
static int sb_dns_hexpattern(const char *domain, char *out, size_t outsz) {
    if (!domain || !domain[0] || !out || outsz < 16) return -1;
    size_t o = 0;
    const char *p = domain;
    while (*p == '*' || *p == '.') p++;   /* bastaki joker/kok nokta temizligi */
    int truncated = 0;                     /* icte/sonda joker: |00| eklenmez */
    while (*p) {
        if (*p == '*') { truncated = 1; break; }
        const char *dot  = strchr(p, '.');
        const char *star = strchr(p, '*');
        size_t len;
        if (star && (!dot || star < dot)) { len = (size_t)(star - p); truncated = 1; }
        else if (dot) len = (size_t)(dot - p);
        else          len = strlen(p);
        if (len == 0) { if (truncated) break; p = dot ? dot + 1 : p + 1; continue; }
        if (len > 63) return -1;          /* gecersiz DNS etiketi */
        int n = snprintf(out + o, outsz - o, "|%02x|", (unsigned)len);
        if (n < 0 || (size_t)n >= outsz - o) return -1;
        o += (size_t)n;
        for (size_t k = 0; k < len; k++) {
            unsigned char c = (unsigned char)p[k];
            if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
            if (o + 1 >= outsz) return -1;
            out[o++] = (char)c;
        }
        if (truncated) break;
        if (!dot) break;
        p = dot + 1;
    }
    if (!truncated) {
        if (o + 4 >= outsz) return -1;
        memcpy(out + o, "|00|", 4); o += 4;
    }
    out[o] = '\0';
    return 0;
}

int site_block_fw_block_dns(const char *victim, const char *domain,
                            const char *owner_ip, const char *owner_domain) {
    if (!victim || !victim[0] || !domain || !domain[0]) return -1;
    if (strcmp(domain, "*") == 0) return -1;   /* joker: string eslesmesi yok */
    if (strcmp(victim, "*") == 0) return -1;   /* kaynak-bazli kural gerekir */
    if (!sb_inited) site_block_init();
    const char *bin = sb_ipt_path();

    platform_mutex_lock(&sb_fw_lock);
    if (!sb_fw_ready) { platform_mutex_unlock(&sb_fw_lock); site_block_fw_init(); platform_mutex_lock(&sb_fw_lock); }
    if (sb_fw_find(victim, domain, SB_FW_KIND_DNS) >= 0) { platform_mutex_unlock(&sb_fw_lock); return 0; }

    char pat[1024];
    if (sb_dns_hexpattern(domain, pat, sizeof(pat)) != 0) {
        platform_mutex_unlock(&sb_fw_lock);
        return -1;
    }

    const char *protos[] = { "udp", "tcp" };
    int ok = 0;
    for (int i = 0; i < 2; i++) {
        char *a[] = {(char*)bin, "-A", SB_FW_CHAIN, "-s", (char*)victim, "-p", (char*)protos[i],
                     "--dport", "53", "-m", "string", "--hex-string", pat,
                     "--algo", "bm", "-j", "DROP", NULL};
        if (sb_exec(a) == 0) ok = i + 1;
    }
    if (!ok) { platform_mutex_unlock(&sb_fw_lock); return -1; }

    sb_fw_store(victim, domain, SB_FW_KIND_DNS, owner_ip, owner_domain);
    sb_stats.fw_dns_rules = (unsigned long)sb_fw_count;
    __sync_fetch_and_add(&sb_stats.fw_events, 1);
    platform_mutex_unlock(&sb_fw_lock);
    return 0;
}

/* sb_fw_lock tutulurken cagrilir; i'inci girdiyi cekirdekten ve listeden sil */
static void sb_fw_del_at(int i) {
    const char *bin = sb_ipt_path();
    SbFwEnt *e = &sb_fw[i];
    if (e->kind == SB_FW_KIND_IP) {
        char *a[] = {(char*)bin, "-D", SB_FW_CHAIN, "-s", e->victim, "-d", e->arg,
                     "-j", "DROP", NULL};
        sb_exec(a);
        char *b[] = {(char*)bin, "-D", SB_FW_CHAIN, "-s", e->arg, "-d", e->victim,
                     "-j", "DROP", NULL};
        sb_exec(b);
    } else {
        const char *protos[] = { "udp", "tcp" };
        char pat[1024];
        if (sb_dns_hexpattern(e->arg, pat, sizeof(pat)) != 0) pat[0] = '\0';
        for (int j = 0; j < 2 && pat[0]; j++) {
            char *a[] = {(char*)bin, "-D", SB_FW_CHAIN, "-s", e->victim, "-p", (char*)protos[j],
                         "--dport", "53", "-m", "string", "--hex-string", pat,
                         "--algo", "bm", "-j", "DROP", NULL};
            sb_exec(a);
        }
    }
    for (int k = i; k < sb_fw_count - 1; k++) sb_fw[k] = sb_fw[k + 1];
    sb_fw_count--;
}

void site_block_fw_unblock_domain(const char *owner_ip, const char *owner_domain) {
    if (!sb_inited || !sb_fw_ready) return;
    const char *oip = (owner_ip && owner_ip[0]) ? owner_ip : "*";
    platform_mutex_lock(&sb_fw_lock);
    for (int i = sb_fw_count - 1; i >= 0; i--) {
        if (strcmp(sb_fw[i].owner_ip, oip) == 0 &&
            strcmp(sb_fw[i].owner_domain, owner_domain ? owner_domain : "*") == 0)
            sb_fw_del_at(i);
    }
    sb_stats.fw_ip_rules = (unsigned long)sb_fw_count;
    sb_stats.fw_dns_rules = (unsigned long)sb_fw_count;
    platform_mutex_unlock(&sb_fw_lock);
}

void site_block_fw_clear(void) {
    if (!sb_inited || !sb_fw_ready) return;
    platform_mutex_lock(&sb_fw_lock);
    for (int i = sb_fw_count - 1; i >= 0; i--) sb_fw_del_at(i);
    platform_mutex_unlock(&sb_fw_lock);
}

/* Kural olusturulur olusturulmaz cekirdek kurallarini KUR (onleyici):
 *   1. Alan adini KENDIMIZ cozumleriz (getaddrinfo) -> kurbanin ilk
 *      baglantisi dahi engellenir (onceden cozulmus/cached IP dahil).
 *   2. DNS string DROP: kurbanin bundan sonraki sorgusu cekirdekte duser,
 *      boylece gercek yanit hic uretilmez (yaris yok).
 * Joker: "*.x"/"*x.com" tabani somut koke indirilip cozumlenir; yalnizca
 * "*" veya icte jokerli ("*x*") hedefler onleyici IP kurulumundan muaftir.
 * Boyle durumlarda gozlem yolu somut kurban gordukce kurallari kurar. */
void site_block_fw_prime(const char *owner_ip, const char *domain) {
    if (!sb_inited) site_block_init();
    if (!owner_ip || !owner_ip[0] || strcmp(owner_ip, "*") == 0) return;
    if (!domain || !domain[0] || strcmp(domain, "*") == 0) return;

    /* Bastaki joker/kok noktalari soy:
     *   "*.youtube.com" -> "youtube.com",  "*youtube.com" -> "youtube.com" */
    const char *base = domain;
    while (*base == '*' || *base == '.') base++;
    if (!base[0]) return;

    /* 1) Alan adini kendimiz cozumle (DNS kuralindan ONCE: kendi sorgumuz
     *    engellenmesin) ve IP DROP kurallarini kur. Icte kalan joker
     *    ("*youtube*") cozumlenemez; bu durumda IP katmani atlanir ve DNS
     *    deseni + gozlem yolu devreye girer. */
    if (!strchr(base, '*')) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(base, NULL, &hints, &res) == 0) {
            for (struct addrinfo *p = res; p; p = p->ai_next) {
                char ipbuf[INET_ADDRSTRLEN];
                struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
                if (sin && inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf)))
                    site_block_fw_block_ip(owner_ip, ipbuf, owner_ip, domain);
            }
            freeaddrinfo(res);
        }
    }

    /* 2) DNS string DROP (udp/tcp 53) - jokerli taban da desene cevrilir */
    site_block_fw_block_dns(owner_ip, base, owner_ip, domain);
}

int site_block_fw_active(void) { return sb_fw_ready ? 1 : 0; }

/* Gozlem aninda bir alan adini KENDIMIZ cozumler ve A kayitlarinin TAMAMINI
 * kurban icin IP DROP olarak kurar.
 *
 * Neden gerekli: bazi uygulamalar (or. Instagram) DNS sorgusu engellense bile
 * onbellekteki/jeton IP'lere ya da SNI gondermeyen dogrudan IP baglantilarla
 * erisir. Somut alan adini (or. DNS sorgu adi "graph.instagram.com" veya SNI
 * "i.instagram.com") cozumleyip IP katmanini ONCEDEN doldurunca, uygulama
 * SNI gostermeden o IP'ye baglansa dahi trafik duser.
 *
 * Ayni (kurban,alan adi) cifti icin tekrar getaddrinfo yapmamak uzere
 * onbelleklenir. sb_fw_lock, fw_block_ip cagrisindan ONCE birakilir. */
static void sb_prime_resolve(const char *victim, const char *domain,
                             const char *owner_ip, const char *owner_domain) {
    if (!victim || !victim[0] || !domain || !domain[0]) return;
    if (strcmp(domain, "*") == 0 || strcmp(victim, "*") == 0) return;

    /* Cozumleme onbellegi: bu cift icin zaten calistiysak cik. */
    char key[SB_IP_LEN + SB_DOMAIN_LEN + 2];
    snprintf(key, sizeof(key), "%s|%s", victim, domain);
    platform_mutex_lock(&sb_fw_lock);
    for (int i = 0; i < sb_primed_count; i++) {
        if (strcmp(sb_primed_key[i], key) == 0) {
            platform_mutex_unlock(&sb_fw_lock);
            return;
        }
    }
    if (sb_primed_count < SB_PRIME_MAX)
        strncpy(sb_primed_key[sb_primed_count++], key, sizeof(sb_primed_key[0]) - 1);
    platform_mutex_unlock(&sb_fw_lock);

    /* Bastaki joker/kok noktalari soy; icte kalan joker cozumlenemez. */
    const char *base = domain;
    while (*base == '*' || *base == '.') base++;
    if (!base[0] || strchr(base, '*')) return;

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(base, NULL, &hints, &res) == 0) {
        for (struct addrinfo *p = res; p; p = p->ai_next) {
            char ipbuf[INET_ADDRSTRLEN];
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ai_addr;
            if (sin && inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf)))
                site_block_fw_block_ip(victim, ipbuf, owner_ip, owner_domain);
        }
        freeaddrinfo(res);
    }
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

    /* Kurban bu makinenin kendi IP'si mi? Oyleyse Ethernet yerine yerel
     * (AF_INET/IP_HDRINCL) teslim kullanilir. */
    int local = sb_is_own_ip(victim);

    /* --- Cekirdek (iptables) deterministik katman ---
     * Enjeksiyondan BAGIMSIZ calisir: ham soket hazir olmasa bile kural
     * kurulur, boylece yaris ortadan kalkar. */
    {
        const char *dstip = pkt->dst_ip;
        if (pkt->domain_kind == DOMAIN_KIND_DNS) {
            /* Gozlemlenen sorgu adini HEM desen olarak duser HEM de cozumleyip
             * elde edilen IP'leri kurariz (uygulama SNI gondermeden o IP'lere
             * baglansa bile engellensin). */
            sb_prime_resolve(victim, pkt->app_domain, rule.ip, rule.domain);
            if (is_udp)
                site_block_fw_block_dns(victim, pkt->app_domain, rule.ip, rule.domain);
        } else if (dstip && dstip[0] && strcmp(dstip, victim) != 0) {
            site_block_fw_block_ip(victim, dstip, rule.ip, rule.domain);
            /* SNI/QUIC/HTTP alan adinin tum A kayitlarini da kapat (ek IP'ler
             * ayni uygulama tarafindan kullaniliyor olabilir). */
            sb_prime_resolve(victim, pkt->app_domain, rule.ip, rule.domain);
        }
    }

    /* Ham enjeksiyon gerekli. Yerel (kendi IP) modda AF_PACKET olmasa bile
     * AF_INET ham soketi yeterlidir -> inited kontrolu de kabul edilir. */
    if (!sb_ri.ok && !sb_ri.inited && !sb_test_sink) {
        platform_mutex_lock(&sb_lock);
        sb_ensure_raw();
        platform_mutex_unlock(&sb_lock);
    }
    if (!sb_ri.ok && !sb_ri.inited && !sb_test_sink) return;

    int mode = rule.mode;
    int did = 0;

    switch (pkt->domain_kind) {
    case DOMAIN_KIND_DNS:
        if ((mode & SB_MODE_SINKHOLE) && is_udp) {
            if (sb_enforce_dns_sinkhole(pkt, local) == 0) did = 1;
        } else if ((mode & SB_MODE_RST) && is_tcp) {
            if (sb_enforce_rst(pkt, local) == 0) did = 1;
        }
        break;
    case DOMAIN_KIND_SNI:
    case DOMAIN_KIND_HTTP:
        if ((mode & SB_MODE_RST) && is_tcp) {
            if (sb_enforce_rst(pkt, local) == 0) did = 1;
        }
        break;
    case DOMAIN_KIND_QUIC:
        /* RST ve BOTH modlari ICMP unreachable uretir; SINKHOLE tek basina uretmez */
        if (mode & SB_MODE_RST) {
            if (sb_enforce_quic_icmp(pkt, local) == 0) did = 1;
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
