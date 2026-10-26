/*
 * sentinel_core.c — SENTINEL cekirdegi
 *
 *   - Bellek ici durum (targets / findings / log); kalici kayit yok
 *   - YAML alt kumesi konfigurasyon
 *   - Yapisal log (JSONL dosyasi + GUI icin halka tampon)
 *   - CVSS 3.1 base skoru
 *   - Faz state machine + orkestrator thread (exception isolation)
 *
 * Mevcut kamera modullerine HICBIR sekilde yazmaz; camera_discovery'yi
 * yalnizca okur (sn_surface_scan).
 */
#include "sentinel.h"
#include "camera_discovery.h"
#include "utils.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

/* ==================== Konfigurasyon ==================== */

typedef struct {
    char target_cidr[64];
    int  aggressiveness;          /* 1 = sessiz, 2 = normal, 3 = agresif */
    int  cloud_enabled;
    int  fuzz_enabled;
    int  fuzz_rate;               /* istek/sn */
    int  fuzz_max;
    int  pivot_enabled;
    int  timeout_ms;
    char firmware_image[SN_PATH_LEN];
    char firmware_url[SN_URL_LEN];
    char wordlist[SN_PATH_LEN];
    char window[32];              /* "22:00-06:00" veya bos */

} SnConfig;

static SnConfig g_cfg;
static int      g_cfg_loaded = 0;

/* ==================== Global durum ==================== */

static platform_mutex_t g_lock;
static int g_lock_ready = 0;

static SnTarget  g_targets[SN_MAX_TARGETS];
static int       g_target_n = 0;

static SnFinding g_findings[SN_MAX_FINDINGS];
static int       g_finding_n = 0;
static int       g_finding_seq = 1;

static char g_log[SN_MAX_LOG][256];
static int  g_log_n = 0;      /* toplam yazilan (ring index hesabi icin) */

static SnStatus g_st;
static volatile int g_stop_req = 0;
static volatile int g_run_thread = 0;

/* ==================== Kucuk yardimcilar ==================== */

long sn_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long)tv.tv_sec * 1000L + tv.tv_usec / 1000L;
}

static void sn_sleep_ms(int ms) {
    if (ms > 0) platform_sleep_ms((unsigned)ms);
}

static void json_esc(const char *in, char *out, int outlen) {
    int j = 0;
    if (outlen <= 0) return;
    for (int i = 0; in && in[i] && j < outlen - 8; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') { out[j++] = '\\'; out[j++] = (char)c; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else if (c < 0x20) { j += snprintf(out + j, (size_t)(outlen - j), "\\u%04x", c); }
        else out[j++] = (char)c;
    }
    out[j] = '\0';
}

void sn_logf(const char *fmt, ...) {
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    char ts[32];
    time_now_hms(ts, sizeof(ts));

    if (g_lock_ready) platform_mutex_lock(&g_lock);
    int idx = g_log_n % SN_MAX_LOG;
    snprintf(g_log[idx], sizeof(g_log[idx]), "[%s] %s", ts, line);
    g_log_n++;
    if (g_lock_ready) platform_mutex_unlock(&g_lock);

    fprintf(stderr, "[SENTINEL] %s\n", line);
}

const char *sn_phase_name(SnPhase p) {
    switch (p) {
    case SN_PH_SURFACE:     return "1 - Yuzey Haritalama";
    case SN_PH_FINGERPRINT: return "2 - Derin Fingerprint";
    case SN_PH_FIRMWARE:    return "3 - Firmware Istihbarati";
    case SN_PH_PROTOCOL:    return "4 - Protokol Mantik Avcisi";
    case SN_PH_FUZZ:        return "5 - Fuzzing Motoru";
    case SN_PH_CLOUD:       return "6 - Cloud / P2P Zinciri";
    case SN_PH_PIVOT:       return "7 - Pivot / Pasif Istismar";
    case SN_PH_EXPLOIT:     return "8 - Exploit Engine";
    case SN_PH_REPORT:      return "10 - Raporlama";
    case SN_PH_DONE:        return "tamamlandi";
    default:                return "bekliyor";
    }
}

const char *sn_phase_desc(SnPhase p) {
    switch (p) {
    case SN_PH_SURFACE:     return "kesif + servis/parser envanteri";
    case SN_PH_FINGERPRINT: return "vendor / SoC / fw surumu";
    case SN_PH_FIRMWARE:    return "indirme, unpack, secret mining, pre-auth yolu";
    case SN_PH_PROTOCOL:    return "ONVIF / RTSP / SDK mantik zafiyetleri";
    case SN_PH_FUZZ:        return "yapi-farkindalikli mutasyon, crash triage";
    case SN_PH_CLOUD:       return "P2P/cloud endpoint ve pin analizi";
    case SN_PH_PIVOT:       return "MITM, multicast, NVR taklidi";
    case SN_PH_EXPLOIT:     return "dinamik vektor secimi, check/exploit";
    case SN_PH_REPORT:      return "pentest deliverable + disclosure";
    default:                return "";
    }
}

/* ==================== SHA-256 ==================== */

int sn_sha256_file(const char *path, char *hex, int hexlen) {
    if (!path || !hex || hexlen < 65) return -1;
    hex[0] = '\0';
#ifdef HAVE_OPENSSL
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { fclose(f); return -1; }
    unsigned char buf[65536], md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    int ok = (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1);
    while (ok) {
        size_t n = fread(buf, 1, sizeof(buf), f);
        if (n == 0) break;
        if (EVP_DigestUpdate(ctx, buf, n) != 1) { ok = 0; break; }
    }
    if (ok && EVP_DigestFinal_ex(ctx, md, &mdlen) == 1) {
        for (unsigned i = 0; i < mdlen && (int)(i * 2 + 2) < hexlen; i++)
            sprintf(hex + i * 2, "%02x", md[i]);
        hex[mdlen * 2] = '\0';
    } else ok = 0;
    EVP_MD_CTX_free(ctx);
    fclose(f);
    return ok ? 0 : -1;
#else
    (void)path;
    return -1;
#endif
}

/* ==================== CVSS 3.1 ==================== */

static double cvss_roundup(double v) {
    int i = (int)(v * 100000.0);
    if (i % 10000 == 0) return (double)i / 100000.0;
    return (double)((i / 10000) + 1) / 10.0;
}

double sn_cvss_base(const char *vector) {
    if (!vector || !*vector) return 0.0;
    double av = -1, ac = -1, pr = -1, ui = -1, c = -1, i = -1, a = -1;
    int scope_changed = 0;

    const char *p = vector;
    while ((p = strstr(p, "/"))) {
        const char *tok = p + 1;
        char key[8] = {0};
        int n = 0;
        while (tok[n] && tok[n] != ':' && n < 7) { key[n] = tok[n]; n++; }
        key[n] = '\0';
        char val = (tok[n] == ':') ? tok[n + 1] : '\0';

        if (!strcasecmp(key, "AV")) {
            if (val == 'N') av = 0.85; else if (val == 'A') av = 0.62;
            else if (val == 'L') av = 0.55; else if (val == 'P') av = 0.2;
        } else if (!strcasecmp(key, "AC")) {
            if (val == 'L') ac = 0.77; else if (val == 'H') ac = 0.44;
        } else if (!strcasecmp(key, "PR")) {
            /* Scope'a gore PR farkli; S anahtari sonra gelebilir -> sakla */
            if (val == 'N') pr = 0.85; else if (val == 'L') pr = 0.62;
            else if (val == 'H') pr = 0.27;
        } else if (!strcasecmp(key, "UI")) {
            if (val == 'N') ui = 0.85; else if (val == 'R') ui = 0.62;
        } else if (!strcasecmp(key, "S")) {
            scope_changed = (val == 'C');
        } else if (!strcasecmp(key, "C")) {
            if (val == 'H') c = 0.56; else if (val == 'L') c = 0.22; else if (val == 'N') c = 0.0;
        } else if (!strcasecmp(key, "I")) {
            if (val == 'H') i = 0.56; else if (val == 'L') i = 0.22; else if (val == 'N') i = 0.0;
        } else if (!strcasecmp(key, "A")) {
            if (val == 'H') a = 0.56; else if (val == 'L') a = 0.22; else if (val == 'N') a = 0.0;
        }
        p = tok;
    }
    if (av < 0 || ac < 0 || pr < 0 || ui < 0 || c < 0 || i < 0 || a < 0) return 0.0;

    /* PR scope degisimine gore yeniden olceklenir */
    if (scope_changed && pr == 0.62) pr = 0.68;
    else if (scope_changed && pr == 0.27) pr = 0.50;

    double iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    double impact = scope_changed
        ? 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        : 6.42 * iss;
    if (impact <= 0) return 0.0;

    double expl = 8.22 * av * ac * pr * ui;
    double base = scope_changed
        ? cvss_roundup(fmin(1.08 * (impact + expl), 10.0))
        : cvss_roundup(fmin(impact + expl, 10.0));
    return base;
}

void sn_severity_from_cvss(double s, char *out, int len) {
    if (!out || len <= 0) return;
    const char *v = "bilgi";
    if (s >= 9.0) v = "kritik";
    else if (s >= 7.0) v = "yuksek";
    else if (s >= 4.0) v = "orta";
    else if (s > 0.0) v = "dusuk";
    snprintf(out, (size_t)len, "%s", v);
}


/* ==================== Konfigurasyon okuyucu ==================== */

static void cfg_defaults(void) {
    memset(&g_cfg, 0, sizeof(g_cfg));
    g_cfg.aggressiveness = 2;
    g_cfg.cloud_enabled  = 1;
    g_cfg.fuzz_enabled   = 1;
    g_cfg.fuzz_rate      = 8;
    g_cfg.fuzz_max       = 400;
    g_cfg.pivot_enabled  = 0;
    g_cfg.timeout_ms     = 2500;
}

static void cfg_set(const char *key, const char *val) {
    /* tirnaklari temizle */
    char v[SN_PATH_LEN];
    snprintf(v, sizeof(v), "%s", val);
    char *p = v;
    while (*p == ' ' || *p == '\t') p++;
    size_t n = strlen(p);
    while (n && (p[n - 1] == '\n' || p[n - 1] == '\r' || p[n - 1] == ' ')) p[--n] = '\0';
    if (n >= 2 && ((p[0] == '"' && p[n - 1] == '"') || (p[0] == '\'' && p[n - 1] == '\''))) {
        p[n - 1] = '\0'; p++;
    }

    if (!strcmp(key, "target_cidr"))       snprintf(g_cfg.target_cidr, sizeof(g_cfg.target_cidr), "%s", p);
    else if (!strcmp(key, "aggressiveness")) g_cfg.aggressiveness = atoi(p);
    else if (!strcmp(key, "cloud"))          g_cfg.cloud_enabled = (!strcasecmp(p, "true") || !strcmp(p, "1"));
    else if (!strcmp(key, "fuzz"))           g_cfg.fuzz_enabled = (!strcasecmp(p, "true") || !strcmp(p, "1"));
    else if (!strcmp(key, "fuzz_rate"))      g_cfg.fuzz_rate = atoi(p);
    else if (!strcmp(key, "fuzz_max"))       g_cfg.fuzz_max = atoi(p);
    else if (!strcmp(key, "pivot"))          g_cfg.pivot_enabled = (!strcasecmp(p, "true") || !strcmp(p, "1"));
    else if (!strcmp(key, "timeout_ms"))     g_cfg.timeout_ms = atoi(p);
    else if (!strcmp(key, "firmware_image")) snprintf(g_cfg.firmware_image, sizeof(g_cfg.firmware_image), "%s", p);
    else if (!strcmp(key, "firmware_url"))   snprintf(g_cfg.firmware_url, sizeof(g_cfg.firmware_url), "%s", p);
    else if (!strcmp(key, "wordlist"))       snprintf(g_cfg.wordlist, sizeof(g_cfg.wordlist), "%s", p);
    else if (!strcmp(key, "window"))         snprintf(g_cfg.window, sizeof(g_cfg.window), "%s", p);
}

int sn_load_config(const char *path) {
    if (!path || !*path) return -1;
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    if (!g_cfg_loaded) { cfg_defaults(); g_cfg_loaded = 1; }

    char line[1024];
    char section[64] = "";
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\0' || *s == '\n') continue;

        /* ust seviye anahtar: deger */
        if (*s != ' ' && *s != '\t') {
            char *colon = strchr(s, ':');
            if (colon) {
                *colon = '\0';
                char key[64];
                snprintf(key, sizeof(key), "%s", s);
                str_trim(key);
                /* "fuzz:" gibi blok basligi -> bolum adi, deger bos */
                char *val = colon + 1;
                while (*val == ' ' || *val == '\t') val++;
                if (*val == '\0' || *val == '\n' || *val == '\r') {
                    snprintf(section, sizeof(section), "%s", key);
                    continue;
                }
                cfg_set(key, val);
                section[0] = '\0';
            }
            continue;
        }
        /* girintili alt anahtar (bolum icinde) */
        if (section[0]) {
            char *colon = strchr(s, ':');
            if (colon) {
                *colon = '\0';
                char key[64];
                snprintf(key, sizeof(key), "%s", s);
                str_trim(key);
                char full[96];
                snprintf(full, sizeof(full), "%s", key);
                cfg_set(full, colon + 1);
            }
        }
    }
    fclose(f);

    if (g_cfg.aggressiveness < 1) g_cfg.aggressiveness = 1;
    if (g_cfg.aggressiveness > 3) g_cfg.aggressiveness = 3;
    return 0;
}

/* YAML'deki "fuzz:" blogu alt anahtarlari (rate/max) dogrudan
 * fuzz_rate / fuzz_max olarak da kabul edilir; blok yaziminda
 * "rate" ve "max" anahtarlarini eslestir. */
static void cfg_apply_section_defaults(void) {
    if (g_cfg.fuzz_rate <= 0) g_cfg.fuzz_rate = 8;
    if (g_cfg.fuzz_max  <= 0) g_cfg.fuzz_max  = 400;
    if (g_cfg.timeout_ms <= 0) g_cfg.timeout_ms = 2500;
}

/* ==================== Init / shutdown ==================== */

int sn_init(const char *cfg_path) {
    if (!g_lock_ready) {
        if (platform_mutex_init(&g_lock) != 0) return -1;
        g_lock_ready = 1;
    }
    memset(&g_st, 0, sizeof(g_st));
    for (int i = 0; i < SN_PH_COUNT; i++) g_st.pstate[i] = SPS_PENDING;

    cfg_defaults();
    if (cfg_path && *cfg_path) {
        if (sn_load_config(cfg_path) == 0) sn_logf("konfigurasyon yuklendi: %s", cfg_path);
        else sn_logf("konfigurasyon bulunamadi (%s), varsayilanlar kullaniliyor", cfg_path);
    }
    cfg_apply_section_defaults();

    /* Kalici kayit YOK: her sey anlik, bellek ici; diske tek bayt yazilmaz. */
    sn_logf("bellek ici mod (kalici kayit / rapor devre disi)");

    sn_logf("SENTINEL %s hazir (agresiflik=%d, cloud=%d, fuzz=%d)",
            SN_VERSION, g_cfg.aggressiveness, g_cfg.cloud_enabled, g_cfg.fuzz_enabled);
    return 0;
}

void sn_shutdown(void) {
    sn_stop_run();
    for (int i = 0; i < 40 && g_run_thread; i++) sn_sleep_ms(50);
    if (g_lock_ready) { platform_mutex_destroy(&g_lock); g_lock_ready = 0; }
}

/* ==================== Hedef / bulgu API ==================== */

static int target_find(const char *ip) {
    for (int i = 0; i < g_target_n; i++)
        if (!strcmp(g_targets[i].ip, ip)) return i;
    return -1;
}

/* Faz 3 sonucunu paylasilan duruma yaz: rapor yazici firmware bolumunu
 * yalnizca g_st.fw_loaded set edildiginde basiyor. CLI/GUI dogrudan
 * analiz yaptiginda bunu cagirmazsa rapor "firmware analiz edilmedi"
 * diyordu (gercek analiz yapilmis olmasina ragmen). */
void sn_fw_state_set(const SnFwResult *r) {
    if (!r) return;
    if (g_lock_ready) platform_mutex_lock(&g_lock);
    g_st.fw = *r;
    g_st.fw_loaded = 1;
    g_st.pstate[SN_PH_FIRMWARE] = SPS_OK;
    if (g_lock_ready) platform_mutex_unlock(&g_lock);
}

int sn_add_target(const char *ip) {
    if (!ip || !*ip) return -1;
    if (g_lock_ready) platform_mutex_lock(&g_lock);
    int idx = target_find(ip);
    if (idx < 0) {
        if (g_target_n >= SN_MAX_TARGETS) {
            if (g_lock_ready) platform_mutex_unlock(&g_lock);
            return -1;
        }
        idx = g_target_n++;
        memset(&g_targets[idx], 0, sizeof(SnTarget));
        snprintf(g_targets[idx].ip, sizeof(g_targets[idx].ip), "%s", ip);
        g_targets[idx].seen_at = time(NULL);
        sn_logf("hedef eklendi: %s", ip);
    }
    g_st.target_count = g_target_n;
    if (g_lock_ready) platform_mutex_unlock(&g_lock);
    return 0;
}

int sn_finding_add(const SnFinding *f) {
    if (!f || !f->title[0]) return -1;

    SnFinding nf = *f;
    if (!nf.ts) nf.ts = time(NULL);
    if (!nf.status[0]) snprintf(nf.status, sizeof(nf.status), "candidate");
    if (!nf.severity[0]) sn_severity_from_cvss(nf.cvss, nf.severity, sizeof(nf.severity));

    if (g_lock_ready) platform_mutex_lock(&g_lock);
    /* dedupe: ayni sinif + baslik + hedef */
    for (int i = 0; i < g_finding_n; i++) {
        if (!strcmp(g_findings[i].cls, nf.cls) &&
            !strcmp(g_findings[i].title, nf.title) &&
            !strcmp(g_findings[i].target, nf.target)) {
            if (g_lock_ready) platform_mutex_unlock(&g_lock);
            return 0;
        }
    }
    if (g_finding_n >= SN_MAX_FINDINGS) {
        if (g_lock_ready) platform_mutex_unlock(&g_lock);
        return -1;
    }
    nf.id = g_finding_seq++;
    g_findings[g_finding_n++] = nf;
    if (!strcmp(nf.status, "confirmed")) g_st.confirmed++;
    g_st.candidates = g_finding_n - g_st.confirmed;
    g_st.finding_count = g_finding_n;
    if (g_lock_ready) platform_mutex_unlock(&g_lock);

    sn_logf("BULGU [%s/%d] %s%s%s", nf.severity, nf.confidence,
            nf.cls, nf.target[0] ? " @ " : "", nf.target[0] ? nf.target : nf.title);
    return 0;
}

void sn_clear_findings(void) {
    if (g_lock_ready) platform_mutex_lock(&g_lock);
    g_finding_n = 0;
    g_st.finding_count = 0;
    g_st.confirmed = 0;
    g_st.candidates = 0;
    if (g_lock_ready) platform_mutex_unlock(&g_lock);
    sn_logf("bulgu listesi temizlendi");
}

int sn_get_targets(SnTarget *out, int max) {
    if (!out || max <= 0) return 0;
    if (g_lock_ready) platform_mutex_lock(&g_lock);
    int n = g_target_n < max ? g_target_n : max;
    memcpy(out, g_targets, (size_t)n * sizeof(SnTarget));
    if (g_lock_ready) platform_mutex_unlock(&g_lock);
    return n;
}

int sn_get_findings(SnFinding *out, int max) {
    if (!out || max <= 0) return 0;
    if (g_lock_ready) platform_mutex_lock(&g_lock);
    int n = g_finding_n < max ? g_finding_n : max;
    memcpy(out, g_findings, (size_t)n * sizeof(SnFinding));
    if (g_lock_ready) platform_mutex_unlock(&g_lock);
    return n;
}

int sn_get_log(char lines[][256], int max) {
    if (!lines || max <= 0) return 0;
    if (g_lock_ready) platform_mutex_lock(&g_lock);
    int total = g_log_n < SN_MAX_LOG ? g_log_n : SN_MAX_LOG;
    int n = total < max ? total : max;
    /* en yeni once */
    for (int i = 0; i < n; i++) {
        int idx = (g_log_n - 1 - i) % SN_MAX_LOG;
        if (idx < 0) idx += SN_MAX_LOG;
        snprintf(lines[i], 256, "%s", g_log[idx]);
    }
    if (g_lock_ready) platform_mutex_unlock(&g_lock);
    return n;
}

void sn_get_status(SnStatus *st) {
    if (!st) return;
    if (g_lock_ready) platform_mutex_lock(&g_lock);
    *st = g_st;
    if (g_lock_ready) platform_mutex_unlock(&g_lock);
}

/* ==================== Zaman penceresi ==================== */

/* "22:00-06:00" ise gece yarisini asan aralik desteklenir. */
static int in_window(const char *win) {
    if (!win || !*win) return 1;
    int h1 = -1, m1 = -1, h2 = -1, m2 = -1;
    if (sscanf(win, "%d:%d-%d:%d", &h1, &m1, &h2, &m2) != 4) return 1;
    time_t now = time(NULL);
    struct tm tmnow;
    localtime_r(&now, &tmnow);
    int cur = tmnow.tm_hour * 60 + tmnow.tm_min;
    int a = h1 * 60 + m1, b = h2 * 60 + m2;
    if (a <= b) return cur >= a && cur <= b;
    return cur >= a || cur <= b;
}

/* ==================== Faz 1: yuzey ==================== */

/* camera_discovery sonuclarini SALT OKUNUR tuketir; kendi modulune
 * dokunmaz. Ek olarak kamera imzali portlari kendi hafif connect
 * sondasiyla dogrular (yeni kod, eski motor degismez). */
int sn_surface_scan(void) {
    CameraScanResults res;
    memset(&res, 0, sizeof(res));
    camera_discovery_get_results(&res);

    int added = 0;
    for (int i = 0; i < res.count && i < CAM_MAX_DEVICES; i++) {
        const CameraDevice *c = &res.cameras[i];
        if (!c->ip[0]) continue;

        char base[64];
        snprintf(base, sizeof(base), "%s", c->ip);
        if (sn_add_target(base) == 0) added++;

        if (g_lock_ready) platform_mutex_lock(&g_lock);
        int idx = target_find(base);
        if (idx >= 0) {
            SnTarget *t = &g_targets[idx];
            if (c->vendor[0])      snprintf(t->vendor, sizeof(t->vendor), "%s", c->vendor);
            if (c->manufacturer[0]) snprintf(t->model, sizeof(t->model), "%s", c->manufacturer);
            if (c->mac[0])         snprintf(t->mac, sizeof(t->mac), "%s", c->mac);
            t->rtsp_port  = c->rtsp_port;
            t->http_port  = c->http_port;
            t->onvif_port = c->has_onvif ? 80 : 0;
            t->evidence   = c->evidence;
            t->confidence = c->confidence;
            t->seen_at    = c->discovered_at ? c->discovered_at : time(NULL);
        }
        if (g_lock_ready) platform_mutex_unlock(&g_lock);
    }

    SnTarget snap[SN_MAX_TARGETS];
    int n = sn_get_targets(snap, SN_MAX_TARGETS);

    if (n > 0)
        sn_logf("faz1: camera_discovery'den %d kamera alindi (%d yeni), toplam hedef %d",
                res.count, added, n);
    else
        sn_logf("faz1: camera_discovery sonucu bos - agda kamera yok "
                "(mevcut recon korunuyor, hedef elle eklenebilir)");

    g_st.target_count = n;
    return n;
}

/* ==================== Orkestrator ==================== */

typedef struct {
    SnPhase phase;
    int (*run_target)(SnTarget *);
    int needs_target;          /* 1 = hedef yoksa SKIPPED */
    int enabled;               /* konfigurasyona bagli */
} PhaseDef;

static void set_phase(SnPhase p, SnPhaseState s, const char *msg) {
    if (g_lock_ready) platform_mutex_lock(&g_lock);
    g_st.phase = p;
    g_st.pstate[p] = s;
    if (msg) snprintf(g_st.msg, sizeof(g_st.msg), "%s", msg);
    if (g_lock_ready) platform_mutex_unlock(&g_lock);
}

static void *orchestrator_main(void *arg) {
    (void)arg;
    extern int sn_pivot_run(SnTarget *t);

    PhaseDef plan[] = {
        { SN_PH_SURFACE,     NULL,                 0, 1 },
        { SN_PH_FINGERPRINT, sn_fingerprint_target, 1, 1 },
        { SN_PH_FIRMWARE,    NULL,                 0, 1 },
        { SN_PH_PROTOCOL,    sn_protocol_run,      1, 1 },
        { SN_PH_FUZZ,        sn_fuzz_run,          1, 1 },
        { SN_PH_CLOUD,       sn_cloud_run,         1, 1 },
        { SN_PH_PIVOT,       NULL,                 1, 1 },
        { SN_PH_EXPLOIT,     sn_exploit_decide,    1, 1 },
    };
    const int plan_n = (int)(sizeof(plan) / sizeof(plan[0]));

    g_st.started = time(NULL);
    g_st.run_active = 1;
    g_st.run_done = 0;

    for (int pi = 0; pi < plan_n && !g_stop_req; pi++) {
        PhaseDef *pd = &plan[pi];

        if (!pd->enabled) { set_phase(pd->phase, SPS_SKIPPED, "modul kapali"); continue; }
        if (!in_window(g_cfg.window)) {
            set_phase(pd->phase, SPS_SKIPPED, "zaman penceresi disinda");
            sn_logf("%s: zaman penceresi disinda, atlandi", sn_phase_name(pd->phase));
            continue;
        }

        set_phase(pd->phase, SPS_RUNNING, sn_phase_desc(pd->phase));
        sn_logf(">>> %s", sn_phase_name(pd->phase));

        int rc = 0;
        if (pd->phase == SN_PH_SURFACE) {
            rc = sn_surface_scan();
            set_phase(pd->phase, SPS_OK, "yuzey haritalandi");
        } else if (pd->phase == SN_PH_FIRMWARE) {
            /* fw_loaded sifirlanmaz: onceki kalici analiz varsa (state store)
             * yapilandirmada imaj yokken de rapor 4. bolumu bos kalmamali. */
            if (g_cfg.firmware_image[0]) {
                SnFwResult fw;
                memset(&fw, 0, sizeof(fw));
                sn_logf("faz3: yerel firmware imaji analiz ediliyor: %s", g_cfg.firmware_image);
                if (sn_fw_analyze(g_cfg.firmware_image, &fw, 1) == 0) {
                    g_st.fw = fw;
                    g_st.fw_loaded = 1;
                    set_phase(pd->phase, SPS_OK, "firmware analizi tamam");
                    rc = 1;
                } else {
                    set_phase(pd->phase, SPS_FAILED, "firmware analizi basarisiz");
                }
            } else if (g_st.fw_loaded) {
                set_phase(pd->phase, SPS_OK,
                          "firmware_image bos - kayitli son analiz kullaniliyor");
                sn_logf("faz3: firmware_image tanimli degil, kayitli analiz korunuyor");
            } else {
                set_phase(pd->phase, SPS_SKIPPED,
                          "firmware imaji yok (yapilandirmada firmware_image bos)");
                sn_logf("faz3: firmware_image tanimli degil - analiz atlandi");
            }
        } else if (pd->phase == SN_PH_PIVOT) {
            SnTarget snap[SN_MAX_TARGETS];
            int n = sn_get_targets(snap, SN_MAX_TARGETS);
            if (n <= 0) { set_phase(pd->phase, SPS_SKIPPED, "hedef yok"); continue; }
            if (!g_cfg.pivot_enabled) {
                set_phase(pd->phase, SPS_SKIPPED, "pivot konfigurasyonda kapali");
                sn_logf("faz7: pivot kapali (guvenlik varsayilani)");
                continue;
            }
            for (int i = 0; i < n && !g_stop_req; i++) {
                if (sn_pivot_run(&snap[i]) != 0)
                    sn_logf("faz7: %s pivot basarisiz", snap[i].ip);
                sn_sleep_ms(200 * g_cfg.aggressiveness);
            }
            set_phase(pd->phase, SPS_OK, "pivot tamam");
        } else {
            SnTarget snap[SN_MAX_TARGETS];
            int n = sn_get_targets(snap, SN_MAX_TARGETS);
            if (n <= 0) {
                set_phase(pd->phase, SPS_SKIPPED, "hedef yok");
                continue;
            }
            int ok = 0, fail = 0;
            for (int i = 0; i < n && !g_stop_req; i++) {
                if (pd->run_target) {
                    if (pd->run_target(&snap[i]) == 0) ok++;
                    else fail++;
                }
                g_st.progress = (int)((100.0 * (i + 1)) / (double)n);
                sn_sleep_ms((4 - g_cfg.aggressiveness) * 150);
            }
            set_phase(pd->phase, fail && !ok ? SPS_FAILED : SPS_OK,
                      fail ? "bazi hedefler basarisiz" : "tamam");
        }
        (void)rc;
    }

    if (!g_stop_req)
        set_phase(SN_PH_REPORT, SPS_SKIPPED, "rapor devre disi (anlik mod)");

    if (g_lock_ready) platform_mutex_lock(&g_lock);
    g_st.phase = SN_PH_DONE;
    g_st.progress = 100;
    g_st.run_active = 0;
    g_st.run_done = 1;
    g_st.finished = time(NULL);
    snprintf(g_st.msg, sizeof(g_st.msg), "%s",
             g_stop_req ? "durduruldu" : "tamamlandi");
    if (g_lock_ready) platform_mutex_unlock(&g_lock);

    sn_logf("orkestrator bitti (%d bulgu, %d dogrulanmis)",
            g_st.finding_count, g_st.confirmed);
    g_run_thread = 0;
    return NULL;
}

int sn_start_run(void) {
    if (g_run_thread) {
        sn_logf("calisma zaten aktif");
        return -1;
    }
    g_stop_req = 0;
    g_run_thread = 1;
    g_st.run_done = 0;
    for (int i = 0; i < SN_PH_COUNT; i++) g_st.pstate[i] = SPS_PENDING;

    platform_thread_t th;
    if (platform_thread_create(&th, orchestrator_main, NULL) != 0) {
        g_run_thread = 0;
        sn_logf("orkestrator thread baslatilamadi");
        return -1;
    }
    platform_thread_detach(th);
    sn_logf("calisma baslatildi");
    return 0;
}

void sn_stop_run(void) {
    if (g_run_thread) {
        g_stop_req = 1;
        sn_logf("durdurma istendi");
    }
}
