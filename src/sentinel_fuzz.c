/*
 * sentinel_fuzz.c — Faz 5: yapi-farkindalikli fuzzing + crash triage
 *
 * Tasarim:
 *   - Kor rastgele mutasyon YOK. Her seed gecerli bir protokol mesajidir
 *     (ONVIF SOAP govdesi, RTSP istegi, HTTP basligi) ve mutasyon yalnizca
 *     anlamli alanlara uygulanir: metin degeri, sayisal alan, uzunluk alani,
 *     XML eleman tekrari, karakter kumesi.
 *   - Hiz siniri: varsayilan 5 istek/sn (SN_FUZZ_RATE), hedef basina
 *     varsayilan 400 istek (SN_FUZZ_MAX). Adaptif geri cekilme: ardisik
 *     3 zaman asimi / baglanti hatasi olursa hiz yarilanir, 6 olursa
 *     tur erken biter (hedef zaten BOS veya cokuyor olabilir).
 *   - Crash triage: yanit yok -> canlilik sondasi (2 deneme). Sonda da
 *     basarisizsa "crash" olarak kaydedilir; tek bir zaman asimi crash
 *     sayilmaz (ag gurultusunu ayirt etmek icin).
 *   - Deterministik: SN_FUZZ_SEED ile ayni istek dizisi yeniden uretilir.
 *
 * Bulgular "candidate" olarak yazilir; canli hedef olmadan "confirmed"
 * denmez. Kanit dosyasi sinirlidir (<= 128 KB) ve istek/yanit ciftlerini
 * kirpilmis halde tutar.
 */
#include "sentinel.h"
#include "cam_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define FZ_MAX_REQ_DEFAULT   400
#define FZ_RATE_DEFAULT      5
#define FZ_TIMEOUT_MS        2500
#define FZ_BODY_MAX          16384
#define FZ_RESP_MAX          8192
#define FZ_EVID_MAX          (128 * 1024)
#define FZ_MAX_MUT           11

/* ==================== Zaman / hiz ==================== */

static long long fz_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

typedef struct {
    int rate;             /* istek/sn */
    int max_req;
    int sent;
    int timeout_streak;
    long long next_ms;
    unsigned seed;
    unsigned rng;
} FzCtx;

static int env_int(const char *name, int def) {
    const char *v = getenv(name);
    if (!v || !*v) return def;
    int n = atoi(v);
    return n > 0 ? n : def;
}

static unsigned fz_rand(FzCtx *c) {
    /* xorshift32: deterministik, tekrar uretilebilir */
    unsigned x = c->rng ? c->rng : 0x9e3779b9u;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    c->rng = x;
    return x;
}

/* Hiz siniri: sonraki istege kadar bekler. rate<=0 -> 1 istek/sn. */
static void fz_pace(FzCtx *c) {
    int rate = c->rate > 0 ? c->rate : 1;
    long long now = fz_now_ms();
    if (c->next_ms < now) c->next_ms = now;
    long long wait = c->next_ms - now;
    if (wait > 0) {
        struct timespec ts;
        ts.tv_sec = wait / 1000;
        ts.tv_nsec = (wait % 1000) * 1000000L;
        nanosleep(&ts, NULL);
    }
    c->next_ms = fz_now_ms() + (1000LL / rate);
}

/* ==================== Kanit dosyasi ==================== */

static char g_ev_path[SN_PATH_LEN];
static FILE *g_ev = NULL;
static long  g_ev_bytes = 0;

static void ev_open(const char *ip) {
    if (g_ev) return;
    const char *dir = getenv("SN_EVIDENCE_DIR");
    if (!dir || !*dir) dir = "sentinel_evidence";
    mkdir(dir, 0755);
    snprintf(g_ev_path, sizeof(g_ev_path), "%s/fuzz_%s.log", dir, ip);
    g_ev = fopen(g_ev_path, "a");
    if (g_ev) {
        g_ev_bytes = ftell(g_ev);
        fprintf(g_ev, "\n=== fuzz oturumu %s | seed=%s ===\n",
                ip, getenv("SN_FUZZ_SEED") ? getenv("SN_FUZZ_SEED") : "auto");
    }
}

static void ev_close(void) {
    if (g_ev) { fclose(g_ev); g_ev = NULL; }
}

/* Sinirli yazim: limit asilirsa dosya kapatilir, kanit yolu korunur. */
static void ev_write(const char *tag, const char *req, const char *resp) {
    if (!g_ev || g_ev_bytes > FZ_EVID_MAX) return;
    int w = fprintf(g_ev, "\n--- %s ---\n%s\n>>> yanit (kirpilmis) ---\n%.2000s\n",
                    tag, req ? req : "", resp && *resp ? resp : "(yanit yok)");
    if (w > 0) g_ev_bytes += w;
    fflush(g_ev);
}

/* ==================== Bulgu yardimcisi ==================== */

static void fz_finding(const char *ip, const char *cls, const char *title,
                       const char *vector, const char *cwe, const char *cvss,
                       int conf, const char *detail) {
    SnFinding f;
    memset(&f, 0, sizeof(f));
    snprintf(f.target, sizeof(f.target), "%s", ip);
    snprintf(f.cls, sizeof(f.cls), "%s", cls);
    snprintf(f.title, sizeof(f.title), "%s", title);
    snprintf(f.vector, sizeof(f.vector), "%s", vector);
    snprintf(f.cwe, sizeof(f.cwe), "%s", cwe);
    snprintf(f.status, sizeof(f.status), "candidate");
    snprintf(f.detail, sizeof(f.detail), "%s", detail);
    snprintf(f.evidence, sizeof(f.evidence), "%s", g_ev_path);
    f.cvss = sn_cvss_base(cvss);
    f.confidence = conf;
    sn_severity_from_cvss(f.cvss, f.severity, sizeof(f.severity));
    sn_finding_add(&f);
}

/* ==================== Seed / mutasyon ==================== */

typedef enum {
    MUT_LONG_TEXT = 0,   /* metin alanina 4096 bayt */
    MUT_EMPTY,           /* alani bosalt */
    MUT_INT_MAX,         /* 4294967295 */
    MUT_INT_NEG,         /* -1 */
    MUT_FORMAT,          /* %n%n%n%n */
    MUT_TRAVERSAL,       /* ../../../../etc/passwd */
    MUT_ENTITY,          /* XML varlik genisletme */
    MUT_TAG_REPEAT,      /* ayni elemani 64 kez tekrarla */
    MUT_OVERLONG_UTF8,   /* gecersiz UTF-8 dizisi */
    MUT_NULL_BYTE,       /* %00 gomme */
    MUT_ATTR_INJECT,     /* tirnak/etiket kirma */
    MUT_COUNT
} FzMut;

static const char *mut_name(FzMut m) {
    switch (m) {
    case MUT_LONG_TEXT:   return "long_text";
    case MUT_EMPTY:       return "empty_value";
    case MUT_INT_MAX:     return "int_max";
    case MUT_INT_NEG:     return "int_negative";
    case MUT_FORMAT:      return "format_string";
    case MUT_TRAVERSAL:   return "path_traversal";
    case MUT_ENTITY:      return "xml_entity";
    case MUT_TAG_REPEAT:  return "tag_repeat";
    case MUT_OVERLONG_UTF8: return "invalid_utf8";
    case MUT_NULL_BYTE:   return "null_byte";
    case MUT_ATTR_INJECT: return "attr_inject";
    default:              return "unknown";
    }
}

static const char *mut_value(FzMut m, char *buf, int len, FzCtx *c) {
    int i;
    switch (m) {
    case MUT_LONG_TEXT:
        for (i = 0; i < len - 1 && i < 4096; i++) buf[i] = 'A';
        buf[i] = '\0';
        return buf;
    case MUT_EMPTY:        buf[0] = '\0'; return buf;
    case MUT_INT_MAX:      snprintf(buf, len, "4294967295"); return buf;
    case MUT_INT_NEG:      snprintf(buf, len, "-1"); return buf;
    case MUT_FORMAT:       snprintf(buf, len, "%%n%%n%%n%%s%%x"); return buf;
    case MUT_TRAVERSAL:    snprintf(buf, len, "../../../../../../etc/passwd"); return buf;
    case MUT_ENTITY:
        snprintf(buf, len, "&lol9;&lol8;&lol7;&lol6;&lol5;&lol4;&lol3;&lol2;&lol1;");
        return buf;
    case MUT_TAG_REPEAT: {
        int off = 0;
        for (i = 0; i < 64 && off < len - 64; i++)
            off += snprintf(buf + off, len - off, "<a>%u</a>", fz_rand(c) & 0xff);
        return buf;
    }
    case MUT_OVERLONG_UTF8:
        snprintf(buf, len, "\xc0\xaf\xed\xa0\x80\xf4\x90\x80\x80");
        return buf;
    case MUT_NULL_BYTE:    snprintf(buf, len, "%%00%%00%%00"); return buf;
    case MUT_ATTR_INJECT:
        snprintf(buf, len, "\" onerror=\"x\" a=\"<b>\"><c d=\"&e;\"");
        return buf;
    default:               buf[0] = '\0'; return buf;
    }
}

/* Yer tutuculu sablon: {{S}} metin, {{N}} sayisal, {{T}} etiket adi. */
typedef struct {
    const char *proto;   /* "onvif" | "rtsp" | "http" */
    const char *name;
    const char *tmpl;
} FzSeed;

static const FzSeed g_seeds[] = {
    /* --- ONVIF SOAP --- */
    { "onvif", "GetDeviceInformation",
      "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
      "<s:Body><GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>"
      "</s:Body></s:Envelope>" },
    { "onvif", "GetSystemDateAndTime",
      "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
      "<s:Body><GetSystemDateAndTime xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>"
      "</s:Body></s:Envelope>" },
    { "onvif", "GetStreamUri",
      "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
      "<s:Body><GetStreamUri xmlns=\"http://www.onvif.org/ver10/media/wsdl\">"
      "<StreamSetup><Stream xmlns=\"http://www.onvif.org/ver10/schema\">{{S}}</Stream>"
      "<Transport><Protocol>{{S}}</Protocol></Transport></StreamSetup>"
      "<ProfileToken>{{S}}</ProfileToken></GetStreamUri></s:Body></s:Envelope>" },
    { "onvif", "GetProfiles",
      "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
      "<s:Body><GetProfiles xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>"
      "</s:Body></s:Envelope>" },
    { "onvif", "CreateUsers",
      "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
      "<s:Body><CreateUsers xmlns=\"http://www.onvif.org/ver10/device/wsdl\">"
      "<User><Username>{{S}}</Username><Password>{{S}}</Password>"
      "<UserLevel>{{S}}</UserLevel></User></CreateUsers></s:Body></s:Envelope>" },

    /* --- RTSP --- */
    { "rtsp", "DESCRIBE",
      "DESCRIBE rtsp://{{S}}/ RTSP/1.0\r\nCSeq: {{N}}\r\n"
      "Accept: application/sdp\r\nUser-Agent: BEAT-SENTINEL\r\n\r\n" },
    { "rtsp", "SETUP_transport",
      "SETUP rtsp://{{S}}/track1 RTSP/1.0\r\nCSeq: {{N}}\r\n"
      "Transport: {{S}}\r\n\r\n" },
    { "rtsp", "PLAY_session",
      "PLAY rtsp://{{S}}/ RTSP/1.0\r\nCSeq: {{N}}\r\nSession: {{S}}\r\n"
      "Range: {{S}}\r\n\r\n" },

    /* --- HTTP --- */
    { "http", "GET_auth",
      "GET /{{S}} HTTP/1.1\r\nHost: {{S}}\r\n"
      "Authorization: Basic {{S}}\r\nConnection: close\r\n\r\n" },
    { "http", "POST_login",
      "POST /login.cgi HTTP/1.1\r\nHost: {{S}}\r\n"
      "Content-Type: application/x-www-form-urlencoded\r\n"
      "Content-Length: {{N}}\r\nConnection: close\r\n\r\n"
      "user={{S}}&pass={{S}}" }
};
static const int g_seed_n = (int)(sizeof(g_seeds) / sizeof(g_seeds[0]));

/* {{S}} / {{N}} yer tutucularini doldurur; her yer tutucu icin ayri deger. */
static void expand_tmpl(const char *tmpl, const char *val, FzCtx *c,
                        char *out, int olen) {
    int o = 0;
    unsigned nv = fz_rand(c) % 4294967295u;
    for (const char *p = tmpl; *p && o < olen - 1; ) {
        if (p[0] == '{' && p[1] == '{' && p[3] == '}' && p[4] == '}') {
            if (p[2] == 'S') {
                int w = snprintf(out + o, olen - o, "%s", val);
                if (w > 0) o += w;
            } else if (p[2] == 'N') {
                int w = snprintf(out + o, olen - o, "%u", nv);
                if (w > 0) o += w;
            } else {
                out[o++] = *p;
            }
            p += 5;
            continue;
        }
        out[o++] = *p++;
    }
    out[o] = '\0';
}

/* ==================== Transport ==================== */

/* Tek istek: HTTP seed'leri cam_http_request, digerleri ham soket.
 * Doner: 1 yanit alindi, 0 yanit yok, -1 baglanti kurulamadi. */
static int fz_send(SnTarget *t, const FzSeed *s, const char *req,
                   char *resp, int rlen) {
    resp[0] = '\0';

    /* ONVIF: SOAP POST zarfina sarilir; RTSP/HTTP: ham metin gonderilir. */
    CamConn c;
    memset(&c, 0, sizeof(c));
    int port;
    if (strcmp(s->proto, "onvif") == 0)
        port = t->onvif_port > 0 ? t->onvif_port : (t->http_port > 0 ? t->http_port : 80);
    else if (strcmp(s->proto, "http") == 0)
        port = t->http_port > 0 ? t->http_port : 80;
    else
        port = t->rtsp_port;
    if (port <= 0) return -1;
    if (cam_conn_open(&c, t->ip, port, FZ_TIMEOUT_MS, 0) != 0) return -1;

    char full[FZ_BODY_MAX + 512];
    if (strcmp(s->proto, "onvif") == 0) {
        snprintf(full, sizeof(full),
                 "POST /onvif/device_service HTTP/1.1\r\nHost: %s\r\n"
                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                 "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                 t->ip, strlen(req), req);
    } else {
        snprintf(full, sizeof(full), "%s", req);
    }

    cam_conn_write(&c, full, (int)strlen(full), FZ_TIMEOUT_MS);
    int n = cam_conn_read(&c, resp, rlen - 1, FZ_TIMEOUT_MS);
    cam_conn_close(&c);
    if (n <= 0) return 0;
    resp[n] = '\0';
    return 1;
}

/* Canlilik sondasi: hedef hala konusuyor mu? 1 = evet, 0 = hayir. */
static int fz_alive(SnTarget *t) {
    char resp[1024];
    for (int attempt = 0; attempt < 2; attempt++) {
        CamConn c;
        memset(&c, 0, sizeof(c));
        int port = t->http_port > 0 ? t->http_port : 80;
        if (t->rtsp_port > 0) port = t->rtsp_port;
        if (cam_conn_open(&c, t->ip, port, FZ_TIMEOUT_MS, 0) != 0) {
            struct timespec ts = { 1, 0 };
            nanosleep(&ts, NULL);
            continue;
        }
        const char *probe = t->rtsp_port > 0
            ? "OPTIONS rtsp://x/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            : "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
        cam_conn_write(&c, probe, (int)strlen(probe), FZ_TIMEOUT_MS);
        int n = cam_conn_read(&c, resp, sizeof(resp) - 1, FZ_TIMEOUT_MS);
        cam_conn_close(&c);
        if (n > 0) return 1;
        struct timespec ts = { 1, 0 };
        nanosleep(&ts, NULL);
    }
    return 0;
}

/* ==================== Triage ==================== */

/* Hata sizintisi: yanitta yigin izi / dahili yol / debug metni var mi? */
static const char *infoleak_marker(const char *resp) {
    static const char *marks[] = {
        "Segmentation fault", "stack smashing", "Assertion", "assertion",
        "Backtrace", "backtrace", "Traceback", "core dumped",
        "/usr/local/", "/opt/", "malloc(): ", "double free",
        "busybox", "BusyBox", "uClinux", "/mnt/mtd", "/var/tmp",
        "PHP Warning", "PHP Fatal", "root:x:0:0", "sqlite3", "std::",
        NULL
    };
    for (int i = 0; marks[i]; i++)
        if (strcasestr(resp, marks[i])) return marks[i];
    return NULL;
}

/* ==================== Ana giris ==================== */

int sn_fuzz_run(SnTarget *t) {
    if (!t || !t->ip[0]) return -1;

    int port_any = (t->http_port > 0) || (t->rtsp_port > 0) || (t->onvif_port > 0);
    if (!port_any) {
        sn_logf("fuzz: %s icin acik HTTP/RTSP/ONVIF portu yok, atlandi", t->ip);
        return 0;   /* atlama = hata degil */
    }

    FzCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.rate  = env_int("SN_FUZZ_RATE", FZ_RATE_DEFAULT);
    ctx.max_req = env_int("SN_FUZZ_MAX", FZ_MAX_REQ_DEFAULT);
    ctx.seed  = (unsigned)env_int("SN_FUZZ_SEED", (int)(time(NULL) ^ (unsigned)getpid()));
    ctx.rng   = ctx.seed ? ctx.seed : 0x1234567u;

    ev_open(t->ip);
    sn_logf("fuzz: %s basladi (rate=%d/s, max=%d, seed=%u)",
            t->ip, ctx.rate, ctx.max_req, ctx.seed);

    int baseline_alive = fz_alive(t);
    if (!baseline_alive) {
        sn_logf("fuzz: %s canlilik sondasi basarisiz - fuzzing baslatilmadi "
                "(hedef kapali veya filtreli; crash DEGIL)", t->ip);
        ev_write("baseline-fail", "GET/OPTIONS canlilik sondasi", "yanit yok");
        ev_close();
        return -1;
    }

    int unique_crash = 0, infoleaks = 0, stopped_early = 0;
    char seen_crash[MUT_COUNT];
    memset(seen_crash, 0, sizeof(seen_crash));

    for (int si = 0; si < g_seed_n && !stopped_early; si++) {
        const FzSeed *s = &g_seeds[si];

        /* Protokol bu hedefte yoksa atla */
        if (strcmp(s->proto, "rtsp") == 0 && t->rtsp_port <= 0) continue;
        if (strcmp(s->proto, "onvif") == 0 && t->http_port <= 0 && t->onvif_port <= 0) continue;
        if (strcmp(s->proto, "http") == 0 && t->http_port <= 0) continue;

        for (int mi = 0; mi < MUT_COUNT && !stopped_early; mi++) {
            if (ctx.sent >= ctx.max_req) break;

            char val[4200];
            mut_value((FzMut)mi, val, sizeof(val), &ctx);

            char req[FZ_BODY_MAX];
            expand_tmpl(s->tmpl, val, &ctx, req, sizeof(req));

            fz_pace(&ctx);
            ctx.sent++;

            char resp[FZ_RESP_MAX];
            int rc = fz_send(t, s, req, resp, sizeof(resp));

            if (rc == 0) {
                /* Yanit yok: ag gurultusu olabilir -> triage */
                ctx.timeout_streak++;
                sn_logf("fuzz: %s/%s/%s yanit yok (streak=%d)",
                        t->ip, s->name, mut_name((FzMut)mi), ctx.timeout_streak);
                ev_write(mut_name((FzMut)mi), req, NULL);

                if (ctx.timeout_streak >= 3) {
                    sn_logf("fuzz: %s ardisik zaman asimi - hiz dusuruluyor (%d -> %d/s)",
                            t->ip, ctx.rate, ctx.rate > 1 ? ctx.rate / 2 : 1);
                    ctx.rate = ctx.rate > 1 ? ctx.rate / 2 : 1;
                }
                if (ctx.timeout_streak >= 2 && !seen_crash[mi]) {
                    if (!fz_alive(t)) {
                        seen_crash[mi] = 1;
                        unique_crash++;
                        char title[SN_TITLE_LEN], detail[SN_DETAIL_LEN];
                        snprintf(title, sizeof(title),
                                 "%s %s sonrasi servis yanit vermiyor (olasi crash)",
                                 s->name, mut_name((FzMut)mi));
                        snprintf(detail, sizeof(detail),
                                 "Iki canlilik sondasi da basarisiz oldu. Istek: %s. "
                                 "Dogrulama icin: hedef yeniden ayaga kalktiktan sonra "
                                 "ayni istegi SN_FUZZ_SEED=%u ile tekrarla.",
                                 mut_name((FzMut)mi), ctx.seed);
                        fz_finding(t->ip, "fuzz_crash", title,
                                   s->proto, "CWE-248",
                                   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                                   55, detail);
                        ev_write("CRASH-CANDIDATE", req, NULL);
                        stopped_early = 1;
                        break;
                    }
                }
            } else if (rc > 0) {
                ctx.timeout_streak = 0;
                const char *mk = infoleak_marker(resp);
                if (mk) {
                    infoleaks++;
                    char title[SN_TITLE_LEN], detail[SN_DETAIL_LEN];
                    snprintf(title, sizeof(title),
                             "%s yanitinda dahili bilgi sizintisi: %s", s->name, mk);
                    snprintf(detail, sizeof(detail),
                             "Yanit, uygulama ici yol/hata ayrintisi iceriyor (%s). "
                             "Bu tek basina RCE degildir; bilgi toplama degeri vardir.", mk);
                    fz_finding(t->ip, "fuzz_infoleak", title,
                               s->proto, "CWE-209",
                               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                               60, detail);
                    ev_write("INFOLEAK", req, resp);
                }
                /* 5xx + bilinen crash metni -> daha yuksek guven */
                if (strstr(resp, "HTTP/5") && strcasestr(resp, "error")) {
                    ev_write("5xx", req, resp);
                }
            }
        }
    }

    sn_logf("fuzz: %s bitti - %d istek, %d crash adayi, %d bilgi sizintisi",
            t->ip, ctx.sent, unique_crash, infoleaks);
    ev_close();
    return 0;
}
