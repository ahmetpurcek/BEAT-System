/*
 * camera_access.c — Kamera Erisim Motoru (Faz 3)
 *
 * Iki asamali erisim:
 *   A) Hizli RTSP DESCRIBE sondasi (kendi TCP soketimiz):
 *      - gecerli yolu bul (200/401 veren yol; 404 veren yol degil)
 *      - kimliksiz 200 -> acik akis
 *      - 401 -> kimlik gerekiyor; Basic ile varsayilan/elle kimlik dene
 *   B) ffmpeg yedek sondasi: Basic tutmazsa (or. yalnizca Digest kabul eden
 *      kameralar) ffmpeg alt-sureci ile URL'ye gomulu kimlikle ilk kareyi
 *      bekler. ffmpeg hem Basic hem Digest'i kendisi halleder.
 *
 * Tum isler tek arka plan thread'de, mutex korumali job tablosuyla calisir.
 */
#include "camera_access.h"
#include "camera_vuln.h"
#include "cam_net.h"
#include "video_stream.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/time.h>
#include <ctype.h>

#define CA_PROBE_TIMEOUT_MS   1800    /* tek RTSP DESCRIBE zaman asimi */
#define CA_FFMPEG_TIMEOUT_MS  3000    /* ffmpeg yedek sondasi zaman asimi */

/* ===================== Yardimcilar ===================== */
static double ca_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Base64 (Basic auth icin) */
static void ca_b64(const unsigned char *in, int len, char *out, int outlen) {
    static const char *t =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, o = 0;
    while (i < len && o + 5 < outlen) {
        int n = len - i;
        unsigned v = (unsigned)in[i] << 16;
        if (n > 1) v |= (unsigned)in[i + 1] << 8;
        if (n > 2) v |= (unsigned)in[i + 2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = (n > 1) ? t[(v >> 6) & 63] : '=';
        out[o++] = (n > 2) ? t[v & 63] : '=';
        i += 3;
    }
    out[o] = '\0';
}

/* RTSP istegi gonder + yanit al (tek tur). auth_hdr: hazir "Authorization: ...\r\n" veya "". */
static int ca_rtsp_exchange(const char *ip, int port, const char *path,
                            const char *auth_hdr,
                            int timeout_ms, char *resp, int resplen) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return -1; }
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { close(fd); return -1; }

    const char *p = (path && path[0]) ? path : "/";
    char req[1280];
    snprintf(req, sizeof(req),
             "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\n"
             "CSeq: 1\r\n"
             "Accept: application/sdp\r\n"
             "%s"
             "User-Agent: BEAT-System\r\n"
             "\r\n",
             ip, port, p, auth_hdr ? auth_hdr : "");

    if (send(fd, req, strlen(req), 0) < 0) { close(fd); return -1; }
    int got = (int)recv(fd, resp, resplen - 1, 0);
    close(fd);
    if (got <= 0) return -1;
    resp[got] = '\0';
    return 0;
}

/*
 * RTSP DESCRIBE sondasi. user/pass NULL/"" ise kimliksiz.
 * allow_digest=1 ise 401 + Digest durumunda cam_net ile NATIVE Digest
 * Authorization basligi uretilip tek sefer yeniden denenir (ffmpeg'e gerek yok).
 * Doner:  0 = 200   1 = 401   2 = diger kod (404 vb.)   -1 = baglanti/zaman asimi
 * wwwauth: 401 ise WWW-Authenticate basligi.
 */
static int ca_rtsp_describe(const char *ip, int port, const char *path,
                            const char *user, const char *pass,
                            int timeout_ms, char *wwwauth, int walen,
                            int allow_digest) {
    if (wwwauth && walen > 0) wwwauth[0] = '\0';

    char auth[512];
    auth[0] = '\0';
    if (user && user[0]) {
        char raw[160];
        snprintf(raw, sizeof(raw), "%s:%s", user, pass ? pass : "");
        char b64[256];
        ca_b64((const unsigned char *)raw, (int)strlen(raw), b64, sizeof(b64));
        snprintf(auth, sizeof(auth), "Authorization: Basic %s\r\n", b64);
    }

    char buf[1024];
    if (ca_rtsp_exchange(ip, port, path, auth, timeout_ms, buf, sizeof(buf)) < 0)
        return -1;

    int code = 0;
    char *sp = strchr(buf, ' ');
    if (sp) code = atoi(sp + 1);

    if (code == 401 && wwwauth && walen > 0) {
        char *w = strcasestr(buf, "WWW-Authenticate:");
        if (w) {
            w += strlen("WWW-Authenticate:");
            while (*w == ' ') w++;
            char *e = strstr(w, "\r\n");
            int n = e ? (int)(e - w) : (int)strlen(w);
            if (n > walen - 1) n = walen - 1;
            memcpy(wwwauth, w, (size_t)n);
            wwwauth[n] = '\0';
        }
    }

    /* Native RTSP Digest (RFC 2617) tek seferlik yeniden deneme. */
    if (code == 401 && allow_digest && user && user[0] &&
        wwwauth && cam_wwwauth_is_digest(wwwauth)) {
        char uri[256];
        char dh[640];
        const char *p = (path && path[0]) ? path : "/";
        snprintf(uri, sizeof(uri), "rtsp://%s:%d%s", ip, port, p);
        cam_http_digest_header(user, pass ? pass : "", wwwauth, "DESCRIBE",
                               uri, dh, sizeof(dh));
        if (dh[0] &&
            ca_rtsp_exchange(ip, port, path, dh, timeout_ms, buf, sizeof(buf)) == 0) {
            code = 0;
            char *s2 = strchr(buf, ' ');
            if (s2) code = atoi(s2 + 1);
        }
    }

    if (code == 200) return 0;
    if (code == 401) return 1;
    return 2;
}

/*
 * ffmpeg yedek sondasi: URL ile ffmpeg baslatip ilk kareyi bekler.
 * (Basic/Digest'i ffmpeg kendisi cozer.) Doner: 1 = kare geldi, 0 = olmadi.
 */
static int ca_ffmpeg_probe(const char *url, int timeout_ms) {
    int p[2];
    if (pipe(p) != 0) return 0;

    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); return 0; }

    if (pid == 0) {
        int dn = open("/dev/null", O_RDONLY);
        if (dn >= 0) { dup2(dn, 0); close(dn); }
        dup2(p[1], 1);
        int er = open("/dev/null", O_WRONLY);
        if (er >= 0) { dup2(er, 2); close(er); }
        close(p[0]);
        close(p[1]);
        execlp("ffmpeg", "ffmpeg",
               "-hide_banner", "-nostdin", "-loglevel", "error",
               "-rtsp_transport", "tcp", "-timeout", "3000000",
               "-fflags", "nobuffer", "-flags", "low_delay",
               "-i", url,
               "-frames:v", "1", "-an", "-f", "rawvideo",
               "-pix_fmt", "rgb24", "pipe:1", (char *)NULL);
        _exit(127);
    }

    close(p[1]);
    char buf[4096];
    int total = 0;
    double t0 = ca_now();
    while ((ca_now() - t0) * 1000.0 < (double)timeout_ms) {
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(p[0], &rs);
        struct timeval tv = {0, 100000};
        int s = select(p[0] + 1, &rs, NULL, NULL, &tv);
        if (s > 0) {
            ssize_t r = read(p[0], buf, sizeof(buf));
            if (r > 0) {
                total += (int)r;
                if (total > 2048) break;   /* yeterli kanit: kare akiyor */
            } else {
                break;                     /* EOF: ffmpeg oldu */
            }
        } else if (s < 0 && errno != EINTR) {
            break;
        }
    }

    kill(pid, SIGKILL);
    close(p[0]);
    waitpid(pid, NULL, 0);
    return total > 0;
}

/* Varsayilan kimlikler artik camera_vuln.c'nin genis veritabanindan
 * (camera_vuln_default_creds) alinir; harici wordlist da desteklenir. */

/* ===================== Job tablosu ===================== */
static CameraAccessJob g_jobs[CA_MAX_JOBS];
static int              g_job_count = 0;
static platform_mutex_t g_lock;
static platform_thread_t g_worker;
static volatile int     g_running = 0;
static volatile int     g_stop = 0;
static int              g_init = 0;

static int ca_find(const char *ip) {
    if (!ip || !ip[0]) return -1;
    for (int i = 0; i < g_job_count; i++)
        if (strcmp(g_jobs[i].ip, ip) == 0) return i;
    return -1;
}

static int ca_new_job(const char *ip) {
    if (g_job_count >= CA_MAX_JOBS) return -1;
    int idx = g_job_count++;
    memset(&g_jobs[idx], 0, sizeof(g_jobs[idx]));
    snprintf(g_jobs[idx].ip, MAX_IP_LEN, "%s", ip);
    g_jobs[idx].state = CA_IDLE;
    return idx;
}

/* ===================== Isci thread ===================== */
static void ca_set_status(int idx, const char *msg) {
    platform_mutex_lock(&g_lock);
    snprintf(g_jobs[idx].last_error, CA_ERR_LEN, "%s", msg);
    platform_mutex_unlock(&g_lock);
}
static void ca_bump_tried(int idx) {
    platform_mutex_lock(&g_lock);
    g_jobs[idx].tried++;
    platform_mutex_unlock(&g_lock);
}
static int ca_is_cancelled(int idx) {
    int c;
    platform_mutex_lock(&g_lock);
    c = (g_jobs[idx].state == CA_CANCELLED);
    platform_mutex_unlock(&g_lock);
    return c;
}
static void ca_finish_ok(int idx, const char *path, const char *user,
                         const char *pass, int open_stream) {
    platform_mutex_lock(&g_lock);
    CameraAccessJob *j = &g_jobs[idx];
    j->state = CA_FOUND;
    j->open_stream = open_stream;
    snprintf(j->path, sizeof(j->path), "%s", path ? path : "/");
    snprintf(j->found_user, CA_USER_LEN, "%s", user ? user : "");
    snprintf(j->found_pass, CA_PASS_LEN, "%s", pass ? pass : "");
    {
        char url[CAM_URL_LEN];
        const char *p = (path && path[0]) ? path : "/";
        if (open_stream || !user || !user[0])
            snprintf(url, sizeof(url), "rtsp://%s:%d%s", j->ip, j->port, p);
        else
            snprintf(url, sizeof(url), "rtsp://%s:%s@%s:%d%s",
                     user, pass ? pass : "", j->ip, j->port, p);
        snprintf(j->found_url, CAM_URL_LEN, "%s", url);
    }
    snprintf(j->last_error, CA_ERR_LEN, "%s",
             open_stream ? "acik akis" : "kimlik dogrulandi");
    platform_mutex_unlock(&g_lock);
}
static void ca_finish_fail(int idx, const char *why) {
    platform_mutex_lock(&g_lock);
    if (g_jobs[idx].state != CA_CANCELLED) {
        g_jobs[idx].state = CA_FAILED;
        snprintf(g_jobs[idx].last_error, CA_ERR_LEN, "%s",
                 why ? why : "erisim saglanamadi");
    }
    platform_mutex_unlock(&g_lock);
}

/* Aday yol listesini olustur (base_url yolu + ortak yollar, tekrarsiz). */
static int ca_build_paths(const char *base_url, char paths[][128], int maxp) {
    int n = 0;

    /* base_url icindeki yol (rtsp://host:port/XXX) */
    const char *scheme = strstr(base_url, "://");
    if (scheme) {
        const char *slash = strchr(scheme + 3, '/');
        if (slash && slash[0] && strcmp(slash, "/") != 0 && n < maxp)
            snprintf(paths[n++], 128, "%s", slash);
    }

    int np = 0;
    const char *const *common = camera_discovery_common_rtsp_paths(&np);
    for (int i = 0; i < np && n < maxp; i++) {
        int dup = 0;
        for (int k = 0; k < n; k++)
            if (strcmp(paths[k], common[i]) == 0) { dup = 1; break; }
        if (!dup) snprintf(paths[n++], 128, "%s", common[i]);
    }
    return n;
}

/* Basic + ffmpeg ile tek bir kimlik ciftini dene.
 *
 * Onemli: bazi sunucular (or. mediamtx) kimlik dogrulamayi yol
 * cozumlemesinden ONCE yapar; bu yuzden kimliksiz her yol 401 doner ve
 * bulunan "ilk 401 yolu" gercek akis olmayabilir. Kimlik dogru oldugunda
 * yanlis yol 404 dondurur; bu durumda kimligi diger aday yollarda da
 * tarayip gercek akisi buluruz. Doner: 1 bulundu, -1 iptal, 0 tutmadi. */
static int ca_try_one_cred(int idx, const char *ip, int port, const char *path,
                           char paths[][128], int np,
                           const char *user, const char *pass,
                           int digest_hint) {
    char wwwauth[192];
    int r = ca_rtsp_describe(ip, port, path, user, pass,
                             CA_PROBE_TIMEOUT_MS, wwwauth, sizeof(wwwauth), 1);
    ca_bump_tried(idx);
    if (r == 0) {
        ca_finish_ok(idx, path, user, pass, 0);
        return 1;
    }
    if (ca_is_cancelled(idx)) return -1;

    /* r == 2 (404): kimlik kabul edildi ama yol bos -> diger aday yollari tara. */
    if (r == 2) {
        for (int k = 0; k < np; k++) {
            if (strcmp(paths[k], path) == 0) continue;
            if (ca_is_cancelled(idx)) return -1;
            int r2 = ca_rtsp_describe(ip, port, paths[k], user, pass,
                                      CA_PROBE_TIMEOUT_MS, NULL, 0, 1);
            ca_bump_tried(idx);
            if (r2 == 0) {
                ca_finish_ok(idx, paths[k], user, pass, 0);
                return 1;
            }
        }
        return 0;   /* kimlik gecerli ama hicbir aday yolda akis yok */
    }

    /* Basic tutmadi: ffmpeg (Basic+Digest) ile son bir sans.
     * digest_hint = 401'de server Digest istediyse hemen dene. */
    if (digest_hint || (r == 1 && strcasestr(wwwauth, "digest"))) {
        char url[CAM_URL_LEN];
        snprintf(url, sizeof(url), "rtsp://%s:%s@%s:%d%s",
                 user, pass ? pass : "", ip, port, path);
        if (ca_ffmpeg_probe(url, CA_FFMPEG_TIMEOUT_MS)) {
            ca_finish_ok(idx, path, user, pass, 0);
            return 1;
        }
        ca_bump_tried(idx);
    }
    return ca_is_cancelled(idx) ? -1 : 0;
}

static void ca_process(int idx) {
    CameraAccessJob cfg;
    platform_mutex_lock(&g_lock);
    g_jobs[idx].state = CA_RUNNING;
    g_jobs[idx].tried = 0;
    g_jobs[idx].last_error[0] = '\0';
    cfg = g_jobs[idx];
    platform_mutex_unlock(&g_lock);

    int port = cfg.port > 0 ? cfg.port : 554;

    char paths[48][128];
    int np = ca_build_paths(cfg.base_url, paths, 48);
    platform_mutex_lock(&g_lock);
    g_jobs[idx].total = np + CA_DEFAULT_CREDS;
    platform_mutex_unlock(&g_lock);

    /* --- Asama 1: yol kesfi (kimliksiz) --- */
    char found_path[128] = "";
    char realm[CA_ERR_LEN] = "";
    int need_auth = 0;
    int digest_hint = 0;

    if (cfg.path[0]) {
        /* daha once bulunmus yol (elle kimlik yeniden denemesi) */
        snprintf(found_path, sizeof(found_path), "%.127s", cfg.path);
        need_auth = 1;
    } else {
        for (int i = 0; i < np; i++) {
            if (ca_is_cancelled(idx)) return;
            int r = ca_rtsp_describe(cfg.ip, port, paths[i], NULL, NULL,
                                     CA_PROBE_TIMEOUT_MS, realm, sizeof(realm), 0);
            ca_bump_tried(idx);
            if (r == 0) {
                ca_finish_ok(idx, paths[i], NULL, NULL, 1);   /* acik akis */
                return;
            }
            if (r == 1) {
                snprintf(found_path, sizeof(found_path), "%.127s", paths[i]);
                if (strcasestr(realm, "digest")) digest_hint = 1;
                need_auth = 1;
                break;
            }
            /* r == 2 (404 vb.) veya -1: sonraki yol */
        }
    }

    if (!need_auth || !found_path[0]) {
        ca_finish_fail(idx, "gecerli RTSP yolu bulunamadi");
        return;
    }

    platform_mutex_lock(&g_lock);
    snprintf(g_jobs[idx].path, sizeof(g_jobs[idx].path), "%s", found_path);
    if (!g_jobs[idx].realm[0] && realm[0])
        snprintf(g_jobs[idx].realm, CAM_REALM_LEN, "%s", realm);
    platform_mutex_unlock(&g_lock);

    /* --- Asama 1b: acik akis dogrulama (auth_required ise de yol acik olabilir) --- */
    int r_noauth = ca_rtsp_describe(cfg.ip, port, found_path, NULL, NULL,
                                    CA_PROBE_TIMEOUT_MS, NULL, 0, 0);
    ca_bump_tried(idx);
    if (r_noauth == 0) {
        ca_finish_ok(idx, found_path, NULL, NULL, 1);
        return;
    }

    /* --- Asama 2: elle kimlik (once) --- */
    if (cfg.manual_user[0] || cfg.used_manual) {
        ca_set_status(idx, "elle kimlik deneniyor...");
        int rc = ca_try_one_cred(idx, cfg.ip, port, found_path, paths, np,
                                 cfg.manual_user, cfg.manual_pass, digest_hint);
        if (rc != 0) return;   /* bulundu veya iptal */
    }

    /* --- Asama 2b: HTTP bilinen-zafiyet bypass sondalari --- */
    if (cfg.http_port > 0) {
        ca_set_status(idx, "bilinen zafiyet sondalari...");
        char detail[CA_ERR_LEN] = "";
        unsigned m = camera_vuln_probe_authbypass(
            cfg.ip, cfg.http_port, 0,
            cfg.vendor[0] ? cfg.vendor : NULL, detail, sizeof(detail));
        if (m) {
            platform_mutex_lock(&g_lock);
            g_jobs[idx].vuln_mask = m;
            snprintf(g_jobs[idx].vuln_detail, CA_ERR_LEN, "%s", detail);
            platform_mutex_unlock(&g_lock);
        }
    }

    /* --- Asama 3: varsayilan kimlikler (genis DB) --- */
    int ncred = 0;
    const CamCred *creds = camera_vuln_default_creds(&ncred);
    for (int i = 0; creds && i < ncred && i < CA_DEFAULT_CREDS; i++) {
        if (ca_is_cancelled(idx)) return;
        platform_mutex_lock(&g_lock);
        snprintf(g_jobs[idx].last_error, CA_ERR_LEN,
                 "varsayilan kimlik: %s/%.12s", creds[i].user, creds[i].pass);
        platform_mutex_unlock(&g_lock);
        int rc = ca_try_one_cred(idx, cfg.ip, port, found_path, paths, np,
                                 creds[i].user, creds[i].pass, 1);
        if (rc != 0) return;
    }

    /* --- Asama 4: ONVIF ile akis adresi (RTSP kimlikleri tutmadiysa) --- */
    {
        static const CamCred onvif_seed[] = {
            {"admin", "admin"}, {"admin", "12345"}, {"admin", ""},
            {"admin", "password"}, {"admin", "123456"}, {"root", "root"},
            {"ubnt", "ubnt"}, {NULL, NULL}
        };
        int hp = cfg.http_port > 0 ? cfg.http_port : 80;
        for (int i = 0; onvif_seed[i].user; i++) {
            if (ca_is_cancelled(idx)) return;
            ca_set_status(idx, "ONVIF sorgulaniyor...");
            OnvifDeviceInfo di;
            memset(&di, 0, sizeof(di));
            if (onvif_probe_device(cfg.ip, hp, 0, onvif_seed[i].user,
                                   onvif_seed[i].pass, &di) == 0 && di.stream_uri[0]) {
                platform_mutex_lock(&g_lock);
                CameraAccessJob *j = &g_jobs[idx];
                j->state = CA_FOUND;
                j->onvif_used = 1;
                j->open_stream = 0;
                snprintf(j->found_user, CA_USER_LEN, "%s", onvif_seed[i].user);
                snprintf(j->found_pass, CA_PASS_LEN, "%s", onvif_seed[i].pass);
                snprintf(j->found_url, CAM_URL_LEN, "%s", di.stream_uri);
                snprintf(j->last_error, CA_ERR_LEN, "ONVIF ile erisim");
                platform_mutex_unlock(&g_lock);
                return;
            }
        }
    }

    ca_finish_fail(idx, "varsayilan kimlikler tutmadi (elle girin)");
}

static void *ca_worker_main(void *arg) {
    (void)arg;
    while (!g_stop) {
        int idx = -1;
        platform_mutex_lock(&g_lock);
        for (int i = 0; i < g_job_count; i++) {
            if (g_jobs[i].state == CA_QUEUED) { idx = i; break; }
        }
        platform_mutex_unlock(&g_lock);

        if (idx < 0) { platform_sleep_ms(80); continue; }
        ca_process(idx);
    }
    return NULL;
}

/* ===================== Genel API ===================== */
void camera_access_init(void) {
    if (g_init) return;
    memset(g_jobs, 0, sizeof(g_jobs));
    g_job_count = 0;
    g_stop = 0;
    platform_mutex_init(&g_lock);
    g_init = 1;
    if (platform_thread_create(&g_worker, ca_worker_main, NULL) == 0)
        g_running = 1;
    else
        g_running = 0;
}

void camera_access_shutdown(void) {
    if (!g_init) return;
    /* Calisan probu kes: tum aktif isleri iptal et, isciyi durdur.
     * Isci detach edilir; uzun problar bitene kadar thread yasar. Mutex'i
     * yok etmiyoruz: cikista isci hala kullaniyor olabilir (use-after-free
     * yerine kucuk bir sizinti tercih edilir). */
    platform_mutex_lock(&g_lock);
    for (int i = 0; i < g_job_count; i++)
        if (g_jobs[i].state == CA_QUEUED || g_jobs[i].state == CA_RUNNING)
            g_jobs[i].state = CA_CANCELLED;
    platform_mutex_unlock(&g_lock);
    g_stop = 1;
    platform_sleep_ms(120);
    if (g_running) platform_thread_detach(g_worker);
    g_init = 0;
    g_running = 0;
}

int camera_access_start(const char *ip, int port, const char *base_url,
                        int auth_required, const char *realm) {
    if (!g_init || !ip || !ip[0]) return -1;
    platform_mutex_lock(&g_lock);
    int idx = ca_find(ip);
    if (idx >= 0 &&
        (g_jobs[idx].state == CA_QUEUED || g_jobs[idx].state == CA_RUNNING)) {
        platform_mutex_unlock(&g_lock);
        return -1;   /* zaten calisiyor */
    }
    if (idx < 0) idx = ca_new_job(ip);
    if (idx < 0) { platform_mutex_unlock(&g_lock); return -1; }
    CameraAccessJob *j = &g_jobs[idx];
    char mru[CA_USER_LEN], mrp[CA_PASS_LEN];
    int  mhp = j->http_port;
    char mvn[64];
    snprintf(mru, sizeof(mru), "%s", j->manual_user);
    snprintf(mrp, sizeof(mrp), "%s", j->manual_pass);
    snprintf(mvn, sizeof(mvn), "%s", j->vendor);
    memset(j, 0, sizeof(*j));
    snprintf(j->ip, MAX_IP_LEN, "%s", ip);
    j->port = port > 0 ? port : 554;
    snprintf(j->base_url, CAM_URL_LEN, "%s", base_url ? base_url : "");
    snprintf(j->manual_user, CA_USER_LEN, "%s", mru);
    snprintf(j->manual_pass, CA_PASS_LEN, "%s", mrp);
    j->http_port = mhp;
    snprintf(j->vendor, sizeof(j->vendor), "%s", mvn);
    j->auth_required = auth_required;
    if (realm) snprintf(j->realm, CAM_REALM_LEN, "%s", realm);
    j->state = CA_QUEUED;
    j->tried = 0;
    platform_mutex_unlock(&g_lock);
    return 0;
}

int camera_access_try_credentials(const char *ip, const char *user,
                                  const char *pass) {
    if (!g_init || !ip || !ip[0]) return -1;
    platform_mutex_lock(&g_lock);
    int idx = ca_find(ip);
    if (idx < 0) { platform_mutex_unlock(&g_lock); return -1; }
    if (g_jobs[idx].state == CA_RUNNING) {
        platform_mutex_unlock(&g_lock);
        return -1;   /* su an deniyor; bitince tekrar deneyin */
    }
    snprintf(g_jobs[idx].manual_user, CA_USER_LEN, "%s", user ? user : "");
    snprintf(g_jobs[idx].manual_pass, CA_PASS_LEN, "%s", pass ? pass : "");
    g_jobs[idx].used_manual = 1;
    g_jobs[idx].state = CA_QUEUED;
    g_jobs[idx].tried = 0;
    g_jobs[idx].found_url[0] = '\0';
    snprintf(g_jobs[idx].last_error, CA_ERR_LEN, "elle kimlik kuyruga alindi");
    platform_mutex_unlock(&g_lock);
    return 0;
}

void camera_access_cancel(const char *ip) {
    if (!g_init) return;
    platform_mutex_lock(&g_lock);
    int idx = ca_find(ip);
    if (idx >= 0 &&
        (g_jobs[idx].state == CA_QUEUED || g_jobs[idx].state == CA_RUNNING))
        g_jobs[idx].state = CA_CANCELLED;
    platform_mutex_unlock(&g_lock);
}

int camera_access_get(const char *ip, CameraAccessJob *out) {
    if (!g_init || !ip || !out) return 0;
    platform_mutex_lock(&g_lock);
    int idx = ca_find(ip);
    int ok = 0;
    if (idx >= 0) { *out = g_jobs[idx]; ok = 1; }
    platform_mutex_unlock(&g_lock);
    return ok;
}

int camera_access_busy(const char *ip) {
    if (!g_init) return 0;
    platform_mutex_lock(&g_lock);
    int idx = ca_find(ip);
    int b = 0;
    if (idx >= 0)
        b = (g_jobs[idx].state == CA_QUEUED || g_jobs[idx].state == CA_RUNNING);
    platform_mutex_unlock(&g_lock);
    return b;
}

void camera_access_reset(void) {
    if (!g_init) return;
    platform_mutex_lock(&g_lock);
    for (int i = 0; i < g_job_count; i++)
        if (g_jobs[i].state != CA_RUNNING && g_jobs[i].state != CA_QUEUED)
            memset(&g_jobs[i], 0, sizeof(g_jobs[i]));
    platform_mutex_unlock(&g_lock);
}

/* ===================== Kesif baglami + snapshot ===================== */
void camera_access_set_context(const char *ip, int http_port, const char *vendor) {
    if (!g_init || !ip || !ip[0]) return;
    platform_mutex_lock(&g_lock);
    int idx = ca_find(ip);
    if (idx < 0) idx = ca_new_job(ip);
    if (idx >= 0) {
        if (http_port > 0) g_jobs[idx].http_port = http_port;
        if (vendor && vendor[0])
            snprintf(g_jobs[idx].vendor, sizeof(g_jobs[idx].vendor), "%s", vendor);
    }
    platform_mutex_unlock(&g_lock);
}

/* Ham HTTP GET ile ikili (JPEG/PNG) govde indirir; cam_net CamConn kullanir.
 * Basarisizsa <0. Doner: 0 = goruntu yazildi. */
static int ca_fetch_binary(const char *ip, int port, const char *path,
                           const char *user, const char *pass,
                           const char *out_path, int timeout_ms) {
    const int cap = 1024 * 1024;
    unsigned char *buf = (unsigned char *)malloc((size_t)cap);
    if (!buf) return -1;

    char ahdr[704];
    ahdr[0] = '\0';
    if (user && user[0]) {
        char raw[160], b64[256];
        snprintf(raw, sizeof(raw), "%s:%s", user, pass ? pass : "");
        cam_b64_encode((const unsigned char *)raw, (int)strlen(raw), b64, sizeof(b64));
        snprintf(ahdr, sizeof(ahdr), "Authorization: Basic %s\r\n", b64);
    }

    int result = -1;
    for (int attempt = 0; attempt < 3 && result != 0; attempt++) {
        CamConn c;
        if (cam_conn_open(&c, ip, port, timeout_ms, 0) != 0) break;
        char req[1280];
        snprintf(req, sizeof(req),
                 "GET %s HTTP/1.0\r\nHost: %s\r\n%sConnection: close\r\n\r\n",
                 path, ip, ahdr);
        if (cam_conn_write(&c, req, (int)strlen(req), timeout_ms) < 0) {
            cam_conn_close(&c);
            break;
        }
        int total = 0;
        for (;;) {
            if (total >= cap - 1) break;
            int r = cam_conn_read(&c, buf + total, cap - 1 - total, timeout_ms);
            if (r <= 0) break;
            total += r;
        }
        cam_conn_close(&c);
        if (total <= 0) break;
        buf[total] = '\0';

        int status = 0;
        {
            char *sp = (char *)memchr(buf, ' ', total > 16 ? 16 : (size_t)total);
            if (sp) status = atoi(sp + 1);
        }
        unsigned char *hdr = NULL;
        for (int i = 0; i + 3 < total; i++) {
            if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
                hdr = buf + i + 4;
                break;
            }
        }

        if (status == 401 && attempt < 2) {
            char www[384] = "";
            char *w = strcasestr((char *)buf, "WWW-Authenticate:");
            if (w) {
                w += strlen("WWW-Authenticate:");
                while (*w == ' ') w++;
                char *e = strstr(w, "\r\n");
                int n = e ? (int)(e - w) : (int)strlen(w);
                if (n > (int)sizeof(www) - 1) n = (int)sizeof(www) - 1;
                memcpy(www, w, (size_t)n);
                www[n] = '\0';
            }
            if (attempt == 0 && user && user[0] && cam_wwwauth_is_digest(www)) {
                char dh[640];
                cam_http_digest_header(user, pass ? pass : "", www, "GET", path,
                                       dh, sizeof(dh));
                if (dh[0]) { snprintf(ahdr, sizeof(ahdr), "%s", dh); continue; }
            }
            break;   /* Basic/anon zaten denendi */
        }

        if (status >= 200 && status < 300 && hdr) {
            int blen = total - (int)(hdr - buf);
            int img = (blen > 3 && hdr[0] == 0xFF && hdr[1] == 0xD8) ||
                      (blen > 8 && hdr[0] == 0x89 && hdr[1] == 'P');
            if (img) {
                FILE *f = fopen(out_path, "wb");
                if (f) {
                    fwrite(hdr, 1, (size_t)blen, f);
                    fclose(f);
                    result = 0;
                }
            }
        }
        break;
    }
    free(buf);
    return result;
}

int camera_access_snapshot(const char *ip, const char *out_path) {
    if (!g_init || !ip || !ip[0] || !out_path || !out_path[0]) return -1;
    CameraAccessJob j;
    if (!camera_access_get(ip, &j)) return -1;
    if (j.state != CA_FOUND) return -1;
    int hp = j.http_port > 0 ? j.http_port : 80;

    int npaths = 0;
    const char *const *paths = camera_vuln_snapshot_paths(&npaths);
    const char *u = j.found_user[0] ? j.found_user : NULL;
    for (int i = 0; i < npaths; i++) {
        if (ca_fetch_binary(ip, hp, paths[i], u, j.found_pass, out_path, 4000) == 0) {
            platform_mutex_lock(&g_lock);
            int idx = ca_find(ip);
            if (idx >= 0)
                snprintf(g_jobs[idx].snapshot_path,
                         sizeof(g_jobs[idx].snapshot_path), "%s", out_path);
            platform_mutex_unlock(&g_lock);
            return 0;
        }
    }
    return -1;
}
