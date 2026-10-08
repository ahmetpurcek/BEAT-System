/*
 * video_stream.c — Uygulama-ici canli RTSP/MJPEG izleme motoru (implementasyon)
 *
 * Her akis icin:
 *   ffmpeg alt-sureci (ham rgb24 -> pipe)  -->  okuyucu thread  -->
 *   cift tampon  -->  ana thread: raylib Texture2D
 */
#include "video_stream.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int slot;
    int used;
    int state;
    int decode_mode;
    int w, h;
    int frame_size;
    char url[VS_URL_LEN];
    char status[VS_STATUS_LEN];
    char logpath[96];   /* bu akisin ffmpeg stderr log dosyasi */
    int  hw_fallback;   /* donanim decode denendi, yazilima dusuldu mu */

    int  auto_reconnect;/* akis kopunca yeniden baglan */
    int  tcp;           /* rtsp transport (yeniden baglanma icin saklanir) */
    char devpath[64];   /* vaapi cihaz yolu (yeniden baglanma icin) */
    pid_t record_pid;   /* kayit ffmpeg sureci, <=0 = yok */
    int   recording;

    int   pipe_fd;      /* ffmpeg stdout (okuma ucu), -1 = yok */
    int   err_fd;       /* ffmpeg stderr log dosyasi (okuma icin) */
    pid_t pid;          /* ffmpeg surec kimligi, <=0 = yok */

    platform_thread_t thread;
    int thread_started;
    volatile int running;

    platform_mutex_t lock;
    unsigned char *buf[2];     /* cift tampon (rawvideo kareleri) */
    int rd_idx;                /* thread'in yazdigi tampon */
    int draw_idx;              /* ana thread'in cizdigi tampon */
    int have_new;              /* yeni kare cizilmeyi bekliyor */

    unsigned long frames;
    double last_frame_time;
    double win_start;
    unsigned long win_frames;
    double fps;
    int eof_seen;

    Texture2D tex;
    int tex_ready;
} VideoStream;

static VideoStream g_vs[VS_MAX_STREAMS];
static int g_vs_init = 0;

static int vs_spawn(VideoStream *vs, VideoDecodeMode mode, int tcp,
                    const char *devpath);

/* ---------- Yardimcilar ---------- */
static double vs_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void vs_set_status(VideoStream *vs, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(vs->status, sizeof(vs->status), fmt, ap);
    va_end(ap);
}

/*
 * ffmpeg stderr logundan ANLAMLI hata satirini secip status'a tasi.
 * ("Broken pipe" gibi kapanis gurultusu degil, gercek neden gosterilir;
 *  URL icindeki kullanici/parola status metninden temizlenir.)
 */
static void vs_capture_ffmpeg_error(VideoStream *vs) {
    if (vs->err_fd < 0) return;
    char tmp[4096];
    ssize_t n = pread(vs->err_fd, tmp, sizeof(tmp) - 1, 0);
    if (n <= 0) return;
    tmp[n] = '\0';

    static const char *keys[] = {
        "401", "Unauthorized", "403", "Connection refused", "Connection timed out",
        "timed out", "Protocol not found", "Invalid data", "Server returned",
        "No route to host", "Network is unreachable", "Input/output error",
        "404", "Not Found", "Cannot open", "Permission denied", NULL
    };

    char best[512] = "";
    char first_err[512] = "";
    char first_line[512] = "";

    char *save = NULL;
    for (char *ln = strtok_r(tmp, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        while (*ln == '\r' || *ln == ' ' || *ln == '\t') ln++;
        if (!*ln) continue;
        if (!first_line[0]) snprintf(first_line, sizeof(first_line), "%s", ln);
        if (!best[0]) {
            for (int i = 0; keys[i]; i++)
                if (strstr(ln, keys[i])) { snprintf(best, sizeof(best), "%s", ln); break; }
        }
        if (!first_err[0] && strstr(ln, "Error opening input"))
            snprintf(first_err, sizeof(first_err), "%s", ln);
    }

    const char *chosen = best[0] ? best : (first_err[0] ? first_err : first_line);
    if (!chosen[0]) return;

    /* kimlik bilgisi sizintisini engelle: URL tokenlarini [url] ile degistir */
    char clean[512];
    size_t o = 0;
    for (size_t i = 0; chosen[i] && o < sizeof(clean) - 1; ) {
        if (strncmp(chosen + i, "rtsp://", 7) == 0 ||
            strncmp(chosen + i, "http://", 7) == 0 ||
            strncmp(chosen + i, "https://", 8) == 0) {
            while (chosen[i] && chosen[i] != ' ' && chosen[i] != '\t') i++;
            const char *rep = "[url]";
            for (int k = 0; rep[k] && o < sizeof(clean) - 1; k++) clean[o++] = rep[k];
        } else {
            clean[o++] = chosen[i++];
        }
    }
    clean[o] = '\0';

    if (strstr(clean, "401") || strstr(clean, "Unauthorized"))
        vs_set_status(vs, "kimlik dogrulama gerekli (401 Unauthorized)");
    else if (strstr(clean, "403"))
        vs_set_status(vs, "erisim reddedildi (403)");
    else if (strstr(clean, "404") || strstr(clean, "Not Found"))
        vs_set_status(vs, "akis bulunamadi (404)");
    else if (strstr(clean, "Connection refused"))
        vs_set_status(vs, "baglanti reddedildi (port kapali olabilir)");
    else if (strstr(clean, "timed out"))
        vs_set_status(vs, "zaman asimi (kamera yanit vermedi)");
    else if (strstr(clean, "Protocol not found") || strstr(clean, "Invalid data"))
        vs_set_status(vs, "desteklenmeyen protokol veya kodek");
    else if (strstr(clean, "Permission denied"))
        vs_set_status(vs, "izin reddedildi");
    else
        vs_set_status(vs, "%s", clean);
}

/* fd'den tam frame_size byte oku. Doner: >0 tam, 0 EOF, <0 hata/iptal */
static int vs_read_full(VideoStream *vs, unsigned char *buf, int size) {
    int got = 0;
    while (got < size) {
        if (!vs->running) return -1;
        ssize_t r = read(vs->pipe_fd, buf + got, (size_t)(size - got));
        if (r > 0) {
            got += (int)r;
        } else if (r == 0) {
            return 0; /* EOF */
        } else {
            if (errno == EINTR) continue;
            return -1;
        }
    }
    return got;
}

static void *vs_reader_thread(void *arg) {
    VideoStream *vs = (VideoStream *)arg;
    int reconnect_attempt = 0;
    while (vs->running) {
        unsigned char *b = vs->buf[vs->rd_idx];
        int r = vs_read_full(vs, b, vs->frame_size);
        if (r <= 0) {
            if (!vs->running) break;

            platform_mutex_lock(&vs->lock);
            vs->eof_seen = 1;
            vs->state = VS_ST_ERROR;
            platform_mutex_unlock(&vs->lock);
            vs_capture_ffmpeg_error(vs);
            if (!vs->status[0])
                vs_set_status(vs, "akis sonlandi (ffmpeg cikti)");

            if (!vs->auto_reconnect) break;

            /* eski ffmpeg surecini temizle */
            if (vs->pid > 0) { kill(vs->pid, SIGKILL); waitpid(vs->pid, NULL, 0); vs->pid = -1; }
            if (vs->pipe_fd >= 0) { close(vs->pipe_fd); vs->pipe_fd = -1; }
            if (vs->err_fd >= 0) { close(vs->err_fd); vs->err_fd = -1; }

            if (reconnect_attempt >= 20) {
                platform_mutex_lock(&vs->lock);
                vs_set_status(vs, "yeniden baglanma basarisiz");
                platform_mutex_unlock(&vs->lock);
                break;
            }
            reconnect_attempt++;

            platform_mutex_lock(&vs->lock);
            vs->state = VS_ST_CONNECTING;
            vs_set_status(vs, "yeniden baglaniyor... (%d)", reconnect_attempt);
            platform_mutex_unlock(&vs->lock);

            int backoff = reconnect_attempt < 5 ? 600 : 2500;
            for (int slept = 0; slept < backoff && vs->running; slept += 100)
                platform_sleep_ms(100);
            if (!vs->running) break;

            if (vs_spawn(vs, (VideoDecodeMode)vs->decode_mode, vs->tcp,
                         vs->devpath) != 0) {
                platform_sleep_ms(400);
                continue;               /* yeniden dene */
            }
            continue;                   /* oku */
        }

        reconnect_attempt = 0;
        double t = vs_now();
        platform_mutex_lock(&vs->lock);
        /* yazilan tamponu cizime ver, okuma icin digerine gec */
        vs->draw_idx = vs->rd_idx;
        vs->rd_idx ^= 1;
        vs->have_new = 1;
        vs->frames++;
        vs->last_frame_time = t;
        vs->win_frames++;
        if (t - vs->win_start >= 1.0) {
            vs->fps = (double)vs->win_frames / (t - vs->win_start);
            vs->win_start = t;
            vs->win_frames = 0;
        }
        if (vs->state != VS_ST_PLAYING) {
            vs->state = VS_ST_PLAYING;
            vs_set_status(vs, "izleniyor");
        }
        platform_mutex_unlock(&vs->lock);
    }
    return NULL;
}

/* ---------- ffmpeg komut satiri ---------- */
/*
 * VAAPI icin dogru render dugumunu sec.
 * /sys/class/drm/renderD<N>/device/uevent icindeki surucuye bakar (i915/xe =
 * Intel, amdgpu/radeon = AMD). Sabit renderD128 kullanmak yanlistir: bu
 * makinede renderD128 nvidia oldugu icin VAAPI "libva error" ile oluyordu.
 */
static int vs_vaapi_pick_device(char *out, size_t n) {
    const char *want[] = { "i915", "xe", "amdgpu", "radeon", NULL };
    DIR *d = opendir("/sys/class/drm");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (strncmp(e->d_name, "renderD", 7) != 0) continue;
            char uevent[256];
            snprintf(uevent, sizeof(uevent), "/sys/class/drm/%s/device/uevent", e->d_name);
            FILE *f = fopen(uevent, "r");
            if (!f) continue;
            char line[256];
            int found = 0;
            while (fgets(line, sizeof(line), f)) {
                if (strncmp(line, "DRIVER=", 7) != 0) continue;
                for (int i = 0; want[i]; i++)
                    if (strstr(line, want[i])) { found = 1; break; }
                if (found) break;
            }
            fclose(f);
            if (found) {
                snprintf(out, n, "/dev/dri/%s", e->d_name);
                closedir(d);
                return 0;
            }
        }
        closedir(d);
    }
    for (int i = 128; i < 136; i++) {
        char p[32];
        snprintf(p, sizeof(p), "/dev/dri/renderD%d", i);
        if (access(p, R_OK | W_OK) == 0) { snprintf(out, n, "%s", p); return 0; }
    }
    out[0] = '\0';
    return -1;
}

static int vs_build_argv(VideoStream *vs, VideoDecodeMode mode, int tcp,
                         const char *devpath, char **argv, int maxargs) {
    int n = 0;
    char scale[160];
    (void)maxargs;

    argv[n++] = (char *)"ffmpeg";
    argv[n++] = (char *)"-hide_banner";
    argv[n++] = (char *)"-nostdin";
    argv[n++] = (char *)"-loglevel";
    argv[n++] = (char *)"error";

    int is_rtsp = (strncmp(vs->url, "rtsp", 4) == 0);
    if (is_rtsp) {
        argv[n++] = (char *)"-rtsp_transport";
        argv[n++] = (char *)(tcp ? "tcp" : "udp");
        /* soket zaman asimi (mikrosaniye) — askida kalan baglantilari kes */
        argv[n++] = (char *)"-timeout";
        argv[n++] = (char *)"5000000";
    }

    if (mode == VS_DECODE_VAAPI) {
        argv[n++] = (char *)"-hwaccel";
        argv[n++] = (char *)"vaapi";
        argv[n++] = (char *)"-hwaccel_device";
        argv[n++] = (char *)((devpath && devpath[0]) ? devpath : "/dev/dri/renderD128");
        argv[n++] = (char *)"-hwaccel_output_format";
        argv[n++] = (char *)"vaapi";
    } else if (mode == VS_DECODE_NVDEC) {
        argv[n++] = (char *)"-hwaccel";
        argv[n++] = (char *)"cuda";
    }

    argv[n++] = (char *)"-fflags";
    argv[n++] = (char *)"nobuffer";
    argv[n++] = (char *)"-flags";
    argv[n++] = (char *)"low_delay";
    argv[n++] = (char *)"-probesize";
    argv[n++] = (char *)"500000";
    argv[n++] = (char *)"-analyzeduration";
    argv[n++] = (char *)"500000";

    argv[n++] = (char *)"-i";
    argv[n++] = vs->url;

    argv[n++] = (char *)"-an";
    argv[n++] = (char *)"-sn";
    argv[n++] = (char *)"-dn";

    argv[n++] = (char *)"-vf";
    if (mode == VS_DECODE_VAAPI) {
        snprintf(scale, sizeof(scale),
                 "scale_vaapi=w=%d:h=%d,hwdownload,format=nv12,format=rgb24",
                 vs->w, vs->h);
    } else {
        snprintf(scale, sizeof(scale),
                 "scale=%d:%d:force_original_aspect_ratio=decrease,"
                 "pad=%d:%d:(ow-iw)/2:(oh-ih)/2,setsar=1",
                 vs->w, vs->h, vs->w, vs->h);
    }
    argv[n++] = scale;

    argv[n++] = (char *)"-r";
    argv[n++] = (char *)"15";
    argv[n++] = (char *)"-f";
    argv[n++] = (char *)"rawvideo";
    argv[n++] = (char *)"-pix_fmt";
    argv[n++] = (char *)"rgb24";
    argv[n++] = (char *)"pipe:1";
    argv[n] = NULL;
    return n;
}

/* ---------- Surec baslatma ---------- */
static int vs_spawn(VideoStream *vs, VideoDecodeMode mode, int tcp, const char *devpath) {
    int p[2];
    if (pipe(p) != 0) return -1;

    /* PID'e ozel log yolu: baska bir surecin/kullanicinin eski logu okunmasin */
    snprintf(vs->logpath, sizeof(vs->logpath), "/tmp/beat-vs-%d-%d.log",
             (int)getpid(), vs->slot);
    int efd = open(vs->logpath, O_RDWR | O_CREAT | O_TRUNC, 0600);

    char *argv[48];
    vs_build_argv(vs, mode, tcp, devpath, argv, 48);

    pid_t pid = fork();
    if (pid < 0) {
        close(p[0]); close(p[1]);
        if (efd >= 0) close(efd);
        return -1;
    }
    if (pid == 0) {
        /* cocuk */
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, 0); close(devnull); }
        dup2(p[1], 1);
        if (efd >= 0) dup2(efd, 2);
        close(p[0]);
        close(p[1]);
        if (efd >= 0) close(efd);
        execvp("ffmpeg", argv);
        _exit(127);
    }
    /* ebeveyn */
    close(p[1]);
    if (efd >= 0) close(efd); /* child kopyasini tutuyor; biz okumak icin yeniden acalim */
    vs->pipe_fd = p[0];
    vs->pid = pid;
    vs->err_fd = open(vs->logpath, O_RDONLY);
    return 0;
}

/*
 * Donanim decode yolunu ONCE dene: ffmpeg baslat, ilk kareyi timeout icinde
 * bekle. Basarisizsa cagiran taraf yazilim decode'a duser; boylece kullanici
 * bozuk/bos akis gormez (surucusuz sistemde VAAPI/NVDEC sessizce olur).
 * doner: 1 = donanim yol calisti, 0 = calismadi.
 */
static int vs_probe_mode(const char *url, int w, int h, VideoDecodeMode mode,
                         int tcp, const char *devpath, int timeout_ms) {
    VideoStream tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.pipe_fd = -1; tmp.err_fd = -1; tmp.slot = 0;
    tmp.w = w; tmp.h = h; tmp.frame_size = w * h * 3;
    strncpy(tmp.url, url, VS_URL_LEN - 1);

    if (vs_spawn(&tmp, mode, tcp, devpath) != 0) return 0;

    unsigned char *buf = (unsigned char *)malloc((size_t)tmp.frame_size);
    int ok = 0;
    double t0 = vs_now();
    if (buf) {
        int got = 0;
        while (got < tmp.frame_size) {
            if ((vs_now() - t0) * 1000.0 > (double)timeout_ms) break;
            ssize_t r = read(tmp.pipe_fd, buf + got, (size_t)(tmp.frame_size - got));
            if (r > 0) { got += (int)r; continue; }
            if (r == 0) break;                 /* EOF: ffmpeg oldu */
            if (errno == EINTR) continue;
            break;
        }
        if (got >= tmp.frame_size) ok = 1;
        free(buf);
    }
    if (tmp.pid > 0) kill(tmp.pid, SIGKILL);
    if (tmp.pipe_fd >= 0) close(tmp.pipe_fd);
    if (tmp.pid > 0) waitpid(tmp.pid, NULL, 0);
    if (tmp.err_fd >= 0) close(tmp.err_fd);
    if (tmp.logpath[0]) unlink(tmp.logpath);
    return ok;
}

/* ---------- Genel API ---------- */
void video_stream_system_init(void) {
    if (g_vs_init) return;
    for (int i = 0; i < VS_MAX_STREAMS; i++) {
        memset(&g_vs[i], 0, sizeof(g_vs[i]));
        g_vs[i].slot = i;
        g_vs[i].pipe_fd = -1;
        g_vs[i].err_fd = -1;
        g_vs[i].state = VS_ST_IDLE;
        platform_mutex_init(&g_vs[i].lock);
    }
    g_vs_init = 1;
}

void video_stream_system_shutdown(void) {
    if (!g_vs_init) return;
    for (int i = 0; i < VS_MAX_STREAMS; i++)
        if (g_vs[i].used) video_stream_close(i);
    g_vs_init = 0;
}

int video_stream_ffmpeg_available(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    cached = (system("command -v ffmpeg >/dev/null 2>&1") == 0) ? 1 : 0;
    return cached;
}

int video_stream_open(const char *url, int w, int h, VideoDecodeMode mode,
                      int transport_tcp) {
    if (!g_vs_init) video_stream_system_init();
    if (!url || !url[0]) return -1;
    if (w <= 0) w = VS_DEFAULT_W;
    if (h <= 0) h = VS_DEFAULT_H;

    int slot = -1;
    for (int i = 0; i < VS_MAX_STREAMS; i++) {
        if (!g_vs[i].used) { slot = i; break; }
    }
    if (slot < 0) return -1;

    VideoStream *vs = &g_vs[slot];
    platform_mutex_lock(&vs->lock);
    memset(vs->status, 0, sizeof(vs->status));
    vs->used = 1;
    vs->state = VS_ST_CONNECTING;
    vs->decode_mode = (int)mode;
    vs->w = w; vs->h = h;
    vs->frame_size = w * h * 3;
    strncpy(vs->url, url, VS_URL_LEN - 1);
    vs->frames = 0;
    vs->fps = 0;
    vs->win_start = vs_now();
    vs->win_frames = 0;
    vs->have_new = 0;
    vs->eof_seen = 0;
    vs->hw_fallback = 0;
    vs->logpath[0] = '\0';
    vs->rd_idx = 0;
    vs->draw_idx = 1;
    vs->running = 1;
    vs->auto_reconnect = 1;
    vs->tcp = transport_tcp;
    vs->devpath[0] = '\0';
    vs->record_pid = -1;
    vs->recording = 0;
    vs_set_status(vs, "baglaniyor...");
    platform_mutex_unlock(&vs->lock);

    if (!vs->buf[0]) vs->buf[0] = (unsigned char *)malloc((size_t)vs->frame_size);
    if (!vs->buf[1]) vs->buf[1] = (unsigned char *)malloc((size_t)vs->frame_size);
    if (!vs->buf[0] || !vs->buf[1]) {
        vs_set_status(vs, "bellek yetersiz");
        vs->state = VS_ST_ERROR;
        vs->used = 0;
        return -1;
    }

    /* Donanim decode isteniyorsa once bu sistemde gercekten calisip
     * calismadigini kisa bir on-denetimle dogrula. */
    char devpath[64] = "";
    VideoDecodeMode use_mode = mode;
    if (mode == VS_DECODE_VAAPI) {
        if (vs_vaapi_pick_device(devpath, sizeof(devpath)) != 0)
            use_mode = VS_DECODE_SOFT;
    }
    if (use_mode != VS_DECODE_SOFT &&
        !vs_probe_mode(url, w, h, use_mode, transport_tcp, devpath, 4000)) {
        use_mode = VS_DECODE_SOFT;
        devpath[0] = '\0';
        vs->hw_fallback = 1;
    }
    vs->decode_mode = (int)use_mode;
    snprintf(vs->devpath, sizeof(vs->devpath), "%s", devpath);

    if (vs_spawn(vs, use_mode, transport_tcp, devpath) != 0) {
        vs_set_status(vs, "ffmpeg baslatilamadi");
        vs->state = VS_ST_ERROR;
        vs->used = 0;
        return -1;
    }

    if (platform_thread_create(&vs->thread, vs_reader_thread, vs) != 0) {
        kill(vs->pid, SIGKILL);
        close(vs->pipe_fd); vs->pipe_fd = -1;
        waitpid(vs->pid, NULL, 0); vs->pid = -1;
        vs_set_status(vs, "okuyucu thread olusturulamadi");
        vs->state = VS_ST_ERROR;
        vs->used = 0;
        return -1;
    }
    vs->thread_started = 1;
    return slot;
}

void video_stream_close(int slot) {
    if (slot < 0 || slot >= VS_MAX_STREAMS) return;
    VideoStream *vs = &g_vs[slot];
    if (!vs->used) return;

    vs->running = 0;
    if (vs->record_pid > 0) { kill(vs->record_pid, SIGKILL); waitpid(vs->record_pid, NULL, 0); vs->record_pid = -1; }
    vs->recording = 0;
    if (vs->pid > 0) kill(vs->pid, SIGKILL);
    if (vs->thread_started) {
        pthread_join(vs->thread, NULL);
        vs->thread_started = 0;
    }
    if (vs->pipe_fd >= 0) { close(vs->pipe_fd); vs->pipe_fd = -1; }
    if (vs->pid > 0) { waitpid(vs->pid, NULL, 0); vs->pid = -1; }
    if (vs->err_fd >= 0) { close(vs->err_fd); vs->err_fd = -1; }
    if (vs->logpath[0]) { unlink(vs->logpath); vs->logpath[0] = '\0'; }

    if (vs->tex_ready) { UnloadTexture(vs->tex); vs->tex_ready = 0; }
    vs->state = VS_ST_STOPPED;
    vs->used = 0;
}

int video_stream_state(int slot) {
    if (slot < 0 || slot >= VS_MAX_STREAMS) return VS_ST_IDLE;
    return g_vs[slot].state;
}
int video_stream_is_active(int slot) {
    if (slot < 0 || slot >= VS_MAX_STREAMS) return 0;
    return g_vs[slot].used;
}

void video_stream_get_info(int slot, VideoStreamInfo *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (slot < 0 || slot >= VS_MAX_STREAMS) return;
    VideoStream *vs = &g_vs[slot];
    platform_mutex_lock(&vs->lock);
    out->slot = slot;
    out->state = vs->state;
    out->decode_mode = vs->decode_mode;
    out->width = vs->w;
    out->height = vs->h;
    out->fps = vs->fps;
    out->frames = vs->frames;
    out->last_frame_time = vs->last_frame_time;
    strncpy(out->url, vs->url, VS_URL_LEN - 1);
    strncpy(out->status, vs->status, VS_STATUS_LEN - 1);
    platform_mutex_unlock(&vs->lock);
}

int video_stream_poll(int slot) {
    if (slot < 0 || slot >= VS_MAX_STREAMS) return 0;
    VideoStream *vs = &g_vs[slot];
    if (!vs->used) return 0;

    int uploaded = 0;
    platform_mutex_lock(&vs->lock);
    if (vs->have_new) {
        unsigned char *px = vs->buf[vs->draw_idx];
        if (!vs->tex_ready) {
            Image img = {0};
            img.data = px;
            img.width = vs->w;
            img.height = vs->h;
            img.mipmaps = 1;
            img.format = PIXELFORMAT_UNCOMPRESSED_R8G8B8;
            vs->tex = LoadTextureFromImage(img);
            if (vs->tex.id > 0) {
                SetTextureFilter(vs->tex, TEXTURE_FILTER_BILINEAR);
                vs->tex_ready = 1;
                uploaded = 1;
            }
        } else {
            UpdateTexture(vs->tex, px);
            uploaded = 1;
        }
        vs->have_new = 0;
    }
    /* hata/akış bitti durumunda da durum metnini guncel tut */
    platform_mutex_unlock(&vs->lock);
    return uploaded;
}

Texture2D video_stream_texture(int slot) {
    Texture2D none = {0};
    if (slot < 0 || slot >= VS_MAX_STREAMS) return none;
    VideoStream *vs = &g_vs[slot];
    if (!vs->used || !vs->tex_ready) return none;
    return vs->tex;
}

void video_stream_set_status(int slot, const char *fmt, ...) {
    if (slot < 0 || slot >= VS_MAX_STREAMS) return;
    VideoStream *vs = &g_vs[slot];
    va_list ap;
    va_start(ap, fmt);
    platform_mutex_lock(&vs->lock);
    vsnprintf(vs->status, sizeof(vs->status), fmt, ap);
    platform_mutex_unlock(&vs->lock);
    va_end(ap);
}

int video_stream_snapshot(int slot, const char *path) {
    if (slot < 0 || slot >= VS_MAX_STREAMS || !path || !path[0]) return -1;
    VideoStream *vs = &g_vs[slot];
    if (!vs->used) return -1;
    int ok = -1;
    platform_mutex_lock(&vs->lock);
    if (vs->frames > 0 && vs->w > 0 && vs->h > 0 && vs->buf[vs->draw_idx]) {
        Image img = {0};
        img.data = vs->buf[vs->draw_idx];
        img.width = vs->w;
        img.height = vs->h;
        img.mipmaps = 1;
        img.format = PIXELFORMAT_UNCOMPRESSED_R8G8B8;
        ExportImage(img, path);
        ok = 0;
    }
    platform_mutex_unlock(&vs->lock);
    return ok;
}

/* Kayit icin ayri ffmpeg sureci: -c copy (yeniden kodlama yok).
 * segment_sec>0 ise segment mp4, degilse tek mp4. */
static pid_t vs_record_spawn(const char *url, const char *pattern, int seg, int tcp) {
    pid_t pid = fork();
    if (pid != 0) return pid;

    char segbuf[24];
    snprintf(segbuf, sizeof(segbuf), "%d", seg > 0 ? seg : 0);
    char *argv[48];
    int n = 0;
    argv[n++] = (char *)"ffmpeg";
    argv[n++] = (char *)"-hide_banner";
    argv[n++] = (char *)"-nostdin";
    argv[n++] = (char *)"-loglevel";
    argv[n++] = (char *)"error";
    if (strncmp(url, "rtsp", 4) == 0) {
        argv[n++] = (char *)"-rtsp_transport";
        argv[n++] = (char *)(tcp ? "tcp" : "udp");
    }
    argv[n++] = (char *)"-i";
    argv[n++] = (char *)url;
    argv[n++] = (char *)"-c";
    argv[n++] = (char *)"copy";
    argv[n++] = (char *)"-an";
    if (seg > 0) {
        argv[n++] = (char *)"-f";
        argv[n++] = (char *)"segment";
        argv[n++] = (char *)"-segment_time";
        argv[n++] = segbuf;
        argv[n++] = (char *)"-reset_timestamps";
        argv[n++] = (char *)"1";
    } else {
        argv[n++] = (char *)"-f";
        argv[n++] = (char *)"mp4";
        argv[n++] = (char *)"-movflags";
        argv[n++] = (char *)"+faststart";
    }
    argv[n++] = (char *)"-y";
    argv[n++] = (char *)pattern;
    argv[n] = NULL;

    int dn = open("/dev/null", O_RDONLY);
    if (dn >= 0) { dup2(dn, 0); close(dn); }
    int dno = open("/dev/null", O_WRONLY);
    if (dno >= 0) { dup2(dno, 1); dup2(dno, 2); close(dno); }
    execvp("ffmpeg", argv);
    _exit(127);
}

int video_stream_record_start(int slot, const char *pattern, int segment_sec) {
    if (slot < 0 || slot >= VS_MAX_STREAMS || !pattern || !pattern[0]) return -1;
    VideoStream *vs = &g_vs[slot];
    if (!vs->used || !vs->url[0]) return -1;
    if (vs->recording && vs->record_pid > 0) return 0;   /* zaten kayit ediyor */
    pid_t pid = vs_record_spawn(vs->url, pattern, segment_sec, vs->tcp);
    if (pid <= 0) return -1;
    vs->record_pid = pid;
    vs->recording = 1;
    return 0;
}

void video_stream_record_stop(int slot) {
    if (slot < 0 || slot >= VS_MAX_STREAMS) return;
    VideoStream *vs = &g_vs[slot];
    if (vs->record_pid > 0) {
        kill(vs->record_pid, SIGKILL);
        waitpid(vs->record_pid, NULL, 0);
        vs->record_pid = -1;
    }
    vs->recording = 0;
}

int video_stream_recording(int slot) {
    if (slot < 0 || slot >= VS_MAX_STREAMS) return 0;
    VideoStream *vs = &g_vs[slot];
    if (vs->recording && vs->record_pid > 0) {
        if (kill(vs->record_pid, 0) != 0) {   /* surec olduysa durumu temizle */
            vs->recording = 0;
            vs->record_pid = -1;
        }
    }
    return vs->recording;
}

void video_stream_set_reconnect(int slot, int enable) {
    if (slot < 0 || slot >= VS_MAX_STREAMS) return;
    g_vs[slot].auto_reconnect = enable ? 1 : 0;
}

int video_stream_reconnect_enabled(int slot) {
    if (slot < 0 || slot >= VS_MAX_STREAMS) return 0;
    return g_vs[slot].auto_reconnect;
}
