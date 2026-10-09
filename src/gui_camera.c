/*
 * gui_camera.c — BEAT System: Kamera Keşif / Erişim / İzleme arayüzü
 *
 * Bu modül backend motorlarını (camera_discovery / camera_access /
 * camera_vuln / video_stream) sürer ve iki yüzey çizer:
 *   - Dashboard sağ kolonundaki KAMERA LİSTESİ paneli
 *   - Araçlar ▸ "Kameralar" alt sekmesi (solda liste / sağda canlı detay)
 *
 * Tüm çizim yardımcıları modül içinde yeniden uygulanır (gui.c static'lerine
 * erişim yok). Font ve ölçek gui.c'den gui_font()/gui_scale() ile alınır.
 */
#include "gui_camera.h"
#include "gui.h"
#include "platform.h"
#include "camera_discovery.h"
#include "camera_access.h"
#include "camera_vuln.h"
#include "video_stream.h"

#include "raylib.h"
#include "../lib/raygui.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ========================================================================
 * Veri modeli
 * ===================================================================== */
#define GC_MAX        128
#define GC_ROW_H      20
#define GC_SNAP_DIR   "snapshots"

typedef enum {
  GC_DISCOVERED = 0,  /* keşfedildi */
  GC_TRYING,          /* erişim deneniyor */
  GC_OPEN,            /* kimliksiz açık akış */
  GC_CREDS,           /* parola/varsayılan bulundu */
  GC_ACCESSED,        /* erişildi (oturum açık) */
  GC_STREAMING,       /* canlı izleniyor */
  GC_FAILED           /* erişilemedi */
} GcState;

typedef struct {
  char     ip[MAX_IP_LEN];
  char     mac[MAX_MAC_LEN];
  char     vendor[64];
  char     model[64];
  int      rtsp_port;
  int      http_port;
  int      auth_required;
  char     realm[CAM_REALM_LEN];
  char     base_url[CAM_URL_LEN];

  GcState  state;
  int      stream_slot;          /* video_stream slotu, -1 = yok */
  int      recording;

  char     found_url[CAM_URL_LEN];
  char     found_user[64];
  char     found_pass[64];
  int      onvif_used;

  int      tried, total;
  unsigned vuln_mask;
  char     note[CA_ERR_LEN];
  char     info[192];            /* parmak izi / ONVIF üretilen metin */
} GcEntry;

static GcEntry g_e[GC_MAX];
static int     g_n = 0;
static char    g_sel[MAX_IP_LEN] = {0};

static float   g_scroll_list = 0.0f;
static float   g_scroll_detail = 0.0f;

static char    g_msg[192] = {0};
static char    g_muser[64] = {0};
static char    g_mpass[64] = {0};
static int     g_muser_edit = 0;
static int     g_mpass_edit = 0;
static double  g_last_sync = 0.0;

static int     g_ready = 0;
static int     g_scan_running = 0;

/* Kullanıcı tarafından girilen tarama hedefi (IP veya CIDR).
 * Boş bırakılırsa yerel arayüz alt ağı taranır ve kendi makine/gateway
 * otomatik dışlanır. Doldurulursa bu dışlama devre dışı kalır; böylece
 * yerel testbed (127.0.0.1) ve kendi alt ağındaki kameralar bulunur. */
static char    g_target[64] = {0};
static int     g_target_edit = 0;

/* ========================================================================
 * Çizim yardımcıları (gui.c static'lerinin bağımsız kopyaları)
 * ===================================================================== */
static void cam_txt(const char *t, int x, int y, int size, Color c) {
  if (!t) return;
  Font f = gui_font();
  if (f.texture.id > 0)
    DrawTextEx(f, t, (Vector2){(float)x, (float)y}, (float)size, 0.5f, c);
  else
    DrawText(t, x, y, size, c);
}

/* Metin genişliği: Türkçe glifleri taşıyan özel font ile ölçülür.
 * raylib'in MeasureText'i varsayılan ASCII fontunu kullanır;ı/İ/ş/Ş/ğ/ç
 * gibi kod noktalarını bulamayınca genişliği yanlış hesaplar ve hizalama
 * ile taşma kontrolleri bozulur (metin panel dışına taşar). */
static int cam_text_w(const char *t, int size) {
  if (!t || !t[0]) return 0;
  Font f = gui_font();
  if (f.texture.id > 0)
    return (int)MeasureTextEx(f, t, (float)size, 0.5f).x;
  return MeasureText(t, size);
}

/* UTF-8 farkındalı taşma kısaltıcı: metni max_w pikseline sığdırır,
 * kesildiyse sonuna '…' ekler. Çıktı daima geçerli UTF-8'dir. */
static void cam_trunc(char *dst, size_t dstsz, const char *src, int size,
                      int max_w) {
  if (!dst || dstsz == 0) return;
  dst[0] = '\0';
  if (!src) return;
  if (cam_text_w(src, size) <= max_w) {
    snprintf(dst, dstsz, "%s", src);
    return;
  }
  if (max_w <= 0) return;
  static const char ell[] = "\xE2\x80\xA6"; /* U+2026 … */
  int avail = max_w - cam_text_w(ell, size);
  if (avail < 0) avail = 0;
  size_t out = 0;
  int w = 0;
  const char *p = src;
  while (*p) {
    int cpn = 0;
    GetCodepointNext(p, &cpn);
    if (cpn <= 0) break;
    if (out + (size_t)cpn + 1 > dstsz) break;
    char tmp[8];
    if (cpn > 7) break;
    memcpy(tmp, p, (size_t)cpn);
    tmp[cpn] = '\0';
    int tn = cam_text_w(tmp, size);
    if (w + tn > avail) break;
    memcpy(dst + out, p, (size_t)cpn);
    out += (size_t)cpn;
    w += tn;
    p += cpn;
  }
  dst[out] = '\0';
  if (out + 4 <= dstsz) { /* '…' 3 bayt + NUL */
    memcpy(dst + out, ell, 3);
    out += 3;
    dst[out] = '\0';
  }
}

/* Metni max_w piksel ile sınırlayarak çizer (sığmazsa '…' ile kısaltır) */
static void cam_txt_fit(const char *t, int x, int y, int size, Color c,
                        int max_w) {
  char b[512];
  cam_trunc(b, sizeof(b), t, size, max_w);
  cam_txt(b, x, y, size, c);
}

static void cam_panel(Rectangle r, Color bg, Color border) {
  DrawRectangleRounded(r, 0.16f, 6, bg);
  if (border.a > 0)
    DrawRectangleRoundedLinesEx(r, 0.16f, 6, 1.0f, border);
}

static Color cam_alpha(Color c, int a) { c.a = (unsigned char)a; return c; }

static void cam_led(float x, float y, float r, Color c, int pulse) {
  if (pulse) {
    double t = GetTime();
    float pr = r + 2.0f + (float)((t - (long)t) * 2.0);
    DrawCircleV((Vector2){x, y}, pr, cam_alpha(c, 40));
  }
  DrawCircleV((Vector2){x, y}, r, c);
}

static void cam_scissor(int x, int y, int w, int h) {
  float s = gui_scale();
  BeginScissorMode((int)(x * s), (int)(y * s), (int)(w * s), (int)(h * s));
}

static void cam_badge(int x, int y, const char *text, int size, Color color) {
  if (!text || !text[0]) return;
  int tw = cam_text_w(text, size);
  int w = tw + 10;
  Rectangle r = {(float)x, (float)y, (float)w, (float)(size + 6)};
  DrawRectangleRounded(r, 0.5f, 4, cam_alpha(color, 34));
  DrawRectangleRoundedLinesEx(r, 0.5f, 4, 1.0f, cam_alpha(color, 150));
  cam_txt(text, x + 5, y + 3, size, color);
}

/* Sağ kenara hizalanmış rozet (right_x = rozetin bittiği sağ kenar) */
static void cam_badge_r(int right_x, int y, const char *text, int size,
                        Color color) {
  if (!text || !text[0]) return;
  cam_badge(right_x - (cam_text_w(text, size) + 10), y, text, size, color);
}

static void cam_scrollbar(float x, float y, float w, float view_h, float content_h,
                          float *scroll) {
  if (content_h <= view_h) return;
  float track = view_h;
  float thumb = track * (view_h / content_h);
  if (thumb < 20) thumb = 20;
  float maxs = content_h - view_h;
  float t = maxs > 0 ? (*scroll / maxs) : 0;
  float ty = y + t * (track - thumb);
  DrawRectangleRounded((Rectangle){x, y, w, track}, 0.5f, 4,
                       (Color){20, 26, 40, 160});
  DrawRectangleRounded((Rectangle){x, ty, w, thumb}, 0.5f, 4, COLOR_SCROLLBAR);
}

static int cam_btn(Rectangle r, const char *label, Color accent, int enabled) {
  Vector2 mp = GetMousePosition();
  int hov = enabled && CheckCollisionPointRec(mp, r);
  DrawRectangleRounded(r, 0.28f, 4,
                       enabled ? cam_alpha(accent, hov ? 64 : 26)
                               : (Color){30, 36, 50, 170});
  DrawRectangleRoundedLinesEx(r, 0.28f, 4, 1.0f,
                              enabled ? cam_alpha(accent, hov ? 220 : 150)
                                      : (Color){60, 70, 90, 110});
  /* Etiket buton genişliğini aşıyorsa '…' ile kısalt (taşmayı önle) */
  char fit[128];
  int inner = (int)r.width - 8;
  cam_trunc(fit, sizeof(fit), label, 10, inner);
  int tw = cam_text_w(fit, 10);
  Color tc = enabled ? (hov ? COLOR_TEXT : COLOR_TEXT_SEC) : COLOR_TEXT_DIM;
  cam_txt(fit, (int)(r.x + (r.width - tw) * 0.5f),
          (int)(r.y + r.height * 0.5f - 6), 10, tc);
  return enabled && hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
}

/* ========================================================================
 * Liste yönetimi
 * ===================================================================== */
static int gc_find(const char *ip) {
  for (int i = 0; i < g_n; i++)
    if (strcmp(g_e[i].ip, ip) == 0) return i;
  return -1;
}

static void gc_close_stream(GcEntry *e) {
  if (e->stream_slot >= 0) {
    if (video_stream_recording(e->stream_slot))
      video_stream_record_stop(e->stream_slot);
    video_stream_close(e->stream_slot);
    e->stream_slot = -1;
    e->recording = 0;
  }
}

static int gc_add(const char *ip) {
  if (g_n >= GC_MAX) return -1;
  if (gc_find(ip) >= 0) return gc_find(ip);
  GcEntry *e = &g_e[g_n];
  memset(e, 0, sizeof(*e));
  snprintf(e->ip, sizeof(e->ip), "%s", ip);
  e->state = GC_DISCOVERED;
  e->stream_slot = -1;
  snprintf(e->base_url, sizeof(e->base_url), "rtsp://%s:554/", ip);
  return g_n++;
}

static void gc_remove(int idx) {
  if (idx < 0 || idx >= g_n) return;
  gc_close_stream(&g_e[idx]);
  for (int i = idx; i < g_n - 1; i++) g_e[i] = g_e[i + 1];
  g_n--;
}

static void gc_clear_all(void) {
  for (int i = 0; i < g_n; i++) gc_close_stream(&g_e[i]);
  g_n = 0;
  g_sel[0] = '\0';
  g_scroll_list = 0;
}

/* Keşif sonuçlarını listeye harmanla (mevcut durum/akış korunur). */
static void gc_merge_discovery(void) {
  CameraScanResults res;
  memset(&res, 0, sizeof(res));
  camera_discovery_get_results(&res);
  g_scan_running = res.is_scanning;
  if (res.count <= 0) return;

  for (int i = 0; i < res.count; i++) {
    CameraDevice *c = &res.cameras[i];
    if (!c->ip[0]) continue;
    int idx = gc_find(c->ip);
    if (idx < 0) idx = gc_add(c->ip);
    if (idx < 0) continue;
    GcEntry *e = &g_e[idx];

    if (c->mac[0] && !e->mac[0]) snprintf(e->mac, sizeof(e->mac), "%s", c->mac);
    if (c->vendor[0]) snprintf(e->vendor, sizeof(e->vendor), "%s", c->vendor);
    if (c->manufacturer[0] && !e->model[0])
      snprintf(e->model, sizeof(e->model), "%.63s", c->manufacturer);
    else if (c->model[0])
      snprintf(e->model, sizeof(e->model), "%.63s", c->model);

    e->rtsp_port = c->rtsp_port > 0 ? c->rtsp_port : (c->ports[0] ? 554 : 0);
    if (e->rtsp_port == 0) e->rtsp_port = 554;
    e->http_port = c->http_port;
    e->auth_required = c->rtsp_auth_required;
    if (c->rtsp_realm[0])
      snprintf(e->realm, sizeof(e->realm), "%s", c->rtsp_realm);
    e->onvif_used = c->has_onvif;
    if (e->state == GC_DISCOVERED && c->mac[0] && !e->note[0])
      snprintf(e->note, sizeof(e->note), "güven: %d%%", c->confidence);

    char base[CAM_URL_LEN];
    camera_discovery_rtsp_url(c, base, sizeof(base));
    if (base[0]) snprintf(e->base_url, sizeof(e->base_url), "%s", base);
  }
}

/* ========================================================================
 * Aksiyonlar (backend)
 * ===================================================================== */
static void gc_do_scan(void) {
  if (camera_discovery_is_scanning()) { camera_discovery_cancel(); return; }
  if (g_target[0])
    snprintf(g_msg, sizeof(g_msg), "Kamera keşfi başlatıldı: %s", g_target);
  else
    snprintf(g_msg, sizeof(g_msg), "Kamera keşfi başlatıldı (yerel ağ)...");
  camera_discovery_start_async(g_target[0] ? g_target : NULL);
  g_scan_running = 1;
}

static void gc_do_access(GcEntry *e) {
  camera_access_set_context(e->ip, e->http_port, e->vendor);
  int port = e->rtsp_port > 0 ? e->rtsp_port : 554;
  if (camera_access_start(e->ip, port, e->base_url, e->auth_required,
                          e->realm) == 0) {
    e->state = GC_TRYING;
    snprintf(e->note, sizeof(e->note), "otonom erişim başlatıldı...");
    snprintf(g_msg, sizeof(g_msg), "%s için erişim denemesi başlatıldı.",
             e->ip);
  } else {
    snprintf(e->note, sizeof(e->note), "erişim kuyruğa alınamadı");
  }
}

static void gc_do_manual(GcEntry *e) {
  if (!g_muser[0] && !g_mpass[0]) {
    snprintf(g_msg, sizeof(g_msg), "Kullanıcı/parola boş.");
    return;
  }
  camera_access_set_context(e->ip, e->http_port, e->vendor);
  snprintf(e->note, sizeof(e->note), "elle: %s/%.16s", g_muser, g_mpass);
  if (camera_access_try_credentials(e->ip, g_muser, g_mpass) == 0) {
    e->state = GC_TRYING;
    snprintf(g_msg, sizeof(g_msg), "%s için elle kimlik denemesi.", e->ip);
  } else {
    snprintf(e->note, sizeof(e->note), "elle deneme başlatılamadı (meşgul?)");
  }
}

static void gc_do_watch(GcEntry *e) {
  if (e->stream_slot >= 0) return;   /* zaten izleniyor */
  if (!video_stream_ffmpeg_available()) {
    snprintf(e->note, sizeof(e->note), "ffmpeg yok - izleme devre dışı");
    snprintf(g_msg, sizeof(g_msg), "ffmpeg bulunamadı; izleme yapılamaz.");
    return;
  }
  if (!e->found_url[0]) {
    snprintf(g_msg, sizeof(g_msg), "Önce erişe/akışa sahip olun (found_url yok).");
    return;
  }
  int slot = video_stream_open(e->found_url, 0, 0, VS_DECODE_SOFT, 1);
  if (slot < 0) {
    snprintf(e->note, sizeof(e->note), "akış açılamadı");
    return;
  }
  video_stream_set_reconnect(slot, 1);
  e->stream_slot = slot;
  e->state = GC_STREAMING;
  snprintf(g_msg, sizeof(g_msg), "%s izleniyor: %s", e->ip, e->found_url);
}

static void gc_do_snapshot(GcEntry *e) {
  char path[300];
  snprintf(path, sizeof(path), GC_SNAP_DIR "/cam_%s.png", e->ip);
  mkdir(GC_SNAP_DIR, 0755);
  int rc = -1;
  if (e->stream_slot >= 0) rc = video_stream_snapshot(e->stream_slot, path);
  if (rc != 0) rc = camera_access_snapshot(e->ip, path);
  if (rc == 0)
    snprintf(g_msg, sizeof(g_msg), "Anlık görüntü kaydedildi: %.150s", path);
  else
    snprintf(g_msg, sizeof(g_msg), "Snapshot alınamadı (%s).", e->ip);
}

static void gc_do_record(GcEntry *e) {
  if (e->stream_slot < 0) {
    snprintf(g_msg, sizeof(g_msg), "Kayıt için önce izleyin.");
    return;
  }
  if (video_stream_recording(e->stream_slot)) {
    video_stream_record_stop(e->stream_slot);
    e->recording = 0;
    snprintf(g_msg, sizeof(g_msg), "Kayıt durduruldu.");
  } else {
    char pat[300];
    mkdir(GC_SNAP_DIR, 0755);
    snprintf(pat, sizeof(pat), GC_SNAP_DIR "/rec_%s_%%03d.mp4", e->ip);
    if (video_stream_record_start(e->stream_slot, pat, 60) == 0) {
      e->recording = 1;
      snprintf(g_msg, sizeof(g_msg), "Kayıt başladı (%.150s).", pat);
    } else {
      snprintf(g_msg, sizeof(g_msg), "Kayıt başlatılamadı.");
    }
  }
}

static void gc_do_fingerprint(GcEntry *e) {
  int hp = e->http_port > 0 ? e->http_port : 80;
  char vendor[64] = {0}, model[64] = {0}, fw[64] = {0}, serial[64] = {0};
  snprintf(g_msg, sizeof(g_msg), "Parmak izi sorgulanıyor (%s)...", e->ip);
  int n = camera_vuln_fingerprint_http(e->ip, hp, 0, vendor, sizeof(vendor),
                                       model, sizeof(model), fw, sizeof(fw),
                                       serial, sizeof(serial));
  if (vendor[0] && !e->vendor[0]) snprintf(e->vendor, sizeof(e->vendor), "%s", vendor);
  if (model[0]) snprintf(e->model, sizeof(e->model), "%s", model);

  /* ONVIF device-service denemesi (kimliksiz + yaygin tohumlar) */
  OnvifDeviceInfo di;
  memset(&di, 0, sizeof(di));
  static const CamCred onvif_seed[] = {
      {"admin", "admin"}, {"admin", "12345"}, {"admin", ""},
      {"admin", "password"}, {"root", "root"}, {NULL, NULL}};
  int got_onvif = 0;
  for (int i = 0; onvif_seed[i].user; i++) {
    if (onvif_probe_device(e->ip, hp, 0, onvif_seed[i].user,
                           onvif_seed[i].pass, &di) == 0) {
      got_onvif = 1;
      break;
    }
  }

  char vb[80] = {0}, mb[80] = {0}, fb[80] = {0}, sb[80] = {0};
  if (vendor[0]) snprintf(vb, sizeof(vb), " vendor=%.40s", vendor);
  if (model[0]) snprintf(mb, sizeof(mb), " model=%.40s", model);
  if (fw[0]) snprintf(fb, sizeof(fb), " fw=%.40s", fw);
  if (serial[0]) snprintf(sb, sizeof(sb), " s/n=%.40s", serial);
  snprintf(e->info, sizeof(e->info), "HTTP:%s%s%s%s%s | ONVIF:%s",
           n > 0 ? " bulundu" : " -", vb, mb, fb, sb,
           got_onvif ? " bulundu" : " -");
  if (got_onvif) {
    e->onvif_used = 1;
    if (di.manufacturer[0]) snprintf(e->vendor, sizeof(e->vendor), "%.63s", di.manufacturer);
    if (di.model[0]) snprintf(e->model, sizeof(e->model), "%.63s", di.model);
    if (di.stream_uri[0] && !e->found_url[0])
      snprintf(e->found_url, sizeof(e->found_url), "%s", di.stream_uri);
  }
  snprintf(g_msg, sizeof(g_msg), "Parmak izi tamam (%s).", e->ip);
}

static void gc_do_vuln(GcEntry *e) {
  int hp = e->http_port > 0 ? e->http_port : 80;
  char detail[CA_ERR_LEN] = {0};
  snprintf(g_msg, sizeof(g_msg), "Zafiyet sondaları (%s)...", e->ip);
  unsigned m = camera_vuln_probe_authbypass(e->ip, hp, 0,
                                            e->vendor[0] ? e->vendor : NULL,
                                            detail, sizeof(detail));
  e->vuln_mask = m;
  if (m) {
    snprintf(e->note, sizeof(e->note), "ZAFİYET: %s", detail[0] ? detail : "bulundu");
    snprintf(g_msg, sizeof(g_msg), "%s: bilinen zafiyet bulgusu!", e->ip);
  } else {
    snprintf(e->note, sizeof(e->note), "bilinen zafiyet sondası temiz");
    snprintf(g_msg, sizeof(g_msg), "%s: zafiyet sondası sonuç yok.", e->ip);
  }
}

/* ========================================================================
 * Durum senkronizasyonu (her frame)
 * ===================================================================== */
static void gc_update_from_jobs(void) {
  for (int i = 0; i < g_n; i++) {
    GcEntry *e = &g_e[i];
    CameraAccessJob job;
    memset(&job, 0, sizeof(job));
    if (!camera_access_get(e->ip, &job)) continue;

    e->tried = job.tried;
    e->total = job.total;
    e->vuln_mask = job.vuln_mask;
    if (job.vuln_detail[0]) snprintf(e->note, sizeof(e->note), "%s", job.vuln_detail);
    else if (job.last_error[0]) snprintf(e->note, sizeof(e->note), "%s", job.last_error);
    if (job.found_url[0]) snprintf(e->found_url, sizeof(e->found_url), "%s", job.found_url);
    if (job.found_user[0]) snprintf(e->found_user, sizeof(e->found_user), "%s", job.found_user);
    if (job.found_pass[0]) snprintf(e->found_pass, sizeof(e->found_pass), "%s", job.found_pass);
    if (job.onvif_used) e->onvif_used = 1;
    if (job.path[0]) {
      char base[CAM_URL_LEN];
      snprintf(base, sizeof(base), "rtsp://%s:%d/%s", e->ip,
               e->rtsp_port > 0 ? e->rtsp_port : 554, job.path);
    }

    if (e->stream_slot >= 0) {
      e->state = GC_STREAMING;
      continue;
    }
    switch (job.state) {
    case CA_QUEUED:
    case CA_RUNNING: e->state = GC_TRYING; break;
    case CA_FOUND:
      if (job.open_stream) e->state = GC_OPEN;
      else if (job.onvif_used) e->state = GC_ACCESSED;
      else e->state = GC_CREDS;
      break;
    case CA_FAILED:
    case CA_CANCELLED: e->state = GC_FAILED; break;
    default: break;
    }
  }
}

static void gc_poll_streams(void) {
  for (int i = 0; i < g_n; i++) {
    GcEntry *e = &g_e[i];
    if (e->stream_slot < 0) continue;
    video_stream_poll(e->stream_slot);
    int st = video_stream_state(e->stream_slot);
    if (st == VS_ST_ERROR) {
      snprintf(e->note, sizeof(e->note), "akış hata/kesildi");
      e->state = GC_ACCESSED;
    } else if (st == VS_ST_PLAYING) {
      e->state = GC_STREAMING;
    }
    if (e->recording && !video_stream_recording(e->stream_slot))
      e->recording = 0;
  }
}

void gui_camera_tick(void) {
  if (!g_ready) return;
  double now = GetTime();
  gc_update_from_jobs();
  gc_poll_streams();
  if (now - g_last_sync > 1.0) {
    gc_merge_discovery();
    g_last_sync = now;
  }
}

/* ========================================================================
 * Yaşam döngüsü
 * ===================================================================== */
void gui_camera_init(void) {
  if (g_ready) return;
  camera_discovery_init();
  camera_access_init();
  video_stream_system_init();
  mkdir(GC_SNAP_DIR, 0755);
  g_last_sync = GetTime();
  g_ready = 1;
  snprintf(g_msg, sizeof(g_msg), "Kamera modülü hazır.");

  /* GEÇİCİ (doğrulama): BEAT_CAM_DEMO=1 iken taşma/Türkçe glif testi için
   * sahte kamera kayıtları ekler. Kalıcı kod değildir. */
  if (getenv("BEAT_CAM_DEMO")) {
    struct {
      const char *ip, *mac, *vendor, *model, *note, *info, *url, *user;
      GcState st;
      int rec, onvif, tried, total;
    } d[] = {
        {"192.168.1.64", "aa:bb:cc:dd:ee:ff", "Hikvision Digital Technology",
         "DS-2CD2T45G0P-I Uzun Model Adı Denemesi", "varsayılan parola bulundu",
         "ONVIF: Hikvision; firmware 5.6.3 — bilinen açık zafiyeti tespit edildi",
         "rtsp://192.168.1.64:554/Streaming/Channels/101", "admin", GC_CREDS,
         1, 1, 42, 120},
        {"10.0.0.23", "11:22:33:44:55:66",
         "Dahua Technology Uzun Üretici Adı", "IPC-HDW2431T-AS",
         "erişilemedi — kimlik doğrulama başarısız",
         "SSDP kimlik: Dahua", "", "", GC_FAILED, 0, 0, 0, 0},
        {"172.16.5.9", "de:ad:be:ef:00:01", "XiongMai / Çin Klonu",
         "AĞ KAMERASI ÇOK UZUN MODEL ETİKETİ TAŞMA TESTİ", "akış hata/kesildi",
         "Parmak izi: web arayüzü Türkçe karakter testi: ıİşŞğĞçÇöÖüÜ",
         "rtsp://172.16.5.9:554/live0.264", "root", GC_STREAMING, 1, 1,
         27, 64},
    };
    for (unsigned di = 0; di < sizeof(d) / sizeof(d[0]); di++) {
      if (gc_add(d[di].ip) < 0) continue;
      GcEntry *e = &g_e[g_n - 1];
      snprintf(e->mac, sizeof(e->mac), "%s", d[di].mac);
      snprintf(e->vendor, sizeof(e->vendor), "%s", d[di].vendor);
      snprintf(e->model, sizeof(e->model), "%s", d[di].model);
      snprintf(e->note, sizeof(e->note), "%s", d[di].note);
      snprintf(e->info, sizeof(e->info), "%s", d[di].info);
      snprintf(e->found_url, sizeof(e->found_url), "%s", d[di].url);
      snprintf(e->found_user, sizeof(e->found_user), "%s", d[di].user);
      e->rtsp_port = 554;
      e->http_port = 80;
      e->state = d[di].st;
      e->recording = d[di].rec;
      e->onvif_used = d[di].onvif;
      e->tried = d[di].tried;
      e->total = d[di].total;
      e->vuln_mask = 0x5;
    }
    if (g_n > 0) snprintf(g_sel, sizeof(g_sel), "%s", g_e[0].ip);
    snprintf(g_msg, sizeof(g_msg),
             "Demo: taşma ve Türkçe glif doğrulaması etkin (ıİşŞğĞçÇöÖüÜ).");
  }
}

void gui_camera_cleanup(void) {
  if (!g_ready) return;
  for (int i = 0; i < g_n; i++) gc_close_stream(&g_e[i]);
  video_stream_system_shutdown();
  camera_access_shutdown();
  camera_discovery_cleanup();
  g_ready = 0;
}

void gui_camera_select(const char *ip) {
  if (!ip) return;
  snprintf(g_sel, sizeof(g_sel), "%s", ip);
  g_sel[MAX_IP_LEN - 1] = '\0';
}

int gui_camera_active_streams(void) {
  int c = 0;
  for (int i = 0; i < g_n; i++)
    if (g_e[i].stream_slot >= 0) c++;
  return c;
}

/* ========================================================================
 * Durum → rozet metni/renk
 * ===================================================================== */
static const char *gc_state_text(GcState s) {
  switch (s) {
  case GC_DISCOVERED: return "keşfedildi";
  case GC_TRYING:     return "deneniyor";
  case GC_OPEN:       return "açık akış";
  case GC_CREDS:      return "parola bulundu";
  case GC_ACCESSED:   return "erişildi";
  case GC_STREAMING:  return "izleniyor";
  case GC_FAILED:     return "erişilemedi";
  default:            return "?";
  }
}
static Color gc_state_color(GcState s) {
  switch (s) {
  case GC_DISCOVERED: return COLOR_TEXT_DIM;
  case GC_TRYING:     return COLOR_AMBER;
  case GC_OPEN:       return COLOR_RED;
  case GC_CREDS:      return COLOR_YELLOW;
  case GC_ACCESSED:   return COLOR_ACCENT;
  case GC_STREAMING:  return COLOR_GREEN;
  case GC_FAILED:     return COLOR_RED;
  default:            return COLOR_TEXT_SEC;
  }
}

/* ========================================================================
 * Dashboard paneli: KAMERA LİSTESİ
 * ===================================================================== */
void gui_camera_draw_list_panel(int rx, int ry, int rw, int rh) {
  cam_panel((Rectangle){(float)rx, (float)ry, (float)rw, (float)rh},
            COLOR_PANEL, cam_alpha(COLOR_BORDER, 140));

  /* Başlık (cyan aksan — İzleme Listesi'nden ayırt edilir) */
  cam_txt_fit("KAMERA LİSTESİ", rx + 10, ry + 10, 12, COLOR_ACCENT,
              rw - 34);
  {
    char cnt[40];
    snprintf(cnt, sizeof(cnt), "%d", g_n);
    cam_badge_r(rx + rw - 10, ry + 7, cnt, 9, COLOR_ACCENT);
  }

  /* Butonlar */
  int bw = (rw - 24) / 2;
  Rectangle b_scan = {(float)(rx + 10), (float)(ry + 30), (float)bw, 20};
  Rectangle b_clear = {(float)(rx + 10 + bw + 4), (float)(ry + 30), (float)bw, 20};
  if (cam_btn(b_scan, camera_discovery_is_scanning() ? "İPTAL" : "KAMERA BUL",
              COLOR_GREEN, 1))
    gc_do_scan();
  if (cam_btn(b_clear, "BOŞALT", COLOR_RED, g_n > 0)) gc_clear_all();

  /* Hedef alanı: boş = yerel ağ (kendi makine/gateway hariç).
   * Doldurulursa (ör. 127.0.0.1, 192.168.1.0/24) dışlama kalkar. */
  Rectangle tb = {(float)(rx + 10), (float)(ry + 54), (float)(rw - 20), 20};
  if (GuiTextBox(tb, g_target, sizeof(g_target), g_target_edit))
    g_target_edit = !g_target_edit;

  /* Tarama durumu */
  int top = ry + 104;
  int list_h = rh - (top - ry) - 22;
  {
    CameraScanResults res;
    memset(&res, 0, sizeof(res));
    camera_discovery_get_results(&res);
    char line[200];
    if (res.is_scanning)
      snprintf(line, sizeof(line), "%s  %d%%", res.phase[0] ? res.phase : "taranıyor",
               res.progress);
    else if (g_n > 0)
      snprintf(line, sizeof(line), "son tarama: %d kamera", g_n);
    else
      snprintf(line, sizeof(line), "kamera yok - tara");
    cam_txt_fit(g_target[0] ? "Hedef: elle girildi (kendi makine/gateway dahil taranır)"
                            : "Hedef: boş = yerel ağ (ör. 127.0.0.1 veya 192.168.1.0/24)",
                rx + 10, ry + 78, 7, COLOR_TEXT_SEC, rw - 20);
    cam_txt_fit(line, rx + 10, ry + 88, 8, COLOR_TEXT_DIM, rw - 20);

    /* ilerleme çubuğu */
    if (res.is_scanning) {
      Rectangle pb = {(float)(rx + 10), (float)(ry + 99), (float)(rw - 20), 4};
      DrawRectangleRounded(pb, 0.5f, 4, (Color){30, 40, 60, 200});
      Rectangle pf = pb;
      pf.width = (rw - 20) * (res.progress / 100.0f);
      DrawRectangleRounded(pf, 0.5f, 4, COLOR_ACCENT);
    }
  }

  /* Satırlar */
  cam_scissor(rx + 6, top, rw - 12, list_h);
  float y = (float)top - g_scroll_list;
  for (int i = 0; i < g_n; i++) {
    GcEntry *e = &g_e[i];
    if (y + GC_ROW_H >= top && y <= top + list_h) {
      Rectangle row = {(float)(rx + 6), y, (float)(rw - 12), (float)(GC_ROW_H - 2)};
      Vector2 mp = GetMousePosition();
      int hov = CheckCollisionPointRec(mp, row);
      int sel = (strcmp(e->ip, g_sel) == 0);
      if (sel) DrawRectangleRounded(row, 0.25f, 4, COLOR_SELECTED);
      else if (hov) DrawRectangleRounded(row, 0.25f, 4, (Color){255, 255, 255, 8});

      Color sc = gc_state_color(e->state);
      cam_led(row.x + 8, y + 9, 3.5f, sc, e->state == GC_TRYING || e->state == GC_STREAMING);

      /* IP/vendor metni durum etiketi ve X kutusuna taşmasın */
      const char *st = gc_state_text(e->state);
      int st_w = cam_text_w(st, 8);
      int xbtn_x = (int)(row.x + row.width) - 14;
      int text_max = xbtn_x - ((int)row.x + 18) - st_w - 12;
      if (text_max < 32) text_max = 32;

      cam_txt_fit(e->ip, (int)row.x + 18, (int)y + 4, 10, COLOR_TEXT, text_max);
      const char *sub = e->vendor[0] ? e->vendor : (e->mac[0] ? e->mac : "");
      if (sub[0])
        cam_txt_fit(sub, (int)row.x + 18, (int)y + 15, 7, COLOR_TEXT_DIM,
                    text_max);
      cam_txt(st, xbtn_x - st_w - 6, (int)y + 6, 8, sc);

      /* X (çıkar) */
      Rectangle xr = {row.x + row.width - 14, y + 2, 12, 12};
      if (CheckCollisionPointRec(mp, xr)) {
        DrawRectangleRounded(xr, 0.3f, 4, cam_alpha(COLOR_RED, 90));
        if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) { gc_remove(i); break; }
      }
      cam_txt("x", (int)xr.x + 3, (int)xr.y, 9, COLOR_TEXT_DIM);

      if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT) &&
          !CheckCollisionPointRec(mp, xr)) {
        snprintf(g_sel, sizeof(g_sel), "%.45s", e->ip);
      }
    }
    y += GC_ROW_H;
  }
  EndScissorMode();
  cam_scrollbar(rx + rw - 8, top, 6, list_h, g_n * GC_ROW_H, &g_scroll_list);

  /* Mesaj satırı */
  if (g_msg[0])
    cam_txt_fit(g_msg, rx + 10, ry + rh - 14, 8, COLOR_TEXT_DIM, rw - 20);
}

/* ========================================================================
 * Araçlar ▸ Kameralar alt sekmesi
 * ===================================================================== */
void gui_camera_draw_tools_panel(int W, int H) {
  int py = 86 + 34;
  int panel_h = H - py - 12;
  int list_w = 340;
  int lx = 12, rx = lx + list_w + 8;
  int rw = W - rx - 12;

  /* --- Sol: kamera listesi --- */
  cam_panel((Rectangle){(float)lx, (float)py, (float)list_w, (float)panel_h},
            COLOR_PANEL, cam_alpha(COLOR_BORDER, 150));
  cam_txt_fit("KAMERA LİSTESİ", lx + 12, py + 10, 13, COLOR_ACCENT,
              list_w - 12 - cam_text_w("ARAÇ-04", 8) - 34);
  cam_badge_r(lx + list_w - 10, py + 11, "ARAÇ-04", 8, COLOR_TEXT_DIM);

  int bw = (list_w - 24) / 2;
  Rectangle b_scan = {(float)(lx + 12), (float)(py + 32), (float)bw, 22};
  Rectangle b_clear = {(float)(lx + 12 + bw + 4), (float)(py + 32), (float)bw, 22};
  if (cam_btn(b_scan, camera_discovery_is_scanning() ? "TARAMAYI İPTAL" : "KAMERA BUL",
              COLOR_GREEN, 1))
    gc_do_scan();
  if (cam_btn(b_clear, "BOŞALT", COLOR_RED, g_n > 0)) gc_clear_all();

  /* Hedef alanı: boş = yerel ağ (kendi makine/gateway hariç). */
  Rectangle tb = {(float)(lx + 12), (float)(py + 58), (float)(list_w - 24), 20};
  if (GuiTextBox(tb, g_target, sizeof(g_target), g_target_edit))
    g_target_edit = !g_target_edit;
  cam_txt(g_target[0] ? "Hedef: elle girildi (dışlama kapalı)"
                      : "Hedef: boş = yerel ağ (ör. 127.0.0.1)",
          lx + 12, py + 82, 7, COLOR_TEXT_SEC);

  int l_top = py + 96;
  int l_h = panel_h - (l_top - py) - 8;
  cam_scissor(lx + 6, l_top, list_w - 12, l_h);
  float y = (float)l_top - g_scroll_list;
  for (int i = 0; i < g_n; i++) {
    GcEntry *e = &g_e[i];
    if (y + 26 >= l_top && y <= l_top + l_h) {
      Rectangle row = {(float)(lx + 6), y, (float)(list_w - 12), 24};
      Vector2 mp = GetMousePosition();
      int hov = CheckCollisionPointRec(mp, row);
      int sel = (strcmp(e->ip, g_sel) == 0);
      if (sel) DrawRectangleRounded(row, 0.2f, 4, COLOR_SELECTED);
      else if (hov) DrawRectangleRounded(row, 0.2f, 4, (Color){255, 255, 255, 8});

      Color sc = gc_state_color(e->state);
      DrawRectangle((int)row.x, (int)y + 2, 3, 20, sc);
      cam_led(row.x + 12, y + 12, 3.5f, sc, e->state == GC_TRYING || e->state == GC_STREAMING);
      /* IP/vendor metni durum etiketine taşmasın */
      const char *st = gc_state_text(e->state);
      int st_w = cam_text_w(st, 8);
      int right_edge = (int)(row.x + row.width) - 8;
      int text_max = right_edge - ((int)row.x + 22) - st_w - 12;
      if (text_max < 40) text_max = 40;

      cam_txt_fit(e->ip, (int)row.x + 22, (int)y + 3, 10, COLOR_TEXT,
                  text_max);

      char sub[96];
      snprintf(sub, sizeof(sub), "%s%s%s",
               e->vendor[0] ? e->vendor : "kamera",
               e->model[0] ? " · " : "", e->model[0] ? e->model : "");
      cam_txt_fit(sub, (int)row.x + 22, (int)y + 14, 7, COLOR_TEXT_DIM,
                  text_max);
      cam_txt(st, right_edge - st_w, (int)y + 8, 8, sc);

      if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        snprintf(g_sel, sizeof(g_sel), "%.45s", e->ip);
        g_scroll_detail = 0;
      }
    }
    y += 26;
  }
  EndScissorMode();
  cam_scrollbar(lx + list_w - 8, l_top, 6, l_h, g_n * 26, &g_scroll_list);

  /* --- Sağ: seçili kamera detayı --- */
  cam_panel((Rectangle){(float)rx, (float)py, (float)rw, (float)panel_h},
            COLOR_PANEL, cam_alpha(COLOR_BORDER, 150));

  int sel = gc_find(g_sel);
  if (sel < 0) {
    cam_txt_fit("SEÇİLİ KAMERA", rx + 12, py + 10, 13, COLOR_ACCENT2,
                rw - 24);
    cam_txt_fit("Soldan bir kamera seçin veya yeni tarama başlatın.",
                rx + 12, py + 40, 11, COLOR_TEXT_DIM, rw - 24);
    if (g_msg[0])
      cam_txt_fit(g_msg, rx + 12, py + panel_h - 16, 9, COLOR_TEXT_DIM,
                  rw - 24);
    return;
  }
  GcEntry *e = &g_e[sel];

  char title[160];
  snprintf(title, sizeof(title), "SEÇİLİ KAMERA  ·  %s", e->ip);
  /* Başlık, sağdaki durum rozetine taşmasın */
  cam_txt_fit(title, rx + 12, py + 10, 13, COLOR_ACCENT2,
              rw - 24 - cam_text_w(gc_state_text(e->state), 9) - 24);
  cam_badge_r(rx + rw - 12, py + 9, gc_state_text(e->state), 9,
              gc_state_color(e->state));

  /* Canlı görüntü alanı */
  int vx = rx + 12, vy = py + 34;
  int vw = rw - 24;
  int vh = (int)(vw * 9.0f / 16.0f);
  if (vh > panel_h - 220) vh = panel_h - 220;
  if (vh < 120) vh = 120;
  Rectangle vid = {(float)vx, (float)vy, (float)vw, (float)vh};
  DrawRectangleRounded(vid, 0.04f, 4, (Color){2, 4, 7, 255});
  DrawRectangleRoundedLinesEx(vid, 0.04f, 4, 1.0f, cam_alpha(COLOR_BORDER, 160));

  if (e->stream_slot >= 0) {
    Texture2D tex = video_stream_texture(e->stream_slot);
    if (tex.id > 0) {
      Rectangle src = {0, 0, (float)tex.width, (float)tex.height};
      Rectangle dst = vid;
      DrawTexturePro(tex, src, dst, (Vector2){0, 0}, 0.0f, WHITE);
    } else {
      const char *t = "BAĞLANIYOR...";
      int tw = cam_text_w(t, 14);
      int tx = tw > vw - 16 ? vx + 8 : vx + (vw - tw) / 2;
      cam_txt_fit(t, tx, vy + vh / 2 - 8, 14, COLOR_TEXT_SEC, vw - 16);
    }
    /* kayıt göstergesi */
    if (e->recording) {
      cam_led(vx + vw - 22, vy + 16, 6, COLOR_RED, 1);
      cam_txt("REC", vx + vw - 52, vy + 10, 10, COLOR_RED);
    }
  } else {
    const char *t = "GÖRÜNTÜ YOK";
    int tw = cam_text_w(t, 16);
    cam_txt_fit(t, tw > vw - 16 ? vx + 8 : vx + (vw - tw) / 2,
                vy + vh / 2 - 10, 16, COLOR_TEXT_DIM, vw - 16);
    const char *t2 = "İzlemek için ERİŞ + İZLE";
    int t2w = cam_text_w(t2, 10);
    cam_txt_fit(t2, t2w > vw - 16 ? vx + 8 : vx + (vw - t2w) / 2,
                vy + vh / 2 + 10, 10, COLOR_TEXT_DIM, vw - 16);
  }

  /* Bilgi bloğu (alttaki kontrol butonlarına taşmasın diye sınırlı).
   * -110: üç buton sırası (3*22) + kimlik etiketi + LİSTEDEN ÇIKAR
   * satırı çakışmasız sığsın. */
  int by = py + panel_h - 110;
  int iy = vy + vh + 8;
  #define INFO_LINE(fmt, ...) do { char _b[256]; snprintf(_b, sizeof(_b), fmt, __VA_ARGS__); \
      if (iy + 12 <= by - 6) cam_txt_fit(_b, rx + 12, iy, 9, COLOR_TEXT_SEC, rw - 24); \
      iy += 14; } while (0)

  INFO_LINE("MAC: %s    Vendor: %s    Model: %s",
            e->mac[0] ? e->mac : "-", e->vendor[0] ? e->vendor : "-",
            e->model[0] ? e->model : "-");
  INFO_LINE("RTSP: %s:%d    HTTP: %d    ONVIF: %s",
            e->ip, e->rtsp_port > 0 ? e->rtsp_port : 554,
            e->http_port, e->onvif_used ? "var" : "-");
  INFO_LINE("Akış: %s", e->found_url[0] ? e->found_url : "(yok)");
  INFO_LINE("Kimlik: %s", e->found_user[0] ? e->found_user : "(yok / açık)");
  if (e->total > 0)
    INFO_LINE("Deneme: %d / %d", e->tried, e->total);
  if (e->note[0])
    INFO_LINE("Durum: %s", e->note);
  if (e->vuln_mask)
    INFO_LINE("Zafiyet maskesi: 0x%x", e->vuln_mask);
  if (e->info[0])
    INFO_LINE("%s", e->info);
  #undef INFO_LINE

  if (g_msg[0] && iy + 10 <= by - 6) {
    cam_txt_fit(g_msg, rx + 12, iy, 8, COLOR_TEXT_DIM, rw - 24);
    iy += 12;
  }

  /* Kontrol butonları (by yukarıda tanımlı; üç sıra + kimlik satırı)
   * Not: "LİSTEDEN ÇIKAR" py+panel_h-24'te; by3 satırı bunun üstünde
   * bitmeli (eski -78 ofseti kimlik satırı ile çakışıyordu). */
  int gap = 6;
  int nbtn = 3;
  int buttonw = (rw - 24 - gap * (nbtn - 1)) / nbtn;

  Rectangle r1 = {(float)(rx + 12), (float)by, (float)buttonw, 22};
  Rectangle r2 = {(float)(rx + 12 + (buttonw + gap)), (float)by, (float)buttonw, 22};
  Rectangle r3 = {(float)(rx + 12 + (buttonw + gap) * 2), (float)by, (float)buttonw, 22};

  int watching = (e->stream_slot >= 0);
  if (cam_btn(r1, watching ? "İZLEMEYİ DURDUR" : "İZLE", COLOR_GREEN, e->found_url[0] != 0 || watching)) {
    if (watching) { gc_close_stream(e); e->state = e->found_url[0] ? GC_ACCESSED : GC_FAILED;
                    snprintf(g_msg, sizeof(g_msg), "İzleme durduruldu."); }
    else gc_do_watch(e);
  }
  if (cam_btn(r2, "ANLIK GÖRÜNTÜ", COLOR_ACCENT, e->stream_slot >= 0 || e->found_url[0] != 0))
    gc_do_snapshot(e);
  if (cam_btn(r3, e->recording ? "KAYDI DURDUR" : "KAYIT", COLOR_RED, e->stream_slot >= 0))
    gc_do_record(e);

  int by2 = by + 26;
  Rectangle s1 = {(float)(rx + 12), (float)by2, (float)buttonw, 22};
  Rectangle s2 = {(float)(rx + 12 + (buttonw + gap)), (float)by2, (float)buttonw, 22};
  Rectangle s3 = {(float)(rx + 12 + (buttonw + gap) * 2), (float)by2, (float)buttonw, 22};
  if (cam_btn(s1, "OTONOM ERİŞ", COLOR_AMBER, !camera_access_busy(e->ip))) gc_do_access(e);
  if (cam_btn(s2, "PARMAK İZİ + ONVIF", COLOR_ACCENT2, 1)) gc_do_fingerprint(e);
  if (cam_btn(s3, "ZAFİYET SONDASI", COLOR_RED, 1)) gc_do_vuln(e);

  /* Elle kimlik satırı (32 piksel aralık: "Kullanıcı/Parola" etiketleri
   * bir üstteki buton sırasına bulaşmasın) */
  int by3 = by2 + 32;
  int ubw = (rw - 24 - gap * 2 - 90) / 2;
  Rectangle ub = {(float)(rx + 12), (float)by3, (float)ubw, 22};
  Rectangle pb = {(float)(rx + 12 + ubw + gap), (float)by3, (float)ubw, 22};
  Rectangle db = {(float)(rx + 12 + (ubw + gap) * 2), (float)by3,
                  (float)(rw - 24 - (ubw + gap) * 2), 22};
  if (GuiTextBox(ub, g_muser, sizeof(g_muser), g_muser_edit)) g_muser_edit = !g_muser_edit;
  if (GuiTextBox(pb, g_mpass, sizeof(g_mpass), g_mpass_edit)) g_mpass_edit = !g_mpass_edit;
  /* Etiketler kutulardan SONRA ve 8px ile: 7px DIM renk küçük ölçekte
   * okunmuyor / buton kenarına değecek kadar sıkışık görünüyordu */
  cam_txt("Kullanıcı", (int)ub.x, (int)ub.y - 11, 8, COLOR_TEXT_SEC);
  cam_txt("Parola", (int)pb.x, (int)pb.y - 11, 8, COLOR_TEXT_SEC);
  if (cam_btn(db, "ELLE DENE", COLOR_GREEN, 1)) gc_do_manual(e);

  /* Listeden çıkar */
  Rectangle cb = {(float)(rx + 12), (float)(py + panel_h - 24), 150, 20};
  if (cam_btn(cb, "LİSTEDEN ÇIKAR", COLOR_RED, 1)) {
    gc_remove(sel);
    g_sel[0] = '\0';
  }
}
