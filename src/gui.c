/*
 * gui.c — BEAT System: raylib + raygui native GUI (v3 — Siyah Tema)
 *
 * Yeniden tasarim ozeti:
 *  - Saf siyah zemin, neon cyan/mor aksanlar, HUD tarzi header (durum
 *    LED'i, arayuz cipi, tarama isigi), panel ici rozetler/legendler.
 *  - Tum GUI durumu (g_* degiskenleri), arka uç cagrilari ve etkilesim
 *    mantigi (scroll, secim, filtre, auto-scroll, capture yonetimi)
 *    onceki surumle BIREBIR AYNI tutuldu.
 */
#include "gui.h"
#include "arp_scanner.h"
#include "filter_engine.h"
#include "network_monitor.h"
#include "network_ids.h"
#include "arp_block.h"
#include "platform.h"
#include "port_scanner.h"
#include "site_block.h"
#include "raylib.h"
#include "utils.h"
#include "gui_camera.h"

#define RAYGUI_IMPLEMENTATION
#include "../lib/raygui.h"
#include <math.h>
#include <stdio.h>
#include <string.h>

/* ========== State (v2 ile birebir) ========== */
static GuiTab g_active_tab = TAB_DASHBOARD;
static ScanResults g_scan;
static ScanLog g_scanlog;
static float g_scroll_devices = 0;
static float g_scroll_alerts = 0;
static char g_selected_device_ip[MAX_IP_LEN] = {0};
static double g_last_refresh = 0;

static PortScanResults g_portscan;
static float g_scroll_nm_flows = 0;
static float g_scroll_device_detail = 0;

static int g_tools_subtab = 0;         /* 0=Paket Izleme, 1=Site Karartma, 2=Port Tarayici */
static float g_scroll_tool_ports = 0;
static int g_selected_packet_num = -1;
static float g_scroll_pdu_detail = 0;
static int g_ps_selected_vuln_port = -1; /* secili port vulnerability detail */
static char g_ps_target[MAX_IP_LEN] = {0};      /* port tarayici secili hedef */
static float g_scroll_ps_devices = 0;    /* port scanner cihaz listesi scroll */
static int g_selected_layer = -1;
static char g_capture_active_ip[MAX_IP_LEN] = {0}; /* aktif trafik izleme yapilan cihaz */
static int g_capture_all = 0; /* tum ag izleme (ARP spoof + full_monitor) aktif */
static char g_capture_iface[MAX_IFACE_LEN] = {0}; /* izlemenin actigi arayuz (failover icin) */
static IdsGuiAlert g_ids_alerts_snapshot[IDS_MAX_GUI_ALERTS];
static int g_ids_alert_count = 0;
static float g_scroll_nm_devices = 0;    /* network monitor cihaz listesi scroll */
static ArpBlockSnapshot g_arp_block;     /* Agdan Kesme (ARP) engel listesi */
static float g_scroll_blk = 0;           /* engellenen cihazlar listesi scroll */
static char g_nm_target[MAX_IP_LEN] = {0}; /* network monitor secili hedef */

/* ========== Site Karartma (ARAC-03) ========== */
static char  g_sb_domain[SB_DOMAIN_LEN] = {0};   /* alan adi giris kutusu */
static int   g_sb_domain_active = 0;             /* kutu odakli mi */
static int   g_sb_mode = SB_MODE_BOTH;           /* mod secimi */
static char  g_sb_sinkhole[SB_IP_LEN] = "0.0.0.0";
static int   g_sb_sinkhole_active = 0;
static int   g_sb_sel_rule = -1;
static float g_sb_scroll_rules = 0;
static float g_sb_scroll_obs = 0;
static float g_sb_scroll_ips = 0;
static char  g_sb_target[MAX_IP_LEN] = {0}; /* SB goruntuleme filtresi (paket izlemeden bagimsiz) */
static int   g_sb_show_all = 0;             /* 1 = 'Tum IP\'ler' secili */

/* ========== Izleme Listesi (paket izleme kapsami) ==========
 * Paket izleme / ARP spoof / IDS uyari gosterimi YALNIZCA bu listedeki
 * IP'lere uygulanir. BOS liste = izleme KAPALI (hicbir sey izlenmez);
 * 'TUMUNU EKLE' butonu listeyi tarayici sonuclariyla doldurur. */
#define MON_LIST_MAX 128
static char g_mon_ips[MON_LIST_MAX][MAX_IP_LEN];
static int g_mon_count = 0;
static float g_scroll_mon_list = 0;
/* Izleme kapsami geri bildirimi (header kisa notu, or. bos liste) */
static char g_mon_notice[128] = {0};
static double g_mon_notice_ts = 0;
static void mon_notice_set(const char *msg) {
  if (!msg) return;
  strncpy(g_mon_notice, msg, sizeof(g_mon_notice) - 1);
  g_mon_notice_ts = GetTime();
}
/* Izleme listesini IDS motor kapsamina yansitir (tanim: rebuild sonrasi) */
static void mon_list_sync_scope(void);
/* Bos liste izleme durdurma cagrisi icin erken on bildirim (tanim: L~800) */
static void capture_stop_all(void);

static int mon_list_has(const char *ip) {
  if (!ip || !ip[0]) return 0;
  for (int i = 0; i < g_mon_count; i++)
    if (strcmp(g_mon_ips[i], ip) == 0) return 1;
  return 0;
}
static int mon_list_active(void) { return g_mon_count > 0; }
static int mon_list_toggle(const char *ip) {
  int at = -1;
  for (int i = 0; i < g_mon_count; i++)
    if (strcmp(g_mon_ips[i], ip) == 0) { at = i; break; }
  if (at >= 0) {
    for (int i = at; i < g_mon_count - 1; i++)
      strncpy(g_mon_ips[i], g_mon_ips[i + 1], MAX_IP_LEN - 1);
    g_mon_ips[g_mon_count - 1][0] = '\0';
    g_mon_count--;
    mon_list_sync_scope();
    /* Son cihaz da cikti: bos liste = izleme kapsami yok -> aktif izleme
     * durdurulur (otomatik olarak tum ag izlenmeye devam edilmez). */
    if (g_mon_count == 0 && (g_capture_all || g_capture_active_ip[0]))
      capture_stop_all();
    return 0; /* listeden cikarildi */
  }
  if (g_mon_count >= MON_LIST_MAX) return -1; /* liste dolu */
  strncpy(g_mon_ips[g_mon_count], ip, MAX_IP_LEN - 1);
  g_mon_ips[g_mon_count][MAX_IP_LEN - 1] = '\0';
  g_mon_count++;
  mon_list_sync_scope();
  return 1; /* eklendi */
}
static int mon_list_remove_at(int idx) {
  if (idx < 0 || idx >= g_mon_count) return 0;
  return mon_list_toggle(g_mon_ips[idx]);
}

/* IDS alarm gorunum haritasi: snapshot TAM tutulur; gorunum yalnizca
 * izleme listesindeki IP'lere ait kayitlari gosterir. Silme islemi
 * gorunum satiri -> harita -> snapshot dizini uzerinden yapilir. */
static int g_ids_alert_map[IDS_MAX_GUI_ALERTS];
static int g_ids_alert_view_count = 0;

/* --- Uyari sekmesi onem-derecesi filtresi (analist triyaji) ---
 * g_ids_sev_filter: -1=tumu, 0=KRITIK, 1=YUKSEK, 2=ORTA, 3=DUSUK. */
static int g_ids_sev_filter = -1;

static int severity_rank(const char *sev) {
  if (!sev) return 3;
  if (strcmp(sev, "KRITIK") == 0) return 0;
  if (strcmp(sev, "YUKSEK") == 0) return 1;
  if (strcmp(sev, "ORTA") == 0) return 2;
  return 3;
}

static void ids_rebuild_alert_view(void) {
  g_ids_alert_view_count = 0;
  for (int i = 0; i < g_ids_alert_count; i++) {
    IdsGuiAlert *va = &g_ids_alerts_snapshot[i];
    /* Kapsam: iki uc da listede yoksa gosterme. BOS liste = kapsam yok
     * -> hicbir uyari gosterilmez (bos listeyken izleme yok). */
    if (!mon_list_has(va->src_ip) && !mon_list_has(va->dst_ip))
      continue;
    /* Onem derecesi filtresi: secili seviye disi kayitlari gizle. */
    if (g_ids_sev_filter >= 0 &&
        severity_rank(va->severity) != g_ids_sev_filter)
      continue;
    g_ids_alert_map[g_ids_alert_view_count++] = i;
  }
}

/* Izleme listesini IDS motor kapsamina yansitir. BOS liste = motor pasif
 * (hicbir paket islenmez); dolu liste = yalnizca listedeki IP'ler. */
static void mon_list_sync_scope(void) {
  if (g_mon_count <= 0) {
    ids_scope_clear();
    /* Site karartma: bos izleme listesi = tum ag gozlenir (KURAL yoksa
     * yine de hicbir trafik karartilmaz; yalnizca gozlem toplanir). */
    site_block_clear_scope();
  } else {
    const char *ips[IDS_SCOPE_MAX];
    int n = 0;
    for (int i = 0; i < g_mon_count && n < IDS_SCOPE_MAX; i++)
      ips[n++] = g_mon_ips[i];
    ids_scope_set(ips, n);
    site_block_set_scope(ips, n);
  }
  ids_rebuild_alert_view();
}
static int g_nm_prev_packet_count = 0;  /* auto-scroll icin onceki paket sayisi */
static int g_nm_auto_scroll = 1;        /* 1=en altta, otomatik kaydir */
static int g_nm_flow_paused = 0;        /* Paket Izleme akis kilidi (izleme SURUYOR) */
static int g_nm_flow_dirty = 1;         /* kilitli akis tek seferlik yenilensin mi */
static char g_pkt_filter[256];         /* display filtre ifadesi (Paket Izleme) */
static char g_pkt_filter_prev[256];    /* onceki ifade: degisiklik algilamak icin */
static int g_pkt_filter_active = 0;    /* filtre kutusu odakli mi (metin girisi) */
static int g_nm_hide_own_arp = 1;      /* kendi (spoof) ARP trafigini gizle (varsayilan acik) */
static int g_pcap_rec_fail = 0;        /* PCAP kayit baslatma hatasi (geri bildirim) */

/* ===== Paket Izleme gorunum tamponu (delta akis) =====
 * Eski tasarim her 100 ms'de ring'in TAMAMINI (16K x ~14.5 KB ~ 237 MB)
 * global_lock altinda kopyaliyordu; capture thread'i bloke olup kernel
 * paket dusuruyor, liste titriyor, sayfa bosaliyor ve sayac geriye
 * gidiyordu. Yeni tasarim: yalnizca son cekilen paket numarasindan sonra
 * gelen paketler (delta) kopyalanir; tam yenileme yalnizca nesil/filtre/
 * hedef degisiminde yapilir. */
#define NM_DISPLAY_MAX 16384
#define NM_DELTA_MAX 512
#define NM_DELTA_BUDGET 2048
static PacketRecord nm_all_packets[NM_DISPLAY_MAX]; /* tam yenileme ara tamponu */
static PacketRecord nm_dev_packets[NM_DISPLAY_MAX]; /* gorunum ring'i (kronolojik) */
static PacketRecord nm_delta_buf[NM_DELTA_MAX];     /* delta cekme tamponu */
static int nm_dpc = 0;          /* gorunum ring'indeki paket sayisi */
static int nm_dstart = 0;       /* gorunum ring'inin en eski elemani */
static int nm_cursor = 0;       /* son gorulen paket numarasi (delta) */
static unsigned nm_fm_gen = 0; /* son tam yenilemedeki ring nesli */
static double g_nm_last_refresh = 0.0; /* akis zaman esigi (throttle) */

/* Gorunum ring'indeki i. paket (kronolojik sirada) */
static PacketRecord *nm_disp_get(int i) {
  return &nm_dev_packets[(nm_dstart + i) % NM_DISPLAY_MAX];
}

/* Gorunum ring'ine paket ekle; doluysa en eskiyi at (tail -f semantigi) */
static void nm_disp_append(const PacketRecord *p) {
  int w = (nm_dstart + nm_dpc) % NM_DISPLAY_MAX;
  nm_dev_packets[w] = *p;
  if (nm_dpc < NM_DISPLAY_MAX)
    nm_dpc++;
  else
    nm_dstart = (nm_dstart + 1) % NM_DISPLAY_MAX;
}

/* Gorunum filtresi: kendi ARP trafigini gizle + hedef eslesmesi + display filtre */
static int nm_filter_match(const PacketRecord *p, const char *own_mac,
                           int have_own_mac) {
  if (g_nm_hide_own_arp && have_own_mac &&
      strcmp(p->src_mac, own_mac) == 0)
    return 0;
  if (strcmp(p->src_ip, g_nm_target) == 0 ||
      strcmp(p->dst_ip, g_nm_target) == 0 ||
      strcmp(p->src_mac, g_nm_target) == 0 ||
      strcmp(p->dst_mac, g_nm_target) == 0)
    return filter_engine_packet_matches(p, g_pkt_filter);
  return 0;
}

static Font g_custom_font = {0};
static float g_ui_scale = 1.0f;

/* ========== Temel cizim yardimcilari ========== */
static void BeginScissorModeScaled(int x, int y, int width, int height) {
  BeginScissorMode((int)(x * g_ui_scale), (int)(y * g_ui_scale),
                   (int)(width * g_ui_scale), (int)(height * g_ui_scale));
}

static void DrawTextC(const char *text, int x, int y, int size, Color color) {
  if (g_custom_font.texture.id > 0) {
    DrawTextEx(g_custom_font, text, (Vector2){(float)x, (float)y}, (float)size,
               1.0f, color);
  } else {
    DrawText(text, x, y, size, color);
  }
}

static int ui_text_w(const char *text, int size) {
  if (g_custom_font.texture.id > 0) {
    Vector2 m = MeasureTextEx(g_custom_font, text, (float)size, 1.0f);
    return (int)m.x;
  }
  return MeasureText(text, size);
}

static void DrawRoundedPanel(Rectangle r, Color bg, Color border) {
  DrawRectangleRounded(r, 0.035f, 8, bg);
  DrawRectangleRoundedLinesEx(r, 0.035f, 8, 1.0f, border);
}

/* Renk alpha'sini degistir */
static Color ui_alpha(Color c, int a) {
  return (Color){c.r, c.g, c.b, (unsigned char)a};
}

/* Renkleri birlestir (vurgu icin) */
static Color ui_mix(Color a, Color b, float t) {
  if (t < 0) t = 0;
  if (t > 1) t = 1;
  return (Color){(unsigned char)(a.r * (1 - t) + b.r * t),
                 (unsigned char)(a.g * (1 - t) + b.g * t),
                 (unsigned char)(a.b * (1 - t) + b.b * t), 255};
}

/* Kalkan ikonu — brand ve bos-durum gorselleri icin */
static void draw_shield_icon(float cx, float cy, float s, Color fill,
                             Color outline) {
  Vector2 v[6] = {
      {cx, cy - 0.52f * s},
      {cx - 0.56f * s, cy - 0.30f * s},
      {cx - 0.38f * s, cy + 0.26f * s},
      {cx, cy + 0.55f * s},
      {cx + 0.38f * s, cy + 0.26f * s},
      {cx + 0.56f * s, cy - 0.30f * s},
  };
  DrawTriangleFan(v, 6, fill);
  DrawLineStrip(v, 6, outline);
  DrawLineV(v[5], v[0], outline);
}

/* Nabizli LED: pulse=1 ise dis halka nefes alir */
static void draw_led(float x, float y, float r, Color c, int pulse) {
  if (pulse) {
    float t = (float)(GetTime() * 2.0);
    float ring = 0.5f + 0.5f * sinf(t);
    DrawCircleLines((int)x, (int)y, r + 2 + ring * 4.0f, ui_alpha(c, 60));
  }
  DrawCircle((int)x, (int)y, r, c);
}

/* Renkli nokta + yaninda kisa etiket */
static void draw_dot_label(int x, int y, Color dot, const char *label,
                           int size, Color text) {
  DrawCircle(x + 3, y + size / 2, 3, dot);
  DrawTextC(label, x + 12, y, size, text);
}

/* IDS backend ASCII onem belirteci -> ekranda Turkce gosterim */
static const char *sev_tr(const char *sev) {
  if (!sev) return "";
  if (strcmp(sev, "KRITIK") == 0) return "KRİTİK";
  if (strcmp(sev, "YUKSEK") == 0) return "YÜKSEK";
  if (strcmp(sev, "DUSUK") == 0)  return "DÜŞÜK";
  return sev; /* ORTA zaten dogru */
}

/* Secilen onem derecesi -> renk (IDS alarmlari) */
static Color severity_color(const char *sev) {
  if (sev && strcmp(sev, "KRITIK") == 0) return COLOR_RED;
  if (sev && strcmp(sev, "YUKSEK") == 0) return COLOR_ORANGE;
  if (sev && strcmp(sev, "ORTA") == 0) return COLOR_YELLOW;
  return COLOR_GREEN; /* DUSUK / bilinmeyen */
}

/* CVE onem derecesi -> renk (port tarayici) */
static Color cve_severity_color(const char *sev) {
  if (sev && strcmp(sev, "CRITICAL") == 0) return COLOR_RED;
  if (sev && strcmp(sev, "HIGH") == 0) return COLOR_ORANGE;
  if (sev && strcmp(sev, "MEDIUM") == 0) return COLOR_YELLOW;
  return COLOR_GREEN;
}

/* Protokol -> satir rengi (paket listesi) */
static Color proto_color(const char *proto) {
  if (!proto) return COLOR_TEXT;
  if (strcmp(proto, "TCP") == 0) return COLOR_CYAN;
  if (strcmp(proto, "UDP") == 0) return COLOR_ACCENT2;
  if (strcmp(proto, "DNS") == 0 || strcmp(proto, "HTTP") == 0 ||
      strcmp(proto, "TLS") == 0 || strcmp(proto, "DHCP") == 0)
    return COLOR_GREEN;
  if (strcmp(proto, "ARP") == 0) return COLOR_AMBER;
  if (strcmp(proto, "ICMP") == 0) return COLOR_RED;
  return COLOR_TEXT;
}

static void draw_custom_scrollbar(float x, float y, float w, float view_h,
                                  float content_h, float *scroll) {
  if (content_h <= view_h)
    return;
  float max_scroll = content_h - view_h;
  float thumb = view_h * (view_h / content_h);
  if (thumb < 20)
    thumb = 20;

  Rectangle track = {x, y, w, view_h};
  if (CheckCollisionPointRec(GetMousePosition(), track)) {
    if (IsMouseButtonDown(MOUSE_BUTTON_LEFT)) {
      float my = GetMousePosition().y - y;
      float percent = (my - thumb / 2) / (view_h - thumb);
      if (percent < 0)
        percent = 0;
      if (percent > 1.0f)
        percent = 1.0f;
      *scroll = percent * max_scroll;
    }
  }

  float thumb_y = y + (*scroll / max_scroll) * (view_h - thumb);
  DrawRectangleRounded(track, 0.5f, 4, (Color){20, 28, 44, 60});
  DrawRectangleRounded((Rectangle){x, thumb_y, w, thumb}, 0.5f, 4,
                       COLOR_SCROLLBAR);
}

/* Panel basligi: vurgu cizgisi + baslik (tutarlı gorunum) */
static void draw_panel_title(int x, int y, const char *title, int size,
                             Color color) {
  DrawRectangle(x, y + 2, 3, size - 1, color);
  DrawTextC(title, x + 10, y, size, color);
}

/* Saydam dolgulu rozet (yazi genisligine gore) */
static void draw_badge(int x, int y, const char *text, int size, Color color) {
  int w = MeasureText(text, size) + 12;
  DrawRectangleRounded((Rectangle){(float)x, (float)y, (float)w, size + 6},
                       0.5f, 4, ui_alpha(color, 26));
  DrawRectangleRoundedLinesEx(
      (Rectangle){(float)x, (float)y, (float)w, (float)(size + 6)}, 0.5f, 4,
      1.0f, ui_alpha(color, 70));
  DrawTextC(text, x + 6, y + 3, size, color);
}

/* Forward declaration — trafik yakalama yardimcilari */
static void capture_stop_all(void);
static void capture_start_all(void);
static void capture_start_for(const char *ip);

/* Sag paneller (dashboard) */
static void draw_right_panel_logs(int rx, int ry, int rw, int rh);
static void draw_right_panel_device(int rx, int ry, int rw, int rh);
static void draw_mon_list_panel(int rx, int ry, int rw, int rh);


/* ========== Header (BEAT System HUD) ========== */
static void draw_header(int W) {
  DrawRectangle(0, 0, W, 48, COLOR_HEADER_BG);
  DrawRectangle(0, 47, W, 1, COLOR_BORDER);

  /* Ustte 2px neon gradient */
  DrawRectangleGradientH(0, 0, W, 2, COLOR_ACCENT, COLOR_ACCENT2);

  /* Tarama isigi: her ~8 sn'de saga dogru akan vurgu (HUD efekti) */
  {
    float now = (float)fmod(GetTime(), 8.0f);
    float bx = (now / 8.0f) * (W + 260) - 130;
    DrawRectangleGradientH((int)bx, 2, 130, 1,
                  ui_alpha(COLOR_ACCENT, 0), ui_alpha(COLOR_ACCENT, 110));
    DrawRectangleGradientH((int)bx + 130, 2, 130,
                  1, ui_alpha(COLOR_ACCENT, 110), ui_alpha(COLOR_ACCENT, 0));
  }

  /* Marka: kalkan ikonu + baslik */
  draw_shield_icon(30, 23, 20, ui_alpha(COLOR_ACCENT, 40), COLOR_ACCENT);
  DrawTextC("BEAT System", 46, 16, 16, COLOR_TEXT);

  /* Saga yasli durum kumesi */
  char clock[16];
  time_now_hms(clock, sizeof(clock));
  int cw = MeasureText(clock, 14);

  /* Izleme durumu + baslat/durdur butonu (Alarm Merkezi'nden tasindi) */
  int monitoring = (g_capture_all || g_capture_active_ip[0]);
  Color stc = (g_ids.running && monitoring) ? COLOR_GREEN : COLOR_TEXT_DIM;
  const char *stt = (g_ids.running && monitoring) ? "AKTİF İZLEME" : "PASIF";
  Rectangle mon_btn = {(float)(W - cw - 40 - 100), 12.0f, 100.0f, 24.0f};
  int stw = MeasureText(stt, 8);
  int stx = (int)mon_btn.x - 8 - stw; /* durum yazisinin sol kenari */
  draw_led((float)(stx - 11), 24.0f, 3.5f, stc, monitoring);
  DrawTextC(stt, stx, 19, 8, stc);
  if (GuiButton(mon_btn, monitoring ? "DURDUR" : "AĞI İZLE")) {
    if (monitoring)
      capture_stop_all();
    else
      capture_start_all();
  }
  /* Bos liste uyarisi: buton izleme baslatamaz, nedenini goster */
  if (g_mon_notice[0] && (GetTime() - g_mon_notice_ts) < 4.0)
    DrawTextC(g_mon_notice, (int)mon_btn.x, (int)mon_btn.y + 26, 8,
              COLOR_AMBER);

  /* Arayuz + IP cipi */
  if (g_scan.local_iface[0]) {
    char chip[96];
    snprintf(chip, sizeof(chip), "%s  |  %s",
             g_scan.local_iface[0] ? g_scan.local_iface : "-",
             g_scan.local_ip[0] ? g_scan.local_ip : "-");
    int ipw = MeasureText(chip, 9) + 18;
    int ipx = stx - 18 - ipw - 10; /* 18: durum LED'i icin bosluk */
    DrawRectangleRounded((Rectangle){(float)ipx, 14, (float)ipw, 20}, 0.5f, 4,
                         (Color){12, 18, 30, 255});
    DrawRectangleRoundedLinesEx(
        (Rectangle){(float)ipx, 14, (float)ipw, 20}, 0.5f, 4, 1.0f,
        ui_alpha(COLOR_ACCENT, 60));
    DrawTextC(chip, ipx + 9, 19, 9, COLOR_TEXT_SEC);
    DrawLine((ipx - 5), 12, (ipx - 5), 36,
              ui_alpha(COLOR_BORDER, 140));
  }

  DrawTextC(clock, W - cw - 14, 16, 14, COLOR_TEXT);
  draw_led((float)(W - cw - 28), 24.0f, 3.0f, COLOR_GREEN, 0);
}

/* ========== Tab Bar ========== */
static void draw_tabs(int W) {
  int y = 50;
  DrawRectangle(0, y, W, 32, (Color){7, 9, 15, 255});
  DrawRectangle(0, y + 31, W, 1, ui_alpha(COLOR_BORDER, 120));

  const char *labels[] = {"Kontrol Paneli", "Alarm Merkezi", "Araçlar"};
  int tx = 12;
  for (int i = 0; i < (int)TAB_COUNT; i++) {
    int tw = MeasureText(labels[i], 13) + 30;
    Rectangle btn = {(float)tx, (float)y + 3, (float)tw, 26};
    int hover = CheckCollisionPointRec(GetMousePosition(), btn);
    if (i == (int)g_active_tab) {
      DrawRectangleRounded(btn, 0.45f, 6, COLOR_SELECTED);
      DrawRectangle(tx, y + 25, tw, 2, COLOR_ACCENT);
      DrawTextC(labels[i], tx + 14, y + 9, 13, COLOR_TEXT);
    } else {
      if (hover)
        DrawRectangleRounded(btn, 0.45f, 6, (Color){255, 255, 255, 8});
      DrawTextC(labels[i], tx + 14, y + 9, 13,
                hover ? COLOR_TEXT_SEC : COLOR_TEXT_DIM);
    }
    if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      g_active_tab = i;
      /* Sekme degisimi aktif oturumu DURDURMAZ: pcap + IDS + (aciksa)
       * ARP spoof/MITM aynen surer; durdurma yalnizca Durdur butonunda. */
      if (i == TAB_DASHBOARD) {
        g_selected_device_ip[0] = '\0';
        g_scroll_devices = 0;
        g_selected_packet_num = -1;
      }
    }
    tx += tw + 4;
  }
}

/* ========== Stat Card ========== */
static void draw_stat_card(Rectangle r, const char *label, const char *value,
                           Color valColor, const char *sub) {
  DrawRoundedPanel(r, COLOR_SURFACE, ui_alpha(COLOR_BORDER, 140));

  /* Sol vurgu cizgisi */
  DrawRectangle(r.x + 1, r.y + 8, 2, r.height - 16, ui_alpha(valColor, 90));

  /* Ustte mini etiket + renk noktasi */
  DrawCircle(r.x + 14, r.y + 13, 2.5f, valColor);
  DrawTextC(label, r.x + 22, r.y + 7, 9, COLOR_TEXT_SEC);

  DrawTextC(value, r.x + 13, r.y + 24, 20, valColor);
  if (sub && sub[0]) {
    char s[96];
    strncpy(s, sub, sizeof(s) - 1);
    s[sizeof(s) - 1] = '\0';
    int sw = MeasureText(s, 10);
    while (sw > r.width - 22 && strlen(s) > 1) {
      s[strlen(s) - 1] = '\0';
      sw = MeasureText(s, 10);
    }
    DrawTextC(s, r.x + 13, r.y + 46, 10, COLOR_TEXT_SEC);
  }
}


/* ========== Dashboard Paneli ========== */
/* Engellenen cihaz listesini motor snapshot'u ile tazele */
static void blocklist_refresh(void) { arp_block_get_snapshot(&g_arp_block); }

/* Izleme listesi paneli: kapsam altindaki IP'ler + kaldir butonu.
 * Satira tiklamak ilgili cihazin detayini acar (detay paneli aynen
 * genislikte kalir). */
static const char *mon_list_mac_of(const char *ip) {
  for (int i = 0; i < g_scan.device_count; i++)
    if (strcmp(g_scan.devices[i].ip, ip) == 0) return g_scan.devices[i].mac;
  return NULL;
}

static void draw_mon_list_panel(int rx, int ry, int rw, int rh) {
  DrawRoundedPanel((Rectangle){rx, ry, rw, rh}, COLOR_PANEL,
                   ui_alpha(COLOR_BORDER, 140));
  draw_panel_title(rx + 10, ry + 10, "İZLEME LİSTESİ", 12, COLOR_GREEN);
  DrawTextC(mon_list_active() ? "Paket izleme bu IP'lerle sınırlı"
                              : "Boş: izleme kapalı - cihaz ekleyin",
            rx + 10, ry + 24, 8, COLOR_TEXT_DIM);
  /* Tum cihazlari listeye ekle / listeyi bosalt */
  int abw = (rw - 20 - 6) / 2;
  Rectangle mab = {rx + 10, ry + 34, abw, 22};
  Rectangle mcb = {rx + 16 + abw, ry + 34, abw, 22};
  int mah = CheckCollisionPointRec(GetMousePosition(), mab);
  DrawRectangleRounded(mab, 0.3f, 6, ui_alpha(COLOR_ACCENT, mah ? 100 : 55));
  DrawRectangleRoundedLinesEx(mab, 0.3f, 6, 1.0f, ui_alpha(COLOR_ACCENT, 190));
  DrawTextC("TÜMÜNÜ EKLE", mab.x + (abw - MeasureText("TÜMÜNÜ EKLE", 9)) / 2,
            ry + 41, 9, COLOR_TEXT);
  if (mah && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
    for (int i = 0; i < g_scan.device_count; i++) {
      const char *dip = g_scan.devices[i].ip;
      if (!dip[0] || mon_list_has(dip)) continue;
      if (mon_list_toggle(dip) < 0) break; /* liste dolu */
    }
  }
  int mch = CheckCollisionPointRec(GetMousePosition(), mcb);
  Color mcc = (g_mon_count > 0) ? COLOR_RED : COLOR_TEXT_DIM;
  DrawRectangleRounded(mcb, 0.3f, 6, ui_alpha(mcc, mch ? 70 : 16));
  DrawRectangleRoundedLinesEx(mcb, 0.3f, 6, 1.0f, ui_alpha(mcc, mch ? 220 : 50));
  DrawTextC("BOŞALT", mcb.x + (abw - MeasureText("BOŞALT", 9)) / 2, ry + 41, 9,
            g_mon_count > 0 ? COLOR_TEXT : ui_alpha(COLOR_TEXT_DIM, 150));
  if (mch && g_mon_count > 0 && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
    g_mon_count = 0;
    g_scroll_mon_list = 0;
    mon_list_sync_scope();   /* kapsam bosaldi: IDS artik hicbir sey izlemez */
    if (g_capture_all || g_capture_active_ip[0]) capture_stop_all();
  }

  DrawRectangle(rx + 6, ry + 60, rw - 12, 1, ui_alpha(COLOR_BORDER, 110));

  int item_h = 36;
  int list_top = ry + 66;
  int list_h = rh - 80;
  float max_scroll = g_mon_count * item_h - list_h;
  if (max_scroll < 0) max_scroll = 0;
  if (g_scroll_mon_list > max_scroll) g_scroll_mon_list = max_scroll;

  Rectangle area = {rx, list_top, rw - 10, list_h};
  if (CheckCollisionPointRec(GetMousePosition(), area)) {
    g_scroll_mon_list -= GetMouseWheelMove() * 30;
    if (g_scroll_mon_list < 0) g_scroll_mon_list = 0;
    if (g_scroll_mon_list > max_scroll) g_scroll_mon_list = max_scroll;
  }

  if (g_mon_count == 0) {
    DrawTextC("Liste boş. 'TÜMÜNÜ EKLE' ile hepsini ekleyin.", rx + 10,
              list_top + 8, 9, COLOR_TEXT_DIM);
    DrawTextC("Boş liste = izleme kapalı (otomatik izleme yok).", rx + 10,
              list_top + 26, 8, ui_alpha(COLOR_TEXT_DIM, 150));
    DrawTextC("İzleme yalnızca listedeki IP'lere uygulanır.",
              rx + 10, ry + rh - 14, 7, ui_alpha(COLOR_TEXT_DIM, 160));
    return;
  }

  BeginScissorModeScaled(area.x, area.y, area.width, area.height);
  for (int i = 0; i < g_mon_count; i++) {
    int iy = list_top + i * item_h - (int)g_scroll_mon_list;
    if (iy + item_h < list_top || iy > list_top + list_h) continue;
    Rectangle row = {rx + 8, iy, rw - 30, item_h - 3};
    int hov = CheckCollisionPointRec(GetMousePosition(), row);
    int selected = (strcmp(g_mon_ips[i], g_selected_device_ip) == 0);
    if (selected)
      DrawRectangleRounded(row, 0.12f, 6, COLOR_SELECTED);
    else if (hov)
      DrawRectangleRounded(row, 0.12f, 6, COLOR_PANEL_HOVER);
    if (selected)
      DrawRectangle(row.x, row.y + 5, 3, row.height - 10, COLOR_GREEN);
    DrawTextC(g_mon_ips[i], row.x + 12, iy + 4, 12, COLOR_TEXT);
    const char *mm = mon_list_mac_of(g_mon_ips[i]);
    DrawTextC(mm ? mm : "--:--:--:--:--:--", row.x + 12, iy + 21, 8,
              COLOR_TEXT_DIM);
    /* Kaldir (X): satiri secmeden listeden cikarir */
    Rectangle xb = {row.x + row.width - 26, iy + 8, 24, 20};
    int xhov = CheckCollisionPointRec(GetMousePosition(), xb);
    DrawRectangleRounded(xb, 0.3f, 4,
                         xhov ? ui_alpha(COLOR_RED, 70)
                              : ui_alpha(COLOR_RED, 16));
    DrawRectangleRoundedLinesEx(xb, 0.3f, 4, 1.0f,
                                xhov ? ui_alpha(COLOR_RED, 220)
                                     : ui_alpha(COLOR_RED, 50));
    DrawTextC("X", xb.x + (24 - MeasureText("X", 10)) / 2, iy + 11, 10,
              xhov ? COLOR_RED : ui_alpha(COLOR_RED, 150));
    if (xhov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      mon_list_remove_at(i);
      break;
    }
    if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      strncpy(g_selected_device_ip, g_mon_ips[i], MAX_IP_LEN - 1);
      g_scroll_device_detail = 0;
      g_selected_packet_num = -1;
      break;
    }
  }
  EndScissorMode();
  draw_custom_scrollbar(area.x + area.width - 6, list_top, 8, list_h,
                        g_mon_count * item_h, &g_scroll_mon_list);

  DrawTextC("İzleme yalnızca listedeki IP'lere uygulanır.",
            rx + 10, ry + rh - 14, 7, ui_alpha(COLOR_TEXT_DIM, 160));
}

static void draw_panel_dashboard(int W, int H) {
  int y0 = 86;
  char buf[64], sub[128];

  /* Ust istatistik karti: Cihaz / Gateway / Bu Cihaz */
  int cw = (W - 32) / 3;
  snprintf(buf, sizeof(buf), "%d", g_scan.total);
  snprintf(sub, sizeof(sub), "Ağ: %s",
           g_scan.network_range[0] ? g_scan.network_range : "...");
  draw_stat_card((Rectangle){12, y0, cw, 62}, "CİHAZ", buf, COLOR_ACCENT,
                 sub);

  snprintf(buf, sizeof(buf), "%s",
           g_scan.gateway_ip[0] ? g_scan.gateway_ip : "...");
  snprintf(sub, sizeof(sub), "MAC: %s",
           g_scan.gateway_mac[0] ? g_scan.gateway_mac : "-");
  draw_stat_card((Rectangle){12 + cw + 4, y0, cw, 62}, "AĞ GEÇİDİ", buf,
                 COLOR_GREEN, sub);

  snprintf(buf, sizeof(buf), "%s",
           g_scan.local_ip[0] ? g_scan.local_ip : "...");
  snprintf(sub, sizeof(sub), "%s",
           g_scan.local_iface[0] ? g_scan.local_iface : "arayüz yok");
  draw_stat_card((Rectangle){12 + (cw + 4) * 2, y0, cw, 62}, "BU CİHAZ", buf,
                 COLOR_CYAN, sub);

  /* Sol: Cihaz listesi | Sag: Detay veya Log */
  int list_w = 300;
  int mon_w = 300; /* Izleme Listesi paneli genisligi */
  int list_y = y0 + 70;
  int list_h = H - list_y - 8;

  /* Sol panel */
  DrawRoundedPanel((Rectangle){12, list_y, list_w, list_h}, COLOR_PANEL,
                   ui_alpha(COLOR_BORDER, 140));
  draw_panel_title(24, list_y + 10, "AĞDAKİ CİHAZLAR", 12, COLOR_ACCENT);
  DrawTextC("Yenileme: otonom", 24, list_y + 24, 8, COLOR_TEXT_DIM);

  /* Tarama badge */
  {
    int bx = 12 + list_w - 74;
    DrawRectangleRounded((Rectangle){(float)bx, (float)(list_y + 7), 62, 16},
                         0.5f, 4,
                         g_scan.is_scanning
                             ? ui_alpha(COLOR_AMBER, 30)
                             : ui_alpha(COLOR_GREEN, 22));
    DrawTextC(g_scan.is_scanning ? "TARANIYOR" : "HAZIR", bx + 9,
              list_y + 10, 8,
              g_scan.is_scanning ? COLOR_AMBER : COLOR_GREEN);
    DrawCircle(bx + 5, list_y + 15, 3,
               g_scan.is_scanning ? COLOR_AMBER : COLOR_GREEN);
  }

  /* Alt: Engellenen cihazlar (Agdan Kesme / ARP black-hole) paneli —
   * cihaz listesinin altindan yer ayirir; panel buyudukce liste kuculur. */
  int blk_eng = arp_block_engine_ok();
  int blk_n = g_arp_block.count;
  int blk_h = 32 + blk_n * 22;
  if (blk_h < 54) blk_h = 54;      /* baslik + en az bir bilgi satiri */
  if (blk_h > 140) blk_h = 140;    /* fazlasi ic kaydirma ile erisilir */
  int blk_top = list_y + list_h - 6 - blk_h;
  int blk_x = 16;
  int blk_w = list_w - 24;
  int dev_h = (blk_top - 6) - (list_y + 40);   /* cihaz listesi yuksekligi */
  if (dev_h < 30) dev_h = 30;

  int item_h = 40;
  int visible_items = (dev_h - 6) / item_h;
  float max_scroll = (g_scan.device_count - visible_items) * item_h;
  if (max_scroll < 0)
    max_scroll = 0;

  Rectangle list_area = {12, list_y + 40, list_w, dev_h};
  if (CheckCollisionPointRec(GetMousePosition(), list_area)) {
    g_scroll_devices -= GetMouseWheelMove() * 30;
    if (g_scroll_devices < 0)
      g_scroll_devices = 0;
    if (g_scroll_devices > max_scroll)
      g_scroll_devices = max_scroll;
  }

  BeginScissorModeScaled(12, list_y + 40, list_w, dev_h);
  for (int i = 0; i < g_scan.device_count; i++) {
    int iy = list_y + 42 + i * item_h - (int)g_scroll_devices;
    if (iy + item_h < list_y + 40 || iy > list_y + 40 + dev_h)
      continue;

    Device *d = &g_scan.devices[i];
    Rectangle item_r = {16, iy, list_w - 24, item_h - 3};
    int is_sel = (strcmp(d->ip, g_selected_device_ip) == 0);
    int hover = CheckCollisionPointRec(GetMousePosition(), item_r);
    int is_gw = (strcmp(d->ip, g_scan.gateway_ip) == 0);
    int is_local = (strcmp(d->ip, g_scan.local_ip) == 0);
    int is_blk = arp_block_is_blocked(d->ip);
    Color tagc = is_gw ? COLOR_AMBER : (is_local ? COLOR_GREEN : COLOR_TEXT_DIM);
    const char *tag =
        is_gw ? "AĞ GEÇİDİ" : (is_local ? "BU CİHAZ" : "CİHAZ");

    /* Zemin: secili / hover / engelli (kirmizi ton) */
    Color bg = is_sel ? COLOR_SELECTED
                      : (hover ? COLOR_PANEL_HOVER : (Color){0, 0, 0, 0});
    if (is_blk)
      bg = ui_mix(bg, COLOR_RED, 0.10f);
    if (is_sel || hover || is_blk)
      DrawRectangleRounded(item_r, 0.12f, 6, bg);
    if (is_sel)
      DrawRectangle(item_r.x, item_r.y + 6, 3, item_r.height - 12,
                    COLOR_ACCENT);

    DrawTextC(d->ip, item_r.x + 14, iy + 5, 12, COLOR_TEXT);
    if (is_sel)
      DrawTextC(d->ip, item_r.x + 15, iy + 6, 12, COLOR_ACCENT);
    if (is_blk)
      DrawTextC(d->ip, item_r.x + 14, iy + 5, 12, COLOR_RED);
    DrawTextC(d->mac, item_r.x + 14, iy + 21, 8, COLOR_TEXT_DIM);

    /* Hizli engelle/geri al butonu sagda; rozet IZLE'in solunda */
    int btn_x = item_r.x + item_r.width - 44;

    /* Izleme listesi ekle/ci kar butonu (izin butonunun solunda) */
    Rectangle mbtn = {btn_x - 40, iy + 8, 34, 22};
    int mon_act = mon_list_has(d->ip);
    int mhov = CheckCollisionPointRec(GetMousePosition(), mbtn);
    Color mcol = mon_act ? COLOR_GREEN : COLOR_ACCENT;
    DrawRectangleRounded(mbtn, 0.3f, 6, ui_alpha(mcol, mhov ? 100 : 55));
    DrawRectangleRoundedLinesEx(mbtn, 0.3f, 6, 1.0f, ui_alpha(mcol, 190));
    DrawTextC("İZLE", mbtn.x + (34 - ui_text_w("İZLE", 8)) / 2, iy + 15, 8,
              mon_act ? COLOR_TEXT : ui_mix(mcol, COLOR_TEXT, 0.55f));
    if (mhov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      mon_list_toggle(d->ip);
      continue;
    }

    int tagw = MeasureText(tag, 7) + 10;
    DrawRectangleRounded(
        (Rectangle){mbtn.x - tagw - 6, iy + 6, tagw, 12}, 0.5f, 4,
        ui_alpha(tagc, 18));
    DrawTextC(tag, mbtn.x - tagw, iy + 8, 7, tagc);

    int can_toggle = blk_eng && !is_gw && !is_local;
    Rectangle tbtn = {btn_x, iy + 8, 36, 22};
    int bhov = CheckCollisionPointRec(GetMousePosition(), tbtn);
    if (can_toggle) {
      Color bcol = is_blk ? COLOR_GREEN : COLOR_RED;
      DrawRectangleRounded(tbtn, 0.3f, 6, ui_alpha(bcol, bhov ? 100 : 55));
      DrawRectangleRoundedLinesEx(tbtn, 0.3f, 6, 1.0f, ui_alpha(bcol, 190));
      DrawTextC(is_blk ? "AÇ" : "KES",
                tbtn.x + (36 - MeasureText(is_blk ? "AÇ" : "KES", 8)) / 2,
                iy + 15, 8, COLOR_TEXT);
      if (bhov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        /* KES/AC — satir secimini tetikleme */
        arp_block_set(d->ip, d->mac, is_blk ? 0 : 1);
        arp_block_get_snapshot(&g_arp_block);
        continue;
      }
    } else {
      /* Ag gecidi / bu cihaz engellenemez: pasif buton */
      DrawRectangleRounded(tbtn, 0.3f, 6, (Color){255, 255, 255, 10});
      DrawTextC(is_blk ? "AÇ" : "KES",
                tbtn.x + (36 - MeasureText(is_blk ? "AÇ" : "KES", 8)) / 2,
                iy + 15, 8, ui_alpha(COLOR_TEXT_DIM, 120));
    }

    if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      if (is_sel) {
        /* Cihaz deselect — izleme Alarm Merkezi'nden yonetilir, burada durmaz */
        g_selected_device_ip[0] = '\0';
        g_selected_packet_num = -1;
      } else {
        /* Baska cihaz secildi — izleme Alarm Merkezi'nden yonetilir, burada durmaz */
        strncpy(g_selected_device_ip, d->ip, MAX_IP_LEN - 1);
        g_scroll_device_detail = 0;
        g_selected_packet_num = -1;
      }
    }
  }
  EndScissorMode();

  draw_custom_scrollbar(12 + list_w - 10, list_y + 40, 10, dev_h,
                        g_scan.device_count * item_h, &g_scroll_devices);

  /* --- Engellenen cihazlar paneli --- */
  {
    Color blk_border = blk_n > 0 ? ui_alpha(COLOR_RED, 130)
                                 : ui_alpha(COLOR_BORDER, 120);
    DrawRoundedPanel((Rectangle){blk_x, blk_top, blk_w, blk_h},
                     COLOR_SURFACE, blk_border);

    DrawTextC("ENGELLENEN CIHAZLAR", blk_x + 10, blk_top + 8, 9,
              blk_n > 0 ? COLOR_RED : COLOR_ACCENT);
    const char *mst = blk_eng ? "MOTOR AKTIF" : "MOTOR YOK";
    Color msc = blk_eng ? COLOR_GREEN : COLOR_RED;
    draw_led(blk_x + blk_w - 20, blk_top + 13, 2.0f, msc, 0);
    DrawTextC(mst, blk_x + blk_w - 20 - MeasureText(mst, 7) - 8, blk_top + 9,
              7, msc);
    DrawRectangle(blk_x + 6, blk_top + 24, blk_w - 12, 1,
                  ui_alpha(COLOR_BORDER, 110));

    int blist_top = blk_top + 30;
    int blist_h = blk_h - 32;

    if (blk_n == 0) {
      DrawTextC(blk_eng
                    ? "Engel yok. Cihaz satırındaki 'KES' ile ağdan kesin."
                    : "ARP motoru kapalı (root/cap_net_raw gerekli).",
                blk_x + 10, blist_top, 8,
                blk_eng ? COLOR_TEXT_DIM : ui_alpha(COLOR_RED, 170));
    } else {
      float max_blk = blk_n * 22 - (blist_h - 2);
      if (max_blk < 0) max_blk = 0;
      if (g_scroll_blk > max_blk)
        g_scroll_blk = max_blk;
      Rectangle blk_area = {blk_x, blist_top, blk_w - 8, blist_h};
      if (CheckCollisionPointRec(GetMousePosition(), blk_area)) {
        g_scroll_blk -= GetMouseWheelMove() * 30;
        if (g_scroll_blk < 0)
          g_scroll_blk = 0;
        if (g_scroll_blk > max_blk)
          g_scroll_blk = max_blk;
      }
      BeginScissorModeScaled(blk_x, blist_top, blk_w, blist_h);
      for (int i = 0; i < blk_n; i++) {
        ArpBlockEntry *be = &g_arp_block.entries[i];
        int by = blist_top + i * 22 - (int)g_scroll_blk;
        if (by + 22 < blist_top || by > blist_top + blist_h)
          continue;
        Rectangle brow = {blk_x + 6, by, blk_w - 22, 20};
        int bhov = CheckCollisionPointRec(GetMousePosition(), brow);
        if (bhov)
          DrawRectangleRounded(brow, 0.1f, 4, ui_alpha(COLOR_RED, 20));
        DrawTextC(be->ip, brow.x + 6, by + 2, 9, COLOR_RED);
        char bl2[96];
        snprintf(bl2, sizeof(bl2), "%s  |  %s",
                 be->mac[0] ? be->mac : "--:--:--:--:--:--",
                 be->blocked_at[0] ? be->blocked_at : "--:--:--");
        DrawTextC(bl2, brow.x + 6, by + 13, 7, COLOR_TEXT_DIM);
        Rectangle rbtn = {brow.x + brow.width - 64, by + 2, 60, 18};
        int rhov = CheckCollisionPointRec(GetMousePosition(), rbtn);
        DrawRectangleRounded(rbtn, 0.25f, 4,
                             ui_alpha(COLOR_GREEN, rhov ? 100 : 50));
        DrawRectangleRoundedLinesEx(rbtn, 0.25f, 4, 1.0f,
                                    ui_alpha(COLOR_GREEN, 160));
        DrawTextC("GERİ AL", rbtn.x + (60 - MeasureText("GERİ AL", 8)) / 2,
                  by + 5, 8, COLOR_TEXT);
        if (rhov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
          arp_block_set(be->ip, be->mac, 0);
          arp_block_get_snapshot(&g_arp_block);
        }
      }
      EndScissorMode();
      draw_custom_scrollbar(blk_x + blk_w - 10, blist_top, 10, blist_h,
                            blk_n * 22, &g_scroll_blk);
    }
  }

  /* Orta/Sag panel: Izleme Listesi her zaman gorunur kalir. Cihaz seciliyse
   * detay yalnizca Tarama Kayitlari'nin yerini alir; secili degilse
   * Izleme Listesi + Tarama Kayitlari yan yana gosterilir. */
  int rx = 12 + list_w + 8;
  int ry = list_y;
  int rh = list_h;

  /* Sağ kolonu dikey böl: üstte İzleme Listesi, altta Kamera Listesi. */
  int mon_h = rh / 2 - 4;
  draw_mon_list_panel(rx, ry, mon_w, mon_h);
  gui_camera_draw_list_panel(rx, ry + mon_h + 8, mon_w, rh - mon_h - 8);
  int lrx = rx + mon_w + 8;
  if (g_selected_device_ip[0]) {
    draw_right_panel_device(lrx, ry, W - lrx - 12, rh);
  } else {
    draw_right_panel_logs(lrx, ry, W - lrx - 12, rh);
  }
}

/* (no-op satiri silinir) */

/* --- Trafik yakalama yardimcilari (per-device capture) --- */
static void capture_stop_all(void) {
  if (arp_spoof_is_running()) arp_spoof_stop();
  full_monitor_stop();
  full_monitor_pcap_record_stop();
  /* DURDURMA PAKETLERI SILMEZ: kullanici trafigi durdurup geriye donuk
     inceleme yapabilsin. Buffer'lar Temizle butonu ile ayrıca silinir. */
  g_capture_active_ip[0] = '\0';
  g_capture_all = 0;
  g_capture_iface[0] = '\0';
  /* Paket Izleme akis kilidi pasif duruma doner, listeye yansir */
  g_nm_flow_paused = 0;
  g_nm_flow_dirty = 1;
}

/* Tum ag izleme: full_monitor + gateway ARP spoof (tum cihazlar) */
static void capture_start_all(void) {
  /* BOS liste = izleme kapsami yok: tum agi izlemeye CALISMA. Kullanici
   * once 'TUMUNU EKLE' / IZLE ile cihazlari listeye almalidir. */
  if (g_mon_count == 0) {
    mon_notice_set("İzleme listesi boş: önce cihaz ekleyin (TÜMÜNÜ EKLE)");
    return;
  }
  capture_stop_all();
  full_monitor_clear();
  g_capture_all = 1;
  /* Paket yakalama, trafigin ve ARP spoof'un actigi arayuzde olmali
     (enp6s0); aksi halde otomatik secim wlan0'a takilir ve hic paket
     gorunmez. */
  strncpy(g_capture_iface, g_scan.local_iface, MAX_IFACE_LEN - 1);
  full_monitor_start(g_scan.local_iface[0] ? g_scan.local_iface : NULL);
  arp_spoof_sync_partners(NULL, 0, NULL, NULL, NULL);
  arp_spoof_set_full_mitm(0);
  if (g_scan.gateway_ip[0] && g_scan.local_iface[0]) {
    arp_spoof_start_all(g_scan.gateway_ip, g_scan.local_iface);
  }
}

static void capture_start_for(const char *ip) {
  /* Once varsa eskisini durdur */
  capture_stop_all();

  /* NOT: buffer temizlenmez. Cihaz listesinde tiklama/yeniden secim
   * sirasinda liste bosalmasin; gecmis gercek paketler korunur ve
   * gorunum hedef filtresiyle cizilir. Tam silme yalnizca "Temizle"
   * butonu ile yapilir. */

  /* Hedef IP'yi kaydet */
  strncpy(g_capture_active_ip, ip, MAX_IP_LEN - 1);

  /* pcap'i baslat — spoof/trafik arayuzuyle ayni NIC (default route) */
  strncpy(g_capture_iface, g_scan.local_iface, MAX_IFACE_LEN - 1);
  full_monitor_start(g_scan.local_iface[0] ? g_scan.local_iface : NULL);

  /* Yerel cihaz degilse ARP spoof baslat.
   * TAM MITM: hedefin LAN'daki diger TUM cihazlarla olan trafigi de
   * bizden gecsin (hedef <-> partner 2 yonlu zehirleme). Boylece hedef
   * TV'ye, laptop'a vs. ne gonderiyorsa paketleri gorunur olur. */
  int is_local = (strcmp(ip, g_scan.local_ip) == 0);
  if (!is_local && g_scan.gateway_ip[0] && g_scan.local_iface[0]) {
    arp_spoof_sync_partners(g_scan.devices, g_scan.device_count,
                            ip, g_scan.local_ip, g_scan.gateway_ip);
    arp_spoof_set_full_mitm(1);
    arp_spoof_start(ip, g_scan.gateway_ip, g_scan.local_iface);
  } else {
    arp_spoof_sync_partners(NULL, 0, NULL, NULL, NULL);
    arp_spoof_set_full_mitm(0);
  }
}

/* Sag panel: Tarama loglari (cihaz secili degilken) */
static void draw_right_panel_logs(int rx, int ry, int rw, int rh) {
  DrawRoundedPanel((Rectangle){rx, ry, rw, rh}, COLOR_PANEL,
                   ui_alpha(COLOR_BORDER, 140));
  draw_panel_title(rx + 12, ry + 10, "TARAMA KAYITLARI", 12, COLOR_GREEN);

  char sc[32];
  snprintf(sc, sizeof(sc), "Oturum #%d", g_scan.scan_count);
  int scw = MeasureText(sc, 9);
  DrawTextC(sc, rx + rw - scw - 14, ry + 12, 9, COLOR_TEXT_DIM);

  /* Terminal gorunumu: basligin altinda terminal zemini */
  DrawRectangle(rx + 10, ry + 32, rw - 20, rh - 42, COLOR_TERMINAL_BG);
  DrawRectangleLinesEx((Rectangle){rx + 10, ry + 32, rw - 20, rh - 42}, 1,
                       ui_alpha(COLOR_BORDER, 120));

  /* Terminal usti cubugu */
  DrawRectangle(rx + 10, ry + 32, rw - 20, 16, (Color){10, 14, 22, 255});
  DrawCircle(rx + 21, ry + 40, 3, COLOR_RED);
  DrawCircle(rx + 30, ry + 40, 3, COLOR_AMBER);
  DrawCircle(rx + 39, ry + 40, 3, COLOR_GREEN);
  DrawTextC("scanner.log", rx + 50, ry + 35, 8, COLOR_TEXT_DIM);

  BeginScissorModeScaled(rx + 12, ry + 50, rw - 24, rh - 62);
  int log_y = ry + 52;
  for (int i = 0; i < g_scanlog.count; i++) {
    int idx =
        (g_scanlog.write_idx - g_scanlog.count + i + MAX_SCAN_LOG_LINES * 2) %
        MAX_SCAN_LOG_LINES;
    if (idx < 0 || idx >= MAX_SCAN_LOG_LINES)
      continue;
    const char *ln = g_scanlog.lines[idx];
    Color lc = str_contains(ln, "hata")   ? COLOR_RED
               : str_contains(ln, "bulundu") ? COLOR_GREEN
                                             : (Color){120, 200, 160, 255};
    char lbuf[268];
    snprintf(lbuf, sizeof(lbuf), "> %s", ln);
    DrawTextC(lbuf, rx + 14, log_y + i * 14, 10, lc);
  }
  EndScissorMode();
}

/* Sag panel: Secili cihaz bilgisi */
static void draw_right_panel_device(int rx, int ry, int rw, int rh) {
  DrawRoundedPanel((Rectangle){rx, ry, rw, rh}, COLOR_PANEL,
                   ui_alpha(COLOR_BORDER, 140));

  /* Baslik */
  char tbuf[128];
  snprintf(tbuf, sizeof(tbuf), "CİHAZ DETAYI");
  draw_panel_title(rx + 12, ry + 10, tbuf, 12, COLOR_CYAN);
  DrawTextC(g_selected_device_ip, rx + 110, ry + 11, 10, COLOR_TEXT_SEC);

  /* Kapat (X) butonu */
  Rectangle xbtn = {rx + rw - 28, ry + 6, 20, 20};
  int xhov = CheckCollisionPointRec(GetMousePosition(), xbtn);
  if (xhov)
    DrawRectangleRounded(xbtn, 0.3f, 4, (Color){255, 255, 255, 14});
  DrawTextC("X", rx + rw - 22, ry + 9, 12, xhov ? COLOR_RED : COLOR_TEXT_DIM);
  if (xhov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
    g_selected_device_ip[0] = '\0';
    return;
  }

  DrawRectangle(rx + 10, ry + 30, rw - 20, 1, ui_alpha(COLOR_BORDER, 160));

  /* Cihaz bilgilerini bul */
  Device *dev = NULL;
  for (int i = 0; i < g_scan.device_count; i++) {
    if (strcmp(g_scan.devices[i].ip, g_selected_device_ip) == 0) {
      dev = &g_scan.devices[i];
      break;
    }
  }

  int cy = ry + 44;
  if (dev) {
    /* Kimlik ozet karti */
    DrawRoundedPanel((Rectangle){rx + 12, cy, rw - 24, 64}, COLOR_SURFACE,
                     ui_alpha(COLOR_BORDER, 120));
    draw_shield_icon(rx + 38, cy + 32, 22, ui_alpha(COLOR_CYAN, 26),
                     COLOR_CYAN);

    int is_gw = (strcmp(dev->ip, g_scan.gateway_ip) == 0);
    int is_local = (strcmp(dev->ip, g_scan.local_ip) == 0);
    Color rolec = is_gw ? COLOR_AMBER : (is_local ? COLOR_GREEN : COLOR_TEXT_SEC);
    const char *role = is_gw ? "AĞ GEÇİDİ (ROUTER)"
                       : (is_local ? "BU CİHAZ (YEREL)" : "AĞ İSTEMCİSİ");
    DrawTextC(role, rx + 58, cy + 10, 10, rolec);
    DrawTextC(dev->ip, rx + 58, cy + 26, 17, COLOR_TEXT);
    DrawTextC(dev->mac, rx + 58, cy + 46, 9, COLOR_TEXT_DIM);
    cy += 76;

    /* Ozellikler tablosu */
    DrawTextC("ÖZELLİKLER", rx + 16, cy, 9, COLOR_TEXT_DIM);
    cy += 18;

    typedef struct { const char *label; const char *value; Color c; } DvRow;
    DvRow rows[10];
    int rc = 0;

    rows[rc++] = (DvRow){"IP Adresi", dev->ip[0] ? dev->ip : "-", COLOR_TEXT};
    rows[rc++] = (DvRow){"MAC Adresi", dev->mac[0] ? dev->mac : "-", COLOR_TEXT};
    if (dev->hostname[0])
      rows[rc++] = (DvRow){"Hostname", dev->hostname, COLOR_TEXT};
    if (dev->vendor[0])
      rows[rc++] = (DvRow){"Üretici", dev->vendor, COLOR_CYAN};

    char last_seen[64] = "-";
    if (dev->last_seen > 0) {
      struct tm tmv;
      time_t lt = dev->last_seen;
      localtime_r(&lt, &tmv);
      strftime(last_seen, sizeof(last_seen), "%H:%M:%S", &tmv);
    }
    char tmpbuf[160];
    snprintf(tmpbuf, sizeof(tmpbuf), "Son görülme: %s", last_seen);
    rows[rc++] = (DvRow){"Durum", tmpbuf, COLOR_GREEN};

    for (int i = 0; i < rc; i++) {
      DrawTextC(rows[i].label, rx + 18, cy, 10, COLOR_TEXT_DIM);
      /* Deger sutunu, uzun degerler kisaltilir */
      char vbuf[200];
      strncpy(vbuf, rows[i].value, sizeof(vbuf) - 1);
      vbuf[sizeof(vbuf) - 1] = '\0';
      int maxw = rw - 180;
      if (maxw > 10) {
        int vw = MeasureText(vbuf, 10);
        while (vw > maxw && strlen(vbuf) > 2) {
          vbuf[strlen(vbuf) - 1] = '\0';
          vw = MeasureText(vbuf, 10);
        }
      }
      DrawTextC(vbuf, rx + 160, cy, 10, rows[i].c);
      cy += 17;
    }
    cy += 6;

    /* Guvenlik bayraklari */
    DrawRectangle(rx + 10, cy, rw - 20, 1, ui_alpha(COLOR_BORDER, 120));
    cy += 12;
    DrawTextC("GÜVENLİK BAYRAKLARI", rx + 16, cy, 9, COLOR_TEXT_DIM);
    cy += 20;

    int fx = rx + 16;
    if (is_gw) {
      draw_badge(fx, cy, "Ağ geçidi", 8, COLOR_AMBER);
      fx += MeasureText("Ağ geçidi", 8) + 26;
    }
    if (is_local) {
      draw_badge(fx, cy, "Yerel cihaz", 8, COLOR_GREEN);
      fx += MeasureText("Yerel cihaz", 8) + 26;
    }
    cy += 26;

    /* --- Izleme Listesi (paket izleme kapsami) --- */
    DrawRectangle(rx + 10, cy, rw - 20, 1, ui_alpha(COLOR_BORDER, 120));
    cy += 12;
    DrawTextC("İZLEME LİSTESİ", rx + 16, cy, 9, COLOR_TEXT_DIM);
    cy += 20;
    int mon_in = mon_list_has(dev->ip);
    Rectangle monb = {rx + 16, cy, 200, 26};
    const char *mlab = mon_in ? "Listeden Çıkar" : "İzleme Listesine Ekle";
    int mnhov = CheckCollisionPointRec(GetMousePosition(), monb);
    Color mncol = mon_in ? COLOR_RED : COLOR_GREEN;
    DrawRectangleRounded(monb, 0.3f, 6, ui_alpha(mncol, mnhov ? 100 : 55));
    DrawRectangleRoundedLinesEx(monb, 0.3f, 6, 1.0f, ui_alpha(mncol, 200));
    DrawTextC(mlab, rx + 16 + (200 - MeasureText(mlab, 10)) / 2, cy + 8, 10,
              COLOR_TEXT);
    if (mnhov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      mon_list_toggle(dev->ip);
    }
    DrawTextC(mon_in ? "Paket izleme, ARP spoof ve IDS uyarıları bu cihaz için AÇIK."
                     : "Listede değil: bu cihaz için paket izleme/uyarı gösterilmez.",
              rx + 16, cy + 31, 8, COLOR_TEXT_DIM);

    cy += 47;

    /* --- Agdan Kes (ARP black-hole) --- */
    DrawRectangle(rx + 10, cy, rw - 20, 1, ui_alpha(COLOR_BORDER, 120));
    cy += 12;
    DrawTextC("AĞDAN KESME", rx + 16, cy, 9, COLOR_TEXT_DIM);
    cy += 20;

    int blk_act = arp_block_is_blocked(dev->ip);
    int blk_off = !g_arp_block.engine_ok || is_gw || is_local;
    Rectangle abtn = {rx + 16, cy, 200, 26};
    const char *alab = blk_act ? "Ağı Geri Ver" : "Ağdan Kes";
    if (!blk_off) {
      int abhov = CheckCollisionPointRec(GetMousePosition(), abtn);
      Color abcol = blk_act ? COLOR_GREEN : COLOR_RED;
      DrawRectangleRounded(abtn, 0.3f, 6, ui_alpha(abcol, abhov ? 100 : 55));
      DrawRectangleRoundedLinesEx(abtn, 0.3f, 6, 1.0f, ui_alpha(abcol, 200));
      DrawTextC(alab, rx + 16 + (200 - MeasureText(alab, 10)) / 2, cy + 8, 10,
                COLOR_TEXT);
      if (abhov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        arp_block_set(dev->ip, dev->mac, blk_act ? 0 : 1);
        arp_block_get_snapshot(&g_arp_block);
      }
    } else {
      DrawRectangleRounded(abtn, 0.3f, 6, (Color){255, 255, 255, 10});
      DrawRectangleRoundedLinesEx(abtn, 0.3f, 6, 1.0f,
                                  ui_alpha(COLOR_TEXT_DIM, 60));
      DrawTextC(alab, rx + 16 + (200 - MeasureText(alab, 10)) / 2, cy + 8, 10,
                ui_alpha(COLOR_TEXT_DIM, 130));
    }
    const char *ahint;
    if (is_gw || is_local)
      ahint = "Ağ geçidi ve bu cihaz engellenemez.";
    else if (!g_arp_block.engine_ok)
      ahint = "ARP motoru kapalı (root/cap_net_raw gerekli).";
    else if (blk_act)
      ahint = "Cihaz ağdan kesildi. Geri vermek için butona basın.";
    else
      ahint = "Cihazın ağ erişimini anında keser (ARP black-hole).";
    DrawTextC(ahint, rx + 16, cy + 31, 8, COLOR_TEXT_DIM);
  } else {
    DrawTextC("Cihaz bilgisi bulunamadı.", rx + 16, cy, 11, COLOR_TEXT_DIM);
  }
}



/* ========== Alarm Merkezi (IDS) ========== */
static void draw_panel_security(int W, int H) {
  int y0 = 86;
  char buf[256];

  /* Severity sayaclari (IDS snapshot uzerinden) */
  int cnt_kritik = 0, cnt_yuksek = 0, cnt_orta = 0, cnt_dusuk = 0;
  for (int i = 0; i < g_ids_alert_view_count; i++) {
    IdsGuiAlert *va = &g_ids_alerts_snapshot[g_ids_alert_map[i]];
    if (strcmp(va->severity, "KRITIK") == 0) cnt_kritik++;
    else if (strcmp(va->severity, "YUKSEK") == 0) cnt_yuksek++;
    else if (strcmp(va->severity, "ORTA") == 0) cnt_orta++;
    else cnt_dusuk++;
  }

  /* Stat kartlari */
  int cw = (W - 40) / 4;
  struct { const char *label; int val; Color color; } cats[] = {
    {"KRİTİK", cnt_kritik, COLOR_RED},
    {"YÜKSEK", cnt_yuksek, COLOR_ORANGE},
    {"ORTA",   cnt_orta,   COLOR_YELLOW},
    {"DÜŞÜK",  cnt_dusuk,  COLOR_GREEN},
  };
  char nbuf[16];
  for (int i = 0; i < 4; i++) {
    snprintf(nbuf, sizeof(nbuf), "%d", cats[i].val);
    draw_stat_card((Rectangle){12 + i * (cw + 4), y0, cw, 62},
                   cats[i].label, nbuf, cats[i].color,
                   i == 0 ? "Anında müdahale gerekli"
                          : (i == 1 ? "Öncelikli inceleme"
                                    : (i == 2 ? "İzleme önerilir"
                                              : "Bilgilendirme")));
  }

  int py = y0 + 70;

  /* IDS durum paneli */
  DrawRoundedPanel((Rectangle){12, py, W - 24, 36}, COLOR_SURFACE,
                   ui_alpha(COLOR_BORDER, 160));
  draw_led(22, py + 18, 4, COLOR_ACCENT, 0);

  snprintf(buf, sizeof(buf), "Kural: %d", g_ids.rule_count);
  DrawTextC(buf, 36, py + 13, 10, COLOR_TEXT_SEC);
  snprintf(buf, sizeof(buf), "Paket: %lu",
           (unsigned long)g_ids.total_pkts_processed);
  DrawTextC(buf, 136, py + 13, 10, COLOR_TEXT_SEC);
  snprintf(buf, sizeof(buf), "Akış: %d", g_ids.active_trackers);
  DrawTextC(buf, 236, py + 13, 10, COLOR_TEXT_SEC);
  snprintf(buf, sizeof(buf), "Toplam Uyarı: %lu",
           (unsigned long)g_ids.total_alerts);
  DrawTextC(buf, 336, py + 13, 10, COLOR_TEXT_SEC);

  /* Izleme gostergesi + baslat/durdur butonu sag ust header'a tasindi
   * (draw_header): her sekmeden erisilebilir. */

  py += 42;

  /* Alarm listesi paneli */
  DrawRoundedPanel((Rectangle){12, py, W - 24, H - py - 8},
                   COLOR_PANEL, ui_alpha(COLOR_BORDER, 140));

  /* Panel basligi + onem derecesi legendi */
  snprintf(buf, sizeof(buf), "TEHDİT ALARMLARI (%d)", g_ids_alert_view_count);
  draw_panel_title(24, py + 10, buf, 12, COLOR_RED);

  /* Legend (basligin saginda) */
  {
    const char *sevs[] = {"KRİTİK", "YÜKSEK", "ORTA", "DÜŞÜK"};
    Color scs[] = {COLOR_RED, COLOR_ORANGE, COLOR_YELLOW,
                   COLOR_GREEN};
    char hbuf[80];
    snprintf(hbuf, sizeof(hbuf), "TEHDİT ALARMLARI (%d)", g_ids_alert_view_count);
    int lxx = 24 + MeasureText(hbuf, 12) + 24;
    for (int li = 0; li < 4; li++) {
      int lw = MeasureText(sevs[li], 7) + 12;
      DrawCircle(lxx + 4, py + 16, 3, scs[li]);
      DrawTextC(sevs[li], lxx + 12, py + 11, 7, scs[li]);
      lxx += lw + 8;
    }
  }

  /* Onem derecesi filtresi (analist triyaji): TUMU + 4 seviye */
  {
    const char *flabels[] = {"TÜMÜ", "KRİTİK", "YÜKSEK", "ORTA", "DÜŞÜK"};
    int fvals[] = {-1, 0, 1, 2, 3};
    Color fcolors[] = {COLOR_ACCENT, COLOR_RED, COLOR_ORANGE,
                       COLOR_YELLOW, COLOR_GREEN};
    int fw = 56, fgap = 4;
    int fx = W - 110 - 12 - (5 * fw + 4 * fgap);
    for (int fi = 0; fi < 5; fi++) {
      Rectangle fr = {fx + fi * (fw + fgap), py + 6, fw, 20};
      int sel = (g_ids_sev_filter == fvals[fi]);
      int hov = CheckCollisionPointRec(GetMousePosition(), fr);
      Color fc = fcolors[fi];
      DrawRectangleRounded(fr, 0.35f, 6,
                           sel ? ui_alpha(fc, 60)
                               : (hov ? ui_alpha(fc, 26)
                                      : ui_alpha(COLOR_SURFACE2, 200)));
      DrawRectangleRoundedLinesEx(fr, 0.35f, 6, 1.0f,
                                  sel ? ui_alpha(fc, 200)
                                      : ui_alpha(fc, 70));
      int tw = MeasureText(flabels[fi], 8);
      DrawTextC(flabels[fi], (int)(fr.x + (fw - tw) / 2), py + 12, 8,
                sel ? fc : ui_mix(fc, COLOR_TEXT, 0.35f));
      if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT) && hov) {
        g_ids_sev_filter = (g_ids_sev_filter == fvals[fi]) ? -1 : fvals[fi];
        g_scroll_alerts = 0;
        ids_rebuild_alert_view();
      }
    }
  }

  /* Temizle butonu */
  Rectangle clr_btn = {W - 110, py + 6, 80, 20};
  if (GuiButton(clr_btn, "TEMİZLE")) {
    ids_clear_alerts();
    g_ids_alert_count =
        ids_get_alerts_snapshot(g_ids_alerts_snapshot, IDS_MAX_GUI_ALERTS);
    ids_rebuild_alert_view();
  }

  if (g_ids_alert_view_count == 0) {
    int cx = W / 2;
    int cy = py + (H - py) / 2;
    draw_shield_icon((float)cx, (float)cy - 10, 34,
                     ui_alpha(COLOR_GREEN, 24), COLOR_GREEN);
    DrawTextC("Aktif tehdit alarmı yok.", cx - 75, cy + 26, 13, COLOR_GREEN);
    if (!g_ids.running)
      DrawTextC("IDS pasif — 'Ağı İzle' ile ağ trafiğini analiz edin.",
                cx - 190, cy + 48, 10, COLOR_TEXT_DIM);
    return;
  }

  int item_h = 74;
  Rectangle area = {12, py + 30, W - 24, H - py - 42};
  if (CheckCollisionPointRec(GetMousePosition(), area)) {
    g_scroll_alerts -= GetMouseWheelMove() * 40;
    if (g_scroll_alerts < 0) g_scroll_alerts = 0;
    float mx = (g_ids_alert_view_count * item_h) - area.height;
    if (mx < 0) mx = 0;
    if (g_scroll_alerts > mx) g_scroll_alerts = mx;
  }

  BeginScissorModeScaled(area.x, area.y, area.width, area.height);
  int removed_idx = -1;
  for (int i = g_ids_alert_view_count - 1; i >= 0; i--) {
    int draw_idx = g_ids_alert_view_count - 1 - i;
    int iy = area.y + draw_idx * item_h - (int)g_scroll_alerts;
    if (iy + item_h < area.y || iy > area.y + area.height) continue;

    IdsGuiAlert *al = &g_ids_alerts_snapshot[g_ids_alert_map[i]];
    /* Scrollbar icin sagdan 32px bosluk: satirlar ezilmiyor */
    Rectangle ir = {area.x + 4, iy, area.width - 32, item_h - 4};

    /* Arka plan rengi severity'ye gore */
    Color sc = severity_color(al->severity);
    Color bg = strcmp(al->severity, "KRITIK") == 0
                   ? (Color){26, 10, 10, 255}
                   : strcmp(al->severity, "YUKSEK") == 0
                         ? (Color){30, 16, 6, 255}
                         : strcmp(al->severity, "ORTA") == 0
                               ? (Color){28, 25, 6, 255}
                               : COLOR_SURFACE;
    DrawRectangleRounded(ir, 0.08f, 6, bg);
    DrawRectangleRoundedLinesEx(ir, 0.08f, 6, 1.0f, ui_alpha(sc, 60));

    /* Sol severity bari */
    DrawRectangleRounded((Rectangle){ir.x, ir.y + 4, 3, ir.height - 8}, 0.3f,
                         3, sc);

    /* Severity badge */
    int slw = MeasureText(sev_tr(al->severity), 8) + 12;
    DrawRectangleRounded((Rectangle){ir.x + 10, ir.y + 6, slw, 14}, 0.5f, 4,
                         ui_alpha(sc, 40));
    DrawRectangleRoundedLinesEx(
        (Rectangle){ir.x + 10, ir.y + 6, slw, 14}, 0.5f, 4, 1.0f,
        ui_alpha(sc, 120));
    DrawTextC(sev_tr(al->severity), ir.x + 16, ir.y + 8, 8, sc);

    /* Skor badge */
    snprintf(buf, sizeof(buf), "%.0f%% risk skoru", al->score * 100);
    int skw = MeasureText(buf, 8) + 10;
    DrawRectangleRounded(
        (Rectangle){ir.x + 12 + slw + 6, ir.y + 6, skw, 14}, 0.5f, 4,
        ui_alpha(sc, 18));
    DrawTextC(buf, ir.x + 17 + slw + 6, ir.y + 8, 8,
              ui_mix(sc, COLOR_TEXT, 0.25f));

    /* Zaman (skor badge'in hemen saginda) */
    DrawTextC(al->timestamp, ir.x + 12 + slw + 6 + skw + 8, ir.y + 9, 8,
              COLOR_TEXT_SEC);

    /* Imza adi */
    DrawTextC(al->sig_name, ir.x + 14, ir.y + 25, 12, COLOR_TEXT);

    /* Yon: port-tetiklemeli kurallarda (Meterpreter vb.) port sahibi
       saldirgandir; motor port_owner_attacker ile isaretler. */
    int ly = ir.y + 43;
    const char *a_ip = al->port_owner_attacker ? al->dst_ip : al->src_ip;
    uint16_t a_port = al->port_owner_attacker ? al->dst_port : al->src_port;
    snprintf(buf, sizeof(buf), "%s:%d", a_ip, a_port);
    DrawTextC(buf, ir.x + 14, ly, 9, COLOR_TEXT);
    int ax = ir.x + 14 + MeasureText(buf, 9) + 8;
    DrawTextC("->", ax, ly, 9, COLOR_TEXT_DIM);
    int hx = ax + MeasureText("->", 9) + 8;
    const char *v_ip = al->port_owner_attacker ? al->src_ip : al->dst_ip;
    uint16_t v_port = al->port_owner_attacker ? al->src_port : al->dst_port;
    snprintf(buf, sizeof(buf), "%s:%d", v_ip, v_port);
    DrawTextC(buf, hx, ly, 9, COLOR_TEXT_DIM);

    /* Aciklama (kisaltilmis) */
    char dshort[100];
    strncpy(dshort, al->description, 99);
    dshort[99] = '\0';
    DrawTextC(dshort, ir.x + 14, ir.y + 57, 8, COLOR_TEXT_DIM);

    /* Satir bazli silme (X) butonu */
    Rectangle del_btn = {ir.x + ir.width - 20, ir.y + 26, 18, 18};
    int del_hover = CheckCollisionPointRec(GetMousePosition(), del_btn);
    DrawRectangleRounded(del_btn, 0.3f, 4,
                         del_hover ? ui_alpha(COLOR_RED, 70)
                                   : ui_alpha(COLOR_RED, 16));
    DrawRectangleRoundedLinesEx(del_btn, 0.3f, 4, 1.0f,
                                del_hover ? ui_alpha(COLOR_RED, 220)
                                          : ui_alpha(COLOR_RED, 50));
    Color xc = del_hover ? COLOR_RED : ui_mix(COLOR_RED, COLOR_TEXT, 0.35f);
    DrawLine((int)del_btn.x + 5, (int)del_btn.y + 5, (int)del_btn.x + 13,
             (int)del_btn.y + 13, xc);
    DrawLine((int)del_btn.x + 13, (int)del_btn.y + 5, (int)del_btn.x + 5,
             (int)del_btn.y + 13, xc);
    if (del_hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
      removed_idx = i;
      break;
    }
  }
  EndScissorMode();

  /* Tek silme sonrasi snapshot'i yenile ve scroll'u sinirla */
  if (removed_idx >= 0) {
    ids_remove_alert(g_ids_alert_map[removed_idx]);
    g_ids_alert_count =
        ids_get_alerts_snapshot(g_ids_alerts_snapshot, IDS_MAX_GUI_ALERTS);
    ids_rebuild_alert_view();
    float mx = (g_ids_alert_view_count * item_h) - area.height;
    if (mx < 0) mx = 0;
    if (g_scroll_alerts > mx) g_scroll_alerts = mx;
  }

  draw_custom_scrollbar(area.x + area.width - 10, area.y, 10, area.height,
                        g_ids_alert_view_count * item_h, &g_scroll_alerts);
}



/* ========== Araclar Paneli ========== */
static void draw_panel_tools(int W, int H) {
  int y0 = 86;

  /* --- Alt sekmeler (segment kontrol) --- */
  const char *stabs[] = {"Paket İzleme", "Site Karartma", "Port Tarayıcı", "Kameralar"};
  Color sclr[] = {COLOR_CYAN, COLOR_RED, COLOR_ACCENT2, COLOR_GREEN};
  int stx = 16;
  for (int i = 0; i < 4; i++) {
    int sw = MeasureText(stabs[i], 12) + 30;
    Rectangle sb = {(float)stx, (float)y0, (float)sw, 24};
    int sh = CheckCollisionPointRec(GetMousePosition(), sb);
    if (i == g_tools_subtab) {
      DrawRectangleRounded(sb, 0.45f, 4, COLOR_SELECTED);
      DrawRectangleRoundedLinesEx(sb, 0.45f, 4, 1.0f, ui_alpha(sclr[i], 150));
      DrawTextC(stabs[i], sb.x + 14, sb.y + 6, 12, COLOR_TEXT);
      DrawRectangle((int)sb.x + 8, (int)sb.y + 22, sw - 16, 2, sclr[i]);
    } else {
      if (sh)
        DrawRectangleRounded(sb, 0.45f, 4, (Color){255, 255, 255, 8});
      DrawTextC(stabs[i], sb.x + 14, sb.y + 6, 12,
                sh ? COLOR_TEXT_SEC : COLOR_TEXT_DIM);
    }
    if (sh && IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
      g_tools_subtab = i;
    stx += sw + 6;
  }

  int py = y0 + 34;
  int panel_h = H - py - 12;
  char buf[256];

  if (g_tools_subtab == 0) {
    /* === Paket Izleme (Network Monitor) === */
    int ctrl_w = 260;
    int result_w = W - 24 - ctrl_w - 8;

    /* --- Sol panel: Kontroller --- */
    DrawRoundedPanel((Rectangle){12, py, ctrl_w, panel_h}, COLOR_PANEL,
                     ui_alpha(COLOR_BORDER, 150));
    draw_panel_title(18, py + 8, "Paket İzleme", 13, COLOR_ACCENT);

    int capture_for_this =
        (g_capture_all ||
         (g_capture_active_ip[0] && g_nm_target[0] &&
          strcmp(g_capture_active_ip, g_nm_target) == 0));

    /* Paket listesi gosterim karari: izleme DURDURULDUKTAN sonra da
       (IP secimi degismedigi surece) buffer'daki paketler gorunsun. */
    int show_packets = (g_capture_all || g_nm_target[0]);

    int cy = py + 44;

    /* --- Mod gostergesi (pcap / procfs / kapali) --- */
    {
      int mode = full_monitor_get_mode();
      const char *mstr = (mode == 2) ? "PCAP" : (mode == 1) ? "PROCFS" : "KAPALI";
      Color mc = (mode == 2) ? COLOR_GREEN
                : (mode == 1) ? COLOR_AMBER
                : (Color){96, 104, 128, 255};
      draw_led(30, cy + 6, 4, mc, mode != 0);
      DrawTextC("Mod:", 40, cy + 1, 9, COLOR_TEXT_DIM);
      DrawTextC(mstr, 40 + MeasureText("Mod:", 9) + 8, cy + 1, 9, mc);
      char ownm[MAX_MAC_LEN];
      if (full_monitor_own_mac(ownm, sizeof(ownm)) == 0) {
        DrawTextC(ownm, ctrl_w - MeasureText(ownm, 7) - 24, cy + 3, 7,
                  COLOR_TEXT_DIM);
      }
      cy += 18;
    }

    /* --- Hedef IP secimi (scrollable liste) --- */
    DrawTextC("Hedef:", 24, cy, 10, COLOR_TEXT_SEC);
    if (g_nm_target[0]) {
      int chip_w = 6 + MeasureText(g_nm_target, 10) + 12;
      DrawRectangleRounded((Rectangle){64, cy - 2, chip_w, 15}, 0.4f, 4,
                           COLOR_SELECTED);
      DrawRectangleRoundedLinesEx((Rectangle){64, cy - 2, chip_w, 15}, 0.4f,
                                  4, 1.0f, ui_alpha(COLOR_ACCENT, 80));
      DrawTextC(g_nm_target, 70, cy, 10, COLOR_ACCENT);
    }
    cy += 17;

    int ip_list_h = 100;
    Rectangle ip_area = {20, cy, ctrl_w - 28, ip_list_h};
    DrawRectangleRounded(ip_area, 0.04f, 4, COLOR_SURFACE);
    DrawRectangleRoundedLinesEx(ip_area, 0.04f, 4, 1.0f,
                                ui_alpha(COLOR_BORDER, 90));
    int item_h = 20;
    int ip_rows = g_mon_count; /* yalniz izleme listesi; "Tüm Ağ" satiri kaldirildi */
    float ip_max_scroll = ip_rows * item_h - ip_list_h;
    if (ip_max_scroll < 0)
      ip_max_scroll = 0;
    if (CheckCollisionPointRec(GetMousePosition(), ip_area)) {
      g_scroll_nm_devices -= GetMouseWheelMove() * 20;
      if (g_scroll_nm_devices < 0)
        g_scroll_nm_devices = 0;
      if (g_scroll_nm_devices > ip_max_scroll)
        g_scroll_nm_devices = ip_max_scroll;
    }
    BeginScissorModeScaled(ip_area.x, ip_area.y, ip_area.width, ip_area.height);
    /* "Tüm Ağ" satiri kaldirildi: liste yalnizca izleme listesindeki
     * cihazlari gosterir. "AĞI İZLE" (spoof) yalnizca arka plan
     * yakalamayi yonetir; paket listesi IP secilinceye kadar bos durur. */
    for (int i = 0; i < g_mon_count; i++) {
      int iy = cy + i * item_h - (int)g_scroll_nm_devices;
      if (iy + item_h < cy || iy > cy + ip_list_h)
        continue;
      Rectangle db = {22, iy + 1, ctrl_w - 44, item_h - 2};
      int sel = (strcmp(g_nm_target, g_mon_ips[i]) == 0);
      int hov = CheckCollisionPointRec(GetMousePosition(), db);
      if (sel)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_SELECTED);
      else if (hov)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_PANEL_HOVER);
      if (sel)
        DrawRectangle(db.x, db.y + 3, 3, db.height - 6, COLOR_ACCENT);
      DrawTextC(g_mon_ips[i], db.x + 10, db.y + 4, 10,
                sel ? COLOR_ACCENT : COLOR_TEXT);
      if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        /* Hedef degisti: izleme SURUYOR, yalnizca gorunum filtresi degisir */
        strncpy(g_nm_target, g_mon_ips[i], MAX_IP_LEN - 1);
        g_selected_packet_num = -1;
        g_nm_prev_packet_count = 0;
        g_nm_auto_scroll = 1;
        g_scroll_nm_flows = 0;
        g_nm_flow_dirty = 1;
      }
    }
    if (g_mon_count == 0)
      DrawTextC("Liste boş: izleme listesine cihaz ekleyin.",
                22, cy + item_h - 2, 8, ui_alpha(COLOR_TEXT_DIM, 160));
    EndScissorMode();
    draw_custom_scrollbar(ip_area.x + ip_area.width - 10, ip_area.y, 10,
                          ip_list_h, ip_rows * item_h,
                          &g_scroll_nm_devices);
    cy += ip_list_h + 8;

    DrawRectangle(24, cy, ctrl_w - 40, 1, ui_alpha(COLOR_BORDER, 140));
    cy += 8;

    /* --- Paket akisi kontrolleri (izleme yalnizca Alarm Merkezi'nden durur) --- */
    if (g_capture_all || g_capture_active_ip[0]) {
      draw_led(30, cy + 8, 4, COLOR_GREEN, 1);
      DrawTextC("Trafik İzleniyor", 38, cy + 3, 10, COLOR_GREEN);
      DrawTextC(g_capture_all ? "Tüm Ağ" : g_nm_target,
                38 + MeasureText("Trafik İzleniyor", 10) + 10, cy + 3, 10,
                COLOR_TEXT_SEC);
      cy += 18;
      if (GuiButton((Rectangle){24, cy, ctrl_w - 40, 26},
                    g_nm_flow_paused ? "Devam Et" : "Durdur")) {
        g_nm_flow_paused = !g_nm_flow_paused;
        g_nm_flow_dirty = 1;
      }
      cy += 30;
    } else if (g_nm_target[0] == '\0') {
      DrawTextC("Bir hedef IP seçin.", 24, cy + 4, 11, COLOR_TEXT_DIM);
      cy += 20;
    } else {
      /* Izleme pasif: once izleme listesine cihaz eklenmeli */
      DrawTextC("İzleme pasif - izleme listesine cihaz ekleyin, sonra AĞI İZLE.",
                24, cy + 4, 9, COLOR_TEXT_DIM);
      cy += 20;
    }

    /* --- MITM / ARP spoof saglik paneli (root, forward, zehirleme durumu) --- */
    if (capture_for_this || g_capture_all) {
      int spoof_on = arp_spoof_is_running();
      int mitm = arp_spoof_get_full_mitm();
      int pcount = arp_spoof_get_partner_count();
      int fwd4 = arp_spoof_ip_forward_status();
      int fwd6 = arp_spoof_ipv6_forward_status();
      int wlan = (g_scan.local_iface[0] == 'w' && g_scan.local_iface[1] == 'l');

      DrawRectangle(24, cy, ctrl_w - 40, 1, ui_alpha(COLOR_BORDER, 140));
      cy += 8;

      if (spoof_on) {
        draw_led(30, cy + 7, 3, COLOR_GREEN, 1);
        DrawTextC("ARP SPOOF: AKTIF", 38, cy + 2, 9, COLOR_GREEN);
      } else {
        draw_led(30, cy + 7, 3, COLOR_RED, 1);
        DrawTextC("ARP SPOOF: KAPALI", 38, cy + 2, 9, COLOR_RED);
      }
      cy += 16;

      if (mitm) {
        snprintf(buf, sizeof(buf), "TAM MITM: hedef <-> %d cihaz zehirli", pcount);
        DrawTextC(buf, 24, cy, 8, COLOR_CYAN);
      } else if (g_capture_all) {
        snprintf(buf, sizeof(buf), "%d cihaz gateway üzerinden zehirli",
                 arp_spoof_get_target_count());
        DrawTextC(buf, 24, cy, 8, COLOR_TEXT_SEC);
      }
      cy += 14;

      snprintf(buf, sizeof(buf), "IP forward: v4 %s | v6 %s",
               fwd4 == 1 ? "AÇIK" : (fwd4 == 0 ? "KAPALI" : "?"),
               fwd6 == 1 ? "AÇIK" : (fwd6 == 0 ? "KAPALI" : "?"));
      DrawTextC(buf, 24, cy, 8, fwd4 == 1 ? COLOR_TEXT_SEC : COLOR_AMBER);
      cy += 14;

      if (!spoof_on) {
        DrawTextC("Root / cap_net_raw gerekli - ARP spoof açılamadı.", 24, cy,
                  8, COLOR_RED);
        cy += 14;
      }
      if (wlan) {
        DrawTextC("Wi-Fi yönetim modu: karşı cihaz kareleri 1'e 1 görünmez!",
                  24, cy, 8, COLOR_AMBER);
        cy += 14;
        DrawTextC("Ethernet + SPAN/rogue AP önerilir.", 24, cy, 8,
                  COLOR_TEXT_DIM);
        cy += 14;
      }
      cy += 4;
    }

    DrawRectangle(24, cy, ctrl_w - 40, 1, ui_alpha(COLOR_BORDER, 140));
    cy += 8;

    /* --- Kendi ARP trafigini gizle (toggle) + PCAP disk kaydi --- */
    if (capture_for_this) {
      Rectangle tog = {24, cy, ctrl_w - 40, 20};
      int th = CheckCollisionPointRec(GetMousePosition(), tog);
      Rectangle box = {28, cy + 5, 10, 10};
      if (g_nm_hide_own_arp) {
        DrawRectangleRounded(box, 0.25f, 4, COLOR_GREEN);
        /* Tik isareti (font ASCII sinirinda, cizgi ile ciz) */
        DrawLine((int)box.x + 2, (int)box.y + 6, (int)box.x + 5,
                 (int)box.y + 9, (Color){10, 14, 24, 255});
        DrawLine((int)box.x + 5, (int)box.y + 9, (int)box.x + 9,
                 (int)box.y + 3, (Color){10, 14, 24, 255});
      } else {
        DrawRectangleRoundedLinesEx(box, 0.25f, 4, 1.0f,
                                    ui_alpha(COLOR_BORDER, 150));
      }
      DrawTextC("Kendi ARP trafiğini gizle", 44, cy + 4, 9,
                th ? COLOR_TEXT : COLOR_TEXT_SEC);
      if (th && IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        g_nm_hide_own_arp = !g_nm_hide_own_arp;
      cy += 24;

      if (full_monitor_pcap_record_is_active()) {
        draw_led(32, cy + 9, 4, COLOR_RED, 1);
        if (GuiButton((Rectangle){44, cy, 96, 22}, "Kaydı Durdur")) {
          full_monitor_pcap_record_stop();
          g_pcap_rec_fail = 0;
        }
        unsigned long long rb = full_monitor_pcap_record_bytes();
        snprintf(buf, sizeof(buf), "%.1f KB", rb / 1024.0);
        DrawTextC(buf, 44 + 102, cy + 6, 9, COLOR_GREEN);
        char pp[200];
        full_monitor_pcap_record_path(pp, sizeof(pp));
        DrawTextC(pp[0] ? pp : "/tmp/beat_system.pcap", 24, cy + 24, 7,
                  COLOR_TEXT_DIM);
        cy += 36;
      } else {
        if (GuiButton((Rectangle){24, cy, ctrl_w - 40, 22}, "PCAP Kaydet")) {
          if (full_monitor_pcap_record_start("/tmp/beat_system.pcap") != 0)
            g_pcap_rec_fail = 1;
          else
            g_pcap_rec_fail = 0;
        }
        DrawTextC("İzleme aktifken tüm trafiği .pcap dosyasına kaydeder", 24,
                  cy + 24, 7, COLOR_TEXT_DIM);
        if (g_pcap_rec_fail) {
          DrawTextC("Kayıt için önce bir izleme başlatın!", 24, cy + 34, 7,
                    COLOR_RED);
          cy += 44;
        } else {
          cy += 32;
        }
      }
      cy += 8;
    }

    /* --- Yakalanan paket ozeti --- */
    /* Gorunum tamponu ve yardimcilar dosya kapsaminda tanimli (yukarida):
     * delta akis + tam yenileme karari orada yonetilir. */

    /* Kendi (spoof) ARP trafigini gizleme icin kendi MAC'imiz */
    char own_mac_buf[MAX_MAC_LEN] = "";
    int have_own_mac =
        (full_monitor_own_mac(own_mac_buf, sizeof(own_mac_buf)) == 0);

    int c0 = full_monitor_packet_count(); /* ring'deki mevcut paket sayisi */
    /* Akis yenileme: pcap modunda (mode==2) yalnizca DELTA paketler kopyalanir
     * (kucuk, kilit kisa); tam yenileme yalnizca nesil degisimi, filtre/hedef
     * degisimi veya duraklatma/resume'de yapilir. Fallback modda (mode==1)
     * eski 10 Hz tam yenileme korunur (procnet ring'i 2 sn'de sifirlanir,
     * delta guvenilmez).
     * DURDUR tusu akisi dondurur (yakalama arka planda surer): kilitliyken
     * yalnizca dirty=1 ise bir kez yenilenir, diger karelerde gorunum
     * ring'ine dokunulmaz; Devam Et dirty=1 ile tam yenileme yapar. */
    int nm_do_full = 0;
    if (show_packets && g_nm_target[0]) {
      unsigned gencur = full_monitor_generation();
      if (gencur != nm_fm_gen) {
        g_nm_flow_dirty = 1;
        nm_fm_gen = gencur;
      }
      int mode = full_monitor_get_mode();
      double nowt = GetTime();
      if (mode == 2 && !g_nm_flow_dirty && !g_nm_flow_paused) {
        /* Surekli delta akisi: kare basina NM_DELTA_BUDGET pakete kadar */
        int budget = NM_DELTA_BUDGET;
        while (budget > 0) {
          int want = (budget < NM_DELTA_MAX) ? budget : NM_DELTA_MAX;
          int got = full_monitor_get_new_packets(&nm_cursor, nm_delta_buf, want);
          if (got <= 0) break;
          for (int i = 0; i < got; i++) {
            if (nm_filter_match(&nm_delta_buf[i], own_mac_buf, have_own_mac))
              nm_disp_append(&nm_delta_buf[i]);
          }
          budget -= got;
        }
        g_nm_last_refresh = nowt;
      } else if ((mode != 0 || g_nm_flow_dirty) &&
                 (!g_nm_flow_paused || g_nm_flow_dirty)) {
        /* Tam yenileme: throttle 0.1 sn (fallback modda eski davranis).
         * Duraklatilmis akis yalnizca dirty'de tek seferlik yenilenir. */
        if (g_nm_flow_dirty ||
            (!g_nm_flow_paused && (nowt - g_nm_last_refresh) >= 0.1)) {
          nm_do_full = 1;
          g_nm_last_refresh = nowt;
        }
      }
      /* mode==0 (kapali) veya duraklatilmis ve !dirty: donmus gorunum */
    } else {
      nm_dpc = 0;
      nm_dstart = 0;
      nm_cursor = 0;
      g_nm_flow_dirty = 1; /* sekme tekrar acilinca tam yenileme */
    }
    if (nm_do_full) {
      g_nm_flow_dirty = 0;
      nm_dpc = 0;
      nm_dstart = 0;
      int c = full_monitor_get_packets(nm_all_packets, NM_DISPLAY_MAX, 0);
      /* Kronolojik (eski->yeni) tara; eslesenleri gorunum ring'ine ekle.
       * Ring tasarsa en yeni NM_DISPLAY_MAX eslesme kalir. */
      for (int i = 0; i < c; i++) {
        if (nm_filter_match(&nm_all_packets[i], own_mac_buf, have_own_mac))
          nm_disp_append(&nm_all_packets[i]);
      }
      nm_cursor = (c > 0) ? nm_all_packets[c - 1].packet_number : 0;
    }

    if (show_packets) {
      draw_dot_label(24, cy, COLOR_GREEN, "Toplam: ", 10, COLOR_TEXT_DIM);
      snprintf(buf, sizeof(buf), "%d paket", nm_dpc);
      if (g_pkt_filter[0]) snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " (filtre)");
      int d = MeasureText("Toplam: ", 10);
      DrawTextC(buf, 24 + d + 10, cy, 10, COLOR_GREEN);
      if (g_nm_flow_paused) {
        DrawTextC("AKIŞ DURAKLATILDI - izleme arka planda sürüyor", 24,
                  cy + 12, 8, COLOR_AMBER);
      } else if (!capture_for_this) {
        char st[128];
        snprintf(st, sizeof(st), "DURDURULDU - buffer korundu (%d kalan)", c0);
        DrawTextC(st, 24, cy + 12, 8, COLOR_AMBER);
      }
    } else if (g_nm_target[0]) {
      DrawTextC("İzleme başlatılmadı.", 24, cy, 10, COLOR_TEXT_DIM);
    }
    cy += 24;

    /* Sol panel alt bilgi alani (paket turu legendi) */
    if (show_packets) {
      int ly = py + panel_h - 100;
      DrawRectangle(24, ly, ctrl_w - 40, 1, ui_alpha(COLOR_BORDER, 120));
      DrawTextC("AKTİVİTE (son 12)", 24, ly + 8, 8, COLOR_TEXT_DIM);

      char slots[512];
      int nslots = full_monitor_activity_slots(slots, sizeof(slots));
      static const char *atoks[12];
      int nt = 0;
      {
        char *p = slots;
        while (p && *p && nt < 12) {
          char *comma = strchr(p, ',');
          if (comma) *comma = '\0';
          if (*p) atoks[nt++] = p;
          if (!comma) break;
          p = comma + 1;
        }
      }
      /* En yeni aktivite sagda olacak sekilde 12 nokta */
      for (int i = 0; i < 12; i++) {
        int idx = nt - 1 - i;
        int sx = 24 + i * 14 + 3;
        Color sc = (Color){44, 50, 68, 255};
        if (idx >= 0) {
          const char *pr = atoks[idx] ? strrchr(atoks[idx], '|') : NULL;
          pr = pr ? pr + 1 : "";
          sc = (idx < nslots) ? proto_color(pr) : (Color){44, 50, 68, 255};
        }
        DrawCircle(sx, ly + 22, 3.5f, sc);
      }
      if (nt > 0 && atoks[0]) {
        char ipx[128];
        size_t plen = strcspn(atoks[0], "|");
        if (plen >= sizeof(ipx)) plen = sizeof(ipx) - 1;
        memcpy(ipx, atoks[0], plen);
        ipx[plen] = '\0';
        snprintf(buf, sizeof(buf), "son: %s (aktif %d)", ipx, nslots);
        DrawTextC(buf, 24, ly + 30, 7, COLOR_TEXT_DIM);
      }

      /* PROTO legend */
      DrawTextC("PROTO", 24, ly + 46, 8, COLOR_TEXT_DIM);
      const char *pl[] = {"TCP", "UDP", "DNS", "ARP", "ICMP"};
      Color pc[] = {COLOR_CYAN, COLOR_ACCENT2, COLOR_GREEN, COLOR_AMBER,
                    COLOR_RED};
      int px2 = 24;
      for (int p = 0; p < 5; p++) {
        DrawCircle(px2 + 3, ly + 63, 2.5f, pc[p]);
        DrawTextC(pl[p], px2 + 9, ly + 57, 8, COLOR_TEXT_SEC);
        px2 += MeasureText(pl[p], 8) + 20;
        if (px2 > ctrl_w - 30)
          break;
      }
    }

    /* --- Sag panel: Paket listesi ve detay --- */
    int rx = 12 + ctrl_w + 8;
    DrawRoundedPanel((Rectangle){rx, py, result_w, panel_h}, COLOR_PANEL,
                     ui_alpha(COLOR_BORDER, 150));

    if (g_nm_target[0]) {
      snprintf(buf, sizeof(buf), "Trafik: %s", g_nm_target);
      draw_panel_title(rx + 12, py + 8, buf, 13, COLOR_ACCENT);
    } else {
      /* Hedef secilmeden liste akmaz; baslik da "Paket Listesi" kalir.
       * Spoof/tum-ag durumu sol paneldeki "Trafik İzleniyor" satiriyla
       * aynen gorunur. */
      draw_panel_title(rx + 12, py + 8, "Paket Listesi", 13, COLOR_ACCENT);
    }
    /* SPAN / port mirror tespiti: yabanci MAC kaynakli kareler yuksekse uyar */
    if (capture_for_this && full_monitor_mirror_suspected()) {
      char mbuf[96];
      snprintf(mbuf, sizeof(mbuf), "MIRROR? yabancı:%d",
               full_monitor_get_foreign_frame_count());
      draw_badge(rx + 150, py + 7, mbuf, 8, COLOR_AMBER);
    }
    if (g_selected_packet_num != -1) {
      Rectangle back_btn = {rx + result_w - 80, py + 5, 70, 18};
      if (GuiButton(back_btn, "Geri Dön")) {
        g_selected_packet_num = -1;
        g_scroll_pdu_detail = 0;
      }
    }

    int hdr_y = py + 28;
    DrawRectangle(rx + 4, hdr_y, result_w - 8, 1, ui_alpha(COLOR_BORDER, 160));


    if (g_selected_packet_num == -1) {
      /* --- Paket Listesi Gorunumu --- */
      int tbl_y = hdr_y + 4;

      /* --- Wireshark-tarzi display filtre cubugu --- */
      int fv = (g_pkt_filter[0] == '\0') ||
               filter_engine_expr_valid(g_pkt_filter);
      int fb_y = tbl_y + 3;
      Rectangle fbb = {rx + 54, fb_y, result_w - 54 - 86, 24};
      DrawTextC("Filtre:", rx + 10, fb_y + 7, 11, COLOR_TEXT_SEC);

      /* Odak yonetimi: kutuya tiklayinca yazi girisi baslar, disari
         tiklayinca veya Enter/Tab ile biter */
      if (IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        if (CheckCollisionPointRec(GetMousePosition(), fbb))
          g_pkt_filter_active = 1;
        else
          g_pkt_filter_active = 0;
      }
      GuiTextBox(fbb, g_pkt_filter, (int)sizeof(g_pkt_filter),
                 g_pkt_filter_active != 0);
      if (IsKeyPressed(KEY_ENTER) || IsKeyPressed(KEY_TAB))
        g_pkt_filter_active = 0;

      /* Ifade degisti: kaydirma ve auto-scroll durumunu sifirla */
      if (strcmp(g_pkt_filter, g_pkt_filter_prev) != 0) {
        strncpy(g_pkt_filter_prev, g_pkt_filter,
                sizeof(g_pkt_filter_prev) - 1);
        g_pkt_filter_prev[sizeof(g_pkt_filter_prev) - 1] = '\0';
        g_scroll_nm_flows = 0;
        g_nm_auto_scroll = 1;
        g_nm_prev_packet_count = 0;
        g_nm_flow_dirty = 1;
      }

      /* Gecersiz ifade: kirmizi cerceve + panel usti uyari yazisi */
      if (!fv) {
        DrawRectangleLinesEx(fbb, 1, COLOR_RED);
        DrawTextC("Geçersiz ifade", rx + result_w - 170, py + 10, 9,
                  COLOR_RED);
      }

      /* Temizle: filtre + scroll/Secim sifirlanir VE paket buffer'i
       * gercekten bosaltilir (ring + istatistik + aktivite). Aksi halde
       * buton yalnizca filtre kutusunu temizliyor, liste dolu kaliyordu. */
      if (GuiButton((Rectangle){rx + result_w - 78, fb_y, 70, 24}, "Temizle")) {
        full_monitor_clear();
        g_pkt_filter[0] = '\0';
        g_pkt_filter_prev[0] = '\0';
        g_pkt_filter_active = 0;
        g_scroll_nm_flows = 0;
        g_nm_auto_scroll = 1;
        g_nm_prev_packet_count = 0;
        g_selected_packet_num = -1;
        g_scroll_pdu_detail = 0;
        g_nm_flow_dirty = 1;
      }

      tbl_y += 32; /* filtre cubugunun altindan tablo baslar */
      DrawRectangle(rx + 4, tbl_y, result_w - 8, 16, COLOR_SURFACE2);
      DrawTextC("No", rx + 8, tbl_y + 3, 9, COLOR_TEXT_DIM);
      DrawTextC("Zaman", rx + 36, tbl_y + 3, 9, COLOR_TEXT_DIM);
      DrawTextC("Kaynak", rx + 88, tbl_y + 3, 9, COLOR_TEXT_DIM);
      DrawTextC("Hedef", rx + 192, tbl_y + 3, 9, COLOR_TEXT_DIM);
      DrawTextC("Proto", rx + 296, tbl_y + 3, 9, COLOR_TEXT_DIM);
      DrawTextC("Len", rx + 352, tbl_y + 3, 9, COLOR_TEXT_DIM);
      DrawTextC("Bilgi", rx + 392, tbl_y + 3, 9, COLOR_TEXT_DIM);
      tbl_y += 18;

      if (nm_dpc == 0) {
        const char *msg;
        if (!g_nm_target[0])
          msg = "Bir hedef IP seçin."; /* Port Tarayici davranisi: once hedef */
        else if (!capture_for_this)
          msg = "İzleme başlatılmadı.";
        else if (g_pkt_filter[0])
          msg = "Filtreye uyan paket yok.";
        else
          msg = "Henüz paket yakalanmadı.";
        int mw = MeasureText(msg, 12);
        DrawTextC(msg, rx + result_w / 2 - mw / 2, py + panel_h / 2, 12,
                  COLOR_TEXT_SEC);
      } else {
        int lh = panel_h - (tbl_y - py) - 4;
        float ms = nm_dpc * 18 - lh;
        if (ms < 0)
          ms = 0;
        /* Liste kisalirsa (filtre/tam yenileme) scroll ust siniri asili
         * kalmasin: aksi halde gorunum bos sayfa gosterir. */
        if (g_scroll_nm_flows > ms)
          g_scroll_nm_flows = ms;

        /* Wireshark tarzi auto-scroll: eger kullanici en alttaysa yeni
           paketler geldiginde otomatik asagiya kaydir */
        float scroll_threshold = 4.0f; /* px tolerans */

        Rectangle fa = {rx, tbl_y, result_w, lh};
        float wheel = GetMouseWheelMove();
        if (CheckCollisionPointRec(GetMousePosition(), fa) && wheel != 0.0f) {
          g_scroll_nm_flows -= wheel * 25;
          if (g_scroll_nm_flows < 0)
            g_scroll_nm_flows = 0;
          if (g_scroll_nm_flows > ms)
            g_scroll_nm_flows = ms;
          /* Kullanici yukari scroll yaptiysa auto-scroll kapat */
          g_nm_auto_scroll = (g_scroll_nm_flows >= ms - scroll_threshold);
        }

        /* Yeni paket geldiyse ve auto-scroll aktifse en alta kaydir */
        if (nm_dpc > g_nm_prev_packet_count && g_nm_auto_scroll && ms > 0) {
          g_scroll_nm_flows = ms;
        }
        /* En altta olup olmadigini tekrar kontrol et */
        if (g_scroll_nm_flows >= ms - scroll_threshold) {
          g_nm_auto_scroll = 1;
        }
        g_nm_prev_packet_count = nm_dpc;
        BeginScissorModeScaled(rx, tbl_y, result_w, lh);
        for (int i = 0; i < nm_dpc; i++) {
          int iy = tbl_y + i * 18 - (int)g_scroll_nm_flows;
          if (iy + 18 < tbl_y || iy > tbl_y + lh)
            continue;
          PacketRecord *p = nm_disp_get(i);

          Rectangle pr = {rx + 4, iy, result_w - 24, 17};
          int hover = CheckCollisionPointRec(GetMousePosition(), pr);
          Color rbg =
              hover ? COLOR_PANEL_HOVER
                    : ((i % 2 == 0) ? (Color){13, 17, 28, 255} : COLOR_SURFACE);
          DrawRectangleRec(pr, rbg);

          Color pc = proto_color(p->protocol);

          char sbuf[32];
          snprintf(sbuf, sizeof(sbuf), "%d", p->packet_number);
          DrawTextC(sbuf, rx + 8, iy + 3, 9, COLOR_TEXT_DIM);
          /* Gerçek saat (HH:MM:SS): eski kod epoch'un yalnizca saniyelik
           * kesrini bastigi icin "0.52" gibi anlamsiz sayilar gorunuyordu */
          {
            time_t ts = (time_t)p->timestamp;
            struct tm *lt = localtime(&ts);
            if (lt)
              snprintf(sbuf, sizeof(sbuf), "%02d:%02d:%02d",
                       lt->tm_hour, lt->tm_min, lt->tm_sec);
            else
              sbuf[0] = '\0';
          }
          DrawTextC(sbuf, rx + 36, iy + 3, 9, COLOR_TEXT_SEC);

          DrawTextC(p->src_ip[0] ? p->src_ip : p->src_mac, rx + 88, iy + 3, 9,
                    COLOR_TEXT);
          DrawTextC(p->dst_ip[0] ? p->dst_ip : p->dst_mac, rx + 192, iy + 3, 9,
                    COLOR_TEXT);

          DrawTextC(p->protocol, rx + 296, iy + 3, 9, pc);

          snprintf(sbuf, sizeof(sbuf), "%d", p->length);
          DrawTextC(sbuf, rx + 352, iy + 3, 9, COLOR_TEXT_SEC);

          char infoshort[128];
          strncpy(infoshort, p->info, 127);
          infoshort[127] = '\0';
          for (int c = 0; c < 127 && infoshort[c]; c++)
            if (infoshort[c] == '\n' || infoshort[c] == '\r')
              infoshort[c] = ' ';
          /* Bilgi sutununu scroll cubuguna tasmayacak sekilde kisalt */
          int max_info_px = (int)((rx + result_w - 30) - (rx + 392));
          if (max_info_px < 20)
            max_info_px = 20;
          while (MeasureText(infoshort, 9) > max_info_px &&
                 strlen(infoshort) > 1)
            infoshort[strlen(infoshort) - 1] = '\0';
          DrawTextC(infoshort, rx + 392, iy + 3, 9, COLOR_TEXT_DIM);

          if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
            g_selected_packet_num = p->packet_number;
            g_scroll_pdu_detail = 0;
            g_selected_layer = -1;
          }
        }
        EndScissorMode();
        draw_custom_scrollbar(rx + result_w - 10, tbl_y, 10, lh,
                              nm_dpc * 18, &g_scroll_nm_flows);
      }
    }

    else {
      PacketRecord *sel_p = NULL;
      for (int i = 0; i < nm_dpc; i++) {
        if (nm_disp_get(i)->packet_number == g_selected_packet_num) {
          sel_p = nm_disp_get(i);
          break;
        }
      }

      if (!sel_p) {
        g_selected_packet_num = -1;
      } else {
        /* Ustte sabit paket bilgi cipi; detay bunun altinda kayar */
        int chip_h = 26;
        int view_y = hdr_y + 4 + chip_h;
        int lh = panel_h - (view_y - py) - 4;

        /* Detay scroll limiti hesabi */
        int d_y = 0;
        for (int i = 0; i < sel_p->layer_count; i++) {
          d_y += 24;
          if (g_selected_layer == i) {
            int lines = 1;
            for (int c2 = 0; sel_p->layers[i].fields[c2]; c2++)
              if (sel_p->layers[i].fields[c2] == '\n')
                lines++;
            d_y += lines * 14 + 10;
          }
        }
        d_y += 30;
        d_y += ((sel_p->raw_len + 15) / 16) * 14 + 10;
        float ms_pdu = d_y - lh;
        if (ms_pdu < 0)
          ms_pdu = 0;

        Rectangle da = {rx, view_y, result_w, lh};
        if (CheckCollisionPointRec(GetMousePosition(), da)) {
          g_scroll_pdu_detail -= GetMouseWheelMove() * 25;
          if (g_scroll_pdu_detail < 0)
            g_scroll_pdu_detail = 0;
          if (g_scroll_pdu_detail > ms_pdu)
            g_scroll_pdu_detail = ms_pdu;
        }

        /* Paket bilgi cipi */
        snprintf(buf, sizeof(buf), "Paket #%d  |  %s  |  %d bayt",
                 sel_p->packet_number, sel_p->protocol, sel_p->length);
        int cw2 = MeasureText(buf, 9) + 16;
        DrawRectangleRounded((Rectangle){rx + 12, hdr_y + 6, cw2, 16}, 0.5f, 4,
                             ui_alpha(COLOR_ACCENT, 22));
        DrawRectangleRoundedLinesEx(
            (Rectangle){rx + 12, hdr_y + 6, cw2, 16}, 0.5f, 4, 1.0f,
            ui_alpha(COLOR_ACCENT, 60));
        DrawTextC(buf, rx + 20, hdr_y + 8, 9, COLOR_TEXT_SEC);

        BeginScissorModeScaled(rx, view_y, result_w, lh);
        int cy2 = view_y - (int)g_scroll_pdu_detail;

        for (int i = 0; i < sel_p->layer_count; i++) {
          PduLayer *l = &sel_p->layers[i];

          Rectangle lr = {rx + 8, cy2, result_w - 28, 22};
          int hover = CheckCollisionPointRec(GetMousePosition(), lr);
          DrawRectangleRounded(lr, 0.06f, 4,
                               hover ? COLOR_PANEL_HOVER : COLOR_SURFACE);
          DrawRectangleRoundedLinesEx(lr, 0.06f, 4, 1.0f,
                                      ui_alpha(COLOR_BORDER, 140));

          /* Katman turune gore renkli ikon kutusu (ac/kapa durumu) */
          Color lc = COLOR_TEXT_SEC;
          if (strncmp(l->name, "Eth", 3) == 0)
            lc = COLOR_AMBER;
          else if (strncmp(l->name, "IP", 2) == 0)
            lc = COLOR_ACCENT;
          else if (strncmp(l->name, "TCP", 3) == 0)
            lc = COLOR_CYAN;
          else if (strncmp(l->name, "UDP", 3) == 0)
            lc = COLOR_ACCENT2;
          DrawRectangleRounded((Rectangle){lr.x + 4, lr.y + 3, 16, 16}, 0.3f,
                               4, ui_alpha(lc, 40));
          DrawTextC(g_selected_layer == i ? "-" : "+", lr.x + 8, lr.y + 4, 11,
                    lc);

          char lhead[512];
          snprintf(lhead, sizeof(lhead), "%s: %s", l->name, l->summary);
          /* Uzun ozetler scroll cubugunun altina girmesin */
          int max_lh = (int)((rx + result_w - 34) - (lr.x + 26));
          if (max_lh < 20)
            max_lh = 20;
          while (MeasureText(lhead, 11) > max_lh && strlen(lhead) > 2)
            lhead[strlen(lhead) - 1] = '\0';
          DrawTextC(lhead, lr.x + 26, lr.y + 6, 11, lc);

          if (hover && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
            if (g_selected_layer == i)
              g_selected_layer = -1;
            else
              g_selected_layer = i;
          }
          cy2 += 24;

          if (g_selected_layer == i) {
            /* Genisletilmis alan: ayrac cizgisi + alan satirlari */
            DrawRectangle(rx + 8, cy2, result_w - 28, 1,
                          ui_alpha(COLOR_BORDER, 90));
            cy2 += 6;
            char tmpf[1024];
            strncpy(tmpf, l->fields, 1023);
            tmpf[1023] = '\0';
            char *line = strtok(tmpf, "\n");
            while (line != NULL) {
              DrawTextC(line, rx + 30, cy2, 10, COLOR_TEXT_SEC);
              cy2 += 14;
              line = strtok(NULL, "\n");
            }
            cy2 += 4;
          }
        }

        cy2 += 12;
        DrawTextC("Frame Hex Dump", rx + 12, cy2, 11, COLOR_TEXT);
        snprintf(buf, sizeof(buf), "offset 0x0000-0x%04X",
                 sel_p->raw_len > 0 ? (unsigned)(sel_p->raw_len - 1) : 0u);
        DrawTextC(buf, rx + 145, cy2, 9, COLOR_TEXT_DIM);
        cy2 += 18;

        for (int r = 0; r < sel_p->raw_len; r += 16) {
          char hexp[64] = {0};
          char ascp[32] = {0};
          snprintf(hexp, sizeof(hexp), "%04X  ", (unsigned)r);
          for (int c2 = 0; c2 < 16; c2++) {
            if (r + c2 < sel_p->raw_len) {
              char hb[8];
              snprintf(hb, sizeof(hb), "%02X ", sel_p->raw_data[r + c2]);
              strcat(hexp, hb);
              char ch = sel_p->raw_data[r + c2];
              ascp[c2] = (ch >= 32 && ch <= 126) ? ch : '.';
            } else {
              strcat(hexp, "   ");
              ascp[c2] = ' ';
            }
          }
          ascp[16] = '\0';

          DrawTextC(hexp, rx + 12, cy2, 10, COLOR_TEXT_SEC);
          DrawTextC(ascp, rx + 300, cy2, 10, COLOR_TEXT);
          cy2 += 14;
        }

        EndScissorMode();
        draw_custom_scrollbar(rx + result_w - 10, view_y, 10, lh, d_y,
                              &g_scroll_pdu_detail);
      }
    }
  }


  else if (g_tools_subtab == 1) {
    /* === Site Karartma (per-IP alan adi engelleme / internet karartma) === */
    int ctrl_w = 260;
    int result_w = W - 24 - ctrl_w - 8;
    SiteBlockStats st;
    site_block_get_stats(&st);

    /* --- Sol panel: Kontroller --- */
    DrawRoundedPanel((Rectangle){12, py, ctrl_w, panel_h}, COLOR_PANEL,
                     ui_alpha(COLOR_BORDER, 150));
    draw_panel_title(18, py + 8, "Site Karartma", 13, COLOR_RED);

    int cy = py + 28;

    /* Global ac/kapa */
    int en = site_block_is_enabled();
    draw_led(26, cy + 7, 4, en ? COLOR_GREEN : COLOR_RED, en);
    DrawTextC(en ? "KARARTMA AKTIF" : "KARARTMA KAPALI", 38, cy + 2, 10,
              en ? COLOR_GREEN : COLOR_TEXT_DIM);
    if (GuiButton((Rectangle){ctrl_w - 72, cy - 2, 60, 20},
                  en ? "Kapat" : "AÇ")) {
      site_block_set_enabled(!en);
      mon_notice_set(en ? "Site karartma kapatıldı."
                        : "Site karartma açıldı.");
    }
    cy += 24;

    if (!st.raw_ready) {
      DrawTextC("Ham enjeksiyon hazır değil (root / arayüz?).", 20, cy, 9,
                COLOR_AMBER);
      cy += 14;
    }

    DrawRectangle(24, cy, ctrl_w - 40, 1, ui_alpha(COLOR_BORDER, 140));
    cy += 8;

    /* --- Hedef cihaz secimi (izleme listesi) --- */
    DrawTextC("Hedef Cihaz (izleme listesi):", 20, cy, 10, COLOR_TEXT_SEC);
    cy += 14;
    if (g_sb_show_all) {
      int chip_w = 6 + MeasureText("Tüm IP'ler", 10) + 12;
      DrawRectangleRounded((Rectangle){20, cy - 2, chip_w, 14}, 0.5f, 4,
                           ui_alpha(COLOR_RED, 26));
      DrawRectangleRoundedLinesEx((Rectangle){20, cy - 2, chip_w, 14}, 0.5f, 4,
                                  1.0f, ui_alpha(COLOR_RED, 90));
      DrawTextC("Tüm IP'ler", 26, cy, 10, COLOR_RED);
    } else if (g_sb_target[0]) {
      int chip_w = 6 + MeasureText(g_sb_target, 10) + 12;
      DrawRectangleRounded((Rectangle){20, cy - 2, chip_w, 14}, 0.5f, 4,
                           ui_alpha(COLOR_RED, 26));
      DrawRectangleRoundedLinesEx((Rectangle){20, cy - 2, chip_w, 14}, 0.5f, 4,
                                  1.0f, ui_alpha(COLOR_RED, 90));
      DrawTextC(g_sb_target, 26, cy, 10, COLOR_RED);
    } else {
      DrawTextC("(görüntülemek için soldan cihaz seçin)", 20, cy, 9,
                COLOR_TEXT_DIM);
    }
    cy += 16;

    int sb_ip_h = 68;
    Rectangle sb_ip_area = {20, cy, ctrl_w - 28, sb_ip_h};
    DrawRectangleRounded(sb_ip_area, 0.04f, 4, COLOR_SURFACE);
    DrawRectangleRoundedLinesEx(sb_ip_area, 0.04f, 4, 1.0f,
                                ui_alpha(COLOR_BORDER, 110));
    int sb_item_h = 18;
    int sb_items = g_mon_count + 1; /* satir 0 = "Tüm IP'ler" */
    float sb_ip_max = sb_items * sb_item_h - sb_ip_h;
    if (sb_ip_max < 0)
      sb_ip_max = 0;
    if (CheckCollisionPointRec(GetMousePosition(), sb_ip_area)) {
      g_sb_scroll_ips -= GetMouseWheelMove() * 20;
      if (g_sb_scroll_ips < 0)
        g_sb_scroll_ips = 0;
      if (g_sb_scroll_ips > sb_ip_max)
        g_sb_scroll_ips = sb_ip_max;
    }
    BeginScissorModeScaled(sb_ip_area.x, sb_ip_area.y, sb_ip_area.width,
                           sb_ip_area.height);
    if (g_mon_count == 0) {
      DrawTextC("İzleme listesi boş (Kontrol Paneli'nden ekleyin).", 26,
                cy + sb_item_h + 4, 9, COLOR_TEXT_DIM);
    }
    for (int i = 0; i < sb_items; i++) {
      int iy = cy + i * sb_item_h - (int)g_sb_scroll_ips;
      if (iy + sb_item_h < cy || iy > cy + sb_ip_h)
        continue;
      Rectangle db = {22, iy + 1, ctrl_w - 44, sb_item_h - 2};
      const char *ip = (i == 0) ? "Tüm IP'ler" : g_mon_ips[i - 1];
      int sel = (i == 0) ? g_sb_show_all
                         : (!g_sb_show_all && strcmp(g_sb_target, g_mon_ips[i - 1]) == 0);
      int hov = CheckCollisionPointRec(GetMousePosition(), db);
      if (sel)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_SELECTED);
      else if (hov)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_PANEL_HOVER);
      if (sel)
        DrawRectangle(db.x, db.y + 3, 3, db.height - 6, COLOR_RED);
      DrawTextC(ip, db.x + 10, db.y + 3, 10, sel ? COLOR_RED : COLOR_TEXT);
      if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT)) {
        if (i == 0) {
          g_sb_target[0] = '\0';
          g_sb_show_all = 1;
        } else {
          strncpy(g_sb_target, g_mon_ips[i - 1], MAX_IP_LEN - 1);
          g_sb_show_all = 0;
        }
        g_sb_scroll_rules = 0;
        g_sb_scroll_obs = 0;
        g_sb_sel_rule = -1;
      }
    }
    EndScissorMode();
    draw_custom_scrollbar(sb_ip_area.x + sb_ip_area.width - 10, sb_ip_area.y, 10,
                          sb_ip_h, sb_items * sb_item_h, &g_sb_scroll_ips);
    cy += sb_ip_h + 8;

    DrawRectangle(24, cy, ctrl_w - 40, 1, ui_alpha(COLOR_BORDER, 140));
    cy += 8;

    /* --- Alan adi giris kutusu --- */
    DrawTextC("Alan Adı (facebook.com):", 20, cy, 10, COLOR_TEXT_SEC);
    cy += 13;
    DrawTextC("Joker: *youtube.com (alt alan)  *youtube* (içerir)", 20, cy, 8,
              COLOR_TEXT_DIM);
    cy += 12;
    Rectangle dbox = {20, cy, ctrl_w - 40, 24};
    int mclick = IsMouseButtonPressed(MOUSE_BUTTON_LEFT);
    int dhover = CheckCollisionPointRec(GetMousePosition(), dbox);
    if (mclick && dhover)
      g_sb_domain_active = 1;
    else if (mclick && !dhover)
      g_sb_domain_active = 0;
    GuiTextBox(dbox, g_sb_domain, (int)sizeof(g_sb_domain),
               g_sb_domain_active != 0);
    cy += 30;

    /* --- Mod secimi --- */
    DrawTextC("Mod:", 20, cy, 10, COLOR_TEXT_SEC);
    int mbw = (ctrl_w - 56) / 3;
    int modes[3] = {SB_MODE_SINKHOLE, SB_MODE_RST, SB_MODE_BOTH};
    const char *mlabels[3] = {"DNS", "RST", "İkisi"};
    for (int m = 0; m < 3; m++) {
      Rectangle mbr = {(float)(22 + m * (mbw + 4)), (float)(cy + 12),
                       (float)mbw, 20};
      int act = (g_sb_mode == modes[m]);
      if (act) {
        DrawRectangleRounded(mbr, 0.3f, 4, ui_alpha(COLOR_RED, 40));
        DrawRectangleRoundedLinesEx(mbr, 0.3f, 4, 1.0f, COLOR_RED);
      } else {
        DrawRectangleRounded(mbr, 0.3f, 4, COLOR_SURFACE2);
      }
      if (CheckCollisionPointRec(GetMousePosition(), mbr) && mclick)
        g_sb_mode = modes[m];
      DrawTextC(mlabels[m], (int)mbr.x + 8, (int)mbr.y + 5, 10,
                act ? COLOR_RED : COLOR_TEXT_SEC);
    }
    cy += 40;

    /* --- Kural ekle --- */
    if (!g_sb_domain[0]) {
      DrawTextC("Engellemek için alan adı girin.", 20, cy, 9, COLOR_TEXT_DIM);
      cy += 22;
    } else {
      const char *blabel = g_sb_target[0] ? "Bu cihaz için engelle"
                                          : "Tüm cihazlar için engelle";
      if (GuiButton((Rectangle){22, cy, ctrl_w - 46, 24}, blabel)) {
        const char *tip = g_sb_target[0] ? g_sb_target : "*";
        int r = site_block_add_rule(tip, g_sb_domain, g_sb_mode);
        if (r >= 0) {
          mon_notice_set("Kural eklendi.");
          g_sb_domain[0] = '\0';
        }
      }
      cy += 30;
    }

    DrawRectangle(24, cy, ctrl_w - 40, 1, ui_alpha(COLOR_BORDER, 140));
    cy += 8;

    /* --- Sinkhole yanit IP --- */
    DrawTextC("Sinkhole IP:", 20, cy, 9, COLOR_TEXT_DIM);
    Rectangle sbox = {104, (float)(cy - 3), (float)(ctrl_w - 124), 20};
    int shover = CheckCollisionPointRec(GetMousePosition(), sbox);
    if (mclick && shover)
      g_sb_sinkhole_active = 1;
    else if (mclick && !shover)
      g_sb_sinkhole_active = 0;
    if (GuiTextBox(sbox, g_sb_sinkhole, (int)sizeof(g_sb_sinkhole),
                   g_sb_sinkhole_active != 0))
      site_block_set_sinkhole_ip(g_sb_sinkhole);
    cy += 26;

    /* --- Istatistik --- */
    snprintf(buf, sizeof(buf), "Sinkhole:%lu  RST:%lu  ICMP:%lu",
             st.sinkholed, st.rst_sent, st.icmp_sent);
    DrawTextC(buf, 20, cy, 9, COLOR_CYAN);
    cy += 12;
    snprintf(buf, sizeof(buf), "Gözlem:%lu  Kural:%d  Kapsam:%d",
             st.observed, site_block_rule_count(), st.scope_count);
    DrawTextC(buf, 20, cy, 9, COLOR_TEXT_DIM);

    /* --- Sag panel: Gozlemler (ust) + Aktif Kurallar (alt) --- */
    int rx = 12 + ctrl_w + 8;
    int obs_h = (panel_h - 8) / 2;
    int rules_h = panel_h - obs_h - 8;

    /* Gozlemler: Ziyaret edilen siteler */
    DrawRoundedPanel((Rectangle){rx, py, result_w, obs_h}, COLOR_PANEL,
                     ui_alpha(COLOR_BORDER, 150));
    draw_panel_title(rx + 8, py + 6, "Ziyaret edilen siteler", 12,
                     COLOR_ACCENT);
    if (GuiButton((Rectangle){rx + result_w - 76, py + 4, 66, 18}, "Temizle"))
      site_block_clear_observations();

    SiteBlockObs obs[SB_OBS_MAX];
    int ocount = site_block_observations(obs, SB_OBS_MAX);
    int ovis = 0;
    for (int i = 0; i < ocount; i++)
      if (g_sb_show_all || (g_sb_target[0] && strcmp(obs[i].ip, g_sb_target) == 0))
        ovis++;
    int oly0 = py + 28;
    int olh = obs_h - 36;
    int orow_h = 20;
    float omax = ovis * orow_h - olh;
    if (omax < 0)
      omax = 0;
    Rectangle oarea = {rx + 6, oly0, result_w - 12, olh};
    if (CheckCollisionPointRec(GetMousePosition(), oarea)) {
      g_sb_scroll_obs -= GetMouseWheelMove() * 20;
      if (g_sb_scroll_obs < 0)
        g_sb_scroll_obs = 0;
      if (g_sb_scroll_obs > omax)
        g_sb_scroll_obs = omax;
    }
    if (g_sb_show_all || g_sb_target[0]) {
      snprintf(buf, sizeof(buf), "Filtre: %s",
               g_sb_target[0] ? g_sb_target : "Tüm IP'ler");
      int flw = MeasureText(buf, 9);
      DrawTextC(buf, rx + result_w - 76 - flw - 8, py + 9, 9, COLOR_RED);
    }
    BeginScissorModeScaled(oarea.x, oarea.y, oarea.width, oarea.height);
    if (ovis == 0) {
      const char *hint = g_sb_show_all
          ? "Gözlem yok."
          : g_sb_target[0]
              ? "Seçili cihaz için gözlem yok."
              : "Soldan bir cihaz seçin ya da 'Tüm IP'ler'i seçin.";
      DrawTextC(hint, rx + 12, oly0 + 8, 10, COLOR_TEXT_DIM);
    }
    int oi = 0;
    for (int i = 0; i < ocount; i++) {
      SiteBlockObs *o = &obs[i];
      if (!(g_sb_show_all || (g_sb_target[0] && strcmp(o->ip, g_sb_target) == 0)))
        continue;
      int yy = oly0 + oi * orow_h - (int)g_sb_scroll_obs;
      oi++;
      if (yy + orow_h < oly0 || yy > oly0 + olh)
        continue;
      Rectangle ob = {rx + 8, yy + 1, result_w - 26, orow_h - 2};
      int hov = CheckCollisionPointRec(GetMousePosition(), ob);
      if (o->blocked)
        DrawRectangleRounded(ob, 0.2f, 4, ui_alpha(COLOR_RED, 30));
      else if (hov)
        DrawRectangleRounded(ob, 0.2f, 4, COLOR_PANEL_HOVER);
      if (o->blocked)
        DrawRectangle(ob.x, ob.y + 2, 3, ob.height - 4, COLOR_RED);
      const char *kt = (o->kind == DOMAIN_KIND_DNS) ? "DNS"
                     : (o->kind == DOMAIN_KIND_SNI) ? "SNI"
                     : (o->kind == DOMAIN_KIND_HTTP) ? "HTTP"
                     : (o->kind == DOMAIN_KIND_QUIC) ? "QUIC" : "?";
      DrawTextC(o->ip, ob.x + 8, ob.y + 3, 10, COLOR_TEXT_SEC);
      DrawTextC(o->domain, ob.x + 112, ob.y + 3, 10,
                o->blocked ? COLOR_RED : COLOR_TEXT);
      DrawTextC(kt, ob.x + ob.width - 144, ob.y + 4, 8, COLOR_CYAN);
      snprintf(buf, sizeof(buf), "x%lu", o->count);
      DrawTextC(buf, ob.x + ob.width - 88, ob.y + 4, 8, COLOR_TEXT_DIM);
      if (GuiButton((Rectangle){ob.x + ob.width - 42, ob.y + 2, 36,
                                orow_h - 6},
                    o->blocked ? "AÇ" : "Blok")) {
        if (o->blocked) {
          /* Tum eslesen kurallari kaldir (wildcard dahil) + gozlem
           * bayraklarini tazele: satir aninda normale doner. */
          int n = site_block_unblock_observed(o->ip, o->domain);
          if (n > 0) {
            snprintf(buf, sizeof(buf), "%d kural kaldırıldı.", n);
            mon_notice_set(buf);
          }
        } else {
          site_block_block_observed(o->ip, o->domain, g_sb_mode);
          mon_notice_set("Gözlemden kural eklendi.");
        }
      }
    }
    EndScissorMode();
    draw_custom_scrollbar(rx + result_w - 10, oly0, 10, olh, ovis * orow_h,
                          &g_sb_scroll_obs);

    /* Aktif kurallar */
    int ry0 = py + obs_h + 8;
    DrawRoundedPanel((Rectangle){rx, ry0, result_w, rules_h}, COLOR_PANEL,
                     ui_alpha(COLOR_BORDER, 150));
    draw_panel_title(rx + 8, ry0 + 6, "Aktif Kurallar", 12, COLOR_RED);
    int rcount = site_block_rule_count();
    int rvis = 0;
    for (int i = 0; i < rcount; i++) {
      SiteBlockRule rr;
      if (site_block_get_rule(i, &rr) != 0)
        continue;
      if (g_sb_show_all || (g_sb_target[0] && strcmp(rr.ip, g_sb_target) == 0))
        rvis++;
    }
    snprintf(buf, sizeof(buf), "%d / %d", rcount, SB_MAX_RULES);
    int cntw = MeasureText(buf, 9);
    DrawTextC(buf, rx + result_w - cntw - 14, ry0 + 9, 9, COLOR_TEXT_DIM);
    if (g_sb_show_all || g_sb_target[0]) {
      snprintf(buf, sizeof(buf), "Filtre: %s",
               g_sb_target[0] ? g_sb_target : "Tüm IP'ler");
      int flw = MeasureText(buf, 9);
      DrawTextC(buf, rx + result_w - cntw - 14 - flw - 8, ry0 + 9, 9, COLOR_RED);
    }

    int rlh = rules_h - 34;
    int rrow_h = 22;
    float rmax = rvis * rrow_h - rlh;
    if (rmax < 0)
      rmax = 0;
    Rectangle rcarea = {rx + 6, ry0 + 26, result_w - 12, rlh};
    if (CheckCollisionPointRec(GetMousePosition(), rcarea)) {
      g_sb_scroll_rules -= GetMouseWheelMove() * 20;
      if (g_sb_scroll_rules < 0)
        g_sb_scroll_rules = 0;
      if (g_sb_scroll_rules > rmax)
        g_sb_scroll_rules = rmax;
    }
    BeginScissorModeScaled(rcarea.x, rcarea.y, rcarea.width, rcarea.height);
    if (rvis == 0) {
      const char *hint = g_sb_show_all
          ? "Kural yok."
          : g_sb_target[0]
              ? "Seçili cihaz için kural yok."
              : "Soldan bir cihaz seçin ya da 'Tüm IP'ler'i seçin.";
      DrawTextC(hint, rx + 12, rcarea.y + 8, 10, COLOR_TEXT_DIM);
    }
    int ri = 0;
    for (int i = 0; i < rcount; i++) {
      SiteBlockRule rr;
      if (site_block_get_rule(i, &rr) != 0)
        continue;
      if (!(g_sb_show_all || (g_sb_target[0] && strcmp(rr.ip, g_sb_target) == 0)))
        continue;
      int ry = rcarea.y + ri * rrow_h - (int)g_sb_scroll_rules;
      ri++;
      if (ry + rrow_h < rcarea.y || ry > rcarea.y + rlh)
        continue;
      Rectangle rb = {rx + 8, ry + 1, result_w - 26, rrow_h - 2};
      int sel = (g_sb_sel_rule == i);
      int hov = CheckCollisionPointRec(GetMousePosition(), rb);
      if (sel)
        DrawRectangleRounded(rb, 0.2f, 4, COLOR_SELECTED);
      else if (hov)
        DrawRectangleRounded(rb, 0.2f, 4, COLOR_PANEL_HOVER);
      Color mcol = (rr.mode == SB_MODE_SINKHOLE) ? COLOR_CYAN
                 : (rr.mode == SB_MODE_RST) ? COLOR_AMBER : COLOR_RED;
      const char *mt = (rr.mode == SB_MODE_SINKHOLE) ? "DNS"
                     : (rr.mode == SB_MODE_RST) ? "RST" : "İKİSİ";
      DrawTextC(rr.ip, rb.x + 8, rb.y + 4, 10, COLOR_TEXT_SEC);
      DrawTextC(rr.domain, rb.x + 112, rb.y + 4, 10, COLOR_TEXT);
      DrawTextC(mt, rb.x + rb.width - 144, rb.y + 5, 8, mcol);
      snprintf(buf, sizeof(buf), "%lu hit", rr.hits);
      DrawTextC(buf, rb.x + rb.width - 88, rb.y + 5, 8, COLOR_TEXT_DIM);
      if (GuiButton((Rectangle){rb.x + rb.width - 42, rb.y + 2, 36,
                                rrow_h - 6}, "Sil"))
        site_block_remove_rule(i);
      if (hov && mclick)
        g_sb_sel_rule = i;
    }
    EndScissorMode();
    draw_custom_scrollbar(rx + result_w - 10, rcarea.y, 10, rlh, rvis * rrow_h,
                          &g_sb_scroll_rules);
  }


  else if (g_tools_subtab == 2) {
    /* === Port Tarayici === */
    int ctrl_w = 260;
    int result_w = W - 24 - ctrl_w - 8;

    /* --- Sol panel: Kontroller --- */
    DrawRoundedPanel((Rectangle){12, py, ctrl_w, panel_h}, COLOR_PANEL,
                     ui_alpha(COLOR_BORDER, 150));
    draw_panel_title(18, py + 8, "Port Tarayıcı", 13, COLOR_ACCENT2);

    portscan_get_results(&g_portscan);
    int is_this =
        (g_ps_target[0] && strcmp(g_portscan.target_ip, g_ps_target) == 0);
    int scanning = (is_this && g_portscan.is_scanning);

    int cy = py + 28;

    /* --- Hedef IP secimi (chip + scrollable liste) --- */
    DrawTextC("Hedef:", 24, cy, 10, COLOR_TEXT_SEC);
    if (g_ps_target[0]) {
      int chip_w = 6 + MeasureText(g_ps_target, 10) + 12;
      DrawRectangleRounded((Rectangle){66, cy - 2, chip_w, 14}, 0.5f, 4,
                           ui_alpha(COLOR_ACCENT2, 26));
      DrawRectangleRoundedLinesEx((Rectangle){66, cy - 2, chip_w, 14}, 0.5f, 4,
                                  1.0f, ui_alpha(COLOR_ACCENT2, 90));
      DrawTextC(g_ps_target, 72, cy, 10, COLOR_ACCENT2);
    }
    cy += 16;

    int ip_list_h = 80;
    Rectangle ip_area = {20, cy, ctrl_w - 28, ip_list_h};
    DrawRectangleRounded(ip_area, 0.04f, 4, COLOR_SURFACE);
    DrawRectangleRoundedLinesEx(ip_area, 0.04f, 4, 1.0f,
                                ui_alpha(COLOR_BORDER, 110));
    int item_h = 20;
    float ip_max_scroll = g_scan.device_count * item_h - ip_list_h;
    if (ip_max_scroll < 0)
      ip_max_scroll = 0;
    if (CheckCollisionPointRec(GetMousePosition(), ip_area)) {
      g_scroll_ps_devices -= GetMouseWheelMove() * 20;
      if (g_scroll_ps_devices < 0)
        g_scroll_ps_devices = 0;
      if (g_scroll_ps_devices > ip_max_scroll)
        g_scroll_ps_devices = ip_max_scroll;
    }
    BeginScissorModeScaled(ip_area.x, ip_area.y, ip_area.width, ip_area.height);
    for (int i = 0; i < g_scan.device_count; i++) {
      int iy = cy + i * item_h - (int)g_scroll_ps_devices;
      if (iy + item_h < cy || iy > cy + ip_list_h)
        continue;
      Rectangle db = {22, iy + 1, ctrl_w - 44, item_h - 2};
      int sel = (strcmp(g_ps_target, g_scan.devices[i].ip) == 0);
      int hov = CheckCollisionPointRec(GetMousePosition(), db);
      if (sel)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_SELECTED);
      else if (hov)
        DrawRectangleRounded(db, 0.2f, 4, COLOR_PANEL_HOVER);
      if (sel)
        DrawRectangle(db.x, db.y + 3, 3, db.height - 6, COLOR_ACCENT2);
      DrawTextC(g_scan.devices[i].ip, db.x + 10, db.y + 4, 10,
                sel ? COLOR_ACCENT2 : COLOR_TEXT);
      if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT))
        strncpy(g_ps_target, g_scan.devices[i].ip, MAX_IP_LEN - 1);
    }
    EndScissorMode();
    draw_custom_scrollbar(ip_area.x + ip_area.width - 10, ip_area.y, 10,
                          ip_list_h, g_scan.device_count * item_h,
                          &g_scroll_ps_devices);
    cy += ip_list_h + 8;

    DrawRectangle(24, cy, ctrl_w - 40, 1, ui_alpha(COLOR_BORDER, 140));
    cy += 8;

    /* --- Tarama butonlari / ilerleme durumu --- */
    if (g_ps_target[0] == '\0') {
      DrawTextC("Bir hedef IP seçin.", 24, cy + 4, 11, COLOR_TEXT_DIM);
      cy += 20;
    } else if (!scanning) {
      DrawTextC("Tarama Başlat:", 24, cy, 10, COLOR_TEXT_SEC);
      cy += 16;
      int bw = (ctrl_w - 56) / 2;
      if (GuiButton((Rectangle){24, cy, bw, 26}, "Top Portlar"))
        portscan_start_top(g_ps_target, PS_SCAN_CONNECT);
      if (GuiButton((Rectangle){28 + bw, cy, bw, 26}, "1 - 1024"))
        portscan_start(g_ps_target, PS_SCAN_CONNECT, 1, 1024);
      cy += 30;
      if (GuiButton((Rectangle){24, cy, bw, 26}, "1 - 10000"))
        portscan_start(g_ps_target, PS_SCAN_CONNECT, 1, 10000);
      if (GuiButton((Rectangle){28 + bw, cy, bw, 26}, "Tam (65535)"))
        portscan_start(g_ps_target, PS_SCAN_CONNECT, 1, 65535);
      cy += 34;
    } else {
      /* Ilerleme cubugu (scanning) */
      int target = g_portscan.total_target_ports > 0
                       ? g_portscan.total_target_ports
                       : 100;
      float prog = (float)g_portscan.total_scanned / (float)target;
      if (prog > 1.0f)
        prog = 1.0f;
      int pbar_w = ctrl_w - 48;

      draw_led(30, cy + 8, 4, COLOR_AMBER, 1);
      DrawTextC("Tarama devam ediyor...", 38, cy + 3, 10, COLOR_AMBER);
      snprintf(buf, sizeof(buf), "%d / %d  (%.0f%%)",
               g_portscan.total_scanned, target, prog * 100);
      DrawTextC(buf, 24 + pbar_w - MeasureText(buf, 9), cy + 3, 9,
                COLOR_TEXT_DIM);
      cy += 18;
      DrawRectangleRounded((Rectangle){24, cy, pbar_w, 18}, 0.5f, 4,
                           (Color){16, 22, 36, 255});
      DrawRectangleRoundedLinesEx((Rectangle){24, cy, pbar_w, 18}, 0.5f, 4,
                                  1.0f, ui_alpha(COLOR_BORDER, 110));
      if (prog > 0.005f)
        DrawRectangleRounded((Rectangle){24, cy, (int)(pbar_w * prog), 18},
                             0.5f, 4, ui_mix(COLOR_ACCENT2, COLOR_BG, 0.55f));
      snprintf(buf, sizeof(buf), "%d / %d  (%.0f%%)", g_portscan.total_scanned,
               target, prog * 100);
      DrawTextC(buf, 30, cy + 4, 9, COLOR_AMBER);
      cy += 22;
      if (GuiButton((Rectangle){24, cy, pbar_w, 22}, "Durdur"))
        portscan_stop();
      cy += 28;
    }

    DrawRectangle(24, cy, ctrl_w - 40, 1, ui_alpha(COLOR_BORDER, 140));
    cy += 8;

    /* --- Sonuc ozeti --- */
    if (is_this && (g_portscan.open_count > 0 || g_portscan.scan_complete)) {
      snprintf(buf, sizeof(buf), "Açık: %d", g_portscan.open_count);
      DrawTextC(buf, 24, cy, 12, COLOR_GREEN);
      cy += 16;
      snprintf(buf, sizeof(buf), "Filtrelenmiş: %d", g_portscan.filtered_count);
      DrawTextC(buf, 24, cy, 10, COLOR_AMBER);
      cy += 13;
      snprintf(buf, sizeof(buf), "Taranan: %d / Süre: %.1fs",
               g_portscan.total_scanned, g_portscan.scan_time_sec);
      DrawTextC(buf, 24, cy, 10, COLOR_TEXT_SEC);
      cy += 13;
      if (g_portscan.os_guess[0]) {
        snprintf(buf, sizeof(buf), "OS: %s (%d%%)", g_portscan.os_guess,
                 g_portscan.os_confidence);
        DrawTextC(buf, 24, cy, 10, COLOR_CYAN);
        cy += 13;
      }
      if (g_portscan.total_vulns_found > 0) {
        snprintf(buf, sizeof(buf), "Zafiyet: %d", g_portscan.total_vulns_found);
        DrawTextC(buf, 24, cy, 10, COLOR_RED);
      }
    } else if (g_ps_target[0] && !is_this && !scanning) {
      DrawTextC("Sonuç yok.", 24, cy, 10, COLOR_TEXT_DIM);
    }

    /* --- Sag panel: Sonuc tablosu --- */
    int rx = 12 + ctrl_w + 8;
    DrawRoundedPanel((Rectangle){rx, py, result_w, panel_h}, COLOR_PANEL,
                     ui_alpha(COLOR_BORDER, 150));
    draw_panel_title(rx + 12, py + 8, "Tarama Sonuçları", 13, COLOR_ACCENT2);

    /* Durum LED'i (sag panel basligi yaninda) */
    if (is_this) {
      int tw = MeasureText("Tarama Sonuçları", 13);
      Color led_c = scanning ? COLOR_AMBER
                   : (g_portscan.scan_complete && g_portscan.open_count > 0)
                       ? COLOR_GREEN
                       : COLOR_TEXT_DIM;
      draw_led((float)(rx + 32 + tw + 26), (float)(py + 14), 3.5f, led_c,
               scanning || g_portscan.is_scanning);
    }

    if (is_this && g_ps_target[0]) {
      snprintf(buf, sizeof(buf), "%s", g_ps_target);
      int bw2 = MeasureText(buf, 9);
      int chip_w = bw2 + 14;
      DrawRectangleRounded(
          (Rectangle){(float)(rx + result_w - chip_w - 14), py + 7,
                      (float)chip_w, 15},
          0.5f, 4, ui_alpha(COLOR_ACCENT2, 22));
      DrawRectangleRoundedLinesEx(
          (Rectangle){(float)(rx + result_w - chip_w - 14), py + 7,
                      (float)chip_w, 15},
          0.5f, 4, 1.0f, ui_alpha(COLOR_ACCENT2, 80));
      DrawTextC(buf, rx + result_w - bw2 - 20, py + 9, 9, COLOR_ACCENT2);
    }

    /* Tablo basligi */
    int hdr_y = py + 28;
    DrawRectangle(rx + 4, hdr_y, result_w - 8, 18, COLOR_SURFACE);
    DrawRectangle(rx + 4, hdr_y + 17, result_w - 8, 1,
                  ui_alpha(COLOR_ACCENT2, 80));
    DrawTextC("Port", rx + 10, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("Durum", rx + 60, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("Servis", rx + 120, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("Ürün/Versiyon", rx + 200, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("Vuln", rx + result_w - 140, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("SSL", rx + result_w - 100, hdr_y + 4, 9, COLOR_TEXT_SEC);
    DrawTextC("RTT", rx + result_w - 60, hdr_y + 4, 9, COLOR_TEXT_SEC);

    int list_y0 = hdr_y + 20;
    int list_h = panel_h - (list_y0 - py) - 4;

    if (!is_this || (g_portscan.open_count == 0 && !g_portscan.scan_complete)) {
      const char *msg =
          scanning ? "Tarama devam ediyor..." : "Tarama başlatılmadı.";
      int mw = MeasureText(msg, 12);
      DrawTextC(msg, rx + result_w / 2 - mw / 2, py + panel_h / 2, 12,
                COLOR_TEXT_SEC);
    } else if (g_portscan.open_count == 0 && g_portscan.scan_complete) {
      DrawTextC("Açık port bulunamadı.", rx + result_w / 2 - 70,
                py + panel_h / 2, 12, COLOR_GREEN);
    } else {
      /* Row height: normal=22, expanded vuln=22 + vuln_count*16 + 8 */
      /* Toplam yuksekligi hesapla (scroll matematigi buna bagli) */
      int total_h = 0;
      for (int i = 0; i < g_portscan.open_count; i++) {
        total_h += 22;
        if (g_ps_selected_vuln_port == g_portscan.ports[i].port &&
            g_portscan.ports[i].vuln_count > 0)
          total_h += g_portscan.ports[i].vuln_count * 16 + 8;
      }
      float ms = total_h - list_h;
      if (ms < 0)
        ms = 0;
      Rectangle la = {rx, list_y0, result_w, list_h};
      if (CheckCollisionPointRec(GetMousePosition(), la)) {
        g_scroll_tool_ports -= GetMouseWheelMove() * 30;
        if (g_scroll_tool_ports < 0)
          g_scroll_tool_ports = 0;
        if (g_scroll_tool_ports > ms)
          g_scroll_tool_ports = ms;
      }

      BeginScissorModeScaled(rx, list_y0, result_w, list_h);
      int ry2 = list_y0 - (int)g_scroll_tool_ports;
      for (int i = 0; i < g_portscan.open_count; i++) {
        PortResult *pr = &g_portscan.ports[i];
        if (ry2 > list_y0 + list_h)
          break;

        int row_h = 22;
        int expanded =
            (g_ps_selected_vuln_port == pr->port && pr->vuln_count > 0);
        if (expanded)
          row_h += pr->vuln_count * 16 + 8;

        if (ry2 + row_h >= list_y0) {
          /* Ana satir (zebra + hover + secili ton) */
          Rectangle rr = {rx + 4, ry2, result_w - 24, 21};
          int hov = CheckCollisionPointRec(GetMousePosition(), rr);
          Color rbg =
              hov ? COLOR_PANEL_HOVER
                  : ((i % 2 == 0) ? (Color){13, 17, 28, 255} : COLOR_SURFACE);
          if (expanded)
            rbg = ui_mix(rbg, COLOR_ACCENT2, 0.08f);
          DrawRectangleRec(rr, rbg);
          if (hov)
            DrawRectangle(rx + 4, ry2, 2, 21, ui_alpha(COLOR_ACCENT2, 160));

          /* Vuln sidebar (en kritik seviyeye gore renk) */
          if (pr->vuln_count > 0) {
            Color vc = COLOR_AMBER;
            for (int v = 0; v < pr->vuln_count; v++)
              if (strcmp(pr->vulns[v].severity, "CRITICAL") == 0) {
                vc = COLOR_RED;
                break;
              }
            DrawRectangle(rx + 6, ry2, 3, 21, vc);
          }

          char pb[16];
          snprintf(pb, sizeof(pb), "%d", pr->port);
          DrawTextC(pb, rx + 12, ry2 + 5, 10, COLOR_TEXT);

          const char *status_str = pr->status == PORT_OPEN       ? "open"
                                   : pr->status == PORT_FILTERED ? "filtered"
                                                                 : "open|flt";
          Color stc = pr->status == PORT_OPEN ? COLOR_GREEN : COLOR_AMBER;
          DrawCircle(rx + 55, ry2 + 10, 2.5f, stc);
          DrawTextC(status_str, rx + 60, ry2 + 5, 10, stc);

          int danger = (pr->port == 4444 || pr->port == 5555 ||
                        pr->port == 31337 || pr->port == 6667);
          DrawTextC(pr->service, rx + 120, ry2 + 5, 10,
                    danger ? COLOR_RED : COLOR_CYAN);

          /* Product/version (sutun genisligine sinirla) */
          char pv[80];
          if (pr->product[0] && pr->version[0])
            snprintf(pv, sizeof(pv), "%.30s %.15s", pr->product, pr->version);
          else if (pr->product[0])
            snprintf(pv, sizeof(pv), "%.45s", pr->product);
          else
            pv[0] = '\0';
          int max_pv_px = (result_w - 144 - 12) - 200;
          if (max_pv_px < 20)
            max_pv_px = 20;
          while (pv[0] && MeasureText(pv, 9) > max_pv_px &&
                 strlen(pv) > 1)
            pv[strlen(pv) - 1] = '\0';
          DrawTextC(pv, rx + 200, ry2 + 5, 9, COLOR_TEXT_DIM);

          /* Vuln count badge */
          if (pr->vuln_count > 0) {
            snprintf(pb, sizeof(pb), "%d", pr->vuln_count);
            int bww = MeasureText(pb, 9) + 10;
            Color bc = COLOR_AMBER;
            for (int v = 0; v < pr->vuln_count; v++)
              if (strcmp(pr->vulns[v].severity, "CRITICAL") == 0) {
                bc = COLOR_RED;
                break;
              }
            DrawRectangleRounded(
                (Rectangle){rx + result_w - 144, ry2 + 4, bww, 14}, 0.5f, 4,
                ui_alpha(bc, 50));
            DrawRectangleRoundedLinesEx(
                (Rectangle){rx + result_w - 144, ry2 + 4, bww, 14}, 0.5f, 4,
                1.0f, ui_alpha(bc, 120));
            DrawTextC(pb, rx + result_w - 140, ry2 + 5, 9, bc);
          }

          /* SSL badge */
          if (pr->is_ssl)
            DrawTextC("TLS", rx + result_w - 96, ry2 + 5, 9, COLOR_GREEN);

          snprintf(pb, sizeof(pb), "%.0fms", pr->rtt_ms);
          DrawTextC(pb, rx + result_w - 56, ry2 + 5, 9, COLOR_TEXT_SEC);

          /* Click: zafiyet detayini ac/kapa */
          if (hov && IsMouseButtonPressed(MOUSE_BUTTON_LEFT) &&
              pr->vuln_count > 0) {
            if (g_ps_selected_vuln_port == pr->port)
              g_ps_selected_vuln_port = -1;
            else
              g_ps_selected_vuln_port = pr->port;
          }

          /* Genisletilmis zafiyet detaylari */
          if (expanded) {
            int vy = ry2 + 24;
            for (int v = 0; v < pr->vuln_count; v++) {
              VulnerabilityNote *vn = &pr->vulns[v];
              Color sc2 = cve_severity_color(vn->severity);
              DrawRectangle(rx + 8, vy, result_w - 16, 15,
                            (Color){sc2.r / 6, sc2.g / 6, sc2.b / 6, 255});
              DrawRectangle(rx + 8, vy, 2, 15, sc2);

              int svw = MeasureText(vn->severity, 8) + 6;
              DrawRectangleRounded((Rectangle){rx + 16, vy + 2, svw, 11}, 0.5f,
                                   4, ui_alpha(sc2, 40));
              DrawTextC(vn->severity, rx + 19, vy + 3, 8, sc2);
              DrawTextC(vn->cve_id, rx + 20 + svw, vy + 3, 8, COLOR_TEXT);

              char desc_short[80];
              strncpy(desc_short, vn->description, 79);
              desc_short[79] = '\0';
              DrawTextC(desc_short,
                        rx + 20 + svw + MeasureText(vn->cve_id, 8) + 8, vy + 3,
                        8, COLOR_TEXT_DIM);
              vy += 16;
            }
          }
        }
        ry2 += row_h;
      }
      EndScissorMode();
      draw_custom_scrollbar(rx + result_w - 10, list_y0, 10, list_h, total_h,
                            &g_scroll_tool_ports);
    }
  }
  else if (g_tools_subtab == 3) {
    /* === Kameralar (Kesif / Erisim / Izleme) === */
    gui_camera_draw_tools_panel(W, H);
  }
}


/* ========== Public API ========== */
void gui_init(int width, int height) {
  (void)width;
  (void)height;

  /* Pencere: boyutlandirilabilir + MSAA */
  SetConfigFlags(FLAG_WINDOW_RESIZABLE | FLAG_MSAA_4X_HINT);
  InitWindow(1280, 720, "BEAT System");

  /* FLAG_WINDOW_MAXIMIZED bayragi raylib'de güvenilir çalışmıyor;
   * MaximizeWindow() ile açıkça maximize ediyoruz. */
  MaximizeWindow();
  SetWindowMinSize(800, 600);

  SetTargetFPS(30);

  /* raygui style — siyah temaya uygun */
  GuiSetStyle(DEFAULT, TEXT_SIZE, 12);
  GuiSetStyle(DEFAULT, BACKGROUND_COLOR, ColorToInt(COLOR_PANEL));
  GuiSetStyle(BUTTON, BASE_COLOR_NORMAL, ColorToInt(COLOR_SURFACE2));
  GuiSetStyle(BUTTON, BASE_COLOR_FOCUSED,
              ColorToInt(ui_mix(COLOR_SURFACE2, COLOR_ACCENT, 0.16f)));
  GuiSetStyle(BUTTON, BASE_COLOR_PRESSED,
              ColorToInt(ui_mix(COLOR_SURFACE2, COLOR_BG, 0.5f)));
  GuiSetStyle(BUTTON, TEXT_COLOR_NORMAL, ColorToInt(COLOR_TEXT));
  GuiSetStyle(BUTTON, TEXT_COLOR_FOCUSED, ColorToInt(COLOR_ACCENT));
  GuiSetStyle(BUTTON, TEXT_COLOR_PRESSED, ColorToInt(COLOR_ACCENT2));
  GuiSetStyle(BUTTON, BORDER_COLOR_NORMAL, ColorToInt(COLOR_BORDER));
  GuiSetStyle(BUTTON, BORDER_COLOR_FOCUSED,
              ColorToInt(ui_alpha(COLOR_ACCENT, 220)));
  GuiSetStyle(BUTTON, BORDER_WIDTH, 1);

  /* Filtre kutusu (GuiTextBox) koyu temaya uysun */
  GuiSetStyle(TEXTBOX, BASE_COLOR_NORMAL, ColorToInt(COLOR_SURFACE2));
  GuiSetStyle(TEXTBOX, BASE_COLOR_FOCUSED,
              ColorToInt(ui_mix(COLOR_SURFACE2, COLOR_ACCENT, 0.22f)));
  GuiSetStyle(TEXTBOX, BASE_COLOR_PRESSED,
              ColorToInt(ui_mix(COLOR_SURFACE2, COLOR_ACCENT, 0.22f)));
  GuiSetStyle(TEXTBOX, TEXT_COLOR_NORMAL, ColorToInt(COLOR_TEXT));
  GuiSetStyle(TEXTBOX, TEXT_COLOR_FOCUSED, ColorToInt(COLOR_ACCENT));
  GuiSetStyle(TEXTBOX, BORDER_COLOR_NORMAL, ColorToInt(COLOR_BORDER));
  GuiSetStyle(TEXTBOX, BORDER_COLOR_FOCUSED,
              ColorToInt(ui_alpha(COLOR_ACCENT, 220)));
  GuiSetStyle(TEXTBOX, BORDER_WIDTH, 1);

  /* TTF Font yukle ve yapilandir.
   * Yol calisma dizinine degil, calistirilabilir dosyanin konumuna gore
   * cozulur: boylece uygulama herhangi bir dizinden baslatilsa da
   * (ornek: proje kokunden ./build/beat_system) ayni gorunumu verir. */
  {
    const char *app_dir = GetApplicationDirectory();
    const char *candidates[] = {
      TextFormat("%s../assets/fonts/Roboto-Regular.ttf", app_dir),
      TextFormat("%sassets/fonts/Roboto-Regular.ttf", app_dir),
      "assets/fonts/Roboto-Regular.ttf",    /* CWD = proje koku */
      "../assets/fonts/Roboto-Regular.ttf", /* CWD = build/ (eski davranis) */
    };
    const char *font_path = 0;
    for (int i = 0; i < (int)(sizeof(candidates) / sizeof(candidates[0]));
         i++) {
      if (FileExists(candidates[i])) {
        font_path = candidates[i];
        break;
      }
    }
    if (font_path) {
      /* Türkçe glifler (ıİşŞğĞçÇöÖüÜ) ASCII'de yok; LoadFontEx'e codepoints
       * verilmezse yalnızca ASCII (ilk 250 glif) yüklenir ve Türkçe harfler
       * '?' olarak çizilir. Latin-1 Supplement + Latin Extended-A'yı (0xA0..
       * 0x017F) ve arayüzde kullanılan ek işaretleri açıkça istiyoruz. */
      int cps[0x0180 - 0x20 + 16];
      int n = 0;
      for (int cp = 0x20; cp < 0x7F; cp++)   cps[n++] = cp; /* ASCII */
      for (int cp = 0xA0; cp < 0x0180; cp++) cps[n++] = cp; /* Latin-1 + Ext-A */
      {
        static const int extras[] = {0x2013, 0x2014, 0x2018, 0x2019,
                                     0x201C, 0x201D, 0x2022, 0x2026,
                                     0x2192, 0x25B8};
        for (unsigned k = 0; k < sizeof(extras) / sizeof(extras[0]); k++)
          cps[n++] = extras[k];
      }
      g_custom_font = LoadFontEx(font_path, 64, cps, n);
      TraceLog(LOG_INFO, "FONT: %s yüklendi (%d glif)", font_path, n);
    } else {
      TraceLog(LOG_WARNING,
               "FONT: Roboto-Regular.ttf bulunamadı, varsayılan fonta düşülüyor");
    }
  }
  if (g_custom_font.texture.id > 0) {
    SetTextureFilter(g_custom_font.texture, TEXTURE_FILTER_BILINEAR);
    GuiSetFont(g_custom_font);
  }

  /* Kamera kesif/erisim/izleme modulu (backend + yuzeyler) */
  gui_camera_init();
}

void gui_cleanup(void) {
  gui_camera_cleanup();
  if (g_custom_font.texture.id > 0)
    UnloadFont(g_custom_font);
  CloseWindow();
}

int gui_should_close(void) { return WindowShouldClose(); }

Font  gui_font(void)  { return g_custom_font; }
float gui_scale(void) { return g_ui_scale; }

void gui_draw(void) {
  int monitor = GetCurrentMonitor();
  int m_height = GetMonitorHeight(monitor);
  if (m_height <= 0)
    m_height = GetScreenHeight();

  /* Monitor cozunurlugune gore olcek (720p -> 1.0, 1080p -> 1.5, 2K -> 2.0,
   * 4K -> 3.0). Text'lerin kucuk kalmamasi icin native DPI tarzi olcek. */
  g_ui_scale = (float)m_height / 720.0f;
  if (g_ui_scale < 0.8f)
    g_ui_scale = 0.8f;

  int W = GetScreenWidth();
  int H = GetScreenHeight();

  /* Mantiksal (Logical) ekran boyutunu hesapla */
  int V_WIDTH = (int)(W / g_ui_scale);
  int V_HEIGHT = (int)(H / g_ui_scale);

  /* Mouse koordinatlarini logical koordinatlara cevir */
  SetMouseScale(1.0f / g_ui_scale, 1.0f / g_ui_scale);
  SetMouseOffset(0, 0);

  /* Periyodik veri yenileme (her 2 saniye) */
  double now = GetTime();
  if (now - g_last_refresh > 2.0) {
    scanner_get_results(&g_scan);
    scanner_get_log(&g_scanlog);

    /* Arayuz degisti (enp6s0 dustu -> wlan0 kaldi): aktif izleme eski
       NIC'e takili kalmasin; yeni default-route arayuzunde yeniden
       baslat (spoof dahil). Tarayici her taramada local_iface'i
       canli gunceller. */
    if ((g_capture_all || g_capture_active_ip[0]) && g_scan.local_iface[0] &&
        g_capture_iface[0] && strcmp(g_capture_iface, g_scan.local_iface) != 0) {
      fprintf(stderr,
              "[GUI] Arayüz değişti: %s -> %s, izleme yeniden başlatılıyor\n",
              g_capture_iface, g_scan.local_iface);
      int was_all = g_capture_all;
      char saved_ip[MAX_IP_LEN];
      strncpy(saved_ip, g_capture_active_ip, MAX_IP_LEN - 1);
      capture_stop_all();
      if (was_all)
        capture_start_all();
      else if (saved_ip[0])
        capture_start_for(saved_ip);
    }

    ids_set_mac_context(g_scan.local_mac, g_scan.gateway_mac,
                        g_scan.gateway_ip, g_scan.local_ip);
    arp_block_set_context(g_scan.local_iface, g_scan.local_mac,
                          g_scan.gateway_ip, g_scan.gateway_mac,
                          g_scan.local_ip);
    blocklist_refresh();
    g_ids_alert_count =
        ids_get_alerts_snapshot(g_ids_alerts_snapshot, IDS_MAX_GUI_ALERTS);
    ids_rebuild_alert_view();
    if (g_capture_all) {
      /* Izleme listesi kapsami: yalnizca listedeki cihazlar spoof edilir.
       * Bos listede izleme zaten baslatilamaz (capture_start_all kapisi). */
      Device mondevs[MAX_DEVICES];
      int mcnt = 0;
      for (int mi = 0; mi < g_scan.device_count && mcnt < MAX_DEVICES; mi++)
        if (mon_list_has(g_scan.devices[mi].ip))
          mondevs[mcnt++] = g_scan.devices[mi];
      arp_spoof_sync_targets(mondevs, mcnt, g_scan.gateway_ip,
                             g_scan.local_ip);
    }
    g_last_refresh = now;
  }

  /* Kamera modulu: backend durum senkronizasyonu + stream yoklama */
  gui_camera_tick();

  BeginDrawing();
  ClearBackground(COLOR_BG);

  /* Vektorel zoom islemini uygulayan kamera */
  Camera2D camera = {0};
  camera.zoom = g_ui_scale;
  BeginMode2D(camera);

  /* Butun cizimler logical boyutlarda yapilir */
  draw_header(V_WIDTH);
  draw_tabs(V_WIDTH);

  switch (g_active_tab) {
  case TAB_DASHBOARD:
    draw_panel_dashboard(V_WIDTH, V_HEIGHT);
    break;
  case TAB_SECURITY:
    draw_panel_security(V_WIDTH, V_HEIGHT);
    break;
  case TAB_TOOLS:
    draw_panel_tools(V_WIDTH, V_HEIGHT);
    break;
  default:
    break;
  }

  EndMode2D();
  EndDrawing();

  /* Input state reset (sistem diger elemanlari etkilemesin diye) */
  SetMouseScale(1, 1);
}

void gui_select_device(const char *ip) {
  strncpy(g_selected_device_ip, ip, MAX_IP_LEN - 1);
  g_scroll_device_detail = 0;
}