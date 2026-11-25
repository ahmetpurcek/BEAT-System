/*
 * gui.h — raylib GUI Modülü (BEAT System)
 *
 * BEAT System arayuzu:
 *  - Koyu gri zemin, siyah paneller, kirmizi ve koyu sari aksan
 *  - Sekmeler: Kontrol Paneli / Alarm Merkezi / Paket Izleme /
 *    Port Tarayici / Site Karartma / SENTINEL
 *  - Tum backend yuzeyi cizilir: ag taramasi, IDS alarmlari,
 *    paket yakalama (Wireshark-tarzi PDU + hex), port taramasi + CVE.
 */
#ifndef GUI_H
#define GUI_H
#include "raylib.h"

/* ============================================================
 * BEAT System Paleti
 * Agirlik: koyu gri > siyah > kirmizi > koyu sari
 * Kucuk durum isaretlerinde (acik/kapali, onem) ek renkler kalir.
 * ============================================================ */

/* Zeminler — cogunluk koyu gri, derin alanlar siyah */
#define COLOR_BG            (Color){ 46,  46,  50, 255 }  /* koyu gri */
#define COLOR_PANEL         (Color){ 34,  34,  38, 255 }  /* koyu gri panel */
#define COLOR_PANEL_HOVER   (Color){ 62,  58,  56, 255 }
#define COLOR_SURFACE       (Color){ 24,  24,  26, 255 }  /* siyaha yakin */
#define COLOR_SURFACE2      (Color){ 54,  52,  50, 255 }
#define COLOR_BORDER        (Color){ 82,  76,  72, 210 }
#define COLOR_HEADER_BG     (Color){ 10,  10,  12, 255 }  /* siyah */
#define COLOR_TERMINAL_BG   (Color){  6,   6,   8, 255 }  /* siyah */

/* Aksanlar — kirmizi, sonra kirmiziyla uyumlu koyu sari */
#define COLOR_ACCENT        (Color){ 196,  42,  44, 255 }  /* kirmizi */
#define COLOR_ACCENT2       (Color){ 176, 140,  42, 255 }  /* koyu sari */
#define COLOR_GREEN         (Color){  72, 158, 108, 255 }  /* kucuk: acik */
#define COLOR_AMBER         (Color){ 176, 140,  42, 255 }
#define COLOR_RED           (Color){ 214,  64,  58, 255 }

/* Onem derecesi (kucuk rozetler, ayirt edilebilir):
 * KRITIK=kirmizi, YUKSEK=turuncu, ORTA=koyu sari, DUSUK=yesil. */
#define COLOR_ORANGE        (Color){ 188,  92,  40, 255 }
#define COLOR_YELLOW        (Color){ 196, 164,  58, 255 }
#define COLOR_CYAN          (Color){ 176, 172, 166, 255 }  /* protokol: acik gri */

/* Metin */
#define COLOR_TEXT          (Color){ 236, 232, 226, 255 }
#define COLOR_TEXT_SEC      (Color){ 188, 182, 174, 255 }
#define COLOR_TEXT_DIM      (Color){ 138, 132, 126, 255 }

/* Etkilesim */
#define COLOR_SELECTED      (Color){ 196,  42,  44,  52 }
#define COLOR_SCROLLBAR     (Color){ 122,  78,  72, 190 }

/* ========== Tabs ========== */
typedef enum {
    TAB_DASHBOARD = 0,
    TAB_SECURITY,
    TAB_PACKETS,    /* Paket Izleme */
    TAB_PORTS,      /* Port Tarayici */
    TAB_SITE_BLOCK, /* Site Karartma (ust seviye sekme) */
    TAB_SENTINEL,   /* SENTINEL v2 — otonom kamera istismar hatti */
    TAB_COUNT
} GuiTab;

/* ========== Paylasilan cizim baglami (gui_camera vb. moduller icin) ========== */
Font  gui_font(void);   /* aktif TTF (yoksa texture.id==0) */
float gui_scale(void);  /* mantiksal->fiziksel olcek (Camera2D zoom) */

/* ========== Genel API (degismedi) ========== */
void gui_init(int width, int height);
void gui_cleanup(void);
void gui_draw(void);
int  gui_should_close(void);
void gui_select_device(const char *ip);

#endif /* GUI_H */

