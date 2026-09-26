/*
 * gui.h — raylib GUI Modülü (v3 — BEAT System Siyah Tema)
 *
 * BEAT System arayuzu. v3 tasarimi:
 *  - Saf siyah zemin + neon cyan aksan (NOC gorunumu)
 *  - Tabs: Kontrol Paneli / Alarm Merkezi / Araclar
 *  - Tum backend yuzeyi cizilir: ag taramasi, IDS alarmlari,
 *    paket yakalama (Wireshark-tarzi PDU + hex), port taramasi + CVE.
 */
#ifndef GUI_H
#define GUI_H
#include "raylib.h"

/* ============================================================
 * BEAT System Paleti — siyah ana renk, neon cyan/yesil aksanlar
 * ============================================================ */

/* Zeminler (saf siyah -> panel grileri) */
#define COLOR_BG            (Color){  4,   6,  10, 255 }
#define COLOR_PANEL         (Color){  9,  12,  19, 255 }
#define COLOR_PANEL_HOVER   (Color){ 18,  25,  40, 255 }
#define COLOR_SURFACE       (Color){ 11,  15,  23, 255 }
#define COLOR_SURFACE2      (Color){ 19,  26,  41, 255 }
#define COLOR_BORDER        (Color){ 42,  58,  88, 200 }
#define COLOR_HEADER_BG     (Color){  5,   7,  12, 255 }
#define COLOR_TERMINAL_BG   (Color){  2,   4,   7, 255 }

/* Aksanlar */
#define COLOR_ACCENT        (Color){  0, 229, 255, 255 }  /* neon cyan */
#define COLOR_ACCENT2       (Color){ 172, 130, 255, 255 } /* neon mor  */
#define COLOR_GREEN         (Color){  52, 211, 153, 255 } /* emerald   */
#define COLOR_AMBER         (Color){ 251, 191,  36, 255 } /* amber     */
#define COLOR_RED           (Color){ 248, 113, 113, 255 } /* soft red  */

/* Onem derecesi gradyani (birbirinden AYIRT EDILEBILIR olmali):
 * KRITIK=kirmizi, YUKSEK=turuncu, ORTA=sari, DUSUK=yesil. */
#define COLOR_ORANGE        (Color){ 249, 115,  22, 255 } /* turuncu (YUKSEK) */
#define COLOR_YELLOW        (Color){ 250, 211,  21, 255 } /* sari    (ORTA)   */
#define COLOR_CYAN          (Color){ 125, 224, 255, 255 } /* acik cyan */

/* Metin */
#define COLOR_TEXT          (Color){ 232, 240, 252, 255 }
#define COLOR_TEXT_SEC      (Color){ 148, 168, 200, 255 }
#define COLOR_TEXT_DIM      (Color){  92, 110, 138, 255 }

/* Etkilesim */
#define COLOR_SELECTED      (Color){  0, 229, 255,  30 }
#define COLOR_SCROLLBAR     (Color){  95, 135, 185, 170 }

/* ========== Tabs ========== */
typedef enum {
    TAB_DASHBOARD = 0,
    TAB_SECURITY,
    TAB_TOOLS,
    TAB_COUNT
} GuiTab;

/* ========== Genel API (degismedi) ========== */
void gui_init(int width, int height);
void gui_cleanup(void);
void gui_draw(void);
int  gui_should_close(void);
void gui_select_device(const char *ip);

#endif /* GUI_H */

