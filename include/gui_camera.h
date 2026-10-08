/*
 * gui_camera.h — BEAT System: Kamera Keşif / Erişim / İzleme arayüzü
 *
 * gui.c'den AYRI, kendi kendine yeten (self-contained) bir GUI modülü.
 * Backend motorlarını (camera_discovery / camera_access / camera_vuln /
 * video_stream) doğrudan sürer ve raylib çizim yardımcılarını kendi içinde
 * yeniden uygular (gui.c'deki static yardımcılar modülden erişilemez).
 *
 * Sağlanan iki yüzey:
 *   1) gui_camera_draw_list_panel()  → Dashboard sağ kolonunda KAMERA LİSTESİ
 *   2) gui_camera_draw_tools_panel() → Araçlar ▸ "Kameralar" alt sekmesi
 *
 * Tek doğruluk kaynağı: bu modülün içindeki tek kamera listesi (g_e[]).
 * Ana sayfa ve Araçlar AYNI listeyi kullanır.
 */
#ifndef GUI_CAMERA_H
#define GUI_CAMERA_H

#include "raylib.h"

/* Yaşam döngüsü: backend init/cleanup + stream sistemi. gui_init/cleanup'tan
 * çağrılır. Idempotent. */
void gui_camera_init(void);
void gui_camera_cleanup(void);

/* Her frame (BeginDrawing'den önce): backend durumlarını senkronlar,
 * erişim işlerini ve video akışlarını yoklar. */
void gui_camera_tick(void);

/* (Opsiyonel) Dışarıdan odaklanacak kamera IP'si seç (gui_select_device benzeri). */
void gui_camera_select(const char *ip);

/* Bilgi: şu an izlenen (aktif akışı olan) kamera sayısı. */
int  gui_camera_active_streams(void);

/* ===== Çizim yüzeyleri (gui.c içinden çağrılır) ===== */

/* Dashboard sağ kolonunda, İzleme Listesi'nin altına çizilir. */
void gui_camera_draw_list_panel(int rx, int ry, int rw, int rh);

/* Araçlar ▸ Kameralar alt sekmesinin tüm içeriği (W,H = mantıksal ekran). */
void gui_camera_draw_tools_panel(int W, int H);

#endif /* GUI_CAMERA_H */
