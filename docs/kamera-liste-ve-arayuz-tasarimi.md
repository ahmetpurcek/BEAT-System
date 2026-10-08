# BEAT System — Kamera Listesi ve Arayüz Tasarımı

Tarih: 2026-10-02
Bağlam: Mevcut "İzleme Listesi" desenine paralel, **bağımsız bir kamera listesi**
ve bu listeye göre çalışan **Araçlar içi kamera arayüzü** tasarımı.
Referans kod: `src/gui.c` — `draw_mon_list_panel`, `g_mon_ips[]`,
`mon_list_toggle()`, `mon_list_sync_scope()`.
Durum: Tasarım / tartışma.

---

## 0. Kavramsal karar: EVET, ayrı liste doğru

**Öneri: Kamera listesi, İzleme Listesi'nden ayrı olmalı.** Gerekçe = sorumluluk
ayrımı (separation of concerns). İki liste farklı işler yapar:

| | İzleme Listesi (mevcut) | Kamera Listesi (yeni) |
|---|---|---|
| Amaç | **Pasif** paket kapsamı | **Aktif** erişim oturumları |
| Etki | IDS + site karartma + ARP spoof hangi IP'lere uygulanır | Hangi kameralar keşfedildi / erişildi / izleniyor |
| Yaşam döngüsü | Sürekli (~sn) | Uzun ömürlü (akış oturumları) |
| Satır içeriği | Sadece IP (+MAC) | IP, MAC, model, **durum**, akış URI, bulunan kimlik |
| Bağımlılık | IDS/`site_block` motorları | FFmpeg/ONVIF/`camera_ingest` |

İkisini tek listede birleştirmek, "izleme kapsamı" kavramını kirletir ve kamera
durum alanlarını İzleme Listesi'ne sıkıştırmaya zorlar. **Ayrı tutmak temiz.**

Ama ikisi arasında **isteğe bağlı bir köprü** olmalı (§4), çünkü bir kamerayı
"hacklemek" çoğu zaman onun trafiğini de izlemek ister.

---

## 1. Veri modeli (mevcut desenden türetilmiş)

Mevcut İzleme Listesi sadece IP tutar (`char g_mon_ips[][MAX_IP_LEN]`). Kamera
listesi ise **satır başına durum** gerektirir, bu yüzden düz IP dizisi yetmez:

```c
/* Kamera erişim durumu (rozet için) */
typedef enum {
    CAM_DISCOVERED = 0,   /* keşfedildi */
    CAM_TRYING,           /* erişim deneniyor */
    CAM_OPEN,             /* kimliksiz açık akış */
    CAM_CREDS_FOUND,      /* parola/varsayılan bulundu */
    CAM_ACCESSED,         /* erişildi (oturum açık) */
    CAM_STREAMING,        /* canlı izleniyor */
    CAM_FAILED            /* erişilemedi */
} CamState;

typedef struct {
    char    ip[MAX_IP_LEN];
    char    mac[MAX_MAC_LEN];
    char    vendor[MAX_VENDOR_LEN];   /* Hikvision / Dahua / ... */
    char    model[64];
    CamState state;
    char    stream_uri[256];          /* aktif RTSP/HTTP akış */
    int     flags;                    /* kimlik bulundu, kayıt açık, PTZ var ... */
} CamEntry;

#define CAM_LIST_MAX 128
static CamEntry g_cams[CAM_LIST_MAX];
static int      g_cam_count = 0;
static float    g_scroll_cam_list = 0;
static int      g_cam_selected = -1;   /* Araçlar'da odaklanan kamera */
```

Fonksiyonlar (mevcut `mon_list_*` ile birebir simetri):
`cam_list_has()`, `cam_list_add()`, `cam_list_remove_at()`,
`cam_list_sync()` (oturumları `camera_ingest` motoruna yansıtır — tıpkı
`mon_list_sync_scope()`'un `ids_scope_set`'e yansıması gibi).

---

## 2. Ana Sayfa (Dashboard) yerleşimi

**Sağ kolonda İzleme Listesi'nin ALTINA** ikinci panel: `draw_cam_list_panel`

```
┌─ Kontrol Paneli (Dashboard) ──────────────────────────────────────┐
│  [İstatistik kartları]                                             │
│ ┌── Sol ──────────┐ ┌── Orta/Sağ ─────────────────────────────┐   │
│ │ Cihaz listesi   │ │  IZLEME LISTESI        (mevcut panel)   │   │
│ │ (tarama sonucu) │ │  [TÜMÜNÜ EKLE] [BOŞALT]                 │   │
│ │ 192.168.1.10    │ │  192.168.1.10  aa:bb:..   [x]           │   │
│ │ 192.168.1.23 📷 │ │  192.168.1.23  cc:dd:..   [x]           │   │
│ │ ...             │ ├─────────────────────────────────────────┤   │
│ │                 │ │  KAMERA LISTESI        (YENİ panel)     │   │
│ │                 │ │  [KAMERALARI BUL] [BOŞALT] [IDS'E EKLE] │   │
│ │                 │ │  📷 .23 Hikvision  ● açık akış   [x]    │   │
│ │                 │ │  📷 .31 Dahua      🔑 parola     [x]    │   │
│ │                 │ │  📷 .44 Xiongmai   ⚠ deneniyor   [x]    │   │
│ │                 │ │  📷 .57 Axis       ❌ erişilemedi [x]   │   │
│ └─────────────────┘ └─────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────┘
```

- Panel görsel dili **İzleme Listesi ile aynı**: `DrawRoundedPanel`,
  `draw_panel_title`, `BeginScissorModeScaled` + `draw_custom_scrollbar`,
  satır = IP + MAC/model, sağda `X`, satıra tıkla → `g_selected_device_ip`
  (cihaz detayını açar) VEYA `g_cam_selected` (kamera odağı).
- **Ayrı renk vurgusu:** İzleme Listesi başlığı `COLOR_GREEN`; Kamera Listesi
  başlığı farklı bir aksan (örn. `COLOR_ACCENT`/cyan) → gözle ayrılır.
- **Butonlar:** `KAMERALARI BUL` (keşif: OUI+ONVIF+port), `BOŞALT`,
  opsiyonel `IDS'E EKLE` (§4).
- Yerleşim sıkışırsa: iki panel dikey **split** (İzleme üstte, Kamera altta),
  mevcut cihaz/log paneli ikilisindeki gibi esnek yükseklik.

---

## 3. Araçlar (Tools) içi kamera arayüzü

Mevcut Araçlar alt sekmeleri: `Paket İzleme | Site Karartma | Port Tarayıcı`
(`g_tools_subtab`, `stabs[]`). **Yeni 4. alt sekme: `Kameralar`.**

Yerleşim, mevcut **Port Tarayıcı** deseninin aynısı (solda liste, sağda detay):

```
┌─ Araçlar ▸ Kameralar ─────────────────────────────────────────────┐
│ Paket İzleme | Site Karartma | Port Tarayıcı | [ KAMERALAR ]      │
├───────────────────────┬───────────────────────────────────────────┤
│ KAMERA LISTESI        │   SEÇİLİ KAMERA                           │
│ (g_cams — aynı liste) │   ┌───────────────────────────────────┐   │
│                       │   │                                   │   │
│ 📷 .23 Hikvision      │   │        CANLI GÖRÜNTÜ              │   │
│    ● açık akış        │   │     (raylib texture — içeride)    │   │
│ 📷 .31 Dahua          │   │                                   │   │
│    🔑 parola          │   └───────────────────────────────────┘   │
│ 📷 .44 Xiongmai       │   Durum: 🔑 erişildi | 1080p H.264 | 25fps│
│    ⚠ deneniyor        │   Akış: rtsp://192.168.1.31:554/...       │
│ 📷 .57 Axis           │                                           │
│    ❌ erişilemedi     │   [ İzle ] [ Anlık Görüntü ] [ Kayıt ]    │
│                       │   [ PTZ ◀ ▲ ▼ ▶ ] [ Tam Ekran ]           │
│ [KAMERALARI BUL]      │   [ Yeniden Eriş ] [ Listeden Çıkar ]     │
│ [Hepsini İzle]        │                                           │
└───────────────────────┴───────────────────────────────────────────┘
```

Önemli: **Bu sekme ile ana sayfadaki panel AYNI listeyi (`g_cams`) kullanır.**
Yani ana sayfada kamera eklersen Araçlar'da görürsün; Araçlar'da kamera
keşfedersen ana sayfa panelinde düşer. (Tıpkı İzleme Listesi'nin tutarlı
olması gibi — tek doğruluk kaynağı.)

Sol liste satırına tıkla → sağ panel o kameraya **odaklanır** → `İzle` ile
`camera_ingest` o kamera için decode thread'ini başlatır → görüntü
**raylib dokusunda, bu pencerenin içinde** akar (harici pencere yok).

---

## 4. İki liste arası köprü (öneri)

Kamera listesi bağımsız ama **isteğe bağlı köprü** iki yönlü fayda sağlar:

1. **`IDS'E EKLE` / otomatik:** Bir kamera listeye eklenince (veya erişilince)
   IP'si İzleme Listesi'ne de eklenir → IDS o kameranın trafiğini puanlar,
   RTSP brute/keşif uyarıları üretir, site karartma kapsamına girer.
   - Tasarım kararı: **manuel buton** mu, **otomatik** mu? (bkz. §7)
2. **Ters yön:** İzleme Listesi'ndeki bir IP kamera olarak sınıflandırılırsa
   Kamera Listesi'ne "öneri" olarak düşebilir (henüz denyelenmedi).

Bu köprü, mevcut `mon_list_sync_scope()`'un aynadaki karşılığıdır: kamera
listesi değişince `cam_list_sync()` ilgili motorları (camera_ingest; istenirse
`ids_scope`/`site_block`) günceller.

---

## 5. Durum rozetleri (satır ikonları)

`draw_badge()` ile, mevcut alarm rozetleri diliyle:

| Rozet | Anlam |
|---|---|
| 📷 | kamera (sınıflandırıldı) |
| ● yeşil | açık akış (kimlik yok) — RISK_CRITICAL |
| 🔑 sarı | varsayılan/parola bulundu |
| ⚠ turuncu | erişim deneniyor |
| ▶ mavi | canlı izleniyor |
| ⏺ kırmızı | kayıt açık |
| ❌ kırmızı | erişilemedi / çevrimdışı |

---

## 6. Kod entegrasyon noktaları (mevcut gui.c'ye göre)

Yeni state + fonksiyonlar:
- `g_cams[]`, `g_cam_count`, `g_cam_selected`, `g_scroll_cam_list`
- `cam_list_has/add/remove_at/sync`
- `draw_cam_list_panel(rx, ry, rw, rh)` — ana sayfa (İzleme Listesi'nin altı)
- `draw_panel_cameras(W,H)` — Araçlar alt sekmesi

Dokunulacak yerler:
- `draw_panel_dashboard()` (~L649): sağ kolona ikinci panel çağrısı.
- `draw_panel_tools()` (~L1470): `stabs[]`'e 4. giriş `"Kameralar"`,
  `g_tools_subtab == 3` dalı.
- `draw_panel_tools` alt dalları (~L1501 / 2272 / 2656): yeni `== 3` dalı.
- `include/gui.h`: yeni sekme sabiti gerekirse.

Motor tarafı (ayrı dosyalar): `camera_ingest.c`, `onvif_client.c`,
`video_surface.c` (bkz. `docs/kamera-coklu-ofis-tasarimi.md`).

---

## 7. Karar için sorular

1. Kamera listesi eklenince IP **otomatik** İzleme Listesi'ne de girsin mi,
   yoksa **manuel buton** mu olsun? (IDS görünürlüğü için öneri: otomatik +
   kapatılabilir anahtar.)
2. Kamera paneli ana sayfada İzleme Listesi'nin **altında** mı (öneri), yoksa
   **ayrı bir sekmede** mi dursun?
3. Araçlar içi kamera sekmesi, **Port Tarayıcı** deseni gibi solda liste/sağda
   detay mı olsun (öneri), yoksa tam ekran tek odak mı?
4. Aynı anda kaç kamera **canlı** çözülecek (duvar boyutu)? (§ çoklu-ofis
   tasarımındaki decode tavanı belirler.)
5. Kamera listesi **kalıcı** mı olsun (uygulama kapanınca kaydedilsin) yoksa
   oturumluk mu? (mevcut İzleme Listesi oturumluk görünüyor.)
```
