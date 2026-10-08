# BEAT System — Çok Kameralı Ofis Dağıtımı ve Uygulama-İçi Görüntüleme Tasarımı

Tarih: 2026-10-02
Bağlam: Kamera sayısının yüksek olduğu (ofis/şirket) bir ağda BEAT'ın en
**optimal** biçimde kamera görüntülerini elde etmesi ve bunları **uygulama
penceresi içinde** (harici tarayıcı / VLC penceresi olmadan) göstermesi.
Durum: Tasarım / tartışma. Kod yazılmadı.

---

## 0. Temel fikir (tek paragraf)

"N kamera" problemini tek katmanla çözmek yanlıştır. Optimum çözüm
**iki katmanlı akış** ve **tek bağlamda render**'dır:

1. **Duvar katmanı (wall):** her kameranın **alt akışından (substream)**, düşük
   çözünürlükte, düşük FPS'te (2–5 fps) küçük önizlemeler. Ucuz, hafif, ölçeklenir.
2. **Odak katmanı (focus):** kullanıcının seçtiği **tek** kamera ana akıştan
   (main stream) tam çözünürlük/FPS'te.

Her iki katman da **FFmpeg ile çözülür ve doğrudan raylib dokusuna (Texture2D)
yazılır** — yani görüntü BEAT penceresinin içinde, kendi grid düzeninde görünür.
Hiçbir aşamada harici bir pencere açılmaz.

Bu, gerçek dünyadaki NVR/VMS yazılımlarının (Milestone, Blue Iris, Shinobi)
yaptığının aynısıdır ve "çok kamera"yı mümkün kılan tek yaklaşımdır.

---

## 1. Neden alt akış (substream) şart?

Neredeyse tüm IP kameralar **iki (veya üç) akış profili** yayınlar:

| Profil | Tipik çözünürlük | Bit hızı | Kullanım |
|---|---|---|---|
| Ana akış | 1080p / 4MP / 4K | 2–8 Mbps | Kayıt, tam ekran odak |
| Alt akış | D1 / 640×360 / 704×576 | 0.3–1 Mbps | Duvar, mobil, önizleme |

Hikvision: `.../Streaming/Channels/101` (main), `102` (sub)
Dahua: `subtype=0` (main), `subtype=1` (sub)
Diğer: ONVIF `GetProfiles` ile ikisi de listelenir.

**Kritik sonuç:** 32 kamerayı ana akıştan çözmek = ~100–250 Mbps bant + çok ağır
CPU/GPU. Alt akıştan çözmek = ~10–30 Mbps + binde bir CPU. Görsel kalite düşer
ama önizleme için yeterlidir. Odaktaki tek kamera ana akıştan alınır.

> **Optimum kural:** Duvar daima alt akış + düşük FPS; tam kalite yalnız
> odaklanan kamerada ve yalnız gerektiğinde.

---

## 2. Uçtan uca veri hattı

```
[KEŞİF]  ONVIF WS-Discovery + OUI + port imzası
             │  (kamera IP, model, firmware)
             ▼
[PROFİL]  ONVIF GetProfiles → main URI + sub URI + snapshot URI
             │  (bazı kameralar ONVIF konuşmaz → RTSP yolu elle/şablonla)
             ▼
[OTURUM]  Kamera = bir "oturum": creds + main/sub URI + durum
             │
             ▼
[ÇÖZME]   FFmpeg: rtsp (TCP) → demux → decode → sws_scale RGBA
             │  her kamera için 1 decode thread, "en son kare" yuvası
             ▼
[RENDER]  raylib Texture2D.UpdateTexture(RGBA) → grid hücresi
             │
             ▼
[GUI]     KAMERALAR sekmesi: oturum listesi + video duvarı + odak paneli
```

---

## 3. Uygulama-içi render (meterpreter benzeri "session" modeli)

Kullanıcının istediği şey tam olarak şu: **harici pencere yok, her şey tek
pencerede.** Meterpreter'da bir session seçip içinde çalışırsın; burada da bir
kamera "oturumu" seçip akışı içeride görürsün.

### 3.1 Render yolu (raylib)
- FFmpeg kareyi **RGBA8888**'e çevirir (sws_scale).
- Kamera başına bir `Texture2D` tutulur; her yeni karede
  `UpdateTexture(tex, rgba_pixels)` çağrılır (CPU→GPU kopya).
- `DrawTexturePro` ile hücreye ölçeklenir. Grid, `Camera2D`/`BeginMode2D`
  altyapınızla zoom'lanabilir (gui.c'de zaten var).

Bu yaklaşım **hiçbir X11/OS penceresi açmaz**, tarayıcıya çıkmaz, VLC çağırmaz.
Her şey BEAT'in OpenGL bağlamında.

### 3.2 Alternatif: libVLC callback yolu
FFmpeg'e alternatif olarak `libvlc_video_set_callbacks` ile VLC'yi kendi bellek
tamponunuza çizdirebilirsiniz; o zaman da pencere açılmaz.
- **Artı:** RTSP/RTSP-over-HTTP/kodek uyumluluğu çok geniştir, hızlı başlar.
- **Eksi:** ağır bağımlılık; çok akışta kaynak yönetimi FFmpeg kadar esnek değil;
  donanım hızlandırmada ince kontrol az.

**Öneri:** Ana yol **FFmpeg**; istenirse libVLC "uyumluluk fallback'i" olarak
opsiyonel eklenir (tıpkı OpenSSL gibi `HAVE_LIBVLC`).

### 3.3 Neden RGBA/swscale MVP için yeterli?
Duvar hücreleri küçük (örn. 160×90…320×180). Bu çözünürlükte swscale maliyeti
ihmal edilebilir. Üst düzey optimizasyon (aşağıda §5) yalnız odak/4K ve yüksek
kamera sayısında gerekir.

---

## 4. İş parçacığı ve performans mimarisi

### 4.1 Kamera başına decode thread + "en son kare" yuvası
Her kamera için tek bir decode thread:
```
loop:
  av_read_frame() → decode
  sws_scale() → rgba
  kilit altında "latest frame" slotunu ez   ← eski kare ATILIR (frame drop)
```
GUI ana thread'i **yalnız** en son kareyi texture'a yükler. Böylece:
- Yavaş çözen kamera GUI'yi **bloklamaz**.
- Geride birikme olmaz; her zaman **en güncel** kare gösterilir (canlı hissi).
- En kritik performans kuralı budur: **kuyruk değil, son-kare yuvası.**

### 4.2 FPS bütçesi (ölçeklenebilirlik anahtarı)
- Duvar kameraları: hedef **2–5 fps** (önizleme yeterli).
- Odaktaki kamera: **15–30 fps**.
- Kare işleme, hücre görünür değilken **durdurulur** (grid dışına kaydırılan
  kameralar decode edilmez).

### 4.3 Decoder havuzu (üst sınır koruması)
Çok yüksek sayıda sistem thread'i açmak yerine sabit bir **worker pool**
(örn. 4–8 çözücü) kullanılır; kameralar round-robin bu havuza bağlanır.
Donanım hızlandırmada havuz boyutu = GPU decode oturum limitine göre ayarlanır.

### 4.4 Kaynak tahmini (kaba)
| Kodek | Çöz. | Yazılımsal decode/ akış | Not |
|---|---|---|---|
| H.264 alt akış | 640×360 | ~%1–3 çekirdek | Rahat |
| H.264 ana akış | 1080p | ~%8–20 çekirdek | Orta |
| H.265 ana akış | 4MP | ~%20–45 çekirdek | Yazılımsal pahalı |

Bu yüzden **H.265'i yazılımsal çok akışta çözmek önerilmez** → HW decode şart.

---

## 5. Donanım hızlandırma ve ölçek kademeleri

| Kamera sayısı | Önerilen | Detay |
|---|---|---|
| 1–4 | Yazılımsal, ana akış OK | Tek makine, hafif |
| 5–16 | Alt akış duvarı + yazılımsal | Substream kritik hale gelir |
| 16–40 | **HW decode (VAAPI/NVDEC)** + alt akış duvarı | Zorunlu sınır |
| 40–64 | HW decode + decoder pool + düşük FPS | Tek makine üst sınırına yakın |
| 64+ | Tek kutu YETMEZ | RTSP relay/proxy veya dağıtık |

### 5.1 GPU tarafı optimizasyonlar (üst seviye)
- **VAAPI / NVDEC / VDPAU** ile donanım decode (`av_hwdevice_ctx_create` +
  `hwaccel=vaapi/cuda`).
- **YUV→RGB'yi shader'da yap:** 3 düzlemi (Y/U/V) GPU dokusu olarak yükle, özel
  shader ile RGB'ye çevir. Böylece swscale CPU yükü ve her karede 1080p RGBA
  upload (~8 MB/kare) ortadan kalkar. Bu, "odakta 4K + 16 kamera" senaryosunun
  tek gerçek çözümüdür.
- **Zero-copy:** `AV_PIX_FMT_VAAPI`/`CUDA` yüzeyini doğrudan map edip OpenGL'e
  bağlamak (ileri seviye; MVP sonrası).

### 5.2 raylib notu
raylib düz `Texture2D`'si RGB'dir; shader'lı YUV yolu için `rlgl`/özel shader
gerekir. MVP'de RGBA+swscale, Faz 3'te YUV shader.

---

## 6. Düşük gecikme (canlı hissi) ayarları

RTSP varsayılanı 1–3 sn gecikme üretebilir. Optimum canlılık için:
- `rtsp_transport=tcp` (kayıp pakette bozulma yerine düzen; bazı kameralarda
  `udp` + `rtp_tcp` yeniden denemesi daha düşük gecikme verir — test edilmeli).
- `fflags=nobuffer`, `flags=low_delay`, `max_delay=500000`.
- `avformat_find_stream_info` sonrası **tampon seviyesini sınırla**;
  `-probesize`/`-analyzeduration` düşür.
- Kare biriktirmeyi **kapat** (zaten §4.1'deki son-kare yuvası bunu yapar).

---

## 7. GUI / UX tasarımı (BEAT içine oturumu)

Yeni sekme: **"KAMERALAR"** (mevcut 3 sekmenin yanına; veya Araçlar alt-sekmesi).

```
┌──────────────────────────────────────────────────────────────┐
│ KAMERALAR   [Keşfet] [Tümünü Bağla] [Duvar: 4x4] [Kayıt]     │
├───────────────┬──────────────────────────────────────────────┤
│ OTURUM LİSTESİ│            VİDEO DUVARI                      │
│ ● K1  Giriş   │  ┌────┐┌────┐┌────┐┌────┐                    │
│ ● K2  Depo    │  │ K1 ││ K2 ││ K3 ││ K4 │  (thumbs)          │
│ ○ K3  Otopark │  └────┘└────┘└────┘└────┘                    │
│ ● K4  Asansör │  ┌────┐┌────┐┌────┐┌────┐                    │
│  ...          │  │ K5 ││ K6 ││ K7 ││ K8 │                    │
│ (status rozet)│  └────┘└────┘└────┘└────┘                    │
│               │                                              │
│ [seçili: K2]  │  Çift tık → ODAK (ana akış, tam ekran)       │
└───────────────┴──────────────────────────────────────────────┘
```

Özellikler:
- **Oturum listesi** = kameralar; durum rozeti (● çevrimiçi / ○ çevrimdışı /
  ⚠ kimliksiz / 🔒 parola bulundu / ❌ erişilemedi).
- **Duvar düzeni:** 1×1, 2×2, 3×3, 4×4, 5×5; otomatik sığdırma.
- **Odak görünümü:** çift tık → ana akış, tam ekran, `Esc` ile dönüş.
- **Otomatik tur (cycle):** odakta N saniyede bir kamera değiştir (NVR tarzı).
- **PTZ:** ONVIF `ContinuousMove`/`AbsoluteMove` kontrolü (destekleyen kameralarda).
- **Anlık görüntü (snapshot):** tek kare JPEG/PNG diske.
- **Kayıt:** odak akışını `.mp4`/'.mkv' (FFmpeg muxer) olarak diske.
- **Canlı doluluk/FPS göstergesi:** her hücrede kodek+çöz+fps; performans şeffaf.

Bu, "meterpreter session" hissini verir: kamerayı seç → içeride canlı akış →
üzerinde işlem (snapshot/kayıt/PTZ).

---

## 8. Ofis ölçeğinde dürüst sınırlar

1. **Decode CPU/GPU tavanı:** gerçek darboğaz budur; network değil. HW decode
   olmadan ~8–16 akıştan sonra makine doymaya başlar.
2. **H.265:** yaygın ve daha az bant ister ama **yazılımsal decode pahalıdır**;
   çoğu ucuz kamera H.265 alt akışı verir → HW decode şart.
3. **Kodek patent/lisans:** H.264/H.265 **dağıtımında** patent lisansı konusu
   vardır (FFmpeg teknik olarak çözer; ticari dağıtımda hukuki değerlendirme
   gerekir). Kişisel/lab kullanımı ayrı; ürünleştirirsen bakılmalı.
4. **Gecikme:** RTSP + TCP ile tipik 0.5–2 sn; "gerçek zamanlı" beklentiyi buna
   göre kalibre et.
5. **Multicast:** RTSP tüketici başına unicast'tır; 40 kamerayı 40 kez çekmek
   bant demektir. Aynı kamerayı birden çok kişi izlerse **RTSP relay/proxy**
   (bir kez çek, çoğa dağıt) gerekir.
6. **VLAN/yönlendirme:** kamera ağı ayrı segmentteyse ve L3 pivot yoksa BEAT
   göremez (fizibilite raporundaki sınır aynen geçerli).
7. **Kimlik:** parola bulunamayan/şifreli kameralar akış vermez → OD'daki tek
   kamera bile "duvarda boş hücre" olur.
8. **Tek kutu tavanı:** ~40–64 alt akış civarı; ötesi dağıtık mimari ister.
9. **ONVIF her kameralık değil:** bazı ucuz modeller ONVIF konuşmaz → RTSP
   yolunu şablonla/elle vermek gerekir (yine de çalışır).
10. **Kararlılık:** çok oturumu uzun süre açık tutmak bellek sızıntısına karşı
    FFmpeg bağlamlarının düzgün kapatılmasını gerektirir (cleanup disiplini).

---

## 9. Modül planı (mevcut BEAT mimarisine oturuyor)

Yeni dosyalar:
- `include/onvif_client.h` + `src/onvif_client.c`
  → WS-Discovery, `GetDeviceInformation`, `GetProfiles`, `GetStreamUri`,
    `GetSnapshotUri`, (opsiyonel PTZ). HTTP Digest/Basic auth.
- `include/camera_ingest.h` + `src/camera_ingest.c`
  → kamera oturumları, FFmpeg demux/decode thread'leri, son-kare yuvası,
    decoder pool, HW hızlandırma, düşük gecikme ayarları.
- `include/video_surface.h` + `src/video_surface.c`
  → raylib Texture2D yönetimi, grid/düzen, hücre çizimi, FPS rozetleri.

Küçük dokunuşlar:
- `gui.c`: "KAMERALAR" sekmesi + duvar/odak/oturum paneli.
- `arp_scanner.c`: kamera OUI + "Kamera" sınıfı.
- `CMakeLists.txt`: **FFmpeg opsiyonel bağımlılığı** (OpenSSL deseniyle),
  `HAVE_FFMPEG` tanımı; yoksa modül "yok" olarak derlenir.

---

## 10. Fazlar

- **Faz 1 — Keşif & envanter:** ONVIF discovery + OUI + port imzası; kamera
  listesi (henüz video yok).
- **Faz 2 — Tek kamera, uygulama-içi:** FFmpeg ile 1 kamera RTSP → raylib
  texture → odak paneli. **Harici pencere olmadan ilk canlı görüntü.**
- **Faz 3 — Duvar katmanı:** alt akış + son-kare yuvası + grid + düşük FPS;
  8–16 kamera ölçeği.
- **Faz 4 — Ölçek & donanım:** decoder pool, VAAPI/NVDEC, YUV shader, PTZ,
  snapshot, kayıt; 40+ kamera.
- **Faz 5 — Dayanıklılık:** otomatik yeniden bağlanma, kaynak temizliği,
  uzun süre kararlılık testi.

---

## 11. Karar için ölçek soruları

1. Hedef **kamera sayısı** ve tipik **çözünürlük/kodek** nedir? (16 mı, 64 mü?
   H.264 mü H.265 mi?) → HW hızlandırma gerekip gerekmediğini belirler.
2. Aynı anda **kaç kamerayı canlı** görmek yeterli (duvar boyutu)? Gerisi
   "tıkla-izle" mi olsun?
3. Kameralar **ONVIF** konuşuyor mu, yoksa üreticiye özel mi (Hikvision/Dahua
   özel yollar)?
4. **Kayıt** isteniyor mu, yoksa yalnız canlı izleme mi (disk/CPU planını değiştirir)?
5. Çalışacağı makinenin **GPU'su** var mı? (VAAPI/NVDEC mevcudiyeti.)
```
