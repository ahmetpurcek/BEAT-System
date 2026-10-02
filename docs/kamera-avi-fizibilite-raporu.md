# BEAT System — "Otonom Kamera Ağı Avcısı + Canlı İzleme" Fizibilite Raporu

Tarih: 2026-10-02
Kapsam: Mevcut ağdaki IP kameraları tespit edip, otonom olarak erişip,
görüntüyü BEAT penceresi içinde izleme özelliğinin teknik değerlendirmesi.
Durum: **Tartışma / tasarım aşaması** (henüz kod yazılmadı).

---

## 0. Tek cümlelik cevap

**Keşif tarafı neredeyse tamamen yapılabilir ve mevcut mimariye çok temiz oturur.
"Otonom erişim" kısmı yapılabilir ama tek bir sihirli algoritma değildir —
parmak izi → kimlik deneme → modele özgü zafiyet modülü zinciridir ve kapsamı
doğal olarak kısmi kalır. "Görüntüyü izleme" kısmı, tek gerçek ek bağımlılık
olan bir video çözücü (FFmpeg) ile yapılabilir; H.264/H.265'i raylib tek başına
çözemez. "Ağdaki TÜM kameraları garantili hackle" diye bir şey yoktur.**

---

## 1. Mevcut mimarinin bu işe sağladığı hazır altyapı

BEAT zaten bir kamera modülünün ihtiyaç duyduğu iskeletin çoğuna sahip:

| İhtiyaç | Mevcut modül | Durum |
|---|---|---|
| L2 cihaz keşfi | `arp_scanner` (raw ARP sweep + `ip neigh`) | Var, hazır |
| Cihaz sınıflandırma | `scanner_classify_device`, `type` alanı ("IoT"/"Kamera") | Var, kamera sınıfı zaten öngörülmüş |
| Risk seviyesi | `RiskLevel` (NONE→CRITICAL) | Var |
| Port/servis parmak izi | `port_scanner` (stealth, SYN/FIN/Xmas, banner) | Var, 554/rtsp zaten port DB'sinde |
| Ham paket üretimi | `raw_inject` (AF_PACKET Ethernet/IP/UDP/TCP + checksum) | Var |
| Pasif trafik görünürlüğü | `network_monitor` (libpcap, L2–L7 dissector, `app_domain`) | Var (DNS/SNI/HTTP/QUIC) |
| Müdahale motorları | `arp_block`, `site_block` (sinkhole/RST/iptables) | Var |
| GUI iskeleti | `gui.c` (3 sekme + Araçlar içinde alt sekmeler) | Var |

Yani sıfırdan bir şey yazmıyoruz; **mevcut veri hattına yeni bir cihaz sınıfı +
yeni bir erişim motoru + yeni bir görüntüleme yüzeyi** ekliyoruz.

---

## 2. Özelliği üç ayrı katmana ayırmak gerekir

"Kameraları hackleyip izlemek" tek bir özellik değil, üç bağımsız problemdir.
Her birinin zorluğu ve başarı oranı çok farklı:

### Katman A — Keşif (Kamera ağını bul)
Zorluk: **Düşük–Orta. Başarı oranı çok yüksek (~%95+).**

### Katman B — Erişim (Otonom "hackleme")
Zorluk: **Orta–Yüksek. Başarı oranı değişken (~%20–%80, kuruluma göre).**

### Katman C — Görüntüleme (Canlı akışı BEAT'ta izle)
Zorluk: **Orta (tek büyük bağımlılık: video çözücü). Başarı oranı, B başarılıysa yüksek.**

---

## 3. KATMAN A — Kamera tespiti (yapılabilir, önerilir)

Kamera keşfi için birden çok bağımsız yöntem var; hepsi BEAT'a eklenebilir:

### A1. Vendor/OUI parmak izi (pasif, sıfır gürültü)
MAC OUI veritabanına kamera üreticilerinin bloklarını eklemek yeterli.
Klasik liste: Hikvision, Dahua, Axis, Vivotek, Reolink, Amcrest, Foscam, EZVIZ,
Uniview (UNV), Xiongmai (sayısız ucuz kamera/NVR), TP-Link Tapo, Anker/Eufy,
Bosch, Hanwha, Avigilon. `Device.vendor` alanı zaten mevcut — sadece OUI tablosu
genişletilir.

### A2. Port/servis parmak izi (aktif, düşük gürültü)
Kameraya özgü imza portları:
- **554/tcp** RTSP (ana akış protokolü) — zaten port DB'de
- **8554/tcp** alternatif RTSP
- **80/8080/443/8443** web arayüzü + ONVIF (SOAP)
- **8000/tcp** Hikvision SDK
- **37777/tcp** Dahua
- **34567/tcp** (ve 8899) Xiongmai
- **1935/tcp** RTMP — zaten port DB'de
- **22/tcp** bazı modeller SSH

Banner/`Server:` başlığı ve HTTP `<title>` (örn. "Network Camera", "IP Camera",
"Hikvision", "Dahua") tek başına yüksek isabet verir. `port_scanner`'ın banner
toplama altyapısı bunu zaten yapabiliyor.

### A3. ONVIF WS-Discovery (en "şık" yöntem, tam otonom)
Standart: **UDP multicast 239.255.255.250:3702** adresine bir SOAP `Probe`
paketi gönderilir; kameralar/NVR'lar kendilerini `ProbeMatch` ile bildirir
(model, firmware, cihaz tipi, servis adresi dahil).
- Bu, "ağdaki tüm kameraları otomatik bul" işini **tek bir multicast paketiyle**
  yapan yerleşik standarttır.
- `raw_inject` + `network_monitor` ile kolayca yazılır: yeni bir
  `onvif_discovery.c` modülü ~200–300 satır.
- Çoğu ONVIF cihazı ek olarak **kimlik doğrulamasız** `GetDeviceInformation` ve
  `GetProfiles` yanıtı verir → model/firmware otonom toplanır.

### A4. Pasif RTSP/DNS-SD tespiti (sıfır ek paket)
`network_monitor`'a küçük bir dissector eklenerek:
- **RTSP** trafiği (554) → `DESCRIBE`/`OPTIONS` istekleri düz metindir; URL ve
  `User-Agent` (örn. `Hikvision`) okunur. Bu, ağdaki bir istemci kameraya
  bağlandığında kamera IP'sini ve akış yolunu **pasif** yakalamanızı sağlar.
- **mDNS/Bonjour** servis tipleri (`_rtsp._tcp`, `_onvif._tcp`).
- Mevcut `app_domain` çıkarımına bu protokoller doğal ekleme.

**A katmanı sonucu:** Kamera ağı, aktif (ONVIF + port taraması) ve pasif
(RTSP/mDNS/OUI) yöntemlerin birleşimiyle güvenilir biçimde haritalanabilir.
Bu katmanın **hiçbir sert sınırı yok**; sadece OUI tablosu ve birkaç imza eklemek
yeterli.

---

## 4. KATMAN B — Otonom erişim ("hackleme") — gerçek sınırlar

Burada dürüst olmak gerekir: **"her kamerayı deviren tek bir otonom exploit yoktur."**
Gerçekçi otonom motor, sıralı bir *karar zinciridir*:

### B1. Kimlik doğrulamasız RTSP
Çok sayıda ucuz kamera RTSP akışını hiç şifresiz sunar. `DESCRIBE rtsp://IP:554/...`
istek atılır, `401` gelmezse akış açıktır. **En yüksek getirili, en sessiz yol.**

### B2. Varsayılan kimlik bilgisi testi (en etkili otonom teknik)
`admin/admin`, `admin/12345`, `admin/<boş>`, `admin/admin12345`, `root/root`,
`root/<boş>`, `888888/888888` (Xiongmai klasik), `admin/password` vb.
- RTSP `DESCRIBE` (HTTP Basic/Digest), ONVIF `GetStreamUri` ve web arayüzüne karşı
  denenir.
- `port_scanner`'ın **stealth delay / jitter** mantığı buraya birebir uyarlanır
  (gürültüyü ve tetiklenmeyi azaltmak için).

### B3. Modele özgü bilinen zafiyet modülleri (parmak izi → dispatch)
Otonom motor, A'daki firmware/model bilgisini alıp bir CVE tablosuna eşler:
- Hikvision: kimliksiz ISAPI bilgi sızıntısı (CVE-2017-7921), komut enjeksiyonu
  (CVE-2021-36260)
- Dahua: auth bypass (CVE-2021-33044 / 33045)
- Xiongmai: arka kapı hesapları / kimliksiz erişim (CVE-2018-10088 ailesi)
- Axis, Vivotek, Reolink: modele özgü çeşitli RCE/auth-bypass'lar

Bu, otonom motorun çekirdeğidir: **her CVE bir "modül"**; firmware parmak izi
modülü seçer. Kapsam ancak yazılan modül sayısı kadar geniştir.

### B4. ONVIF ile programatik akış URL'si alma
Varsayılan/zayıf kimlik B2'de tutarsa, `GetStreamUri` çağrısı size **akış URL'sini
tahmin etmeden** verir (Hikvision `/Streaming/Channels/101`,
Dahua `/cam/realmonitor?channel=1&subtype=0` gibi yolları elle bulmak gerekmez).
Bu, B2→C geçişini çok temizler.

### B katmanının GERÇEK sınırları (yapılamayanlar)

1. **Güçlü/benzersiz parola, güncel firmware:** bypass edilemez. Sadece
   wordlist/kimlik tahmini ile kalırsınız; bu da başarısızsa erişim yoktur.
2. **TLS-only / SRTP şifreli akışlar:** Sertifika pinning veya şifreli medya
   varsa anahtar olmadan **çözemezsiniz**. Kamera ağ trafiği şifreliyse pasif
   yakalama da işe yaramaz.
3. **Ayrı VLAN / yönlendirilmiş segment:** BEAT bir **L2/LAN aracıdır**. Kamera
   ağı farklı bir VLAN/segmentte ise ve oraya bir L3 pivot yoksa, L2'den
   erişemezsiniz. Çözüm: o segmente fiziksel/trunk erişimi, ya da router/NVR
   üzerinden pivot — BEAT'ın doğal kapsamı dışı.
4. **Cloud-only kameralar (Ring, Nest, yeni Eufy bulut modu):** yerel RTSP
   yüzeyi yoktur → yerel saldırı yüzeyi yok. Bu tamamen farklı bir problemdir
   (bulut hesabı); BEAT kapsamı dışı.
5. **Analog kameralar (CVBS/AHD/TVI coax):** ağda tek tek görünmezler; DVR/NVR
   arkasında tek cihaz olarak dururlar → **NVR'ı hedeflersiniz**, kamerayı değil.
6. **P2P + güçlü şifreleme (bazı Xiongmai türevleri, çoğu bulut markası):**
   cihazın bulut kanalı çözülemez; sadece yerel arayüz denenir.
7. **0-day / bilinmeyen firmware:** "otonom keşfedilemez." Bu manuel araştırma
   işidir; otonom motor yalnızca *bilinen* zafiyetleri çalıştırır.

### B katmanı operasyonel riskler (tasarımda ele alınmalı)

- **Hesap kilitleme:** N başarısız denemeden sonra kamera kaynak IP'yi bloklar
  veya hesabı kilitler → otonom brute-force kendi kendini mahvedebilir.
- **Kararsız firmware çökmesi:** Özellikle Xiongmai/Hikvision türevleri, kötü
  biçimlendirilmiş istekte çöker veya yeniden başlar → **kamera "brick" riski**.
- **Tamper/izinsiz müdahale alarmı:** Bazı NVR'lar başarısız girişleri/port
  taramasını alarm olarak kaydeder → tespit edilirsiniz.
- **Kimlik doğrulama akışı:** ONVIF HTTP **Digest** auth (MD5/SHA) çoğu cihazda
  zorunlu; Basic yetmez. Digest + nonce yönetimi implement edilmeli.

---

## 5. KATMAN C — Görüntüyü BEAT içinde izleme

### C1. Kritik gerçek: raylib video çözemez
raylib bir oyun/GUI kütüphanesidir; H.264/H.265 bit akışını **çözemez.**
Kamera akışının ekranda görünmesi için bir **video çözücü** şart. Seçenekler:

| Yol | Zorluk | Not |
|---|---|---|
| **MJPEG over HTTP** | Çok kolay | Ucuz kameraların çoğu `http://IP/video.cgi` gibi MJPEG JPEG kareleri verir → `LoadTextureFromImage` ile doğrudan. **MVP için ideal.** |
| **FFmpeg (libavformat+libavcodec+libswscale)** | Orta | RTSP'yi native açar, H.264/H.265 çözer, RGB'ye çevirir → raylib `UpdateTexture`. **Ana çözüm.** |
| OpenH264 / vendor SDK | Yüksek | FFmpeg'in yaptığını elle yapmak; önerilmez. |

**Öneri:** FFmpeg'i (pkg-config `libavformat libavcodec libswscale libavutil`)
OpenSSL gibi **opsiyonel bağımlılık** yapın; yoksa MJPEG-only derlenir. Böylece
mevcut "yoksa fallback" felsefeniz korunur.

### C2. Çözme yükü / ölçek
- Aynı anda N akış çözmek CPU/GPU yoğundur. 1–2 akış yazılımsal çözülür;
  4+ akış için **donanım hızlandırma (VAAPI/NVDEC/VDPAU)** gerekir.
- Kare → raylib texture yüklemeleri bellek/GPU bant genişliği tüketir; akış
  başına bir decode thread + düşürülmüş FPS (örn. 10–15 fps izleme) şart.
- Yapısal öneri: `video_stream.c` = her kamera için bir decode thread; ana
  thread sadece en son RGB karesini texture'a yükler (mevcut thread/mutex
  soyutlamanız hazır).

### C3. Kayıt / anlık görüntü
Ek kolay kazanç: ham akışı diske `.mp4`/`.mkv` (FFmpeg muxer) veya tek kare JPEG
anlık görüntü. Bu, "izleme" özelliğinin doğal bir uzantısıdır.

---

## 6. Önerilen entegrasyon mimarisi (mevcut veri hattına oturumu)

```
[1] KEŞİF  →  arp_scanner (OUI: kamera üreticileri)
              + onvif_discovery.c (WS-Discovery UDP 3702)   ← YENİ
              + port_scanner (554/8554/8000/37777/34567 imzaları)

[2] SINIFLANDIRMA → Device.type = "Kamera", vendor, model, firmware
                    RiskLevel: kimliksiz/açık akış → RISK_CRITICAL

[3] PASİF İZLEME → network_monitor + RTSP dissector eklemesi  ← YENİ
                    (DESCRIBE/OPTIONS düz metninden URL+UA)

[4] ERİŞİM MOTORU → camera_access.c                           ← YENİ
    B1 kimliksiz RTSP → B2 varsayılan kimlik → B3 CVE dispatch
    (port_scanner stealth delay/jitter'ı yeniden kullanır)

[5] GÖRÜNTÜLEME → video_stream.c + FFmpeg/MJPEG                ← YENİ
    decode thread → RGB → raylib UpdateTexture

[6] GUI → yeni sekme "KAMERALAR" veya Araçlar alt-sekmesi       ← YENİ
    (liste + kamera başına küçük canlı önizleme + durum rozeti)
```

Yeni dosyalar (öneri):
- `include/onvif_discovery.h` + `src/onvif_discovery.c`
- `include/camera_access.h`  + `src/camera_access.c`
- `include/video_stream.h`   + `src/video_stream.c`
- `CMakeLists.txt`: FFmpeg opsiyonel tespiti (OpenSSL gibi)

Mevcut dosyalara dokunuş (küçük):
- `arp_scanner.c`: OUI kamera bloğu + "Kamera" sınıfı
- `network_monitor.c`: RTSP/mDNS dissector (`app_domain`'e paralel)
- `gui.c`: yeni sekme + video paneli
- `network_ids.c`: "kimliksiz kamera akışı" = yüksek önem uyarısı (opsiyonel)

---

## 7. Artıları / Eksileri özeti

### Artı yönleri
- Mevcut modüllerin çoğu birebir yeniden kullanılır (ARP, port, raw_inject, pcap).
- ONVIF WS-Discovery + pasif RTSP ile keşif **tam otonom ve standart**.
- Kamera/NVR, gerçek dünyada en yaygın kırılgan IoT sınıfı → yüksek operasyonel ve
  gösteri değeri.
- IDS/Tehdit Haritası zaten host modeline sahip; kameralar yeni bir risk sınıfı olur.
- MJPEG yolu ile **çok hızlı bir MVP** mümkün (FFmpeg'siz).

### Eksileri / sert sınırlar
- **H.264/H.265 çözme** = yeni ve büyük bir bağımlılık (FFmpeg). raylib'in
  kendisi yetmez — bu, mimariye en büyük eklenti.
- **"Tüm kameraları hackle" garantisi yoktur**; kapsam yazılan CVE modülleri +
  kimlik wordlist'i kadardır. Güçlü parola/şifreli akış/VLAN/bulut kameralar
  erişim dışında kalır.
- **Brick/kilitlenme/alarm riski:** otonom erişim agresif olursa kamera çöker veya
  sizi bloklar → hız sınırlama + "güvenli mod" şart.
- **Modül bakım yükü:** her firmware güncellemesi modülleri kırabilir.
- **Çoklu akış = donanım yükü:** 4+ akış için HW hızlandırma gerekir.

---

## 8. Önerilen faz planı

- **Faz 1 (kolay, yüksek değer):** OUI + port imzası + ONVIF WS-Discovery ile
  **kamera keşfi ve envanteri**. GUI'de "Kameralar" listesi. Erişim/görüntüleme yok.
- **Faz 2:** Pasif RTSP dissector + varsayılan kimlik testi (stealth delay ile) +
  MJPEG canlı önizleme. **FFmpeg'siz ilk canlı görüntü burada gelir.**
- **Faz 3:** FFmpeg ile RTSP/H.264/H.265 çözme; çoklu akış + anlık görüntü/kayıt.
- **Faz 4:** Modele özgü CVE modül kütüphanesi (`camera_access` dispatch) +
  güvenli mod / hız sınırları / kilitleme koruması.

---

## 9. Karar için açık sorular

1. İlk canlı görüntü için **MJPEG yolu (FFmpeg'siz, hızlı MVP)** mı, yoksa
   doğrudan **FFmpeg/RTSP** mı tercih edilir?
2. Erişim motoru kimlik **testi** ile mi sınırlı olsun, yoksa **CVE exploit
   modülleri** de yazılsın mı? (Kapsam ve bakım yükü farkı büyük.)
3. Çoklu akış hedefi kaç kamera? (1–2 → yazılımsal; 4+ → HW hızlandırma.)

---

## 10. Yasal çerçeve (mevcut README ile tutarlı)
Bu özellik yalnızca **sahibi olduğunuz veya yazılı test izniniz bulunan** ağ ve
kameralara karşı kullanılmalıdır. Otonom erişim/kayıt yeteneği, yanlış ağda
kullanıldığında ciddi hukuki sonuç doğurur; bu yüzden tasarımda kapsam kilidi
(scope) ve açık kullanıcı onayı zorunlu kılınmalıdır.
```
