# BEAT System

**Tek pencereden yerel ağ güvenliği:** cihaz keşfi, canlı trafik görünürlüğü,
kural tabanlı saldırı tespiti (IDS), aktif müdahale (ağdan kesme / site
karartma) ve **IP kamera keşfi → otonom erişim → uygulama-içi canlı izleme** —
hepsi C11 ile yazılmış, Raylib tabanlı tek bir masaüstü uygulamasında.

---

## 1. BEAT System nedir?

BEAT System, bir ağ segmentini gözlemleyen ve gerektiğinde o segmente
**müdahale eden** bütünleşik bir konsoldur. Uygulama, birbirinden kopuk
araçların toplamı değil; **tek bir veri hattı** üzerinde çalışan katmanlardan
oluşur. Aynı paket, aynı cihaz ve aynı kural kümesi hem ekranda gösterilir,
hem IDS tarafından puanlanır, hem de müdahale motorlarına girdi olur.

İş akışı beş aşamada ilerler ve her aşama bir sonrakini besler:

| Aşama | Ne yapar | Motor |
|---|---|---|
| **1. Keşif** | Ağdaki cihazları bulur, sınıflandırır (yönlendirici, bilgisayar, mobil, IoT) | `arp_scanner` |
| **2. Kapsam seçimi** | Hangi cihazların izleneceğini belirler; tüm motorlar bu listeye bağlanır | **İzleme Listesi (scope)** |
| **3. Görünürlük** | Trafiği paket bazında yakalar, katman katman çözer, filtrelenebilir liste sunar | `network_monitor` + `filter_engine` |
| **4. Tespit** | Çözülen trafiği kurallardan geçirir, saldırı/kurban skorları üretir | `network_ids` |
| **5. Müdahale** | Seçilen cihazı ağdan keser veya seçilen siteyi karartır | `site_block` |

Buna ek olarak hedef bazlı derinlemesine inceleme için `port_scanner` (stealth
port/servis/zafiyet taraması) ayrı bir araç sekmesinde sunulur.

Aynı konsol, **IP kameralarına özel paralel bir hat** da çalıştırır: kameraları
bulur (`camera_discovery`), bilinen zafiyet/kimlik yollarını sondalar
(`camera_vuln`), otonom veya elle erişim kurar (`camera_access`) ve görüntüyü
uygulama penceresi içinde canlı gösterir (`video_stream`). Bu hat, aşağıdaki
klasik IDS hattından bağımsız ilerler ama aynı ağ keşfi ve aynı tek-pencere
felsefesini paylaşır.

### Veri hattı (modüller nasıl bağlanıyor?)

```
          ┌───────────────────────────────────────────────┐
          │                 BEAT System                   │
          └──────────────────────┬────────────────────────┘
                                 │
[1] KEŞİF ───────────────────────┤
  arp_scanner: raw ARP sweep + ip neigh
                                 │
                                 ▼
                   ┌─────────────┬─────────────┐
                   │       İzleme Listesi      │
                   │          (scope)          │
                   └─────────────┬─────────────┘
                                 │
[2] GÖRÜNÜRLÜK ──────────────────┤
  network_monitor (libpcap) → filter_engine
  └─ L2..L7 dissector, app_domain (DNS / TLS SNI / HTTP / QUIC)
                                 │
[3] TESPİT ──────────────────────┤
  network_ids (~20 kural) → skor + alarm
  └─ GUI: Alarm Merkezi + Tehdit Haritası
                                 │
[4] MÜDAHALE ────────────────────┤
  site_block (Karartma)
  └─ raw_inject: yalnızca listedeki hedefler
                                 │
                                 ▼

Bağımsız yüzeyler (İzleme Listesi'ne BAKMAZ):
                  ┌──────────────────────────────────┐
                  │  • Port Tarayıcı (manuel hedef)  │
                  │  • ARP Black-Hole (KES/AÇ)       │
                  └──────────────────────────────────┘
```

**Kritik bağ:** `network_monitor` çözücüsü, uygulama katmanından çıkardığı alan
adını (`app_domain`: DNS / TLS SNI / HTTP Host / QUIC SNI) paket kaydına
*yapısal* olarak yazar. IDS ve `site_block` aynı alanı tek kaynaktan okur —
yani "hangi cihaz hangi siteye gitti" bilgisi tek yerde üretilir ve tüm
modüller aynı gerçeği görür.

### Kamera hattı (paralel, IDS'ten bağımsız)

Kamera hattı, yukarıdaki IDS/İzleme-Listesi veri hattından **ayrı** çalışır ve
İzleme Listesi'ne bağlı değildir. Kendi keşif → erişim → izleme zincirini
kurar:

```
  camera_discovery ──────────────► CameraDevice[] (kanıt + güven skoru)
    • ARP + kamera imzalı port taraması
    • RTSP OPTIONS/DESCRIBE sondası
    • HTTP web arayüzü imzası
    • ONVIF WS-Discovery (3702)
    • SSDP/UPnP (1900) + mDNS (5353)
    • MAC OUI kamera üreticisi
    └─ self IP / gateway / broadcast / multicast / link-local DIŞLANIR
                                 │
                                 ▼
  camera_vuln ───────────────────┤  parmak izi + zafiyet
    • device-info endpoint (model/firmware/seril)
    • Hikvision ISAPI / Dahua RPC2 / Xiongmai backdoor sondaları
    • ONVIF device-service (WS-UsernameToken / Basic / Digest)
                                 │
                                 ▼
  camera_access ─────────────────┤  otonom erişim (arka plan işçi)
    • RTSP yol keşfi + kimliksiz açık akış
    • varsayılan kimlik DB (~96) + harici wordlist
    • Basic/Digest doğrulama + HTTP snapshot
                                 │
                                 ▼
  video_stream ──────────────────┘  uygulama-içi izleme
    • görünmez ffmpeg alt-süreci → RGB kare → Texture2D
    • çoklu akış grid, snapshot, kayıt, otomatik reconnect
```

### İzleme Listesi (Scope)

Diyagramda gördüğünüz gibi **port taraması dışındaki her şey İzleme
Listesi'ne bağlı çalışır.** Bu liste; paket izleme görünümünü, IDS motorunu,
alarm görünümünü ve site karartmanın gözlem kapsamını tek tek değil, birlikte
yönetir:

| Liste durumu | Paket İzleme görünümü | IDS motoru | Alarm görünümü | Site karartma gözlemi |
|---|---|---|---|---|
| **Dolu** | Yalnızca listedeki cihazların trafiği gösterilir | Yalnızca listedeki trafik kurallardan geçer | En az bir ucu listede olan alarmlar gösterilir | Yalnızca listedeki cihazlar izlenir |
| **Boş** | Görünüm boştur, izleme çalışmaz | IDS tamamen pasiftir, paket işlenmez | Alarm gösterilmez | Tüm ağ gözlenir (kural yoksa karartma olmaz) |

> **İpucu:** Başlamak için keşfin bulduğu cihazları tek seferde listeye almak
> üzere Kontrol Paneli'ndeki **TÜMÜNÜ EKLE** düğmesini kullanın. Boş bir listeyle
> GUI'de paket izleme görünümü çalışmaz ve IDS **pasif** kalır.

**İzleme Listesi'ne bakmayan üç yüzey** diyagramda ayrı kutuda gösterilmiştir:
`port_scanner` (hedefi manuel seçersiniz), ARP Black-Hole **KES/AÇ**
(cihaz satırından tek tıkla tetiklenir) ve **kamera hattı**. Bunlar dışındaki
tüm işlevler, izleme listesinin dolu olmasına bağlıdır.

---

## 2. Özellikler

| Modül | Açıklama |
|---|---|
| **Modern GUI** | Raylib + Raygui, çözünürlükten bağımsız ölçeklenen koyu "NOC" teması (siyah zemin + neon cyan) |
| **İzleme Listesi (Scope)** | Keşiften sonra hangi cihazların izleneceğini belirler; paket izleme, IDS, alarm ve site karartma kapsamını birlikte yönetir (boş liste = IDS pasif) |
| **Ağ Keşfi** | Raw ARP sweep, `/proc/net/arp` ve `ip neigh` birleştirme; üretici/hostname çözümü ve cihaz sınıflandırma |
| **Canlı Trafik İzleme** | `libpcap` ile gerçek zamanlı yakalama, L2–L7 ayrıştırma, Wireshark tarzı PDU katmanları + hex görünümü, `.pcap` dışa aktarma |
| **Display Filtre Motoru** | Wireshark sözdiziminin alt kümesi (`ip.addr == 10.0.0.5 && tcp.port == 443`, `dns`, `info contains GET`) |
| **Ağ IDS** | ~20 kural: ARP spoofing/MITM, port tarama (hızlı + hız sınırlı/yavaş), SSH brute-force, flood, kötü amaçlı portlar, DNS tünel/DGA ve SQLi/XSS/JNDI/Meterpreter imzaları |
| **Tehdit Haritası** | Akış tablosundan her cihaz için saldırgan/kurban skoru ve tehdit durumu |
| **Ağdan Kesme (ARP Black-Hole)** | İki yönlü sahte ARP enjeksiyonu ile hedefin internet erişimini keser/geri verir (MITM değildir — yönlendirme yapmaz) |
| **Site Karartma** | Cihaz + alan adı bazında trafiği karartır: DNS sinkhole + TCP RST (+ QUIC için ICMP `port unreachable`), üstüne iptables (`BEAT_SB`) deterministik DROP katmanı |
| **QUIC SNI Çözümleme** | UDP/443 (HTTP/3) Initial paketinden TLS SNI çıkarır (OpenSSL varsa) |
| **Stealth Port Tarayıcı** | Nmap bağımsız; TCP CONNECT/SYN/FIN/NULL/Xmas/ACK/Window/Maimon/UDP/Idle/FTP-bounce/SCTP/IP-proto; jitter, gecikme, decoy; TTL tabanlı OS tahmini ve CVE notları |
| **Headless Mod** | GUI olmadan IDS çalıştırır; uyarıları stdout + JSONL dosyasına yazar (SIEM entegrasyonu / FP ölçümü) |
| **IP Kamera Keşfi** | ARP + kamera-imzalı port taraması (554/8554/8555/37777/34567/8000/… ) + RTSP OPTIONS/DESCRIBE + HTTP web arayüzü imzası + ONVIF WS-Discovery + SSDP/UPnP + mDNS + MAC OUI; kanıt maskesi (port/RTSP/401/HTTP/ONVIF/OUI/üretici portu) ve 0-100 güven skoru. Kendi IP, gateway, broadcast, multicast ve link-local adresler otomatik dışlanır |
| **Kamera Parmak İzi & Zafiyet** | Üretici device-info endpoint parmak izi (model/firmware/seril); Hikvision ISAPI auth-token, Dahua RPC2 login, Xiongmai backdoor ve anonim device-info sondaları; ONVIF device-service istemcisi (GetDeviceInformation / GetProfiles / GetStreamUri) WS-UsernameToken (PasswordDigest) + Basic + Digest fallback |
| **Otonom Kamera Erişimi** | RTSP yol keşfi, kimliksiz açık akış denemesi, ~96 geniş varsayılan kimlik DB'si + harici wordlist, Basic/Digest doğrulama, elle kimlik girişi ve HTTP snapshot; tüm ağ işlemleri tek arka plan işçi thread'inde (arayüz bloke olmaz) |
| **Uygulama-içi İzleme** | Görünmez `ffmpeg` alt-süreci ile RTSP/MJPEG çözüp raylib texture'a basar (harici oynatıcı/browser yok); çoklu akış grid (`VS_MAX_STREAMS=8`), anlık kare (snapshot), kayıt (yeniden kodlama yok), otomatik yeniden bağlanma, yazılım/VAAPI/NVDEC decode |

---

## 3. Arayüz (GUI)

Uygulama üç ana sekmeden oluşur:

- **Kontrol Paneli** — `AĞDAKİ CİHAZLAR` listesi, cihaz detayı, **`İZLEME LİSTESİ`**,
  `ENGELLENEN CİHAZLAR` paneli ve `TARAMA KAYITLARI`. Cihaz satırındaki
  **KES/AÇ** düğmesi ARP black-hole motorunu tetikler; keşif sonrası listeye
  cihaz eklemek için **TÜMÜNÜ EKLE** kullanılır. Sağ kolonda ayrıca
  **`KAMERA LİSTESİ`** paneli bulunur: keşfedilen kameralar (güven skoru/
  kanıt rozetleriyle) ve **KAMERA BUL** / **BOŞALT** düğmeleri.
- **Alarm Merkezi** — `TEHDİT ALARMLARI` listesi (önem derecesine göre renkli:
  KRİTİK/YÜKSEK/ORTA/DÜŞÜK), tehdit haritası ve izlemeyi başlat/durdur kontrolü.
- **Araçlar** — dört alt sekme:
  1. **Paket İzleme** — canlı paket listesi, display filtre kutusu, PDU/hex
     detayı, `.pcap` kaydı.
  2. **Site Karartma** — hangi IP hangi siteye gitti (gözlem listesi), tek
     tıkla kurala çevirme, aktif kurallar, karartmayı aç/kapat.
  3. **Port Tarayıcı** — hedef cihaz seç, tarama tipi/stealth ayarı, açık
     port + servis + sürüm + CVE sonuçları.
  4. **Kameralar** — kamera hattının ana yüzeyi (solda kamera listesi; sağda
     seçili kameranın detay paneli). Eylemler: **İZLE** (canlı görüntü),
     **ANLIK GÖRÜNTÜ**, **KAYIT**, **OTONOM ERİŞ** (varsayılan kimlik +
     zafiyet yolları), **PARMAK İZİ + ONVIF**, **ZAFİYET SONDASI** ve elle
     kullanıcı/parola girişi. Dashboard'daki `KAMERA LİSTESİ` ile **aynı**
     listeyi paylaşır (tek doğruluk kaynağı `gui_camera.c`).

---

## 4. Bağımlılıkların Kurulumu (Kali Linux)

```bash
# 1. Paket listesini güncelle
sudo apt update && sudo apt upgrade -y

# 2. Derleme araçları
sudo apt install -y build-essential cmake pkg-config git

# 3. libpcap (paket yakalama)
sudo apt install -y libpcap-dev

# 4. OpenGL ve X11 başlıkları (Raylib için zorunlu)
sudo apt install -y libgl1-mesa-dev libgles2-mesa-dev \
    libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev \
    libxi-dev libxext-dev

# 5. Raylib
sudo apt install -y libraylib-dev

# 6. (Önerilen) QUIC SNI çözümleme + kamera TLS sondası için OpenSSL
sudo apt install -y libssl-dev

# 7. (Kamera izleme için) ffmpeg/ffprobe
#    RTSP/MJPEG akışını uygulama-içinde çözmek için kullanılır.
#    Yoksa keşif/erişim çalışır ama canlı görüntü açılamaz.
sudo apt install -y ffmpeg
```

**Raylib depoda yoksa** kaynak koddan derleyin:

```bash
git clone --depth 1 --branch 5.5 https://github.com/raysan5/raylib.git /tmp/raylib-src
cd /tmp/raylib-src
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON
make -j$(nproc)
sudo make install
sudo ldconfig
cd ~
```

Kurulumu doğrulayın:

```bash
pkg-config --modversion raylib    # örn. 5.5.0
pkg-config --modversion libpcap   # örn. 1.10.5
pkg-config --modversion openssl   # opsiyonel
ffmpeg -version                   # kamera izleme için (runtime)
```

> CMake, `raylib` ve `libpcap` için `pkg-config` kullanır. Yukarıdaki
> `.pc` dosyaları bulunabiliyorsa derleme sorunsuz geçer. OpenSSL bulunamazsa
> `quic_sni.c` derlemeden çıkar (ICMP fallback devreye girer) + kamera HTTPS
> sondası devre dışı kalır (Basic/Digest/ONVIF yine çalışır) — derleme yine de
> başarılı olur. **ffmpeg derleme için gerekmez**; yalnızca canlı izleme/kayıt/
> snapshot çalışma zamanında çağrılır ve yokluğu arayüzde bildirilir.

---

## 5. Derleme

Proje kökünde:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Çıktı: **`build/beat_system`**

Derleme sırasında konsol, OpenSSL bulunup bulunmadığını ve platform
bilgisini bildirir:

```
-- OpenSSL bulundu: QUIC SNI cozumleme + kamera TLS sondasi aktif
-- Platform: Linux
-- Derleyici: /usr/bin/cc
```

---

## 6. Çalıştırma

### 6.1 Normal (GUI) mod

```bash
./build/beat_system
```

Raylib penceresi açılır ve otonom ağ taraması başlar. Root değilseniz uygulama
yine açılır ancak pcap yakalama, raw tarama ve müdahale motorları sınırlı
çalışır (yakalama `procfs` fallback'e düşer: yalnızca yerel soketler görünür).

> **İlk adım:** Keşif bittikten sonra Kontrol Paneli'nde listede görünen
> cihazları **TÜMÜNÜ EKLE** ile İzleme Listesi'ne alın; ardından **Ağı İzle**'yi başlatın. Boş izleme listesiyle IDS pasif kalır.

### 6.2 Root modu — tam özellik seti (önerilen)

Paket yakalama, raw port taramaları (SYN/FIN/Xmas...), ARP black-hole,
site karartma ve iptables katmanı **root yetkisi gerektirir**. `sudo` ile
GUI açmak için önce X11 display izni verin:

```bash
xhost +local:root            # X11 display izni
sudo ./build/beat_system     # tam özellik setiyle çalıştır
xhost -local:root            # iş bitince izni geri al
```

> Kamera keşfi raw ARP süpürmesi de kullanır; root ile daha eksiksiz sonuç
> verir. Root olmadan da TCP port/RTSP/HTTP/ONVIF/SSDP/mDNS tabanlı keşif
> çalışır.

### 6.3 Headless mod (GUI'siz IDS)

GUI açmadan, gerçek trafiği IDS motoruna besleyip uyarı üretmek için:

```bash
sudo ./build/beat_system --headless [SEÇENEKLER]
```

> **Dikkat (scope):** Headless modda `--scope` / `--scope-cidr` verilmezse
> İzleme Listesi boş kalır, IDS tamamen pasif olur ve hiçbir uyarı üretilmez.
> IDS'ten çıktı almak istiyorsanız bu seçeneklerden birini mutlaka verin.

| Seçenek | Açıklama |
|---|---|
| `--iface <ad>` | Yakalama arayüzü (varsayılan: otomatik) |
| `--scope <ip,ip,...>` | İzleme listesi (virgülle ayrılmış IP'ler) |
| `--scope-cidr <CIDR>` | İzleme listesini CIDR'den üret (örn. `192.168.1.0/24`) |
| `--local-ip <ip>` | Bu makinenin IP'si (self-traffic filtresi) |
| `--local-mac <mac>` | Bu makinenin MAC'i (ARP spoof tespiti için) |
| `--gateway-ip <ip>` | Ağ geçidi IP (varsayılan: otomatik) |
| `--gateway-mac <mac>` | Ağ geçidi MAC (varsayılan: otomatik) |
| `--duration <sn>` | Çalışma süresi (0 = sonsuz, Ctrl+C ile dur) |
| `--out <dosya>` | Uyarıları JSONL olarak bu dosyaya da yaz |
| `--quiet` | Uyarı başlıklarını yazma (yalnızca sayaç) |
| `--help` / `-h` | Kullanım bilgisi |

Örnek — 24 saatlik segmenti 60 sn izle ve alarmları JSONL'e dök:

```bash
sudo ./build/beat_system --headless \
    --iface eth0 \
    --scope-cidr 192.168.1.0/24 \
    --duration 60 \
    --out alerts.jsonl
```

Çıkışta özet basılır: işlenen paket, toplam uyarı, bastırılan yanlış-pozitif,
aktif izleyici sayısı.

---

## 7. Kamera Modülü (Keşif → Erişim → İzleme)

Kamera hattı dört motordan oluşur ve tamamı arayüzden sürülür. Hiçbiri İzleme
Listesi'ne bağlı değildir.

### 7.1 Keşif — `camera_discovery`

Kamerayı tek bir sinyalle değil, **çoklu kanıt** ile doğrular; her kamera için
kanıt bit maskesi ve 0-100 güven skoru üretir (`CAM_EV_PORT`, `CAM_EV_RTSP`,
`CAM_EV_RTSP_AUTH`, `CAM_EV_HTTP`, `CAM_EV_ONVIF`, `CAM_EV_OUI`, `CAM_EV_VPORT`).

| Yöntem | Detay |
|---|---|
| Kamera-imzalı port taraması | `554, 8554, 8555, 80, 8080, 81, 88, 8000, 8081, 37777, 34567, 8899, 9000, 443, 1024, 5000` gibi geniş set; üretici portları (37777/34567/8899/8000) ayrıca işaretlenir |
| RTSP sondası | `OPTIONS` / `DESCRIBE`; `Server` başlığı ve `401 realm` çıkarımı |
| HTTP web arayüzü | `Server` başlığı + kamera imza kelimeleri |
| ONVIF WS-Discovery | UDP `239.255.255.250:3702` multicast `Probe` |
| SSDP/UPnP | UDP `239.255.255.250:1900` `ssdp:all` M-SEARCH |
| mDNS/Bonjour | UDP `224.0.0.251:5353` |
| MAC OUI | Bilinen kamera üreticisi veritabanı |
| DNS yanıt toplama | Ek host keşfi (self/gateway hariç) |

**Kendi ağın dışlanır:** keşif başlamadan `gather_self_info()`, makinenin tüm
yerel IP'lerini, gateway'i, ağ/broadcast adresini toplar. `is_excluded_host()`
şu adresleri **hiçbir** host-koleksiyon noktasında (ARP taraması, SSDP/mDNS,
DNS yanıtları, port sondası) listeye almaz:

- Makinenin kendi IP'leri (`is_self_ip`)
- Ağ geçidi (gateway) IP'si
- Ağ adresi (`.0`) ve broadcast (`.255`)
- Multicast ve link-local (169.254.x.x) adresler

Böylece "kameralar" listesinde **kendi local makinen ve gateway** görünmez;
onlar yalnızca bağlam bilgisi olarak kullanılır. Tarama aşamaları ilerlemeyi
(`progress`, `phase`, `scanned/total/responded hosts`) canlı raporlar; tek
tarama üst sınırı `CAM_MAX_HOSTS=1024`, işçi sayısı `CAM_MAX_WORKERS=32`.

Arayüzden **KAMERA BUL** ile başlatılır; tarama arka planda (`start_async`)
çalışır ve iptal edilebilir.

### 7.2 Parmak izi & zafiyet sondaları — `camera_vuln`

| Yetenek | Açıklama |
|---|---|
| HTTP parmak izi | Üreticiye özel device-info endpoint'lerinden model / firmware / seril numarası |
| Hikvision | ISAPI `auth-token` bilgi sızıntısı + kullanıcı listesi sızıntısı |
| Dahua | RPC2 kimlik atlatma denemesi |
| Xiongmai | Varsayılan arka kapı hesabı + anonim device-info |
| ONVIF istemcisi | `GetDeviceInformation` / `GetProfiles` / `GetStreamUri`; kimlik `WS-UsernameToken` (PasswordDigest, HMAC-SHA1) + HTTP Basic + HTTP Digest fallback; kimliksiz de denenir |
| Kimlik veritabanı | Geniş varsayılan tablo + `kullanici:parola` biçiminde harici wordlist yükleyici |

Sonda sonuçları `CAM_VULN_*` bayrakları olarak kaydedilir ve arayüzde gösterilir.

### 7.3 Otonom erişim — `camera_access`

1. RTSP yol keşfi (sık kullanılan akış yolları, hızlı `DESCRIBE`).
2. Kimliksiz açık akış denemesi.
3. Varsayılan kimlik listesi (~96 aday; `admin/admin`, `admin/12345`, …).
4. Elle girilen kullanıcı/parola.

Başarıda kameranın çalışan akış URL'si (gerekirse `user:pass` gömülü)
`found_url`'e yazılır; arayüz bunu `video_stream` ile açıp grid'de gösterir.
Tüm ağ işlemleri **tek arka plan işçi thread'inde** yürür — GUI bloke olmaz.

### 7.4 Uygulama-içi izleme — `video_stream`

Kameralar **harici bir oynatıcıda/browser'da değil, doğrudan BEAT penceresi
içinde** çizilir (meterpreter tarzı tek pencere).

- Her akış için görünmez bir `ffmpeg` alt-süreci + okuyucu thread.
- Texture oluşturma/güncelleme yalnızca ana (render) thread'de.
- Düşük gecikme: `nobuffer/low_delay`, sabit decode çözünürlüğü, fps sınırı.
- Çoklu akış (8 slota kadar), anlık kare (snapshot), kayıt (`-c copy`, yeniden
  kodlama yok, isteğe bağlı segmentlere bölme), kopunca **otomatik yeniden
  bağlanma**.
- Decode: yazılım / VAAPI (Intel-AMD) / NVDEC (NVIDIA).

### 7.5 Kamera modülünü test etme (testbed)

Gerçek kamera olmadan modülü uçtan uca denemek için `testbed/` altında
`mediamtx` tabanlı bir yazılım testbedi vardır (4 açık RTSP + 1 korumalı RTSP +
1 MJPEG sahte kamera; H.264/H.265/MJPEG):

```bash
cd testbed
./start.sh     # başlat + ffprobe ile doğrula
./stop.sh      # hepsini kapat
```

> **Testbed gereksinimleri (yalnızca testbed için, ana derleme için değil):**
> `docker` (host-network erişimi ile) + `python3` + `ffmpeg`/`ffprobe`. İlk
> çalıştırmada `bluenviron/mediamtx:latest` imajı otomatik çekilir. Üretim
> kullanımında testbed gerekmez.

Ayrıntılı kamera haritası ve hesaplar için `testbed/README.md`'ye bakın.

---

## 8. Neden root gerekiyor?

| Yetenek | Gerekçe |
|---|---|
| Canlı paket yakalama | `AF_PACKET` / `libpcap` ham soket erişimi |
| Raw port taramaları | SYN/FIN/NULL/Xmas/ACK gibi yarı-açık taramalar ham TCP üretir |
| ARP black-hole | Ham ARP çerçevesi enjeksiyonu |
| Site karartma | Ham enjeksiyon + `iptables` (`BEAT_SB` zinciri) yönetimi |
| QUIC ICMP fallback | Ham `AF_INET` soketi ile ICMP üretimi |
| Kamera ARP keşfi | Ham ARP süpürmesi (root olmadan `/proc/net/arp` / `ip neigh` fallback) |

Root olmadan uygulama "kısıtlı mod"da çalışır: TCP connect taraması, pasif
procfs gözlemi ve GUI kullanılabilir; ham soket gerektiren müdahaleler devre
dışı kalır ve motorlar bunu arayüzde rozet/uyarı olarak bildirir.

---

## 9. Proje Yapısı

```
BEAT-System/
├── CMakeLists.txt              # Bağımlılıklar, OpenSSL tespiti, hedef tanımı
├── README.md                   # Bu dosya
├── include/                    # Başlık dosyaları
│   ├── platform.h              # Platform soyutlaması (thread, mutex, iface)
│   ├── utils.h                 # Dinamik dizi, hash map, string/IP/zaman yardımcıları
│   ├── arp_scanner.h           # Ağ keşfi arayüzü
│   ├── arp_block.h             # ARP black-hole motoru arayüzü
│   ├── port_scanner.h          # Stealth port tarayıcı arayüzü
│   ├── network_monitor.h       # PCAP yakalama + paket kaydı + PDU modeli
│   ├── network_ids.h           # IDS kural motoru ve LAN tehdit modeli
│   ├── filter_engine.h         # Display filtre ayrıştırıcı
│   ├── raw_inject.h            # Ham Ethernet/IP/UDP/TCP kare enjeksiyonu
│   ├── quic_sni.h              # QUIC Initial → TLS SNI çıkarımı
│   ├── site_block.h            # Site karartma motoru (sinkhole/RST/iptables)
│   ├── cam_net.h               # Kamera için TCP/TLS + HTTP istemci + MD5/SHA1/HMAC/base64 + Digest
│   ├── camera_discovery.h      # Kamera keşif motoru (port/RTSP/HTTP/ONVIF/OUI + kanıt/güven skoru)
│   ├── camera_access.h         # Otonom erişim motoru (yol keşfi, kimlik denemesi, snapshot)
│   ├── camera_vuln.h           # Parmak izi + zafiyet sondaları + ONVIF istemcisi + kimlik DB
│   ├── video_stream.h          # Uygulama-içi RTSP/MJPEG izleme (ffmpeg → raylib texture)
│   ├── gui_camera.h            # Kamera GUI modülü arayüzü (Dashboard paneli + Araçlar sekmesi)
│   └── gui.h                   # GUI modülü arayüzü ve tema paleti
├── lib/
│   └── raygui.h                # Raygui (header-only)
├── src/
│   ├── main.c                  # Giriş noktası: GUI + headless modlar
│   ├── platform.c              # Thread / mutex / arayüz soyutlamaları
│   ├── utils.c                 # Yardımcı fonksiyonlar
│   ├── arp_scanner.c           # Ağ keşfi (raw ARP / /proc/net/arp / ip neigh)
│   ├── arp_block.c             # ARP black-hole motoru
│   ├── port_scanner.c          # Port tarama (TCP connect + raw varyantlar)
│   ├── network_monitor.c       # libpcap yakalama, L2–L7 dissector, pcap kaydı
│   ├── network_ids.c           # IDS kuralları, akış/host tablosu, skorlama
│   ├── filter_engine.c         # Display filtre ayrıştırıcı
│   ├── raw_inject.c            # Ham kare kurucu/gönderici + checksum
│   ├── quic_sni.c              # QUIC SNI çözücü (OpenSSL)
│   ├── site_block.c            # Site karartma + iptables katmanı
│   ├── cam_net.c               # Kamera ağ/kripto altyapısı (saf-C MD5/SHA1/HMAC, HTTP, Digest)
│   ├── camera_discovery.c      # Kamera keşfi: ARP+port+RTSP+HTTP+ONVIF+SSDP/mDNS+OUI, self/gateway dışlama
│   ├── camera_access.c         # Otonom erişim: yol keşfi, varsayılan/elle kimlik, arka plan işçi
│   ├── camera_vuln.c           # Parmak izi, Hikvision/Dahua/Xiongmai sondaları, ONVIF, wordlist
│   ├── video_stream.c          # Görünmez ffmpeg alt-süreci → RGB kare → Texture2D; kayıt/reconnect
│   ├── gui_camera.c            # Kamera GUI modülü (Dashboard paneli + Araçlar▸Kameralar)
│   └── gui.c                   # Raylib/Raygui arayüz (3 sekme)
├── testbed/                    # Kamera modülü yazılım testbedi (mediamtx + MJPEG)
│   ├── start.sh / stop.sh      # Testbed başlat/durdur (ffprobe ile doğrulama)
│   ├── mediamtx-open.yml       # Açık RTSP sunucusu yapılandırması
│   ├── mediamtx-auth.yml       # Korumalı RTSP sunucusu (kimlik testi)
│   ├── mjpeg_server.py         # MJPEG-over-HTTP sahte kamera
│   ├── test_camera_discovery.c # Keşif motoru bağımsız testi
│   └── README.md               # Testbed kamera haritası ve kullanımı
└── assets/fonts/               # GUI yazı tipleri
```

> `build/` dizini derleme çıktısıdır ve sürüm kontrolüne dahil edilmez.

---

## 10. Notlar ve Bilinen Sınırlar

- **Doğrulama:** IDS kural motoru, akış tablosu ve site karartma yolları
  geliştirme sırasında kural/paket düzeyinde test edilmiştir; gerçek trafikte
  yanlış-pozitif oranını ölçmek için `--headless` modu kullanılabilir.
- **QUIC:** SNI çözümleme OpenSSL'e bağlıdır; OpenSSL olmadan UDP/443
  trafiği için `ICMP port unreachable` fallback'i uygulanır.
- **ARP black-hole MITM değildir:** trafik yönlendirilmez, yalnızca hedefin
  ARP tablosu zehirlenir; kaldırma işlemi doğru ARP Reply'ları ile anında
  geri alınır (ARP zaten 30–60 sn içinde kendiliğinden düzelir).
- **Kamera hattı — sahada uçtan uca test:** keşif/erişim/izleme kod yolu
  derlenmiş ve GUI render'ı doğrulanmıştır; ancak gerçek kamera karşısında
  uçtan uca (bul → auth → stream) doğrulama için `testbed/` kullanılmalıdır.
  Farklı marka/firmware'lerde başarı; kameranın sertleştirme durumuna, kimlik
  politikasına ve ağ segmentasyonuna bağlıdır.
- **TLS sondası:** HTTPS/ONVIF-over-TLS denemeleri yalnızca OpenSSL derlemede
  tanımlıysa çalışır; aksi halde HTTPS adımı atlanır (Basic/Digest/RTSP yine
  denenir).
- **ffmpeg bağımlılığı:** canlı izleme, snapshot ve kayıt çalışma zamanında
  `ffmpeg`'e bağlıdır; binary yoksa keşif/erişim çalışır ama görüntü açılamaz.

---

## 11. Yasal Uyarı

Bu araç **yalnızca eğitim ve yetkili güvenlik testleri** amacıyla
geliştirilmiştir. Sahip olmadığınız veya test etme izniniz bulunmayan ağ ve
sistemlere karşı kullanmak yasaktır. Kullanım sorumluluğu tamamen kullanıcıya
aittir.
