# BEAT System

**Tek pencereden yerel ağ güvenliği:** cihaz keşfi, canlı trafik görünürlüğü,
kural tabanlı saldırı tespiti (IDS) ve aktif müdahale (ağdan kesme / site
karartma) — hepsi C11 ile yazılmış, Raylib tabanlı tek bir masaüstü
uygulamasında.

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
| **5. Müdahale** | Seçilen cihazı ağdan keser veya seçilen siteyi karartır | `arp_block` + `site_block` |

Buna ek olarak hedef bazlı derinlemesine inceleme için `port_scanner` (stealth
port/servis/zafiyet taraması) ayrı bir araç sekmesinde sunulur.

### Veri hattı (modüller nasıl bağlanıyor?)

```
          ┌─────────────────────────────────────────────────┐
          │ BEAT System — tek süreç, tek veri hattı         │
          └──────────────────────┬──────────────────────────┘
                                  │
[1] KEŞİF ────────────────────────┤
  arp_scanner: raw ARP sweep + ip neigh
                                  │
                                  ▼
                   ┌──────────────┬─────────────┐
                   │        İZLEME LİSTESİ      │
                   │           (scope)          │
                   └──────────┬─────────────────┘
                              │
[2] GÖRÜNÜRLÜK ───────────────┤
  network_monitor (libpcap) → filter_engine
  └─ L2..L7 dissector, app_domain (DNS / TLS SNI / HTTP / QUIC)
                              │
[3] TESPİT ───────────────────┤
  network_ids (~20 kural) → skor + alarm
  └─ GUI: Alarm Merkezi + Tehdit Haritası
                              │
[4] MÜDAHALE ─────────────────┤
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

**İzleme Listesi'ne bakmayan iki yüzey** diyagramda ayrı kutuda gösterilmiştir:
`port_scanner` (hedefi manuel seçersiniz) ve ARP Black-Hole **KES/AÇ**
(cihaz satırından tek tıkla tetiklenir). Bunlar dışındaki tüm işlevler, izleme
listesinin dolu olmasına bağlıdır.

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

---

## 3. Arayüz (GUI)

Uygulama üç sekmeden oluşur:

- **Kontrol Paneli** — `AĞDAKİ CİHAZLAR` listesi, cihaz detayı, **`İZLEME LİSTESİ`**,
  `ENGELLENEN CİHAZLAR` paneli ve `TARAMA KAYITLARI`. Cihaz satırındaki
  **KES/AÇ** düğmesi ARP black-hole motorunu tetikler; keşif sonrası listeye
  cihaz eklemek için **TÜMÜNÜ EKLE** kullanılır.
- **Alarm Merkezi** — `TEHDİT ALARMLARI` listesi (önem derecesine göre renkli:
  KRİTİK/YÜKSEK/ORTA/DÜŞÜK), tehdit haritası ve izlemeyi başlat/durdur kontrolü.
- **Araçlar** — üç alt sekme:
  1. **Paket İzleme** — canlı paket listesi, display filtre kutusu, PDU/hex
     detayı, `.pcap` kaydı.
  2. **Site Karartma** — hangi IP hangi siteye gitti (gözlem listesi), tek
     tıkla kurala çevirme, aktif kurallar, karartmayı aç/kapat.
  3. **Port Tarayıcı** — hedef cihaz seç, tarama tipi/stealth ayarı, açık
     port + servis + sürüm + CVE sonuçları.

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

# 6. (Opsiyonel) QUIC SNI çözümleme için OpenSSL
sudo apt install -y libssl-dev
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
```

> CMake, `raylib` ve `libpcap` için `pkg-config` kullanır. Yukarıdaki üç
> `.pc` dosyası bulunabiliyorsa derleme sorunsuz geçer. OpenSSL bulunamazsa
> `quic_sni.c` derlemeden çıkar (ICMP fallback devreye girer) — derleme
> yine de başarılı olur.

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
-- OpenSSL bulundu: QUIC SNI cozumleme aktif
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
> cihazları **TÜMÜNÜ EKLE** ile İzleme Listesi'ne alın; ardından Alarm
> Merkezi'nden **Ağı İzle**'yi başlatın. Boş izleme listesiyle IDS pasif kalır.

### 6.2 Root modu — tam özellik seti (önerilen)

Paket yakalama, raw port taramaları (SYN/FIN/Xmas...), ARP black-hole,
site karartma ve iptables katmanı **root yetkisi gerektirir**. `sudo` ile
GUI açmak için önce X11 display izni verin:

```bash
xhost +local:root            # X11 display izni
sudo ./build/beat_system     # tam özellik setiyle çalıştır
xhost -local:root            # iş bitince izni geri al
```

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

## 7. Neden root gerekiyor?

| Yetenek | Gerekçe |
|---|---|
| Canlı paket yakalama | `AF_PACKET` / `libpcap` ham soket erişimi |
| Raw port taramaları | SYN/FIN/NULL/Xmas/ACK gibi yarı-açık taramalar ham TCP üretir |
| ARP black-hole | Ham ARP çerçevesi enjeksiyonu |
| Site karartma | Ham enjeksiyon + `iptables` (`BEAT_SB` zinciri) yönetimi |
| QUIC ICMP fallback | Ham `AF_INET` soketi ile ICMP üretimi |

Root olmadan uygulama "kısıtlı mod"da çalışır: TCP connect taraması, pasif
procfs gözlemi ve GUI kullanılabilir; ham soket gerektiren müdahaleler devre
dışı kalır ve motorlar bunu arayüzde rozet/uyarı olarak bildirir.

---

## 8. Proje Yapısı

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
│   └── gui.c                   # Raylib/Raygui arayüz (3 sekme)
└── assets/fonts/               # GUI yazı tipleri
```

> `build/` dizini derleme çıktısıdır ve sürüm kontrolüne dahil edilmez.

---

## 9. Notlar ve Bilinen Sınırlar

- **Doğrulama:** IDS kural motoru, akış tablosu ve site karartma yolları
  geliştirme sırasında kural/paket düzeyinde test edilmiştir; gerçek trafikte
  yanlış-pozitif oranını ölçmek için `--headless` modu kullanılabilir.
- **QUIC:** SNI çözümleme OpenSSL'e bağlıdır; OpenSSL olmadan UDP/443
  trafiği için `ICMP port unreachable` fallback'i uygulanır.
- **ARP black-hole MITM değildir:** trafik yönlendirilmez, yalnızca hedefin
  ARP tablosu zehirlenir; kaldırma işlemi doğru ARP Reply'ları ile anında
  geri alınır (ARP zaten 30–60 sn içinde kendiliğinden düzelir).

---

## 10. Yasal Uyarı

Bu araç **yalnızca eğitim ve yetkili güvenlik testleri** amacıyla
geliştirilmiştir. Sahip olmadığınız veya test etme izniniz bulunmayan ağ ve
sistemlere karşı kullanmak yasaktır. Kullanım sorumluluğu tamamen kullanıcıya
aittir.
