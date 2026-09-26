# BEAT System

> Raylib tabanlı, tek pencereden ağ keşfi, port taraması, canlı trafik izleme ve saldırı tespiti (IDS) sunan C11 güvenlik aracı.
> **Hedef platform: Kali Linux (x86_64)**

---

## 📋 Özellikler

| Modül | Açıklama |
|---|---|
| **Modern GUI** | Raylib + Raygui ile geliştirilmiş, çözünürlükten bağımsız ölçeklenen arayüz |
| **Ağ Keşfi (ARP Scanner)** | Raw ARP soketleri ile sweep, `/proc/net/arp` ve `ip neigh` ile cihaz tespiti |
| **Ağdan Kesme (ARP Black-Hole)** | Raw `AF_PACKET` soketleri ile hedef cihaza sürekli sahte ARP yanıtı göndererek internet erişimini keser/geri verir |
| **Otonom Port Tarayıcı (AutoPort)** | Nmap bağımsız, çok kanallı (thread pool) TCP/raw port ve servis analizi; TTL tabanlı OS tahmini |
| **Canlı Trafik İzleme** | `libpcap` ile gerçek zamanlı paket yakalama ve L3/L4 ayrıştırma |
| **İzleme Listesi (Mon List)** | Ağ izleyicisi ve ARP saldırılarını belirli IP'lerle sınırlandır |
| **Ağ IDS** | 20 kural: ARP spoofing, MITM, sahte TCP bayrakları, yatay/dikey port taraması, SSH brute-force, SQLi/XSS/JNDI/Meterpreter imzaları |
| **Display Filtre Motoru** | Wireshark tarzı filtre ifadeleri (`ip.addr == 10.0.0.5 && tcp.port == 443`) — 138 birim testle doğrulanmış |

---

## 📦 Bağımlılık Kurulumu (Kali Linux)

```bash
# 1. Paket listesini güncelle
sudo apt update && sudo apt upgrade -y

# 2. Derleme araçları
sudo apt install -y build-essential cmake pkg-config git

# 3. libpcap
sudo apt install -y libpcap-dev

# 4. OpenGL ve X11 başlıkları (Raylib için zorunlu)
sudo apt install -y libgl1-mesa-dev libgles2-mesa-dev \
    libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev \
    libxi-dev libxext-dev

# 5. Raylib — Kali deposunda varsa:
sudo apt install -y libraylib-dev

# Depoda yoksa (hata alırsanız) kaynak koddan derleyin:
git clone --depth 1 --branch 5.0 https://github.com/raysan5/raylib.git /tmp/raylib-src
cd /tmp/raylib-src
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DWITH_PIC=ON
make -j$(nproc)
sudo make install
sudo ldconfig
cd ~
```

> 💡 Kurulumu doğrulamak için: `pkg-config --modversion raylib` → `5.0.0` gibi bir sürüm döndürmeli.

---

## 🚀 Derleme

```bash
# Proje kökünde:
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Çalıştırılabilir dosya: `build/beat_system`

---

## 🏁 Çalıştırma

### Normal mod

```bash
./build/beat_system
```

### Root modu — tam özellik seti (önerilen)

SYN/FIN/Xmas raw taramaları, ARP black-hole ve libpcap yakalama **root yetkisi gerektirir**.

```bash
xhost +local:root          # X11 display izni (sudo ile GUI açmak için)
sudo ./build/beat_system
xhost -local:root          # işlem bitince izni geri al
```

---

## 🧪 Testler

```bash
# Display Filtre Motoru (138 test)
gcc -std=c11 -D_GNU_SOURCE -Iinclude tests/filter_engine_test.c src/filter_engine.c src/utils.c -o /tmp/fetest && /tmp/fetest

# LAN Akış Testi
gcc -std=c11 -D_GNU_SOURCE -Iinclude tests/lan_flow_test.c src/filter_engine.c src/utils.c -o /tmp/lantest && /tmp/lantest

# Monitor/Ayrıştırma Testi
gcc -std=c11 -D_GNU_SOURCE -Iinclude tests/monitor_dissect_test.c src/filter_engine.c src/utils.c -o /tmp/montest && /tmp/montest
```

---

## 📁 Proje Yapısı

```
BEAT-System/
├── CMakeLists.txt              # Bağımlılıklar ve derleme yapılandırması
├── README.md                   # Bu dosya
├── include/                    # Başlık dosyaları
│   ├── platform.h              # Platform soyutlaması (thread, iface shims)
│   ├── arp_scanner.h           # Ağ keşfi arayüzü
│   ├── arp_block.h             # ARP black-hole motoru arayüzü
│   ├── port_scanner.h          # Port tarayıcı arayüzü
│   ├── network_monitor.h       # PCAP izleme arayüzü
│   ├── network_ids.h           # IDS kural motoru arayüzü
│   ├── filter_engine.h         # Display filtre ayrıştırıcı arayüzü
│   ├── gui.h                   # GUI modülü arayüzü
│   └── utils.h                 # Yardımcı araçlar (hashmap, str, log)
├── lib/
│   └── raygui.h                # Raygui (header-only, tek dosya)
├── src/
│   ├── main.c                  # Giriş noktası
│   ├── platform.c              # Thread ve platform soyutlaması
│   ├── utils.c                 # Yardımcılar
│   ├── arp_scanner.c           # Ağ keşfi (raw ARP / /proc/net/arp)
│   ├── arp_block.c             # ARP black-hole motoru (AF_PACKET raw)
│   ├── port_scanner.c          # Port tarama (TCP connect + raw soket)
│   ├── network_monitor.c       # libpcap canlı yakalama ve ayrıştırma
│   ├── network_ids.c           # IDS kuralları ve alert motoru
│   ├── filter_engine.c         # Display filtre ayrıştırıcı
│   └── gui.c                   # Raylib/Raygui grafik arayüzü
├── assets/fonts/               # GUI yazı tipleri
├── tests/
│   ├── filter_engine_test.c    # Display filtre birim testleri (138 test)
│   ├── lan_flow_test.c         # LAN akış testleri
│   └── monitor_dissect_test.c  # Paket ayrıştırma testleri
└── build/                      # Derleme çıktısı (.gitignore'da)
```

---

## ⚠️ Yasal Uyarı

Bu araç **yalnızca eğitim ve yetkili güvenlik testleri** amacıyla geliştirilmiştir.
Sahip olmadığınız veya test etme izniniz bulunmayan ağ ve sistemlere karşı kullanmak yasaktır.
Kullanım sorumluluğu tamamen kullanıcıya aittir.
