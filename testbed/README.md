# BEAT Kamera Testbedi

Gerçek bir IP-kamera ağı olmadan kamera modülünü (keşif + otonom erişim + uygulama-içi
canlı izleme) test etmek için kurulan yazılım testbedi. İki `mediamtx` RTSP sunucusu,
beş RTSP "kamera" ve bir MJPEG-over-HTTP "kamera" ayağa kaldırır.

## Hızlı başlangıç

```bash
cd testbed
./start.sh          # başlat + ffprobe ile doğrula
./stop.sh           # hepsini kapat
```

`start.sh` çıktısındaki `[OK]` satırları tüm kameraların yayında olduğunu doğrular.

## Gereksinimler

- Docker (host network erişimi ile) — `bluenviron/mediamtx:latest` imajı
- `ffmpeg` / `ffprobe` (yayın üretimi ve doğrulama)
- `python3` (MJPEG sunucusu)

## Kamera haritası

| Kamera | Tip | Adres | Kodek | Çözünürlük | Kimlik |
|--------|-----|-------|-------|-----------|--------|
| cam1 | RTSP (açık) | `rtsp://127.0.0.1:8554/cam1` | H.264 | 640x360 | yok |
| cam2 | RTSP (açık) | `rtsp://127.0.0.1:8554/cam2` | H.264 | 1280x720 | yok |
| cam3 | RTSP (açık) | `rtsp://127.0.0.1:8554/cam3` | H.265 | 640x360 | yok |
| cam4 | RTSP (açık) | `rtsp://127.0.0.1:8554/cam4` | H.264 | 320x240 | yok |
| authcam | RTSP (korumalı) | `rtsp://127.0.0.1:8555/cam1` | H.264 | 640x360 | aşağıya bakınız |
| mjpeg | HTTP MJPEG | `http://127.0.0.1:8090/stream.mjpg` | MJPEG | 640x360 | yok |

### Korunan sunucu (:8555) hesapları

| Kullanıcı | Parola | Yetki | Amaç |
|-----------|--------|-------|------|
| `admin` | `admin123` | publish + read | güçlü-parola ofis senaryosu |
| `viewer` | `12345` | read | zayıf-parola senaryosu |
| `guest` | *(boş)* | read | boş-parola senaryosu |

Anonim (kimliksiz) erişim **reddedilir** — erişim motorunun kimlik denemesi burada test edilir.

## Neyi test eder?

1. **Keşif:** açık portlar (8554, 8555, 8090), RTSP OPTIONS/DESCRIBE imzaları, OUI/vendor tespiti.
2. **Erişim motoru:** açık akışa doğrudan bağlanma; korunan akışta varsayılan ve elle girilen
   kimlik bilgilerini deneme (`admin:admin123`, `viewer:12345`, `guest:`).
3. **Canlı izleme:** FFmpeg ile RTSP/MJPEG → raylib texture; 1/2/3/4 kamerayı otonom grid'de gösterme.
4. **Kodek çeşitliliği:** H.264, H.265 ve MJPEG akışlarının doğru işlenmesi.
5. **Donanım decode:** VAAPI (Intel UHD) ve NVDEC (RTX) yolunun bu akışlarla testi.

## Notlar

- Sunucular `--network host` ile çalışır; RTSP `:8554` (açık) ve `:8555` (korumalı) doğrudan host
  üzerindedir, uygulama `127.0.0.1`'e bağlanır.
- Çakışmayı önlemek için HLS/WebRTC/API/SRT/MoQ kapalı; RTP/RTCP portları 8010/8011 ve 8020/8021'e taşındı.
- Yayıncı PID dosyaları `/tmp/beat-cam/*.pid` altındadır; `stop.sh` bunları kullanır
  (pkill yerine PID — pkill kalıbı kendi komut satırıyla eşleşip kabuğu öldürebilir).
- Testbed kalıcı değildir: `stop.sh` her şeyi siler, kalıntı bırakmaz.
