/*
 * video_stream.h — Uygulama-ici canli RTSP/MJPEG izleme motoru
 *
 * Kamera akisini GORUNMEZ bir ffmpeg alt-sureci ile cozup ham RGB kareleri
 * bir borudan okur ve raylib Texture2D'ye cevirir. Boylece goruntu harici bir
 * oynaticida/browserda degil, dogrudan BEAT arayuzu icinde cizilir
 * (meterpreter tarzi: tek pencere, gomulu goruntu).
 *
 * Tasarim:
 *  - Her akis icin bir okuyucu thread (ffmpeg stdout -> cift tampon)
 *  - Texture olusturma/guncelleme yalnizca ana (render) thread'de yapilir
 *  - Donanim decode (VAAPI/NVDEC) opsiyonel bayrakla acilir (Faz 4)
 *
 * Latency icin nobuffer/low_delay + sabit decode cozunurlugu + kare hizi
 * siniri (varsayilan 15 fps) kullanilir.
 */
#ifndef VIDEO_STREAM_H
#define VIDEO_STREAM_H

#include "platform.h"
#include "raylib.h"

#define VS_MAX_STREAMS 8
#define VS_DEFAULT_W   640
#define VS_DEFAULT_H   360
#define VS_URL_LEN     256
#define VS_STATUS_LEN  128

/* Cozme yontemi */
typedef enum {
    VS_DECODE_SOFT = 0,   /* yazilim decode (her yerde calisir) */
    VS_DECODE_VAAPI,      /* Intel/AMD VAAPI */
    VS_DECODE_NVDEC       /* NVIDIA NVDEC (CUDA) */
} VideoDecodeMode;

/* Akis durumu */
typedef enum {
    VS_ST_IDLE = 0,       /* slot bos */
    VS_ST_CONNECTING,     /* ffmpeg basladi, ilk kare bekleniyor */
    VS_ST_PLAYING,        /* kare akiyor */
    VS_ST_ERROR,          /* acilamadi / ffmpeg cikti */
    VS_ST_STOPPED         /* durduruldu */
} VideoStreamState;

/* Akis bilgisi (yalnizca okuma icin; ana thread doldurur) */
typedef struct {
    int    slot;
    int    state;
    int    decode_mode;
    int    width, height;     /* decode edilen kare boyutu */
    double fps;               /* olculen kare hizi (bu akis) */
    unsigned long frames;     /* toplam okunan kare */
    double last_frame_time;   /* son karenin zamani (GetTime() tabanli) */
    char   url[VS_URL_LEN];
    char   status[VS_STATUS_LEN];  /* insan-okur durum/ hata metni */
} VideoStreamInfo;

/* Sistem yasam dongusu */
void video_stream_system_init(void);
void video_stream_system_shutdown(void);

/* Bir akis acar. url: rtsp://[user:pass@]host:port/path veya http mjpeg.
 * w/h: decode hedef cozunurluk (0 -> varsayilan). mode: decode yontemi.
 * transport_tcp: rtsp icin 1=tcp, 0=udp. Doner: slot (>=0) veya -1. */
int  video_stream_open(const char *url, int w, int h,
                       VideoDecodeMode mode, int transport_tcp);

/* Akisi durdurur ve slotu serbest birakir. */
void video_stream_close(int slot);

/* Slot durumu / bilgisi. */
int  video_stream_state(int slot);

/* Ana (render) thread: yeni kare varsa Texture2D'yi gunceller.
 * Doner: 1 = bu cagrida yeni kare yuklendi, 0 = degisiklik yok. */
int  video_stream_poll(int slot);

/* Ana (render) thread: cizime hazir texture. Hazir degilse id==0. */
Texture2D video_stream_texture(int slot);

/* ffmpeg mevcut mu (bir kez). */
int  video_stream_ffmpeg_available(void);

/* Anlik kareyi diske yaz (uzanti .png/.jpg). Ana (render) thread'de cagrilmali.
 * Doner: 0 = yazildi, -1 = hata/slot bos. */
int  video_stream_snapshot(int slot, const char *path);

/* Akisi diske kaydet (ffmpeg -c copy, yeniden kodlama yok). pattern: tek dosya
 * ya da %03d iceren segment sablonu. segment_sec>0 ise bolumlere ayrilir.
 * Doner: 0 = basladi, -1 = hata. */
int  video_stream_record_start(int slot, const char *pattern, int segment_sec);
void video_stream_record_stop(int slot);
int  video_stream_recording(int slot);

/* Akis kopunca otomatik yeniden baglanmayi ac/kapat (varsayilan: acik). */
void video_stream_set_reconnect(int slot, int enable);

#endif /* VIDEO_STREAM_H */
