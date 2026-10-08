/*
 * cam_net.h — Kamera modulu icin paylasilan ag + kripto altyapisi
 *
 * Amac: kamera kesif/erisim modullerinin ihtiyac duydugu dusuk seviye
 * islevleri tek yerde toplamak:
 *   - Zaman asimli TCP/TLS baglanti (CamConn soyutlamasi)
 *   - Basit HTTP/1.x istemcisi (GET/HEAD/POST, bas/digest auth, 401 ayristirma)
 *   - Saf-C MD5 / SHA1 / HMAC-SHA1 / Base64  (OpenSSL'e hard bagimlilik yok;
 *     TLS icin OpenSSL varsa kullanilir, yoksa HTTPS sondasi atlanir)
 *   - HTTP Digest (RFC 2617) Authorization basligi uretimi
 *
 * Harici bagimlilik: POSIX soketleri. TLS yalnizca HAVE_OPENSSL tanimli ise.
 */
#ifndef CAM_NET_H
#define CAM_NET_H

#include <stddef.h>

/* ================= Baglanti soyutlamasi ================= */
typedef struct {
    int   fd;       /* ham soket, -1 = kapali */
    void *ssl;      /* SSL* (TLS) veya NULL */
    int   is_tls;
} CamConn;

/* Zaman asimli baglanti. tls=1 ise TLS el sikismasi yapilir (HAVE_OPENSSL
 * tanimli degilse tls istegi -2 ile reddedilir). Doner: 0 ok, <0 hata. */
int  cam_conn_open(CamConn *c, const char *ip, int port, int timeout_ms, int tls);
int  cam_conn_write(CamConn *c, const void *buf, int len, int timeout_ms);
/* En fazla timeout_ms icinde len bayta kadar okur; doner: okunan >=0, <0 hata. */
int  cam_conn_read(CamConn *c, void *buf, int len, int timeout_ms);
void cam_conn_close(CamConn *c);

/* TLS bu derlemede kullanilabilir mi? */
int  cam_net_tls_available(void);

/* ================= Kripto (saf C) ================= */
void cam_b64_encode(const unsigned char *in, int len, char *out, int outlen);

void cam_md5(const unsigned char *in, size_t len, unsigned char out[16]);
void cam_md5_hex(const void *in, size_t len, char out[33]);

void cam_sha1(const unsigned char *in, size_t len, unsigned char out[20]);
/* SHA1 -> base64 (ONVIF PasswordDigest icin). */
void cam_sha1_b64(const void *in, size_t len, char *out, int outlen);
/* HMAC-SHA1 -> base64 (ONVIF UsernameToken imzasi icin). */
void cam_hmac_sha1_b64(const void *key, size_t keylen,
                       const void *data, size_t datalen, char *out, int outlen);

/* Rastgele nonce uret (hex yaz). */
void cam_make_nonce(char *out, int outlen);

/* ================= HTTP istemcisi ================= */
typedef struct {
    int  status;                 /* HTTP durum kodu, 0 = yanit yok */
    char server[160];            /* Server basligi */
    char location[256];          /* Location */
    char content_type[128];      /* Content-Type */
    char www_auth[384];          /* WWW-Authenticate (401) */
    char set_cookie[512];        /* Set-Cookie (ilk) */
    char headers[4096];          /* tum baslik blogu (ham) */
} CamHttpResp;

/*
 * Tek HTTP istegi gonderir. body icine (bodylen sinirli) yanit govdesi yazilir,
 * resp (NULL degilse) ayristirilmis basliklarla doldurulur.
 * Doner: 0 ok (yanit alindi), <0 baglanti hatasi. (status ayrica bildirilir.)
 */
int cam_http_request(const char *ip, int port, int tls,
                     const char *method, const char *path,
                     const char *host_header, const char *extra_headers,
                     int timeout_ms, char *body, int bodylen, CamHttpResp *resp);

/*
 * Kimlik dogrulamali GET: once kimliksiz dener; 401 gelirse WWW-Authenticate'e
 * gore Basic veya Digest ile tekrar dener (iki adim).
 * user NULL/"" ise yalniz kimliksiz denenir.
 * Doner: 0 = 200/2xx alindi, 1 = 401 (kimlik tutmadi), 2 = diger, <0 hata.
 */
int cam_http_get_auth(const char *ip, int port, int tls, const char *path,
                      const char *user, const char *pass,
                      int timeout_ms, char *body, int bodylen, CamHttpResp *resp);

/* RFC 2617 Digest Authorization basligi uretir. auth_extra icine
 * "Authorization: Digest ...\r\n" yazilir. */
void cam_http_digest_header(const char *user, const char *pass,
                            const char *www_auth /* 401 basligi */,
                            const char *method, const char *uri,
                            char *out, int outlen);

/* WWW-Authenticate basliginda "digest" var mi? */
int  cam_wwwauth_is_digest(const char *www_auth);

#endif /* CAM_NET_H */
