/*
 * camera_vuln.h — Kamera parmak izi, bilinen zafiyet sondalari, ONVIF istemcisi
 *
 * Uc ana yetenek:
 *   1) Ureticiye ozel HTTP "device info" endpoint parmak izi (model/firmware).
 *   2) Bilinen kimlik-dogrulama atlatma / zafiyet sondalari
 *      (Hikvision ISAPI auth-token, Dahua RPC2 login, Xiongmai backdoor vb.).
 *   3) ONVIF device-service istemcisi: GetDeviceInformation / GetProfiles /
 *      GetStreamUri. Kimlik: WS-UsernameToken (PasswordDigest) + HTTP Basic +
 *      HTTP Digest fallback. Kimliksiz de denenir.
 *
 * Ek olarak genis varsayilan kimlik veritabani ve harici wordlist yukleyici.
 */
#ifndef CAMERA_VULN_H
#define CAMERA_VULN_H

/* Bilinen kamera zafiyet bayraklari (sonda sonucu) */
enum {
    CAM_VULN_NONE            = 0,
    CAM_VULN_HIK_ISAPI_TOKEN = 1u << 0,  /* Hikvision ISAPI auth-token bilgi sizintisi */
    CAM_VULN_HIK_USERS       = 1u << 1,  /* Hikvision kullanici listesi sizintisi */
    CAM_VULN_DAHUA_LOGIN     = 1u << 2,  /* Dahua RPC2 kimlik atlatma */
    CAM_VULN_XIONGMAI_BACKDOOR = 1u << 3,/* Xiongmai varsayilan arka kapi hesabi */
    CAM_VULN_ANON_INFO       = 1u << 4   /* kimliksiz device-info acigi */
};

/* --- Varsayilan kimlik DB --- */
typedef struct { const char *user; const char *pass; } CamCred;
/* Genis varsayilan kimlik tablosu (NULL ile sonlanir). */
const CamCred *camera_vuln_default_creds(int *count);
/* Harici wordlist: satirlar "kullanici:parola" veya sadece "parola" (admin varsayilir).
 * out: malloc edilmis CamCred dizisi; doner: yuklenen sayi (0 hata). */
int camera_vuln_load_wordlist(const char *path, CamCred **out, int max_lines);
void camera_vuln_free_wordlist(CamCred *list);

/* --- HTTP parmak izi --- */
/* Ureticiye ozel device-info endpoint'lerini dener; vendor/model/firmware doldurur.
 * Doner: eslesen endpoint sayisi (0 = bulunamadi). */
int camera_vuln_fingerprint_http(const char *ip, int port, int tls,
                                 char *vendor, int vlen,
                                 char *model, int mlen,
                                 char *firmware, int flen,
                                 char *serial_out, int slen);

/* --- Bilinen zafiyet sondalari --- */
/* vendor_hint: kesiften gelen uretici adi (NULL olabilir); ipucu yoksa tum
 * sondalar denenir. Doner: CAM_VULN_* maskesi; detail'a insan-okur aciklama. */
unsigned camera_vuln_probe_authbypass(const char *ip, int port, int tls,
                                      const char *vendor_hint,
                                      char *detail, int dlen);

/* --- Snapshot URL adaylari (erisim dogrulandiktan sonra tek kare cekmek icin) --- */
const char *const *camera_vuln_snapshot_paths(int *count);

/* --- ONVIF device-service --- */
typedef struct {
    char manufacturer[128];
    char model[128];
    char firmware[128];
    char serial[128];
    char stream_uri[256];     /* GetStreamUri sonucu (varsa) */
    char media_xaddr[256];    /* kesfedilen media servis adresi */
    int  auth_used;           /* 0 none, 1 WS-UsernameToken, 2 Basic, 3 Digest */
} OnvifDeviceInfo;

/* ONVIF device-service'i sorgular. user/pass NULL/"" ise kimliksiz denenir.
 * Doner: 0 = cihaz bilgisi alindi, 1 = ONVIF yanit verdi ama auth gerekti,
 *        -1 = ONVIF yok/ulasilamadi. */
int onvif_probe_device(const char *ip, int port, int tls,
                       const char *user, const char *pass,
                       OnvifDeviceInfo *out);

#endif /* CAMERA_VULN_H */
