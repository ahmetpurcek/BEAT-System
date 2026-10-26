/*
 * sentinel_proto.c — Faz 2 (fingerprint) + Faz 4 (protokol mantik zafiyeti)
 *
 * Bilinen CVE listesine dayanmaz. Protokol implementasyonlarinin mantik
 * hatalarini arar:
 *   - ONVIF: auth'in nerede kontrol edildigi (header / body / hic)
 *   - RTSP : oturum kimligi dogrulamasi, kimliksiz DESCRIBE
 *   - HTTP : CL/TE desenkronizasyonu, yol normalizasyonu, null byte,
 *            parametre duplikasyonu
 *   - Vendor SDK portlari: Dahua DVRIP el sikismasi ile surum/cihaz sizintisi
 *
 * Her deneme loglanir. Kalici imza ogrenmesi kaldirildi (SQLite yok):
 * ogrenme artik bellek icinde tutulmaz, bulgular oturum suresince yasar.
 *
 * NOT: Canli kamera olmadan bu yolun dogrulanamadigi raporlanir; kod
 * "calismis gibi" sunulmaz.
 */
#include "sentinel.h"
#include "cam_net.h"
#include "camera_discovery.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define PROTO_TIMEOUT_MS 2500
#define PROTO_MAX_SESSION_GUESS 16

/* ==================== Yardimcilar ==================== */

static void add_proto_finding(const char *target, const char *cls, const char *title,
                             const char *vector, const char *cwe, const char *cvss,
                             int conf, const char *status, const char *detail,
                             const char *evidence) {
    SnFinding f;
    memset(&f, 0, sizeof(f));
    snprintf(f.target, sizeof(f.target), "%s", target ? target : "");
    snprintf(f.cls, sizeof(f.cls), "%s", cls);
    snprintf(f.title, sizeof(f.title), "%s", title);
    snprintf(f.vector, sizeof(f.vector), "%s", vector);
    snprintf(f.cwe, sizeof(f.cwe), "%s", cwe ? cwe : "");
    snprintf(f.status, sizeof(f.status), "%s", status ? status : "candidate");
    snprintf(f.detail, sizeof(f.detail), "%s", detail ? detail : "");
    snprintf(f.evidence, sizeof(f.evidence), "%s", evidence ? evidence : "");
    f.cvss = sn_cvss_base(cvss);
    f.confidence = conf;
    sn_severity_from_cvss(f.cvss, f.severity, sizeof(f.severity));
    sn_finding_add(&f);
}

/* Basarili pattern loglanir; kalici imza deposu yok (SQLite kaldirildi). */
static void signature_learn(const char *vendor, const char *sig, const char *sample) {
    (void)vendor; (void)sample;
    sn_logf("proto: imza ogrenildi (oturum): %s", sig ? sig : "?");
}

/* ==================== RTSP ==================== */

static int rtsp_send(const char *ip, int port, const char *req, char *resp, int rlen) {
    CamConn c;
    memset(&c, 0, sizeof(c));
    if (cam_conn_open(&c, ip, port, PROTO_TIMEOUT_MS, 0) != 0) return -1;
    cam_conn_write(&c, req, (int)strlen(req), PROTO_TIMEOUT_MS);
    int n = cam_conn_read(&c, resp, rlen - 1, PROTO_TIMEOUT_MS);
    cam_conn_close(&c);
    if (n <= 0) { resp[0] = '\0'; return -1; }
    resp[n] = '\0';
    return n;
}

static int rtsp_status(const char *resp) {
    const char *p = strstr(resp, "RTSP/1.0 ");
    if (!p) return 0;
    return atoi(p + 9);
}

static void rtsp_tests(SnTarget *t) {
    if (t->rtsp_port <= 0) return;
    char req[512], resp[8192];

    /* 1) Kimliksiz OPTIONS -> Server basligi (fingerprint) */
    snprintf(req, sizeof(req),
             "OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\n"
             "User-Agent: BEAT-SENTINEL\r\n\r\n", t->ip, t->rtsp_port);
    if (rtsp_send(t->ip, t->rtsp_port, req, resp, sizeof(resp)) > 0) {
        int st = rtsp_status(resp);
        char *srv = strstr(resp, "Server:");
        if (srv) {
            char line[128];
            snprintf(line, sizeof(line), "%s", srv + 7);
            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            str_trim(line);
            if (line[0] && !t->vendor[0])
                snprintf(t->vendor, sizeof(t->vendor), "%.60s", line);
            sn_logf("proto: %s RTSP OPTIONS %d, Server=%s", t->ip, st, line);
        }
        /* 2) Kimliksiz DESCRIBE: 401 beklenir; 200 ise acik akis */
        snprintf(req, sizeof(req),
                 "DESCRIBE rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 2\r\n"
                 "Accept: application/sdp\r\n\r\n", t->ip, t->rtsp_port);
        if (rtsp_send(t->ip, t->rtsp_port, req, resp, sizeof(resp)) > 0) {
            int ds = rtsp_status(resp);
            if (ds == 200 && strstr(resp, "m=video")) {
                add_proto_finding(t->ip, "protocol_logic",
                    "RTSP kimliksiz DESCRIBE basarili (acik akis)",
                    "rtsp_unauth", "CWE-306",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    88, "confirmed",
                    "DESCRIBE kimlik dogrulama istemeden SDP dondurdu; video akisi "
                    "kimliksiz alinabilir.", "");
                signature_learn(t->vendor, "rtsp_unauth_describe", "200 + m=video");
            } else if (ds == 401) {
                char *wa = strstr(resp, "WWW-Authenticate:");
                sn_logf("proto: %s RTSP DESCRIBE 401 (%s)", t->ip,
                        wa ? "auth var" : "auth basligi yok");
                if (!wa)
                    add_proto_finding(t->ip, "protocol_logic",
                        "RTSP 401 ama WWW-Authenticate basligi yok",
                        "rtsp_auth_malformed", "CWE-287",
                        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        45, "candidate",
                        "401 donuyor fakat challenge basligi yok; istemci "
                        "davranisi belirsiz, bazi implementasyonlarda auth atlanir.", "");
            }
        }
    } else {
        sn_logf("proto: %s RTSP portu %d yanit vermedi", t->ip, t->rtsp_port);
    }

    /* 3) Oturum kimligi dogrulamasi: SETUP olmadan PLAY */
    int accepted = 0;
    for (int i = 0; i < PROTO_MAX_SESSION_GUESS && !accepted; i++) {
        unsigned sid = 0x10000000u + (unsigned)i * 0x1111u;
        snprintf(req, sizeof(req),
                 "PLAY rtsp://%s:%d/ RTSP/1.0\r\nCSeq: %d\r\n"
                 "Session: %08X\r\n\r\n", t->ip, t->rtsp_port, 10 + i, sid);
        if (rtsp_send(t->ip, t->rtsp_port, req, resp, sizeof(resp)) > 0) {
            int st = rtsp_status(resp);
            if (st == 200) {
                accepted = 1;
                char det[SN_DETAIL_LEN];
                snprintf(det, sizeof(det),
                         "SETUP yapilmadan, tahmin edilen Session: %08X ile PLAY "
                         "kabul edildi (HTTP %d). Oturum kimligi dogrulanmiyor; "
                         "aktif istemcinin akisina katilma olasiligi.", sid, st);
                add_proto_finding(t->ip, "protocol_logic",
                    "RTSP oturum kimligi dogrulanmiyor (session hijack)",
                    "rtsp_session_guess", "CWE-287",
                    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    80, "validated", det, "");
                signature_learn(t->vendor, "rtsp_session_accept", "PLAY 200 without SETUP");
            }
        }
        platform_sleep_ms(60);
    }
}

/* ==================== ONVIF ==================== */

static int soap_post(SnTarget *t, int port, const char *body, const char *soap_action,
                     char *resp, int rlen) {
    char hdr[512];
    snprintf(hdr, sizeof(hdr),
             "Content-Type: application/soap+xml; charset=utf-8\r\n"
             "SOAPAction: \"%s\"\r\n", soap_action);
    CamHttpResp r;
    memset(&r, 0, sizeof(r));
    int rc = cam_http_request(t->ip, port, 0, "POST", "/onvif/device_service",
                              NULL, hdr, PROTO_TIMEOUT_MS, resp, rlen, &r);
    if (rc != 0) return -1;
    return r.status;
}

static void soap_envelope(char *out, int olen, const char *body) {
    snprintf(out, (size_t)olen,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        "xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\">"
        "<s:Body>%s</s:Body></s:Envelope>", body);
}

static void soap_usertoken(char *out, int olen, const char *user, const char *pass) {
    char nonce[40];
    cam_make_nonce(nonce, sizeof(nonce));
    char digest_in[128];
    time_t now = time(NULL);
    struct tm tmv;
    gmtime_r(&now, &tmv);
    char created[32];
    snprintf(created, sizeof(created), "%04d-%02d-%02dT%02d:%02d:%02dZ",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    snprintf(digest_in, sizeof(digest_in), "%s%s%s", nonce, created, pass);
    char pd[64];
    cam_sha1_b64(digest_in, strlen(digest_in), pd, sizeof(pd));
    snprintf(out, (size_t)olen,
        "<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/"
        "oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        "<wsse:UsernameToken><wsse:Username>%s</wsse:Username>"
        "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/"
        "oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</wsse:Password>"
        "<wsse:Nonce>%s</wsse:Nonce><wsse:Created>%s</wsse:Created>"
        "</wsse:UsernameToken></wsse:Security>", user, pd, nonce, created);
}

/* ONVIF auth yerlesimi mantik testi:
 *   A) hic auth yok         -> 200 ise kimliksiz bilgi sizintisi
 *   B) header'da UsernameToken -> 200 beklenir (dogru implementasyon)
 *   C) yalnizca body'de token  -> 200 ise "body-only" mantik zafiyeti    */
static void onvif_auth_placement(SnTarget *t, int port) {
    char body[512], env[1024], tok[600], resp[8192];

    snprintf(body, sizeof(body),
             "<tds:GetDeviceInformation/>");
    soap_envelope(env, sizeof(env), body);
    int s_noauth = soap_post(t, port, env, "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
                             resp, sizeof(resp));

    int s_header = -1, s_body = -1;
    if (s_noauth != 200) {
        soap_usertoken(tok, sizeof(tok), "admin", "admin");
        char inner[1024];
        snprintf(inner, sizeof(inner), "%s%s", tok, body);
        soap_envelope(env, sizeof(env), inner);
        s_header = soap_post(t, port, env,
                             "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
                             resp, sizeof(resp));

        /* body-only: token bir kapsayici elemanin icinde gonderilir */
        snprintf(inner, sizeof(inner),
                 "<tds:GetDeviceInformation><tds:Extension>%s</tds:Extension>"
                 "</tds:GetDeviceInformation>", tok);
        soap_envelope(env, sizeof(env), inner);
        s_body = soap_post(t, port, env,
                           "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
                           resp, sizeof(resp));
    }

    sn_logf("proto: %s ONVIF auth yerlesimi (authsiz=%d, header=%d, body=%d)",
            t->ip, s_noauth, s_header, s_body);

    if (s_noauth == 200) {
        add_proto_finding(t->ip, "protocol_logic",
            "ONVIF GetDeviceInformation kimliksiz erisilebilir",
            "onvif_unauth", "CWE-306",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            90, "confirmed",
            "Kimlik dogrulama olmadan cihaz uretici/model/firmware/seri bilgisi "
            "dondu. Bilgi sizintisi, sonraki vektorler icin hedefleme saglar.", "");
        signature_learn(t->vendor, "onvif_unauth_deviceinfo", "200 without any token");
    } else if (s_body == 200 && s_header != 200) {
        add_proto_finding(t->ip, "protocol_logic",
            "ONVIF auth yalnizca body'deki token'i kabul ediyor (mantik zafiyeti)",
            "onvif_body_only_auth", "CWE-287",
            "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            75, "validated",
            "Ayni kimlik bilgisi SOAP header'da reddedilirken body icindeki "
            "kapsayici eleman altinda kabul edildi. Bu implementasyon auth "
            "kontrolunu yanlis yerde yapiyor; farkli servisler (GetUsers, "
            "GetSystemLog) ayni hatayi tasiyabilir.", "");
        signature_learn(t->vendor, "onvif_body_only_auth", "body token accepted, header rejected");
    }
}

/* Kimliksiz servis sizintisi: GetUsers / GetSystemLog */
static void onvif_service_leak(SnTarget *t, int port) {
    const struct { const char *body; const char *action; const char *label; } probes[] = {
        { "<tds:GetUsers/>", "http://www.onvif.org/ver10/device/wsdl/GetUsers", "GetUsers" },
        { "<tds:GetSystemLog><tds:LogType>System</tds:LogType></tds:GetSystemLog>",
          "http://www.onvif.org/ver10/device/wsdl/GetSystemLog", "GetSystemLog" },
    };
    char env[768], resp[8192];
    for (int i = 0; i < 2; i++) {
        soap_envelope(env, sizeof(env), probes[i].body);
        int st = soap_post(t, port, env, probes[i].action, resp, sizeof(resp));
        if (st == 200 && (strstr(resp, "Username") || strstr(resp, "LogEntry"))) {
            char title[SN_TITLE_LEN];
            snprintf(title, sizeof(title), "ONVIF %s kimliksiz veri sizintisi", probes[i].label);
            add_proto_finding(t->ip, "protocol_logic", title, "onvif_service_leak",
                "CWE-306", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                85, "confirmed",
                "Kimlik dogrulama olmadan kullanici listesi / sistem log'u dondu. "
                "Hesap adlari parola puskurtme icin, log'lar ic ag topolojisi icin "
                "kullanilabilir.", "");
        }
        platform_sleep_ms(120);
    }
}

/* ==================== HTTP mantik testleri ==================== */

static int http_get_path(SnTarget *t, int port, const char *path,
                         char *body, int blen, CamHttpResp *r) {
    return cam_http_request(t->ip, port, 0, "GET", path, NULL, NULL,
                            PROTO_TIMEOUT_MS, body, blen, r);
}

static void http_logic_tests(SnTarget *t, int port) {
    char body[4096];
    CamHttpResp base, test;
    if (http_get_path(t, port, "/", body, sizeof(body), &base) != 0) return;

    sn_logf("proto: %s HTTP %d, Server=%s", t->ip, base.status,
            base.server[0] ? base.server : "-");
    if (base.server[0] && !t->vendor[0])
        snprintf(t->vendor, sizeof(t->vendor), "%.60s", base.server);

    /* 1) Yol normalizasyonu: auth korumali bir yolun atlatilmasi */
    const char *base_paths[] = { "/", "/index.html", "/cgi-bin/", NULL };
    const char *bypass_tails[] = {
        "..;/", "%2e%2e/", "..%2f", "/.%2e/", "//", "/%00/", NULL };
    for (int i = 0; base_paths[i]; i++) {
        for (int j = 0; bypass_tails[j]; j++) {
            char path[256];
            snprintf(path, sizeof(path), "%s%s", base_paths[i], bypass_tails[j]);
            if (http_get_path(t, port, path, body, sizeof(body), &test) != 0) continue;
            /* 200 + ana sayfadan farkli govde = normalizasyon tutarsizligi adayi */
            if (test.status == 200 && base.status == 200 &&
                strcmp(test.content_type, base.content_type) &&
                test.content_type[0]) {
                char det[SN_DETAIL_LEN];
                snprintf(det, sizeof(det),
                         "Yol \"%s\" 200 ve farkli icerik tipi (%s) dondurdu; "
                         "normalizasyon sirasinda farkli bir kaynak sunuluyor. "
                         "Auth kontrolu ile dosya cozumleme ayrisiyor olabilir.",
                         path, test.content_type);
                add_proto_finding(t->ip, "protocol_logic",
                    "HTTP yol normalizasyonu tutarsizligi", "http_path_normalization",
                    "CWE-22", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    40, "candidate", det, "");
                signature_learn(t->vendor, "http_path_norm", path);
                j = 100; i = 100;   /* tek ornek yeter */
            }
            platform_sleep_ms(70);
        }
    }

    /* 2) CL/TE desenkronizasyonu (request smuggling adayi) */
    {
        CamConn c;
        memset(&c, 0, sizeof(c));
        if (cam_conn_open(&c, t->ip, port, PROTO_TIMEOUT_MS, 0) == 0) {
            const char *req =
                "POST / HTTP/1.1\r\n"
                "Host: x\r\n"
                "Content-Length: 6\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "0\r\n\r\nG";
            cam_conn_write(&c, req, (int)strlen(req), PROTO_TIMEOUT_MS);
            char r1[2048];
            int n = cam_conn_read(&c, r1, sizeof(r1) - 1, PROTO_TIMEOUT_MS);
            if (n > 0) {
                r1[n] = '\0';
                int st = 0;
                if (strncmp(r1, "HTTP/1.", 7) == 0) st = atoi(r1 + 9);
                sn_logf("proto: %s CL+TE istegi -> %d", t->ip, st);
                if (st == 200 || st == 400 || st == 501) {
                    add_proto_finding(t->ip, "protocol_logic",
                        "HTTP CL+TE birlikte kabul ediliyor (smuggling adayi)",
                        "http_cl_te", "CWE-444",
                        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        35, "candidate",
                        "Ayni istekte hem Content-Length hem Transfer-Encoding "
                        "gonderildi ve sunucu yanit uretti. On-unde bir proxy varsa "
                        "istek kacakciligi (smuggling) mumkun olabilir; tek basina "
                        "kanit degildir.", "");
                }
            }
            cam_conn_close(&c);
        }
    }

    /* 3) Parametre duplikasyonu: auth karari ilk mi son mu? */
    {
        char det[SN_DETAIL_LEN];
        int st = http_get_path(t, port, "/?user=admin&user=guest", body, sizeof(body), &test);
        if (st == 0 && test.status == 200) {
            snprintf(det, sizeof(det),
                     "Ayni parametre iki kez gonderildiginde istek 200 dondu "
                     "(status=%d). Auth/rol karari hangi degeri kullaniyor "
                     "dogrulanmali (HPP).", test.status);
            add_proto_finding(t->ip, "protocol_logic",
                "HTTP parametre duplikasyonu isleniyor (HPP adayi)",
                "http_hpp", "CWE-235",
                "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
                30, "candidate", det, "");
        }
    }

    /* 4) Auth sonrasi snapshot yolu kesfi (erisim varsa) */
    if (base.status == 401) {
        const char *wa = base.www_auth;
        sn_logf("proto: %s web arayuzu korumali (%s)", t->ip,
                cam_wwwauth_is_digest(wa) ? "digest" : "basic/diger");
    }

    /* 5) Yonetim arayuzu surum sizintisi */
    {
        const char *paths[] = { "/ISAPI/System/deviceInfo", "/cgi-bin/magicBox.cgi?action=getSystemInfo",
                                "/RPC2_Login", "/api/system/info", NULL };
        for (int i = 0; paths[i]; i++) {
            if (http_get_path(t, port, paths[i], body, sizeof(body), &test) != 0) continue;
            if (test.status == 200 && body[0] && strchr(body, '<')) {
                char det[SN_DETAIL_LEN];
                snprintf(det, sizeof(det),
                         "%s kimliksiz 200 dondu ve govde uretti; surum/seri "
                         "bilgisi sizabilir.", paths[i]);
                add_proto_finding(t->ip, "protocol_logic",
                    "Yonetim API'si kimliksiz surum bilgisi veriyor",
                    "api_info_leak", "CWE-200",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    55, "validated", det, "");
                break;
            }
            platform_sleep_ms(90);
        }
    }
}

/* ==================== Vendor SDK (Dahua DVRIP) ==================== */

/* Dahua DVRIP login: 32 bayt baslik + JSON govde. Cihaz surum/cihaz
 * bilgisini auth oncesi dondurur; bu bir mantik sizintisidir. */
static void dvrip_probe(SnTarget *t, int port) {
    if (port <= 0) return;
    unsigned char pkt[512];
    memset(pkt, 0, sizeof(pkt));
    const char *body = "{\"method\":\"global.login\",\"params\":{\"userName\":\"admin\","
                       "\"password\":\"\",\"clientType\":\"Web3.0\"},\"id\":1}";
    int blen = (int)strlen(body) + 1;
    pkt[0] = 0x20;                      /* 32 bayt baslik */
    pkt[2] = 0; pkt[3] = 0;
    pkt[4] = (unsigned char)(blen & 0xff);
    pkt[5] = (unsigned char)((blen >> 8) & 0xff);
    pkt[6] = (unsigned char)((blen >> 16) & 0xff);
    pkt[7] = (unsigned char)((blen >> 24) & 0xff);
    pkt[16] = 1;                        /* id */
    memcpy(pkt + 32, body, (size_t)blen);

    CamConn c;
    memset(&c, 0, sizeof(c));
    if (cam_conn_open(&c, t->ip, port, 3000, 0) != 0) return;
    cam_conn_write(&c, pkt, 32 + blen, 3000);
    char resp[8192];
    int n = cam_conn_read(&c, resp, sizeof(resp) - 1, 3000);
    cam_conn_close(&c);
    if (n <= 40) return;
    resp[n] = '\0';

    const char *p = strstr(resp + 32, "\"params\"");
    sn_logf("proto: %s DVRIP %d yanit %d bayt", t->ip, port, n);
    if (p) {
        char det[SN_DETAIL_LEN];
        snprintf(det, sizeof(det),
                 "DVRIP (port %d) auth oncesi yanit parametre blogu dondurdu: %.200s. "
                 "Cihaz/surum kesfi ve parola-hash semasi analizi icin kullanilabilir.",
                 port, p);
        add_proto_finding(t->ip, "protocol_logic",
            "Dahua DVRIP auth oncesi yanit (bilgi sizintisi)",
            "dvrip_preauth", "CWE-200",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            60, "candidate", det, "");
        signature_learn(t->vendor, "dvrip_preauth", "global.login params returned");
    }
}

/* ==================== Public API ==================== */

int sn_fingerprint_target(SnTarget *t) {
    if (!t || !t->ip[0]) return -1;
    char body[4096];
    CamHttpResp r;

    /* HTTP parmak izi (birden fazla port) */
    int ports[3] = { t->http_port, 80, 8080 };
    for (int i = 0; i < 3; i++) {
        int p = ports[i];
        if (p <= 0) continue;
        int dup = 0;
        for (int k = 0; k < i; k++) if (ports[k] == p) dup = 1;
        if (dup) continue;
        memset(&r, 0, sizeof(r));
        if (cam_http_request(t->ip, p, 0, "GET", "/", NULL, NULL,
                             PROTO_TIMEOUT_MS, body, sizeof(body), &r) == 0) {
            if (!t->http_port) t->http_port = p;
            if (r.server[0]) {
                snprintf(t->vendor, sizeof(t->vendor), "%.60s", r.server);
                if (strcasestr(r.server, "hikvision")) snprintf(t->soc, sizeof(t->soc), "Hisilicon (Hikvision)");
                else if (strcasestr(r.server, "dahua")) snprintf(t->soc, sizeof(t->soc), "Dahua OEM");
                else if (strcasestr(r.server, "webs"))  snprintf(t->soc, sizeof(t->soc), "Hisilicon (web)");
            }
            /* bilinen surum kaliplari */
            const char *v = NULL;
            if ((v = strstr(body, "appVersion"))) {
                const char *q = strchr(v, '>');
                if (q) snprintf(t->fw_version, sizeof(t->fw_version), "%.40s", q + 1);
            }
            break;
        }
    }

    /* ONVIF anonim cihaz bilgisi */
    int onvif_port = t->onvif_port ? t->onvif_port : (t->http_port ? t->http_port : 80);
    char env[768], resp[8192];
    soap_envelope(env, sizeof(env), "<tds:GetDeviceInformation/>");
    int st = soap_post(t, onvif_port, env,
                       "http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation",
                       resp, sizeof(resp));
    if (st == 200) {
        t->onvif_port = onvif_port;
        const char *mf = strstr(resp, "<tds:Manufacturer>");
        const char *mo = strstr(resp, "<tds:Model>");
        const char *fv = strstr(resp, "<tds:FirmwareVersion>");
        if (mf) sscanf(mf + 18, "%63[^<]", t->vendor);
        if (mo) sscanf(mo + 11, "%63[^<]", t->model);
        if (fv) sscanf(fv + 22, "%63[^<]", t->fw_version);
        sn_logf("fing: %s ONVIF %s / %s / fw %s", t->ip,
                t->vendor[0] ? t->vendor : "?",
                t->model[0] ? t->model : "?",
                t->fw_version[0] ? t->fw_version : "?");
    } else {
        sn_logf("fing: %s ONVIF yanit yok/korumali (status=%d)", t->ip, st);
    }

    /* RTSP Server basligi */
    if (t->rtsp_port > 0) {
        char req[256], rsp[4096];
        snprintf(req, sizeof(req),
                 "OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\n\r\n", t->ip, t->rtsp_port);
        CamConn c; memset(&c, 0, sizeof(c));
        if (cam_conn_open(&c, t->ip, t->rtsp_port, PROTO_TIMEOUT_MS, 0) == 0) {
            cam_conn_write(&c, req, (int)strlen(req), PROTO_TIMEOUT_MS);
            int n = cam_conn_read(&c, rsp, sizeof(rsp) - 1, PROTO_TIMEOUT_MS);
            cam_conn_close(&c);
            if (n > 0) {
                rsp[n] = '\0';
                char *srv = strstr(rsp, "Server:");
                if (srv && !t->vendor[0]) {
                    char line[128];
                    snprintf(line, sizeof(line), "%s", srv + 7);
                    char *nl = strpbrk(line, "\r\n");
                    if (nl) *nl = '\0';
                    str_trim(line);
                    snprintf(t->vendor, sizeof(t->vendor), "%.60s", line);
                }
            }
        }
    }

    /* SoC ailesi tahmini: MAC OUI + banner */
    if (!t->soc[0] && t->mac[0]) {
        char ven[128];
        if (camera_discovery_oui_is_camera(t->mac, ven, sizeof(ven)))
            snprintf(t->soc, sizeof(t->soc), "OUI: %.50s", ven);
    }

    int conf = 20;
    if (t->vendor[0]) conf += 30;
    if (t->model[0]) conf += 20;
    if (t->fw_version[0]) conf += 20;
    if (t->onvif_port) conf += 10;
    t->confidence = conf > 100 ? 100 : conf;
    t->seen_at = time(NULL);
    sn_logf("fing: %s tamam (guven=%d, vendor=%s, soc=%s)", t->ip, t->confidence,
            t->vendor[0] ? t->vendor : "-", t->soc[0] ? t->soc : "-");
    return 0;
}

int sn_protocol_run(SnTarget *t) {
    if (!t || !t->ip[0]) return -1;
    int hits_before = 0;
    {
        SnFinding tmp[SN_MAX_FINDINGS];
        hits_before = sn_get_findings(tmp, SN_MAX_FINDINGS);
    }

    if (t->rtsp_port > 0) rtsp_tests(t);

    int hp = t->http_port ? t->http_port : 80;
    onvif_auth_placement(t, hp);
    onvif_service_leak(t, hp);
    http_logic_tests(t, hp);

    if (t->sdk_port > 0) dvrip_probe(t, t->sdk_port);
    else dvrip_probe(t, 37777);

    SnFinding tmp[SN_MAX_FINDINGS];
    int now = sn_get_findings(tmp, SN_MAX_FINDINGS);
    sn_logf("proto: %s tamam (%d yeni bulgu)", t->ip, now - hits_before);
    return 0;
}


